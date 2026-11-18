from __future__ import annotations

import argparse
import logging
import sys
import os
from datetime import datetime
from pathlib import Path


from config import get_settings
from db.repository import (
    AnalysisRepository,
    SchemaError,
    create_analysis_tables,
    inspect_skills_schema,
    missing_analysis_tables,
)
from db.session import build_engine, build_session_factory
from pipeline.static_pipeline import StaticAnalysisPipeline
from llm_config import get_llm_settings
from pipeline.llm_pipeline import LLMAnalysisPipeline
from pipeline.dynamic_pipeline import DynamicAnalysisPipeline
from db.dynamic_repository import DynamicAnalysisRepository
from db.llm_models import LLMAnalysisResult


LOG_DIR = Path("logs")
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
VALID_RISK_LEVELS = {"critical","high","medium","low"}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    settings = get_settings()
    engine = build_engine(settings)

    try:
        if args.command == "init-db":
            schema = inspect_skills_schema(engine)
            create_analysis_tables(engine)
            print("Created analysis tables if missing: analysis_runs, analysis_results, analysis_findings")
            print(f"Verified skills primary key: {', '.join(schema['primary_key'])}")
            print("Verified skills artifact columns: artifact_uri, artifact_hash")
            return 0

        if args.command == "analyze-static":
            logger, log_path = configure_file_logging("analyze-static", args.log_level)
            print(f"Writing analysis log to {log_path}")
            logger.info("Initialized analysis logging path=%s level=%s", log_path, args.log_level)

            inspect_skills_schema(engine)
            missing_tables = missing_analysis_tables(engine)
            if missing_tables:
                message = (
                    "Missing analysis tables: "
                    + ", ".join(missing_tables)
                    + ". Run `python3 cli.py init-db` first."
                )
                logger.error(message)
                print(message, file=sys.stderr)
                return 2

            pipeline = StaticAnalysisPipeline(
                settings,
                build_session_factory(engine),
                logger=logger,
                max_consecutive_failures=args.max_consecutive_failures,
                max_failure_rate=args.max_failure_rate,
                min_processed_before_consecutive_check=args.min_processed_before_consecutive_check,
                max_absolute_failures=args.max_absolute_failures,
            )
            summary = pipeline.run(
                limit=args.limit,
                skill_id=args.skill_id,
                force=args.force,
                progress_every=args.progress_every,
            )
            print(
                "Static analysis run {analysis_run_id}: selected={selected}, skipped={skipped}, "
                "succeeded={succeeded}, failed={failed}, analyzer={analyzer_name} "
                "v{analyzer_version}, log={log_path}".format(
                    **summary,
                    log_path=log_path,
                )
            )
            return 0
        
        if args.command == "analyze-llm":
            logger, log_path = configure_file_logging("analyze-llm", args.log_level)
            print(f"Writing analysis log to {log_path}")

            pipeline = LLMAnalysisPipeline(
                get_llm_settings(),
                build_session_factory(engine),
                logger=logger,
            )
            summary = pipeline.run(
                risk_levels=args.risk_levels,
                limit=args.limit,
                skill_id=args.skill_id,
                force=args.force,
                progress_every=args.progress_every,
            )
            print(
                "LLM analysis run {llm_analysis_run_id}: selected={selected}, skipped={skipped}, "
                "succeeded={succeeded}, failed={failed}, log={log_path}".format(
                    **summary,
                    log_path=log_path,
                )
            )
            return 0

        if args.command == "analyze-dynamic":
            logger, log_path = configure_file_logging("analyze-dynamic", args.log_level, "openclaw.dynamic_analysis")
            print(f"Writing analysis log to {log_path}")
            logger.info("Initialized dynamic analysis logging path=%s level=%s", log_path, args.log_level)

            pipeline = DynamicAnalysisPipeline(
                settings=settings,
                session_factory=build_session_factory(engine),
                logger=logger,
                timeout_secs=args.timeout_secs,
                total_timeout_secs=args.total_timeout_secs,
                max_consecutive_failures=args.max_consecutive_failures,
                max_failure_rate=args.max_failure_rate,
                min_processed_before_consecutive_check=args.min_processed_before_consecutive_check,
                max_absolute_failures=args.max_absolute_failures,
            )
            summary = pipeline.run(
                limit=args.limit,
                force=args.force,
                progress_every=args.progress_every,
            )
            print(
                "Dynamic analysis run {dynamic_analysis_run_id}: selected={selected}, "
                "succeeded={succeeded}, failed={failed}, elapsed={elapsed_seconds:.1f}s "
                "log={log_path}".format(**summary, log_path=log_path)
            )
            return 0

        if args.command == "summary":
            missing_tables = missing_analysis_tables(engine)
            if missing_tables:
                print(
                    "Missing analysis tables: "
                    + ", ".join(missing_tables)
                    + ". Run `python3 cli.py init-db` first.",
                    file=sys.stderr,
                )
                return 2

            with build_session_factory(engine)() as session:
                repo = AnalysisRepository(session)
                print_summary(repo)
            return 0

        if args.command == "findings":
            missing_tables = missing_analysis_tables(engine)
            if missing_tables:
                print(
                    "Missing analysis tables: "
                    + ", ".join(missing_tables)
                    + ". Run `python3 cli.py init-db` first.",
                    file=sys.stderr,
                )
                return 2

            with build_session_factory(engine)() as session:
                repo = AnalysisRepository(session)
                print_findings(repo, severity=args.severity, limit=args.limit)
            return 0

        parser.print_help()
        return 1
    except SchemaError as exc:
        print(f"Schema error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenClaw skill analysis CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="Create analysis tables if they do not exist")

    analyze_static = subparsers.add_parser("analyze-static", help="Run static analysis")
    analyze_static.add_argument("--limit", type=non_negative_int, default=None)
    analyze_static.add_argument("--skill-id", type=positive_int, default=None)
    analyze_static.add_argument(
        "--force",
        action="store_true",
        help="Analyze even if a successful result exists for this analyzer version",
    )
    analyze_static.add_argument(
        "--log-level",
        type=log_level_name,
        default="INFO",
        help="File log level for analysis progress: DEBUG, INFO, WARNING, or ERROR",
    )
    analyze_static.add_argument(
        "--progress-every",
        type=positive_int,
        default=25,
        help="Write an aggregate progress log every N processed skills",
    )
    analyze_static.add_argument(
        "--max-consecutive-failures",
        type=positive_int,
        default=10,
        help="Stop pipeline if N consecutive skills fail (default: 10)",
    )
    analyze_static.add_argument(
        "--max-failure-rate",
        type=float,
        default=0.5,
        help="Stop pipeline if failure rate exceeds this threshold (default: 0.5)",
    )
    analyze_static.add_argument(
        "--min-processed-before-consecutive-check",
        type=positive_int,
        default=100,
        help="Minimum skills processed before consecutive failure check triggers (default: 100)",
    )
    analyze_static.add_argument(
        "--max-absolute-failures",
        type=positive_int,
        default=50,
        help="Stop pipeline if total failures exceed this count (default: 50)",
    )

    analyze_llm = subparsers.add_parser("analyze-llm", help="Run LLM analysis")
    analyze_llm.add_argument("--limit", type=non_negative_int, default=None, help="How many skills the pipeline processes in one run")
    analyze_llm.add_argument("--skill-id", type=positive_int, default=None)
    analyze_llm.add_argument("--force", action="store_true", help="Analyze even if a successful result exists for this analyzer version")
    analyze_llm.add_argument(
        "--risk-levels",
        nargs="+",
        type=risk_level_type,
        default=None,
        help="Risk levels to analyze e.g. --risk-levels critical high",
    )
    analyze_llm.add_argument(
        "--log-level",
        type=log_level_name,
        default="INFO",
        help="File log level for analysis progress: DEBUG, INFO, WARNING, or ERROR"
    )
    analyze_llm.add_argument(
        "--progress-every",
        type=positive_int,
        default=25,
        help="Write an aggregate progress log every N processed skills"
    )

    analyze_dynamic = subparsers.add_parser(
        "analyze-dynamic",
        help="Run dynamic analysis on LLM-confirmed critical/high shell-script skills",
    )
    analyze_dynamic.add_argument(
        "--limit", type=non_negative_int, default=None,
        help="Maximum number of skills to analyze",
    )
    analyze_dynamic.add_argument(
        "--force", action="store_true",
        help="Re-analyze even if a successful result already exists",
    )
    analyze_dynamic.add_argument(
        "--timeout-secs", type=positive_int, default=30,
        help="Per-script execution timeout in seconds (default: 30)",
    )
    analyze_dynamic.add_argument(
        "--total-timeout-secs", type=positive_int, default=120,
        help="Total timeout budget per skill across all scripts (default: 120)",
    )
    analyze_dynamic.add_argument(
        "--log-level", type=log_level_name, default="INFO",
        help="File log level: DEBUG, INFO, WARNING, or ERROR",
    )
    analyze_dynamic.add_argument(
        "--progress-every", type=positive_int, default=25,
        help="Write progress log every N processed skills",
    )
    analyze_dynamic.add_argument(
        "--max-consecutive-failures", type=positive_int, default=10,
        help="Stop pipeline if N consecutive skills fail (default: 10)",
    )
    analyze_dynamic.add_argument(
        "--max-failure-rate", type=float, default=0.5,
        help="Stop pipeline if failure rate exceeds this threshold (default: 0.5)",
    )
    analyze_dynamic.add_argument(
        "--min-processed-before-consecutive-check",
        type=positive_int,
        default=100,
        help="Minimum skills processed before consecutive failure check triggers (default: 100)",
    )
    analyze_dynamic.add_argument(
        "--max-absolute-failures",
        type=positive_int,
        default=50,
        help="Stop pipeline if total failures exceed this count (default: 50)",
    )
    subparsers.add_parser("summary", help="Print analysis result and finding counts")

    findings = subparsers.add_parser("findings", help="Print recent structured findings")
    findings.add_argument("--severity", choices=("low", "medium", "high"), default=None)
    findings.add_argument("--limit", type=positive_int, default=25)

    return parser


def configure_file_logging(command_name: str, log_level: str, logger_name: str = "openclaw.analysis") -> tuple[logging.Logger, Path]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = build_log_path(command_name)

    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, log_level))
    logger.propagate = False

    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(getattr(logging, log_level))
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)
    return logger, log_path


def build_log_path(command_name: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"{command_name}-{timestamp}.log"
    if not log_path.exists():
        return log_path

    suffix = 2
    while True:
        candidate = LOG_DIR / f"{command_name}-{timestamp}-{suffix}.log"
        if not candidate.exists():
            return candidate
        suffix += 1


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return parsed


def log_level_name(value: str) -> str:
    parsed = value.upper()
    if parsed not in LOG_LEVELS:
        raise argparse.ArgumentTypeError("value must be one of DEBUG, INFO, WARNING, or ERROR")
    return parsed

def risk_level_type(value:str) -> str:
    parsed = value.lower().strip()
    if parsed not in VALID_RISK_LEVELS:
        raise argparse.ArgumentTypeError(f"Invalid risk-level value. Choose from : critical, high, medium,low")
    return parsed
    

def print_summary(repo: AnalysisRepository) -> None:
    latest_run = repo.latest_run_summary()
    if latest_run is None:
        print("No analysis runs found.")
        return

    print(
        "Latest run: #{id} {analyzer_name} v{analyzer_version} status={status}".format(
            **latest_run
        )
    )
    print(f"Started: {latest_run['started_at']}")
    print(f"Finished: {latest_run['finished_at']}")
    print_counts("Latest run results", sorted(latest_run["result_counts"].items()))
    print_counts("Results by risk level", repo.results_by_risk_level())
    print_counts("Findings by category", repo.findings_by_category())
    print_counts("Findings by severity", repo.findings_by_severity())
    if latest_run["error_message"]:
        print(f"Run error: {latest_run['error_message']}")


def print_findings(repo: AnalysisRepository, severity: str | None, limit: int) -> None:
    rows = repo.findings(severity=severity, limit=limit)
    if not rows:
        qualifier = f" with severity={severity}" if severity else ""
        print(f"No findings{qualifier}.")
        return

    for finding in rows:
        print(
            "#{id} severity={severity} category={category} result={result_id} title={title}".format(
                id=finding.id,
                severity=finding.severity,
                category=finding.category,
                result_id=finding.analysis_result_id,
                title=finding.title,
            )
        )


def print_counts(title: str, counts: list[tuple[str, int]]) -> None:
    print(f"{title}:")
    if not counts:
        print("  none")
        return
    for label, count in counts:
        print(f"  {label}: {count}")


if __name__ == "__main__":
    raise SystemExit(main())
