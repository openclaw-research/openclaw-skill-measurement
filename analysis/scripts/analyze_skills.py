"""Run the production static analyzer against real skills from the database.

Convenience CLI wrapper around StaticAnalysisPipeline for targeted re-analysis
(single skill or bounded batch) during development and validation. For full
production runs, invoke via cli.py.

Usage:
    venv/bin/python scripts/analyze_skills.py --limit 50
    venv/bin/python scripts/analyze_skills.py --skill-id 123
    venv/bin/python scripts/analyze_skills.py --limit 100 --force

Results are tagged with ``analyzer_name='static'`` and ``analyzer_version='4'``.

Querying results:
    SELECT risk_level, count(*)
    FROM analysis_results
    WHERE analyzer_name = 'static'
    GROUP BY 1 ORDER BY 2 DESC;
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# Make the project root importable when run from tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import get_settings  # noqa: E402
from db.repository import (  # noqa: E402
    SchemaError,
    inspect_skills_schema,
    missing_analysis_tables,
)
from db.session import build_engine, build_session_factory  # noqa: E402
from pipeline.static_pipeline import StaticAnalysisPipeline  # noqa: E402
from analyzers.static.analyzer import StaticAnalyzer  # noqa: E402


LOG_DIR = Path("logs")
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run static analyzer against real skills from the database."
    )
    parser.add_argument("--limit", type=int, default=None, help="Max skills to analyze")
    parser.add_argument("--skill-id", type=int, default=None, help="Analyze one specific skill")
    parser.add_argument(
        "--force", action="store_true", help="Re-analyze even if a static analysis result exists"
    )
    parser.add_argument("--log-level", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR")
    parser.add_argument("--progress-every", type=int, default=25, help="Progress log interval")
    args = parser.parse_args(argv)

    settings = get_settings()
    engine = build_engine(settings)

    try:
        inspect_skills_schema(engine)
    except SchemaError as exc:
        print(f"Schema error: {exc}", file=sys.stderr)
        return 2

    missing = missing_analysis_tables(engine)
    if missing:
        print(
            f"Missing analysis tables: {', '.join(missing)}. "
            "Run `python cli.py init-db` first.",
            file=sys.stderr,
        )
        return 2

    logger, log_path = configure_logging(args.log_level)
    analyzer = StaticAnalyzer()

    print(f"static analyzer: name={analyzer.name!r} version={analyzer.version!r}")
    print(f"Results will be tagged: analyzer_name='{analyzer.name}' in the database")
    print(f"Writing log to {log_path}")

    pipeline = StaticAnalysisPipeline(
        settings,
        build_session_factory(engine),
        analyzer=analyzer,
        logger=logger,
    )

    summary = pipeline.run(
        limit=args.limit,
        skill_id=args.skill_id,
        force=args.force,
        progress_every=args.progress_every,
    )

    print(
        "\nstatic analysis run #{analysis_run_id}: "
        "selected={selected}, skipped={skipped}, "
        "succeeded={succeeded}, failed={failed}, "
        "analyzer={analyzer_name} v{analyzer_version}".format(**summary)
    )
    print(f"Log: {log_path}")
    return 0


def configure_logging(log_level: str) -> tuple[logging.Logger, Path]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"analyze-skills-{timestamp}.log"

    logger = logging.getLogger("openclaw.analysis")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.propagate = False

    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)

    return logger, log_path


if __name__ == "__main__":
    raise SystemExit(main())