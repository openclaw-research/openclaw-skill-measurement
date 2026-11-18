"""Command-line entry point for the skill collector.

Commands:
    init-db   Create database tables (safe to re-run; uses CREATE IF NOT EXISTS).
    crawl     Run a skill crawl for a named source.
    backfill  Re-fetch full ZIP artifacts for skills already in the DB.

The active storage backend and database connection are controlled entirely
through environment variables (see .env). Crawl behaviour (limits, delays,
dry-run) is controlled via CLI flags at invocation time.
"""

import argparse
import datetime
import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()


# Single registry of available sources, keyed by the --source value. Adding a new
# source means adding one entry here; both crawl and backfill resolve through it,
# so there is no per-command source map to keep in sync.
def _source_registry():
    """Return the {name: BaseSource subclass} registry.

    Imports are done lazily inside the function so that importing cli.py (e.g. for
    --help) does not pull in every source's dependencies.
    """
    from sources.clawhub import ClawHubSource
    from sources.github import GitHubSkillsSource

    return {
        "clawhub": ClawHubSource,
        "github-skills": GitHubSkillsSource,
    }


def _resolve_source_class(name: str):
    """Look up a source class by name, exiting with a clear message if unknown."""
    registry = _source_registry()
    if name not in registry:
        print(
            f"Unknown source '{name}'. Available: {', '.join(registry)}",
            file=sys.stderr,
        )
        sys.exit(1)
    return registry[name]


def _build_store():
    """Instantiate the artifact store selected by ARTIFACT_STORE env var (default: local)."""
    backend = os.environ.get("ARTIFACT_STORE", "local").lower()
    if backend == "s3":
        from storage.s3 import S3ArtifactStore
        return S3ArtifactStore()
    if backend == "local":
        from storage.local import LocalArtifactStore
        return LocalArtifactStore()
    print(f"Unknown ARTIFACT_STORE value '{backend}'. Choose 'local' or 's3'.", file=sys.stderr)
    sys.exit(1)


def cmd_crawl(args):
    """Run a crawl for the specified source using the configured storage backend."""
    from pipeline import run_crawl

    source_cls = _resolve_source_class(args.source)
    source = source_cls(
        page_size=args.page_size,
        max_skills=args.limit,
        delay=args.delay,
    )
    store = _build_store()

    print(f"Starting crawl: source={source.source_name}, store={type(store).__name__}"
          + (" [DRY RUN]" if args.dry_run else "")
          + (" [METADATA ONLY]" if args.metadata_only and not args.dry_run else ""))

    result = run_crawl(
        source, store,
        dry_run=args.dry_run,
        verify_existing=args.verify_existing,
        metadata_only=args.metadata_only,
    )

    if args.dry_run:
        print("Dry-run complete.")
    else:
        print(f"Crawl complete: run_id={result['run_id']}")
    print(json.dumps(result["stats"], indent=2))


def cmd_backfill(args):
    """Re-fetch full ZIP artifacts for skills already in the DB."""
    from pipeline import run_backfill

    source_cls = _resolve_source_class(args.source)
    source = source_cls(delay=args.delay)
    store = _build_store()

    print(
        f"Starting backfill: source={source.source_name}, store={type(store).__name__}"
        + (" [FORCE]" if args.force else "")
        + (" [DRY RUN]" if args.dry_run else "")
    )

    result = run_backfill(source, store, dry_run=args.dry_run, force=args.force, limit=args.limit)

    if args.dry_run:
        print("Dry-run backfill complete.")
    else:
        print(f"Backfill complete: run_id={result['run_id']}")
    print(json.dumps(result["stats"], indent=2))


def cmd_init_db(args):
    """Create all database tables. Safe to re-run (skips existing tables)."""
    from db.models import Base
    from db.session import engine

    print("Creating tables...")
    Base.metadata.create_all(engine)
    print("Done.")


def main():
    parser = argparse.ArgumentParser(prog="collector", description="OpenClaw skill collector")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-db", help="Create database tables")
    p_init.set_defaults(func=cmd_init_db)

    p_crawl = sub.add_parser("crawl", help="Run a skill crawl")
    p_crawl.add_argument(
        "--source", default="clawhub",
        help="Source to crawl (default: clawhub)",
    )
    p_crawl.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Stop after crawling N skills (default: no limit)",
    )
    p_crawl.add_argument(
        "--page-size", type=int, default=100, metavar="N",
        help="Results per listing page (default: 100)",
    )
    p_crawl.add_argument(
        "--delay", type=float, default=0.1, metavar="SECS",
        help="Seconds between HTTP requests (default: 0.1)",
    )
    p_crawl.add_argument(
        "--dry-run", action="store_true",
        help="Discover skills without writing to DB or storage",
    )
    p_crawl.add_argument(
        "--metadata-only", action="store_true",
        help="Persist metadata stubs but do not download or store artifacts",
    )
    p_crawl.add_argument(
        "--verify-existing", action="store_true",
        help=(
            "Re-download artifacts for known (slug, version) pairs and insert a new DB row "
            "if the hash has changed. Historical rows are preserved. Recommended weekly."
        ),
    )
    p_crawl.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG logging",
    )
    p_crawl.set_defaults(func=cmd_crawl)

    p_backfill = sub.add_parser("backfill", help="Re-fetch full ZIP artifacts for existing skills")
    p_backfill.add_argument(
        "--source", default="clawhub",
        help="Source to backfill (default: clawhub)",
    )
    p_backfill.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Process at most N skill rows (default: no limit)",
    )
    p_backfill.add_argument(
        "--delay", type=float, default=0.1, metavar="SECS",
        help="Seconds between HTTP requests (default: 0.1)",
    )
    p_backfill.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be updated without writing anything",
    )
    p_backfill.add_argument(
        "--force", action="store_true",
        help="Re-download and re-store even when the artifact hash is unchanged",
    )
    p_backfill.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG logging",
    )
    p_backfill.set_defaults(func=cmd_backfill)

    args = parser.parse_args()

    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    log_format = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=log_format)

    if args.command in ("crawl", "backfill"):
        # Per-source log directory: logs/<source>/<command>_<timestamp>.log.
        # Source-level only — no per-repo subfolders.
        source = getattr(args, "source", "unknown")
        log_dir = os.path.join("logs", source)
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(log_dir, f"{args.command}_{ts}.log")
        fh = logging.FileHandler(log_path)
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(fh)
        print(f"Logging to {log_path}")

    args.func(args)


if __name__ == "__main__":
    main()
