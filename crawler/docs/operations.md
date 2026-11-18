# Operations

Running, scheduling, and monitoring crawls. Configuration comes from `.env` (DB URL,
`ARTIFACT_STORE`, S3 settings, optional `GITHUB_TOKEN`).

## Manual crawl commands

Run from the project root (uses the venv interpreter directly):

```bash
# ClawHub
./venv/bin/python cli.py crawl --source clawhub

# GitHub (uses GITHUB_TOKEN from env/.env if present; not required)
./venv/bin/python cli.py crawl --source github-skills

# Re-fetch existing artifacts and record changed bytes as new snapshot rows
./venv/bin/python cli.py crawl --source clawhub --verify-existing

# Re-download artifacts for rows already in the DB (in-place update; no new rows)
./venv/bin/python cli.py backfill --source clawhub
```

Useful flags: `--limit N` (stop after N skills), `--page-size N` (ClawHub listing),
`--delay S` (seconds between HTTP requests), `-v` (DEBUG logging).

### Crawl modes

| Mode | Flag | DB writes | Artifact fetch/store | Use for |
|------|------|-----------|----------------------|---------|
| **Dry run** | `--dry-run` | none | none | validating discovery; counting `SKILL.md` per repo |
| **Metadata only** | `--metadata-only` | stub rows (NULL `artifact_hash`/`artifact_uri`, `revision` set) | none | fast inventory; legally-sensitive sources |
| **Full** | (default) | full rows | yes | normal collection |

Notes:
- Full crawls use **revision-aware detection**: a skill already stored at the same `revision` is
  skipped (timestamps touched, no download). See [sources.md](sources.md#update-detection).
- `--metadata-only` then a later full crawl: the stub is upgraded — the full crawl fetches it
  because the stub has no `artifact_hash`.

### Periodic verification (ClawHub, ~weekly)

ClawHub has no revision, so a normal crawl skips re-downloading a known `(slug, version)`. But
ClawHub has been observed serving different bytes under the same version, which a plain crawl
won't notice. `--verify-existing` re-downloads known artifacts and inserts a new hash row when
the bytes changed (old rows preserved as mutation evidence):

```bash
./venv/bin/python cli.py crawl --source clawhub --verify-existing
```

This is **scheduled** (~every 10 days) via `openclaw-crawler-verify@clawhub.timer` — see
[Scheduling](#scheduling-systemd-per-source) below; you don't normally run it by hand. GitHub
needs no equivalent: a changed repo HEAD already changes `revision`, which triggers a re-fetch
automatically.

## Scheduling (systemd, per source)

Crawls are one-shot processes scheduled by **one timer per source**, built on a single templated
service [`deploy/openclaw-crawler@.service`](../deploy/openclaw-crawler@.service) whose instance
name (`%i`) is the source:

| Source | Timer | Cadence |
|--------|-------|---------|
| `clawhub` (normal) | `openclaw-crawler@clawhub.timer` | every 48h (`OnUnitActiveSec`) |
| `clawhub` (verify) | `openclaw-crawler-verify@clawhub.timer` | ~every 10 days (`OnCalendar=*-*-02,12,22 12:00`) |
| `github-skills` | `openclaw-crawler@github-skills.timer` | daily (`OnCalendar`, `Persistent=true`) |

The verify schedule uses a second templated service
[`deploy/openclaw-crawler-verify@.service`](../deploy/openclaw-crawler-verify@.service)
(`crawl --source %i --verify-existing`).

**Why source-level, not per-repo:** one source run already crawls all of its seed repos, and
revision-aware detection skips unchanged repos cheaply — a per-repo timer fan-out would be many
more units to manage for no isolation benefit.

**ClawHub verify (~10 days) — blocking, not phased.** The normal clawhub crawl is long
(~20–27h observed) and runs every 48h, so it occupies a large fraction of the time; there is no
reliable fixed-time window to "slot" the verify into (and the normal timer's phase drifts). So
the verify does **not** try to dodge the normal crawl by timing — it acquires the shared clawhub
lock with a **blocking wait** (`flock -w`, 48h cap). If a normal crawl is running when verify
fires (days 2/12/22, 12:00 UTC), verify **waits** for it to finish and then runs — it is not
skipped. While verify holds the lock, a normal crawl that fires is skipped (`flock -n`) and
resumes its next 48h cycle. The shared lock guarantees the two never run concurrently; the
normal 48h timer is unchanged. (This replaced an earlier, fragile 12h time-of-day offset.)

**GitHub cadence (daily):** unchanged repos skip the tarball download, so a no-change day costs
only a few API calls per repo; daily gives finer mutation-detection granularity than weekly at
negligible cost. Switch `OnCalendar=daily` → `weekly` to lighten it.

### Per-source locks (concurrency)

Each instance runs under `flock -n /tmp/openclaw-crawler-%i.lock`:

- a source **never overlaps itself** (a second invocation exits immediately while its own run is
  active);
- a source's **normal and verify crawls share the same lock** (`openclaw-crawler@clawhub` and
  `openclaw-crawler-verify@clawhub` both lock `/tmp/openclaw-crawler-clawhub.lock`), so they
  never run simultaneously. The normal crawl is non-blocking (`flock -n`, skips if busy); the
  verify crawl is **blocking** (`flock -w` 48h, waits for an in-progress normal crawl) so it is
  not perpetually skipped by the long normal crawl;
- **different sources may run concurrently** — their `skills.source` rows and `{source}/…` S3
  prefixes are disjoint, so there is no DB or storage contention.

### Production checkout vs development checkout

Scheduled crawls run from a dedicated **production clone** at
`/home/ubuntu/openclaw-crawler-prod` (the units' `WorkingDirectory`), which is always on
`main`. The development checkout at `/home/ubuntu/openclaw-skill-crawling` can sit on any
branch or dirty state without affecting scheduled runs — timers execute whatever code the
production clone contains, never the dev tree. The two checkouts share the per-source
`/tmp/openclaw-crawler-<source>.lock` files, so a manual dev-tree crawl still cannot
overlap a scheduled one.

**Deploy step after merging a PR** (this is what makes a merge take effect):

```bash
cd /home/ubuntu/openclaw-crawler-prod
git pull
# only if requirements.txt changed:
./venv/bin/pip install -r requirements.txt
```

The prod clone has its own `venv/` and a copied `.env` (both gitignored). Deploy cheat
sheet by change type:

| Merged change touches | Deploy action (in `/home/ubuntu/openclaw-crawler-prod`) |
|-----------------------|----------------------------------------------------------|
| code / docs / scripts | `git pull` (sufficient on its own) |
| `requirements.txt` | `git pull && ./venv/bin/pip install -r requirements.txt` |
| configuration | edit **both** `.env` files by hand (gitignored, never pulled) — prod's is the one scheduled crawls read |
| `deploy/*.service` / `*.timer` | `git pull`, then `sudo cp deploy/* /etc/systemd/system/ && sudo systemctl daemon-reload` |

If prod ever behaves like old code, compare `git -C /home/ubuntu/openclaw-crawler-prod
log -1` against `origin/main` — an un-pulled merge is the usual cause.

### Install / enable (run as root on the host)

> Do this only when ready — and for `github-skills`, after a manual validation crawl.

```bash
cd /home/ubuntu/openclaw-crawler-prod
sudo cp deploy/openclaw-crawler@.service             /etc/systemd/system/
sudo cp deploy/openclaw-crawler-verify@.service      /etc/systemd/system/
sudo cp deploy/openclaw-crawler@clawhub.timer        /etc/systemd/system/
sudo cp deploy/openclaw-crawler-verify@clawhub.timer /etc/systemd/system/
sudo cp deploy/openclaw-crawler@github-skills.timer  /etc/systemd/system/
sudo systemctl daemon-reload
```

Migrating off the old single-source units (if previously installed) — do it when no clawhub run
is mid-flight:

```bash
sudo systemctl disable --now openclaw-crawler.timer
sudo rm -f /etc/systemd/system/openclaw-crawler.service /etc/systemd/system/openclaw-crawler.timer
sudo systemctl daemon-reload
```

Enable the timers:

```bash
sudo systemctl enable --now openclaw-crawler@clawhub.timer
sudo systemctl enable --now openclaw-crawler-verify@clawhub.timer
# GitHub — only after manual validation:
sudo systemctl enable --now openclaw-crawler@github-skills.timer
```

### Status & logs

```bash
sudo systemctl list-timers 'openclaw-crawler*'                  # next scheduled runs
sudo systemctl status openclaw-crawler@github-skills.service     # last run result
sudo journalctl -u openclaw-crawler@clawhub.service -f           # follow journal
sudo journalctl -u openclaw-crawler@github-skills.service -n 100
```

Crawl run history also lives in the `crawl_runs` table (status + `stats` JSONB).

## File logging

Each crawl/backfill writes a file log under a **per-source** directory:

```
logs/<source>/<command>_<timestamp>.log     e.g. logs/github-skills/crawl_20260628_035443.log
```

- Source-level only — **no per-repo subfolders**.
- `logs/` is gitignored; the systemd journal is authoritative for scheduled runs.
- Logging is configured once in `cli.py:main()` (`logging.basicConfig` + a `FileHandler`); all
  modules log via `logging.getLogger(__name__)`.

## What not to run concurrently

- **Same source twice.** Don't start a second `--source X` while one is running. The systemd
  per-source lock enforces this for scheduled runs; for manual runs, check first
  (`systemctl status openclaw-crawler@X.service`, `pgrep -af "cli.py crawl --source X"`).
- **Different sources together: fine.** clawhub + github-skills may run at once (disjoint rows
  and S3 prefixes — verified in practice).
- **`backfill` / `--verify-existing` vs a normal crawl of the same source:** avoid overlapping
  these; they operate on the same rows/artifacts. Different sources are still independent.
- **Migrations (`scripts/migrate_*.py`):** they alter schema — don't run while a crawl of any
  source is writing. They are idempotent but should be run during a quiet window.
- **Destructive cleanup** (deleting `source=` rows / `{source}/` S3 objects): never run against a
  source that is mid-crawl.
