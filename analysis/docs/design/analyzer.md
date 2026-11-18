# Static Analyzer Design

The static analyzer is deterministic and never executes artifact code. It lives
under `analyzers/static/` and is split by responsibility so rules, scanning,
extraction, scoring, and orchestration can change independently.

## Module layout

| Module | Responsibility |
| --- | --- |
| `analyzer.py` | High-level orchestrator only. Validates the root, calls `scan_tree`, computes risk/findings/summary, and assembles `result_json`. Re-exports `StaticAnalyzer` and `COLLECTOR_METADATA_FILES` as the package's public entry point. |
| `inventory.py` | Single-pass traversal of the artifact directory. Assigns region tags, builds `ScanState` (inventory, extension counts, important-file flags, indicators, env/URL evidence, parsed-file context), and routes collector metadata. Calls the normalization pass before scanning each file. |
| `normalize.py` | Three-step text normalization pass run per file before indicator matching: (1) NFKC Unicode normalization, (2) zero-width and bidi control character stripping, (3) Cyrillic-to-Latin homoglyph folding. Returns a `NormalizationResult` with per-transform counts for the `normalization_stats` block in `result_json`. |
| `rules/definitions.py` | Data only: finding categories, match terms, combo regex patterns, env/URL regexes, file-classification sets, and size/evidence limits. **The single place to edit the rule set.** |
| `rules/matching.py` | Indicator matching helpers (`scan_text_indicators`, `scan_combo_patterns`, `scan_path_indicators`, `scan_env_var_references`, `scan_urls`) and evidence accumulation (`add_evidence`). Implements per-term region weighting, boundary checking, and case-sensitivity controls via the `TermConfig` dataclass. |
| `text.py` | Text reading (`read_text_for_analysis`) and snippet truncation (`snippet_for_line`). |
| `extraction.py` | Parsed-file context for `SKILL.md` (case-insensitive), `_meta.json`, `package.json`, `requirements.txt`, and lightweight code-file context. `package.json` install scripts also contribute `dependency_or_install_script` evidence. |
| `scoring.py` | Risk-level heuristic (`calculate_risk_level`) and the human-readable result summary (`build_summary`). |
| `findings.py` | Structured finding construction from accumulated indicators. Applies cross-category escalation rules (`ESCALATION_RULES`) before per-category findings. |

Dependency direction is one-way and import-cycle-free:

```
analyzer.py
  └── inventory.py
        ├── normalize.py
        ├── extraction.py
        ├── rules/matching.py
        └── text.py
analyzer.py also imports:
  ├── scoring.py
  └── findings.py
        (all leaf to) rules/definitions.py
```

## Single-pass traversal

`scan_tree` in `inventory.py` processes each file completely before moving to
the next. For each file the order is:

1. Assign a region tag (see [Region tagging](#region-tagging)).
2. Route collector metadata files — skip content scanning entirely.
3. Match the file path against path-checked indicator categories.
4. Read file text (`read_text_for_analysis`); skip if binary (null bytes) or
   larger than `MAX_TEXT_BYTES` (1 MB).
5. Run the normalization pass (`normalize.py`).
6. Run `scan_text_indicators` with the file's region tag.
7. Run `scan_combo_patterns` against the full file text.
8. Run `scan_env_var_references`.
9. Run `scan_urls`.
10. Run `extract_file_context`.

This ordering — plus the per-category evidence cap (`MAX_EVIDENCE_PER_CATEGORY`)
— is part of the observable output contract. Traversal is intentionally a single
pass rather than separate inventory and content passes.

## Region tagging

Every file in the inventory receives a `region` tag used to weight indicator
evidence. Region weights reduce false positives from documentation mentions of
sensitive terms while preserving full-weight detection in executable code.

| Region | File types | Weight policy |
| --- | --- | --- |
| `bundled_code` | `.py`, `.js`, `.ts`, `.sh`, `.rb`, `.go`, `.rs`, `.ps1`, and other executable extensions | Full weight (1.0) for all indicators |
| `config` | `.json`, `.yaml`, `.yml`, `.toml`, `.ipynb` | Full weight for secret and credential terms; reduced for network terms |
| `dependency` | `requirements.txt`, `package.json`, `Pipfile`, `go.mod`, `Cargo.toml`, etc. | Full weight |
| `prose` | `.md`, `.txt`, `.rst`, `.html`, `.css` | Low weight (0.1 default) for most terms |
| `binary` | `.exe`, `.dll`, `.so`, `.pyc` | Not text-scanned; recorded in inventory only |
| `symlink` | Symlinks | Path-scanned only |

Region weights are defined per term in `rules/definitions.py` using the
`region_weights` dict on each term entry. The default weight for regions not
listed in `region_weights` is `DEFAULT_REGION_WEIGHT = 0.1` (Policy C). Terms
with an explicit `0.0` weight in a region are hard-gated and produce no evidence
for that region. Evidence with weight below `COUNT_THRESHOLD = 1.0` is still
recorded for the LLM layer but does not increment the indicator count used by
risk scoring.

## Normalization pass

Before indicator matching, each file's text passes through `normalize.py`:

1. **NFKC normalization** — collapses compatibility-equivalent Unicode variants
   (e.g. fullwidth characters, ligatures).
2. **Invisible character stripping** — removes zero-width spaces (U+200B–U+200D),
   BOM (U+FEFF), bidi formatting characters (U+202A–U+202E), bidi isolates
   (U+2066–U+2069), and Unicode tag characters (U+E0000–U+E007F) used in
   ASCII-smuggling attacks.
3. **Cyrillic-to-Latin homoglyph folding** — maps the seven most common Cyrillic
   lookalikes (а/е/о/р/с/х/у and their uppercase forms) to their Latin
   equivalents.

Counts for each transform are recorded in `result_json["normalization_stats"]`
with a per-file breakdown under `files_with_transforms`.

## Collector-generated metadata

Files in `COLLECTOR_METADATA_FILES` are appended by the crawler and are **not**
developer-authored skill content. They are recorded in
`result_json["collector_metadata_files"]` for inventory traceability but are
never scanned, so they do not contribute to indicators, URLs, env vars,
extension counts, `file_count`, or risk.

The current exclusion set is:

| File | Reason for exclusion |
| --- | --- |
| `_detail.json` | Marketplace listing metadata (URLs, descriptions, publisher info). Scanning inflates `secret_handling`, `network_access`, and `external_urls`. Added in v3. |
| `skill-card.md` | Auto-generated by ClawScan. Contains system prompt references and descriptive prose that trigger `suspicious_prompting` on benign skills. Added in v4. |

`_meta.json` is developer-authored skill metadata and is **not** in this
exclusion set.

If the crawler adds new metadata files in the future, add them to
`COLLECTOR_METADATA_FILES` in `rules/definitions.py` and bump the analyzer
version.

See [database.md](database.md) for how exclusion affects stored measurements.

## Indicator categories

The analyzer defines 14 indicator categories across four severity tiers. Risk
scoring uses co-occurrence logic across these categories (see
[Risk scoring](#risk-scoring)).

### Critical

| Category | Description |
| --- | --- |
| `reverse_shell_patterns` | `/dev/tcp/`, `bash -i`, `nc -e`, `socat exec`, `pty.spawn`, `os.dup2`, PowerShell socket patterns, etc. |

### High

| Category | Description |
| --- | --- |
| `credential_theft_targets` | Well-known credential file paths: SSH keys, cloud provider configs (`.aws/credentials`, `.kube/config`), browser credential stores, macOS Keychain commands, crypto wallet paths and seed phrase terms. |
| `exfiltration_channels` | Webhook services (Discord, Slack hooks), paste sites (Pastebin, Hastebin), Telegram bot API, tunnelling services (ngrok, serveo), OOB testing domains (Burp Collaborator, interact.sh). |
| `obfuscation_techniques` | Base64 decode (`b64decode`, `atob`), serialisation (`pickle.loads`, `marshal.loads`), compression decompress calls, `String.fromCharCode`, `Buffer.from`. |
| `download_and_execute` | `curl`/`wget` piped to interpreter, PowerShell `Invoke-Expression`/`DownloadString`/`Start-Process`, `urlretrieve`. HTTP fetch → exec chains caught by COMBO-014. |
| `suspicious_prompting` | Prompt injection keywords: "ignore previous instructions", "system prompt", "exfiltrate", "bypass safety", "without telling", agent coercion patterns. |

### Medium

| Category | Description |
| --- | --- |
| `persistence_mechanisms` | `crontab`, `LaunchAgents`/`LaunchDaemons`, `systemctl enable`, shell profile modification (`.bashrc`, `.zshrc`), Windows `schtasks`, `nohup`, `screen -dm`. |
| `network_access` | `http://`/`https://`, `import requests`, `requests.get`/`.post`, `urllib.request`, `httpx`, `aiohttp`, `fetch(`, `axios`, `curl`, `wget`, `socket.connect`. |
| `filesystem_access` | `/tmp`, `/home`, `open(` (word-boundary matched, does not fire inside `urlopen(`), `.write(`, `unlink`, `rmtree`, `rm`, `mkdir`, `chmod`, `shutil.copy`, `fs.readFile`/`fs.writeFile`. |
| `secret_handling` | `password`, `token`, `api_key`, `secret`, `credential`, `authorization`, `bearer`, `.env`, `private_key`, `access_token`, `refresh_token`. |
| `hidden_content` | Markdown reference-link injection (`[//]: #`), zero-width Unicode chars, Cyrillic homoglyphs, CSS/HTML hiding (`display:none`, `visibility:hidden`, `font-size:0`). |
| `dependency_or_install_script` | `postinstall`, `preinstall`, `install.sh`, `pip install`, `npm install`, `curl -fs`, `npx`, etc. Also fired by `package.json` install script fields. |
| `process_execution` | `subprocess`, `os.system`, `os.popen`, `eval(`, `spawn(`, `child_process`, `shell=True`, `shell_exec`, `Runtime.exec`. |

### Low

| Category | Description |
| --- | --- |
| `hook_or_tool_exposure` | Paths or content referencing hooks, tools, or OpenClaw integration points: `hooks/`, `tools/`, `.claude/`, `mcp`, `.clawhub/`, `sessions.json`. |

## Combo patterns

`COMBO_PATTERNS` in `rules/definitions.py` defines 14 multi-token regex patterns
that fire when two or more tokens appear in a specific relationship. Combo
patterns run against the full file text (not line-by-line) after
`scan_text_indicators` completes for each file. Evidence is recorded in the
category bucket named in the pattern's `category` field.

| ID | Category | Severity | Description |
| --- | --- | --- | --- |
| COMBO-001 | `obfuscation_techniques` | critical | Base64 decode piped to execution (`b64decode`/`atob` → `eval`/`exec`/`popen`) |
| COMBO-006 | `reverse_shell_patterns` | critical | Socket + subprocess combination (textbook reverse shell) |
| COMBO-011 | `download_and_execute` | critical | Remote script piped to interpreter (`curl`/`wget` → `sh`/`python`/`perl`) |
| COMBO-014 | `download_and_execute` | critical | HTTP fetch (`urlopen`, `urlretrieve`, `requests.get/post`) followed by execution (`exec`, `eval`, `subprocess`, `os.system`) |
| COMBO-007 | `exfiltration_channels` | high | DNS lookup with command substitution (`dig`/`nslookup` + `${}`) |
| COMBO-008 | `hidden_content` | high | HTML comment containing action keywords (`curl`, `exec`, `eval`, etc.) |
| COMBO-009 | `hidden_content` | high | Markdown reference link with action keywords |
| COMBO-010 | `secret_handling` | high | Specific high-value API key accessed via `os.environ`/`process.env` |
| COMBO-012 | `obfuscation_techniques` | high | `eval()` with dynamic string construction |
| COMBO-013 | `suspicious_prompting` | high | Agent secrecy instruction ("silently run", "without telling the user") |
| COMBO-002 | `obfuscation_techniques` | medium | Long base64 string literal (200+ chars) |
| COMBO-003 | `obfuscation_techniques` | medium | Long hex escape sequence (6+ consecutive `\xNN`) |
| COMBO-004 | `obfuscation_techniques` | medium | `String.fromCharCode` with 4+ arguments |
| COMBO-005 | `obfuscation_techniques` | medium | Python `chr()` concatenation chain (3+ calls) |

## Risk scoring

Risk is a deterministic heuristic over indicator counts computed by
`calculate_risk_level` in `scoring.py`. The tiers are evaluated in order; the
first matching tier is returned.

| Tier | Condition |
| --- | --- |
| `critical` | `reverse_shell_patterns` > 0, OR `download_and_execute` > 0 with `network_access` or `process_execution` > 0, OR `credential_theft_targets` > 0 with `exfiltration_channels` > 0 |
| `high` | `secret_handling` + (`network_access` or `process_execution`), OR `suspicious_prompting` + (`network_access` or `process_execution`), OR `credential_theft_targets` + (`network_access` or `process_execution`), OR `exfiltration_channels` > 0, OR `obfuscation_techniques` + (`network_access` or `process_execution`), OR `download_and_execute` > 0, OR `suspicious_prompting` > 0 |
| `medium` | Any of: `network_access`, `process_execution`, `filesystem_access`, `secret_handling`, `dependency_or_install_script`, `persistence_mechanisms`, `hidden_content` |
| `low` | At least one indicator fired across any category |
| `none` | Zero indicators across all categories |

## Findings construction

`build_findings` in `findings.py` constructs the structured findings list in
three stages:

**1. Cross-category escalation (`ESCALATION_RULES`)** — evaluated first. Each
rule fires when a primary category has hits and at least one required category
also has hits, producing a finding at the escalated severity. Multiple rules can
fire for the same skill. Examples:

- `credential_theft_targets` + `exfiltration_channels` → critical
- `reverse_shell_patterns` + (`network_access` or `process_execution`) → critical
- `secret_handling` + (`network_access` or `process_execution`) → high
- `suspicious_prompting` + (`network_access` or `process_execution`) → high
- `obfuscation_techniques` + (`network_access` or `process_execution`) → high
- `download_and_execute` + `network_access` → high

**2. Per-category findings** — one finding per category with at least one hit,
using the base severity from `FINDING_RULES`. Categories that fired an
escalation rule have their standalone severity bumped to match.

**3. Auxiliary findings** — a `secret_handling` low-severity finding for
env var references, and a `network_access` low-severity finding for external
URLs, when either list is non-empty.

## Parsed-file extraction

`extract_file_context` in `extraction.py` populates `result_json["parsed_files"]`
with structured context for recognized files. Filename matching is
**case-insensitive** (v4.1 fix).

| File (case-insensitive) | Extracted context |
| --- | --- |
| `SKILL.md` | Line count, heading list (up to 25 headings) |
| `_meta.json` | Top-level JSON keys |
| `package.json` | Dependencies, dev dependencies, scripts list, install scripts (`preinstall`, `install`, `postinstall`, `prepare`). Install scripts also add evidence to `dependency_or_install_script`. |
| `requirements.txt` | Package names (sorted) |
| `.py` files | Line count, shebang presence |
| `.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs` files | Line count, shebang presence |
| `.sh`/`.bash`/`.zsh` files and shebang scripts | Line count, shebang presence |

The `important_files` flag in `result_json` records whether each of
`SKILL.md`, `_meta.json`, `README.md`, `package.json`, and
`requirements.txt` was found in the artifact. Matching is case-insensitive:
a file named `skill.md` correctly sets `important_files["SKILL.md"] = true`.

## Versioning

`StaticAnalyzer.version` identifies the rule/output contract, not the class
name. The class is named `StaticAnalyzer` (version-agnostic); the active version
is the `version` attribute.

**Bump `version` when:**
- a new finding category is added or removed
- scanning logic changes in a way that makes old and new results incomparable
- the `result_json` schema changes in a breaking way

**Do not bump `version` when:**
- a pure refactor preserves all output
- a minor correction affects only a small subset of skills and results remain
  comparable (use a minor version such as `"4.1"` instead)

A version bump forces re-analysis of every previously-analyzed skill on the next
run without `--force`, because skip logic keys on
`(skill_id, artifact_hash, analyzer_name, analyzer_version)`. A minor version
bump (e.g. `"4"` → `"4.1"`) forces re-analysis only of skills whose results
differ under the new behavior.

### Version history

| Version | Change summary |
| --- | --- |
| `1` | Initial implementation. |
| `2` | Rule and output refinements. Full corpus run June 2026. Includes `_detail.json` content (pre-exclusion). |
| `3` | Excluded `_detail.json` from content analysis (`COLLECTOR_METADATA_FILES`). Results from v2 are considered polluted for corpus-level statistics. Full corpus run June 2026. |
| `4` | Seven new indicator categories (`reverse_shell_patterns`, `credential_theft_targets`, `exfiltration_channels`, `obfuscation_techniques`, `download_and_execute`, `hidden_content`, `persistence_mechanisms`). Existing categories refined. 13 combo regex patterns. Region-aware weighted term matching. Per-file normalization pass. Cross-category escalation rules. `skill-card.md` added to `COLLECTOR_METADATA_FILES`. Risk tiers `critical` and `none` added. Full corpus run July 2026 (run #71, 93,936 skills). |
| `4.1` | Minor correction: `SKILL.md` filename matching in `extraction.py` and `inventory.py` changed to case-insensitive. Affects ~6 skills with lowercase `skill.md` filenames whose `parsed_files["skill_md"]` was previously null. No category, scoring, or schema change. |
| `4.2` | False positive reduction: removed `urlopen(` and `urllib.request.urlopen` from `download_and_execute` terms (standard HTTP client calls were incorrectly triggering `critical` risk on legitimate API skills such as `kraken` and `tesla-commands`). Added COMBO-014 to preserve detection of genuine HTTP fetch → exec chains. Added word boundary to `open(` in `filesystem_access` to prevent false substring match inside `urlopen(`. Sibling snapshot deduplication: `StaticAnalysisPipeline` now computes a `content_hash` over developer-authored files only (excluding `COLLECTOR_METADATA_FILES`); snapshots that share a `(source, source_id, version)` tuple but differ only by collector-generated metadata (`skill-card.md`, `_detail.json`) are skipped without re-analysis. `content_hash` stored in `result_json["artifact"]["content_hash"]`. |

The active production version is **`4.2`**. Run #71 (`static v4`, July 2026)
is the current clean corpus baseline; v4.2 re-analyzes only skills affected by
the false positive fixes or sibling deduplication logic.