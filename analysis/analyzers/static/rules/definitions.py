"""Static analyzer rule and pattern definitions (v4).

Adds seven new indicator categories, refines existing terms, and introduces combo regex
patterns for multi-token detection. See the module-level comment block for the
category layout.

v4 changes from v3:
  - Seven new categories: reverse_shell_patterns, credential_theft_targets,
    exfiltration_channels, obfuscation_techniques, download_and_execute,
    hidden_content, persistence_mechanisms.
  - Existing categories refined: noisy terms removed, missing terms added,
    suspicious_prompting bumped from medium to high.
  - 13 combo regex patterns (COMBO_PATTERNS).
  - PATH_INDICATOR_CATEGORIES expanded.
"""
from __future__ import annotations

import re

# Developer-authored files whose presence is reported in important_files.
IMPORTANT_FILES = ("SKILL.md", "_meta.json", "README.md", "package.json", "requirements.txt")

# Files appended by the OpenClaw crawler; excluded from content analysis so they
# do not inflate indicator counts, URL lists, or risk scores.
COLLECTOR_METADATA_FILES = frozenset({"_detail.json", "skill-card.md"})

# Limits.
MAX_TEXT_BYTES = 1_000_000
MAX_EVIDENCE_PER_CATEGORY = 75
MAX_ENV_EVIDENCE = 75
MAX_URL_EVIDENCE = 75

# ---------------------------------------------------------------------------
# Indicator categories.
#
#   Critical  — reverse_shell_patterns
#   High      — credential_theft_targets, exfiltration_channels,
#               obfuscation_techniques, download_and_execute,
#               suspicious_prompting
#   Medium    — persistence_mechanisms, network_access, filesystem_access,
#               secret_handling, hidden_content, dependency_or_install_script,
#               process_execution
#   Low       — hook_or_tool_exposure
# ---------------------------------------------------------------------------

FINDING_RULES = {

    # === CRITICAL ============================================================

    "reverse_shell_patterns": {
        "terms": (
            "/dev/tcp/",
            "/dev/udp/",
            "bash -i",
            "bash -c 'bash -i",
            "nc -e",
            "nc -c",
            "ncat -e",
            "netcat -e",
            "mkfifo",
            "socat exec",
            "socat tcp",
            "pty.spawn",
            "os.dup2",
            "perl -e 'use Socket",
            "ruby -rsocket",
            "php -r '$sock",
            "fsockopen",
            "TCPClient",
            "New-Object System.Net.Sockets",
        ),
        "severity": "critical",
        "title": "Reverse shell pattern detected",
        "description": (
            "Code patterns associated with establishing a reverse shell, giving an "
            "attacker interactive command execution on the victim machine."
        ),
    },

    # === HIGH ================================================================

    "credential_theft_targets": {
        "terms": (
            # SSH
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_ecdsa",
            ".ssh/authorized_keys",
            ".ssh/config",
            ".ssh/known_hosts",
            # Cloud providers
            ".aws/credentials",
            ".aws/config",
            ".azure/",
            ".config/gcloud/",
            ".kube/config",
            ".docker/config.json",
            ".gnupg/",
            ".git-credentials",
            ".netrc",
            ".terraform.d/credentials.tfrc.json",
            ".vault-token",
            ".npmrc",
            ".pypirc",
            # Crypto wallets
            ".solana/id.json",
            ".ethereum/",
            ".bitcoin/",
            "wallet.dat",
            "keystore/",
            "metamask",
            "solflare",
            "trust wallet",
            "keplr",
            "seed phrase",
            "seed_phrase",
            "mnemonic phrase",
            "mnemonic seed",
            "private_key",
            "secret_key",
            "recovery phrase",
            "recovery_phrase",
            # Browser credential stores
            "Login Data",
            "Chrome/User Data",
            "Google/Chrome",
            "Chromium/",
            "BraveSoftware/",
            "Microsoft/Edge",
            "logins.json",
            "cookies.sqlite",
            "places.sqlite",
            "key4.db",
            "cert9.db",
            ".mozilla/firefox",
            "Safari/Cookies",
            "Safari/LocalStorage",
            "Local Storage/leveldb",
            # macOS Keychain
            "security find-generic-password",
            "security find-internet-password",
            "security dump-keychain",
            "login.keychain",
        ),
        "severity": "high",
        "title": "Credential theft target references found",
        "description": (
            "References to well-known credential storage paths (SSH keys, cloud configs, "
            "crypto wallets, browser credential stores, macOS Keychain). Skills rarely "
            "need direct access to these files."
        ),
    },
    "exfiltration_channels": {
        "terms": (
            # Webhook services
            "discord.com/api/webhooks",
            "hooks.slack.com",
            "webhook.site",
            "pipedream.net",
            "requestbin",
            "hookbin.com",
            # Paste services
            "pastebin.com",
            "paste.ee",
            "hastebin",
            "dpaste",
            "ghostbin",
            "rentry.co",
            "ix.io",
            # Telegram bot API
            "api.telegram.org/bot",
            # Tunnelling / ngrok
            "ngrok.io",
            "ngrok-free.app",
            "serveo.net",
            "localhost.run",
            "localtunnel.me",
            # OOB testing domains
            "burpcollaborator.net",
            "oast.fun",
            "oast.me",
            "oast.pro",
            "oast.live",
            "interact.sh",
            "canarytokens.com",
            "dnslog.cn",
            # DNS exfil
            "nsupdate",
        ),
        "severity": "high",
        "title": "Known exfiltration or C2 endpoint references found",
        "description": (
            "References to webhook services, paste sites, Telegram bot API, tunnelling "
            "services, or out-of-band interaction domains commonly used for data theft."
        ),
    },
    "obfuscation_techniques": {
        "terms": (
            # Base64
            "base64 -d",
            "base64 --decode",
            "b64decode",
            "base64.b64decode",
            "base64.decodebytes",
            "atob(",
            "btoa(",
            # Char-code construction
            "String.fromCharCode",
            "bytes.fromhex",
            "bytearray.fromhex",
            "codecs.decode",
            # Serialisation
            "marshal.loads",
            "pickle.loads",
            "pickle.load(",
            "dill.loads",
            "cloudpickle.loads",
            "shelve.open",
            # Compression
            "zlib.decompress",
            "gzip.decompress",
            "bz2.decompress",
            "lzma.decompress",
            # JS-specific
            "Buffer.from(",
        ),
        "severity": "high",
        "title": "Code obfuscation indicators found",
        "description": (
            "Encoding, decoding, or deserialisation patterns that may hide the true "
            "payload. Legitimate skills rarely need base64+eval or pickle.loads."
        ),
    },
    "download_and_execute": {
        "terms": (
            {"term": "&& ./",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "&& bash ", "boundary": "operator",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "&& sh ", "boundary": "operator",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "&& python ",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "urlretrieve",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "Invoke-Expression", "case_sensitive": True},
            {"term": "IEX(", "case_sensitive": True},
            {"term": "Invoke-WebRequest", "case_sensitive": True},
            {"term": "DownloadString", "case_sensitive": True},
            {"term": "DownloadFile", "case_sensitive": True},
            {"term": "Start-Process", "case_sensitive": True},
        ),
        "severity": "high",
        "title": "Download-and-execute chain indicators found",
        "description": (
            "Patterns that download remote content and pipe it directly to an interpreter, "
            "or download then execute — a primary payload delivery chain in ClawHavoc."
        ),
    },
    "suspicious_prompting": {
        "terms": (
            "ignore previous",
            "ignore all previous",
            "system prompt",
            "developer message",
            "exfiltrate",
            "send credentials",
            "steal",
            "background process",
            "daemonize",
            "reverse shell",
            "disregard",
            "override instructions",
            "bypass safety",
            "do not inform",
            "without telling",
        ),
        "severity": "high",
        "title": "Suspicious prompting or instruction indicators found",
        "description": (
            "Static patterns suggest instructions related to credential exposure, "
            "persistence, background execution, prompt manipulation, or agent coercion."
        ),
    },

    # === MEDIUM ==============================================================

    "persistence_mechanisms": {
        "terms": (
            # Unix cron
            "crontab",
            "/etc/cron.",
            "/var/spool/cron",
            # macOS
            "LaunchAgents",
            "LaunchDaemons",
            "loginitems",
            "com.apple.loginwindow",
            # Systemd
            "systemctl enable",
            "systemctl start",
            "/etc/systemd/",
            # Shell profiles
            ".bashrc",
            ".bash_profile",
            ".zshrc",
            ".profile",
            ".zprofile",
            ".bash_login",
            ".zlogin",
            # Windows
            "schtasks",
            "CurrentVersion\\Run",
            "Startup folder",
            # Generic
            {"term": "nohup", "boundary": True},
            "disown",
            "screen -dm",
            "tmux new -d",
        ),
        "severity": "medium",
        "title": "Persistence mechanism indicators found",
        "description": (
            "References to cron, launch agents, systemd units, shell profile "
            "modification, or scheduled tasks used to maintain access after "
            "initial compromise."
        ),
    },
    "network_access": {
        "terms": (
            {"term": "http://", "boundary": "url",
             "region_weights": {"prose": 0.1, "inline_code": 0.3, "code_block": 0.5,
                                "bundled_code": 1.0, "config": 0.5, "frontmatter": 0.2}},
            {"term": "https://", "boundary": "url",
             "region_weights": {"prose": 0.1, "inline_code": 0.3, "code_block": 0.5,
                                "bundled_code": 1.0, "config": 0.5, "frontmatter": 0.2}},
            {"term": "import requests",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "requests.get",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "requests.post",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "urllib.request",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "httpx", "boundary": "word"},
            {"term": "aiohttp", "boundary": "word"},
            {"term": "fetch(",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "axios", "boundary": "word"},
            {"term": "curl ", "boundary": "word"},
            {"term": "wget ", "boundary": "word"},
            "net/http",
            "socket.connect",
            "http.client",
            {"term": "websocket", "boundary": "word"},
        ),
        "severity": "medium",
        "title": "Network access indicators found",
        "description": "Static patterns suggest the artifact may perform network access.",
    },
    "filesystem_access": {
        "terms": (
            "/tmp",
            "/home",
            {"term": "~/.",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 0.5}},
            {"term": "open(",
             "boundary": "word",
             "region_weights": {"prose": 0.0, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": ".write(",
             "region_weights": {"prose": 0.0, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "writefile", "boundary": "word"},
            {"term": "unlink", "boundary": "word"},
            {"term": "remove(",
             "region_weights": {"prose": 0.0, "code_block": 0.5, "bundled_code": 1.0}},
            "rmtree",
            {"term": "rm ", "case_sensitive": True, "boundary": "word"},
            {"term": "rm -", "case_sensitive": True, "boundary": "word"},
            {"term": "mkdir", "boundary": "word"},
            {"term": "chmod", "boundary": "word"},
            "shutil.copy",
            "shutil.move",
            {"term": "fs.readFile",
             "region_weights": {"prose": 0.0, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "fs.writeFile",
             "region_weights": {"prose": 0.0, "code_block": 0.5, "bundled_code": 1.0}},
        ),
        "severity": "medium",
        "title": "Filesystem access indicators found",
        "description": "Static patterns suggest the artifact may write, remove, or modify files.",
    },
    "secret_handling": {
        "terms": (
            {"term": "password", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "passwd", "boundary": "word"},
            {"term": "token", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "api_key", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "apikey", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "secret", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "credential", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "authorization", "boundary": "word",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0, "frontmatter": 1.0}},
            {"term": "bearer ", "boundary": "word"},
            {"term": ".env",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0, "config": 1.0}},
            "private_key",
            "client_secret",
            "access_token",
            "refresh_token",
        ),
        "severity": "medium",
        "title": "Secret or credential indicators found",
        "description": "Static patterns suggest the artifact may reference credentials or secrets.",
    },
    "hidden_content": {
        "terms": (
            # Markdown reference-link injection
            "[//]: #",
            "[//]:#",
            # Zero-width Unicode
            "\u200b",
            "\u200c",
            "\u200d",
            "\ufeff",
            "\u2060",
            # Unicode homoglyphs (Cyrillic lookalikes)
            "\u0410",
            "\u0435",
            "\u043e",
            # CSS / HTML hiding
            'style="display:none',
            "style='display:none",
            "visibility:hidden",
            "font-size:0",
        ),
        "severity": "medium",
        "title": "Hidden content indicators found",
        "description": (
            "Markdown reference links, zero-width Unicode characters, Unicode homoglyphs, "
            "or CSS-hidden elements that conceal instructions from visual review."
        ),
    },
    "dependency_or_install_script": {
        "terms": (
            "postinstall",
            "preinstall",
            "install.sh",
            "setup.py",
            "pip install",
            "npm install",
            "curl -fs",
            "go install",
            "cargo install",
            "gem install",
            "brew install",
            {"term": "npx", "boundary": True},
        ),
        "severity": "medium",
        "title": "Dependency or install script indicators found",
        "description": "Static patterns suggest install-time scripts or dependency setup behavior.",
    },
    "process_execution": {
        "terms": (
            {"term": "subprocess",
             "region_weights": {"prose": 0.1, "code_block": 0.5, "bundled_code": 1.0}},
            {"term": "os.system",
             "region_weights": {"prose": 0.1, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "os.popen",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "eval(",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "spawn(",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "child_process",
             "region_weights": {"prose": 0.1, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "popen",
             "region_weights": {"prose": 0.1, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "shell=True",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "proc_open",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "passthru(",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "shell_exec",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
            {"term": "Runtime.exec",
             "region_weights": {"prose": 0.0, "code_block": 1.0, "bundled_code": 1.0}},
        ),
        "severity": "medium",
        "title": "Process execution indicators found",
        "description": "Static patterns suggest the artifact may invoke shell or subprocess APIs.",
    },

    # === LOW =================================================================

    "hook_or_tool_exposure": {
        "terms": (
            "hooks/",
            "tools/",
            ".claude/",
            "openclaw",
            {"term": "mcp", "boundary": True},
            ".clawhub/",
            ".clawdbot/",
            "sessions.json",
            "mcp.json",
        ),
        "severity": "low",
        "title": "Hook or tool exposure indicators found",
        "description": "Paths or content reference hooks, tools, or OpenClaw integration points.",
    },
}

# Categories whose terms are also matched against relative paths, not just content.
PATH_INDICATOR_CATEGORIES = (
    "hook_or_tool_exposure",
    "dependency_or_install_script",
    "credential_theft_targets",
    "persistence_mechanisms",
)

# ---------------------------------------------------------------------------
# Combo regex patterns.
#
# Each pattern fires when two or more tokens appear together in a specific
# relationship. The ``category`` field must match a key in FINDING_RULES so
# that evidence is recorded in the correct indicator bucket.
# ---------------------------------------------------------------------------

COMBO_PATTERNS = (
    # --- CRITICAL ---
    {
        "id": "COMBO-001",
        "category": "obfuscation_techniques",
        "severity": "critical",
        "title": "Base64 decode piped to execution",
        "description": (
            "Base64-encoded content decoded and passed to a command interpreter — "
            "strong indicator of hidden payload execution."
        ),
        "pattern": re.compile(
            r"(base64\s+(-d|--decode)|b64decode|atob)\s*\(?\s*.*?"
            r"(eval|exec|system|popen|sh\b|bash\b|\|\s*(ba)?sh)",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    {
        "id": "COMBO-006",
        "category": "reverse_shell_patterns",
        "severity": "critical",
        "title": "Socket + subprocess combination found",
        "description": "Socket connection combined with subprocess/pty — textbook reverse shell.",
        "pattern": re.compile(
            r"socket\s*[\.\(].*?(subprocess|os\.dup2|pty\.spawn|os\.system)",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    {
        "id": "COMBO-011",
        "category": "download_and_execute",
        "severity": "critical",
        "title": "Remote script piped to interpreter",
        "description": "Downloading a remote script and piping it to a shell/interpreter.",
        "pattern": re.compile(
            r"(curl|wget)\s+[^\n|]*\|\s*((ba)?sh|python|perl|ruby|node)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "COMBO-014",
        "category": "download_and_execute",
        "severity": "critical",
        "title": "HTTP fetch followed by code execution",
        "description": (
            "Content fetched via HTTP is passed directly to an execution primitive — "
            "a primary payload delivery chain."
        ),
        "pattern": re.compile(
            r"(urlopen\s*\(|urlretrieve\s*\(|requests\.(get|post)\s*\(|"
            r"urllib\.request\.urlopen\s*\()"
            r".{0,300}"
            r"(exec\s*\(|eval\s*\(|compile\s*\(|subprocess|os\.system|os\.popen|"
            r"spawn\s*\(|shell_exec)",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    # --- HIGH ---
    {
        "id": "COMBO-007",
        "category": "exfiltration_channels",
        "severity": "high",
        "title": "DNS lookup with command substitution found",
        "description": "DNS commands using shell substitution to encode stolen data in queries.",
        "pattern": re.compile(r"(dig|nslookup|host)\s+.*?\$[\({]", re.IGNORECASE),
    },
    {
        "id": "COMBO-008",
        "category": "hidden_content",
        "severity": "high",
        "title": "HTML comment containing action keywords",
        "description": "HTML comment with execution keywords — attackers hide instructions here.",
        "pattern": re.compile(
            r"<!--.*?(curl|wget|exec|eval|run|bash|python|system|fetch|send|post\s).*?-->",
            re.IGNORECASE | re.DOTALL,
        ),
    },
    {
        "id": "COMBO-009",
        "category": "hidden_content",
        "severity": "high",
        "title": "Markdown reference link with action keywords",
        "description": "Invisible markdown link containing execution keywords.",
        "pattern": re.compile(
            r"\[//\]:\s*#?\s*\(.*?(curl|wget|exec|eval|run|bash|system|send|fetch).*?\)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "COMBO-010",
        "category": "secret_handling",
        "severity": "high",
        "title": "Sensitive environment variable access found",
        "description": "Code reads a specific high-value API key or credential variable.",
        "pattern": re.compile(
            r"(os\.environ|os\.getenv|process\.env|ENV\[|import\.meta\.env)\s*"
            r"[\.\[\(]\s*['\"]?"
            r"(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET"
            r"|DATABASE_URL|DB_PASSWORD|PRIVATE_KEY|SSH_KEY|STRIPE_SECRET"
            r"|SLACK_TOKEN|DISCORD_TOKEN|TELEGRAM_TOKEN|JWT_SECRET"
            r"|CLAW_API|CLAUDE_API|SESSION_SECRET)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "COMBO-012",
        "category": "obfuscation_techniques",
        "severity": "high",
        "title": "eval() with dynamic string construction",
        "description": "Using eval on a dynamically constructed string to hide the payload.",
        "pattern": re.compile(
            r"eval\s*\(\s*(['\"].*['\"]\.join|.*\+\s*['\"]|`\$\{|compile\s*\()",
            re.IGNORECASE,
        ),
    },
    {
        "id": "COMBO-013",
        "category": "suspicious_prompting",
        "severity": "high",
        "title": "Agent secrecy instruction detected",
        "description": "Instructions telling the agent to hide actions from the user.",
        "pattern": re.compile(
            r"(silently|quietly|without\s+(telling|informing|notifying|the\s+user\s+knowing))"
            r"\s+.{0,60}(run|execute|send|post|read|access|download|upload|connect)",
            re.IGNORECASE,
        ),
    },
    # --- MEDIUM ---
    {
        "id": "COMBO-002",
        "category": "obfuscation_techniques",
        "severity": "medium",
        "title": "Long base64-encoded string literal found",
        "description": "A 200+ character base64 string may contain an embedded payload.",
        "pattern": re.compile(r"""['"][A-Za-z0-9+/]{200,}={0,2}['"]"""),
    },
    {
        "id": "COMBO-003",
        "category": "obfuscation_techniques",
        "severity": "medium",
        "title": "Long hex escape sequence found",
        "description": "Six or more consecutive hex escapes hiding malicious strings.",
        "pattern": re.compile(r"(\\x[0-9a-fA-F]{2}){6,}"),
    },
    {
        "id": "COMBO-004",
        "category": "obfuscation_techniques",
        "severity": "medium",
        "title": "Character code string construction found",
        "description": "Building strings from char codes to evade keyword scanners.",
        "pattern": re.compile(
            r"String\.fromCharCode\s*\(\s*(\d+\s*,\s*){3,}\d+\s*\)", re.IGNORECASE,
        ),
    },
    {
        "id": "COMBO-005",
        "category": "obfuscation_techniques",
        "severity": "medium",
        "title": "Python chr() concatenation found",
        "description": "Building strings by concatenating chr() calls to evade detection.",
        "pattern": re.compile(r"(chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}chr\s*\(\s*\d+\s*\)"),
    },
)

# ---------------------------------------------------------------------------
# Environment-variable access patterns.
# ---------------------------------------------------------------------------

ENV_PATTERNS = (
    ("os.getenv", re.compile(r"\bos\.getenv\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")),
    ("os.environ", re.compile(r"\bos\.environ(?:\.get)?\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")),
    ("os.environ[]", re.compile(r"\bos\.environ\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]")),
    ("process.env", re.compile(r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)")),
    ("import.meta.env", re.compile(r"\bimport\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)")),
    ("ENV[]", re.compile(r"\bENV\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]")),
    ("shell", re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")),
)

URL_PATTERN = re.compile(r"https?://[^\s'\"<>)\]}]+")

PYTHON_EXTENSIONS = {".py"}
JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh"}