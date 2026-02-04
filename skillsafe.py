#!/usr/bin/env python3
"""skillsafe - Agent Skill Security Scanner.

Zero-dependency static analysis tool that scans AgentSkills (SKILL.md + bundled
files) for malicious patterns.  Informed by the ClawHavoc campaign (Jan 2026)
and the OWASP Agentic AI threat taxonomy.

Detects: credential harvesting, data exfiltration, remote code execution,
memory poisoning, encoded payloads, social-engineering prerequisites,
privilege escalation, persistence mechanisms, obfuscation, and more.

Usage:
    skillsafe /path/to/skill                  # scan a single skill directory
    skillsafe /path/to/skills --recursive     # scan all skills recursively
    skillsafe /path/to/SKILL.md               # scan a single SKILL.md file
    cat SKILL.md | skillsafe -                # read from stdin

    skillsafe /path/to/skill --check          # CI mode (exit 1 if findings)
    skillsafe /path/to/skill --json           # JSON output
    skillsafe /path/to/skill --severity high  # filter by severity
"""

from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name

    def color(self) -> str:
        return {
            Severity.INFO: "\033[36m",
            Severity.LOW: "\033[34m",
            Severity.MEDIUM: "\033[33m",
            Severity.HIGH: "\033[91m",
            Severity.CRITICAL: "\033[31;1m",
        }[self]


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# ── Finding / Rule ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    file: str
    line: int | None = None
    evidence: str = ""


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    description: str


# ── Rules Catalogue ───────────────────────────────────────────────────────────

RULES: list[Rule] = [
    Rule("SS01", "Remote Code Fetch & Execute", Severity.CRITICAL,
         "Downloads and executes remote code (curl|bash, wget|sh, etc.)"),
    Rule("SS02", "Credential Harvesting", Severity.CRITICAL,
         "Accesses credential files (.env, .ssh, wallets, keychains, etc.)"),
    Rule("SS03", "Data Exfiltration", Severity.HIGH,
         "Sends data to external endpoints (POST, webhooks, email)"),
    Rule("SS04", "Memory / Soul Poisoning", Severity.CRITICAL,
         "Modifies agent memory/personality files (MEMORY.md, SOUL.md, etc.)"),
    Rule("SS05", "Encoded Payload", Severity.HIGH,
         "Contains base64 or hex-encoded commands/payloads"),
    Rule("SS06", "Suspicious Prerequisite", Severity.HIGH,
         "Instructs user to paste terminal commands or install from unusual sources"),
    Rule("SS07", "Privilege Escalation", Severity.HIGH,
         "Uses sudo, chmod 777, setuid, or dscl commands"),
    Rule("SS08", "Persistence Mechanism", Severity.HIGH,
         "Installs cron jobs, launch agents, systemd units, or startup scripts"),
    Rule("SS09", "Reverse Shell / C2", Severity.CRITICAL,
         "Patterns consistent with reverse shell or command-and-control"),
    Rule("SS10", "Obfuscation", Severity.MEDIUM,
         "Zero-width characters, Unicode homoglyphs, or excessive escaping"),
    Rule("SS11", "ClickFix Social Engineering", Severity.HIGH,
         "Instructions to copy-paste terminal commands from external sites"),
    Rule("SS12", "Unpinned External Dependency", Severity.MEDIUM,
         "References npm/pip/brew packages without version pinning"),
    Rule("SS13", "Dangerous File Operations", Severity.HIGH,
         "rm -rf, file overwrite, or mass deletion patterns"),
    Rule("SS14", "Network Reconnaissance", Severity.HIGH,
         "Network scanning, port scanning, cloud metadata access, or internal network references"),
    Rule("SS15", "Prompt Injection / Instruction Override", Severity.HIGH,
         "Attempts to override agent instructions or ignore safety rules"),
    Rule("SS16", "Suspicious Binary / Archive", Severity.HIGH,
         "Skill bundles executable binaries, archives, or compiled files"),
    Rule("SS17", "Environment Variable Exfiltration", Severity.HIGH,
         "Reads environment variables and sends them externally"),
    Rule("SS18", "Cryptocurrency Targeting", Severity.CRITICAL,
         "Targets cryptocurrency wallets, seed phrases, or exchange credentials"),
    Rule("SS19", "Sensitive Path Traversal", Severity.MEDIUM,
         "References paths outside the skill directory (../, /etc/, ~/)"),
    Rule("SS20", "Hidden File Manipulation", Severity.MEDIUM,
         "Creates or modifies dotfiles/hidden configuration"),
    Rule("SS21", "API Key / Secret Reference", Severity.INFO,
         "References API keys or secrets (may be legitimate configuration)"),
    Rule("SS22", "Local Network Reference", Severity.INFO,
         "References localhost, internal IPs, or local ports (common in server skills)"),
]

RULE_MAP: dict[str, Rule] = {r.id: r for r in RULES}


# ── Pattern Definitions ──────────────────────────────────────────────────────

# SS01 — Remote Code Fetch & Execute
RCE_PATTERNS = [
    (r'curl\s+[^\n]*\|\s*(ba)?sh', "curl piped to shell"),
    (r'wget\s+[^\n]*\|\s*(ba)?sh', "wget piped to shell"),
    (r'curl\s+[^\n]*\|\s*python', "curl piped to python"),
    (r'wget\s+[^\n]*\|\s*python', "wget piped to python"),
    (r'curl\s+[^\n]*\|\s*perl', "curl piped to perl"),
    (r'curl\s+[^\n]*\|\s*ruby', "curl piped to ruby"),
    (r'eval\s*\(\s*\$\(curl', "eval of curl output"),
    (r'source\s+<\(curl', "sourcing curl output"),
    (r'python3?\s+-c\s+["\']import\s+urllib', "python inline URL fetch"),
    (r'powershell\s+.*-e\w*\s+', "powershell encoded command"),
    (r'iex\s*\(.*invoke-webrequest', "powershell IEX download"),
    (r'npx\s+[^\s]+@latest', "npx latest (mutable version)"),
    (r'pip\s+install\s+--index-url\s+http://', "pip install from HTTP (not HTTPS)"),
    (r'pip\s+install\s+git\+https?://', "pip install from git URL"),
]

# SS02 — Credential Harvesting
# Focus on *accessing/reading* credentials, not just mentioning them.
CRED_PATTERNS = [
    (r'~/\.ssh/', "SSH directory access"),
    (r'~/.aws/', "AWS credentials access"),
    (r'~/.gnupg/', "GPG keyring access"),
    (r'(?:cat|read|open|load|source|include)\s+.*\.env\b', ".env file read"),
    (r'\$\(cat\s+.*\.env', ".env content in subshell"),
    (r'\.clawdbot/\.env', "Clawdbot credentials"),
    (r'\.moltbot/\.env', "Moltbot credentials"),
    (r'~/\.config/moltbot', "Moltbot config access"),
    (r'~/\.config/clawdbot', "Clawdbot config access"),
    (r'keychain|Keychain|KeychainAccess', "Keychain access"),
    (r'security\s+find-(generic|internet)-password', "macOS Keychain CLI"),
    (r'cat\s+.*\.pem\b', "Reading PEM certificate/key"),
    (r'cat\s+.*id_rsa', "Reading SSH private key"),
    (r'cat\s+.*/credentials', "Reading credentials file"),
    (r'git-credentials', "Git credentials file"),
    (r'\.netrc\b', ".netrc credentials"),
    (r'\.npmrc\b', "npm credentials"),
    (r'\.pypirc\b', "PyPI credentials"),
    (r'\.docker/config\.json', "Docker credentials"),
    (r'\.kube/config', "Kubernetes config"),
]

# SS03 — Data Exfiltration
# Focus on clearly suspicious exfil patterns. Generic curl POST is very common.
EXFIL_PATTERNS = [
    (r'curl\s+.*(?:-d|--data)\s+.*(?:cat\s|<|@|\$\()', "curl POST with file/command content"),
    (r'curl\s+.*-F\s+.*file=@', "curl uploading file"),
    (r'webhook[s]?\.(?!github\.com)', "webhook URL (non-GitHub)"),
    (r'ngrok\.', "ngrok tunnel"),
    (r'requestbin\.', "RequestBin"),
    (r'pipedream\.', "Pipedream endpoint"),
    (r'glot\[?\.\]?io', "glot.io (used in ClawHavoc)"),
    (r'pastebin\.com|hastebin\.com', "paste service"),
    (r'GITHUB_OUTPUT|GITHUB_ENV', "GitHub Actions env injection"),
    (r'echo\s+.*>>\s*\$GITHUB_', "writing to GitHub env files"),
]

# SS04 — Memory / Soul Poisoning
MEMORY_PATTERNS = [
    (r'(?:write|modify|edit|update|overwrite|append).*(?:MEMORY\.md|SOUL\.md|IDENTITY\.md|AGENTS\.md|HEARTBEAT\.md)', "modifying agent personality/memory files"),
    (r'(?:echo|cat|tee|printf).*>+\s*.*(?:MEMORY\.md|SOUL\.md|IDENTITY\.md|AGENTS\.md)', "writing to agent files via shell"),
    (r'memory_file|soul_file|identity_file', "variable referencing agent files"),
    (r'(?:inject|poison|override|replace).*(?:memory|soul|personality|identity|instructions)', "memory/personality modification intent"),
    (r'forget\s+(?:your|previous|all)\s+(?:instructions|rules|guidelines)', "instruction amnesia"),
]

# SS05 — Encoded Payload
ENCODED_PATTERNS = [
    (r'base64\s+(?:-d|--decode)', "base64 decode command"),
    (r'echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|\s*base64', "base64 encoded string piped to decode"),
    (r'atob\s*\(', "JavaScript base64 decode"),
    (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}', "hex-encoded byte string"),
    (r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}', "unicode escape sequence chain"),
    (r'(?:from\s+base64\s+import|import\s+base64)(?=.*(?:decode|b64decode|urlsafe_b64decode))', "Python base64 decode import"),
    (r'codecs\.decode\s*\(.*rot.?13', "ROT13 decode"),
    (r'zlib\.decompress|gzip\.decompress', "compressed payload"),
]

# SS06 — Suspicious Prerequisite
PREREQ_PATTERNS = [
    (r'(?:prerequisite|pre-requisite|requirement|setup|install(?:ation)?)\s*(?:step|instruction)?[:\s]*\n.*(?:run|execute|paste|copy)', "prerequisite install instruction"),
    (r'paste\s+(?:this|the\s+following|these)\s+(?:command|into|in\s+your\s+terminal)', "paste command instruction"),
    (r'open\s+(?:Terminal|cmd|PowerShell)\s+and\s+(?:run|paste|execute|type)', "terminal instruction"),
    (r'(?:run|execute)\s+(?:this|the\s+following)\s+(?:command|script)\s+(?:in|from)\s+(?:your|a)\s+terminal', "terminal command instruction"),
    (r'install.*from\s+(?:https?://(?!pypi\.org|npmjs\.com|github\.com/[a-z]+/[a-z]+/releases))', "install from non-standard source"),
]

# SS07 — Privilege Escalation
PRIVESC_PATTERNS = [
    (r'sudo\s+', "sudo usage"),
    (r'chmod\s+777\s', "chmod 777 (world writable)"),
    (r'chmod\s+[0-7]*[2367][0-7]*\s', "chmod with write-all bit"),
    (r'chown\s+root', "chown to root"),
    (r'setuid|setgid|SUID|SGID', "setuid/setgid reference"),
    (r'dscl\s+', "macOS directory services CLI"),
    (r'visudo|/etc/sudoers', "sudoers modification"),
    (r'gsettings\s+set\s+org\.gnome', "GNOME settings modification"),
]

# SS08 — Persistence
PERSIST_PATTERNS = [
    (r'crontab\s+', "crontab modification"),
    (r'/etc/cron\.\w+/', "cron directory access"),
    (r'LaunchAgent|LaunchDaemon|com\.apple\.launch', "macOS Launch Agent/Daemon"),
    (r'~/Library/LaunchAgents', "user LaunchAgent directory"),
    (r'systemctl\s+enable', "systemd service enable"),
    (r'/etc/systemd/system/', "systemd unit path"),
    (r'/etc/init\.d/', "init.d script"),
    (r'~/.bashrc|~/.zshrc|~/.profile|~/.bash_profile', "shell profile modification"),
    (r'HKEY_|reg\s+add|regedit', "Windows registry"),
    (r'Startup\s*folder|shell:startup', "Windows startup folder"),
    (r'at\s+\d+:\d+', "at command scheduling"),
    (r'~/.config/autostart/', "Linux autostart directory"),
]

# SS09 — Reverse Shell / C2
C2_PATTERNS = [
    (r'/dev/tcp/', "bash /dev/tcp (reverse shell)"),
    (r'nc\s+.*-e\s+/bin/(ba)?sh', "netcat reverse shell"),
    (r'ncat\s+.*-e', "ncat with execute"),
    (r'socat\s+.*exec', "socat with exec"),
    (r'mkfifo\s+.*nc\s', "named pipe + netcat"),
    (r'python.*socket.*connect.*exec', "Python socket reverse shell"),
    (r'ruby.*TCPSocket.*exec', "Ruby TCP reverse shell"),
    (r'php.*fsockopen.*exec', "PHP reverse shell"),
    (r'(?:bash|sh)\s+-i\s+>&?\s*/dev/tcp', "interactive reverse shell"),
    (r'(?!127\.0\.0\.1)(?!0\.0\.0\.0)(?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}', "External IP:port (potential C2)"),
    (r'ngrok\s+(?:tcp|http)\s', "ngrok tunnel (potential C2)"),
]

# SS10 — Obfuscation
OBFUS_PATTERNS = [
    # Zero-width characters (detected by codepoint)
    (r'[\u200b\u200c\u200d\ufeff\u2060\u00ad]', "zero-width character"),
    # Unicode homoglyphs in Latin text
    (r'[а-яА-Я]', "Cyrillic character in non-Cyrillic context"),
    (r'[᠎​‎‏]', "invisible Unicode formatting character"),
    # Excessive backslash escaping
    (r'(?:\\[nrtv\'"\\]){5,}', "excessive escape sequences"),
    # HTML entities in markdown
    (r'&#x?[0-9a-fA-F]+;', "HTML entity encoding in markdown"),
    # Variable name obfuscation
    (r'\b[_O0Il]{5,}\b', "obfuscated variable name"),
]

# SS11 — ClickFix Social Engineering
CLICKFIX_PATTERNS = [
    (r'copy\s+(?:and\s+)?paste\s+(?:this|the\s+following)\s+(?:into|in)\s+(?:your\s+)?terminal', "copy-paste terminal instruction"),
    (r'paste\s+(?:this|it)\s+(?:into|in)\s+(?:your\s+)?(?:terminal|command\s+line|shell|cmd|PowerShell)', "paste into terminal"),
    (r'open\s+(?:a\s+)?terminal\s+and\s+(?:enter|type|paste|run)', "open terminal instruction"),
    (r'run\s+this\s+in\s+(?:your\s+)?terminal', "run in terminal instruction"),
    (r'Win\+R|⊞\s*Win|command\s*prompt\s*.*(?:run|paste)', "Windows Run dialog instruction"),
    (r'click.*allow.*(?:permission|access|admin)', "click-allow social engineering"),
]

# SS12 — Unpinned External Dependency
UNPIN_PATTERNS = [
    (r'npm\s+install\s+(?!.*@\d)[a-z][\w-]+(?:\s|$)', "npm install without version"),
    (r'pip\s+install\s+(?!.*[>=<~!])[a-z][\w-]+(?:\s|$)', "pip install without version"),
    (r'brew\s+install\s+', "brew install (inherently unpinned)"),
    (r'npx\s+[a-z][\w-]+@latest', "npx @latest (mutable)"),
    (r'gem\s+install\s+(?!.*-v\s)[a-z]', "gem install without version"),
    (r'cargo\s+install\s+(?!.*--version\s)[a-z]', "cargo install without version"),
    (r'go\s+install\s+.*@latest', "go install @latest"),
]

# SS13 — Dangerous File Operations
DANGEROUS_FILE_PATTERNS = [
    (r'rm\s+-rf\s+[/~]', "rm -rf on root or home"),
    (r'rm\s+-rf\s+\*', "rm -rf wildcard"),
    (r'>\s*/dev/[^n]', "write to device file"),
    (r'dd\s+.*of=/', "dd write to device/path"),
    (r'mkfs\.\w+', "filesystem format command"),
    (r'shred\s+', "secure file deletion"),
    (r'truncate\s+.*-s\s*0', "file truncation"),
    (r'find\s+.*-delete', "find with delete"),
]

# SS14 — Network Recon (HIGH severity patterns only)
RECON_PATTERNS = [
    (r'nmap\s+', "nmap network scan"),
    (r'masscan\s+', "masscan port scan"),
    (r'169\.254\.169\.254', "cloud metadata endpoint"),
    (r'metadata\.google\.internal', "GCP metadata endpoint"),
    (r'ping\s+-c|traceroute\s', "network probing"),
    (r'arp\s+-a|ifconfig\s|ip\s+addr', "network interface enumeration"),
]

# SS15 — Prompt Injection
INJECTION_PATTERNS = [
    (r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)', "ignore instructions"),
    (r'disregard\s+(?:all\s+)?(?:previous|your)\s+(?:instructions|rules)', "disregard instructions"),
    (r'you\s+are\s+now\s+', "identity override"),
    (r'your\s+new\s+(?:instructions|role|purpose)\s+(?:are|is)', "new instructions injection"),
    (r'(?:^|\n)\s*SYSTEM\s*PROMPT\s*:', "system prompt injection marker"),
    (r'\[INST\]|\[/INST\]|<\|system\|>|<\|user\|>', "LLM control tokens"),
    (r'forget\s+(?:everything|all|your)\s+(?:about|instructions|rules)', "forget instructions"),
    (r'do\s+not\s+(?:follow|obey|listen\s+to)\s+(?:your|the|any)\s+(?:instructions|rules)', "do not follow rules"),
    (r'act\s+as\s+(?:if\s+you\s+(?:have|had)\s+no|an?\s+(?:unrestricted|unfiltered))', "act as unrestricted"),
    (r'jailbreak|DAN\s+mode|developer\s+mode', "jailbreak attempt"),
]

# SS17 — Environment Variable Exfiltration
# Focus on env dump + exfil combinations, not just env access
ENV_EXFIL_PATTERNS = [
    (r'(?:env|printenv|set)\s*(?:\||>|>>)\s*(?:curl|wget|nc|cat)', "env dump piped to network/file"),
    (r'(?:env|printenv).*(?:curl|wget|nc|POST)', "env vars combined with network"),
    (r'os\.environ\b.*(?:post|send|request|upload|socket|connect)', "env access + network send"),
    (r'dict\(os\.environ\)', "full env dict capture"),
]

# SS18 — Cryptocurrency Targeting
CRYPTO_PATTERNS = [
    (r'(?:seed\s+phrase|mnemonic|recovery\s+(?:phrase|words?))', "seed phrase/mnemonic reference"),
    (r'(?:MetaMask|Exodus|Phantom|Coinbase|Ledger|Trezor)\s*(?:vault|wallet|data|config)?', "crypto wallet software"),
    (r'\.solana/|\.ethereum/|\.bitcoin/', "crypto wallet directory"),
    (r'wallet\.dat|keystore/|UTC--', "crypto wallet file"),
    (r'private[-_]?key|priv[-_]?key', "private key reference"),
    (r'0x[a-fA-F0-9]{40}', "Ethereum address"),
    (r'(?:binance|kraken|coinbase|ftx).*(?:api|key|secret|token)', "exchange API key"),
    (r'(?:BTC|ETH|SOL|USDT|USDC).*(?:address|wallet|transfer|send)', "crypto transfer operation"),
]

# SS19 — Sensitive Path Traversal
TRAVERSAL_PATTERNS = [
    (r'\.\./', "path traversal (../)"),
    (r'/etc/(?:passwd|shadow|hosts|resolv)', "system config file access"),
    (r'/var/log/', "system log access"),
    (r'/proc/|/sys/', "procfs/sysfs access"),
    (r'~/Library/(?!Caches)', "macOS Library directory (non-cache)"),
    (r'%APPDATA%|%LOCALAPPDATA%', "Windows AppData"),
]

# SS20 — Hidden File Manipulation
HIDDEN_FILE_PATTERNS = [
    (r'\.git/hooks/', "git hooks modification"),
    (r'mkdir\s+.*\.\w+(?!.*\b(?:venv|env|cache|config)\b)', "creating suspicious hidden directory"),
]

# SS21 — API Key / Secret Reference (INFO - may be legitimate config)
API_KEY_PATTERNS = [
    (r'OPENAI_API_KEY|ANTHROPIC_API_KEY', "AI API key env var referenced"),
    (r'GH_TOKEN|GITHUB_TOKEN|GITHUB_PAT', "GitHub token referenced"),
    (r'AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID', "AWS credential referenced"),
    (r'DATABASE_URL|DB_PASSWORD', "Database credential referenced"),
    (r'SLACK_TOKEN|SLACK_BOT_TOKEN', "Slack token referenced"),
    (r'STRIPE_SECRET_KEY|STRIPE_API_KEY', "Stripe key referenced"),
    (r'API_KEY|SECRET_KEY|AUTH_TOKEN', "Generic API key/secret referenced"),
]

# SS22 — Local Network Reference (INFO - common in server/API skills)
LOCAL_NET_PATTERNS = [
    (r'localhost(?::\d+)?', "localhost reference"),
    (r'127\.0\.0\.1(?::\d+)?', "loopback IP reference"),
    (r'0\.0\.0\.0(?::\d+)?', "bind-all interface"),
    (r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+', "internal/private IP"),
]


# ── Scanner Engine ───────────────────────────────────────────────────────────

RULE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "SS01": RCE_PATTERNS,
    "SS02": CRED_PATTERNS,
    "SS03": EXFIL_PATTERNS,
    "SS04": MEMORY_PATTERNS,
    "SS05": ENCODED_PATTERNS,
    "SS06": PREREQ_PATTERNS,
    "SS07": PRIVESC_PATTERNS,
    "SS08": PERSIST_PATTERNS,
    "SS09": C2_PATTERNS,
    "SS10": OBFUS_PATTERNS,
    "SS11": CLICKFIX_PATTERNS,
    "SS12": UNPIN_PATTERNS,
    "SS13": DANGEROUS_FILE_PATTERNS,
    "SS14": RECON_PATTERNS,
    "SS15": INJECTION_PATTERNS,
    "SS17": ENV_EXFIL_PATTERNS,
    "SS18": CRYPTO_PATTERNS,
    "SS19": TRAVERSAL_PATTERNS,
    "SS20": HIDDEN_FILE_PATTERNS,
    "SS21": API_KEY_PATTERNS,
    "SS22": LOCAL_NET_PATTERNS,
}

# Binary / archive extensions for SS16
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".msi",
    ".dmg", ".app", ".elf", ".deb", ".rpm",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".jar", ".war", ".class",
    ".pyc", ".pyo", ".whl",
    ".wasm",
}


def _scan_text(content: str, filepath: str, rules_to_check: set[str] | None = None) -> list[Finding]:
    """Scan a text string against all pattern-based rules."""
    findings: list[Finding] = []
    lines = content.split("\n")

    for rule_id, patterns in RULE_PATTERNS.items():
        if rules_to_check and rule_id not in rules_to_check:
            continue
        rule = RULE_MAP[rule_id]
        for pattern_str, description in patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            for match in pattern.finditer(content):
                # Find line number
                line_start = content.count("\n", 0, match.start()) + 1
                evidence = lines[line_start - 1].strip() if line_start <= len(lines) else ""
                # Truncate evidence
                if len(evidence) > 120:
                    evidence = evidence[:117] + "..."
                findings.append(Finding(
                    rule=rule_id,
                    severity=rule.severity,
                    message=f"{rule.name}: {description}",
                    file=filepath,
                    line=line_start,
                    evidence=evidence,
                ))

    return findings


def _check_base64_payloads(content: str, filepath: str) -> list[Finding]:
    """Deep check for base64-encoded payloads that decode to something suspicious."""
    findings: list[Finding] = []
    lines = content.split("\n")

    # Find long base64-looking strings
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')
    for match in b64_pattern.finditer(content):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Check if decoded content looks suspicious
            suspicious_keywords = [
                "curl", "wget", "bash", "sh ", "exec", "eval",
                "subprocess", "os.system", "/bin/", "powershell",
                "socket", "connect", "http://", "https://",
                "password", "secret", "token", "api_key",
            ]
            for kw in suspicious_keywords:
                if kw in decoded.lower():
                    line_num = content.count("\n", 0, match.start()) + 1
                    evidence = lines[line_num - 1].strip()[:120]
                    findings.append(Finding(
                        rule="SS05",
                        severity=Severity.CRITICAL,
                        message=f"Encoded Payload: base64 decodes to suspicious content containing '{kw}'",
                        file=filepath,
                        line=line_num,
                        evidence=evidence,
                    ))
                    break
        except Exception:
            pass

    return findings


def _scan_binary_files(skill_path: Path) -> list[Finding]:
    """Check for suspicious binary or archive files bundled in skill."""
    findings: list[Finding] = []
    for root, _dirs, files in os.walk(skill_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in BINARY_EXTENSIONS:
                rel = os.path.relpath(os.path.join(root, fname), skill_path)
                findings.append(Finding(
                    rule="SS16",
                    severity=RULE_MAP["SS16"].severity,
                    message=f"Suspicious Binary / Archive: bundled file '{fname}' ({ext})",
                    file=rel,
                    line=None,
                    evidence=f"Binary/archive file: {fname}",
                ))
    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same rule, file, line)."""
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── YAML Frontmatter Parser ─────────────────────────────────────────────────

def _parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    """Parse YAML frontmatter from SKILL.md.  Returns (metadata, body)."""
    if not content.startswith("---"):
        return {}, content

    end = content.find("\n---", 3)
    if end == -1:
        return {}, content

    yaml_block = content[3:end].strip()
    body = content[end + 4:].strip()

    metadata: dict[str, str] = {}
    for line in yaml_block.split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val:
                metadata[key] = val

    return metadata, body


# ── Scoring ──────────────────────────────────────────────────────────────────

def _calculate_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 safety score.  Higher = safer."""
    if not findings:
        return 100

    penalty = 0
    for f in findings:
        if f.severity == Severity.CRITICAL:
            penalty += 20
        elif f.severity == Severity.HIGH:
            penalty += 10
        elif f.severity == Severity.MEDIUM:
            penalty += 5
        elif f.severity == Severity.LOW:
            penalty += 2
        else:
            penalty += 1

    return max(0, 100 - penalty)


def _grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def _grade_color(grade: str) -> str:
    return {
        "A+": "\033[32;1m",
        "A": "\033[32m",
        "B": "\033[33m",
        "C": "\033[33m",
        "D": "\033[91m",
        "F": "\033[31;1m",
    }.get(grade, "")


# ── Skill Discovery ─────────────────────────────────────────────────────────

def _find_skills(path: Path, recursive: bool = False) -> list[Path]:
    """Find skill directories (containing SKILL.md) at the given path."""
    skills: list[Path] = []

    if path.is_file():
        if path.name == "SKILL.md" or path.suffix == ".md":
            skills.append(path)
        return skills

    if not path.is_dir():
        return skills

    # Direct skill directory
    if (path / "SKILL.md").exists():
        skills.append(path)

    if recursive:
        for root, dirs, files in os.walk(path):
            # Skip hidden dirs, node_modules, __pycache__
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__", ".git")]
            if "SKILL.md" in files:
                skill_path = Path(root)
                if skill_path not in skills:
                    skills.append(skill_path)

    return skills


# ── Full Scan ────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    skill_name: str
    skill_path: str
    metadata: dict[str, str]
    findings: list[Finding]
    score: int
    grade: str
    files_scanned: int


def scan_skill(path: Path, severity_filter: Severity | None = None,
               ignore_rules: set[str] | None = None) -> ScanResult:
    """Scan a single skill directory or SKILL.md file."""
    ignore_rules = ignore_rules or set()

    # Determine if path is a file or directory
    if path.is_file():
        skill_dir = path.parent
        skill_name = path.stem
        files_to_scan = [path]
    else:
        skill_dir = path
        skill_name = path.name
        files_to_scan = []
        for root, _dirs, files in os.walk(skill_dir):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                if ext in (".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts",
                           ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
                           ".env", ".txt", ".rb", ".pl", ".go", ".rs"):
                    files_to_scan.append(fpath)

    all_findings: list[Finding] = []
    metadata: dict[str, str] = {}

    # Determine which rules to check
    active_rules = set(RULE_MAP.keys()) - ignore_rules

    for fpath in files_to_scan:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue

        rel = str(fpath.relative_to(skill_dir)) if fpath.is_relative_to(skill_dir) else str(fpath)

        # Parse frontmatter from SKILL.md
        if fpath.name == "SKILL.md":
            metadata, body = _parse_frontmatter(content)
            # Scan full content (frontmatter + body)
            all_findings.extend(_scan_text(content, rel, active_rules))
            # Deep base64 check
            all_findings.extend(_check_base64_payloads(content, rel))
        else:
            all_findings.extend(_scan_text(content, rel, active_rules))
            all_findings.extend(_check_base64_payloads(content, rel))

    # Check for binary files in skill directory
    if path.is_dir():
        binary_findings = _scan_binary_files(path)
        all_findings.extend([f for f in binary_findings if "SS16" not in ignore_rules])

    # Deduplicate
    all_findings = _deduplicate(all_findings)

    # Filter by severity
    if severity_filter is not None:
        all_findings = [f for f in all_findings if f.severity >= severity_filter]

    # Sort by severity (highest first), then by file/line
    all_findings.sort(key=lambda f: (-f.severity, f.file, f.line or 0))

    score = _calculate_score(all_findings)
    grade = _grade(score)

    return ScanResult(
        skill_name=metadata.get("name", skill_name),
        skill_path=str(path),
        metadata=metadata,
        findings=all_findings,
        score=score,
        grade=grade,
        files_scanned=len(files_to_scan),
    )


def scan_stdin(severity_filter: Severity | None = None,
               ignore_rules: set[str] | None = None) -> ScanResult:
    """Scan SKILL.md content from stdin."""
    content = sys.stdin.read()
    ignore_rules = ignore_rules or set()
    active_rules = set(RULE_MAP.keys()) - ignore_rules

    metadata, body = _parse_frontmatter(content)
    findings = _scan_text(content, "<stdin>", active_rules)
    findings.extend(_check_base64_payloads(content, "<stdin>"))
    findings = _deduplicate(findings)

    if severity_filter is not None:
        findings = [f for f in findings if f.severity >= severity_filter]

    findings.sort(key=lambda f: (-f.severity, f.file, f.line or 0))

    score = _calculate_score(findings)
    grade = _grade(score)

    return ScanResult(
        skill_name=metadata.get("name", "<stdin>"),
        skill_path="<stdin>",
        metadata=metadata,
        findings=findings,
        score=score,
        grade=grade,
        files_scanned=1,
    )


# ── Output Formatters ────────────────────────────────────────────────────────

def _format_rich(result: ScanResult, verbose: bool = False) -> str:
    """Rich terminal output."""
    lines: list[str] = []
    gc = _grade_color(result.grade)

    lines.append(f"\n{BOLD}{'═' * 60}{RESET}")
    lines.append(f"{BOLD}  Skill: {result.skill_name}{RESET}")
    if result.metadata.get("description"):
        desc = result.metadata["description"]
        if len(desc) > 70:
            desc = desc[:67] + "..."
        lines.append(f"  {DIM}{desc}{RESET}")
    lines.append(f"  Path:  {result.skill_path}")
    lines.append(f"  Files: {result.files_scanned}")
    lines.append(f"{BOLD}{'═' * 60}{RESET}")

    if not result.findings:
        lines.append(f"\n  {gc}✓ No security issues found{RESET}")
    else:
        # Summary by severity
        by_sev: dict[Severity, int] = {}
        for f in result.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        lines.append(f"\n  {BOLD}Findings: {len(result.findings)}{RESET}")
        for sev in sorted(by_sev.keys(), reverse=True):
            count = by_sev[sev]
            lines.append(f"    {sev.color()}{sev.label():10}{RESET} {count}")

        lines.append(f"\n  {'─' * 56}")

        for f in result.findings:
            sev_str = f"{f.severity.color()}{Severity(f.severity).label():10}{RESET}"
            loc = f"{f.file}"
            if f.line:
                loc += f":{f.line}"
            lines.append(f"  {sev_str} [{f.rule}] {f.message}")
            lines.append(f"           {DIM}{loc}{RESET}")
            if f.evidence and verbose:
                lines.append(f"           {DIM}> {f.evidence}{RESET}")

    lines.append(f"\n  {BOLD}Score:{RESET} {gc}{result.score}/100 ({result.grade}){RESET}")
    lines.append("")

    return "\n".join(lines)


def _format_json(results: list[ScanResult]) -> str:
    """JSON output for programmatic consumption."""
    output: list[dict[str, Any]] = []
    for r in results:
        output.append({
            "skill": r.skill_name,
            "path": r.skill_path,
            "metadata": r.metadata,
            "score": r.score,
            "grade": r.grade,
            "files_scanned": r.files_scanned,
            "findings": [
                {
                    "rule": f.rule,
                    "severity": Severity(f.severity).label(),
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "evidence": f.evidence,
                }
                for f in r.findings
            ],
        })

    if len(output) == 1:
        return json.dumps(output[0], indent=2)
    return json.dumps(output, indent=2)


def _format_summary(results: list[ScanResult]) -> str:
    """Compact summary table for multiple skills."""
    lines: list[str] = []
    lines.append(f"\n{BOLD}{'Skill':<30} {'Grade':>6} {'Score':>6} {'Findings':>9}{RESET}")
    lines.append(f"{'─' * 55}")

    total_findings = 0
    for r in results:
        gc = _grade_color(r.grade)
        lines.append(f"{r.skill_name:<30} {gc}{r.grade:>6}{RESET} {r.score:>6} {len(r.findings):>9}")
        total_findings += len(r.findings)

    lines.append(f"{'─' * 55}")
    lines.append(f"{'Total':<30} {'':>6} {'':>6} {total_findings:>9}")
    lines.append("")

    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────

def _parse_severity(s: str) -> Severity:
    """Parse severity string to Severity enum."""
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    key = s.lower().strip()
    if key in mapping:
        return mapping[key]
    raise argparse.ArgumentTypeError(f"Unknown severity: {s}. Use: info, low, medium, high, critical")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillsafe",
        description="Agent Skill Security Scanner — detect malicious patterns in AgentSkills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              skillsafe ./my-skill                  Scan a skill directory
              skillsafe ./skills --recursive        Scan all skills recursively
              skillsafe ./SKILL.md                  Scan a single file
              cat SKILL.md | skillsafe -            Read from stdin
              skillsafe ./skill --check             CI mode (exit 1 if findings)
              skillsafe ./skill --json              JSON output
              skillsafe ./skill --severity high     Only HIGH+ findings
              skillsafe --rules                     List all rules

            Informed by the ClawHavoc campaign (Jan 2026) and OWASP Agentic AI threats.
        """),
    )
    parser.add_argument("path", nargs="?", default=None,
                        help="Skill directory, SKILL.md file, or '-' for stdin")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recursively scan for skills in subdirectories")
    parser.add_argument("-s", "--severity", type=_parse_severity, default=None,
                        help="Minimum severity to report (info/low/medium/high/critical)")
    parser.add_argument("--check", action="store_true",
                        help="CI mode: exit 1 if any findings at HIGH or above")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show evidence for each finding")
    parser.add_argument("--ignore", type=str, default="",
                        help="Comma-separated rule IDs to ignore (e.g., SS12,SS19)")
    parser.add_argument("--rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--version", action="version", version="skillsafe 1.0.0")

    args = parser.parse_args(argv)

    # List rules
    if args.rules:
        print(f"\n{BOLD}skillsafe Rules{RESET}\n")
        for rule in RULES:
            print(f"  {rule.severity.color()}{rule.id}{RESET}  {rule.severity.label():10} {rule.name}")
            print(f"      {DIM}{rule.description}{RESET}")
        print()
        return 0

    if not args.path:
        parser.print_help()
        return 1

    # Parse ignore list
    ignore_rules: set[str] = set()
    if args.ignore:
        ignore_rules = {r.strip().upper() for r in args.ignore.split(",")}

    # Scan
    results: list[ScanResult] = []

    if args.path == "-":
        result = scan_stdin(severity_filter=args.severity, ignore_rules=ignore_rules)
        results.append(result)
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: {args.path} does not exist", file=sys.stderr)
            return 1

        skills = _find_skills(target, recursive=args.recursive)
        if not skills:
            # Maybe it's a single markdown file
            if target.is_file() and target.suffix == ".md":
                skills = [target]
            else:
                print(f"No skills found at {args.path}", file=sys.stderr)
                return 1

        for skill_path in skills:
            result = scan_skill(skill_path, severity_filter=args.severity, ignore_rules=ignore_rules)
            results.append(result)

    # Output
    if args.json:
        print(_format_json(results))
    elif len(results) == 1:
        print(_format_rich(results[0], verbose=args.verbose))
    else:
        # Multiple skills: show individual reports + summary
        for r in results:
            print(_format_rich(r, verbose=args.verbose))
        print(_format_summary(results))

    # CI exit code
    if args.check:
        has_high = any(
            any(f.severity >= Severity.HIGH for f in r.findings)
            for r in results
        )
        return 1 if has_high else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
