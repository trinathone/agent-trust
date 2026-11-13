#!/usr/bin/env python3
"""agent-trust: untrusted-content pre-flight for agent workspaces.

Maps which text in a workspace the repo owner wrote (TRUSTED) and which came
from somewhere else (UNTRUSTED), then flags text that tries to steer a coding
agent: hidden HTML comments with instructions, assistant-addressed
imperatives, destructive shell commands, credential reads paired with
external writes, and exfiltration patterns.

Standard library only. No network. Deterministic: the same workspace gives
the same report and the same exit code.

Usage:
    python3 agent_trust.py scan [path] [--json] [--strict] [--quiet]
    python3 agent_trust.py init [path] [--force]
    python3 agent_trust.py dismiss <fingerprint> [--path PATH]
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field

VERSION = "1.0.0"
CONFIG_NAME = ".agent-trust.json"
MAX_BYTES = 1024 * 1024  # files larger than 1 MB are skipped
BINARY_PROBE = 8192

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_HIGH = 2
EXIT_ERROR = 3

TRUSTED = "TRUSTED"
UNTRUSTED = "UNTRUSTED"
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
SEVERITY_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}

# Strength of a pattern match. STRONG patterns read as instructions aimed at
# an agent; AMBIGUOUS patterns are normal documentation phrasing that only
# matters when it comes from somewhere untrusted.
STRONG = "strong"
AMBIGUOUS = "ambiguous"

SKIP_DIRS = {".git"}
DEPENDENCY_DIRS = {
    "vendor", "node_modules", "third_party", "deps", "external", "fetched",
    "downloads",
}
ISSUE_DIRS = {"issues", "prs"}
ISSUE_FILE_RE = re.compile(r"^(issue|pr)-[^/]*\.md$", re.I)
README_NAMES = {"readme.md", "readme", "readme.txt", "readme.rst"}
TRUSTED_TOP_DIRS = {"src", "tests", "test"}
TRUSTED_ROOT_FILES = {"AGENTS.md", "TASK.md", "README.md"}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULE_NAMES = {
    "AT001": "hidden-html-comment",
    "AT002": "agent-imperative",
    "AT003": "destructive-command",
    "AT004": "credential-read-external-write",
    "AT005": "exfiltration",
    "AT006": "doc-instruction-phrasing",
}

I = re.I

# Per-line patterns: (rule id, strength, regex, why).
LINE_PATTERNS = [
    # AT002: text that addresses the agent and tells it what to do.
    ("AT002", STRONG, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|"
        r"earlier|all|your|system)\b.{0,20}\b(instructions?|prompts?|rules|"
        r"directions|guidelines)\b", I),
     "tries to override the agent's instructions"),
    ("AT002", STRONG, re.compile(
        r"\bbefore you (finish|complete|are done|submit|commit|wrap up|open the "
        r"(pr|pull request))\b", I),
     "end-of-task trigger aimed at an agent ('before you finish')"),
    ("AT002", STRONG, re.compile(
        r"(^|[\s>*#\"'`(\[-])(assistant|ai assistant|ai agent|coding agent|"
        r"copilot|claude|chatgpt|llm|ai)\s*:", I),
     "text addressed directly to an assistant"),
    ("AT002", STRONG, re.compile(
        r"\b(note to (the )?(ai|assistant|agent|llm)|if you are an? (ai|llm|"
        r"language model|assistant|agent|coding agent))\b", I),
     "text addressed directly to an assistant"),
    ("AT002", STRONG, re.compile(
        r"\b(delete|remove|rm)\b.{0,20}\b(tests?|test (files|folder|directory|"
        r"suite)|specs?)\b", I),
     "tells the reader to delete tests"),
    ("AT002", STRONG, re.compile(
        r"\b(read|cat|print|dump|copy|paste|include|show|fetch|exfiltrate)\b"
        r".{0,30}(\.env\b|\.pem\b|id_rsa|\bcredentials?\b|\bsecrets?\b|"
        r"github_token|\bapi[_ ]?keys?\b|\baccess tokens?\b)", I),
     "tells the reader to read secrets or credentials"),
    ("AT002", STRONG, re.compile(
        r"\b(include|paste|put|add|append|embed|post|copy|write)\b.{0,80}"
        r"\b(in|into|to|on)\s+(the\s+|a\s+|this\s+|your\s+)?(pr|pull request|"
        r"merge request|issue)\s*(description|body|title|comment)", I),
     "tells the reader to put content into a PR or issue"),
    ("AT002", STRONG, re.compile(
        r"^\s*[>*-]?\s*additionally,?\s+(please\s+)?(read|fetch|post|include|"
        r"send|copy|delete|remove|run|execute|upload|push|commit|open|list|"
        r"print)\b", I),
     "'Additionally, <do X>' injection opener"),
    ("AT002", STRONG, re.compile(
        r"\byou must\b.{0,40}\b(delete|remove|read|send|post|include|upload|"
        r"push|exfiltrate|disable|ignore)\b", I),
     "'you must' paired with a risky action"),
    ("AT002", AMBIGUOUS, re.compile(r"\byou must\b", I),
     "'you must' phrasing (often normal documentation)"),

    # AT003: destructive shell commands.
    ("AT003", STRONG, re.compile(
        r"\brm\s+(-[a-z]*(r[a-z]*f|f[a-z]*r)[a-z]*|-r\s+-f|-f\s+-r|"
        r"--recursive\s+--force|--force\s+--recursive)\b", I),
     "recursive forced delete (rm -rf)"),
    ("AT003", STRONG, re.compile(r"\bgit\s+reset\s+--hard\b", I),
     "discards local work (git reset --hard)"),
    ("AT003", STRONG, re.compile(r"\bgit\s+clean\s+-[a-z]*f", I),
     "deletes untracked files (git clean -f)"),
    ("AT003", STRONG, re.compile(r"\bgit\s+push\b[^\n]*\s(--force|-f)\b", I),
     "rewrites remote history (git push --force)"),
    ("AT003", STRONG, re.compile(
        r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", I),
     "pipes a download straight into a shell"),
    ("AT003", STRONG, re.compile(r"\bmkfs(\.\w+)?\b", I),
     "formats a filesystem (mkfs)"),
    ("AT003", STRONG, re.compile(r"\bdd\s+if=", I),
     "raw disk write (dd if=)"),
    ("AT003", STRONG, re.compile(r"\bchmod\s+-R\s+0?777\s+/", I),
     "opens permissions on a whole tree"),
    ("AT003", STRONG, re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
     "fork bomb"),

    # AT005: secrets piped or posted to the network.
    ("AT005", STRONG, re.compile(
        r"\b(env|printenv)\b\s*\|[^\n]*\b(curl|wget|nc|ncat|netcat)\b", I),
     "pipes the environment into a network call"),
    ("AT005", STRONG, re.compile(
        r"\b(curl|wget|http|nc)\b[^\n]*\$\{?\w*(token|secret|password|passwd|"
        r"api_?key|access_key|credentials?)\w*\}?", I),
     "sends a secret variable in a network call"),
    ("AT005", STRONG, re.compile(
        r"\b(curl|wget)\b[^\n]*(-d|--data[\w-]*|-F|--form|-T|--upload-file)"
        r"\s*['\"]?@?[^\s'\"]*(\.env|\.pem|id_rsa|credentials|\.npmrc|\.netrc)",
        I),
     "uploads a credential file"),
    ("AT005", STRONG, re.compile(
        r"\b(cat|base64|tar)\b[^\n|]*(\.env|\.pem|id_rsa|credentials|\.ssh|"
        r"\.npmrc|\.netrc)[^\n]*\|[^\n]*\b(curl|wget|nc|ncat|netcat)\b", I),
     "pipes a credential file into a network call"),
    ("AT005", STRONG, re.compile(
        r"\b(curl|wget)\b[^\n]*\$\(\s*(env|printenv|cat)\b", I),
     "embeds environment or file contents in a network call"),
    ("AT005", STRONG, re.compile(
        r"(requests\.(post|put)|urlopen|fetch\()[^\n]*(os\.environ|process\.env)",
        I),
     "sends environment variables over the network"),
    ("AT005", STRONG, re.compile(r"\bexfiltrat\w*", I),
     "talks about exfiltrating data"),
    ("AT005", STRONG, re.compile(
        r"\b(send|post|upload|forward)\b.{0,40}(github_token|\$\w*token|"
        r"\bsecrets?\b|\bcredentials\b|\.env\b).{0,60}https?://", I),
     "sends secrets to a URL"),

    # AT006: ordinary documentation phrasing. Only ever MEDIUM, and only in
    # untrusted files.
    ("AT006", AMBIGUOUS, re.compile(
        r"\b(you should|you can|you'll|you will|you may)\s+(now\s+)?"
        r"(want to\s+)?(run|execute|type|install)\b", I),
     "instruction phrased as documentation ('you should now run...')"),
    ("AT006", AMBIGUOUS, re.compile(r"^\s*(now|next|then),?\s+run\b", I),
     "instruction phrased as documentation ('now run...')"),
]

# AT001: hidden HTML comments.
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_ADDRESS_RE = re.compile(
    r"\b(assistant|ai|agent|copilot|claude|chatgpt|llm|language model|ignore|"
    r"disregard|before you finish|you must|additionally|instructions?)\b", I)
COMMENT_VERB_RE = re.compile(
    r"(^|[.!?;]\s+|\b(please|then|now|also|and)\s+)(delete|remove|run|execute|"
    r"read|fetch|send|post|include|add|copy|upload|print|ignore|forget|"
    r"disregard|exfiltrate|curl|write|commit|push|replace|modify|export|cat|"
    r"open|list|paste)\b", I)
COMMENT_TARGET_RE = re.compile(
    r"(\btests?\b|\.env\b|token|secret|credential|password|api.?key|\.pem\b|"
    r"\bssh\b|\bpr\b|pull request|\bcomment\b|https?://|\bcurl\b|\bwget\b|"
    r"\benv\b|private)", I)

# AT004: a credential read and an external write in the same file.
CRED_RE = re.compile(
    r"(\.env\b|\bcredentials?\b|\.pem\b|github_token|gh_token|id_rsa|\.ssh/|"
    r"aws_secret|\bsecrets?\b|\bapi[_ -]?keys?\b|private key|\.npmrc|\.netrc)",
    I)
WRITE_RE = re.compile(
    r"((pr|pull request|merge request)\s+(description|body)|"
    r"\bcomment\b.{0,20}\b(on|to|in)\b.{0,20}\b(issue|pr|pull request)\b|"
    r"\bpost(ed|s)?\b.{0,40}\bcomment\b|\bas a (public )?comment\b|"
    r"\bcurl\b[^\n]*(-d\b|--data|-F\b|-X\s*POST|-T\b)|"
    r"\b(send|post|upload|forward)\b.{0,60}https?://|\bwebhook|\bgist\b|"
    r"requests\.post|urlopen)", I)

WHY_AT001_STRONG = "hidden HTML comment that addresses an agent or asks for a risky action"
WHY_AT001_AMBIG = "hidden HTML comment containing an imperative"
WHY_AT004 = "reads a credential and writes somewhere external in the same file"

HANDLING = {
    "AT001": "Strip HTML comments before the agent reads this file, or "
             "quarantine it. Treat the comment as DATA, never as instructions.",
    "AT002": "Quarantine the file or exclude it from the agent's checkout. If "
             "the agent needs it, label it as DATA that carries no authority.",
    "AT003": "Do not let the agent run commands taken from this file. Exclude "
             "it from the checkout or label it as DATA.",
    "AT004": "Quarantine the file: it pairs a secret read with an outbound "
             "write, the shape of an exfiltration attempt.",
    "AT005": "Quarantine the file and exclude it from the agent's checkout. "
             "Check whether anything already ran it.",
    "AT006": "Probably ordinary documentation phrasing. Read it once, then "
             "label the file as DATA or dismiss the finding.",
}
HANDLING_MEDIUM = ("Ambiguous phrasing. Review it, then label the file as DATA "
                   "or dismiss the finding.")
HANDLING_LOW = ("Owner's own text, noted for awareness only. Dismiss the "
                "finding if it is intentional.")


# ---------------------------------------------------------------------------
# Secret redaction (snippets quote instruction text, never credential values)
# ---------------------------------------------------------------------------

REDACT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"[A-Za-z0-9+/_=-]{40,}"),
]
ASSIGN_RE = re.compile(
    r"\b([A-Za-z0-9_]*(token|secret|password|passwd|pwd|api_?key|access_key|"
    r"private_key|credentials?)[A-Za-z0-9_]*)(\s*[:=]\s*)(['\"]?)([^\s'\"]+)",
    I)


def redact(text: str) -> str:
    """Mask anything that looks like a credential value."""
    def _assign(m: re.Match) -> str:
        value = m.group(5)
        if value.startswith("$") or value.startswith("<"):
            return m.group(0)  # a variable reference, not a value
        return f"{m.group(1)}{m.group(3)}{m.group(4)}<redacted>"

    text = ASSIGN_RE.sub(_assign, text)
    for pat in REDACT_PATTERNS:
        text = pat.sub("<redacted>", text)
    return text


def snippet_of(text: str, limit: int = 160) -> str:
    s = redact(" ".join(text.split()))
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def normalise(text: str) -> str:
    return " ".join(text.split()).lower()


def fingerprint(rule: str, path: str, content: str) -> str:
    raw = f"{rule}\0{path}\0{normalise(content)}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    pass


@dataclass
class Config:
    trusted: list = field(default_factory=list)
    untrusted: list = field(default_factory=list)
    dismissed: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)


DEFAULT_CONFIG = {
    "_comment": [
        "agent-trust config. JSON has no comments, so notes live in keys that "
        "start with '_'; the tool ignores them.",
        "trusted / untrusted: glob lists matched against paths relative to "
        "the repo root, with '/' separators.",
        "'*' matches any characters, including '/'. A pattern ending in '/' "
        "matches everything under that directory.",
        "Config lists win over the built-in defaults. If a path matches both "
        "lists, untrusted wins.",
        "Example: \"trusted\": [\"vendor/our-own-lib/\"], \"untrusted\": "
        "[\"generated/\", \"*.patch\"]",
        "dismissed: finding fingerprints to skip on later scans. Add them "
        "with: python3 agent_trust.py dismiss <fingerprint>",
    ],
    "trusted": [],
    "untrusted": [],
    "dismissed": [],
}


def load_config(root: str) -> Config:
    path = os.path.join(root, CONFIG_NAME)
    if not os.path.isfile(path):
        return Config()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {CONFIG_NAME}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{CONFIG_NAME} must hold a JSON object")
    cfg = Config(raw=raw)
    for key in ("trusted", "untrusted", "dismissed"):
        value = raw.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{CONFIG_NAME}: '{key}' must be a list of strings")
        setattr(cfg, key, list(value))
    return cfg


def glob_match(rel: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/")
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if pattern.endswith("/"):
        return rel.startswith(pattern) or fnmatch.fnmatchcase(rel, pattern + "*")
    if fnmatch.fnmatchcase(rel, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatchcase(rel, pattern[3:]):
        return True
    return False


def matches_any(rel: str, patterns: list) -> bool:
    return any(glob_match(rel, p) for p in patterns)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(rel: str, cfg: Config) -> tuple:
    """Return (TRUSTED or UNTRUSTED, reason) for a repo-relative path."""
    if matches_any(rel, cfg.untrusted):
        return UNTRUSTED, "config: untrusted glob"
    if matches_any(rel, cfg.trusted):
        return TRUSTED, "config: trusted glob"

    parts = rel.split("/")
    dirs, name = parts[:-1], parts[-1]
    lower_dirs = [d.lower() for d in dirs]
    lname = name.lower()

    for d in lower_dirs:
        if d in DEPENDENCY_DIRS:
            return UNTRUSTED, f"dependency path ({d}/)"
    if any(d in ISSUE_DIRS for d in lower_dirs) or ISSUE_FILE_RE.match(name):
        return UNTRUSTED, "issue or PR text"
    if lname in README_NAMES and dirs:
        return UNTRUSTED, "README below the repo root"
    if not dirs and name in TRUSTED_ROOT_FILES:
        return TRUSTED, "repo owner's root doc"
    if dirs and lower_dirs[0] in TRUSTED_TOP_DIRS:
        return TRUSTED, f"owner code ({dirs[0]}/)"
    if rel.startswith(".github/workflows/"):
        return TRUSTED, "owner CI workflow"
    return TRUSTED, "repo-owned (default)"


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    name: str
    severity: str
    trust: str
    path: str
    line: int
    snippet: str
    why: str
    handling: str
    fingerprint: str


def _severity(trust: str, strength: str) -> str:
    if trust == TRUSTED:
        return LOW
    return HIGH if strength == STRONG else MEDIUM


def _handling(rule: str, severity: str) -> str:
    if severity == LOW:
        return HANDLING_LOW
    if severity == MEDIUM and rule != "AT006":
        return HANDLING_MEDIUM
    return HANDLING[rule]


def _make(rule, strength, trust, rel, line, content, why) -> Finding:
    sev = _severity(trust, strength)
    return Finding(
        rule=rule, name=RULE_NAMES[rule], severity=sev, trust=trust, path=rel,
        line=line, snippet=snippet_of(content), why=why,
        handling=_handling(rule, sev),
        fingerprint=fingerprint(rule, rel, content),
    )


def scan_text(text: str, rel: str, trust: str) -> list:
    """Return findings for one file's text. Trusted files report STRONG
    patterns only (as LOW); ambiguous phrasing in the owner's own files is
    just documentation."""
    findings = []
    keep = (lambda s: True) if trust == UNTRUSTED else (lambda s: s == STRONG)

    # AT001: hidden HTML comments.
    for m in HTML_COMMENT_RE.finditer(text):
        body = m.group(1)
        verb = COMMENT_VERB_RE.search(body.strip())
        if COMMENT_ADDRESS_RE.search(body) or (verb and COMMENT_TARGET_RE.search(body)):
            strength, why = STRONG, WHY_AT001_STRONG
        elif verb:
            strength, why = AMBIGUOUS, WHY_AT001_AMBIG
        else:
            continue
        if keep(strength):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(_make("AT001", strength, trust, rel, line, body, why))

    lines = text.splitlines()

    # Per-line rules: at most one finding per (rule, line), strongest wins.
    for idx, line in enumerate(lines, 1):
        best = {}
        for rule, strength, rx, why in LINE_PATTERNS:
            if not rx.search(line):
                continue
            prev = best.get(rule)
            if prev is None or (prev[0] == AMBIGUOUS and strength == STRONG):
                best[rule] = (strength, why)
        for rule in sorted(best):
            strength, why = best[rule]
            if keep(strength):
                findings.append(_make(rule, strength, trust, rel, idx, line, why))

    # AT004: credential read plus external write anywhere in the same file.
    cred_line = next((i for i, l in enumerate(lines, 1) if CRED_RE.search(l)), None)
    write_line = next((i for i, l in enumerate(lines, 1) if WRITE_RE.search(l)), None)
    if cred_line and write_line:
        content = lines[cred_line - 1]
        if write_line != cred_line:
            content = content + "\n" + lines[write_line - 1]
        why = f"{WHY_AT004} (credential: line {cred_line}, write: line {write_line})"
        f = _make("AT004", STRONG, trust, rel, cred_line, content, why)
        f.snippet = snippet_of(lines[cred_line - 1])
        findings.append(f)

    return findings


def iter_files(root: str):
    """Yield (relative posix path, absolute path) in sorted, stable order."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            abspath = os.path.join(dirpath, name)
            rel = os.path.relpath(abspath, root).replace(os.sep, "/")
            yield rel, abspath


def read_text(abspath: str):
    """Return (text, None) or (None, skip reason)."""
    try:
        st = os.lstat(abspath)
    except OSError as exc:
        return None, f"unreadable ({exc.strerror})"
    if os.path.islink(abspath):
        return None, "symlink"
    if st.st_size > MAX_BYTES:
        return None, "larger than 1 MB"
    try:
        with open(abspath, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return None, f"unreadable ({exc.strerror})"
    if b"\0" in data[:BINARY_PROBE]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), None


def scan(root: str) -> dict:
    cfg = load_config(root)
    dismissed = set(cfg.dismissed)
    files, skipped, findings = [], [], []
    dismissed_count = 0

    for rel, abspath in iter_files(root):
        if rel == CONFIG_NAME:
            skipped.append({"path": rel, "reason": "agent-trust config"})
            continue
        text, reason = read_text(abspath)
        if text is None:
            skipped.append({"path": rel, "reason": reason})
            continue
        trust, why = classify(rel, cfg)
        files.append({"path": rel, "trust": trust, "reason": why})
        for f in scan_text(text, rel, trust):
            if f.fingerprint in dismissed:
                dismissed_count += 1
                continue
            findings.append(f)

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.path, f.line, f.rule))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in (HIGH, MEDIUM, LOW)}
    summary = {
        "files": len(files),
        "trusted": sum(1 for f in files if f["trust"] == TRUSTED),
        "untrusted": sum(1 for f in files if f["trust"] == UNTRUSTED),
        "skipped": len(skipped),
        "findings": len(findings),
        "high": counts[HIGH],
        "medium": counts[MEDIUM],
        "low": counts[LOW],
        "dismissed": dismissed_count,
    }
    return {
        "tool": "agent-trust",
        "version": VERSION,
        "files": files,
        "skipped": skipped,
        "findings": [asdict(f) for f in findings],
        "summary": summary,
    }


def exit_code(report: dict, strict: bool) -> int:
    if not strict:
        return EXIT_OK
    s = report["summary"]
    if s["high"]:
        return EXIT_HIGH
    if s["findings"]:
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def summary_line(report: dict) -> str:
    s = report["summary"]
    return (f"SUMMARY: {s['files']} files scanned ({s['trusted']} trusted, "
            f"{s['untrusted']} untrusted), {s['skipped']} skipped; "
            f"{s['findings']} findings (HIGH {s['high']}, MEDIUM {s['medium']}, "
            f"LOW {s['low']}); {s['dismissed']} dismissed")


def render_text(report: dict, root_label: str) -> str:
    out = [f"agent-trust {VERSION}: scan of {root_label}", ""]
    files = sorted(report["files"], key=lambda f: (f["trust"] != UNTRUSTED, f["path"]))
    width = min(max([len(f["path"]) for f in files] + [4]), 60)
    out.append(f"TRUST MAP ({len(files)} files)")
    for f in files:
        out.append(f"  {f['trust']:<9}  {f['path']:<{width}}  {f['reason']}")
    if report["skipped"]:
        out.append("")
        out.append(f"SKIPPED ({len(report['skipped'])})")
        for s in report["skipped"]:
            out.append(f"  {s['path']}  ({s['reason']})")
    out.append("")
    findings = report["findings"]
    out.append(f"FINDINGS ({len(findings)})")
    if not findings:
        out.append("  none")
    for f in findings:
        out.append(f"  [{f['severity']}] {f['path']}:{f['line']}  {f['rule']} {f['name']}")
        out.append(f"      quote: \"{f['snippet']}\"")
        out.append(f"      why: {f['why']}")
        out.append(f"      handling: {f['handling']}")
        out.append(f"      fingerprint: {f['fingerprint']}")
    out.append("")
    out.append(summary_line(report))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _err(msg: str) -> int:
    sys.stderr.write(f"agent-trust: error: {msg}\n")
    return EXIT_ERROR


def cmd_scan(args) -> int:
    if not os.path.isdir(args.path):
        return _err(f"not a directory: {args.path}")
    try:
        report = scan(args.path)
    except ConfigError as exc:
        return _err(str(exc))
    if args.json:
        out = dict(report)
        out["root"] = args.path
        print(json.dumps(out, indent=2, sort_keys=True))
    elif args.quiet:
        print(summary_line(report))
    else:
        print(render_text(report, args.path))
    return exit_code(report, args.strict)


def cmd_init(args) -> int:
    if not os.path.isdir(args.path):
        return _err(f"not a directory: {args.path}")
    target = os.path.join(args.path, CONFIG_NAME)
    if os.path.exists(target) and not args.force:
        return _err(f"{target} already exists (use --force to overwrite)")
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)
        fh.write("\n")
    print(f"wrote {target}")
    return EXIT_OK


FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")


def cmd_dismiss(args) -> int:
    fp = args.fingerprint.strip().lower()
    if not FINGERPRINT_RE.match(fp):
        return _err(f"not a fingerprint (expected 16 hex characters): {args.fingerprint}")
    if not os.path.isdir(args.path):
        return _err(f"not a directory: {args.path}")
    try:
        cfg = load_config(args.path)
    except ConfigError as exc:
        return _err(str(exc))
    raw = dict(cfg.raw) if cfg.raw else {"trusted": [], "untrusted": [], "dismissed": []}
    dismissed = list(cfg.dismissed)
    target = os.path.join(args.path, CONFIG_NAME)
    if fp in dismissed:
        print(f"{fp} is already dismissed in {target}")
        return EXIT_OK
    dismissed.append(fp)
    raw["dismissed"] = dismissed
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2)
        fh.write("\n")
    print(f"dismissed {fp} in {target}")
    return EXIT_OK


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 3 so they never collide with the --strict codes."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EXIT_ERROR)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="agent_trust.py",
                description="Untrusted-content pre-flight for agent workspaces.")
    p.add_argument("--version", action="version", version=f"agent-trust {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="map trusted vs untrusted text and flag risky instructions")
    s.add_argument("path", nargs="?", default=".", help="workspace root (default: .)")
    s.add_argument("--json", action="store_true", help="machine-readable report")
    s.add_argument("--strict", action="store_true",
                   help="exit 2 on any HIGH finding, 1 on any other finding, 0 if clean")
    s.add_argument("--quiet", action="store_true", help="print only the summary line")
    s.set_defaults(func=cmd_scan)

    i = sub.add_parser("init", help=f"write a default {CONFIG_NAME}")
    i.add_argument("path", nargs="?", default=".", help="workspace root (default: .)")
    i.add_argument("--force", action="store_true", help="overwrite an existing config")
    i.set_defaults(func=cmd_init)

    d = sub.add_parser("dismiss", help="record a finding fingerprint so later scans skip it")
    d.add_argument("fingerprint", help="16-character fingerprint from a scan report")
    d.add_argument("--path", default=".", help="workspace root holding the config (default: .)")
    d.set_defaults(func=cmd_dismiss)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
