#!/usr/bin/env python3
"""Env/config secret scanner (top-50 #10). Stdlib only.

Scans a directory tree for hardcoded-secret shapes and reports
file:line:rule only. A matched value is NEVER printed: a finding
line carries the relative file path, the line number, the rule
name, and the matched value's length at most.

Exit codes: 1 if any finding, 0 if clean, 2 on a bad path.
"""

import os
import re
import sys

# Values that are obviously placeholders or test dummies, not
# secrets. Only applied to the generic/env-assignment rules, where
# the value is a free string. A test-prefixed literal ("test-...")
# is a dummy by construction, not a production secret.
PLACEHOLDER = re.compile(
    r"(^test[-_]|your[-_]|example|changeme|placeholder|xxx|<\S+>)",
    re.IGNORECASE,
)

# One finding per line at most: rules are tried in priority order
# and the first match wins, so a line is never reported twice.
RULES = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(
        r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # Quoted string literal only: `token = derive(...)` or
    # `token = None` are code, not hardcoded secrets. The keyword
    # must start a fresh underscore-separated segment (so
    # DB_PASSWORD and CAGE_MASTER_SECRET match, but a word like
    # "monkey" does not). An optional b prefix covers bytes
    # literals, the usual shape for HMAC keys.
    ("generic-assignment", re.compile(
        r"""(?i)(?:^|[^A-Za-z0-9])(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*b?["']([^"']{4,})["']""")),
    # os.environ["NAME"] = "value" style test/setup assignments,
    # including prefixed names like DATABASE_PASSWORD.
    ("env-assignment", re.compile(
        r"""(?i)\[["'][^"']*?(password|passwd|secret|api[_-]?key|token)\b[^"']*["']\]\s*=\s*b?["']([^"']{4,})["']""")),
]

SKIP_DIRS = {"__pycache__", ".git", "node_modules"}


def scan_file(path, root):
    """Yield (relpath, lineno, rule, value_len) findings for one file."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except (UnicodeDecodeError, OSError):
        return  # binary or unreadable: not scannable text
    rel = os.path.relpath(path, root)
    for lineno, line in enumerate(lines, 1):
        for rule, pattern in RULES:
            match = pattern.search(line)
            if not match:
                continue
            if rule in ("generic-assignment", "env-assignment"):
                value = match.group(2)
                if PLACEHOLDER.search(value):
                    break  # placeholder, not a secret; stop at this line
                length = len(value)
            else:
                length = len(match.group(0))
            yield (rel, lineno, rule, length)
            break  # first matching rule wins for this line


def scan_dir(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            findings.extend(scan_file(os.path.join(dirpath, name), root))
    return findings


def main(argv):
    if len(argv) != 2:
        print("usage: secret_scanner.py <directory>", file=sys.stderr)
        return 2
    root = argv[1]
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    findings = scan_dir(root)
    for rel, lineno, rule, length in findings:
        print(f"{rel}:{lineno}:{rule} len={length}")
    print(f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
