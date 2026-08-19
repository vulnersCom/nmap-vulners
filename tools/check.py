#!/usr/bin/env python3
"""Repository hygiene gate for this public repository.

Checks what the test suite cannot: that nothing which must never be published
has entered the tree, and that text files keep one consistent shape.

  * secrets and credential-looking blobs
  * AI assistant and agent leftovers
  * OS, editor and scan-output clutter
  * CRLF, trailing whitespace, missing final newline
  * every JSON file in the tree stays valid JSON, catalog/ included

Run it from the repository root:

    python3 tools/check.py

Exit status is non-zero when something needs fixing.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# A line may be exempted from the secret scan by ending it with this marker.
# Whole-file exemptions used to be listed here instead, which turned the files
# that handle the API key - the end-to-end runner above all - into the one
# place a real token could be committed unnoticed.
ALLOW_MARKER = "hygiene-allow"

# Fixtures that are deliberately malformed, because a test feeds them to the
# scripts to prove the failure path is handled.
INTENTIONALLY_MALFORMED = {
    # Its CRLF line endings are the thing under test.
    "tests/fixtures/paths_crlf.txt",
}

# Token shapes of the common providers, plus private key blocks.
SECRET_PATTERNS = [
    ("Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI-style key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub PAT", re.compile(r"github_pat_[A-Za-z0-9_]{30,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}")),
    ("Vulners API key assignment",
     re.compile(r"""api_key\s*=\s*["'][A-Za-z0-9]{20,}["']""")),
    # A Vulners token is 64 characters of mixed-case alphanumerics and carries
    # no prefix to key on, so the shape is all there is: either assigned to
    # something named like a credential, or standing alone on its own line the
    # way a key file holds it. These two patterns used to demand [0-9a-f],
    # which no real token satisfies - a committed key file passed the gate.
    ("credential-shaped token",
     re.compile(r"(?i)(?:api[_-]?key|token|secret|bearer)\W{0,4}\b[A-Za-z0-9]{40,}\b")),
    ("bare 64-character token", re.compile(r"^\s*[A-Za-z0-9]{64}\s*$")),
]

# Samples the secret scan must keep catching, and samples it must keep
# ignoring. They are assembled rather than written out, so that scanning this
# file does not flag the scanner's own test data.
_KEY_BODY = "A1B2c3D4" * 8

MUST_MATCH = [
    ("key file holding a token on its own line", _KEY_BODY),
    ("key file line with surrounding whitespace", "  " + _KEY_BODY + "  "),
    ("token of the shape the live service issues", "A1B2C3D4" * 8),
    ("token written as lowercase hex", "abcdef01" * 8),
    ("token assigned to a credential-shaped name", "VULNERS_API_KEY=" + _KEY_BODY),
    ("bearer header", "Authorization: Bearer " + _KEY_BODY),
]

MUST_NOT_MATCH = [
    ("ordinary prose", "the scan found nothing worth reporting here"),
    ("a short identifier", "cpe:/a:apache:http_server:2.4.49"),
    ("an alphanumeric run below the threshold", "B" + "a1" * 19),
]

# Paths that must never be tracked in this repository.
FORBIDDEN_PATTERNS = [
    ("AI assistant artifact",
     re.compile(r"(^|/)(CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md|PROBLEMS\.md"
                r"|\.cursorrules|\.windsurfrules|\.aider[^/]*|\.mcp\.json)$")),
    ("AI assistant directory",
     re.compile(r"(^|/)\.(claude|codex|cursor|continue|windsurf|codeium|specstory)/")),
    ("AI working notes", re.compile(r"(^|/)dev_docs/")),
    ("OS clutter", re.compile(r"(^|/)(\.DS_Store|Thumbs\.db|Desktop\.ini|\._[^/]+)$")),
    ("editor clutter", re.compile(r"(^|/)(\.idea/|\.vscode/|[^/]+\.sw[op]$|[^/]+~$)")),
    ("nmap scan output", re.compile(r"\.(nmap|gnmap)$")),
    ("nmap XML scan output", re.compile(r"(^|/)(scan|output|results?)[^/]*\.xml$")),
    ("session notes", re.compile(r"(^|/)(handoff|handoffs|plans?|notes)/")),
    ("environment file", re.compile(r"(^|/)\.env(\.|$)")),
    ("key material", re.compile(r"\.(pem|p12|pfx|keystore)$|(^|/)id_(rsa|ed25519)")),
]

# Every shipped script carries the same author and the same licence line; the
# licence has to be Nmap's, because the scripts run as part of Nmap and the
# LICENSE file in this repository is Nmap's own text.
REQUIRED_SCRIPT_FIELDS = {
    "author": 'author = "Vulners Team (info@vulners.com)"',
    "license": 'license = "Same as Nmap--See https://nmap.org/book/man-legal.html"',
}

TEXT_SUFFIXES = {".nse", ".lua", ".json", ".txt", ".md", ".py", ".yml", ".yaml",
                 ".sh", ".ps1"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".editorconfig"}


def tracked_files():
    """Files git knows about, as repo-relative paths."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


class Report:
    def __init__(self):
        self.problems = []

    def problem(self, path, message):
        self.problems.append(f"{path}: {message}")

    def summary(self, checked):
        if not self.problems:
            print(f"hygiene ok - {checked} tracked files checked")
            return 0
        print(f"hygiene FAILED - {len(self.problems)} problem(s):\n")
        for line in self.problems:
            print(f"  {line}")
        return 1


def is_text(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES


def check_forbidden(report, paths):
    for path in paths:
        for label, pattern in FORBIDDEN_PATTERNS:
            if pattern.search(path):
                report.problem(path, f"{label} must not be tracked")


def check_secrets(report, paths):
    for path in paths:
        full = REPO / path
        try:
            content = full.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            report.problem(path, f"cannot be read: {exc}")
            continue

        for number, line in enumerate(content.splitlines(), 1):
            if ALLOW_MARKER in line:
                continue
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    # Never echo the value itself.
                    report.problem(path, f"looks like a {label} on line {number}")


def check_script_metadata(report, paths):
    """The shipped scripts agree on who wrote them and under what licence."""
    for path in paths:
        if not path.endswith(".nse") or path.startswith("tests/"):
            continue
        content = (REPO / path).read_text(encoding="utf-8", errors="ignore")
        for field, expected in REQUIRED_SCRIPT_FIELDS.items():
            if expected not in content:
                report.problem(path, f"{field} must read exactly: {expected}")


def check_text_shape(report, paths):
    for path in paths:
        if path in INTENTIONALLY_MALFORMED:
            continue
        full = REPO / path
        if not is_text(full):
            continue
        try:
            data = full.read_bytes()
        except OSError as exc:
            # A tracked file that is not on disk is a problem to report, not a
            # traceback to read.
            report.problem(path, f"cannot be read: {exc}")
            continue
        if not data:
            continue
        if b"\r\n" in data:
            report.problem(path, "contains CRLF line endings")
        if not data.endswith(b"\n"):
            report.problem(path, "has no final newline")
        for number, line in enumerate(data.split(b"\n"), start=1):
            if full.suffix == ".md":
                # Two trailing spaces are a meaningful line break in Markdown.
                continue
            if line != line.rstrip():
                report.problem(path, f"trailing whitespace on line {number}")
                break


def check_json(report, paths):
    for path in paths:
        if path in INTENTIONALLY_MALFORMED or not path.endswith(".json"):
            continue
        try:
            json.loads((REPO / path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            report.problem(path, f"is not valid JSON: {exc}")


def check_secret_patterns(report):
    """The secret patterns still match the shapes they exist to catch.

    Nothing else notices when one of them is narrowed: the scan simply stops
    reporting, and a repository that publishes everything it tracks keeps
    looking clean. That is not hypothetical - it is how the hex-only pattern
    above survived long enough to be found by hand.
    """
    for label, sample in MUST_MATCH:
        if not any(pattern.search(sample) for _, pattern in SECRET_PATTERNS):
            report.problem("tools/check.py",
                           f"the secret scan no longer catches a {label}")
    for label, sample in MUST_NOT_MATCH:
        hit = next((name for name, pattern in SECRET_PATTERNS
                    if pattern.search(sample)), None)
        if hit:
            report.problem("tools/check.py",
                           f"the secret scan now reports {label} as a {hit}")


def main():
    paths = tracked_files()
    report = Report()
    check_secret_patterns(report)
    check_forbidden(report, paths)
    check_secrets(report, paths)
    check_script_metadata(report, paths)
    check_text_shape(report, paths)
    check_json(report, paths)
    return report.summary(len(paths))


if __name__ == "__main__":
    sys.exit(main())
