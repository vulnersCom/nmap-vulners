#!/usr/bin/env python3
"""Repository hygiene gate for this public repository.

Checks what the test suite cannot: that nothing which must never be published
has entered the tree, and that text files keep one consistent shape.

  * secrets and credential-looking blobs
  * AI assistant and agent leftovers
  * OS, editor and scan-output clutter
  * CRLF, trailing whitespace, missing final newline
  * every JSON file in the tree stays valid JSON, catalog/ included
  * no .nse file reaches a global that is not there

Run it from the repository root:

    python3 tools/check.py

Exit status is non-zero when something needs fixing.
"""

import argparse
import json
import re
import shutil
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
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"
                       r"\.[A-Za-z0-9_-]{10,}")),
    ("Vulners API key assignment",
     re.compile(r"""api_key\s*=\s*["'][A-Za-z0-9]{20,}["']""")),
    # A Vulners token is 64 characters of mixed-case alphanumerics and carries
    # no prefix to key on, so the shape is all there is: either assigned to
    # something named like a credential, or standing alone on its own line the
    # way a key file holds it. These two patterns used to demand [0-9a-f],
    # which no real token satisfies - a committed key file passed the gate.
    ("credential-shaped token",
     re.compile(r"(?i)(?:api[_-]?key|token|secret|bearer)\W{0,4}"
                r"\b[A-Za-z0-9]{40,}\b")),
    ("bare 64-character token", re.compile(r"^\s*[A-Za-z0-9]{64}\s*$")),
    # The two patterns above between them need either a credential-shaped WORD
    # beside the token or the token ALONE on its line, so a quote or a comma
    # defeated both: measured, 8 of 12 plausible placements of a real 64-byte
    # token were invisible - as a JSON value, in a dict literal, in YAML, in a
    # quoted shell export, in a CSV cell, in prose.
    #
    # A token needs no keyword to be a token. What it cannot hide is its shape:
    # a long unbroken alphanumeric run carrying both cases. Measured over every
    # tracked file, catalogue included, this fires zero times on real content -
    # patterns, paths and CPEs all break on punctuation long before 40.
    ("high-entropy token", re.compile(
        r"(?<![A-Za-z0-9+/=])"
        r"(?=[A-Za-z0-9]{40,}(?![A-Za-z0-9]))"
        r"(?=[a-z0-9]*[A-Z])(?=[A-Z0-9]*[a-z])"
        r"[A-Za-z0-9]{40,}")),
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
    ("token assigned to a credential-shaped name",
        "VULNERS_API_KEY=" + _KEY_BODY),
    ("bearer header", "Authorization: Bearer " + _KEY_BODY),
    # The placements that used to slip through. They are here rather than in a
    # comment because this list is what keeps the patterns honest: the scanner
    # was confidently green while missing every one of them.
    ("token as a JSON value", '  "value": "' + _KEY_BODY + '",'),
    ("token in a dict literal", 'CONFIG = {"vulners": "' + _KEY_BODY + '"}'),
    ("token as a YAML value", "  credential: " + _KEY_BODY),
    ("token in a quoted shell export",
        'export VULNERS_KEY="' + _KEY_BODY + '"'),
    ("token in a CSV cell", "prod," + _KEY_BODY + ",active"),
]

MUST_NOT_MATCH = [
    ("ordinary prose", "the scan found nothing worth reporting here"),
    ("a short identifier", "cpe:/a:apache:http_server:2.4.49"),
    ("an alphanumeric run below the threshold", "B" + "a1" * 19),
]

# Paths that must never be tracked in this repository.
FORBIDDEN_PATTERNS = [
    ("AI assistant artifact",
     re.compile(r"(^|/)(CLAUDE(\.local)?\.md|AGENTS\.md|GEMINI\.md"
                r"|PROBLEMS\.md"
                r"|\.cursorrules|\.windsurfrules|\.aider[^/]*|\.mcp\.json)$")),
    ("AI assistant directory",
     re.compile(r"(^|/)\.(claude|codex|cursor|continue|windsurf|codeium"
                r"|specstory)/")),
    ("AI working notes", re.compile(r"(^|/)dev_docs/")),
    ("OS clutter",
        re.compile(r"(^|/)(\.DS_Store|Thumbs\.db|Desktop\.ini|\._[^/]+)$")),
    ("editor clutter",
        re.compile(r"(^|/)(\.idea/|\.vscode/|[^/]+\.sw[op]$|[^/]+~$)")),
    ("nmap scan output", re.compile(r"\.(nmap|gnmap)$")),
    ("nmap XML scan output",
        re.compile(r"(^|/)(scan|output|results?)[^/]*\.xml$")),
    ("session notes", re.compile(r"(^|/)(handoff|handoffs|plans?|notes)/")),
    ("environment file", re.compile(r"(^|/)\.env(\.|$)")),
    ("key material",
        re.compile(r"\.(pem|p12|pfx|keystore)$|(^|/)id_(rsa|ed25519)")),
]

# Every shipped script carries the same author and the same licence line; the
# licence has to be Nmap's, because the scripts run as part of Nmap and the
# LICENSE file in this repository is Nmap's own text.
REQUIRED_SCRIPT_FIELDS = {
    "author": 'author = "Vulners Team (info@vulners.com)"',
    "license": 'license = "Same as Nmap--See '
               'https://nmap.org/book/man-legal.html"',
}

# .xml is here for tests/fixtures/golden_1x.xml, the calibration capture the
# XML contract is measured against. It cannot be regenerated - 1.x is gone -
# so a CRLF conversion by a contributor on Windows would quietly destroy the
# one artefact that proves the report shape did not change.
#
# LICENSE is deliberately absent: it is nmap's own text, held verbatim, and it
# carries a line with trailing whitespace. Reformatting somebody else's licence
# to satisfy this repository's linter is not a trade worth making.
TEXT_SUFFIXES = {".nse", ".lua", ".json", ".txt", ".md", ".py", ".yml",
                 ".yaml",
                 ".sh", ".ps1", ".xml"}
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
                    report.problem(path,
                                   f"looks like a {label} on line {number}")


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


# Every name an .nse file in this repository may legitimately reach through
# _ENV. Anything else is either a typo or a local read above its own `local`
# line - and in Lua that is not a warning, it is a global read. NSE runs its
# scripts in a strict environment, so the read raises, and nmap answers a
# script that raised by replacing the port's ENTIRE result with "Script
# execution failed": every finding on that port lost, in the text output and in
# the XML.
#
# Not hypothetical. A guard in audit_smart read `#fresh` eleven lines above
# `local fresh`, so every scan that made a SECOND billed call lost the port it
# was on. The suite was green: nothing had ever made two.
ALLOWED_GLOBALS = {
    # Set by nse_main before a script chunk runs.
    "SCRIPT_NAME", "SCRIPT_TYPE",
    # What a script may define. nse_main hard-requires only some of these.
    "action", "author", "categories", "dependencies", "description",
    "hostrule", "license", "portrule", "postrule", "prerule",
    # This repository's one deliberate export, and the test runner's fixtures.
    "_TEST",
    # Lua's own, as reached without a module prefix.
    "assert", "collectgarbage", "dofile", "error", "getmetatable", "ipairs",
    "load", "loadfile", "next", "pairs", "pcall", "print", "rawequal",
    "rawget", "rawlen", "rawset", "require", "select", "setmetatable",
    "tonumber", "tostring", "type", "xpcall",
    # The standard libraries, reached by their table name. NSE's environment
    # provides all of these; they are listed because the check also reads the
    # test harness, which uses them directly.
    "io", "math", "os", "package", "string", "table", "_G",
}

# Names every one of this repository's .nse files reaches through _ENV, used as
# a positive control. Without one, a luac whose listing wording differs - a
# 5.5 build, a distribution patch - makes GLOBAL_ACCESS match nothing, the loop
# body never runs, and the whole barrier passes in silence. Its sibling
# check_secret_patterns has guarded itself with MUST_MATCH all along.
CONTROL_GLOBALS = {"author", "license"}

# How luac notes a read of or a write to a global: the operand comment on a
# GETTABUP/SETTABUP against the _ENV upvalue. `luac -l` lists nested functions
# too, so a name reached only inside one closure is still seen.
GLOBAL_ACCESS = re.compile(r'; _ENV "([A-Za-z_][A-Za-z0-9_]*)"')


def lua_compiler():
    """Whatever luac this machine has, or None."""
    for name in ("luac5.4", "luac54", "luac", "luac5.5", "luac55"):
        found = shutil.which(name)
        if found:
            return found
    return None


# Counts the published documentation states, and the file each is a count of.
# Written out three times across two files, and wrong in all three places twice
# in two iterations - the catalogue grows on a schedule and prose does not. A
# number a reader can check is a number that has to be right.
DOCUMENTED_COUNTS = [
    (re.compile(r"(\d[\d ]*) product and version rules"),
     "fingerprints.json", "rules"),
    (re.compile(r"(\d[\d ]*) paths the sweep requests"), "paths.json",
                      "paths"),
    (re.compile(r"(\d[\d ]*) targeted version probes"), "probes.json",
                      "probes"),
    # The phrasings the prose actually reaches for. Five of the eleven places
    # these numbers appear used to be gated, and the catalogue rebuilds on a
    # schedule while prose does not - so the ungated six were guaranteed to go
    # stale. The rule for a contributor is therefore: say "N rules" or
    # "N paths", and this checks it; invent a third phrasing and it will not.
    (re.compile(r"(\d[\d ]*) rules\b"), "fingerprints.json", "rules"),
    (re.compile(r"(\d[\d ]*)[- ]paths?\b"), "paths.json", "paths"),
    (re.compile(r"(\d[\d ]*) probes\b"), "probes.json", "probes"),
]

COUNTED_DOCS = ("README.md", "CONTRIBUTING.md")


def catalogue_sizes():
    """How big each dictionary actually is, or None when one cannot be read."""
    sizes = {}
    for name, field in (("fingerprints.json", "rules"), ("paths.json",
                                                         "paths"),
                        ("probes.json", "probes")):
        try:
            loaded = json.loads(
                (REPO / "catalog" / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        sizes[(name, field)] = len(loaded.get(field) or ())
    return sizes


def check_documented_counts(report, paths):
    """The sizes the documentation states are the sizes the catalogue has."""
    sizes = catalogue_sizes()
    if sizes is None:
        report.problem("catalog/", "cannot be read, so the documented counts "
                                   "could not be checked")
        return

    for path in COUNTED_DOCS:
        if path not in paths:
            continue
        text = (REPO / path).read_text(encoding="utf-8")
        for pattern, name, field in DOCUMENTED_COUNTS:
            real = sizes[(name, field)]
            for stated in pattern.findall(text):
                if int(stated.replace(" ", "")) != real:
                    report.problem(path, "says %s where catalog/%s holds %d"
                                   % (stated.strip(), name, real))


def check_lua_globals(report, paths):
    """No Lua file reaches a name that is not there.

    The harness is checked alongside the scripts: a local read above its own
    declaration behaves identically there - it raises only when that branch
    runs, and the suite is green until it does.
    """
    luac = lua_compiler()
    if luac is None:
        print("note: no luac on this machine, so the global check was skipped")
        return

    for path in sorted(p for p in paths if p.endswith((".nse", ".lua"))):
        listing = subprocess.run([luac, "-p", "-l", str(REPO / path)],
                                 capture_output=True, text=True)
        if listing.returncode != 0:
            report.problem(path, "does not compile: %s"
                           % listing.stderr.strip().splitlines()[-1:])
            continue
        reached = set(GLOBAL_ACCESS.findall(listing.stdout))
        # Only the shipped scripts, scoped exactly as check_script_metadata
        # scopes them: a harness fixture is deliberately minimal and declares
        # neither field.
        shipped = path.endswith(".nse") and not path.startswith("tests/")
        if shipped and not CONTROL_GLOBALS <= reached:
            report.problem(path, "luac's listing was not understood, so the "
                                 "global check did not actually run; expected "
                                 "to see %s reached through _ENV"
                                 % ", ".join(sorted(CONTROL_GLOBALS)))
            continue
        for name in sorted(reached):
            if name not in ALLOWED_GLOBALS:
                report.problem(
                    path,
                    "reaches the global %r; if that is a local, it is used "
                    "above its own declaration" % name)


def main():
    # Without this, "--help" ran the whole check and printed its result, which
    # is a confusing way to answer a question about usage - and the only one of
    # the four tools here that behaved that way.
    argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()

    paths = tracked_files()
    report = Report()
    check_secret_patterns(report)
    check_forbidden(report, paths)
    check_secrets(report, paths)
    check_script_metadata(report, paths)
    check_text_shape(report, paths)
    check_json(report, paths)
    check_lua_globals(report, paths)
    check_documented_counts(report, paths)
    return report.summary(len(paths))


if __name__ == "__main__":
    sys.exit(main())
