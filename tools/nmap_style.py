#!/usr/bin/env python3
"""Hold this repository to Nmap's own Code Standards.

vulners.nse is a script for nmap, and nmap publishes what it expects of one:
HACKING points at https://secwiki.org/w/Nmap/Code_Standards, and that page
links the check script at
https://gist.github.com/dmiller-nmap/5e0c5b5524d0a594e38785d3cdc8dc07 .

This gate is that page, expressed as a test. It is not a copy of the gist:
the gist's Lua half is a globals check that tools/check.py already runs with
luac, and its Python half shells out to a pep8 binary. What is left - the
whitespace rules, the line length, the Lua rules and the NSEdoc conventions -
is here, so a rule nobody can run is not a rule.

    all languages   space and newline only: no tabs, ever; LF endings; no
                    trailing whitespace; UTF-8; one newline at end of file;
                    lines under 80 columns
    Lua             everything local (tools/check.py); NSEdoc where it helps;
                    no semicolons; explicit endianness in string.pack and
                    string.unpack; structured output; no bin or bit library
    NSEdoc          private documentation opens with --; not ---; no @tag
                    before the first --- block; a script declares description,
                    author, license and categories
    Python          PEP 8, through pycodestyle, with the gist's ignore list
    Shell           POSIX sh, and a #!/bin/sh shebang

Three exemptions, each because the alternative is a lie rather than a longer
line:

  * a line inside a Lua [[ long bracket ]] is data - a captured page, a JSON
    fixture - and rewrapping it changes what was captured
  * a line inside an @output or @xmloutput block is a verbatim capture of what
    the script prints, and the report itself is wider than 80 columns since
    every row carries a vulners.com link
  * LICENSE is nmap's own text, carried unmodified

Run from the repository root. Exits non-zero on the first finding, like every
other gate here.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WIDTH = 79

# The gist runs pep8 with these off: they are the continuation-line rules,
# where the tool has an opinion and reasonable code has another.
PEP8_IGNORE = "E123,E124,E126,E127,E128,W503,W504"

# The languages the standards speak about, plus PowerShell, which they do not
# mention and which we hold to the same width anyway. Line length is measured
# here and nowhere else: nmap's own markdown runs well past 80 columns, a
# generated catalogue has no line breaks to give, and .gitignore is a list of
# paths.
CODE = (".nse", ".lua", ".luadoc", ".py", ".sh", ".ps1")
UNTOUCHED = (
    "LICENSE",                        # nmap's own text, carried unmodified
    "tests/fixtures/paths_crlf.txt",  # CRLF on purpose: it proves the reader
                                      # survives a file written on Windows,
                                      # and .gitattributes keeps it that way
)


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True,
                         text=True, check=True)
    return [name for name in out.stdout.split() if name not in UNTOUCHED]


def long_bracket_lines(lines):
    """Line numbers inside a Lua [[ ]], which hold data rather than layout."""
    inside = set()
    open_at = None
    for n, line in enumerate(lines, 1):
        if open_at is None:
            if "[[" in line and "]]" not in line:
                open_at = n
                inside.add(n)
            elif "[[" in line:
                inside.add(n)
        else:
            inside.add(n)
            if "]]" in line:
                open_at = None
    return inside


def sample_lines(lines):
    """Line numbers inside an @output or @xmloutput block."""
    inside = set()
    showing = False
    for n, line in enumerate(lines, 1):
        if re.match(r"^-- @(output|xmloutput)\b", line):
            showing = True
            continue
        if showing:
            if not line.startswith("--"):
                showing = False
                continue
            if re.match(r"^-- @", line):
                showing = False
                continue
            inside.add(n)
    return inside


class Findings:
    def __init__(self):
        self.items = []

    def add(self, where, rule, detail=""):
        self.items.append((where, rule, detail))

    def report(self):
        if not self.items:
            print("nmap style ok - %d tracked files checked" % self.checked)
            return 0
        for where, rule, detail in self.items[:40]:
            print("%-44s %s%s" % (where, rule, "  " + detail if detail else ""))
        if len(self.items) > 40:
            print("... and %d more" % (len(self.items) - 40))
        print("\n%d findings against Nmap's Code Standards" % len(self.items))
        return 1


def check_bytes(name, raw, found):
    if b"\r\n" in raw:
        found.add(name, "CRLF line endings")
    if not raw.endswith(b"\n"):
        found.add(name, "no newline at end of file")
    elif raw.endswith(b"\n\n"):
        found.add(name, "a blank line at end of file")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        found.add(name, "not UTF-8")


def check_lines(name, lines, found):
    measure_length = name.endswith(CODE)
    exempt = set()
    if name.endswith((".nse", ".lua", ".luadoc")):
        exempt = long_bracket_lines(lines) | sample_lines(lines)

    for n, line in enumerate(lines, 1):
        where = "%s:%d" % (name, n)
        if "\t" in line:
            found.add(where, "a tab")
        if line != line.rstrip():
            found.add(where, "trailing whitespace")
        if measure_length and len(line) > WIDTH and n not in exempt:
            found.add(where, "over %d columns" % WIDTH, "%d" % len(line))


def check_lua(name, text, lines, found):
    data = long_bracket_lines(lines)
    for n, line in enumerate(lines, 1):
        if n in data:
            continue
        code = line.split("--")[0]
        code = re.sub(r'"[^"]*"', '""', code)
        code = re.sub(r"'[^']*'", "''", code)
        if ";" in code:
            found.add("%s:%d" % (name, n), "a semicolon", line.strip()[:40])

    if re.search(r'require\s*\(?\s*["\'](bin|bit)["\']', text):
        found.add(name, "the deprecated bin or bit library")

    for mark, fmt in re.findall(
            r"string\.(?:pack|unpack)\s*\(\s*(['\"])([^'\"]*)\1", text):
        if not fmt[:1] in "<>=!":
            found.add(name, "string.pack without explicit endianness", fmt)

    # The gist's perl one-liner: an @tag in the first comment block is an
    # error unless that block opened with ---.
    for n, line in enumerate(lines, 1):
        if line.startswith("---"):
            break
        if re.match(r"^-- *@", line):
            found.add("%s:%d" % (name, n), "an @tag before the first --- block")
            break

    # Private documentation opens with --;. A --- block belongs to something
    # exported - in a script, that is the header and the NSE entry points.
    for n, line in enumerate(lines):
        if not line.startswith("---"):
            continue
        for follow in lines[n + 1:n + 80]:
            if follow.startswith("--"):
                continue
            if re.match(r"^local\b", follow):
                found.add("%s:%d" % (name, n + 1),
                          "--- on private documentation; use --;",
                          follow.strip()[:40])
            break


def check_script(name, text, found):
    for field in ("description", "author", "license", "categories"):
        if not re.search(r"^%s\s*=" % field, text, re.M):
            found.add(name, "a script must declare %s" % field)
    if "stdnse.output_table" not in text:
        found.add(name, "no structured output; NSE expects output_table")


def check_shell(name, text, found):
    if not text.startswith("#!/bin/sh\n"):
        found.add(name, "shell scripts take a #!/bin/sh shebang")


def check_python(names, found):
    probe = subprocess.run([sys.executable, "-m", "pycodestyle", "--version"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        print("warning: no pycodestyle, so PEP 8 was NOT checked "
              "(pip install pycodestyle)", file=sys.stderr)
        return
    out = subprocess.run(
        [sys.executable, "-m", "pycodestyle", "--ignore=" + PEP8_IGNORE]
        + list(names), cwd=REPO, capture_output=True, text=True)
    for line in out.stdout.splitlines():
        parts = line.split(":", 3)
        if len(parts) == 4:
            found.add("%s:%s" % (parts[0], parts[1]), "PEP 8", parts[3].strip())
        else:
            found.add(line, "PEP 8")


def main():
    found = Findings()
    names = tracked()
    found.checked = len(names)
    python = []

    for name in names:
        path = REPO / name
        raw = path.read_bytes()
        if not raw or name.endswith(".gif"):
            continue
        check_bytes(name, raw, found)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]

        check_lines(name, lines, found)
        if name.endswith((".nse", ".lua", ".luadoc")):
            check_lua(name, text, lines, found)
        if name.endswith(".nse") and not name.startswith("tests/"):
            check_script(name, text, found)
        if name.endswith(".sh"):
            check_shell(name, text, found)
        if name.endswith(".py"):
            python.append(name)

    check_python(python, found)
    return found.report()


if __name__ == "__main__":
    sys.exit(main())
