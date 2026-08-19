#!/usr/bin/env python3
"""Version and validate the catalogue vulners.nse downloads at scan time.

    tools/catalog.py --index     # rewrite index.json, bumping the serial
    tools/catalog.py --check     # validate catalog/ as the script will read it

The script carries no fingerprint data. The dictionaries live in `catalog/`,
are published to a GitHub branch, and are fetched at scan time - which is what
lets the corpus grow without shipping a new script.

    catalog/index.json          the manifest: schema, serial, what exists
    catalog/fingerprints.json   product and version rules
    catalog/paths.json          the paths the HTTP sweep requests
    catalog/probes.json         targeted version probes

These four files are the only copy, and `tools/fingerprints/build.py` writes
all three dictionaries into them. This tool does not convert anything - it
maintains the manifest and checks the SHAPE of what is published.

What it deliberately does not check is the patterns. Deciding whether a Lua
pattern is one the script will keep is `usable_pattern` in vulners.nse, and a
second implementation of it here could only drift away from that one. The test
suite asserts the property instead, through the script's own readers - see "the
published catalogue survives this script's own readers intact" in
tests/test_catalog.lua - so anything that publishes must run the suite too.

**Versioning.** `schema` says which format the files are in; vulners.nse refuses
a schema higher than the one it knows and says so, which is what makes a future
format change safe rather than a silent misreading. `serial` increases on every
publish and is the whole update protocol: a cached copy fetches the small index,
compares one integer, and downloads the dictionaries only when that integer
moved.

There is deliberately no signing and no per-file hash. HTTPS to GitHub is the
trust boundary; a truncated body stops being JSON and is discarded, and the
script validates the shape of everything it did parse before using any of it.
"""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CATALOG = REPO / "catalog"
INDEX = CATALOG / "index.json"

# Must match CATALOG_SCHEMA in vulners.nse and in tools/fingerprints/build.py.
SCHEMA = 1

# kind -> (filename, the key its dictionary lives under)
DICTIONARIES = {
    "fingerprints": ("fingerprints.json", "rules"),
    "paths": ("paths.json", "paths"),
    "probes": ("probes.json", "probes"),
}

# The runtime channel keys. Lowercase only: nselib lowercases every response
# header name and the matcher builds its keys from what nselib hands it, so a
# rule filed under "hdr:Server" is data that ships, costs bytes on every
# download, and can never fire - a failure here rather than a passenger.
#
# Imported from the module that WRITES the key rather than restated, because a
# second spelling can only drift: the two disagreed until this import replaced
# them, and `hdr:Server` was accepted by the producer while being refused here.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fingerprints.normalize import CHANNEL_KEY  # noqa: E402

ALIAS = re.compile(r"^cpe:/[aoh]:[^:]+:[^:]+$")

# MAX_CATALOG_STRING in vulners.nse:240. A string past it is refused by the
# reader, so shipping one is bytes on every download that can never be used.
MAX_STRING = 2048


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def next_serial():
    """One more than the published serial, or 1 for the first publish.

    A plain counter: the only question a cached copy asks is "is there something
    newer than what I have", and an integer answers it without a clock, a
    timezone or a tie-break.
    """
    if not INDEX.exists():
        return 1
    try:
        return int(load(INDEX)["serial"]) + 1
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit("catalog/index.json has no readable serial")


def write_index():
    entries = {}
    for kind, (filename, key) in sorted(DICTIONARIES.items()):
        target = CATALOG / filename
        if not target.exists():
            raise SystemExit("catalog/%s is missing" % filename)
        payload = load(target)
        if payload.get("schema") != SCHEMA:
            raise SystemExit("catalog/%s declares schema %r, this tool writes %d"
                             % (filename, payload.get("schema"), SCHEMA))
        entries[kind] = {"file": filename, "entries": len(payload.get(key) or {})}

    index = {
        "schema": SCHEMA,
        "serial": next_serial(),
        "generated": datetime.datetime.now(datetime.timezone.utc)
                     .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "catalogs": entries,
    }
    INDEX.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n",
                     encoding="utf-8")

    print("catalog/index.json  schema %d, serial %d" % (SCHEMA, index["serial"]))
    for kind in sorted(entries):
        print("  %-14s %-20s %5d entries"
              % (kind, entries[kind]["file"], entries[kind]["entries"]))
    return 0


def check():
    """Validate the shape of the catalogue: the manifest, and every field the
    script indexes by.

    Not the patterns. A check weaker than the reader lets through exactly the
    rules that will be dropped in the field - silently, since a rule that fails
    validation at scan time is indistinguishable from a product nobody is
    running - so the property is asserted where the reader itself lives, in
    tests/test_catalog.lua. Anything that publishes runs the suite as well as
    this.
    """
    problems = []

    if not INDEX.exists():
        raise SystemExit("catalog/index.json is missing - run tools/catalog.py --index")
    index = load(INDEX)

    if index.get("schema") != SCHEMA:
        problems.append("index schema is %r, this tool writes %d"
                        % (index.get("schema"), SCHEMA))
    if not isinstance(index.get("serial"), int) or index["serial"] < 1:
        problems.append("serial must be a positive integer, got %r"
                        % (index.get("serial"),))

    # The dictionary the SCRIPT would build from each file, or None when the
    # file is unusable. Collected here and reused below: the three sections
    # that follow used to re-open the same files unconditionally, so a missing
    # or mistyped dictionary produced a Python traceback instead of the problem
    # list this function spends sixty lines building - in a workflow that runs
    # unattended once a week.
    bodies = {}

    # The type each dictionary must have. Lua has one table type, so a JSON
    # object where the script expects an array is NOT caught at the reader's
    # type check: `ipairs` over string keys simply yields nothing. For paths
    # that is the whole catalogue - read_paths returns nil, assemble returns
    # nil, and the script ends up with no fingerprints either.
    SHAPES = {"fingerprints": dict, "paths": list, "probes": list}

    catalogs = index.get("catalogs") or {}
    for kind, (filename, key) in DICTIONARIES.items():
        listed = catalogs.get(kind)
        if not listed:
            problems.append("index does not list %s" % kind)
            continue
        if listed.get("file") != filename:
            problems.append("index calls %s %r" % (kind, listed.get("file")))
        target = CATALOG / filename
        if not target.exists():
            problems.append("%s is listed but missing" % filename)
            continue

        payload = load(target)
        if payload.get("schema") != SCHEMA:
            problems.append("%s has schema %r" % (filename, payload.get("schema")))
        body = payload.get(key)
        if body is None:
            problems.append("%s has no %r" % (filename, key))
            continue
        if not isinstance(body, SHAPES[kind]):
            problems.append("%s: %r is a %s, the script reads it as a %s"
                            % (filename, key, type(body).__name__,
                               SHAPES[kind].__name__))
            continue
        bodies[kind] = body
        if len(body) != listed.get("entries"):
            problems.append("%s holds %d entries, the index says %r"
                            % (filename, len(body), listed.get("entries")))

    rules = bodies.get("fingerprints") or {}
    for name, rule in sorted(rules.items()):
        if not isinstance(rule, dict):
            problems.append("rule %r is a %s, not an object"
                            % (name, type(rule).__name__))
            continue
        # The reader runs `regex` through string.find. A non-string raises
        # there, and nmap answers a raising script by discarding every finding
        # the port had - so this is the whole port, not one rule.
        for field in ("regex", "channel", "alias"):
            if not isinstance(rule.get(field), str):
                problems.append("rule %r has %s %r, which is not a string"
                                % (name, field, rule.get(field)))
        if not all(isinstance(rule.get(f), str)
                   for f in ("regex", "channel", "alias")):
            continue
        for field in ("regex", "alias", "anchor", "example"):
            value = rule.get(field)
            if isinstance(value, str) and len(value) > MAX_STRING:
                problems.append("rule %r has %s of %d bytes; the reader "
                                "refuses anything over %d"
                                % (name, field, len(value), MAX_STRING))
        if not CHANNEL_KEY.match(rule.get("channel", "")):
            problems.append("rule %r is filed under %r, which nothing reads"
                            % (name, rule.get("channel")))
        if not ALIAS.match(rule.get("alias", "")):
            problems.append("rule %r has alias %r, which is not a CPE prefix"
                            % (name, rule.get("alias")))
        anchor = rule.get("anchor", "")
        if anchor and anchor != anchor.lower():
            problems.append("rule %r has a non-lowercase anchor" % name)

    paths = bodies.get("paths") or []
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/") \
                or re.search(r"\s", path) or len(path) > MAX_STRING:
            problems.append("path %r is not a request line this script would send"
                            % (path,))

    for probe in bodies.get("probes") or []:
        if not isinstance(probe, dict):
            problems.append("probe %r is a %s, not an object"
                            % (probe, type(probe).__name__))
            continue
        label = probe.get("name", "?")
        if not ALIAS.match(probe.get("alias", "")):
            problems.append("probe %r has alias %r" % (label, probe.get("alias")))
        for rule in probe.get("detect") or []:
            if not isinstance(rule, dict) or not isinstance(rule.get("regex"), str):
                problems.append("probe %r has a detector whose regex is not a "
                                "string; string.find raises on it, and a raising "
                                "script costs the port every finding it had"
                                % label)
                continue
            if not CHANNEL_KEY.match(rule.get("channel") or ""):
                problems.append("probe %r detects on %r, which nothing reads"
                                % (label, rule.get("channel")))
        for rule in probe.get("extract") or []:
            if not isinstance(rule, dict) or not isinstance(rule.get("regex"), str):
                problems.append("probe %r has an extractor whose regex is not a "
                                "string" % label)
        for path in probe.get("paths") or []:
            if not isinstance(path, str) or not path.startswith("/"):
                problems.append("probe %r would request %r" % (label, path))
        if not (probe.get("detect") and probe.get("extract") and probe.get("paths")):
            problems.append("probe %r cannot be triggered, sent or read" % label)

    if problems:
        for problem in problems:
            print("FAIL  %s" % problem)
        return 1

    print("catalog ok - schema %d, serial %d, %s"
          % (index["schema"], index["serial"],
             ", ".join("%d %s" % (catalogs[k]["entries"], k)
                       for k in sorted(catalogs))))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--index", action="store_true",
                       help="rewrite catalog/index.json and bump the serial")
    group.add_argument("--check", action="store_true",
                       help="validate catalog/ as vulners.nse will read it")
    args = parser.parse_args()
    return write_index() if args.index else check()


if __name__ == "__main__":
    sys.exit(main())
