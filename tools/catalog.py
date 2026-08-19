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

These four files are the only copy. `tools/fingerprints/build.py` writes the
rules and the probes directly into them; `paths.json` is maintained by hand.
This tool does not convert anything - it maintains the manifest and checks that
what is published can actually be read.

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

# The runtime channel keys. A rule filed under anything else is data that ships,
# costs bytes on every download, and can never fire - so it is a failure here
# rather than a passenger.
CHANNEL_KEY = re.compile(r"^(?:raw|body|title|script|banner|cookie"
                         r"|hdr:[\w.-]+|meta:[\w.:-]+)$")

ALIAS = re.compile(r"^cpe:/[aoh]:[^:]+:[^:]+$")


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
    """Validate the catalogue the way vulners.nse will read it.

    Deliberately the same questions the script asks, because a check that is
    weaker than the reader lets through exactly the files that will be dropped
    in the field - silently, since a rule that fails validation at scan time is
    indistinguishable from a product nobody is running.
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
        if len(body) != listed.get("entries"):
            problems.append("%s holds %d entries, the index says %r"
                            % (filename, len(body), listed.get("entries")))

    rules = load(CATALOG / "fingerprints.json").get("rules") or {}
    for name, rule in sorted(rules.items()):
        if not CHANNEL_KEY.match(rule.get("channel", "")):
            problems.append("rule %r is filed under %r, which nothing reads"
                            % (name, rule.get("channel")))
        if not ALIAS.match(rule.get("alias", "")):
            problems.append("rule %r has alias %r, which is not a CPE prefix"
                            % (name, rule.get("alias")))
        anchor = rule.get("anchor", "")
        if anchor and anchor != anchor.lower():
            problems.append("rule %r has a non-lowercase anchor" % name)

    paths = load(CATALOG / "paths.json").get("paths") or []
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/") \
                or re.search(r"\s", path):
            problems.append("path %r is not a request line this script would send"
                            % (path,))

    for probe in load(CATALOG / "probes.json").get("probes") or []:
        label = probe.get("name", "?")
        if not ALIAS.match(probe.get("alias", "")):
            problems.append("probe %r has alias %r" % (label, probe.get("alias")))
        for rule in probe.get("detect") or []:
            if not CHANNEL_KEY.match(rule.get("channel", "")):
                problems.append("probe %r detects on %r, which nothing reads"
                                % (label, rule.get("channel")))
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
