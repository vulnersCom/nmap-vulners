#!/usr/bin/env python3
"""The structural contract that downstream importers read out of -oX.

DefectDojo, Faraday, nmap2csv and raven all locate this project's findings the
same way: `script[@id="vulners"]`, then two levels of `<table>`, then a fixed
set of `<elem>` keys. None of them tolerates that shape changing, and none of
them fails loudly when it does - a renamed key silently imports zero findings.

So the shape is checked here rather than trusted. The requirements below are
calibrated against tests/fixtures/golden_1x.xml, a capture of what the three
1.x scripts emitted before they were merged; that file cannot be regenerated
once they are gone, which is why it is committed.

What is deliberately NOT checked: element order. The 1.x scripts build result
rows as plain Lua tables, whose iteration order is unspecified - six distinct
orders were observed across six runs of the same scan. 2.0 fixes that with
stdnse.output_table(); until then, order is not something a gate can assert.

    python3 tools/xml_contract.py tests/fixtures/golden_1x.xml
    python3 tools/xml_contract.py --script-id vulners report.xml

Exit status is non-zero when the contract is broken.
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

# nmap emits CPE 2.2 URIs; a 2.3 formatted string is accepted too, because the
# keyed path can key a group on the CPE the service resolved (see plan 5.2).
CPE_SHAPE = re.compile(r"^cpe:(/|2\.3:)")

# Present on every bulletin, whatever found it.
REQUIRED_PER_BULLETIN = ("id", "type")

# Present somewhere in the script's output. They are not required on every row:
# an unscored bulletin carries no cvss, which is a recorded decision, and 1.x
# enterprise omits is_exploit on rows that are not exploits.
REQUIRED_SOMEWHERE = ("cvss", "cvss_type", "is_exploit")


class Contract:
    """Requirement results, in the order they were checked."""

    def __init__(self):
        self.results = []

    def require(self, ok, requirement, detail=""):
        self.results.append((bool(ok), requirement, detail))
        return bool(ok)

    @property
    def broken(self):
        return [r for r in self.results if not r[0]]

    def report(self, source):
        print(f"{source}:")
        for ok, requirement, detail in self.results:
            mark = "ok  " if ok else "FAIL"
            print(f"  {mark}  {requirement}")
            if not ok and detail:
                print(f"          {detail}")
        return 0 if not self.broken else 1


def scripts_named(root, script_id):
    return [s for s in root.iter("script") if s.get("id") == script_id]


def check(xml_path, script_id="vulners"):
    """Check one report against the contract. Returns a Contract."""
    contract = Contract()
    root = ET.parse(xml_path).getroot()

    elements = scripts_named(root, script_id)
    if not contract.require(
            elements,
            f'a <script id="{script_id}"> element is present',
            "every downstream importer selects findings by this exact id"):
        return contract

    groups, bulletins, elem_keys, problems = [], [], set(), []

    for element in elements:
        for group in element.findall("table"):
            groups.append(group)
            for bulletin in group.findall("table"):
                bulletins.append(bulletin)
                for nested in bulletin.findall("table"):
                    problems.append(f"a third table level under {group.get('key')!r}")
                keys = {}
                for elem in bulletin.findall("elem"):
                    key = elem.get("key")
                    elem_keys.add(key)
                    keys[key] = (elem.text or "").strip()
                for required in REQUIRED_PER_BULLETIN:
                    if not keys.get(required):
                        problems.append(
                            f"a bulletin under {group.get('key')!r} has no {required}")
                for key, value in keys.items():
                    if not value:
                        problems.append(f"an empty <elem key={key!r}>")

    contract.require(groups, "findings are grouped in tables",
                     "no <table> under the script element")
    contract.require(all(g.get("key") for g in groups),
                     "every group carries a key attribute",
                     "a group with no key cannot be attributed to any software")
    # A group key is either a CPE, or a human software label that says so.
    # 2.0 deliberately does not invent a CPE for a label the service could not
    # resolve - inventing one would make an importer attach findings to software
    # that does not exist - so it marks the group instead. Demanding a CPE
    # outright rejected a report the design is supposed to produce.
    unlabelled = []
    for group in groups:
        key = group.get("key") or ""
        if CPE_SHAPE.match(key):
            continue
        identity = next((e.text for e in group.findall("elem")
                         if e.get("key") == "identity"), None)
        if identity != "software":
            unlabelled.append(key)
    contract.require(
        not unlabelled,
        'every group is keyed by a CPE, or marked identity="software"',
        f"neither: {unlabelled[:3]}")
    contract.require(bulletins, "groups contain bulletin tables",
                     "a group with no nested table reports nothing")
    contract.require(all(b.get("key") is None for b in bulletins),
                     "bulletin tables are unkeyed, so they read as a list")

    nesting = [p for p in problems if "third table level" in p]
    contract.require(not nesting, "no table is nested inside a bulletin",
                     "; ".join(sorted(set(nesting))[:3]))
    missing = [p for p in problems if " has no " in p]
    contract.require(not missing,
                     f"every bulletin carries {' and '.join(REQUIRED_PER_BULLETIN)}",
                     "; ".join(sorted(set(missing))[:3]))
    empty = [p for p in problems if p.startswith("an empty")]
    contract.require(not empty, "no element is emitted empty",
                     "; ".join(sorted(set(empty))[:3]))

    absent = [k for k in REQUIRED_SOMEWHERE if k not in elem_keys]
    contract.require(not absent,
                     f"the report uses {', '.join(REQUIRED_SOMEWHERE)}",
                     f"never emitted: {', '.join(absent)}")
    return contract


# A minimal report in the shape the contract describes, plus the ways 2.0
# could plausibly break it. Without this, a requirement that stops working -
# a typo in an element name, a predicate that can never be false - would let
# every report through and read as a clean gate.
SELFTEST_REPORT = """<?xml version="1.0"?>
<nmaprun><host><ports><port><script id="vulners" output="x">
<table key="cpe:/a:apache:http_server:2.4.49">
<table>
<elem key="id">CVE-2021-41773</elem>
<elem key="type">cve</elem>
<elem key="cvss">9.8</elem>
<elem key="cvss_type">cvss3.1</elem>
<elem key="is_exploit">false</elem>
</table>
</table>
</script></port></ports></host></nmaprun>
"""

SELFTEST_BREAKAGES = {
    "the script is renamed":
        lambda x: x.replace('id="vulners"', 'id="vulnerability"'),
    "a bulletin loses its id":
        lambda x: x.replace('<elem key="id">CVE-2021-41773</elem>\n', ""),
    "a bulletin loses its type":
        lambda x: x.replace('<elem key="type">cve</elem>\n', ""),
    "an element is renamed":
        lambda x: x.replace('key="cvss"', 'key="score"'),
    "a third table level appears":
        lambda x: x.replace('<elem key="type">cve</elem>',
                            '<table key="n"><elem key="x">1</elem></table>'),
    "a group loses its key":
        lambda x: x.replace('<table key="cpe:/a:apache:http_server:2.4.49">',
                            "<table>"),
    "an element is emitted empty":
        lambda x: x.replace('<elem key="type">cve</elem>',
                            '<elem key="type"></elem>'),
    "a group is keyed by neither a CPE nor a marked software label":
        lambda x: x.replace('key="cpe:/a:apache:http_server:2.4.49"',
                            'key="Apache httpd 2.4.49"'),
    "bulletin tables gain keys":
        lambda x: x.replace('<table>\n<elem key="id"', '<table key="0">\n<elem key="id"'),
}


def selftest(tmpdir):
    """Check that the contract passes a good report and fails every bad one.

    Returns a list of problems; empty means the gate still gates.
    """
    import tempfile

    problems = []

    def verdict(xml):
        handle = tempfile.NamedTemporaryFile("w", suffix=".xml", dir=tmpdir,
                                             delete=False)
        with handle:
            handle.write(xml)
        try:
            with open(os.devnull, "w") as quiet:
                stdout, sys.stdout = sys.stdout, quiet
                try:
                    return check(handle.name).broken
                finally:
                    sys.stdout = stdout
        finally:
            os.unlink(handle.name)

    if verdict(SELFTEST_REPORT):
        problems.append("the contract rejects a report that satisfies it")
    for description, break_it in SELFTEST_BREAKAGES.items():
        if not verdict(break_it(SELFTEST_REPORT)):
            problems.append(f"the contract no longer notices when {description}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", nargs="*", help="nmap -oX files to check")
    parser.add_argument("--script-id", default="vulners",
                        help="the script element to check (default: vulners)")
    parser.add_argument("--selftest", action="store_true",
                        help="check that the contract still catches breakage")
    args = parser.parse_args()

    # Nothing to do is not success. With neither a report nor --selftest this
    # printed nothing and exited 0, so a CI line whose arguments came from a
    # shell variable that expanded to nothing - or a glob that matched a moved
    # fixture - reported a gate that never ran. The unit runner had the same
    # hole and now calls it a failure; so does this.
    if not args.selftest and not args.reports:
        parser.error("give at least one report to check, or --selftest")

    status = 0
    if args.selftest:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            problems = selftest(tmpdir)
        for problem in problems:
            print(f"selftest: {problem}")
        print("selftest: ok" if not problems else "selftest: FAILED")
        status |= 1 if problems else 0
    for report in args.reports:
        status |= check(report, args.script_id).report(report)
    return status


if __name__ == "__main__":
    sys.exit(main())
