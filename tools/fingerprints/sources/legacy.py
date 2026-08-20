"""Read the patterns this repository already ships.

These are not just another source. Their aliases were measured against the live
Vulners API on 2026-08-18 - which spelling of nginx answers, which spelling of
IIS answers - so where they disagree with an upstream catalogue about a
product's identity, they are the ones that have been tested against the thing
that has to answer. `build.py` gives them the last word for that reason.

They are also the regression baseline: whatever else this import changes, a
product this script detected yesterday has to be detectable today.
"""

import json
import re

# The old names encode the channel as a suffix - "Bugzilla, html", "nginx,
# headers_0_1" - because they were generated from a scraper that numbered its
# captures. Ten entries predate the convention and are classified by reading
# the pattern instead.
SUFFIX = re.compile(r",\s*(headers|html|script)(?:_[\d_]+)?$")

# A pattern that names an HTTP header at its start is a header pattern whatever
# its key says. Anchoring on the colon is what distinguishes "Server:%s*Foo"
# from a body pattern that merely mentions a word.
HEADER_ISH = re.compile(r"^\^?[A-Za-z][A-Za-z0-9%-]*%?-?[A-Za-z0-9%-]*:")


def classify(name, regex):
    match = SUFFIX.search(name)
    if match:
        # A "script" rule reads a <script src=> value, which is what the suffix
        # has always meant; 1.x had no such channel and ran it over the whole
        # body instead. It is filed under BOTH, so nothing 1.x detected is
        # lost, and the body copy is then subject to the same timing gate as
        # any other body rule - which is what retires the two lazy jQuery
        # patterns from the body while keeping them where their subject is a
        # few hundred bytes.
        return {"headers": "headers-raw", "html": "body",
                "script": "script+body"}[match.group(1)]
    if HEADER_ISH.match(regex):
        return "headers-raw"
    # Unclassifiable, so it keeps the behaviour it has today: the 1.x sweep ran
    # every pattern over the header block and the body alike, and narrowing an
    # unread rule would silently drop whatever it detects.
    return "both"


def load(path):
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    # The catalogue wraps its dictionary; a bare map is what the pre-catalogue
    # file looked like, and reading both keeps this working across the change.
    data = document.get("rules", document) if isinstance(document,
                                                         dict) else {}

    rules = []
    for name, entry in sorted(data.items()):
        regex = entry.get("regex")
        alias = entry.get("alias")
        if not regex or not alias:
            continue
        if entry.get("source"):
            # Written by a previous run of the importer, so it is not the
            # baseline - it is upstream, and this run will read it from
            # upstream. Without this the file is idempotent in the wrong
            # direction: every imported rule would come back as "legacy" on the
            # next build, exempt from reduction and capping, and the exemption
            # would compound with every rebuild.
            continue
        channel = entry.get("channel") or classify(name, regex)
        spread = {"both": ["headers-raw", "body"], "script+body": ["script",
                                                                   "body"]}
        for one in spread.get(channel, [channel]):
            rules.append({
                "source": "legacy",
                "upstream": name,
                "channel": one,
                "field": entry.get("field"),
                # Already a Lua pattern. It skips the translator entirely,
                # which is the point: these have been in the field for years
                # and a round trip through PCRE would be a chance to change
                # them.
                "lua": regex,
                "pattern": None,
                "version_group": 1,
                "cpe_template": alias,
                "product": name.split(",")[0].strip(),
                "vendor": None,
                "description": "",
                # The generated file records one example per rule under
                # "example"; a hand-written one may carry a list. Both are
                # read, so a rebuild does not throw away the proof the last one
                # made.
                "examples": ([{"subject": entry["example"]["subject"],
                               "version": entry["example"]["version"]}]
                             if isinstance(entry.get("example"), dict)
                             else list(entry.get("examples", []))),
                "ignore_case": False,
                "dot_newline": False,
                "multiline": False,
                "field_scoped": False,
                "authoritative_alias": True,
            })
    return rules
