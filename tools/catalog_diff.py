#!/usr/bin/env python3
"""Compare two catalogues and decide whether one may replace the other
unattended.

    tools/catalog_diff.py --before <dir> --after <dir> [--summary <file>]

The dictionaries are published to a branch that every installed script
downloads from, so a bad catalogue reaches the whole world within a day and
there is no release to hold it back. Once the rebuild is automatic, nothing but
this stands between an upstream that reorganised itself and every scan on earth
quietly recognising less than it did yesterday.

The asymmetry that makes an automatic gate possible: **growth is safe and loss
is not**. A catalogue that gained two hundred rules cannot make any existing
detection stop working, because the rules are independent - each one either
matches or does not. A catalogue that lost two hundred is either a deliberate
cleanup or an upstream that moved its files, and those two look identical from
here. So growth publishes itself and loss asks for a human.

Exit status is the verdict, because a workflow reads it:

    0   safe - publish it
    2   changed too much to publish unattended - open a pull request instead
    1   broken - do not publish, and say why
"""

import argparse
import json
import os
import sys
from pathlib import Path

# How much of the catalogue may disappear in one rebuild before a human is
# asked.
#
# Not zero: upstreams do retire fingerprints, and the importer itself drops a
# rule whose examples stop reproducing, so a small loss is ordinary
# maintenance. Five per cent of 722 rules is 36, which is a big enough cleanup
# to be worth a glance and small enough that ordinary churn does not stop the
# pipeline.
MAX_RULE_LOSS = 0.05

# Identities are held tighter than rules. Losing a rule usually means one of
# several patterns for a product went away; losing an IDENTITY means the
# product became undetectable, which is the failure an operator would actually
# notice.
MAX_IDENTITY_LOSS = 0.02

# Paths are held loosest of the three, and are still held. A sweep that stops
# asking stops finding, and NO RULE HAS TO CHANGE for that to happen - so a
# clone that failed, or an upstream that reorganised its plugin directory,
# walks straight past both thresholds above while quietly costing the sweep its
# reach. Ten per cent of 939 paths is 94, which no ordinary week of upstream
# churn reaches: the paths come from three catalogues at once, and losing a
# tenth means one of them stopped being read.
MAX_PATH_LOSS = 0.10


def load(directory, name):
    path = Path(directory) / name
    if not path.exists():
        raise SystemExit("%s is missing" % path)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read(directory):
    """The three dictionaries, as comparable sets.

    A rule is identified by what it DOES - its alias, the part of a response it
    reads, and its pattern - and never by its name. The name is a label built
    from the product and the channel, and it moves for reasons that change
    nothing: the first rebuild after the channel keys were renamed reported 139
    rules lost and 139 gained, a 19% loss by name, while the set of behaviours
    was byte-for-byte identical. A gate that stops the pipeline for a rename is
    a gate that gets switched off.
    """
    rules = load(directory, "fingerprints.json").get("rules") or {}
    paths = load(directory, "paths.json").get("paths") or []
    probes = load(directory, "probes.json").get("probes") or []

    # A JSON serial can be anything; only an integer is comparable, and the
    # comparison below used to raise TypeError on a scheduled, unattended run.
    # Anything else is reported as "no serial", which is already a broken
    # verdict. bool is an int in Python, and `true` is not a serial.
    serial = load(directory, "index.json").get("serial")
    if isinstance(serial, bool) or not isinstance(serial, int):
        serial = None

    return {
        # The anchor belongs in the identity, not beside it: it is a hard
        # prefilter (`lowered:find(anchor, at, true)`), so a rule whose anchor
        # stops matching is a rule whose pattern is never tried - dead, while
        # looking present. Identity by (alias, channel, regex) alone graded a
        # rebuild that mangled every anchor as "auto", i.e. self-publishing.
        # It costs nothing in false alarms: the anchor is derived from the
        # regex, so it only moves when the regex does or when the derivation
        # itself changed - which is exactly the case worth stopping for.
        "rules": {(rule.get("alias"), rule.get("channel"), rule.get("regex"),
                   rule.get("anchor"))
                  for rule in rules.values()},
        "names": set(rules),
        "identities": {rule.get("alias") for rule in rules.values()},
        "paths": set(paths),
        # A probe is identified by the product it probes for AND by its reach:
        # the paths it asks for and the detectors that decide to ask. A probe
        # that keeps its alias while losing four of five paths has lost most of
        # its ability to find anything, and by alias alone that read as no
        # change at all.
        "probes": {(probe.get("alias"),
                    tuple(sorted(probe.get("paths") or [])),
                    tuple(sorted((d.get("channel"), d.get("regex"))
                                 for d in probe.get("detect") or [])))
                   for probe in probes},
        "serial": serial,
    }


def portion(lost, total):
    return (len(lost) / total) if total else 0.0


def _probe_names(probes):
    """The aliases behind a set of probe identities, for a human to read."""
    return sorted({identity[0] for identity in probes})


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--selftest", action="store_true",
                        help="prove this gate refuses what it must")
    parser.add_argument("--before", help="the published catalogue")
    parser.add_argument("--after", help="the rebuilt catalogue")
    parser.add_argument("--summary", help="write a markdown summary here")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not (args.before and args.after):
        parser.error("--before and --after are required unless --selftest")

    before, after = read(args.before), read(args.after)

    lost_rules = before["rules"] - after["rules"]
    new_rules = after["rules"] - before["rules"]
    lost_identities = before["identities"] - after["identities"]
    new_identities = after["identities"] - before["identities"]
    lost_paths = before["paths"] - after["paths"]
    lost_probes = before["probes"] - after["probes"]

    lines = [
        "## Catalogue rebuild",
        "",
        "| | before | after | change |",
        "|---|---:|---:|---:|",
        "| rules | %d | %d | %+d |" % (len(before["rules"]),
                                                  len(after["rules"]),
                                       len(after["rules"])
                                       - len(before["rules"])),
        "| identities | %d | %d | %+d |" % (len(before["identities"]),
                                            len(after["identities"]),
                                            len(after["identities"])
                                            - len(before["identities"])),
        "| paths | %d | %d | %+d |" % (len(before["paths"]),
                                                  len(after["paths"]),
                                       len(after["paths"])
                                       - len(before["paths"])),
        "| probes | %d | %d | %+d |" % (len(before["probes"]),
                                                   len(after["probes"]),
                                        len(after["probes"])
                                        - len(before["probes"])),
        "",
        "%d rules added, %d removed." % (len(new_rules), len(lost_rules)),
    ]

    renamed = len(after["names"] - before["names"])
    if renamed and not (new_rules or lost_rules):
        lines += ["",
            "%d rules were renamed and none changed behaviour." % renamed]

    if new_identities:
        lines += ["", "**Newly detectable (%d):** %s"
                  % (len(new_identities),
                     ", ".join(sorted(new_identities)[:20])
                     + (", ..." if len(new_identities) > 20 else ""))]
    if lost_identities:
        lines += ["", "**No longer detectable (%d):** %s"
                  % (len(lost_identities),
                     ", ".join(sorted(lost_identities)[:20])
                     + (", ..." if len(lost_identities) > 20 else ""))]
    if lost_probes:
        lines += ["", "**Probes removed or narrowed:** %s"
                  % ", ".join(_probe_names(lost_probes))]
    if lost_paths:
        lines += ["", "**Swept paths removed (%d):** %s"
                  % (len(lost_paths), ", ".join(sorted(lost_paths)[:20]))]

    verdict, why = _decide(before, after, lost_rules, lost_identities,
                           lost_probes, lost_paths)

    lines += ["", "**Verdict: %s**%s" % (verdict, " - " + why if why else "")]
    report = "\n".join(lines) + "\n"

    print(report)
    if args.summary:
        Path(args.summary).write_text(report, encoding="utf-8")

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("verdict=%s\n" % verdict)

    return {"auto": 0, "unchanged": 0, "review": 2, "broken": 1}[verdict]


def _decide(before, after, lost_rules, lost_identities, lost_probes,
            lost_paths):
    """The verdict, kept apart from the reporting so a test can call it."""
    rule_loss = portion(lost_rules, len(before["rules"]))
    identity_loss = portion(lost_identities, len(before["identities"]))
    path_loss = portion(lost_paths, len(before["paths"]))
    verdict, why = "auto", None

    if not after["rules"]:
        verdict, why = "broken", "the rebuilt catalogue has no rules at all"
    elif not after["paths"]:
        # Not merely "the sweep stops asking": read_paths returning nil makes
        # assemble return nil, so an empty paths.json discards the fingerprints
        # with it and the script ends up with NO catalogue at all. That is a
        # broken build, not one a human should weigh up - "review" opens a pull
        # request somebody can merge.
        verdict, why = "broken", "the rebuilt catalogue has no paths at all"
    elif after["serial"] is None or before["serial"] is None:
        verdict, why = "broken", "a catalogue has no serial"
    elif after["serial"] <= before["serial"]:
        verdict, why = ("broken",
                        "serial %s does not move past the published %s, so no "
                        "cached copy would ever download it"
                        % (after["serial"], before["serial"]))
    elif rule_loss > MAX_RULE_LOSS:
        verdict, why = ("review",
                        "%.1f%% of the rules disappeared (%d of %d), "
                        "which is more often an upstream that moved than an "
                        "intended cleanup"
                        % (100 * rule_loss, len(lost_rules),
                                                len(before["rules"])))
    elif identity_loss > MAX_IDENTITY_LOSS:
        verdict, why = ("review",
                        "%.1f%% of the identities became undetectable "
                        "(%d of %d)" % (100 * identity_loss,
                                        len(lost_identities),
                                        len(before["identities"])))
    elif path_loss > MAX_PATH_LOSS:
        verdict, why = ("review",
                        "%.1f%% of the swept paths disappeared (%d of "
                        "%d); a sweep that stops asking stops finding, and no "
                        "rule has to change for that to happen"
                        % (100 * path_loss, len(lost_paths),
                                                len(before["paths"])))
    elif lost_probes:
        verdict, why = ("review",
                        "a targeted probe was removed, or lost paths or "
                        "detectors: %s" % ", ".join(_probe_names(lost_probes)))
    elif (after["rules"] == before["rules"]
          and after["paths"] == before["paths"]
          and after["probes"] == before["probes"]):
        # All three dictionaries, not just the rules and the paths. Publishing
        # only happens on "auto", so a rebuild whose one change was a NEW probe
        # was called unchanged and never reached anybody - and a probe is the
        # only thing in the catalogue that goes and asks.
        verdict = "unchanged"
        why = "nothing changed, so there is nothing to publish"

    return verdict, why


def _verdict(before_dir, after_dir):
    """The verdict for two catalogue directories."""
    before, after = read(before_dir), read(after_dir)
    return _decide(before, after,
                   before["rules"] - after["rules"],
                   before["identities"] - after["identities"],
                   before["probes"] - after["probes"],
                   before["paths"] - after["paths"],
                   )

# -------------------------------------------------------------------- selftest


def _catalogue(directory, rules, serial=1, paths=("/",), probes=(),
                                                  regex_from=None,
               anchor_from=None, probe_paths=("/a", "/b")):
    """Write a minimal catalogue, for the selftest below."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fingerprints.json").write_text(json.dumps({
        "schema": 1,
        "rules": {name: {"alias": alias,
                         "regex": "%s([%%d.]+)"
                                  % (regex_from(name) if regex_from
                                     else name).replace(" ", ""),
                         # Follows the regex by default, because that is what
                         # the importer does - so a pure rename moves neither.
                         "anchor": (anchor_from(name) if anchor_from else
                                    (regex_from(name) if regex_from
                                     else name).replace(" ", "")),
                         "channel": "hdr:server"}
                  for name, alias in rules.items()},
    }), encoding="utf-8")
    (directory / "paths.json").write_text(
        json.dumps({"schema": 1, "paths": list(paths)}), encoding="utf-8")
    (directory / "probes.json").write_text(json.dumps({
        "schema": 1,
        "probes": [{"name": n, "alias": "cpe:/a:x:" + n,
                    "paths": list(probe_paths),
                    "detect": [{"channel": "body", "regex": n}]}
                   for n in probes],
    }), encoding="utf-8")
    (directory / "index.json").write_text(
        json.dumps({"schema": 1, "serial": serial}), encoding="utf-8")


def selftest():
    """Prove the gate refuses what it is there to refuse.

    This tool is the only thing standing between an automatic rebuild and every
    installed scanner, so "it looked right" is not a standard it can be held
    to. Each case below is a way the pipeline could ship a worse catalogue than
    the one it replaces.
    """
    import shutil
    import tempfile

    # A hundred rules over twenty identities: enough that a 5% threshold is a
    # real number rather than a rounding accident.
    base = {"rule %d" % i: "cpe:/a:v:p%d" % (i % 20) for i in range(100)}

    cases = []

    # The "after" serial defaults to one past the "before" serial, because
    # tools/catalog.py --index bumps it on every rebuild - even one that
    # changed nothing. A case about content must therefore not also be a case
    # about the serial, or it only ever measures the serial.
    def case(name, expected, after_rules, serial=3, **kwargs):
        cases.append((name, expected, after_rules, serial, kwargs))

    case("an identical catalogue has nothing to publish", "unchanged",
         dict(base))
    case("pure growth publishes itself", "auto",
         dict(base,
              **{"rule new %d" % i: "cpe:/a:v:new%d" % i for i in range(30)}))
    case("a small cleanup still publishes", "auto",
         {k: v for k, v in base.items() if k not in ("rule 1", "rule 2")})
    case("losing a tenth of the rules asks for a human", "review",
         {k: v for k, v in base.items() if int(k.split()[1]) >= 10})
    # Paths, which nothing tested until the branch that reads them existed. A
    # rebuild can lose the sweep's reach without a single rule changing, so
    # these two cases keep the rules identical and vary only the path list.
    case("losing most of the swept paths asks for a human", "review",
         dict(base),
         paths=("/", "/a"),
                before_paths=tuple(["/"] + ["/p%d" % i for i in range(19)]))
    case("losing one path of twenty still publishes", "auto", dict(base),
         paths=tuple(["/"] + ["/p%d" % i for i in range(18)]),
         before_paths=tuple(["/"] + ["/p%d" % i for i in range(19)]))
    case("a rebuild whose only change is a new probe publishes", "auto",
         dict(base), after_probes=("drupal",))
    case("a serial that did not move is broken", "broken", dict(base),
                                                                serial=1)
    case("a serial going backwards is broken", "broken", dict(base), serial=0)
    case("an empty catalogue is broken", "broken", {})
    # An empty paths.json is not "the sweep got smaller": read_paths returning
    # nil makes assemble return nil, so the script keeps NO catalogue at all.
    case("a catalogue with no paths at all is broken", "broken", dict(base),
         paths=())
    # A serial the gate cannot compare used to raise TypeError here, in a job
    # that runs unattended once a week.
    case("a serial that is not a number is broken", "broken", dict(base),
         serial="3")
    # The anchor is a hard prefilter, so a rule whose anchor no longer matches
    # is dead while still being present, byte for byte, in the dictionary.
    case("mangled anchors are a loss even when every pattern is intact",
         "review", dict(base), anchor_from=lambda name: "zz-no-such-anchor")

    # The case this gate got wrong the first time it was run for real: the rule
    # names changed, nothing else did, and it reported a 19% loss.
    cases.append(("a pure rename is not a loss", "unchanged",
                  {name.replace("rule", "pattern"): alias
                   for name, alias in base.items()}, 3, {"rename": True}))

    failures = []
    for name, expected, after_rules, serial, kwargs in cases:
        workspace = tempfile.mkdtemp()
        try:
            before = Path(workspace) / "before"
            after = Path(workspace) / "after"
            _catalogue(before, base, serial=2,
                       paths=kwargs.get("before_paths", ("/",)),
                       probes=kwargs.get("before_probes", ()))
            _catalogue(after, after_rules, serial=serial,
                       paths=kwargs.get("paths", ("/",)),
                       probes=kwargs.get("after_probes", ()),
                       anchor_from=kwargs.get("anchor_from"),
                       regex_from=(lambda n: n.replace("pattern", "rule"))
                                  if kwargs.get("rename") else None)

            verdict = _verdict(str(before), str(after))[0]
            if verdict != expected:
                failures.append("%s: expected %s, got %s" % (name, expected,
                                                             verdict))
            else:
                print("ok    %s" % name)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    # Losing a probe is held apart from losing rules: a probe is the only thing
    # here that makes a request, so its removal changes what a scan DOES.
    workspace = tempfile.mkdtemp()
    try:
        before, after = Path(workspace) / "b", Path(workspace) / "a"
        _catalogue(before, base, serial=2, probes=("drupal", "joomla"))
        _catalogue(after, base, serial=3, probes=("drupal",))
        verdict = _verdict(str(before), str(after))[0]
        if verdict != "review":
            failures.append("a removed probe: expected review, got "
                "%s" % verdict)
        else:
            print("ok    a removed probe asks for a human")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    # A probe that keeps its alias while losing the paths it asks for has lost
    # most of its ability to find anything. Identified by alias alone, that was
    # indistinguishable from no change at all.
    workspace = tempfile.mkdtemp()
    try:
        before, after = Path(workspace) / "b", Path(workspace) / "a"
        _catalogue(before, base, serial=2, probes=("drupal",),
                   probe_paths=("/a", "/b", "/c", "/d", "/e"))
        _catalogue(after, base, serial=3, probes=("drupal",),
                   probe_paths=("/a",))
        verdict = _verdict(str(before), str(after))[0]
        if verdict != "review":
            failures.append("a probe narrowed to one path: expected review, "
                            "got %s" % verdict)
        else:
            print("ok    a probe that loses most of its paths asks for a "
                "human")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    # And the published catalogue must compare clean against itself, or the
    # gate would block the next real rebuild for a reason that has nothing to
    # do with it.
    published = Path(__file__).resolve().parents[1] / "catalog"
    if published.exists():
        verdict = _verdict(str(published), str(published))[0]
        if verdict != "broken":
            failures.append("the published catalogue against itself: expected "
                            "broken (the serial cannot move), got "
                                "%s" % verdict)
        else:
            print("ok    the published catalogue is readable by this gate")

    if failures:
        for failure in failures:
            print("FAIL  %s" % failure)
        return 1
    print("\nselftest: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
