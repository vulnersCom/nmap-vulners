#!/usr/bin/env python3
"""Build the published fingerprint dictionaries from the upstream catalogues.

    tools/fingerprints/build.py --sources <dir>
    tools/catalog.py --index            # then bump the serial

`<dir>` holds a checkout of each upstream repository, by its own name:
recog, wappalyzer, nuclei-templates, WhatWeb, FingerprintHub. They are not
vendored here - they carry incompatible licences and change weekly - so this is
a tool the maintainer runs, and its output is what ships.

Four things happen, in this order, and the third is the one that matters:

1. each source is read into one shape (`sources/*.py`)
2. every PCRE is translated into Lua patterns (`pcre2lua.py`)
3. **every translated rule is run against its upstream examples in a real Lua
   interpreter, and a rule that does not reproduce its documented extraction is
   dropped.** No rule ships on the strength of the translation looking right
4. rules are de-duplicated, and the aliases this repository has already measured
   against the live API win over the catalogues' opinion

The output is `catalog/fingerprints.json` and `catalog/probes.json`, which are
the only copy - the script downloads them at scan time and carries no data of
its own. Run `tools/catalog.py --index` afterwards to bump the serial, or no
installed script will know there is anything new.

A rule is only useful to this script if it yields vendor, product AND version,
because the endpoint is addressed by a versioned CPE. Presence-only rules are
kept apart, for the targeted probes that go and fetch a version once a product
is known.
"""

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import luaeval                                    # noqa: E402
import normalize                                  # noqa: E402
import sample                                     # noqa: E402
from pcre2lua import (translate, literal_runs,     # noqa: E402
                      capture_can_hold_a_digit, Untranslatable)
import paths as path_builder                      # noqa: E402
import probes as probe_builder                    # noqa: E402
from sources import legacy, nuclei, recog, wappalyzer  # noqa: E402

# The channel a rule is matched against, and what the script builds as its
# subject. Anything not listed here is not something a response can answer.
CHANNELS = {
    "server": "the Server header's value",
    "powered-by": "the X-Powered-By header's value",
    "header": "one named header's value",
    "headers-raw": "the whole header block",
    "cookie": "one Set-Cookie value",
    "wwwauth": "the WWW-Authenticate header's value",
    "title": "the text of <title>",
    "meta": "the content= of one named <meta>",
    "body": "the whole decoded body",
    "script": "one <script src=> value",
    "banner": "nmap's own service banner, so it costs no request",
    "favicon": "the MD5 of /favicon.ico",
}



# Must match tools/catalog.py and the CATALOG_SCHEMA in vulners.nse.
CATALOG_SCHEMA = 1


def write_catalog(path, payload):
    """Write one catalogue dictionary, creating catalog/ if it is not there."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")



# A rebuild may only shrink the catalogue by this much before it is treated as
# an accident rather than an edit.
#
# This is not hypothetical. The upstream checkouts live outside the repository,
# in a scratch directory; when they were cleaned up, a rebuild read no recog and
# no wappalyzer, produced the 195 rules it could still see, and overwrote 722
# with them. Nothing failed - the tool did exactly what it was told - and the
# only signal was a count in a line of output nobody was reading.
#
# A generator that overwrites its own input has to notice when its input
# disappeared.
MIN_RETAINED = 0.80


def refuse_to_shrink(out_path, fresh_count, sources_found, force, kind="rules"):
    """Stop before writing when this build looks like a mistake."""
    if force:
        return

    if not sources_found:
        raise SystemExit(
            "no upstream catalogue was found under --sources, so this build "
            "would publish only what is already in the repository. Clone recog "
            "and wappalyzer into that directory, or pass --force if replacing "
            "the catalogue with the baseline is really what you want.")

    if not os.path.exists(out_path):
        return
    try:
        with open(out_path, encoding="utf-8") as handle:
            existing = json.load(handle)
    except (OSError, ValueError):
        return

    previous = len(existing.get(kind) or existing or {})
    if previous and fresh_count < previous * MIN_RETAINED:
        raise SystemExit(
            "this build produces %d %s where the published catalogue has "
            "%d. That is a %.0f%% loss, which is a missing source far more "
            "often than an intended edit. Pass --force if it is intended."
            % (fresh_count, kind, previous, 100 * (1 - fresh_count / previous)))


def gather(sources_dir, repo_root):
    """Every source, read into the one shape.

    @return (rules, upstreams_found) - the second is how the caller knows the
            difference between "upstream contributed nothing" and "upstream was
            not there at all", which look identical in the rule count.
    """
    found = []
    upstreams = 0

    recog_dir = os.path.join(sources_dir, "recog")
    if os.path.isdir(recog_dir):
        found.extend(recog.load(recog_dir))
        upstreams += 1

    wap_dir = os.path.join(sources_dir, "wappalyzer")
    if os.path.isdir(wap_dir):
        found.extend(wappalyzer.load(wap_dir))
        upstreams += 1

    existing = os.path.join(repo_root, "catalog", "fingerprints.json")
    if os.path.exists(existing):
        found.extend(legacy.load(existing))

    return found, upstreams


def translated(rules, report):
    """Attach Lua patterns, dropping what cannot be expressed."""
    out = []
    for rule in rules:
        if rule.get("lua"):
            # Already Lua - the repository's own patterns.
            from pcre2lua import literal_anchor
            example = next((e for e in rule.get("examples", []) if e.get("version")), None)
            out.append(dict(rule, variants=[(
                rule["lua"], literal_anchor(rule["lua"]),
                example["subject"] if example else None,
                example["version"] if example else None)]))
            continue
        if not rule.get("pattern"):
            continue
        try:
            variants = translate(
                rule["pattern"],
                rule.get("version_group"),
                ignore_case=rule.get("ignore_case", False),
                anchored=False,
                dot_newline=rule.get("dot_newline", False),
            )
        except Untranslatable as reason:
            report["untranslatable"][str(reason)[:48]] += 1
            continue
        out.append(dict(rule, variants=variants))
    return out


def oracles(rule):
    """Every (subject, expected version) this rule can be checked against.

    Upstream examples first, because a string a human wrote down as real is
    worth more than one a generator invented. Generated samples fill in for the
    three sources that ship none, and for recog they serve as a cross-check that
    the generator agrees with reality.
    """
    found = [(e["subject"], e["version"]) for e in rule.get("examples", [])
             if e.get("version")]
    if rule.get("pattern"):
        found.extend(sample.samples(
            rule["pattern"], rule.get("version_group"),
            ignore_case=rule.get("ignore_case", False),
            dot_newline=rule.get("dot_newline", False)))
    return found


def verify(rules, report):
    """Drop every rule, and every variant, that the oracle does not confirm.

    Three outcomes are distinguished, and the middle one is the reason this is
    per-variant rather than per-rule:

    * **raised** - the pattern is not valid Lua. That is a translator bug and
      the variant goes, always.
    * **short** - the variant captured a prefix of what the real engine
      captured. Expanding an optional tail can only shorten a capture, so this
      is expansion working as intended, not disagreement.
    * **wrong** - the variant captured something that is not a prefix. It
      latched onto different text, and shipping it would put a version number
      into a CPE on the strength of a pattern that means something else.

    A rule survives when every subject is reproduced exactly by at least one
    surviving variant. A rule with no oracle at all survives only if this
    repository already shipped it.
    """
    jobs, index = [], []
    for position, rule in enumerate(rules):
        rule["oracle"] = oracles(rule)
        for subject, expected in rule["oracle"]:
            for variant, entry in enumerate(rule["variants"]):
                jobs.append((entry[0], subject))
                index.append((position, variant, subject, expected))

    results = luaeval.run(jobs) if jobs else []

    bad_variant = collections.defaultdict(set)
    reproduced = collections.defaultdict(set)
    # Which subjects each INDIVIDUAL variant reproduces. Tracking this per rule
    # was not enough: an expanded alternation ships as several patterns, and
    # attaching the rule's example to all of them documented variant B with a
    # subject only variant A matches. The suite caught it, on a pattern for
    # "Abyss/2.12.1-X1-MacOS X AbyssLib/2.12" whose recorded example belonged to
    # a sibling - so the example proved nothing and the anchor test failed too.
    proof = collections.defaultdict(list)
    for (position, variant, subject, expected), result in zip(index, results):
        if result is False:
            bad_variant[position].add(variant)
            report["raised"][rules[position]["source"]] += 1
        elif result is None:
            pass
        elif result[0] == expected:
            reproduced[position].add(subject)
            proof[(position, variant)].append((subject, expected))
        elif expected.startswith(result[0]) and result[0]:
            report["short"][rules[position]["source"]] += 1
        else:
            bad_variant[position].add(variant)

    kept = []
    for position, rule in enumerate(rules):
        if not rule["oracle"]:
            if rule["source"] == "legacy":
                kept.append(rule)
            else:
                report["no_oracle"][rule["source"]] += 1
            continue

        # A variant ships only if it reproduces a subject ITSELF. One that
        # matches nothing the oracle offers is unproven, and an unproven
        # pattern is exactly the thing this whole pipeline exists to refuse.
        survivors = []
        for number, entry in enumerate(rule["variants"]):
            pattern, anchor = entry[0], entry[1]
            if number in bad_variant[position]:
                continue
            if not capture_can_hold_a_digit(pattern):
                # The runtime refuses a version with no digit in it, so this
                # pattern could match all day and never produce an identity.
                report["capture_cannot_be_a_version"][rule["source"]] += 1
                continue
            evidence = proof.get((position, number))
            if not evidence:
                report["variant_unproven"][rule["source"]] += 1
                continue
            subject, expected = evidence[0]
            survivors.append((pattern, anchor, subject, expected))

        if not survivors:
            report["all_variants_wrong"][rule["source"]] += 1
            continue

        subjects = {subject for subject, _ in rule["oracle"]}
        missed = subjects - reproduced[position]
        if missed:
            report["not_reproduced"][rule["source"]] += 1
            continue

        if len(survivors) != len(rule["variants"]):
            report["variant_dropped"][rule["source"]] += 1
        kept.append(dict(rule, variants=survivors))
    return kept


# The body a target may serve, so the worst case is measured at the size that
# can actually arrive. Matches MAX_BODY_SIZE in vulners.nse.
MAX_BODY_SIZE = 128 * 1024

# What one pattern may cost on that worst case. The sweep's whole budget is
# 3 seconds and it holds many patterns, so any single one taking a tenth of it
# is not a fingerprint, it is a denial of service the target gets to trigger.
MAX_PATTERN_SECONDS = 0.30


def adversarial(pattern, anchor):
    """The most expensive subject a target can build for this pattern.

    An attacker reads the shipped rules - they are in a public repository - and
    serves whatever costs most. The strongest thing they can do cheaply is
    repeat the literal the prefilter looks for, since that both defeats the
    prefilter and gives the pattern the most places to start from.
    """
    # Every literal the pattern requires, in order - not just the longest one.
    # Seeding with the anchor alone measured the jQuery rules as free: repeating
    # ".js?version=" gives them no "jquery" to start from, so the scan never
    # begins. Repeating "jquery.js?version=" starts it 7300 times and finishes
    # none of them, which is the 5.3 seconds this gate exists to catch.
    seed = "".join(literal_runs(pattern)) or anchor \
        or "".join(ch for ch in pattern if ch.isalnum()) or "a"
    return (seed * (MAX_BODY_SIZE // len(seed) + 1))[:MAX_BODY_SIZE]


def refuse_quadratic(rules, report):
    """Keep a pattern that is quadratic on hostile input off the big channels.

    A header value, a title or a script src is bounded to a few hundred bytes,
    so an expensive pattern there costs nothing that matters. A body is bounded
    only by MAX_BODY_SIZE, and this repository has already shipped two rules -
    `jquery[^"\'<>]-%.js%?ver=...` - whose lazy unanchored scan restarts at every
    occurrence. Measured on 128 KB of `jquery.js?version=`: 5.3 s for that one
    pattern, against a sweep budget of 3 s, with the scheduler unable to
    preempt any of it.
    """
    kept = []
    for rule in rules:
        if rule["channel"] not in ("body", "headers-raw"):
            kept.append(rule)
            continue

        survivors = []
        for entry in rule["variants"]:
            pattern, anchor = entry[0], entry[1]
            spent = luaeval.time_pattern(pattern, adversarial(pattern, anchor))
            if spent is not None and spent > MAX_PATTERN_SECONDS:
                report["quadratic"]["%s (%.2fs)" % (rule["channel"], spent)] += 1
                report["quadratic_dropped"][rule.get("product") or rule["upstream"]] += 1
                continue
            survivors.append(entry)
        if survivors:
            kept.append(dict(rule, variants=survivors))
    return kept


def nmap_identities(path):
    """Every CPE nmap's own service-probe database can already emit."""
    found = set()
    if not path or not os.path.exists(path):
        return found
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if "cpe:/" not in line:
                continue
            for match in re.finditer(r"cpe:/([aoh]):([^:\s]+):([^:\s]+)", line):
                found.add("cpe:/%s:%s:%s" % (match.group(1),
                                             match.group(2).lower(),
                                             match.group(3).lower()))
    return found


# The most patterns any one identity may keep on one channel. Set cover already
# removes what is redundant against observed subjects; this bounds what is
# merely prolific, so no single product can dominate the file.
MAX_PATTERNS_PER_IDENTITY = 8


def drop_what_nmap_knows(rules, known, report):
    """Discard banner rules for identities nmap already reports itself.

    The banner channel reads nmap's own service fingerprint, so it competes
    directly with nmap's service-probe database - and loses on volume. Measured,
    it arrived as 832 patterns for 111 identities, of which MariaDB alone was
    138, MySQL 108, OpenSSH 54 and BIND 50. Every one of those four is a CPE
    nmap emits itself, and this script already reads `port.version.cpe`, so
    carrying them re-derives at 286 KB what is handed over for nothing.

    What survives is the part nmap cannot do. The HTTP channels are never
    filtered this way: nmap reads the Server header and stops, where these rules
    read titles, meta tags, cookies and bodies it never looks at.
    """
    if not known:
        return rules
    kept = []
    for rule in rules:
        alias = normalize.corrected(normalize.alias_of(rule["cpe_template"]))
        if rule["channel"] == "banner" and alias in known:
            report["already_in_nmap"][alias] += 1
            continue
        kept.append(rule)
    return kept


def cap_per_identity(rules, report):
    """Bound how many patterns one identity may contribute to one channel."""
    seen = collections.Counter()
    kept = []
    for rule in rules:
        alias = normalize.corrected(normalize.alias_of(rule["cpe_template"]))
        key = (alias, rule["channel"], rule.get("field"))
        if rule["source"] == "legacy":
            # Never capped. These are what the script detects today, and a cap
            # that trims them is not a size saving, it is a regression: the
            # first version of this cap silently dropped three Artifactory and
            # three FishEye patterns, each of them a detection that works.
            seen[key] += len(rule["variants"])
            kept.append(rule)
            continue
        room = MAX_PATTERNS_PER_IDENTITY - seen[key]
        if room <= 0:
            report["capped"][rule["channel"]] += len(rule["variants"])
            continue
        if len(rule["variants"]) > room:
            report["capped"][rule["channel"]] += len(rule["variants"]) - room
            rule = dict(rule, variants=rule["variants"][:room])
        seen[key] += len(rule["variants"])
        kept.append(rule)
    return kept


def reduce_patterns(rules, report):
    """Keep the fewest patterns that still make every demonstrated detection.

    Recog writes one fingerprint per banner form it has seen, so PowerDNS
    arrives as twenty patterns that differ only in what follows the version.
    Shipped whole, the banner channel was 1136 entries for 111 identities - 64%
    of the file for 6% of the products.

    Each identity's patterns are run against every subject that identity's
    oracles offer, and a greedy set cover keeps the smallest group that still
    extracts the same version from every one of them. Where two patterns cover
    the same subjects the more general one wins, because it is the one with a
    chance of matching a banner form nobody has recorded yet.

    The honest caveat: this minimises against **observed** subjects. A dropped
    pattern could in principle match some string no example covers. That is why
    the cover is per identity and not global - a product never loses its last
    pattern - and why the reduction is reported rather than silent.
    """
    by_alias = collections.defaultdict(list)
    untouched = []
    for rule in rules:
        alias = normalize.corrected(normalize.alias_of(rule["cpe_template"]))
        if rule["source"] == "legacy":
            # Exempt for the same reason as the cap: a cover computed from
            # generated subjects has no standing to retire a pattern that has
            # been detecting real software in the field.
            untouched.append(rule)
        elif alias:
            by_alias[(alias, rule["channel"], rule.get("field"))].append(rule)

    jobs, index = [], []
    for key, group in by_alias.items():
        subjects = {}
        for rule in group:
            for subject, expected in rule.get("oracle", []):
                subjects[subject] = expected
        if len(group) < 2 or not subjects:
            continue
        for rule in group:
            for position, entry in enumerate(rule["variants"]):
                for subject, expected in subjects.items():
                    jobs.append((entry[0], subject))
                    index.append((key, id(rule), position, subject, expected))

    covers = collections.defaultdict(set)
    if jobs:
        for (key, rule_id, position, subject, expected), result in zip(index, luaeval.run(jobs)):
            if result and result is not True and result[0] == expected:
                covers[(key, rule_id, position)].add(subject)

    kept = list(untouched)
    for key, group in by_alias.items():
        subjects = {}
        for rule in group:
            for subject, expected in rule.get("oracle", []):
                subjects[subject] = expected

        if len(group) < 2 or not subjects:
            kept.extend(group)
            continue

        candidates = []
        for rule in group:
            for position, variant in enumerate(rule["variants"]):
                candidates.append((covers.get((key, id(rule), position), set()),
                                   len(variant[0]), rule, variant))

        remaining = set(subjects)
        chosen = []
        # Most coverage first, shortest pattern to break a tie: a shorter
        # pattern is the less specific one, so it generalises further.
        while remaining:
            candidates.sort(key=lambda item: (-len(item[0] & remaining), item[1]))
            best = candidates[0]
            if not (best[0] & remaining):
                break
            chosen.append(best)
            remaining -= best[0]
            candidates.remove(best)

        if not chosen:
            kept.extend(group)
            continue

        merged = collections.defaultdict(list)
        for _cover, _size, rule, variant in chosen:
            merged[id(rule)].append((rule, variant))
        for entries in merged.values():
            rule = entries[0][0]
            kept.append(dict(rule, variants=[variant for _r, variant in entries]))

        dropped = sum(len(r["variants"]) for r in group) - len(chosen)
        if dropped > 0:
            report["patterns_reduced"][rule["channel"]] += dropped

    return kept


def emit(rules):
    """The shipped shape: one entry per rule, keyed by a stable name."""
    entries = {}
    seen = collections.defaultdict(list)

    for rule in rules:
        alias = normalize.corrected(normalize.alias_of(rule["cpe_template"]))
        if not alias:
            continue
        for entry in rule["variants"]:
            key = (rule["channel"], rule.get("field"), entry[0])
            seen[key].append((rule, alias, entry))

    for key, candidates in sorted(seen.items(), key=lambda item: str(item[0])):
        channel, field, pattern = key
        # The repository's own alias wins: it is the one that has been asked of
        # the live service. Otherwise recog wins over wappalyzer, because recog
        # curates CPEs as its purpose and wappalyzer carries them as a courtesy.
        order = {"legacy": 0, "recog": 1, "wappalyzer": 2}
        rule, alias, variant = sorted(
            candidates, key=lambda item: order.get(item[0]["source"], 9))[0]
        anchor = variant[1]

        name = "%s, %s" % (rule.get("product") or rule["upstream"], channel)
        suffix = 0
        unique = name
        while unique in entries:
            suffix += 1
            unique = "%s_%d" % (name, suffix)

        key = normalize.channel_key(channel, field)
        if key is None:
            # Nothing at runtime would ever look this up, so shipping it would
            # be bytes that can never fire.
            continue

        entry = {
            "alias": alias,
            "regex": pattern,
            "channel": key,
        }
        if anchor:
            entry["anchor"] = anchor
        if rule["source"] != "legacy":
            entry["source"] = "%s:%s" % (rule["source"], rule["upstream"])
        # The example belongs to THIS variant, not to the rule: a sibling
        # variant of the same alternation may not match it at all.
        if variant[2] is not None and variant[3] is not None:
            entry["example"] = {"subject": variant[2], "version": variant[3]}
        entries[unique] = entry

    return entries


def join_table(sources_dir, entries, nmap_known_path):
    """product name -> CPE, from every catalogue available locally.

    Nuclei carries no CPE for any of its 909 templates, so its probes have to be
    joined to an identity somebody else curated. Guessing a vendor is exactly
    what this repository forbids, and it is forbidden for a good reason - a
    plausible but wrong CPE produces a silent false negative - so the table is
    built only from names that already came with a CPE attached: Wappalyzer's
    285, Recog's product attributes, nmap's own service-probe database, and the
    identities this file already ships.
    """
    table = collections.defaultdict(set)

    def add(name, alias):
        if not name or not alias:
            return
        key = re.sub(r"[^a-z0-9]", "", str(name).lower())
        if key:
            table[key].add(alias)

    wap_dir = os.path.join(sources_dir, "wappalyzer")
    if os.path.isdir(wap_dir):
        seen = set()
        for rule in wappalyzer.load(wap_dir):
            if rule["product"] in seen:
                continue
            seen.add(rule["product"])
            add(rule["product"], normalize.alias_of(rule.get("cpe_template")))

    recog_dir = os.path.join(sources_dir, "recog")
    if os.path.isdir(recog_dir):
        for rule in recog.load(recog_dir):
            add(rule.get("product"), normalize.alias_of(rule.get("cpe_template")))

    if nmap_known_path and os.path.exists(nmap_known_path):
        with open(nmap_known_path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if "cpe:/" not in line:
                    continue
                for match in re.finditer(r"cpe:/([aoh]):([^:\s]+):([^:\s]+)", line):
                    alias = "cpe:/%s:%s:%s" % (match.group(1), match.group(2).lower(),
                                               match.group(3).lower())
                    add(match.group(3), alias)

    for entry in entries.values():
        add(entry["alias"].split(":")[3], entry["alias"])

    def alias_for(tokens):
        for token in tokens:
            key = re.sub(r"[^a-z0-9]", "", token.lower())
            found = table.get(key)
            if found:
                # Where several identities share a product name, the one whose
                # vendor equals its product is the project's own, which is the
                # mainstream spelling far more often than a reseller's.
                return sorted(found, key=lambda a: (a.split(":")[2] != a.split(":")[3], a))[0]
        return None

    return alias_for, len(table)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", required=True,
                        help="directory holding the upstream checkouts")
    parser.add_argument("--out", default="catalog/fingerprints.json")
    parser.add_argument("--paths-out", default="catalog/paths.json",
                        help="where the swept path list is written")
    parser.add_argument("--probes-out", default="catalog/probes.json",
                        help="where the targeted version probes are written")
    parser.add_argument("--force", action="store_true",
                        help="publish even when the result loses most of the "
                             "catalogue, which normally means a missing source")
    parser.add_argument("--report-unjoined", action="store_true",
                        help="list the probe templates no catalogue can name")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would ship, write nothing")
    parser.add_argument("--nmap-probes",
                        default="/opt/homebrew/share/nmap/nmap-service-probes",
                        help="nmap's own probe database, whose identities the "
                             "banner channel must not duplicate")
    args = parser.parse_args()

    report = collections.defaultdict(collections.Counter)

    rules, upstreams = gather(args.sources, args.root)
    print("read        %5d rules from %d upstream catalogue(s)"
          % (len(rules), upstreams))
    print("            %s" % dict(collections.Counter(r["source"] for r in rules)))

    usable = [r for r in rules
              if r.get("version_group") and normalize.alias_of(r.get("cpe_template"))]
    print("versioned   %5d rules carry both a version group and a CPE" % len(usable))

    with_lua = translated(usable, report)
    print("translated  %5d  (%d refused)" % (len(with_lua), len(usable) - len(with_lua)))
    for reason, count in report["untranslatable"].most_common(8):
        print("              %4d  %s" % (count, reason))

    proven = verify(with_lua, report)
    print("verified    %5d  rules reproduce every subject their oracle offers"
          % len(proven))
    for label in sorted(report):
        if label != "untranslatable" and report[label]:
            print("              %-20s %s" % (label, dict(report[label])))

    known = nmap_identities(args.nmap_probes)
    print("nmap knows   %4d identities from its own service probes" % len(known))
    fresh = drop_what_nmap_knows(proven, known, report)
    print("deduped     %5d rules once nmap's own banner coverage is removed "
          "(%d dropped)" % (len(fresh), len(proven) - len(fresh)))

    safe = refuse_quadratic(fresh, report)
    if report["quadratic"]:
        print("timing      %5d patterns cost more than %.2fs on a hostile body: %s"
              % (sum(report["quadratic_dropped"].values()), MAX_PATTERN_SECONDS,
                 dict(report["quadratic_dropped"])))

    minimal = cap_per_identity(reduce_patterns(safe, report), report)
    print("reduced     %5d rules after covering every demonstrated detection"
          % len(minimal))
    if report["patterns_reduced"]:
        print("              %s" % dict(report["patterns_reduced"]))

    entries = emit(minimal)
    print("emitted     %5d entries" % len(entries))
    print("            channels: %s"
          % dict(collections.Counter(e["channel"] for e in entries.values())))
    print("            aliases:  %d distinct"
          % len({e["alias"] for e in entries.values()}))

    # --- the swept paths ---------------------------------------------------
    alias_for, table_size = join_table(args.sources, entries, args.nmap_probes)

    # Only an identity this catalogue can actually report. The sweep matches a
    # response against the rules we ship, so a path for software we have no rule
    # for is a request whose answer nothing can read.
    shipped = {entry["alias"] for entry in entries.values()}

    def recognisable(tokens):
        alias = alias_for(tokens)
        return alias if alias in shipped else None

    candidates, trees = path_builder.load(args.sources, report)

    # --- targeted version probes, chosen BEFORE the sweep -------------------
    # A probe is conditional and the sweep is not, so where both could go to the
    # same path the probe wins and the sweep leaves it alone.
    found, unjoined = nuclei.load(os.path.join(args.sources, "nuclei-templates"),
                                  alias_for, set(path_builder.ALWAYS))
    wap_rules = wappalyzer.load(os.path.join(args.sources, "wappalyzer")) \
        if os.path.isdir(os.path.join(args.sources, "wappalyzer")) else []
    probe_entries = probe_builder.build(wap_rules, found, report)
    owned_by_probe = {path for entry in probe_entries.values()
                      for path in entry["paths"]}

    swept_list, named = path_builder.select(
        candidates, recognisable, report, exclude=owned_by_probe)
    generic = len(path_builder.ALWAYS) + len(path_builder.front_pages())
    print("\npaths")
    print("  read        %5d source files over %d trees: %s"
          % (sum(report["paths_read"].values()), trees, dict(report["paths_read"])))
    print("  usable      %5d distinct paths after filtering (%d refused)"
          % (len(candidates.by_path), sum(report["paths_refused"].values())))
    print("  published   %5d: %d asked of every server, %d from the upstreams"
          % (len(swept_list), generic, len(swept_list) - generic))
    print("              %d of them belong to software this catalogue can name; "
          "the rest are still worth a request for the headers they answer with"
          % report["paths_kept"]["identities named"])
    if report["paths_dropped"]:
        print("  dropped     %s" % dict(report["paths_dropped"]))

    print("\nprobes")
    print("  join table  %5d product names carry a CPE from some catalogue"
          % table_size)
    print("  nuclei      %5d templates name a path and a version pattern; "
          "%d could be joined to an identity" % (len(found) + len(unjoined), len(found)))

    print("  built       %5d probes that can be triggered without a request"
          % len(probe_entries))
    for label in ("probe_no_detector", "probe_no_extractor",
                  "probe_detector_untranslatable", "probe_unverifiable"):
        if report[label]:
            print("                %-30s %d" % (label, sum(report[label].values())))
    for name in sorted(probe_entries):
        entry = probe_entries[name]
        print("      %-22s %-40s %s" % (name[:22], entry["alias"], entry["paths"]))

    if args.report_unjoined:
        print("\n  no catalogue names these %d, so they cannot be probed:"
              % len(unjoined))
        for template, paths in unjoined:
            print("      %-32s %s" % (template[:32], paths))

    if args.dry_run:
        return 0

    # Written in catalogue shape, because the catalogue is the only copy. There
    # is no second "editable source" file: two copies of a 722-rule dictionary
    # is two things to keep in step, and the one that drifts is always the one
    # nobody is reading.
    probes = []
    for name in sorted(probe_entries):
        entry = probe_entries[name]
        detect = []
        for rule in entry["detect"]:
            key = normalize.channel_key(rule["channel"], rule.get("field"))
            if key is None:
                continue
            detect.append({"channel": key, "regex": rule["regex"],
                           "anchor": rule.get("anchor") or ""})
        if not detect:
            continue
        probes.append({
            "name": name,
            "alias": entry["alias"],
            "detect": detect,
            "paths": entry["paths"],
            "extract": [{"regex": r["regex"], "anchor": r.get("anchor") or ""}
                        for r in entry["extract"]],
            "source": entry.get("source", ""),
        })

    refuse_to_shrink(args.out, len(entries), upstreams, args.force)
    refuse_to_shrink(args.paths_out, len(swept_list), trees, args.force, "paths")

    write_catalog(args.paths_out, {"schema": CATALOG_SCHEMA, "paths": swept_list})
    print("wrote       %s" % args.paths_out)

    write_catalog(args.probes_out, {"schema": CATALOG_SCHEMA, "probes": probes})
    print("wrote       %s" % args.probes_out)

    write_catalog(args.out, {"schema": CATALOG_SCHEMA, "rules": entries})
    print("wrote       %s" % args.out)
    print("\nnow run: python3 tools/catalog.py --index   (bumps the serial)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
