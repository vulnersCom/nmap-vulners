"""Assemble targeted version probes: detect a product, then go and ask it.

The passive rules answer "what is running here" from a response the sweep
already fetched. They are silent whenever the front page names a product and
not its version - which is the normal case for the applications that matter
most, because hiding the version is the first hardening step every guide
recommends. A CMS that says "Joomla" and nothing else produces no CPE, and no
CPE means no lookup.

A probe closes that gap with one request, and only when it is worth making:

1. a **detector** must fire on a response the sweep already has. It comes from
   Wappalyzer, whose presence-only patterns are exactly this signal.
2. the identity must still have **no version** after all the passive rules ran.
   A probe that would re-learn something already known is not sent.
3. only then is the **path** fetched, and an **extractor** read out of it. Both
   come from Nuclei, which is the only catalogue in the set that records where
   to go: Joomla at /administrator/manifests/files/joomla.xml, Drupal at
   /CHANGELOG.txt, Jira at /secure/Dashboard.jspa.

The three-way join is what bounds the cost. A probe exists only where one
catalogue can name the identity, a second can recognise the product without a
request, and a third knows which door to knock on - so a scan of a host running
none of them sends nothing at all.
"""

import collections

import normalize
from pcre2lua import translate, Untranslatable
import sample


# How many paths one probe may name. Nuclei often lists a preferred path and
# fallbacks; beyond two the marginal chance of an answer does not justify a
# request made to a host that has already been identified.
MAX_PATHS_PER_PROBE = 2


def _lua(pattern, group, ignore_case, report, label):
    """One translated, sample-verified Lua pattern, or None."""
    try:
        variants = translate(pattern, group, ignore_case=ignore_case)
    except Untranslatable as reason:
        report["probe_untranslatable"][str(reason)[:40]] += 1
        return None

    if group is None:
        # A detector reports presence, so any variant will do - but it must
        # still be a pattern that compiles, which translate() has established.
        return variants[0]

    oracle = [pair for pair in sample.samples(pattern, group, ignore_case=ignore_case)
              if normalize.plausible(pair[1])]
    if not oracle:
        # Either nothing could be generated, or what it extracted is not a
        # version. Both are disqualifying: a probe exists to append a version to
        # a CPE, and appending "Domino A ." asks the service about a release
        # that never existed.
        report["probe_unverifiable"][label] += 1
        return None
    return variants, oracle


def build(wappalyzer_rules, nuclei_probes, report):
    """Probes, keyed by a stable name, ready to be written as JSON."""
    # Presence-only Wappalyzer rules, by the identity they detect. These are the
    # ones this importer otherwise discards: they name a product and no version,
    # which is useless on its own and is precisely a probe's trigger.
    detectors = collections.defaultdict(list)
    for rule in wappalyzer_rules:
        if rule.get("version_group") is not None:
            continue
        alias = normalize.corrected(normalize.alias_of(rule.get("cpe_template")))
        if not alias:
            continue
        if rule["channel"] not in ("header", "meta", "cookie", "body", "script"):
            continue
        detectors[alias].append(rule)

    entries = {}
    for probe in nuclei_probes:
        alias = normalize.corrected(probe["alias"])
        available = detectors.get(alias)
        if not available:
            # Nothing can recognise this product without a request, so the probe
            # would have to be sent unconditionally - to every host, on the
            # chance that one of them runs it. That is a scanner behaving badly.
            report["probe_no_detector"][alias] += 1
            continue

        detect = []
        for rule in available:
            pattern = _lua(rule["pattern"], None, rule.get("ignore_case", True),
                           report, alias)
            if pattern is None:
                continue
            text, anchor = pattern
            detect.append({
                "channel": rule["channel"],
                "field": rule.get("field"),
                "regex": text,
                "anchor": anchor or "",
            })
        if not detect:
            report["probe_detector_untranslatable"][alias] += 1
            continue

        extract, example = [], None
        for expression, group in probe["extractors"]:
            result = _lua(expression, group, False, report, alias)
            if result is None:
                continue
            variants, oracle = result
            for text, anchor in variants:
                extract.append({"regex": text, "anchor": anchor or ""})
            if example is None and oracle:
                example = {"subject": oracle[0][0], "version": oracle[0][1]}
        if not extract:
            report["probe_no_extractor"][alias] += 1
            continue

        entries[probe["product"]] = {
            "alias": alias,
            "detect": detect,
            "paths": probe["paths"][:MAX_PATHS_PER_PROBE],
            "extract": extract,
            "source": "%s:%s + wappalyzer" % (probe["source"], probe["upstream"]),
        }
        if example:
            entries[probe["product"]]["example"] = example

    return entries
