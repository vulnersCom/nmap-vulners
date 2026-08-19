#!/usr/bin/env python3
"""Prove the importer's decisions, so an automatic rebuild cannot quietly change them.

    python3 tools/fingerprints/selftest.py

Once the catalogue rebuilds itself on a schedule, nothing between an upstream
edit and every installed scanner is looked at by a human. The catalogue gate
(`tools/catalog_diff.py`) covers the outcome - did the rebuild lose detections -
but it cannot tell a translation that is subtly wrong from one that is right,
because both produce the same number of rules.

That is what this covers: the decisions the importer makes about individual
rules. Every case here is a bug that was really shipped, or a property whose
loss would be invisible in any count.

Lua is the oracle wherever a pattern is involved. Nothing here asserts that a
translated pattern LOOKS right; it is run through the interpreter and has to
behave.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import luaeval                                                    # noqa: E402
import normalize                                                  # noqa: E402
import sample                                                     # noqa: E402
from pcre2lua import (translate, literal_anchor, literal_runs,     # noqa: E402
                      capture_can_hold_a_digit, Untranslatable)


class Checks:
    def __init__(self):
        self.passed = 0
        self.failures = []

    def that(self, condition, description, context=""):
        if condition:
            self.passed += 1
            print("ok    %s" % description)
        else:
            self.failures.append(description + (("  [%s]" % context) if context else ""))
            print("FAIL  %s%s" % (description, ("  [%s]" % context) if context else ""))
        return bool(condition)

    def report(self):
        print("\n%d passed, %d failed" % (self.passed, len(self.failures)))
        return 1 if self.failures else 0


def matches(pattern, subject):
    """What `pattern` captures from `subject`, run through real Lua."""
    result = luaeval.run([(pattern, subject)])[0]
    if result is False:
        return "RAISED"
    if result is None:
        return None
    return result[0] if result else ""


def check_translation(checks):
    """A translated pattern must extract what the original extracts."""
    # (pcre, capture group, ignore case, subject, expected version)
    corpus = [
        (r"^Apache/([\d.]+)", 1, False, "Apache/2.4.41", "2.4.41"),
        # A character class range. Escaping the dash - which the first version of
        # the translator did - turns [0-9.] into three characters instead of
        # eleven, and every version pattern in the corpus contains such a class.
        (r"^Logitech Media Server \(([0-9.]+) - [0-9]+\)$", 1, False,
         "Logitech Media Server (7.9.3 - 1586752599)", "7.9.3"),
        (r"^Server: Boa/([\d.]+[a-z]?)$", 1, False, "Server: Boa/0.94.13", "0.94.13"),
        # A word boundary CLOSING a word. \b became %f[%w] here - a frontier that
        # can never hold before a hyphen - so the rule matched nothing at all.
        (r"\bTomcat\b(?:-([\d.]+))?", 1, True, "Tomcat-9.0.1", "9.0.1"),
        # An alternation that must be expanded, where only one branch captures.
        (r"(?:Apache(?:$|/([\d.]+)|[^/-])|(?:^|\b)HTTPD)", 1, False,
         "Apache/2.2.15", "2.2.15"),
        # Case folding, and the anchor that has to survive it.
        (r"akka-http(?:/([\d.]+))?", 1, True, "akka-http/10.2.4", "10.2.4"),
        (r"^OpenSSH[_-]([\w.]+)", 1, False, "OpenSSH_7.4", "7.4"),
        # A bounded repeat too large to unroll is widened to unbounded.
        (r"^X-Thing: ([\w.]{1,512})$", 1, False, "X-Thing: 1.2.3", "1.2.3"),
    ]

    for pcre, group, fold, subject, expected in corpus:
        try:
            variants = translate(pcre, group, ignore_case=fold)
        except Untranslatable as reason:
            checks.that(False, "translates %s" % pcre, str(reason))
            continue

        got = [matches(pattern, subject) for pattern, _ in variants]
        checks.that(expected in got,
                    "%s extracts %r from %r" % (pcre, expected, subject),
                    "variants gave %r" % (got,))
        checks.that("RAISED" not in got,
                    "%s produces only patterns Lua accepts" % pcre)


def check_anchors(checks):
    """The prefilter literal must be one the pattern cannot match without."""
    checks.that(literal_anchor("^Apache/([%d.][%d.]*)") == "apache/",
                "the anchor is the longest guaranteed literal, lowercased")

    # `+` does not break a run in Lua - a+b guarantees "ab" - but the emitter
    # writes a+ as "aa*", where it does. Reading `+` as an ordinary character
    # put a literal plus into the anchor and the prefilter then matched nothing.
    checks.that(literal_anchor("abb*c([%d.]+)") is None,
                "a repeat breaks the run rather than being taken literally")

    # The anchor has to be computed BEFORE case folding: a folded pattern is all
    # character classes and has no literal run left to search for.
    variants = translate(r"Adminer</a> <span class=\"version\">([\d.]+)</span>",
                         1, ignore_case=True)
    anchors = [anchor for _, anchor in variants]
    checks.that(all(anchor and anchor == anchor.lower() for anchor in anchors),
                "a case-folded rule still carries a lowercase anchor",
                "got %r" % (anchors,))

    for pattern, anchor in variants:
        subject = 'Adminer</a> <span class="version">4.8.1</span>'
        checks.that(anchor in subject.lower(),
                    "the anchor really occurs in what the pattern matches")
        checks.that(matches(pattern, subject) == "4.8.1",
                    "and the pattern extracts the version from it")

    # Every literal, in order, is what makes the worst case for a lazy pattern.
    runs = literal_runs("jquery[^\"'<>]-%.js%?ver=([%d.]+)")
    checks.that(runs == ["jquery", ".js?ver="],
                "every required literal is reported, not only the longest",
                "got %r" % (runs,))


def check_capture_digit(checks):
    """A capture that cannot hold a digit can never produce a version."""
    checks.that(not capture_can_hold_a_digit("([sS][aA][rR][gG][eE])"),
                "a codename capture is refused")
    checks.that(capture_can_hold_a_digit("([%d.][%d.]*)"),
                "a numeric capture is accepted")
    checks.that(capture_can_hold_a_digit("([%w.]+)"),
                "an alphanumeric capture is accepted")
    checks.that(capture_can_hold_a_digit("([^\"]+)"),
                "a negated class that does not exclude digits is accepted")


def check_samples(checks):
    """The sample generator proposes; Python's own engine disposes."""
    import re

    for pcre, group in [(r"^Apache/([\d.]+)", 1),
                        (r"Drupal(?:\s([\d.]+))?", 1),
                        (r"AWStats ([\d.]+(?: \(build [\d.]+\))?)", 1)]:
        pairs = sample.samples(pcre, group)
        checks.that(bool(pairs), "a subject can be generated for %s" % pcre)
        compiled = re.compile(pcre)
        for subject, captured in pairs:
            found = compiled.search(subject)
            checks.that(found is not None and found.group(group) == captured,
                        "the generated subject really is one %s accepts" % pcre,
                        "%r -> %r" % (subject, captured))

    # A generated capture should demonstrate something. "." verifies a pattern
    # and shows nothing, and the runtime rejects it anyway.
    pairs = sample.samples(r"Foo ([0-9.]+)", 1)
    checks.that(pairs and any(char.isdigit() for char in pairs[0][1]),
                "a numeric class demonstrates a digit, not a bare separator",
                "got %r" % (pairs[:1],))


def check_identities(checks):
    """Alias normalisation, and the corrections measured against the live API."""
    checks.that(normalize.alias_of("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*")
                == "cpe:/a:apache:tomcat", "a 2.3 CPE becomes a 2.2 prefix")
    checks.that(normalize.alias_of("cpe:/a:perl:perl:{service.version}")
                == "cpe:/a:perl:perl", "a recog template loses its placeholder")
    checks.that(normalize.alias_of("cpe:2.3:a:{vendor}:thing:*") is None,
                "an unfilled vendor is refused rather than guessed")

    checks.that(normalize.corrected("cpe:/a:igor_sysoev:nginx") == "cpe:/a:f5:nginx",
                "the nginx spelling that answers wins")
    checks.that(normalize.corrected("cpe:/o:oracle:sunos") == "cpe:/o:sun:sunos",
                "the SunOS spelling that answers wins")

    checks.that(normalize.plausible("2.4.41"), "a dotted version is plausible")
    checks.that(normalize.plausible("3.7.4.post0"), "so is a package version")
    checks.that(not normalize.plausible("sarge"), "a codename is not")

    checks.that(normalize.channel_key("server") == "hdr:server",
                "the Server channel is filed by header name")
    checks.that(normalize.channel_key("meta", "generator") == "meta:generator",
                "a meta rule is filed by tag name")
    checks.that(normalize.channel_key("headers-raw") == "raw",
                "the raw header block keeps its own channel")
    checks.that(normalize.channel_key("nonsense") is None,
                "a channel nothing reads is refused")


def check_shrink_guard(checks):
    """The guard that stops a rebuild with no sources from publishing itself."""
    import json
    import tempfile
    import build

    with tempfile.TemporaryDirectory() as workspace:
        target = os.path.join(workspace, "fingerprints.json")
        with open(target, "w", encoding="utf-8") as handle:
            json.dump({"schema": 1, "rules": {str(i): {} for i in range(100)}}, handle)

        raised = False
        try:
            build.refuse_to_shrink(target, 100, sources_found=0, force=False)
        except SystemExit:
            raised = True
        checks.that(raised, "a rebuild that found no upstream is refused")

        raised = False
        try:
            build.refuse_to_shrink(target, 40, sources_found=2, force=False)
        except SystemExit:
            raised = True
        checks.that(raised, "a rebuild that loses most of the catalogue is refused")

        raised = False
        try:
            build.refuse_to_shrink(target, 98, sources_found=2, force=False)
        except SystemExit:
            raised = True
        checks.that(not raised, "ordinary churn is allowed through")

        raised = False
        try:
            build.refuse_to_shrink(target, 1, sources_found=0, force=True)
        except SystemExit:
            raised = True
        checks.that(not raised, "--force is the deliberate override")


def main():
    if luaeval.LUA is None:
        print("FAIL  no lua interpreter on PATH; the translation cases need one")
        return 1

    checks = Checks()
    check_translation(checks)
    check_anchors(checks)
    check_capture_digit(checks)
    check_samples(checks)
    check_identities(checks)
    check_shrink_guard(checks)
    return checks.report()


if __name__ == "__main__":
    sys.exit(main())
