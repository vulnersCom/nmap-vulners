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
import paths as path_builder                                      # noqa: E402
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
        # PCRE's \w includes the underscore and Lua's %w does not, so mapping
        # one onto the other TRUNCATED the capture at the first underscore -
        # and a truncated version is worse than a miss, because it mints a
        # confident wrong CPE and asks the API about a release that never was.
        (r"^Tomcat/([\w.]+)$", 1, False, "Tomcat/9.0.1_beta", "9.0.1_beta"),
        (r"^name=(\w+)$", 1, False, "name=my_app", "my_app"),
        # \b before a NON-word class. \W was listed as a word class, so this
        # became "%f[%w]%W" - a start-of-word frontier immediately before a
        # guaranteed non-word character, which can never match.
        (r"Tomcat\b\W+v(\d+)", 1, False, "Tomcat - v9", "9"),
        # A range whose endpoint needs escaping. Lua consumes "%x" as an escape
        # BEFORE testing for a range, so "[+--]" collapsed from three
        # characters to a set that matched none of them.
        (r"^v([+--]+)$", 1, False, "v+,-", "+,-"),
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


def check_rejections(checks):
    """A translated pattern must also refuse what the original refuses.

    The corpus above only ever asserted that a rule still finds its recorded
    example. That cannot see a WIDENING: a pattern that matches strictly more
    than the original keeps every example it had and gains false positives, so
    the oracle stays green while the rule starts inventing versions.
    """
    # (pcre, capture group, a subject the ORIGINAL does not match)
    corpus = [
        # {20} was widened to "one or more" - upper bound AND lower bound - so
        # a single letter satisfied a rule that demanded twenty.
        (r"^ID: ([\d.]+) [A-Z]{20}$", 1, "ID: 1.2 X"),
        (r"^Build ([\d.]+) [0-9a-f]{32}$", 1, "Build 9.9 a"),
        # %W admitted the underscore that PCRE's \W excludes.
        (r"^v(\d+)\W$", 1, "v12_"),
    ]

    for pcre, group, subject in corpus:
        try:
            variants = translate(pcre, group)
        except Untranslatable:
            # Refusing to translate is a sound answer: the rule does not ship,
            # so it cannot be wrong in the field.
            checks.that(True, "%s is refused rather than widened" % pcre)
            continue
        got = [matches(pattern, subject) for pattern, _ in variants]
        checks.that(all(value in (None, "RAISED") for value in got),
                    "%s still rejects %r" % (pcre, subject),
                    "variants gave %r" % (got,))


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


def check_adversarial_seed(checks):
    """The hostile subject must be built from the literals a rule really needs.

    fold_case turns every letter into a two-element class, so literal_runs()
    finds nothing in a folded pattern. adversarial() then fell back to the
    anchor alone - the weaker seed whose own comment records that it measured
    the jQuery rules as free - and 145 of the shipped rules were in exactly
    that state, which left the quadratic gate blind to the case-folded body
    rules it exists for. Restoring the literals took the gate from catching one
    pattern to catching ten.
    """
    from build import unfold, adversarial
    from pcre2lua import literal_runs

    folded = translate(r"jquery[^\"]*?\.js\?ver=([\d.]+)", 1,
                       ignore_case=True)[0]
    pattern, anchor = folded

    checks.that(literal_runs(pattern) == [],
                "a folded pattern really does offer no literal run")
    checks.that(literal_runs(unfold(pattern)) == ["jquery", ".js?ver="],
                "unfolding puts the literals back, in order")
    checks.that(adversarial(pattern, anchor).startswith("jquery.js?ver="),
                "so the hostile subject repeats what the pattern must match, "
                "not just the prefilter literal")

    # A two-character class that is NOT a fold must survive untouched, or
    # unfolding would quietly rewrite ordinary rules.
    checks.that(unfold("[ab]x") == "[ab]x",
                "a genuine two-character class is not a folded letter")


def check_channel_keys(checks):
    """A channel key survives a round trip, and only a usable one is minted.

    CLAUDE.md promises a hand-edited entry carrying no `source` survives the
    next rebuild. It did not: channel_key understood only the SOURCE spellings,
    so an entry filed the way the catalogue itself spells it - "hdr:server",
    "meta:generator", which is 246 of the 722 shipped rules - was mapped to
    None and dropped with a bare `continue`.
    """
    for key in ("hdr:server", "meta:generator", "body", "raw", "banner"):
        checks.that(normalize.channel_key(key) == key,
                    "an already-normalised %r survives a rebuild" % key)

    checks.that(normalize.channel_key("server") == "hdr:server",
                "a source spelling is still normalised")
    checks.that(normalize.channel_key("header", "X-Powered-By") == "hdr:x-powered-by",
                "and a header field is lowercased into the key")

    # nselib lowercases every response header name, so an uppercase key can
    # never be looked up. Minting one would ship bytes that can never fire.
    for key in ("hdr:Server", "meta:Generator", "HDR:server"):
        checks.that(normalize.channel_key(key) is None,
                    "%r is refused: the matcher can only ever see lowercase" % key)


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


def check_paths(checks):
    """What the sweep is allowed to knock on.

    The list goes out against every web port of every host in a scan, so a bad
    entry is not one wasted request - it is one per port per host, from a script
    that has to be able to explain every packet it sends.
    """
    refused = {
        "/../../etc/passwd": "traversal",
        "/a\\b": "a backslash asks for a parser bug, not a fingerprint",
        "/{{BaseURL}}/x{{n}}": "an unresolved interpolation",
        "/%c0": "a percent escape, which in this corpus is normaliser abuse",
        "/?map=*": "a wildcard the operator was meant to fill in",
        "/.settings/rules.json?auth=FIREBASE_SECRET": "an ALL_CAPS placeholder",
        "/:9182": "a host:port fragment somebody pasted into a path field",
        "/&?=?": "punctuation, not a path",
        "/logo.gif": "an image; no rule can read one",
        "/fonts/x.woff2": "a font",
        "https://example.com/x": "somebody else's host",
        "/" + "a" * 200: "longer than any real fingerprinting path",
        "": "nothing at all",
    }
    for path, why in refused.items():
        checks.that(path_builder.normalise(path) is None,
                    "a path is refused: %s" % why,
                    "normalise(%r) returned %r" % (path, path_builder.normalise(path)))

    kept = {
        "/wp-login.php": "/wp-login.php",
        "wp-login.php": "/wp-login.php",          # WhatWeb omits the slash
        "{{BaseURL}}/CHANGELOG.txt": "/CHANGELOG.txt",   # nuclei writes it so
        "/data?get=prodServerGen": "/data?get=prodServerGen",
        "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000":
            "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
        "/bootstrap/css/bootstrap.min.css": "/bootstrap/css/bootstrap.min.css",
    }
    for raw, expected in kept.items():
        checks.that(path_builder.normalise(raw) == expected,
                    "a usable path survives normalisation: %s" % raw,
                    "got %r" % (path_builder.normalise(raw),))

    # Order is load-bearing: the script requests a PREFIX of this list, bounded
    # by -T, so the informative paths have to come before the guesses.
    import collections
    report = collections.defaultdict(collections.Counter)
    candidates = path_builder.Candidates()
    candidates.add("/wp-login.php", "wordpress", "whatweb")
    candidates.add("/wp-login.php", "wordpress-detect", "nuclei")
    candidates.add("/only-once.php", "obscure appliance", "whatweb")
    chosen, named = path_builder.select(candidates, lambda tokens: None, report)

    checks.that(chosen[0] == "/",
                "the front page is asked first, always",
                "got %r" % (chosen[:1],))
    checks.that(chosen.index("/wp-login.php") < chosen.index("/only-once.php"),
                "a path two catalogues name outranks one only a single plugin does",
                "%r" % (chosen[:14],))
    front = path_builder.front_pages()
    checks.that(chosen.index("/only-once.php") < chosen.index(front[-1]),
                "and every upstream path outranks the front-page guesses",
                "%r" % (chosen[-4:],))

    # A path a probe owns is not swept as well: the probe is conditional and the
    # sweep is not, and only the probe carries the version extractor.
    chosen, _ = path_builder.select(candidates, lambda tokens: None, report,
                                    exclude={"/wp-login.php"})
    checks.that("/wp-login.php" not in chosen,
                "a path a targeted probe owns is left out of the sweep",
                "%r" % (chosen[:12],))

    checks.that(path_builder.ALWAYS[0] == "/" and "/robots.txt" in path_builder.ALWAYS,
                "the universal list is the front page and robots.txt")


def main():
    if luaeval.LUA is None:
        print("FAIL  no lua interpreter on PATH; the translation cases need one")
        return 1

    checks = Checks()
    check_translation(checks)
    check_rejections(checks)
    check_anchors(checks)
    check_capture_digit(checks)
    check_adversarial_seed(checks)
    check_channel_keys(checks)
    check_samples(checks)
    check_identities(checks)
    check_paths(checks)
    check_shrink_guard(checks)
    return checks.report()


if __name__ == "__main__":
    sys.exit(main())
