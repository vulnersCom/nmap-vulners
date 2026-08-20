"""Read HTTPArchive/Wappalyzer into normalised rules.

Wappalyzer knows about four thousand technologies and carries a CPE for under
three hundred of them, which sounds like a poor yield until you notice which
three hundred: they are the ones a vulnerability scanner cares about. The rest
are analytics tags and font services, and a CPE-less detection is of no use
here anyway, because the endpoint this script queries is addressed by CPE.

Its patterns are JavaScript regular expressions with a Wappalyzer convention
bolted on: a pattern may carry `\\;version:\\1` to name the group holding the
version, and `\\;confidence:50` to hedge. Only the passive channels are read -
the ones answerable from a response this script already fetches. `js` and `dom`
need a browser, and importing them would produce rules that can never fire.
"""

import json
import glob
import os
import re

# The fields that can be answered from an HTTP response, and the channel each
# becomes. `scriptSrc` is kept because a versioned library filename is often
# the only place a version appears at all.
PASSIVE = {
    "headers": "header",
    "cookies": "cookie",
    "meta": "meta",
    "html": "body",
    "scriptSrc": "script",
}

VERSION_SPEC = re.compile(r"\\;version:(.*)$")
PLAIN_GROUP = re.compile(r"^\\(\d+)$")
TAGGED = re.compile(r"\\;(confidence|version):")


def _patterns(value):
    """Wappalyzer writes a pattern, a list of them, or a map of them."""
    if isinstance(value, str):
        yield None, value
    elif isinstance(value, list):
        for item in value:
            yield from _patterns(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            for _, pattern in _patterns(item):
                yield key, pattern


def _split(pattern):
    """Strip Wappalyzer's tags, returning (regex, version_group).

    version_group is None when the pattern states no version, and the pattern
    is refused outright when the version is given as a ternary - `\\1?\\1:6`
    means "group 1 if it matched, otherwise the literal 6", and a literal
    fallback would put a made-up version into a CPE.
    """
    version = None
    match = VERSION_SPEC.search(pattern)
    if match:
        spec = match.group(1)
        pattern = pattern[:match.start()]
        plain = PLAIN_GROUP.match(spec.strip())
        if not plain:
            return None, None
        version = int(plain.group(1))

    # Whatever tags remain - confidence, and any future one - are metadata, not
    # pattern. Cutting at the first one keeps an unknown tag from being matched
    # as literal text.
    cut = TAGGED.search(pattern)
    if cut:
        pattern = pattern[:cut.start()]
    return pattern, version


def load(root_dir):
    technologies = {}
    for path in sorted(glob.glob(os.path.join(root_dir, "src", "technologies",
                                              "*.json"))):
        with open(path, encoding="utf-8") as handle:
            technologies.update(json.load(handle))

    rules = []
    for name, tech in sorted(technologies.items()):
        cpe = tech.get("cpe")
        if not cpe:
            continue

        for field, channel in PASSIVE.items():
            if field not in tech:
                continue
            for key, raw in _patterns(tech[field]):
                pattern, version_group = _split(raw)
                if pattern is None or not pattern:
                    continue
                if version_group is None:
                    # Presence-only. Kept, because a product identified without
                    # a version is what a targeted version probe is fired for.
                    pass

                rules.append({
                    "source": "wappalyzer",
                    "upstream": "%s/%s%s" % (name, field,
                                             "/" + key if key else ""),
                    "channel": channel,
                    "field": (key or "").lower() or None,
                    "pattern": pattern,
                    # Wappalyzer patterns are matched case-insensitively by
                    # every implementation of it, including the reference one.
                    "ignore_case": True,
                    "dot_newline": False,
                    "multiline": False,
                    "version_group": version_group,
                    "cpe_template": cpe,
                    "vendor": None,
                    "product": name,
                    "description": tech.get("description", "")[:200],
                    "examples": [],
                    # A header or meta rule is scoped to one named field; an
                    # html rule is written against the whole document.
                    "field_scoped": channel in ("header", "meta", "cookie"),
                })
    return rules
