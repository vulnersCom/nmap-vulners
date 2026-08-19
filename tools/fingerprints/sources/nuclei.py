"""Read ProjectDiscovery's technology templates, for the paths they know.

Nuclei is the answer to a question the other catalogues do not ask: **where do
you go to find out the version**. Recog reads a banner, Wappalyzer reads a front
page, and both are silent when the front page does not say. Nuclei knows that
Confluence tells you at `/dologin.action`, Drupal at `/CHANGELOG.txt`, PuppetDB
at `/pdb/meta/v1/version` - 314 templates pair a specific path with a regex that
pulls a version out of what comes back.

What it does not carry is a CPE, not for a single one of its 909 templates. That
matters more here than anywhere else, because the endpoint this script queries
is addressed by CPE: a probe that finds "Confluence 7.13.0" and cannot name the
identity has found nothing this script can use.

So the join is by product name against identities the curated sources already
supplied, and a template that does not join is **skipped and counted**, never
resolved by guessing a vendor. Nine of them join today. The rest are listed by
`--report-unjoined`, and turning that list into identities needs a CPE resolver,
which is recorded in dev_docs/backlog.md as the blocker it is.
"""

import glob
import os
import re

try:
    import yaml
except ImportError:  # pragma: no cover - reported by the caller
    yaml = None

# Paths that are generic rather than product-specific. Nuclei uses them to read
# a version out of a site's own metadata, which is fine for nuclei and useless
# here: the sweep already fetches them, and firing a targeted probe at
# /robots.txt would spend a request to re-read a page it already has.
GENERIC = {"/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/index.html"}

# Nuclei interpolates these at run time. A path containing one cannot be turned
# into a request this script would make.
INTERPOLATED = re.compile(r"\{\{")


def _capture_count(expression):
    """Capturing groups in a PCRE: '(' not escaped, not '(?', not in a class."""
    count, index, in_class = 0, 0, False
    while index < len(expression):
        ch = expression[index]
        if ch == "\\":
            index += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif ch == "(" and not in_class and expression[index + 1:index + 2] != "?":
            count += 1
        index += 1
    return count


def _product_tokens(template_id):
    """The names a template might be known by, for joining to an identity."""
    base = template_id.lower()
    for suffix in ("-detect", "-version", "-panel", "-detection"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return {base, base.replace("-", "_"), base.replace("-", "")}


def load(root_dir, alias_for, already_swept=()):
    """Targeted version probes, joined to identities that already exist.

    @param alias_for callable taking a set of product tokens and returning a CPE
           alias or None. Supplied by the caller so that the only identities
           used are ones another catalogue already curated.
    """
    if yaml is None:
        return [], []

    probes, unjoined = [], []
    pattern = os.path.join(root_dir, "http", "technologies", "**", "*.yaml")
    for path in sorted(glob.glob(pattern, recursive=True)):
        try:
            with open(path, encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
        except Exception:
            continue
        if not isinstance(document, dict):
            continue

        template_id = document.get("id") or os.path.basename(path)[:-5]
        info = document.get("info") or {}

        for request in (document.get("http") or document.get("requests") or []):
            if str(request.get("method", "GET")).upper() != "GET":
                continue

            paths = []
            for raw in request.get("path", []):
                candidate = str(raw).replace("{{BaseURL}}", "") or "/"
                if candidate in GENERIC or INTERPOLATED.search(candidate):
                    continue
                if "\\" in candidate:
                    # Nuclei writes "/\\" to make a server normalise a path. It
                    # is a request line this script would not send, and putting
                    # a backslash on the wire from a "safe" script is not a
                    # detection, it is a probe for a parser bug.
                    continue
                if not candidate.startswith("/"):
                    candidate = "/" + candidate
                if candidate in already_swept:
                    # The sweep fetches it anyway, so a probe spending a second
                    # request on it learns nothing the passive rules did not
                    # already have a chance at.
                    continue
                if candidate not in paths:
                    paths.append(candidate)
            if not paths:
                continue

            extractors = []
            for extractor in (request.get("extractors") or []):
                if extractor.get("type") != "regex":
                    continue
                group = extractor.get("group")
                for expression in extractor.get("regex", []):
                    text = str(expression)
                    if group:
                        extractors.append((text, int(group)))
                        continue
                    # Nuclei with no `group` returns the whole match, which is
                    # never a version - it is the sentence the version sits in.
                    # Reading it as group 1 gave Gitea a capture of "(\s*)" and
                    # Lotus Domino a version of "Domino A .". So a group-less
                    # extractor is used only when the regex has exactly one
                    # capture, where the intent is unambiguous.
                    if _capture_count(text) == 1:
                        extractors.append((text, 1))
            if not extractors:
                continue

            tokens = _product_tokens(template_id)
            alias = alias_for(tokens)
            if not alias:
                unjoined.append((template_id, paths[:2]))
                break

            probes.append({
                "source": "nuclei",
                "upstream": template_id,
                "alias": alias,
                "product": info.get("name") or template_id,
                "paths": paths,
                "extractors": extractors,
            })
            break

    return probes, unjoined
