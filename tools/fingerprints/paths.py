"""Where to knock: the paths the sweep requests on every web port.

The sweep is the half of this plugin that finds software nmap's own probe
cannot see, and it can only find what it asks for. Until this module existed
the list was inherited from 1.x and was not a fingerprinting list at all: 125
paths that were eleven filenames - index, default, home, main, start, admin,
base, menu, inicio, indice, localstart - crossed with eleven extensions. 121
requests per port looking for a front page, and not one path that reveals a
product.

What a useful path looks like is what the upstream catalogues already record.
Measured on 2026-08-19:

    WhatWeb            1 832 plugins, 549 distinct :url probes, attached to
                       a named product - by far the richest source of "go here
                       to see whether this is installed"
    nuclei             909 technology templates; 456 of their path mentions are
                       "/" and the rest name a real endpoint
    FingerprintHub     3 338 templates, every one carrying vendor and product,
                       and SIX distinct non-root paths in the whole corpus. The
                       source document rates it the primary source of active
                       probe paths; against today's upstream that is not true.
    Wappalyzer         no probe paths at all. Its `url` field is a regex
                       against the URL a browser is already on, not a path to
                       fetch.
    Recog              none by design; it parses banners, it does not knock.

**The list is deliberately generous.** An earlier version published only paths
whose product this catalogue already had a rule for - 51 paths - and that was
the wrong test twice over.

The first reason is what the sweep actually matches. It runs all 722 rules over
every response, and a response carries `Server`, `X-Powered-By`, `Set-Cookie`,
a title and a body whoever the path belongs to. Knocking on
`/mifs/user/login.jsp` on a host that runs no MobileIron still gets an answer,
and that answer is where the header rules find nginx, PHP, IIS or the reverse
proxy in front of them. The point of a broad list is that SOMETHING answers.

The second reason is that the paths are nearly free. Measured against a live
server on loopback, one nmap run each:

    51 paths     58 requests    6.15 s
    125 paths   132 requests    6.15 s
    400 paths   407 requests    6.20 s
    948 paths   955 requests    6.30 s

`-sV` alone is 6.11 s of that. The sweep is pipelined over a handful of
connections, so the marginal path costs about 0.2 ms; the whole difference
between the tightest list and the broadest is 150 ms on a scan that spends six
seconds in nmap's own version probe. There was nothing to save.

What is still filtered is what cannot work rather than what might not: a path
that can only answer with an image or a font, one that carries a traversal, a
backslash or a percent escape, a nuclei interpolation, an ALL_CAPS placeholder
the operator was supposed to fill in, and an absolute URL naming somebody
else's host.
"""

import glob
import os
import re

try:
    import yaml
except ImportError:  # pragma: no cover - reported by the caller
    yaml = None


# What "/" plus redirect-following does not cover: a server that answers 404
# for "/" without redirecting, and serves its front page under a name. Seven,
# not the 121 the 1.x list spent on it - the sweep follows redirects that stay
# on the host, so the ordinary "front page lives elsewhere" case is already
# handled by fetching "/" and going where it points.
#
# /robots.txt earns its place differently: it is one request on any server, and
# its body names the directories the software keeps - which is text the body
# rules read like any other.
ALWAYS = (
    "/",
    "/index.html",
    "/index.htm",
    "/index.php",
    "/index.asp",
    "/index.aspx",
    "/index.jsp",
    "/index.cgi",
    "/robots.txt",
)

# Fetching these buys nothing. The sweep matches text: the rules read headers,
# titles, meta tags, script sources and the decoded body, so a path that can
# only ever answer with an image, a font or an archive is a request spent on
# bytes no rule can read. WhatWeb wants some of them for their md5, which is a
# channel this script does not have.
UNREADABLE = (
    ".ico", ".gif", ".png", ".jpg", ".jpeg", ".bmp", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".tar",
    ".exe", ".dll", ".so", ".dmg", ".pkg", ".msi", ".jar", ".class",
    ".swf", ".pdf", ".mp3", ".mp4", ".avi", ".mov", ".wav",
)

# A path this script would refuse to put on the wire, or should refuse to.
#
#   ..                traversal
#   \ { } < > | ^ " `   never legal in a request line; a server answers 400
#   *                 legal in a URI and always a placeholder in this corpus:
#                     /?map=* is what the operator was meant to fill in
#   %                 in this corpus never a real escape - it is /%c0, /%3f and
#                     /actuator%72, three attempts to confuse a normaliser
#   whitespace        would end the request line early
REFUSED = re.compile(r"\.\.|[{}<>|^\"`\\*%\s\x00-\x1f]")

# "/:9182" and "/:9091/healthz" are a host:port fragment somebody pasted into a
# path field, not a path.
PORT_FRAGMENT = re.compile(r"^/:")

# A path made only of punctuation - "/&?=?" - is not a path either. Checked
# over the whole string rather than the part before "?", because PHP's own
# easter egg is "/?=PHPB8B5F2A0-..." and everything it says is in the query.
# "/" itself is a path, and is handled before this is reached.
HAS_SUBSTANCE = re.compile(r"[A-Za-z0-9]")

# Nuclei and WhatWeb leave the operator's own value in the example: an
# ALL_CAPS_TOKEN in a query is a placeholder like FIREBASE_SECRET, not
# something to send.
PLACEHOLDER = re.compile(r"[A-Z][A-Z0-9]*_[A-Z0-9_]{2,}")

# Long enough for the deepest real fingerprinting path measured (78
# characters), short enough that a corrupt entry cannot become a request line
# of its own.
MAX_PATH = 128

# Paths every scan already makes, or that say nothing about the software.
GENERIC = {"", "/favicon.ico", "/sitemap.xml"} | set(ALWAYS)

# The list this repository swept before the upstreams were read: eleven names a
# front page might have, crossed with eleven extensions it might carry. As a
# fingerprinting list it finds nothing on its own - every one of them answers
# with the same front page "/" already returned - but as a way of getting SOME
# answer out of a server that refuses "/", eleven names is eleven chances, and
# they cost nothing next to the upstream paths. Kept, and kept generated, so it
# is obvious what they are.
FRONT_STEMS = ("index", "default", "home", "main", "start", "admin",
               "base", "menu", "inicio", "indice", "localstart")
FRONT_EXTENSIONS = ("html", "htm", "php", "asp", "aspx", "jsp", "jhtml",
                    "jsa", "cgi", "pl", "shtml", "cfm")


def front_pages():
    """Every plausible name for a front page, in a stable order."""
    return ["/%s.%s" % (stem, extension)
            for stem in FRONT_STEMS for extension in FRONT_EXTENSIONS]


# A ceiling, not a policy. The script refuses a catalogue with more than 2 000
# paths, so this stops a broken upstream from producing a list it would reject
# outright rather than expressing an opinion about how many is too many.
MAX_PATHS = 1500


def normalise(raw):
    """A path this script could request, or None."""
    text = str(raw or "").strip()
    if not text:
        return None

    # nuclei writes the path as an interpolation of the base URL; WhatWeb
    # writes some of its paths without the leading slash.
    text = text.replace("{{BaseURL}}", "")
    if text.startswith("http://") or text.startswith("https://"):
        # An absolute URL names somebody else's host. It is not a path this
        # sweep can request of the target.
        return None
    if not text.startswith("/"):
        text = "/" + text

    if (len(text) > MAX_PATH or REFUSED.search(text)
            or PLACEHOLDER.search(text)):
        return None
    if PORT_FRAGMENT.match(text) or not HAS_SUBSTANCE.search(text):
        return None

    if text.split("?", 1)[0].lower().endswith(UNREADABLE):
        return None

    return text


class Candidates:
    """Paths, with who named them and which catalogue said so."""

    def __init__(self):
        self.by_path = {}

    def add(self, raw, product, source):
        path = normalise(raw)
        if path is None or path in GENERIC:
            return False
        entry = self.by_path.setdefault(
            path, {"path": path, "products": set(), "sources": set()})
        if product:
            entry["products"].add(str(product).strip().lower())
        entry["sources"].add(source)
        return True

    def ranked(self):
        """Most corroborated first, then most sources, then stable by name.

        Corroboration is the only quality signal available without fetching
        anything: a path several distinct products are recognised at, or that
        two independent catalogues both record, is likelier to be worth a
        request than one plugin's guess about one appliance.
        """
        return sorted(self.by_path.values(),
                      key=lambda e: (-len(e["products"]), -len(e["sources"]),
                                     e["path"]))


# ------------------------------------------------------------------- WhatWeb

# `matches [ {:url=>"/wp-login.php", ...} ]`. Ruby, so it is read with a regex
# rather than parsed: the `passive do ... end` bodies are arbitrary code and
# out of reach, but the `matches` array is declarative and its :url entries are
# exactly the paths WhatWeb fetches in aggressive mode.
WW_NAME = re.compile(r'^\s*name\s+"([^"]+)"', re.M)
WW_URL = re.compile(r':url\s*=>\s*["\']([^"\']+)["\']')


def _whatweb(root, out, report):
    directory = os.path.join(root, "plugins")
    if not os.path.isdir(directory):
        return 0

    files = 0
    for filename in sorted(glob.glob(os.path.join(directory, "*.rb"))):
        try:
            with open(filename, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        files += 1
        name = WW_NAME.search(text)
        product = name.group(1) if name else os.path.basename(filename)[:-3]
        for match in WW_URL.finditer(text):
            if not out.add(match.group(1), product, "whatweb"):
                report["paths_refused"]["whatweb"] += 1
    return files


# -------------------------------------------------------------------- nuclei

def _nuclei(root, out, report):
    if yaml is None:
        return 0
    pattern = os.path.join(root, "http", "technologies", "**", "*.yaml")
    files = 0
    for filename in sorted(glob.glob(pattern, recursive=True)):
        document = _yaml(filename)
        if document is None:
            continue
        files += 1
        product = document.get("id") or os.path.basename(filename)[:-5]
        requests = document.get("http") or document.get("requests") or []
        for request in requests:
            if str(request.get("method", "GET")).upper() != "GET":
                continue
            for raw in (request.get("path") or []):
                if not out.add(raw, product, "nuclei"):
                    report["paths_refused"]["nuclei"] += 1
    return files


# ------------------------------------------------------------ FingerprintHub

def _fingerprinthub(root, out, report):
    if yaml is None:
        return 0
    pattern = os.path.join(root, "web-fingerprint", "**", "*.yaml")
    files = 0
    for filename in sorted(glob.glob(pattern, recursive=True)):
        document = _yaml(filename)
        if document is None:
            continue
        files += 1
        metadata = ((document.get("info") or {}).get("metadata") or {})
        label = ("%s %s" % (metadata.get("vendor") or "",
                            metadata.get("product")
                            or document.get("id") or "")).strip()
        requests = document.get("http") or document.get("requests") or []
        for request in requests:
            if str(request.get("method", "GET")).upper() != "GET":
                continue
            for raw in (request.get("path") or []):
                if not out.add(raw, label, "fingerprinthub"):
                    report["paths_refused"]["fingerprinthub"] += 1
    return files


def _yaml(filename):
    try:
        with open(filename, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except Exception:
        return None
    return document if isinstance(document, dict) else None


READERS = (
    ("whatweb", "WhatWeb", _whatweb),
    ("nuclei", "nuclei-templates", _nuclei),
    ("fingerprinthub", "FingerprintHub", _fingerprinthub),
)


def load(sources_dir, report):
    """Every path an upstream associates with a product.

    @return the Candidates, and how many source trees were actually read
    """
    out = Candidates()
    read = 0
    for key, directory, reader in READERS:
        root = os.path.join(sources_dir, directory)
        if not os.path.isdir(root):
            continue
        files = reader(root, out, report)
        if files:
            read += 1
            report["paths_read"][key] = files
    return out, read


def tokens_of(product):
    """The names a product might be joined by."""
    base = str(product).lower().strip()
    tokens = {base}
    for suffix in ("-detect", "-detection", "-version", "-panel", "-eol",
                   " detect", " detection"):
        if base.endswith(suffix):
            tokens.add(base[: -len(suffix)])
    for token in list(tokens):
        tokens.add(token.replace("-", ""))
        tokens.add(token.replace(" ", ""))
        tokens.add(token.replace("_", ""))
        first = re.split(r"[\s\-_]+", token)[0]
        if len(first) > 3:
            tokens.add(first)
    return {t for t in tokens if t}


def select(candidates, alias_for, report, exclude=()):
    """The published list, in the order the sweep will request it.

    @param alias_for callable taking a set of product tokens and returning the
           CPE alias this catalogue would report, or None. Not a filter -
           a path
           for software we cannot name still gets an answer whose headers
           we can
           read - only a count, so the build log can say how much of the list
           this catalogue could put a name to.
    @param exclude paths a targeted probe already owns. A probe goes out only
           when its detector fired and no version is known, so it costs nothing
           on a host that is not running that product - where sweeping the same
           path costs a request on every web port and reads less, because the
           probe's version extractor is not one of the passive rules.
    """
    chosen, seen = [], set(exclude)
    named = {}

    def take(path):
        if path in seen:
            return False
        seen.add(path)
        chosen.append(path)
        return True

    # The order is load-bearing: the script requests a prefix of this list,
    # bounded by nmap's -T, so the most useful paths have to come first.
    #
    #   1. what every scan asks anyway
    #   2. the product paths, most corroborated first - the informative half
    #   3. the front-page names, last, because they are a guess at where a page
    #      lives rather than a statement about what software is there. They
    #      earn their place only on a server that refuses "/", which is why
    #      they must
    #      not push a real fingerprinting path out of a small budget.
    for path in ALWAYS:
        take(path)

    for entry in candidates.ranked():
        if len(chosen) >= MAX_PATHS:
            report["paths_dropped"]["over the %d ceiling" % MAX_PATHS] += 1
            continue
        if not take(entry["path"]):
            report["paths_dropped"]["a probe already goes there"] += 1
            continue
        for product in sorted(entry["products"]):
            alias = alias_for(tokens_of(product))
            if alias:
                named.setdefault(alias, []).append(entry["path"])
                break

    for path in front_pages():
        if len(chosen) >= MAX_PATHS:
            break
        take(path)

    report["paths_kept"]["identities named"] = len(named)
    return chosen, named
