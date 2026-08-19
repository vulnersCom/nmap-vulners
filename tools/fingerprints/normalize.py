"""Turn each source's idea of a product identity into the one CPE this asks for.

The endpoint this script queries is addressed by a CPE 2.2 URI - `cpe:/a:f5:nginx`
plus a version - and takes it verbatim, so the alias a rule carries is not a
label. It is the request. A plausible-looking alias that the service does not
recognise produces silence, and silence from a vulnerability scanner reads as
"nothing wrong here".

That is why nothing in this file guesses. It converts the spellings the sources
use into the one this script needs, applies the corrections the repository has
already measured against the live service, and leaves the question of whether an
identity is *answerable* to `validate.py`, which asks the service itself.
"""

import re

CPE23 = re.compile(r"^cpe:2\.3:([aoh]):([^:]*):([^:]*)")
CPE22 = re.compile(r"^cpe:/([aoh]):([^:]*):([^:]*)")

# CPE components are percent-escaped in the 2.3 binding and backslash-escaped in
# its formatted-string form. Both spellings have to come back to the plain text
# the 2.2 URI carries, or the alias names a product that does not exist.
UNESCAPE = re.compile(r"\\(.)")


def _component(text):
    text = UNESCAPE.sub(r"\1", text or "")
    if text in ("*", "-", ""):
        return None
    return text.lower()


def alias_of(template):
    """`cpe:/a:vendor:product` for any CPE spelling the sources use, or None.

    Recog writes `cpe:/a:apache:tomcat:{service.version}`, Wappalyzer writes the
    2.3 form padded with wildcards. Both mean the same identity, and the version
    they carry is either a placeholder or a wildcard - never a real version, so
    it is dropped rather than trusted.
    """
    if not template:
        return None
    text = template.strip()

    match = CPE23.match(text)
    if not match:
        match = CPE22.match(text)
    if not match:
        return None

    part, vendor, product = match.group(1), _component(match.group(2)), _component(match.group(3))
    if not vendor or not product:
        return None
    if "{" in vendor or "{" in product:
        # An unfilled recog template in the vendor or product position means the
        # identity itself depends on the match, which this importer cannot know.
        return None
    return "cpe:/%s:%s:%s" % (part, vendor, product)


# Identities the repository has already measured against the live service, and
# the spelling that actually answers. Recorded with the counts that decided it,
# because the catalogue and the service disagree and only the service pays.
#
#   microsoft:internet_information_server  107 advisories, 0 bulletins
#   microsoft:internet_information_services 91 advisories, 11 bulletins
#   f5:nginx 124 bulletins / nginx:nginx 4 / igor_sysoev:nginx 0
#   h2o_project:h2o 0 bulletins / h2o:h2o 24
#
# Measured 2026-08-18; see dev_docs/decisions.md. Anything added here needs the
# same measurement next to it, not an opinion.
CORRECTIONS = {
    "cpe:/a:microsoft:internet_information_server": "cpe:/a:microsoft:internet_information_services",
    "cpe:/a:igor_sysoev:nginx": "cpe:/a:f5:nginx",
    "cpe:/a:nginx:nginx": "cpe:/a:f5:nginx",
    "cpe:/a:h2o_project:h2o": "cpe:/a:h2o:h2o",

    # Added 2026-08-18, each from a CONTROLLED comparison - both spellings asked
    # about the same versions, because asking each about its own tells you
    # nothing. `cpe:/o:sun:solaris` looked dead by that weaker test and is not:
    # it returns 285 at version 10, and its zero came from being asked about a
    # version string scraped out of a banner.
    #
    #   oracle:sunos           5.10 -> 0    5.11 -> 0
    #   sun:sunos              5.10 -> 95   5.11 -> 159
    "cpe:/o:oracle:sunos": "cpe:/o:sun:sunos",
    #
    #   elasticsearch:kibana   6.4.2 -> 26  7.10.0 -> 2
    #   elastic:kibana         6.4.2 -> 52  7.10.0 -> 60
    # Both answer, so this is not a silent-failure fix; it is the identity that
    # answers better across the range, which is what the rule asks for.
    "cpe:/a:elasticsearch:kibana": "cpe:/a:elastic:kibana",
}

# Spellings deliberately NOT merged, so the question is not re-opened:
#
#   mortbay:jetty vs eclipse:jetty - eclipse answers at both versions tried
#   (36, 38) and mortbay only at the old one (10 at 6.1.26, 0 at 9.4.51). They
#   are not competing spellings of one identity: a Jetty 6 install really is
#   the mortbay product, so both rules stay and each names its own era.
#
#   acme:thttpd vs acme_labs:thttpd - 4/2 against 3/4 over the same versions.
#   Neither dominates, and nothing is gained by picking.
#
#   apache / ibm / oracle :http_server - three different servers that share a
#   product name, not three spellings of one.


def corrected(alias):
    return CORRECTIONS.get(alias, alias)


# A version string that is not a version. Recog and Wappalyzer both have
# patterns whose capture can come back as a word - "unknown", "development" -
# and appending one to a CPE asks the service about a product release that never
# existed, which is a lookup spent to learn nothing.
PLAUSIBLE_VERSION = re.compile(r"^\d+(\.\d+)*[A-Za-z0-9._+-]*$")


def plausible(version):
    return bool(version) and bool(PLAUSIBLE_VERSION.match(version)) and len(version) <= 64


# The runtime key a rule is filed under - the part of a response the matcher
# will run it against. It is computed here, once, and written into the
# catalogue: the script that reads the catalogue should not have to know that
# "server" and "hdr:server" are the same thing, and the two spellings drifting
# apart is exactly the kind of silent mismatch that leaves a rule unreachable.
FIXED_CHANNELS = {"raw", "body", "title", "script", "banner", "cookie"}
CHANNEL_ALIASES = {
    "server": "hdr:server",
    "powered-by": "hdr:x-powered-by",
    "wwwauth": "hdr:www-authenticate",
    "headers-raw": "raw",
}

CHANNEL_KEY = re.compile(r"^(?:raw|body|title|script|banner|cookie"
                         r"|hdr:[\w.-]+|meta:[\w.:-]+)$")


def channel_key(channel, field=None):
    """The runtime key, or None when nothing would ever look the rule up."""
    field = (field or "").lower()

    key = CHANNEL_ALIASES.get(channel)
    if key is None:
        if channel == "header":
            key = "hdr:" + field if field else "raw"
        elif channel == "meta":
            key = "meta:" + field if field else "body"
        elif channel in FIXED_CHANNELS:
            key = channel
        else:
            return None
    return key if CHANNEL_KEY.match(key) else None
