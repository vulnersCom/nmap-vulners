"""Read Rapid7 Recog into normalised rules.

Recog is the only source in the catalogue that ships an oracle: every
fingerprint carries `<example>` elements, and an example may state the values
it is expected to yield. That turns "did the translation preserve the meaning"
from a judgement into a measurement, so nothing here is imported on the
strength of the pattern looking right.

Its second gift is `matches=` on the file element, which names the field the
pattern is written against - `http_header.server`, `ssh.banner`, `html_title`.
The old script matched every pattern against every byte of every response; a
rule that says which field it reads can be run against that field alone, which
is both faster and unable to produce the cross-header false positives an
unanchored pattern invites.
"""

import base64
import os
import xml.etree.ElementTree as ET

# The channel each recog file feeds. A file whose matches= is absent or names
# something this script cannot obtain is skipped rather than guessed at: a rule
# run against the wrong field is a false positive with a version number on it,
# which is worse than no rule.
CHANNELS = {
    "http_header.server": "server",
    "http_header.x-powered-by": "powered-by",
    "http_header.x-fortisandbox-version": "header",
    "http_header.cookie": "cookie",
    "http_header.wwwauth": "wwwauth",
    "html_title": "title",
    "favicon.md5": "favicon",

    # Read out of nmap's own service fingerprint, so they cost no request.
    "ftp.banner": "banner",
    "imap4.banner": "banner",
    "pop3.banner": "banner",
    "smtp.banner": "banner",
    "nntp.banner": "banner",
    "ssh.banner": "banner",
    "mysql.banners": "banner",
    "telnet.banner": "banner",
    "sip_header.server": "banner",
    "sip_header.user_agent": "banner",
    "rtsp_header.server": "banner",
    "dns.versionbind": "banner",
    "ntp.readvar": "banner",
    "ldap.search_result": "banner",
    "smb.native_lm": "banner",
    "smb.native_os": "banner",
    "x11.vendor": "banner",
}

# Files with no matches= attribute but a well-understood subject.
BY_FILENAME = {
    "telnet_banners.xml": "banner",
}


def _decode(element):
    """An example's subject, honouring recog's base64 escape hatch."""
    text = element.text or ""
    if element.get("_encoding") == "base64":
        try:
            return base64.b64decode(text).decode("latin-1")
        except Exception:
            return None
    return text


def load(root_dir):
    """Every recog fingerprint this project can use, as dicts.

    Each rule carries the raw PCRE, the group holding the version, the CPE
    template, and the examples - translation and verification happen later, so
    that this file stays a reader and the decisions stay in one place.
    """
    rules = []
    xml_dir = os.path.join(root_dir, "xml")
    for name in sorted(os.listdir(xml_dir)):
        if not name.endswith(".xml"):
            continue
        path = os.path.join(xml_dir, name)
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            continue

        matches = root.get("matches", "")
        channel = CHANNELS.get(matches) or BY_FILENAME.get(name)
        if channel is None:
            continue

        for index, node in enumerate(root.findall("fingerprint")):
            pattern = node.get("pattern")
            if not pattern:
                continue

            params = {}
            positions = {}
            for param in node.findall("param"):
                pname = param.get("name", "")
                pos = int(param.get("pos", "0") or 0)
                value = param.get("value")
                if pos == 0 and value is not None:
                    params[pname] = value
                elif pos > 0:
                    positions[pname] = pos

            cpe = params.get("service.cpe23") or params.get("os.cpe23")
            version_group = (positions.get("service.version")
                             or positions.get("os.version"))

            examples = []
            for example in node.findall("example"):
                subject = _decode(example)
                if subject is None or subject == "":
                    continue
                expected = (example.get("service.version")
                            or example.get("os.version"))
                examples.append({"subject": subject, "version": expected})

            flags = node.get("flags", "")
            rules.append({
                "source": "recog",
                "upstream": "%s#%d" % (name, index),
                "channel": channel,
                "pattern": pattern,
                "ignore_case": "REG_ICASE" in flags,
                "dot_newline": "REG_DOT_NEWLINE" in flags,
                "multiline": "REG_MULTILINE" in flags,
                "version_group": version_group,
                "cpe_template": cpe,
                "vendor": (params.get("service.vendor")
                           or params.get("os.vendor")),
                "product": (params.get("service.product")
                            or params.get("os.product")),
                "description": node.findtext("description", "").strip(),
                "examples": examples,
                # A recog pattern is written against one field's whole value,
                # so the field is the subject and ^ means the start of it.
                "field_scoped": True,
            })
    return rules
