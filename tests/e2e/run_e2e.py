#!/usr/bin/env python3
"""End-to-end checks: run the real nmap against local servers.

The unit suite (tests/run.nse) exercises the scripts through their action()
function with a fake http library. This file closes the remaining gap: that
nmap itself loads the scripts, that the port rules fire, that requests leave
the process in the expected shape, and that the output reaches the report -
both the human one and the XML one.

Three servers are started on loopback:
  * a target web server answering with recognisable version banners
  * a stand-in Vulners API answering the v4 audit, v3 id and v3 burp endpoints
  * nothing else; no traffic ever leaves the machine

Usage:
    python3 tests/e2e/run_e2e.py            # offline, the default
    python3 tests/e2e/run_e2e.py --live     # also checks the real API

The --live mode needs VULNERS_API_KEY in the environment and talks to
vulners.com. It verifies that the response shapes the offline doubles imitate
are still what the service actually sends.
"""

import argparse
import concurrent.futures
import gzip
import http.server
import json
import os
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import xml_contract  # noqa: E402  (needs the path above)

REPO = Path(__file__).resolve().parents[2]
FAKE_KEY = "FAKE-TEST-KEY-NOT-A-REAL-TOKEN"

# Banners the rules in catalog/fingerprints.json recognise.
TARGET_HEADERS = {
    "Server": "nginx/1.13.4",
    "X-Powered-By": "PHP/5.6.38",
}

# What POST /api/v4/audit/software/ accepts in "fields"; anything else makes it
# answer 422 and return nothing at all. Taken from the service's own error
# message on 2026-08-18.
AUDIT_FIELDS = {
    "aiDescription", "title", "short_description", "type", "bulletinFamily",
    "published", "modified", "lastseen", "href", "metrics", "exploitation",
    "cvelist", "ai_score", "epss", "description", "enchantments",
    "webApplicability", "cvelistMetrics", "reporter", "references",
    "cvss2", "cvss3", "cvss4", "exploits",
}

# What POST /api/v3/search/id/ accepts in "fields". Verified against the live
# endpoint on 2026-08-18: it answers 200 to exactly this list, and its documents
# carry every one of them.
SEARCH_ID_FIELDS = {
    "id", "type", "bulletinFamily", "title", "href", "published", "cvss",
    "epss", "cvelist", "metrics", "enchantments", "ai_score", "modified",
    "lastseen", "description", "references", "cvss2", "cvss3", "cvss4",
}

CANNED_VULN_ID = "CVE-2018-16843"
CANNED_CVSS = 7.5
CANNED_EXPLOIT_ID = "EDB-ID:45233"
LOW_VULN_ID = "CVE-2019-20372"
LOW_CVSS = 4.3


def script(name):
    """Absolute path of a script in the checkout.

    nmap resolves a relative --script argument against script.db first, so
    './vulners.nse' silently runs the copy installed with nmap rather than the
    one being developed. An absolute path always wins.
    """
    return str(REPO / name)


def free_port() -> int:
    """Ask the OS for a port that is currently free."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def claim_port(preferred: int):
    """Return the preferred port if it is free, otherwise None.

    shortport.http only recognises a service without -sV on well known HTTP
    ports, so the "runs without -sV" check needs one of them.

    SO_REUSEADDR because the previous run of this file listened on the same
    port: its connections sit in TIME_WAIT for a minute afterwards, and a plain
    bind refuses while they do. Without it the check skipped itself whenever it
    was run twice in a row - which is exactly when it was being worked on.
    """
    try:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", preferred))
    except OSError:
        return None
    return preferred


class Recorder:
    """Everything one server saw.

    Per server, not per handler class, which is what lets the checks run at the
    same time: each check gets its own target and its own API, so a counter can
    only ever hold that check's traffic. While these lived on the classes the
    checks had to run one at a time, and the file spent 93 seconds doing 16 nmap
    runs that have no reason to wait for each other.

    Locked because ThreadingHTTPServer answers each connection in its own
    thread, and nmap opens several: `count += 1` is a load, an add and a store,
    and the sweep makes a hundred-odd requests over a handful of connections.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.connections = 0
        self.compressed_replies = 0
        self.seen_api_keys = []
        self.seen_user_agents = []
        self.burp_api_keys = []      # the X-Api-Key header seen on burp
        self.burp_queries = []       # query dicts of the free endpoint
        self.requests_by_path = {}   # every endpoint hit, with its count
        self.reject_keys = False     # answer 401 to any authenticated request

    def bump(self, name, by=1):
        with self.lock:
            setattr(self, name, getattr(self, name) + by)

    def note(self, name, value):
        with self.lock:
            getattr(self, name).append(value)

    def hit(self, endpoint):
        with self.lock:
            self.requests_by_path[endpoint] = \
                self.requests_by_path.get(endpoint, 0) + 1


class Recording(http.server.BaseHTTPRequestHandler):
    """Base for the handlers: reaches the Recorder its server was given."""

    protocol_version = "HTTP/1.1"

    @property
    def state(self):
        return self.server.state

    def log_message(self, *args):
        pass


class TargetHandler(Recording):
    """A web server that looks like an outdated nginx with PHP."""

    def setup(self):
        self.state.bump("connections")
        super().setup()

    def do_GET(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        self.state.bump("requests")
        body = b"<html><body>nmap-vulners e2e target</body></html>"
        self.send_response(200)
        for name, value in TARGET_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/html")

        # Real servers compress when asked, so the fingerprinting has to work
        # on a body nmap decompressed rather than on the bytes off the wire.
        if "gzip" in (self.headers.get("Accept-Encoding") or ""):
            body = gzip.compress(body)
            self.send_header("Content-Encoding", "gzip")
            self.state.bump("compressed_replies")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ApacheTargetHandler(Recording):
    """A web server nmap fingerprints as cpe:/a:apache:http_server:2.4.7.

    The live checks need a CPE the real API actually answers: the nginx CPEs
    the main target yields answer with far less than an Apache one, and the
    check would be asserting on a nearly empty result.
    """

    def do_GET(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        body = b"<html><body>nmap-vulners live target</body></html>"
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.7 (Ubuntu)")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BannerTarget(socketserver.BaseRequestHandler):
    """A TCP service that greets, and that nmap cannot name.

    Not HTTP, and deliberately nothing nmap's own probe database recognises: the
    banner channel exists for exactly this port. nmap records a service
    fingerprint when its probes did NOT settle the service, and the shipped
    catalogue carries a recog rule that reads this greeting.
    """

    greeting = b"welcome\r\nPowerDNS Authoritative Server 4.5.2-1\r\n"

    def handle(self):
        # Greet and hang up. A listener that holds the connection open makes
        # nmap wait out every one of its two dozen probes: measured at 93.2 s
        # for this one port against 0.1 s here, with the same fingerprint
        # recorded either way. Plenty of real banner services close on a
        # command they do not understand.
        try:
            self.request.sendall(self.greeting)
        except OSError:
            pass


class QuietTCPServer(socketserver.ThreadingTCPServer):
    """The raw-socket twin of QuietHTTPServer; same reason, same silence."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def serve_tcp(handler):
    """Start a raw TCP listener in a daemon thread; return its port."""
    for attempt in range(5):
        try:
            server = QuietTCPServer(("127.0.0.1", free_port()), handler)
        except OSError:
            if attempt == 4:
                raise
            continue
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_address[1]
    raise AssertionError("unreachable")


class CatalogHandler(Recording):
    """Serve catalog/ over loopback.

    The script downloads its dictionaries at scan time. Left alone it would
    fetch them from raw.githubusercontent.com, which would make this file's
    whole premise - that nothing here touches the network - false, and would
    make every check depend on GitHub being up and on whatever is published
    there rather than on what is in this working tree.

    Serving the working tree is also the stronger check: it is the catalogue
    about to be committed that gets exercised, not last week's.
    """

    def do_GET(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        name = self.path.lstrip("/").split("?")[0]
        target = REPO / "catalog" / name

        # Only inside catalog/, and only files it actually holds. The script
        # takes the file name from the index, so a real deployment can name a
        # file; it must not be able to name a path.
        if "/" in name or ".." in name or not target.exists():
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = target.read_bytes()
        self.state.bump("requests")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def audit_vulnerabilities():
    """Two vulnerabilities as the v4 audit returns them, one with an exploit."""
    return [
        {
            "id": CANNED_VULN_ID,
            "type": "cve",
            "metrics": {"cvss": {"score": CANNED_CVSS, "version": "3.1",
                                 "severity": "HIGH"}},
            "enchantments": {"dependencies": {"references": [
                {"type": "exploitdb", "idList": [CANNED_EXPLOIT_ID]},
                {"type": "alpinelinux", "idList": ["ALPINE:CVE-2018-16843"]},
            ]}},
        },
        {
            "id": LOW_VULN_ID,
            "type": "cve",
            "metrics": {"cvss": {"score": LOW_CVSS, "version": "3.1",
                                 "severity": "MEDIUM"}},
            "enchantments": {"dependencies": {"references": []}},
        },
    ]


def enriched_document(vuln_id):
    """One document in the shape /api/v3/search/id/ really answers with.

    Modelled on a live answer captured on 2026-08-18. The exploit entry
    deliberately carries both bulletinFamily "exploit" and a cvelist naming the
    CVE, plus metrics.adp.kev - because on the real service the KEV container
    does ride on exploit records, and a double that put it only on CVEs would
    hide the attribution the ranking depends on.
    """
    exploit = vuln_id == CANNED_EXPLOIT_ID
    kev = vuln_id in (CANNED_EXPLOIT_ID, CANNED_VULN_ID)
    score = LOW_CVSS if vuln_id == LOW_VULN_ID else CANNED_CVSS

    document = {
        "id": vuln_id,
        "type": "exploitdb" if exploit else "cve",
        "bulletinFamily": "exploit" if exploit else "NVD",
        "title": ("nginx 1.13.4 - Remote Code Execution" if exploit
                  else f"{vuln_id} in nginx"),
        "href": (f"https://www.exploit-db.com/exploits/{vuln_id}" if exploit
                 else f"https://web.nvd.nist.gov/view/vuln/detail?vulnId={vuln_id}"),
        "published": "2018-11-07T00:00:00",
        "cvss": {"score": score, "version": "3.1", "severity": "HIGH"},
        "epss": [{"cve": CANNED_VULN_ID, "epss": 0.97321,
                  "percentile": 0.99854, "date": "2026-08-18"}],
        "cvelist": [CANNED_VULN_ID] if exploit else [vuln_id],
        "metrics": {"adp": {}},
    }
    if kev:
        document["metrics"]["adp"] = {
            "kev": {"dateAdded": "2021-11-03",
                    "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
            "ssvc": {"role": "CISA Coordinator",
                     "options": [{"Exploitation": "active"},
                                 {"Automatable": "yes"},
                                 {"Technical Impact": "total"}]},
        }
    return document


class ApiHandler(Recording):
    """A stand-in for the Vulners API, both the v4 and the v3 endpoints."""

    def _count(self):
        self.state.hit(self.path.split("?", 1)[0])

    def _reply(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")

        # The real API compresses when asked, and the answers are large enough
        # that the scripts ask. Doing the same here keeps the decompression
        # path - nmap's, not ours - inside the tested ground.
        if "gzip" in (self.headers.get("Accept-Encoding") or ""):
            body = gzip.compress(body)
            self.send_header("Content-Encoding", "gzip")
            self.state.bump("compressed_replies")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject_key(self):
        """Answer the way the service answers an unusable key."""
        body = json.dumps({"result": "error",
                           "data": {"error": "Unknown api key",
                                    "errorCode": 157}}).encode()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - the free script uses GET
        self._count()
        parsed = urllib.parse.urlparse(self.path)
        self.state.note("seen_user_agents", self.headers.get("User-Agent"))

        if not parsed.path.startswith("/api/v3/burp/software/"):
            self.send_error(404)
            return

        # Recorded rather than asserted here: the free endpoint is CDN-cached
        # only for requests that carry no key, so a client that sends one takes
        # its whole population off the shared cache.
        self.state.note("burp_api_keys", self.headers.get("X-Api-Key"))

        # The live endpoint sits behind a rule that answers 403 to a keyless
        # request whose User-Agent does not name this plugin. A double that
        # accepted anything is how two defects reached a release.
        user_agent = self.headers.get("User-Agent") or ""
        if "Vulners NMAP Plugin" not in user_agent:
            self.send_error(403, "Forbidden")
            return

        # The real endpoint does not percent-decode its arguments: an escaped
        # CPE (cpe%3A%2Fa%3A...) comes back as errorCode 303 for every plugin
        # version, so a client that escapes the value gets nothing at all.
        # parse_qsl would decode it and hide exactly that, so the raw query
        # string is what this double looks at.
        query = dict(part.split("=", 1)
                     for part in parsed.query.split("&") if "=" in part)
        self.state.note("burp_queries", query)

        if "%" in query.get("software", ""):
            self._reply({"result": "error",
                         "data": {"error": "Unsupported nmap plugin version.",
                                  "errorCode": 303}})
            return

        # The free endpoint answers with the v3 search envelope.
        self._reply({
            "result": "OK",
            "data": {"search": [
                {"_source": {"id": CANNED_VULN_ID, "type": "cve",
                             "bulletinFamily": "NVD",
                             "cvss": {"score": CANNED_CVSS, "version": "3.1"}}},
                {"_source": {"id": CANNED_EXPLOIT_ID, "type": "exploitdb",
                             "bulletinFamily": "exploit",
                             "cvss": {"score": 0, "version": "2.0"}}},
                {"_source": {"id": LOW_VULN_ID, "type": "cve",
                             "bulletinFamily": "NVD",
                             "cvss": {"score": LOW_CVSS, "version": "3.1"}}},
            ]},
        })

    def _reject_unknown_fields(self, payload, allowed):
        """Answer 422 for a field the real service does not accept."""
        unknown = [f for f in (payload.get("fields") or [])
                   if f not in allowed]
        if not unknown:
            return False

        body = json.dumps({"errors": [{
            "type": "literal_error",
            "loc": ["body", "input_dto", "fields", 0],
            "msg": f"Input should be one of the documented fields, not {unknown[0]!r}",
        }]}).encode()
        self.send_response(422)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_POST(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        self._count()
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        self.state.note("seen_api_keys", self.headers.get("X-Api-Key"))
        self.state.note("seen_user_agents", self.headers.get("User-Agent"))

        if self.state.reject_keys:
            self._reject_key()
            return

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}

        # The whitelist belongs to the v4 audit endpoints only. Applying it to
        # /api/v3/search/id/ as well used to reject "id" and "cvss", which the
        # live v3 endpoint accepts - verified against vulners.com on 2026-08-18.
        if self.path.startswith("/api/v4/audit/"):
            if self._reject_unknown_fields(body, AUDIT_FIELDS):
                return
        elif self.path.startswith("/api/v3/search/id/"):
            if self._reject_unknown_fields(body, SEARCH_ID_FIELDS):
                return

        if self.path.startswith("/api/v4/audit/software/"):
            software = body.get("software", [])
            # The live API does not answer in request order; neither do we.
            self._reply({"result": [
                {"input": item,
                 "matched_criteria": "cpe:2.3:a",
                 "vulnerabilities": audit_vulnerabilities()}
                for item in reversed(software)
            ]})
            return

        if self.path.startswith("/api/v4/audit/smart"):
            self._reply({"result": [
                {"input": item, "cpe": None, "confidence": 50,
                 "vulnerabilities": [{"id": CANNED_VULN_ID, "type": "cve"}]}
                for item in body.get("software", [])
            ]})
            return

        if self.path.startswith("/api/v3/search/id/"):
            documents = {vuln_id: enriched_document(vuln_id)
                         for vuln_id in body.get("id", [])}
            self._reply({"result": "OK", "data": {"documents": documents}})
            return

        self.send_error(404)


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    """A server that does not narrate its own disconnections.

    nmap resets a pipelined connection as soon as it has what it wants, and
    socketserver answers each reset with a full traceback on stderr. Measured:
    37 KB and 29 tracebacks per clean run - on the same stream a real failure
    would use, which is exactly where noise costs the most.
    """

    def handle_error(self, request, client_address):
        pass


def serve(handler, port=None):
    """Start a server in a daemon thread; return its port and its Recorder.

    With port=None the port is chosen here and re-chosen if binding loses the
    race against another process - free_port() has to release the socket before
    it can be bound again, and parallel scans do collide on that window. A port
    passed explicitly is bound once: the caller asked for that one.
    """
    attempts = 1 if port is not None else 5
    for attempt in range(attempts):
        chosen = port if port is not None else free_port()
        try:
            server = QuietHTTPServer(("127.0.0.1", chosen), handler)
        except OSError:
            if attempt == attempts - 1:
                raise
            continue
        server.state = Recorder()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return chosen, server.state
    raise AssertionError("unreachable")


# A scratch HOME shared by every check. Read-only in practice: the point of
# pinning it is that nothing here reads the developer's key file, and one check
# asserts that nothing writes into it either.
SCRATCH_HOME = None


def clean_env(**overrides):
    """The environment a check runs in, with the API token pinned.

    2.0 discovers a token from VULNERS_API_KEY, so a run that inherits the
    developer's environment takes the authenticated path on their machine and
    the free path in CI - and sends their real token to whatever host the check
    points at. Every check therefore states which it wants; nothing inherits.
    """
    env = {k: v for k, v in os.environ.items() if k != "VULNERS_API_KEY"}
    # HOME is pinned too: the script reads a token from ~/.nmap/vulners.key, and
    # a run that inherited the developer's HOME would pick theirs up.
    if SCRATCH_HOME is not None:
        env["HOME"] = str(SCRATCH_HOME)
    env.update({k: v for k, v in overrides.items() if v is not None})
    return env


def run_nmap(args, timeout=300, env=None):
    """Run nmap and return its combined output.

    Raises when the script did not survive the scan. nmap exits 0 either way -
    it prints the error, discards the port's findings and carries on - so the
    exit status says nothing, and a check reading the output would only notice
    if it happened to assert on something the lost findings would have carried.

    The two failures look different and both matter:

      "failed to initialize the script engine"  the chunk did not compile
      "ERROR: Script execution failed"          it compiled and then raised

    Only the first was ever checked, and only in one place. It is also the one
    `tools/check.py` already catches with luac before CI gets here; the runtime
    raise, which is the case that reaches users, went unnoticed.
    """
    completed = subprocess.run(
        ["nmap", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env if env is not None else clean_env(),
    )
    output = completed.stdout + completed.stderr
    for marker in ("ERROR: Script execution failed",
                   "failed to initialize the script engine"):
        if marker in output:
            raise AssertionError(
                "nmap reported %r; every finding on that port was discarded.\n"
                "  nmap %s\n%s" % (marker, " ".join(args), output[-2000:]))
    return output


class Checks:
    """Minimal PASS/FAIL bookkeeping.

    Lines are collected rather than printed. The checks run at the same time, so
    printing as they go would interleave one check's failure context into
    another's results and shuffle the order between runs; absorb() puts them
    back in declaration order at the end.
    """

    def __init__(self):
        self.failures = []
        self.lines = []
        self.passed = 0
        self.skipped = 0

    def check(self, condition, description, context=""):
        if condition:
            self.passed += 1
            self.lines.append(f"ok    {description}")
        else:
            self.failures.append(description)
            self.lines.append(f"FAIL  {description}")
            if context:
                self.lines.append(
                    "        " + context.strip().replace("\n", "\n        "))

    def skip(self, description, why):
        self.skipped += 1
        self.lines.append(f"skip  {description}  ({why})")

    def absorb(self, other):
        self.failures += other.failures
        self.lines += other.lines
        self.passed += other.passed
        self.skipped += other.skipped

    def report(self, expected_at_least=None):
        print("\n".join(self.lines))
        tail = f", {self.skipped} skipped" if self.skipped else ""
        print(f"\n{self.passed} passed, {len(self.failures)} failed{tail}")
        if self.failures:
            return 1
        # A run in which every check quietly vanished is not a run that passed.
        # With the check list empty this printed "0 passed, 0 failed" and
        # exited 0 - the same scar the unit runner carried, where a typo in
        # `only=` reported SUITE OK for a suite that never ran a case.
        if expected_at_least is not None and self.passed < expected_at_least:
            print(f"\nFAILED: only {self.passed} assertions ran, and this gate "
                  f"is expected to make at least {expected_at_least}. A gate "
                  f"that measures nothing reports success.")
            return 1
        return 0


# The floor this gate must clear to be believed. It is a PINNED number, not
# len(OFFLINE_CHECKS): deriving it from the check list would make an empty
# check list satisfy itself, which is the failure being guarded against. Set
# comfortably below the 61 assertions made today, so ordinary growth never
# touches it while a collapse still fails the run.
MINIMUM_ASSERTIONS = 50

# Set once the catalogue server is up; every run points at it. A check that
# wants to COUNT catalogue fetches starts a server of its own, because this one
# is answering every other check at the same time.
CATALOG_PORT = None


def vulners_args(api_port, extra=None):
    """The script arguments every offline check needs.

    api_host and api_port are not optional here: the merged script defaults to
    vulners.com, so a check that forgets them sends real traffic off the box -
    which this file's whole premise forbids. The 1.x fingerprint script had no
    API of its own, which is why its checks used to omit them.

    catalog_url is not optional for the same reason, and for one more: without
    it the script fetches its dictionaries from GitHub, so a check would pass or
    fail on what is published rather than on what is in this tree.
    """
    args = ["vulners.api_host=127.0.0.1", f"vulners.api_port={api_port}"]
    if CATALOG_PORT is not None:
        args.append(f"vulners.catalog_url=http://127.0.0.1:{CATALOG_PORT}/")
    if extra:
        args.append(extra)
    return ",".join(args)


def run_vulners(target_port, api_port, token=None, extra=None, xml=None,
                hosts=("127.0.0.1",), sv=True):
    """One offline run of the merged script."""
    args = ["-Pn"]
    if sv:
        args.append("-sV")
    args += ["-p", str(target_port), "--script", script("vulners.nse"),
             "--script-args", vulners_args(api_port, extra)]
    if xml:
        args += ["-oX", str(xml)]
    args += list(hosts)
    return run_nmap(args, env=clean_env(VULNERS_API_KEY=token))


def group_keys(xml_text):
    """The software identities a report grouped its findings under."""
    if not xml_text:
        return []
    root = ET.fromstring(xml_text)
    keys = []
    for element in root.iter("script"):
        if element.get("id") != "vulners":
            continue
        keys += [table.get("key") for table in element.findall("table")]
    return sorted(k for k in keys if k)


# ------------------------------------------------------------------- a world

class World:
    """One check's own target, own API and own report file.

    A check used to reset counters that lived on the handler classes, run nmap,
    and read them back - which is only correct while exactly one check is in
    flight. Giving each check its servers is what lets them all run at once, and
    the file went from 93 seconds to a fraction of that without dropping a
    single assertion.
    """

    def __init__(self, name):
        self.name = name
        self.checks = Checks()
        self.target_port, self.target = serve(TargetHandler)
        self.api_port, self.api = serve(ApiHandler)
        # A private directory per world, not a fixed path in the source tree.
        # The report used to live at tests/e2e/_e2e_<name>.xml, which made it
        # process-global: two runs of this gate at once deleted each other's
        # reports and read each other's, so a check could assert happily
        # against a NEIGHBOUR's XML - or against one left by an earlier run
        # while the current scan produced nothing at all. Measured: with
        # `run_nmap` stubbed to run no scan whatsoever, the XML checks reported
        # "6 passed, 0 failed".
        self._scratch = tempfile.TemporaryDirectory(prefix="e2e-report-")
        self.xml = Path(self._scratch.name) / f"{name}.xml"

    def check(self, *args, **kwargs):
        self.checks.check(*args, **kwargs)

    def skip(self, *args, **kwargs):
        self.checks.skip(*args, **kwargs)

    def scan(self, **kwargs):
        """One offline run against this world's own target and API."""
        kwargs.setdefault("target_port", self.target_port)
        kwargs.setdefault("api_port", self.api_port)
        # Remembered so report() can refuse anything older: a report that
        # predates the scan is not this scan's answer, whatever it says.
        self._scan_started = time.time()
        return run_vulners(**kwargs)

    def report(self):
        """The XML of the last scan that asked for one, and only that."""
        if not self.xml.exists():
            return ""
        started = getattr(self, "_scan_started", None)
        if started is not None and self.xml.stat().st_mtime < started:
            raise AssertionError(
                "the report at %s predates the scan that was supposed to write "
                "it; reading it would assert against stale output" % self.xml)
        return self.xml.read_text()

    def close(self):
        self._scratch.cleanup()


def concurrently(*thunks):
    """Run several scans at once and return their results in order.

    Every -sV run costs six seconds whatever it scans: nmap's NULL probe waits
    for a banner an HTTP server never sends, and that wait is the whole cost of
    a check - the script itself adds sixty milliseconds. Measured: -Pn alone
    0.02 s, -Pn -sV 6.11 s, -sV with the script and the full sweep 6.17 s.
    So a check that runs three scans one after another is the slowest thing in
    the file, and it decides when the whole run ends.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(thunks)) as pool:
        return [future.result() for future in [pool.submit(t) for t in thunks]]


# ----------------------------------------------------------------- offline

def check_fingerprint(world):
    """The web sweep still identifies software nmap's own probe cannot see."""
    output = world.scan(xml=world.xml)
    keys = group_keys(world.report())

    world.check("cpe:/a:f5:nginx:1.13.4" in keys or
                "cpe:/a:igor_sysoev:nginx:1.13.4" in keys,
                "the sweep finds the nginx CPE of a live server",
                f"{keys}\n{output[-800:]}")
    # nmap reports this service as nginx and cannot see the X-Powered-By
    # header, so a PHP finding can only have come from the sweep.
    world.check("cpe:/a:php:php:5.6.38" in keys,
                "the sweep finds a CPE nmap's own detection cannot",
                f"{keys}\n{output[-800:]}")
    # The script surviving the scan is asserted for EVERY scan in this file
    # now, inside run_nmap, rather than for this one check by a string that
    # only ever matched a compile failure.

    world.check(world.target.compressed_replies > 0,
                "the path sweep asks the server to compress, and still matches",
                f"compressed replies: {world.target.compressed_replies}")
    # Pipelining: a hundred-odd paths must not mean a hundred-odd connections.
    target = world.target
    world.check(
        target.requests > 10 and target.connections * 4 < target.requests,
        "the path list is pipelined rather than one connection per path",
        f"{target.requests} requests over {target.connections} connections",
    )


def check_sweep_can_be_disabled(world):
    """vulners.paths=none is a real off switch, and the only one users have.

    Measured against a control rather than against zero: -sV probes the target
    itself, so a run that sweeps nothing still shows a handful of requests that
    were never the script's.

    Four scans against four servers rather than four against one, so they can
    run at the same time and each still counts only its own traffic.
    """
    (control_port, control), (off_port, off), (on_port, on), (quiet_port, quiet) = \
        [serve(TargetHandler) for _ in range(4)]

    concurrently(
        lambda: run_nmap(["-Pn", "-sV", "-p", str(control_port), "127.0.0.1"]),
        lambda: world.scan(target_port=off_port, extra="vulners.paths=none"),
        lambda: world.scan(target_port=on_port),
        lambda: run_nmap(["-Pn", "-sV", "-T4", "-p", str(quiet_port),
                          "--script", script("vulners.nse"),
                          "--script-args", vulners_args(world.api_port),
                          "127.0.0.1"]),
    )
    baseline, disabled = control.requests, off.requests
    swept, polite = on.requests, quiet.requests

    published = len(json.loads((REPO / "catalog" / "paths.json").read_text())["paths"])

    world.check(disabled <= baseline,
                "vulners.paths=none adds no requests of its own to the target",
                f"baseline {baseline}, with paths=none {disabled}")

    # Every published path, always. -T changes the rate and never the list, so a
    # polite scan has to ask exactly the same questions as an ordinary one.
    world.check(swept >= baseline + published,
                "every path the catalogue publishes is actually requested",
                f"baseline {baseline}, swept {swept}, catalogue has {published}")
    # -T4 rather than -T2: the rate ladder itself is pinned by unit cases against
    # a counted clock, precisely and instantly, where a real -T2 run would sit
    # here sleeping 19 seconds to prove something already proved. What only the
    # real nmap can show is that a different -T still asks the whole list.
    world.check(polite >= baseline + published,
                "and a different timing template still asks all of them",
                f"baseline {baseline}, at -T4 {polite}, catalogue has {published}")


def check_works_without_sv(world):
    """The README promises the sweep also works without -sV.

    shortport.http recognises a service on a well known port without version
    detection, which is what puts the port in scope and lets the sweep run.
    """
    plain_http_port = claim_port(8080)
    if plain_http_port is None:
        world.skip("the sweep works without -sV", "port 8080 is busy")
        return

    serve(TargetHandler, plain_http_port)
    output = run_nmap([
        "-Pn", "-p", str(plain_http_port),
        "--script", script("vulners.nse"),
        "--script-args", vulners_args(world.api_port),
        "127.0.0.1",
    ])
    world.check(CANNED_VULN_ID in output,
                "the sweep works without -sV on a well known http port", output)


def check_free_path(world):
    """Without a token the script uses the free endpoint and says so."""
    api = world.api
    output = world.scan(extra="vulners.mincvss=7.0", xml=world.xml)
    xml = world.report()

    world.check(CANNED_VULN_ID in output,
                "the free path reports the vulnerability the API returned", output)
    world.check(re.search(r"^\|\s+HIGH\s+7\.5\b", output, re.M) is not None,
                "findings are laid out as an aligned table with a severity",
                output)
    world.check(re.search(r"^\|.*\bEXP\b", output, re.M) is not None,
                "an exploit is flagged in the FLAGS column", output)
    world.check(LOW_VULN_ID not in output,
                "mincvss hides a finding below the threshold", output)
    world.check(any(q.get("type") == "cpe" for q in api.burp_queries),
                "the free path asks the burp endpoint about CPEs",
                str(api.burp_queries[:3]))

    cpe_queries = [q.get("software", "") for q in api.burp_queries
                   if q.get("type") == "cpe"]
    world.check(cpe_queries and all(q.startswith("cpe:/") and "%" not in q
                                    for q in cpe_queries),
                "the CPE is sent unescaped, as the endpoint needs it",
                str(cpe_queries[:3]))
    world.check(all("Vulners NMAP Plugin" in (ua or "")
                    for ua in api.seen_user_agents),
                "every request carries the User-Agent the CDN requires",
                str(api.seen_user_agents[:3]))
    world.check(any(k.startswith("cpe:/") for k in group_keys(xml)),
                "findings are grouped under the CPE, not a software label",
                str(group_keys(xml)))
    world.check(api.compressed_replies > 0,
                "the free path asks for a compressed answer and reads it",
                f"compressed replies: {api.compressed_replies}")
    # Only the free endpoint is used, and it is a GET so the CDN can cache it.
    world.check(set(api.requests_by_path) == {"/api/v3/burp/software/"},
                "a run without a token touches only the free endpoint",
                str(api.requests_by_path))


def check_free_notice(world):
    """Every keyless run says it ran without a token, and where to get one."""
    output = world.scan()
    world.check("Ran without an API key" in output,
                "a keyless run says so, on every scan", output[-1200:])
    world.check("https://vulners.com/userinfo" in output,
                "and says where to get a key", output[-1200:])
    # Deliberately vague about which fields: what a token returns depends on the
    # licence behind it, so naming EPSS would be a promise the script cannot keep.
    world.check("EPSS" not in output.split("Post-scan")[-1],
                "the notice does not promise fields a licence may withhold",
                output[-1200:])


def check_keyed_path(world):
    """A token adds enrichment, and never travels to the cached free endpoint."""
    api = world.api
    output = world.scan(token=FAKE_KEY, xml=world.xml)

    world.check(CANNED_VULN_ID in output,
                "the authenticated path reports the vulnerability", output)
    world.check("/api/v3/search/id/" in api.requests_by_path,
                "a token buys enrichment through the id endpoint",
                str(api.requests_by_path))
    world.check(FAKE_KEY in api.seen_api_keys,
                "the token authenticates the enrichment request",
                f"keys seen: {api.seen_api_keys}")
    world.check(FAKE_KEY not in output,
                "the token is never printed into nmap output", output)

    # The free endpoint is CDN-cached for four hours, and only for requests
    # without a key. Sending one would take every user of this script off the
    # shared cache and onto the origin, for an answer that does not improve.
    world.check(all(key is None for key in api.burp_api_keys),
                "the burp request carries no token, even when one is configured",
                f"keys seen on burp: {api.burp_api_keys}")

    xml = world.report()
    world.check('key="title"' in xml,
                "enrichment puts a title on the finding", xml[:1200])
    world.check('key="epss"' in xml,
                "enrichment puts an EPSS score on the finding", xml[:1200])
    world.check('key="kev"' in xml,
                "a CISA KEV listing reaches the report", xml[:1200])
    world.check('key="mode">keyed<' in xml,
                "the report records which path the scan took", xml[:1200])


def check_keyless_is_not_silent(world):
    """A missing token is no longer silence.

    1.x had two scripts, and the authenticated one returned nothing at all
    without a key. Merged, that would mean a user whose trial expired got
    strictly less than a user with no key - so the free path runs instead.
    """
    output = world.scan()
    world.check("vulners:" in output,
                "a run without a token still reports findings", output[-1500:])
    world.check(CANNED_VULN_ID in output,
                "and those findings are real ones from the free endpoint",
                output[-1500:])


def check_rejected_key_degrades(world):
    """A rejected token drops to the free path instead of silencing the scan."""
    world.api.reject_keys = True
    output = world.scan(token=FAKE_KEY)

    world.check(CANNED_VULN_ID in output,
                "a rejected token still leaves the free findings reported",
                output[-1500:])
    world.check("Ran without a usable API key" in output,
                "and the scan says why it degraded", output[-1500:])


def check_xml_output(world):
    """Structured output must survive into -oX, not only into the text report."""
    world.scan(token=FAKE_KEY, xml=world.xml)

    xml = world.report()
    world.check('<script id="vulners"' in xml,
                "the result reaches the XML output under the id importers read",
                xml[:1500])
    world.check(f'key="id">{CANNED_VULN_ID}<' in xml,
                "XML output carries the vulnerability id as a structured element",
                xml[:1500])
    world.check('key="cvss_type">cvss3.1<' in xml,
                "XML output carries the cvss version as a structured element",
                xml[:1500])
    world.check('key="severity">' in xml,
                "every finding carries a severity, scored or not", xml[:1500])
    world.check('key="schema">2.0<' in xml,
                "the report states which schema a consumer is reading",
                xml[:1500])

    # nmap copies its own command line into the report, so a token passed with
    # --script-args lands there whatever the script does. What the script
    # controls is its own output, and that must stay clean.
    script_elements = re.findall(r"<script id=\"vulners[^>]*>.*?</script>", xml, re.S)
    world.check(script_elements and all(FAKE_KEY not in el for el in script_elements),
                "the API token never appears in the script's own XML output",
                "\n".join(script_elements)[:800])


def check_service_cpe_enrichment(world):
    """Fingerprinted CPEs must reach the <service> element, not only the script.

    nmap's own probe of this target reports nginx and produces
    cpe:/a:igor_sysoev:nginx. The PHP CPE exists only because the script reads
    the X-Powered-By header and calls nmap.set_port_version(), so it is the
    clearest witness that publishing still happens.

    This is checked in the report rather than in the script's text output
    because the text listing of found CPEs goes away in 2.0, while the service
    element is what every consumer of -oX actually reads. Without this check
    the publishing could be dropped in the merge and nothing would notice.
    """
    world.scan(xml=world.xml)
    xml = world.report()
    root = ET.fromstring(xml) if xml else None
    published = []
    if root is not None:
        for service in root.iter("service"):
            published += [cpe.text for cpe in service.findall("cpe")]

    world.check("cpe:/a:php:php:5.6.38" in published,
                "a CPE found by fingerprinting reaches the service element",
                f"service CPEs: {published}")
    world.check(len(published) == len(set(published)),
                "the published CPE list has no duplicates",
                f"service CPEs: {published}")


def check_xml_contract(world):
    """The XML keeps the shape DefectDojo, Faraday, nmap2csv and raven read.

    They all select findings with script[@id="vulners"] and walk two levels of
    table; none of them fails loudly when that shape moves, they just import
    nothing. tools/xml_contract.py holds the requirements, calibrated against
    the 1.x capture in tests/fixtures.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        problems = xml_contract.selftest(tmpdir)
    world.check(not problems,
                "the XML contract still catches a broken report",
                "\n".join(problems))

    golden = REPO / "tests" / "fixtures" / "golden_1x.xml"
    contract = xml_contract.check(golden)
    world.check(not contract.broken,
                "the captured 1.x report satisfies the XML contract",
                "; ".join(r[1] for r in contract.broken))

    # Scanned separately rather than reusing another check's report: the
    # contract is about the script named "vulners", which is the file this
    # release turns into the whole plugin.
    run_nmap([
        "-Pn", "-sV", "-p", str(world.target_port),
        "--script", script("vulners.nse"),
        # Through the shared helper, like every other check. Hand-rolled here,
        # this omitted catalog_url - so the one check that claims to validate
        # the report shape fetched its dictionaries from raw.githubusercontent
        # on every run, against the file's own promise that no traffic leaves
        # the machine. It passes today only because the catalog branch is not
        # published yet; the moment 2.0 publishes it, this check would start
        # validating whatever is live and go red whenever GitHub is down.
        "--script-args", vulners_args(world.api_port),
        "-oX", str(world.xml),
        "127.0.0.1",
    ])
    if not world.xml.exists():
        world.check(False, "the current report satisfies the XML contract",
                    "no report was written")
        return
    contract = xml_contract.check(world.xml)
    world.check(not contract.broken,
                "the current report satisfies the XML contract",
                "; ".join(f"{r[1]} - {r[2]}" for r in contract.broken))


def check_key_from_env_stays_out_of_reports(world):
    """A token taken from the environment must not reach the report at all."""
    output = world.scan(token=FAKE_KEY, xml=world.xml)
    xml = world.report()

    # Asserting that the script produced output would prove nothing here: a
    # keyless run produces output too, now that it falls back to the free path.
    # What shows the environment was actually read is the token arriving at the
    # endpoints that need one.
    world.check(FAKE_KEY in world.api.seen_api_keys,
                "VULNERS_API_KEY is picked up by the script",
                f"keys seen: {world.api.seen_api_keys}")
    world.check(FAKE_KEY not in xml,
                "a token taken from the environment stays out of the XML report entirely",
                xml[:800])
    world.check(FAKE_KEY not in output,
                "a token taken from the environment stays out of the text report")


def check_scan_cache(world):
    """Two hosts running the same software must not be looked up twice."""
    # Its own API and its own target, so the one-host control can run at the
    # same time as the two-host scan instead of after it.
    solo_target, _ = serve(TargetHandler)
    solo_api_port, solo_api = serve(ApiHandler)

    output, _ = concurrently(
        lambda: world.scan(xml=world.xml, hosts=("127.0.0.1", "localhost")),
        lambda: world.scan(target_port=solo_target, api_port=solo_api_port,
                           hosts=("127.0.0.1",)),
    )
    first = dict(world.api.requests_by_path)

    # An absolute request count is the wrong assertion now: discovery is one
    # free GET per CPE plus, with a token, an enrichment POST - so "one request
    # for two hosts" can never hold. What the cache promises is that the second
    # host adds nothing, and that is what is measured.
    single = dict(solo_api.requests_by_path)

    world.check(sum(first.values()) == sum(single.values()),
                "a second host running the same software costs no extra request",
                f"two hosts: {first}\none host: {single}")

    per_host = []
    for report in output.split("Nmap scan report for")[1:]:
        per_host.append(sorted(set(re.findall(r"(cpe:/\S+?)\s+\d+ finding", report))))
    world.check(len(per_host) == 2 and per_host[0] == per_host[1] and per_host[0],
                "both hosts report the same result, not just the first one",
                f"{per_host}\n{output[-1200:]}")


def check_writes_nothing(world):
    """A whole scan must leave the filesystem exactly as it found it.

    The script has no cache and no argument that gives it one. This is the
    end-to-end half of the unit case that counts io.open calls: that one proves
    the script does not ask, this one proves nothing else on the way does
    either - with the real nmap, the real catalogue fetch and a real HOME to
    write into.

    Its own HOME, not the shared one: the checks run at the same time, so a
    file written by somebody else's scan would already be there when this one
    took its "before" snapshot - and a script that had started caching again
    would pass. Measured: it did exactly that until this directory became
    private to the check.
    """
    with tempfile.TemporaryDirectory() as scratch:
        home = Path(scratch)
        (home / ".nmap").mkdir()
        before = sorted(str(p.relative_to(home)) for p in home.rglob("*"))

        run_nmap(["-Pn", "-sV", "-p", str(world.target_port),
                  "--script", script("vulners.nse"),
                  "--script-args", vulners_args(world.api_port), "127.0.0.1"],
                 env=clean_env(VULNERS_API_KEY=FAKE_KEY, HOME=str(home)))

        after = sorted(str(p.relative_to(home)) for p in home.rglob("*"))
        world.check(before == after,
                    "a scan writes nothing into the user's home directory",
                    f"appeared: {sorted(set(after) - set(before))}")


def check_banner_port(world):
    """A port nmap could not name is identified from its banner alone.

    Three things at once, and none of them had an end-to-end guard: that the
    portrule admits a port whose only identity is a service fingerprint, that
    the banner rules are matched line by line against it, and that the identity
    reaches both the report and the free lookup. Measured before the portrule
    was widened: nmap recorded a 2 209-byte fingerprint, every clause of the
    portrule was false, and the script never ran on the port at all.
    """
    banner_port = serve_tcp(BannerTarget)

    output = run_nmap([
        "-Pn", "-sV", "-p", str(banner_port),
        "--script", script("vulners.nse"),
        "--script-args", vulners_args(world.api_port),
        "127.0.0.1",
    ])

    # The group heading is trimmed to the table width, so the version may be
    # cut off it; the identity is what this asserts on.
    world.check("cpe:/a:powerdns:authoritative_server" in output,
                "a service nmap cannot name is identified from its banner",
                output[-1500:])
    world.check(CANNED_VULN_ID in output,
                "and that identity is looked up like any other", output[-1500:])

    asked = [q.get("software", "") for q in world.api.burp_queries]
    world.check(any("powerdns" in q for q in asked),
                "the banner identity reaches the free endpoint",
                str(asked[:5]))


def check_catalogue_is_fetched_once(world):
    """However many ports answer, the catalogue is downloaded once.

    The reason the fetch lives in a prerule at all. The chunk re-executes once
    per OPEN port - measured at 7 executions for 7 open ports - so a fetch on the
    port path would mean one download per port, all racing each other. The unit
    suite pins the guard; only the real nmap running a real multi-port scan pins
    that the phase it lives in behaves the way that argument assumes.

    Counted on its own catalogue server: the shared one is answering every other
    check at the same time.
    """
    catalog_port, catalog = serve(CatalogHandler)
    second_port, _ = serve(TargetHandler)

    run_nmap(["-Pn", "-sV",
              "-p", f"{world.target_port},{second_port}",
              "--script", script("vulners.nse"),
              "--script-args",
              f"vulners.api_host=127.0.0.1,vulners.api_port={world.api_port},"
              f"vulners.catalog_url=http://127.0.0.1:{catalog_port}/",
              "127.0.0.1"])

    world.check(catalog.requests == 4,
                "two open ports cost one catalogue download, not two",
                f"the index and three dictionaries is 4; got {catalog.requests}")


def check_catalogue_can_be_refused(world):
    """vulners.catalog=none is offline mode, and it is not silence."""
    # Against a control, not against zero: -sV probes the target itself, so a
    # run that sweeps nothing still shows the requests nmap made.
    control_port, control = serve(TargetHandler)

    output, _ = concurrently(
        lambda: world.scan(extra="vulners.catalog=none"),
        lambda: run_nmap(["-Pn", "-sV", "-p", str(control_port), "127.0.0.1"]),
    )
    baseline, swept = control.requests, world.target.requests

    world.check(swept <= baseline,
                "with no catalogue there is nothing to sweep, so nothing is asked",
                f"baseline {baseline}, with catalog=none {swept}")
    world.check(CANNED_VULN_ID in output,
                "what nmap itself named is still looked up", output[-1500:])
    world.check("catalogue is off" in output,
                "and the report says the fingerprinting was skipped",
                output[-1500:])


def check_unreachable_catalogue(world):
    """An unreachable catalogue costs fingerprinting, and nothing else."""
    # A port nothing listens on. This is the airgapped machine, the proxy that
    # blocks GitHub, and the CDN outage - all of which must leave a scan that
    # still reports what nmap named rather than one that reports nothing.
    dead = free_port()
    output = world.scan(extra=f"vulners.catalog_url=http://127.0.0.1:{dead}/")

    world.check(CANNED_VULN_ID in output,
                "the lookups that need no dictionary still run", output[-1500:])
    world.check("could not be downloaded" in output,
                "and the operator is told which capability was missing",
                output[-1500:])


# -------------------------------------------------------------------- live

def check_live(world):
    """Optional: verify the real API still answers in the shape we imitate."""
    token = os.environ.get("VULNERS_API_KEY")
    if not token:
        world.skip("live API contract", "VULNERS_API_KEY is not set")
        return

    output = run_nmap([
        "-Pn", "-sV", "-p", str(world.target_port),
        "--script", script("vulners.nse"), "127.0.0.1",
    ], env=clean_env(VULNERS_API_KEY=token))

    world.check("vulners:" in output,
                "the live API answers the merged script", output[-2000:])
    world.check(re.search(r"^\|\s+\w+\s+\d+\.\d\b", output, re.M) is not None,
                "live results carry a severity and a score", output[-2000:])
    world.check(token not in output,
                "the live API token never appears in nmap output")

    # The free endpoint is checked against an Apache banner: it answers that
    # CPE, while both nginx spellings come back empty, which would leave the
    # check asserting on silence. The token is stripped rather than inherited,
    # because otherwise this would not be a keyless run at all.
    apache_port, _ = serve(ApacheTargetHandler)
    free_output = run_nmap([
        "-Pn", "-sV", "-p", str(apache_port),
        "--script", script("vulners.nse"), "127.0.0.1",
    ], env=clean_env())

    world.check("vulners:" in free_output,
                "the live free endpoint answers a keyless scan",
                free_output[-2000:])
    world.check("cpe:/a:apache:http_server:2.4.7" in free_output,
                "the live free lookup reports under the CPE it asked about",
                free_output[-2000:])
    # Not "a CVE appears": the default view is bounded and ranked, and on the
    # free path a real Apache 2.4.7 answers with 56 exploit bulletins that all
    # outrank every CVE - which is what caught the summary being fillable by one
    # band. What this asserts is that real bulletins came back at all, of either
    # kind, and that the band cap left room for a named vulnerability.
    world.check(re.search(r"^\|\s+\w+\s+\d+\.\d.*\S", free_output, re.M) is not None,
                "the live free lookup returns real bulletins",
                free_output[-2000:])
    world.check(re.search(r"CVE-\d{4}-\d+", free_output) is not None,
                "and the bounded summary still names a vulnerability, not only exploits",
                free_output[-2000:])
    world.check("Ran without an API key" in free_output,
                "a keyless live run says so", free_output[-2000:])


# ------------------------------------------------------------------ the run

# Declared once, in the order their results are printed. Slowest first, because
# the pool takes them in this order and a long check started last decides when
# the whole run ends.
OFFLINE_CHECKS = [
    check_sweep_can_be_disabled,   # four nmap runs
    check_scan_cache,              # two, one of them over two hosts
    check_fingerprint,
    check_free_path,
    check_keyed_path,
    check_xml_output,
    check_xml_contract,
    check_service_cpe_enrichment,
    check_key_from_env_stays_out_of_reports,
    check_free_notice,
    check_keyless_is_not_silent,
    check_rejected_key_degrades,
    check_works_without_sv,
    check_writes_nothing,
    check_catalogue_can_be_refused,
    check_unreachable_catalogue,
    check_catalogue_is_fetched_once,
    check_banner_port,
]


def run_check(fn):
    """Run one check in its own world and hand back what it recorded."""
    world = World(fn.__name__.replace("check_", ""))
    try:
        fn(world)
    except Exception as failure:              # noqa: BLE001 - a check may raise
        world.check(False, f"{fn.__name__} completed",
                    f"{type(failure).__name__}: {failure}")
    finally:
        world.close()
    return world.checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="additionally check the real vulners.com API")
    # Twice the cores, capped: every check is a scan waiting on nmap's NULL
    # probe rather than on a CPU, so oversubscribing is what actually helps.
    # Measured on 16 cores: 118 s serial, 25 s at 4, 13 s at 8, 7 s at 16.
    parser.add_argument("--jobs", type=int,
                        default=max(4, min(16, 2 * (os.cpu_count() or 2))),
                        help="checks to run at once (1 to serialise)")
    args = parser.parse_args()

    global CATALOG_PORT, SCRATCH_HOME
    CATALOG_PORT, _ = serve(CatalogHandler)
    scratch = tempfile.TemporaryDirectory()
    SCRATCH_HOME = Path(scratch.name)
    (SCRATCH_HOME / ".nmap").mkdir()

    # Collected per check and printed in declaration order, so a parallel run
    # reads exactly like a serial one and two runs can be diffed.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        collected = list(pool.map(run_check, OFFLINE_CHECKS))

    if args.live:
        collected.append(run_check(check_live))

    checks = Checks()
    for one in collected:
        checks.absorb(one)
    if not args.live:
        checks.skip("live API contract", "run with --live to include it")

    scratch.cleanup()
    return checks.report(expected_at_least=MINIMUM_ASSERTIONS)


if __name__ == "__main__":
    sys.exit(main())
