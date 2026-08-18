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
import gzip
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FAKE_KEY = "FAKE-TEST-KEY-NOT-A-REAL-TOKEN"

# Banners the shipped patterns in http-vulners-regex.json recognise.
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
    """
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", preferred))
    except OSError:
        return None
    return preferred


class TargetHandler(http.server.BaseHTTPRequestHandler):
    """A web server that looks like an outdated nginx with PHP."""

    protocol_version = "HTTP/1.1"
    requests = 0
    connections = 0
    compressed_replies = 0  # pages actually sent gzipped

    def setup(self):
        TargetHandler.connections += 1
        super().setup()

    def do_GET(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        TargetHandler.requests += 1
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
            TargetHandler.compressed_replies += 1

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ApacheTargetHandler(http.server.BaseHTTPRequestHandler):
    """A web server nmap fingerprints as cpe:/a:apache:http_server:2.4.7.

    The live checks need a CPE the real API actually answers: the nginx CPEs
    the main target yields answer with far less than an Apache one, and the
    check would be asserting on a nearly empty result.
    """

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        body = b"<html><body>nmap-vulners live target</body></html>"
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.7 (Ubuntu)")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


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


class ApiHandler(http.server.BaseHTTPRequestHandler):
    """A stand-in for the Vulners API, both the v4 and the v3 endpoints."""

    protocol_version = "HTTP/1.1"
    seen_api_keys = []
    seen_user_agents = []
    audit_batches = []      # sizes of the software lists received
    burp_queries = []       # query dicts of the free endpoint
    requests_by_path = {}   # every endpoint hit, with its count
    compressed_replies = 0  # answers actually sent gzipped

    def _count(self):
        endpoint = self.path.split("?", 1)[0]
        counts = ApiHandler.requests_by_path
        counts[endpoint] = counts.get(endpoint, 0) + 1

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
            ApiHandler.compressed_replies += 1

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - the free script uses GET
        self._count()
        parsed = urllib.parse.urlparse(self.path)
        ApiHandler.seen_user_agents.append(self.headers.get("User-Agent"))

        if not parsed.path.startswith("/api/v3/burp/software/"):
            self.send_error(404)
            return

        # The real endpoint does not percent-decode its arguments: an escaped
        # CPE (cpe%3A%2Fa%3A...) comes back as errorCode 303 for every plugin
        # version, so a client that escapes the value gets nothing at all.
        # parse_qsl would decode it and hide exactly that, so the raw query
        # string is what this double looks at.
        query = dict(part.split("=", 1)
                     for part in parsed.query.split("&") if "=" in part)
        ApiHandler.burp_queries.append(query)

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

    def _reject_unknown_fields(self, payload):
        """Answer 422 for a field the real service does not accept."""
        unknown = [f for f in (payload.get("fields") or [])
                   if f not in AUDIT_FIELDS]
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
        ApiHandler.seen_api_keys.append(self.headers.get("X-Api-Key"))
        ApiHandler.seen_user_agents.append(self.headers.get("User-Agent"))

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}

        if self._reject_unknown_fields(body):
            return

        if self.path.startswith("/api/v4/audit/software/"):
            software = body.get("software", [])
            ApiHandler.audit_batches.append(len(software))
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
            documents = {
                vuln_id: {"id": vuln_id, "type": "cve",
                          "cvss": {"score": CANNED_CVSS, "version": "3.1"},
                          "enchantments": {"dependencies": {"references": []}}}
                for vuln_id in body.get("id", [])
            }
            self._reply({"result": "OK", "data": {"documents": documents}})
            return

        self.send_error(404)

    def log_message(self, *args):
        pass


def serve(handler, port=None):
    """Start a server in a daemon thread and return the port it listens on.

    With port=None the port is chosen here and re-chosen if binding loses the
    race against another process - free_port() has to release the socket before
    it can be bound again, and parallel scans do collide on that window. A port
    passed explicitly is bound once: the caller asked for that one.
    """
    attempts = 1 if port is not None else 5
    for attempt in range(attempts):
        chosen = port if port is not None else free_port()
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", chosen), handler)
        except OSError:
            if attempt == attempts - 1:
                raise
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return chosen
    raise AssertionError("unreachable")


def run_nmap(args, timeout=300, env=None):
    """Run nmap and return its combined output."""
    completed = subprocess.run(
        ["nmap", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return completed.stdout + completed.stderr


class Checks:
    """Minimal PASS/FAIL bookkeeping."""

    def __init__(self):
        self.failures = []
        self.passed = 0
        self.skipped = 0

    def check(self, condition, description, context=""):
        if condition:
            self.passed += 1
            print(f"ok    {description}")
        else:
            self.failures.append(description)
            print(f"FAIL  {description}")
            if context:
                print("        " + context.strip().replace("\n", "\n        "))

    def skip(self, description, why):
        self.skipped += 1
        print(f"skip  {description}  ({why})")

    def report(self):
        tail = f", {self.skipped} skipped" if self.skipped else ""
        print(f"\n{self.passed} passed, {len(self.failures)} failed{tail}")
        return 1 if self.failures else 0


# ----------------------------------------------------------------- offline

def check_regex_script(checks, target_port):
    """http-vulners-regex against a live server."""
    TargetHandler.requests = 0
    TargetHandler.connections = 0
    TargetHandler.compressed_replies = 0

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", script("http-vulners-regex.nse"),
        "127.0.0.1",
    ])

    checks.check("cpe:/a:f5:nginx:1.13.4" in output,
                 "http-vulners-regex reports the nginx CPE of a live server", output)
    checks.check("cpe:/a:php:php:5.6.38" in output,
                 "http-vulners-regex reports the PHP CPE of a live server", output)
    checks.check("SCRIPT ENGINE" not in output.upper(),
                 "nmap loads http-vulners-regex without script engine errors", output)

    checks.check(TargetHandler.compressed_replies > 0,
                 "the path sweep asks the server to compress, and still matches",
                 f"compressed replies: {TargetHandler.compressed_replies}")

    # Pipelining: a hundred-odd paths must not mean a hundred-odd connections.
    checks.check(
        TargetHandler.requests > 10 and TargetHandler.connections * 4 < TargetHandler.requests,
        "the path list is pipelined rather than one connection per path",
        f"{TargetHandler.requests} requests over {TargetHandler.connections} connections",
    )


def check_regex_without_sv(checks):
    """The README promises the regex script also works without -sV."""
    plain_http_port = claim_port(8080)
    if plain_http_port is None:
        checks.skip("http-vulners-regex works without -sV", "port 8080 is busy")
        return

    serve(TargetHandler, plain_http_port)
    output = run_nmap([
        "-Pn", "-p", str(plain_http_port),
        "--script", script("http-vulners-regex.nse"),
        "127.0.0.1",
    ])
    checks.check("cpe:/a:f5:nginx:1.13.4" in output,
                 "http-vulners-regex works without -sV on a well known http port",
                 output)


def check_free_script(checks, target_port, api_port):
    """vulners.nse against the stand-in burp endpoint."""
    ApiHandler.burp_queries.clear()

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", ",".join([script("http-vulners-regex.nse"), script("vulners.nse")]),
        "--script-args",
        f"vulners.api_host=127.0.0.1,vulners.api_port={api_port},vulners.mincvss=7.0",
        "127.0.0.1",
    ])

    checks.check(CANNED_VULN_ID in output,
                 "vulners reports the vulnerability returned by the API", output)
    checks.check("cvss3.1: 7.5" in output,
                 "vulners renders the CVSS version and score", output)
    checks.check(f"{CANNED_EXPLOIT_ID}" in output and "*EXPLOIT*" in output,
                 "vulners marks exploits", output)
    checks.check(LOW_VULN_ID not in output,
                 "vulners honours mincvss", output)
    checks.check(any(q.get("type") == "cpe" for q in ApiHandler.burp_queries),
                 "vulners asks the burp endpoint for CPEs",
                 str(ApiHandler.burp_queries[:3]))
    cpe_queries = [q.get("software", "") for q in ApiHandler.burp_queries
                   if q.get("type") == "cpe"]
    checks.check(cpe_queries and all(q.startswith("cpe:/") and "%" not in q
                                     for q in cpe_queries),
                 "vulners sends the CPE unescaped, as the API needs it",
                 str(cpe_queries[:3]))
    checks.check(any("Vulners NMAP" in (ua or "") for ua in ApiHandler.seen_user_agents),
                 "vulners identifies itself with a User-Agent",
                 str(ApiHandler.seen_user_agents[:3]))
    checks.check(re.search(r"^\|   cpe:/", output, re.M) is not None,
                 "vulners reports under the CPE, not through the software fallback",
                 output)
    checks.check(ApiHandler.compressed_replies > 0,
                 "the free script asks for a compressed answer and reads it",
                 f"compressed replies: {ApiHandler.compressed_replies}")


def check_enterprise_script(checks, target_port, api_port):
    """vulners_enterprise against the stand-in v4 API."""
    ApiHandler.seen_api_keys.clear()
    ApiHandler.audit_batches.clear()

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", ",".join([script("http-vulners-regex.nse"),
                              script("vulners_enterprise.nse")]),
        "--script-args",
        f"vulners_enterprise.api_key={FAKE_KEY},"
        f"vulners_enterprise.api_host=127.0.0.1,"
        f"vulners_enterprise.api_port={api_port}",
        "127.0.0.1",
    ])

    checks.check(CANNED_VULN_ID in output,
                 "vulners_enterprise reports the vulnerability returned by the API", output)
    checks.check("cvss3.1: 7.5" in output,
                 "vulners_enterprise renders the CVSS version and score", output)
    checks.check(CANNED_EXPLOIT_ID in output and "HAS EXPLOIT" in output,
                 "vulners_enterprise surfaces the referenced exploit", output)
    checks.check("ALPINE:CVE-2018-16843" not in output,
                 "vulners_enterprise ignores non-exploit references", output)
    checks.check(FAKE_KEY in ApiHandler.seen_api_keys,
                 "vulners_enterprise authenticates with the X-Api-Key header",
                 f"keys seen by the API: {ApiHandler.seen_api_keys}")
    checks.check(FAKE_KEY not in output,
                 "the API key is not printed into nmap output", output)
    checks.check(ApiHandler.audit_batches and max(ApiHandler.audit_batches) > 1,
                 "every CPE of a port is audited in one batched request",
                 f"batch sizes: {ApiHandler.audit_batches}")
    checks.check(len(ApiHandler.audit_batches) == 1,
                 "one port means one audit request",
                 f"batch sizes: {ApiHandler.audit_batches}")


def check_enterprise_without_key(checks, target_port, api_port):
    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", script("vulners_enterprise.nse"),
        "--script-args", f"vulners_enterprise.api_host=127.0.0.1,"
                         f"vulners_enterprise.api_port={api_port}",
        "127.0.0.1",
    ], env={k: v for k, v in os.environ.items() if k != "VULNERS_API_KEY"})

    checks.check("vulners_enterprise:" not in output,
                 "vulners_enterprise produces no output without an API key", output)


def check_xml_output(checks, target_port, api_port, tmp_xml):
    """Structured output must survive into -oX, not only into the text report."""
    run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", ",".join([script("http-vulners-regex.nse"),
                              script("vulners_enterprise.nse")]),
        "--script-args",
        f"vulners_enterprise.api_key={FAKE_KEY},"
        f"vulners_enterprise.api_host=127.0.0.1,"
        f"vulners_enterprise.api_port={api_port}",
        "-oX", str(tmp_xml),
        "127.0.0.1",
    ])

    xml = tmp_xml.read_text() if tmp_xml.exists() else ""
    checks.check('<script id="vulners_enterprise"' in xml,
                 "the enterprise result reaches the XML output", xml[:1500])
    checks.check(f'key="id">{CANNED_VULN_ID}<' in xml.replace("&#", "&#"),
                 "XML output carries the vulnerability id as a structured element",
                 xml[:1500])
    checks.check('key="cvss_type">cvss3.1<' in xml,
                 "XML output carries the cvss version as a structured element",
                 xml[:1500])

    # nmap copies its own command line into the report, so a key passed with
    # --script-args lands there whatever the script does. What the script
    # controls is its own output, and that must stay clean.
    script_elements = re.findall(r"<script id=\"vulners[^>]*>.*?</script>", xml, re.S)
    checks.check(script_elements and all(FAKE_KEY not in el for el in script_elements),
                 "the API key never appears in the script's own XML output",
                 "\n".join(script_elements)[:800])


def check_key_from_env_stays_out_of_reports(checks, target_port, api_port, tmp_xml):
    """A key taken from the environment must not reach the report at all."""
    env = dict(os.environ)
    env["VULNERS_API_KEY"] = FAKE_KEY

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", script("vulners_enterprise.nse"),
        "--script-args", f"vulners_enterprise.api_host=127.0.0.1,"
                         f"vulners_enterprise.api_port={api_port}",
        "-oX", str(tmp_xml),
        "127.0.0.1",
    ], env=env)

    xml = tmp_xml.read_text() if tmp_xml.exists() else ""

    checks.check("vulners_enterprise:" in output,
                 "VULNERS_API_KEY is picked up by the script", output[-800:])
    checks.check(FAKE_KEY not in xml,
                 "a key taken from the environment stays out of the XML report entirely",
                 xml[:800])
    checks.check(FAKE_KEY not in output,
                 "a key taken from the environment stays out of the text report")


def host_sections(output):
    """The result keys each scanned host reported, one list per host."""
    per_host = []
    for report in output.split("Nmap scan report for")[1:]:
        per_host.append(sorted(re.findall(r"^\|   (\S+):\s*$", report, re.M)))
    return per_host


def check_scan_cache(checks, target_port, api_port):
    """Two hosts in one scan must not repeat identical audits."""
    ApiHandler.audit_batches.clear()
    ApiHandler.requests_by_path.clear()

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", ",".join([script("http-vulners-regex.nse"),
                              script("vulners_enterprise.nse")]),
        "--script-args",
        f"vulners_enterprise.api_key={FAKE_KEY},"
        f"vulners_enterprise.api_host=127.0.0.1,"
        f"vulners_enterprise.api_port={api_port}",
        "127.0.0.1", "localhost",
    ])

    # Counting only the audit endpoint hid a defect: the second host used to
    # skip the audit and fall back to the smart endpoint, costing two extra
    # requests and reporting a poorer result.
    total = sum(ApiHandler.requests_by_path.values())
    checks.check(total == 1,
                 "two hosts running the same software cost one API request",
                 f"requests: {ApiHandler.requests_by_path}\n{output[-800:]}")

    sections = host_sections(output)
    checks.check(len(sections) == 2 and sections[0] == sections[1] and sections[0],
                 "both hosts report the same result, not just the first one",
                 f"{sections}\n{output[-1200:]}")


# -------------------------------------------------------------------- live

def check_live(checks, target_port):
    """Optional: verify the real API still answers in the shape we imitate."""
    api_key = os.environ.get("VULNERS_API_KEY")
    if not api_key:
        checks.skip("live API contract", "VULNERS_API_KEY is not set")
        return

    output = run_nmap([
        "-Pn", "-sV", "-p", str(target_port),
        "--script", ",".join([script("http-vulners-regex.nse"),
                              script("vulners_enterprise.nse")]),
        "127.0.0.1",
    ])

    checks.check("vulners_enterprise:" in output,
                 "the live API answers the enterprise script", output[-2000:])
    checks.check(re.search(r"cvss[\d.]*: \d", output) is not None,
                 "live results carry a score and its cvss version", output[-2000:])
    checks.check(api_key not in output,
                 "the live API key never appears in nmap output")

    # The free endpoint is checked against an Apache banner: it answers that
    # CPE, while both nginx spellings come back empty, which would leave the
    # check asserting on silence.
    apache_port = serve(ApacheTargetHandler)
    free_output = run_nmap([
        "-Pn", "-sV", "-p", str(apache_port),
        "--script", script("vulners.nse"),
        "127.0.0.1",
    ])
    checks.check("vulners:" in free_output,
                 "the live free endpoint answers the key-less script",
                 free_output[-2000:])
    checks.check("cpe:/a:apache:http_server:2.4.7" in free_output,
                 "the live free lookup reports under the CPE it asked about",
                 free_output[-2000:])
    checks.check(re.search(r"CVE-\d{4}-\d+", free_output) is not None,
                 "the live free lookup returns real bulletins",
                 free_output[-2000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="additionally check the real vulners.com API")
    args = parser.parse_args()

    target_port = serve(TargetHandler)
    api_port = serve(ApiHandler)

    checks = Checks()
    tmp_xml = REPO / "tests" / "e2e" / "_e2e_output.xml"

    try:
        check_regex_script(checks, target_port)
        check_free_script(checks, target_port, api_port)
        check_enterprise_script(checks, target_port, api_port)
        check_enterprise_without_key(checks, target_port, api_port)
        check_xml_output(checks, target_port, api_port, tmp_xml)
        check_key_from_env_stays_out_of_reports(checks, target_port, api_port, tmp_xml)
        check_scan_cache(checks, target_port, api_port)
        check_regex_without_sv(checks)

        if args.live:
            check_live(checks, target_port)
        else:
            checks.skip("live API contract", "run with --live to include it")
    finally:
        if tmp_xml.exists():
            tmp_xml.unlink()

    return checks.report()


if __name__ == "__main__":
    sys.exit(main())
