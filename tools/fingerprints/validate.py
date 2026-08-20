#!/usr/bin/env python3
"""Ask the service whether each imported identity is one it can answer.

    tools/fingerprints/validate.py --in catalog/fingerprints.json

A CPE that exists in the NVD dictionary is not the same thing as a CPE the
Vulners API returns bulletins for, and this repository has measured the gap:
`microsoft:internet_information_server` is referenced by more advisories than
`...services` and returns nothing, while `...services` returns eleven.
`f5:nginx` returns 124 where `nginx:nginx` returns 4 and `igor_sysoev:nginx` -
the spelling nmap itself emits - returns none.

So the catalogue answers "does this identity exist and is it mainstream", and
only the service answers "will this plugin get anything back". A rule whose
alias the service does not recognise is not a detection. It is a detection that
reports nothing, which reads to an operator exactly like a clean host.

The endpoint used here is the free, keyless one - the same one the script
itself uses, and deliberately so: what is measured is what will happen at scan
time. No API token is sent, in any mode.
"""

import argparse
import collections
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "https://vulners.com/api/v3/burp/software/"

# The endpoint refuses anything that does not name the plugin - measured, a
# User-Agent of "nmap-vulners fingerprint import" gets 403 where this gets 200.
# It says what it is in the parenthesis so the maintainer can tell an import
# run from a real scan in the service's own logs.
USER_AGENT = "Vulners NMAP Plugin 2.0 (fingerprint import)"

# The service is a shared resource and this is a maintenance tool, not a scan.
# Measured: 354 requests at a third of a second earned a Cloudflare 1015 with
# Retry-After: 141, and every alias after that point recorded as "could not be
# tested" - 203 of them. A throttle read as a verdict is the exact failure this
# file exists to prevent, one layer up.
PAUSE = 1.5

# How long to wait when the service says to wait, and how many times.
MAX_BACKOFF = 300
MAX_RETRIES = 4

# Python does not use the system trust store on macOS, so a plain urlopen fails
# with CERTIFICATE_VERIFY_FAILED and every identity comes back "unknown" -
# which looks exactly like the service having no opinion. Being explicit about
# the CA bundle is what keeps a transport failure from being read as an answer.


def _context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


CONTEXT = _context()


def ask(alias, version, timeout=20):
    """Bulletins the service returns for one identity, or None when it
    errored."""
    query = urllib.parse.urlencode({
        "software": "%s:%s" % (alias, version),
        "version": version,
        "type": "cpe",
    })
    request = urllib.request.Request(
        ENDPOINT + "?" + query, headers={"User-Agent": USER_AGENT})
    payload = None
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=CONTEXT) as response:
                payload = json.loads(response.read().decode("utf-8",
                                                            "replace"))
            break
        except urllib.error.HTTPError as error:
            if error.code == 429:
                # Being throttled says nothing about the identity. Wait as long
                # as the service asks, then ask again; give up only after that.
                wait = error.headers.get("Retry-After")
                try:
                    wait = min(int(wait), MAX_BACKOFF)
                except (TypeError, ValueError):
                    wait = 60 * (attempt + 1)
                print("      rate limited, waiting %ds" % wait, flush=True)
                time.sleep(wait)
                continue
            try:
                payload = json.loads(error.read().decode("utf-8", "replace"))
            except Exception:
                return None
            break
        except Exception:
            return None

    if payload is None:
        return None

    result = payload.get("result")
    data = payload.get("data")
    if not isinstance(data, dict):
        return 0 if result == "warning" else None

    # "warning" with nothing found is an authoritative empty answer, and an
    # error naming the cpe means the identity was understood and holds nothing.
    search = data.get("search")
    if isinstance(search, list):
        return len(search)
    if result == "warning":
        return 0
    error_text = str(data.get("error", ""))
    if "Nothing found" in error_text or "nothing found" in error_text:
        return 0
    return None


# How many real versions to try per identity before calling it silent. One is
# not enough and the endpoint is the reason: asked about `cpe:/a:apple:cups`
# at 2.3.1 it answers "Nothing found for the given cpe" - the byte-identical
# answer it gives for `cpe:/a:totally:nonexistent_product`. A clean release and
# an unknown identity are indistinguishable in a single query, so the only way
# to tell them apart is to ask about more than one release.
VERSIONS_PER_ALIAS = 3


def versions_for(entries):
    """The real versions each alias can be asked about, most specific first.

    A made-up version would test the wrong thing, so every version used here is
    one an upstream catalogue recorded as observed in the field.
    """
    picked = collections.defaultdict(list)
    for entry in sorted(entries.values(), key=lambda e: e["alias"]):
        example = entry.get("example")
        if not example or not example.get("version"):
            continue
        version = example["version"].strip()
        if not version or not version[0].isdigit():
            continue
        bucket = picked[entry["alias"]]
        if version not in bucket:
            bucket.append(version)
    return picked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="source",
                        default="catalog/fingerprints.json")
    parser.add_argument("--cache",
                        default="tools/fingerprints/alias-bulletins.json",
                        help="measured counts, so a re-run costs no requests")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after this many new queries")
    args = parser.parse_args()

    with open(args.source, encoding="utf-8") as handle:
        document = json.load(handle)
    entries = document.get("rules", document)

    cache = {}
    if os.path.exists(args.cache):
        with open(args.cache, encoding="utf-8") as handle:
            cache = json.load(handle)

    versions = versions_for(entries)
    aliases = sorted({entry["alias"] for entry in entries.values()})

    asked = 0
    stop = False
    for alias in aliases:
        if alias in cache or stop:
            continue
        candidates = versions.get(alias) or []
        if not candidates:
            cache[alias] = {"count": None,
                            "why": "no example version to ask with"}
            continue

        best, tried, failures = 0, [], 0
        for version in candidates[:VERSIONS_PER_ALIAS]:
            if args.limit and asked >= args.limit:
                stop = True
                break
            count = ask(alias, version)
            asked += 1
            time.sleep(PAUSE)
            if count is None:
                failures += 1
                continue
            tried.append([version, count])
            best = max(best, count)
            if count:
                # One release with bulletins settles it: the identity answers.
                break
        if stop and not tried:
            break

        if not tried and failures:
            # Every attempt failed at the transport. Recording that as "empty"
            # would be recording a network problem as a fact about the service.
            cache[alias] = {"count": None, "why": "every request failed"}
        else:
            cache[alias] = {"count": best, "tried": tried}
        print("  %-52s %-14s %s"
              % (alias, tried[0][0] if tried else "-",
                 "?" if not tried else best), flush=True)

        if asked % 25 < VERSIONS_PER_ALIAS:
            with open(args.cache, "w", encoding="utf-8") as handle:
                json.dump(cache, handle, indent=1, sort_keys=True)

    with open(args.cache, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=1, sort_keys=True)
        handle.write("\n")

    tally = collections.Counter()
    for alias in aliases:
        record = cache.get(alias) or {}
        count = record.get("count")
        verdict = "unknown" if count is None else (
            "answers" if count else "empty")
        tally[verdict] += 1
    print("\naliases: %d asked this run, %s" % (asked, dict(tally)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
