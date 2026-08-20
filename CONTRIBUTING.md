# Contributing

## Running the checks

Everything runs offline. No API key, no network access, no scanning of anyone.

```sh
# 1. unit tests - executed inside nmap, so the scripts see the real NSE libraries
nmap -sn -Pn --script ./tests/run.nse --script-args testdir=tests,root=. 127.0.0.1

# 2. end-to-end tests - real nmap against a local web server and a stand-in API
python3 tests/e2e/run_e2e.py

# 3. repository hygiene - secrets, AI artifacts, clutter, line endings, and a
#    global read that NSE would turn into a lost result
python3 tools/check.py

# 4. the catalogue is shaped the way the script reads it
python3 tools/catalog.py --check

# 5. the XML contract every importer reads still catches a broken report
python3 tools/xml_contract.py --selftest

# 6. the PCRE-to-Lua translator still makes the decisions it is supposed to
python3 tools/fingerprints/selftest.py

# 7. the publish gate still refuses a rebuild that loses ground
python3 tools/catalog_diff.py --selftest
```

The last four are the data and the tools that publish it. They matter as much as
the first three, because the catalogue rebuilds itself on a schedule and
publishes without a human: a translator that starts writing patterns nothing can
execute, or a gate that stops noticing loss, reaches every installed script
within a day and there is no release to hold it back.

The unit suite takes under a second and the end-to-end suite about seven, so
there is no reason to run them one at a time or only at the end. The ten unit
suites are `test_harness`, `test_config`, `test_catalog`, `test_fingerprints`,
`test_channels`, `test_sweep`, `test_lookup`, `test_keyed`, `test_render` and
`test_notice`. Working on one, load just that file:

```sh
nmap -sn -Pn --script ./tests/run.nse \
  --script-args testdir=tests,root=.,only=test_sweep.lua 127.0.0.1
```

The end-to-end checks run in parallel, each against its own pair of servers.
`--jobs 1` serialises them, which is worth doing when a check fails in a way that
looks like interference.

The end-to-end suite is offline by default. To additionally check that the real
API still answers in the shape the doubles imitate:

```sh
VULNERS_API_KEY=<token> python3 tests/e2e/run_e2e.py --live
```

**A passing test is not proof.** Six assertions in this repository were once
green while measuring nothing. Before trusting a new test, break the behaviour it
covers on a scratch copy of the script and confirm the test fails:

```sh
cp vulners.nse /tmp/intact && <edit vulners.nse> && <run the gate> && cp /tmp/intact vulners.nse
```

**Give the mutation run a timeout.** One mutation did not fail the suite, it
hung it, and a harness with no per-run bound turns that finding into an
afternoon. The same lesson holds outside the tests: every CI job now carries
`timeout-minutes`, because three of them once sat on `apt-get install` for
twenty-five minutes against a six-hour default.

**Run a script by its absolute path when testing by hand.** nmap resolves a
relative `--script ./vulners.nse` against its own `script.db` first, so it
silently runs the copy installed with nmap instead of the one you are editing:

```sh
nmap -sV --script "$PWD/vulners.nse" <target>     # your file
nmap -sV --script ./vulners.nse <target>          # possibly nmap's own copy
```

**The script carries no fingerprint data.** It downloads three dictionaries at
scan time, from a GitHub branch, so the corpus can grow without a release:

```
catalog/index.json          the manifest: schema and serial
catalog/fingerprints.json   721 product and version rules
catalog/paths.json          939 paths the sweep requests
catalog/probes.json         6 targeted version probes
```

Those four files are the only copy - there is no second "editable source". Edit
them directly for a one-off correction, then:

```sh
python3 tools/catalog.py --index     # bump the serial, or nobody downloads it
python3 tools/catalog.py --check     # the checks the script itself applies
```

`catalog/fingerprints.json`, `catalog/paths.json` and `catalog/probes.json` are
normally **generated** by `tools/fingerprints/build.py` from checkouts of Recog,
Wappalyzer, WhatWeb, FingerprintHub and nuclei-templates, and rebuilt weekly by
`.github/workflows/catalog-refresh.yml`.
A hand edit survives the next rebuild only if the entry carries no `source`
field. You never need to rebuild them to work on the script.

**While working, point the script at your own catalogue** rather than the
published one, or you will be testing against whatever is live:

```sh
python3 -m http.server 8000 --directory catalog &
nmap -sV --script "$PWD/vulners.nse" \
  --script-args vulners.catalog_url=http://127.0.0.1:8000/ <target>
```

`vulners.catalog=none` turns the download off entirely; the script then looks up
only what nmap itself identified, which is also what happens on a machine with
no route to GitHub.

Run all seven from the repository root. Each exits non-zero on failure, and CI
runs exactly the same commands.

Useful while working on one thing:

```sh
# only the cases whose name matches a pattern
nmap -sn -Pn --script ./tests/run.nse \
  --script-args testdir=tests,root=.,filter=mincvss 127.0.0.1

# list every passing case as well
nmap -sn -Pn --script ./tests/run.nse \
  --script-args testdir=tests,root=.,verbose=1 127.0.0.1
```

## How the tests are built

`tests/run.nse` is a prerule script, so the suite executes inside nmap itself.
The scripts under test are loaded into an isolated environment with `json`,
`stdnse`, `url` and `shortport` provided by the nmap installation that runs the
tests. Only the network is faked: `tests/lib/harness.lua` supplies a
programmable `http` double, plus stand-ins for `nmap` and `stdnse` when a test
needs to inspect what was logged.

Adding a test file means adding it to `TEST_FILES` in `tests/run.nse`. A test
file returns a list of `{name = ..., fn = ...}` entries.

`tests/e2e/run_e2e.py` runs the real `nmap` binary against local servers: a web
server with recognisable version banners, a stand-in Vulners API, and one serving
`catalog/` out of the working tree so the checks exercise the dictionaries about
to be committed rather than whatever is published. That is what catches problems
the unit suite cannot see, such as an argument arriving as a string where the
http library expects a number.

Each check gets its own servers and its own counters, which is what lets them run
at the same time. A check that needs to count requests must therefore read them
off its own `world`, never off a handler class - the counters used to live there,
and that is precisely why the checks could not overlap.

## Cutting a release

Tag it and push the tag; `.github/workflows/release.yml` does the rest:

```sh
git tag -a v2.0 -m "nmap-vulners 2.0"
git push origin v2.0
```

The workflow runs the gates first, then builds `.tar.gz` and `.zip` archives
with `git archive` - so they hold exactly what a user downloads: `vulners.nse`,
`catalog/*.json`, both installers, the README and the LICENSE, and nothing else:
`.gitattributes` keeps the tests, the tools, the workflows and the README's
695 KB demonstration out of it - writes
`SHA256SUMS`, and publishes a release with generated notes.

The catalogue ships in the archive even though nothing installs it and the
script never reads it from disk. It is a snapshot, useful for serving locally
with `vulners.catalog_url` on a network that cannot reach GitHub; the live
copies are on the `catalog` branch and are what an ordinary scan downloads.

Nothing needs to be built by hand, and a release whose gates fail is never
published. `workflow_dispatch` re-runs it for an existing tag.

The script's `api_version` is a different number: it identifies the request
generation to vulners.com and travels in the `User-Agent`, so it moves when the
request shape changes, not when a release is cut. The free endpoint sits behind
a rule that answers 403 to a keyless request whose User-Agent does not contain
`Vulners NMAP Plugin`, so that substring is a wire contract, not a label. Check any bump against the
live service before shipping it - the header is what the service uses to tell
plugin generations apart.

## The installers

`install.sh` (POSIX) and `install.ps1` (Windows) both:

* ask nmap where its data directory is, by reading which `nse_main.lua` it opens
  under `-d2` - that reflects the build, the package manager and `NMAPDIR`
* **replace** an existing `vulners.nse`; nmap ships one of its own, and leaving
  it in place means nmap keeps running that copy
* **remove the 1.x files** - `vulners_enterprise.nse`, `http-vulners-regex.nse`
  and their two data files. A leftover fingerprint script still carries the
  `default` category and keeps sweeping targets under a plain `-sC`
* **offer to store an API key**, validating it against the API first and writing
  it mode 600. Under `sudo` they resolve the home directory from `$SUDO_USER`,
  because nmap resolves `~/.nmap` through `getpwuid(getuid())` and not `$HOME`.
  `--no-key` / `-NoKey` skips the prompt, and so does having no terminal to ask
  on - CI, a Dockerfile, cron. **The question is asked on `/dev/tty`, not on
  stdin**, and it has to be: installed the documented way, `curl ... | sh`,
  stdin is the pipe carrying the script, so testing it found no terminal and
  skipped the offer on exactly the path most people take - and reading it would
  have eaten the part of the script `sh` had not parsed yet
* **refuse a ref that does not carry this release.** In download mode they fetch
  `vulners.nse` from `--ref` (default `master`) and check it for the line naming
  where the catalogue lives. A ref still holding 1.x would otherwise be
  installed while the two data files 1.x needs were being deleted, which is a
  downgrade to something that cannot run, arriving silently
* verify by resolution, not by copying: they check that `--script vulners`
  resolves to the file they installed, and warn when it does not

CI runs both on Linux, macOS and Windows, installs, verifies and uninstalls
again, so a change to either is exercised on the platforms it claims.

## The workflows

Four of them: `ci.yml` on every push and pull request, `release.yml` on a tag,
`catalog.yml` publishing `catalog/` to the `catalog` branch, and
`catalog-refresh.yml` rebuilding the dictionaries weekly from the upstream
corpora.

Two things they learned by being run rather than read. Every job carries
`timeout-minutes`, because the default is six hours and a hung job is a publish
that silently never happens. And every apt call goes through
`.github/actions/apt`, which bounds each one at seven minutes and retries once:
a healthy `apt-get install` on these runners takes 12 to 49 seconds and a bad
one has never finished, so a hang is not a slow success and should not be
waited out. A hang is also not a failure - it never returns, so nothing retries
it by itself.

## House rules

* **Comments and documentation in the project files are English only.**
* Never commit an API key. The script reads a token from
  `--script-args vulners.api_key=`, from `vulners.api_key_file=`, from
  `VULNERS_API_KEY`, or from `~/.nmap/vulners.key`; keep any such file outside
  the repository. `tools/check.py` looks for a bare 64-character alphanumeric
  line, which is the shape of a key file committed by accident.
* No AI assistant leftovers (`CLAUDE.md`, `.claude/`, `.cursorrules`, and the
  like), no OS or editor clutter, no scan output. `.gitignore` covers the usual
  names and `tools/check.py` is the second barrier.
* `catalog/fingerprints.json` is data with rules: each entry needs an
  `alias` of the form `cpe:/<part>:<vendor>:<product>` and a `regex` that is a
  valid Lua pattern with exactly one capture - the version. Patterns without a
  capture can never produce a CPE, so the test suite rejects them.
* Changes to a script want a test that fails without them.
