# Contributing

## Running the checks

Everything runs offline. No API key, no network access, no scanning of anyone.

```sh
# 1. unit tests - executed inside nmap, so the scripts see the real NSE libraries
nmap -sn -Pn --script ./tests/run.nse --script-args testdir=tests,root=. 127.0.0.1

# 2. end-to-end tests - real nmap against a local web server and a stand-in API
python3 tests/e2e/run_e2e.py

# 3. repository hygiene - secrets, AI artifacts, clutter, line endings
python3 tools/check.py
```

The end-to-end suite is offline by default. To additionally check that the real
API still answers in the shape the doubles imitate:

```sh
VULNERS_API_KEY=<token> python3 tests/e2e/run_e2e.py --live
```

**Run a script by its absolute path when testing by hand.** nmap resolves a
relative `--script ./vulners.nse` against its own `script.db` first, so it
silently runs the copy installed with nmap instead of the one you are editing:

```sh
nmap -sV --script "$PWD/vulners.nse" <target>     # your file
nmap -sV --script ./vulners.nse <target>          # possibly nmap's own copy
```

**The data file has the same trap.** `nmap.fetchfile` looks in the nmap
installation's `nselib/data/` before the working directory, so once
`http-vulners-regex.json` has been installed there, editing the copy in the
checkout changes nothing. Remove the installed copy while developing, or check
with `-d2` which one was read.

Run all three from the repository root. Each exits non-zero on failure, and CI
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

`tests/e2e/run_e2e.py` starts two local servers - a web server with recognisable
version banners and a stand-in Vulners API - and runs the real `nmap` binary
against them. That is what catches problems the unit suite cannot see, such as
an argument arriving as a string where the http library expects a number.

## Cutting a release

Tag it and push the tag; `.github/workflows/release.yml` does the rest:

```sh
git tag -a v1.5 -m "nmap-vulners 1.5"
git push origin v1.5
```

The workflow runs the three gates first, then builds `.tar.gz` and `.zip`
archives with `git archive` - so they hold exactly what a user downloads: the
three scripts, their two data files, both installers, the README and the
LICENSE - writes `SHA256SUMS`, and publishes a release with generated notes.

Nothing needs to be built by hand, and a release whose gates fail is never
published. `workflow_dispatch` re-runs it for an existing tag.

The per-script `api_version` is a different number: it identifies the request
generation to vulners.com and travels in the `User-Agent`, so it moves when the
request shape changes, not when a release is cut. Check any bump against the
live service before shipping it - the header is what the service uses to tell
plugin generations apart.

## The installers

`install.sh` (POSIX) and `install.ps1` (Windows) both:

* ask nmap where its data directory is, by reading which `nse_main.lua` it opens
  under `-d2` - that reflects the build, the package manager and `NMAPDIR`
* **replace** an existing `vulners.nse`; nmap ships one of its own, and leaving
  it in place means nmap keeps running that copy
* verify by resolution, not by copying: they check that `--script vulners`
  resolves to the file they installed, and warn when it does not

CI runs both on Linux, macOS and Windows, installs, verifies and uninstalls
again, so a change to either is exercised on the platforms it claims.

## House rules

* **Comments and documentation in the project files are English only.**
* Never commit an API key. `vulners_enterprise.nse` reads the token from
  `--script-args api_key=`, from `VULNERS_API_KEY`, or from a file given with
  `api_key_file=`; keep that file outside the repository.
* No AI assistant leftovers (`CLAUDE.md`, `.claude/`, `.cursorrules`, and the
  like), no OS or editor clutter, no scan output. `.gitignore` covers the usual
  names and `tools/check.py` is the second barrier.
* `http-vulners-regex.json` is data with rules: each entry needs an
  `alias` of the form `cpe:/<part>:<vendor>:<product>` and a `regex` that is a
  valid Lua pattern with exactly one capture - the version. Patterns without a
  capture can never produce a CPE, so the test suite rejects them.
* Changes to a script want a test that fails without them.
