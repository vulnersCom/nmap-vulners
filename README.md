<div align="center">

# nmap-vulners

**Turn an nmap service scan into a ranked list of CVEs, exploits and what is
being attacked in the wild.**

One NSE script that takes the software nmap already identified, asks the
[Vulners](https://vulners.com) database what is known about it, and prints the
answer inside the scan report - worst first, by what is actually exploitable.

[![tests](https://img.shields.io/github/actions/workflow/status/vulnersCom/nmap-vulners/ci.yml?branch=master&label=tests&logo=github)](https://github.com/vulnersCom/nmap-vulners/actions)
[![license](https://img.shields.io/badge/license-Nmap%20Public%20Source-0e7c86)](LICENSE)
[![nmap](https://img.shields.io/badge/nmap-7.x-4b8bbe?logo=gnu)](https://nmap.org)
[![data](https://img.shields.io/badge/data-vulners.com-ff5f56)](https://vulners.com)
[![stars](https://img.shields.io/github/stars/vulnersCom/nmap-vulners?logo=github&color=yellow)](https://github.com/vulnersCom/nmap-vulners/stargazers)

</div>

---

## What it does

One NSE script. It takes the software nmap identified, asks Vulners what is
known about it, and prints the answer ranked so that the findings somebody is
actually being attacked with come first.

On an HTTP port it also fingerprints the web stack itself, which names software
`-sV` cannot see - an application framework, a CMS, the PHP version behind a
reverse proxy. 722 rules read the parts of a response that carry a version: the
`Server` header, `X-Powered-By`, cookies, the page title, `<meta>` tags,
`<script src>` filenames and the body. Those identities are looked up too, and
published onto the port so the rest of the scan can use them.

Two things it does beyond the sweep:

* **it reads nmap's own service banner.** When `-sV` could not name a service,
  the raw banner is matched against rules for FTP, SMTP, SSH, MySQL, DNS, NTP,
  LDAP and more. That costs no extra request, and it is the case where a port
  would otherwise report nothing at all.
* **it asks a product that will not say.** A CMS that names itself and hides its
  version is common, and no amount of pattern matching extracts a number that is
  not on the page. When the product is recognised and the version is not, one
  request goes to the place that answers - `/CHANGELOG.txt` for Drupal,
  `/administrator/manifests/files/joomla.xml` for Joomla. A host running none of
  the six probed products is sent nothing extra.

```sh
nmap -sV --script vulners <target>
```

That is the whole interface. It works without an API key; with one it tells you
more. There is no mode switch.

```
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.7 ((Ubuntu))
| vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 56 exploitable
|   SEVERITY  CVSS    AI  FLAGS    ID
|   ========  ====  ====  =======  ====================================
|   CRITICAL  10.0   8.8  EXP      3E6BA608-776F-5B1F-9BA5-589CD2A5A351
|   CRITICAL   9.8   9.9  EXP      1337DAY-ID-39214
|   CRITICAL   9.8   9.6  EXP      PACKETSTORM:171631
|   CRITICAL   9.8   9.9           CVE-2021-44790
|   CRITICAL   9.8   9.8           CVE-2023-25690
|_  262 more not shown; -v shows all, -vv adds links and provenance
```

With a key, the same scan of the same host answers differently - `KEV` means
CISA has recorded the vulnerability as exploited in the wild, and `EPSS` is the
published probability that it will be:

```
| vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 78 exploitable
|   SEVERITY  CVSS  EPSS  FLAGS    ID
|   ========  ====  ====  =======  ======================================
|   CRITICAL   9.1  >99%  KEV EXP  CVE-2024-38475
|   CRITICAL   9.1  >99%  KEV      CNVD-2024-36387
|   CRITICAL   9.0  >99%  KEV EXP  CVE-2021-40438
|   CRITICAL  10.0   99%  EXP      3E6BA608-776F-5B1F-9BA5-589CD2A5A351
|   CRITICAL   9.8   97%  EXP      CVE-2021-44790
|_  262 more not shown; -v shows all, -vv adds links and provenance
```

Same 272 findings, a different order, a different top row - and 22 more of them
known to be exploitable, because a key links each exploit to the CVEs it
exploits. Both of these are real answers from vulners.com, captured against a
local server presenting that banner.

## Ranking

Facts outrank predictions. Findings are ordered:

1. **CISA KEV** - recorded as exploited in the wild
2. **SSVC `active`** - a coordinator's judgement that exploitation is happening
3. **an exploit exists** - the code is published, for this or for a CVE it names
4. **high EPSS** - a model expects exploitation
5. everything else

CVSS breaks ties inside a band, not across them: an exploited 7.5 is a worse
problem than an unexploited 9.8, and this is the order that says so.

Columns follow the data. A signal the answer did not carry loses its column
rather than showing an empty cell, because a blank EPSS reads as "quiet", and
that is a claim an absent field cannot support.

## What an API key adds

| | |
|---|---|
| **Without a key** | Every CPE nmap found is looked up on the free endpoint. Findings, scores, exploit flags and Vulners' own AI score. No credits, no account |
| **A key, no credits** | Each finding gains what the id endpoint knows: titles, links, dates, the exploit-to-CVE linkage, CISA KEV, and - depending on the licence - EPSS and SSVC |
| **A key, one credit** | Software the free path could not name at all is identified from its raw banner. This is the only thing here that costs anything, and only for a service with no CPE |

A port that already carries a CPE never costs a credit: measured across four
products, the free lookup returns the **same CVEs** as the paid one for a CPE.
What a credit buys is identification, not more vulnerabilities.

Free keys are at [vulners.com/userinfo](https://vulners.com/userinfo).

## Install

**macOS, Linux, Kali, WSL** - one line, no arguments:

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.sh | sh
```

**Windows** - PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.ps1 | iex
```

The installer asks nmap where it keeps its data, copies the scripts and their
data files there, rebuilds the script database, and then checks that
`--script vulners` really resolves to what it just installed - nmap ships a
`vulners.nse` of its own, and this replaces it.

<details>
<summary><b>Without root, and other options</b></summary>

```sh
# into ~/.nmap, no sudo; the installer prints the NMAPDIR line to add to your profile
curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.sh | sh -s -- --user

# a specific directory
./install.sh --prefix /usr/local/share/nmap

# a specific release
./install.sh --ref v1.5

# remove everything it installed
./install.sh --uninstall
```

PowerShell takes the same options: `-User`, `-Prefix`, `-Ref`, `-Uninstall`.

</details>

<details>
<summary><b>From a checkout</b></summary>

```sh
git clone https://github.com/vulnersCom/nmap-vulners
cd nmap-vulners
./install.sh
```

The installer uses the files next to it, so this installs exactly what you
cloned. Running the scripts straight out of the checkout works too:

```sh
nmap -sV --script "$PWD/vulners.nse" <target>
```

> Use an **absolute** path when running from a checkout. nmap resolves a
> relative `--script ./vulners.nse` against its own `script.db` first, and
> quietly runs the copy that shipped with nmap instead of yours.

</details>

<details>
<summary><b>By hand</b></summary>

One file: copy `vulners.nse` into `<nmap data dir>/scripts/` and run
`sudo nmap --script-updatedb`. Its pattern and path data are embedded, so there
is nothing else to place - and nothing to forget, which used to produce a script
that ran, found nothing, and said nothing about why.

If you are upgrading from 1.x, delete `vulners_enterprise.nse` and
`http-vulners-regex.nse` from that directory as well. A leftover
`http-vulners-regex.nse` still carries the `default` category and keeps sweeping
targets under a plain `-sC`. The installer does this for you.

The nmap data directory is usually `/usr/share/nmap` (Debian, Ubuntu, Kali),
`/usr/local/share/nmap` (built from source), `/opt/homebrew/share/nmap`
(Homebrew) or `C:\Program Files (x86)\Nmap` (Windows). To be certain, ask nmap:

```sh
nmap -d2 --script-help probe 2>&1 | grep nse_main.lua
```

The directory holding `nse_main.lua` is the one this nmap uses.

</details>

## Script arguments

| Argument | Default | Meaning |
|---|---|---|
| `vulners.mincvss` | `0` | Hide findings scored below this. Unscored bulletins and anything with a known exploit are shown whatever the threshold |
| `vulners.paths` | the embedded 125 | Paths for the web sweep: a Lua list, one string naming a file with one path per line, or `none` to switch the sweep off |
| `vulners.width` | `80` | Terminal width the table is laid out for |
| `vulners.max_items` | `32` | Ceiling on billed items for the whole scan |
| `vulners.api_key` | - | API token. Leaky: nmap copies its own command line into `-oX` |
| `vulners.api_key_file` | - | Absolute path to a file whose first line is the token |
| `vulners.api_host` | `vulners.com` | Host name of the API |
| `vulners.api_port` | `443` | Port on `api_host` |

A bare name works too, so `--script-args mincvss=7` is enough.

The 1.x argument prefixes - `vulners_enterprise.*` and
`http-vulners-regex.paths` - are accepted for one release and print a
deprecation notice.

## Where to keep the API key

In order of preference:

1. `~/.nmap/vulners.key`, one line, mode 600 - the installer offers to write it
2. `VULNERS_API_KEY` in the environment
3. `--script-args vulners.api_key_file=/absolute/path`
4. `--script-args vulners.api_key=<token>`

The last is convenient and leaky: nmap copies its own command line into every
report, so the token ends up in the `args` attribute of `-oX` output and in your
shell history. The script itself never writes the token anywhere, including its
debug output - there is a regression test that says so.

A key file you name explicitly and that cannot be read stops the run, rather
than quietly falling back: an operator who names a file means that file.

## Where the fingerprints come from

The script does not carry them. It downloads three dictionaries once per scan,
before the first host is touched:

```
https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/
    index.json          what exists, at which serial
    fingerprints.json   722 product and version rules
    paths.json          the paths the sweep requests
    probes.json         targeted version probes
```

That is one request per scan - not per host and not per port - for 34 KB
compressed, in nmap's pre-scan phase. An installed script therefore picks up new
fingerprints without being updated.

**It writes nothing to your filesystem.** The dictionaries are held for the
duration of the scan and dropped, which is how every script nmap ships behaves:
of the 611 of them, 26 open a file for writing and every one writes only where a
script argument told it to. None keeps a cache, and neither does this.

**If they cannot be downloaded, the scan still runs.** The dictionaries feed the
web fingerprinting and nothing else, so a machine with no route to GitHub loses
that and keeps everything else: the software nmap itself identified is still
looked up, and the report says which capability was missing rather than leaving
you to read an empty result as a clean network.

| argument | what it does |
|---|---|
| `vulners.catalog_url=<url>` | fetch from a mirror instead - for an airgapped network |
| `vulners.catalog=none` | do not fetch at all; look up only what nmap named |

## How it works

```
nmap -sV
   |
   +-- service fingerprint --> port.version.cpe --------------+
   |                                                          |
   +-- vulners.nse                                            |
         reads nmap's banner for services -sV could not name   |
         on an HTTP port: requests the path list in one        |
         pipeline, matches 722 rules against the header, the   |
         title, the meta tags, the scripts and the body        |
         probes for a version when a product hid it            |
         publishes everything it recognised ------------------+
                                                               |
                                                               v
                                        GET /api/v3/burp/software/  per identity
                                          free, no key, CDN-cached
                                                               |
                                        POST /api/v3/search/id/ per 100 findings
                                          free, needs a key: enrichment
                                                               |
                                        POST /api/v4/audit/smart  only for a
                                          service with no CPE: 1 credit
                                                               |
                                                   ranked, filtered, printed
```

Answers are cached for the whole scan, keyed per identity, so a hundred
identical servers cost one lookup. Enrichment is cached per finding id, so two
web ports running overlapping software fetch each document once.

## Machine-readable output

Everything printed is also structured, so `-oX` can be parsed without touching
the human text. The script id, the two table levels and the five original
element keys are unchanged from 1.x, which is what DefectDojo, Faraday,
nmap2csv and raven read:

```xml
<script id="vulners">
  <elem key="schema">2.0</elem>
  <elem key="mode">keyed</elem>
  <table key="cpe:/a:apache:http_server:2.4.7">
    <table>
      <elem key="id">CVE-2021-40438</elem>
      <elem key="type">cve</elem>
      <elem key="severity">CRITICAL</elem>
      <elem key="cvss">9.0</elem>
      <elem key="cvss_type">cvss3.1</elem>
      <elem key="is_exploit">false</elem>
      <elem key="exploit_known">true</elem>
      <elem key="kev">true</elem>
      <elem key="epss">0.99612</elem>
      <elem key="exploitation">active</elem>
      <elem key="title">Apache HTTP Server SSRF in mod_proxy</elem>
      <elem key="href">https://vulners.com/cve/CVE-2021-40438</elem>
    </table>
  </table>
</script>
```

New in 2.0: `schema`, `mode`, `severity`, `exploit_known`, `kev`, `epss`,
`epss_percentile`, `exploitation`, `ai_score`, `title`, `published`, `href` and
`found_on`. Every one is present-or-absent, never empty. Nothing is nested more
deeply than before, because a third table level is invisible to every importer
examined.

The structured output always carries every finding that passed `mincvss`, even
the ones the verbosity ladder hides from the text - so no automation loses
findings by not passing `-v`.

**The rendered text is a break.** The `*EXPLOIT*` and `*HAS EXPLOIT*` tokens,
the per-row vulners.com URL and the tab-delimited layout are gone, replaced by
the aligned table above. Text-scraping consumers need updating; `-oX` consumers
do not.

## Scanning politely

A scan of a network asks the API far less than it looks:

* one request per software identity, and answers cached for the whole scan
* a lookup already in flight is waited for rather than repeated
* discovery goes to a **CDN-cached** endpoint, without a key even when one is
  configured, so it stays on the shared cache instead of hitting the origin
* the 125-path sweep runs over about **5 TCP connections** rather than 126, asks
  for compressed pages, and stops matching once it has spent its byte budget
* a rate limit or an outage stops that leg of the scan instead of retrying per
  host, and a rejected key drops to the free path rather than silencing the scan
* credits are spent only where the free path cannot answer at all

## Development

The tests, the hygiene gate and `CONTRIBUTING.md` are in the git repository
only; the release archive ships the scripts and their data. Three gates, all
offline except where noted:

```sh
nmap -sn -Pn --script ./tests/run.nse --script-args testdir=tests,root=. 127.0.0.1
python3 tests/e2e/run_e2e.py
python3 tools/check.py
```

114 unit cases run inside nmap against the real NSE libraries; 50 end-to-end
cases drive the real nmap binary against a local web server and a stand-in
Vulners API that enforces what the real one enforces; the hygiene gate keeps
secrets, scan output and editor clutter out of the tree, and checks that the
embedded data still matches its source. `python3 tests/e2e/run_e2e.py --live`
adds checks against the real service. See [CONTRIBUTING.md](CONTRIBUTING.md).

## FAQ

**Does it exploit anything?** No. It reads banners and pages and asks a
database. It is in nmap's `safe` category.

**Does it work without an API key?** Yes, fully. Without one it uses the free
endpoint, which returns the same vulnerabilities for a CPE as the paid one. A
key adds detail per finding, and can name software the free path cannot.

**Why did `-sC` stop finding web software?** Because `vulners` is no longer in
nmap's `default` category, and neither is the fingerprint sweep that used to
live in `http-vulners-regex.nse`. Sending the identity of a target's software to
a third party should be something you asked for: run `--script vulners`.

**Why does a vulnerability show `cvss2.0` while another shows `cvss3.1`?** The
label names the scale the score is on. Vulners returns whichever the source
published; a v2 score of 9.3 is not a v3 score of 9.3.

**Why is a low-scoring entry shown when I set `mincvss`?** Because it has a
known exploit, or because the source never scored it. Both are deliberate.

**It found nothing on a host I know is vulnerable.** Run with `-d2`: it logs
every identity it asked about. Usually nmap named the service but not its
version, and there is no version to look up.

## License

The scripts are licensed the same as Nmap itself - see [LICENSE](LICENSE) for the
Nmap Public Source License, and
[nmap.org/npsl](https://nmap.org/npsl/) for what it means.

Vulnerability data comes from [Vulners](https://vulners.com) and is subject to
their terms.

## Related

* [vulners.com](https://vulners.com) - the database behind these scripts
* [vulnersCom/api](https://github.com/vulnersCom/api) - the Python client
* [vulnersCom/burp-vulners-scanner](https://github.com/vulnersCom/burp-vulners-scanner) - the same data inside Burp Suite
* [nmap.org/book/nse.html](https://nmap.org/book/nse.html) - how NSE scripts work

---

<div align="center">

Maintained by the Vulners Team &lt;info@vulners.com&gt;

`#nmap` `#nse` `#vulnerability-scanner` `#cve` `#cvss` `#cpe` `#vulners`
`#security-tools` `#pentest` `#infosec` `#network-scanner` `#exploit-database`
`#lua` `#vulnerability-detection` `#security-automation`

</div>
