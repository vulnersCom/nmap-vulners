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

<img src="docs/demo.gif" alt="Three scans: an SSH port with no API key, the same port with one, and a web port where the sweep names the Tomcat behind a Coyote banner" width="900">

<sub>Real scans of hosts published for scanning. No key, then a key, then a web
port: nmap's <code>-sV</code> reports a Coyote banner and the sweep names the
Tomcat and the jQuery behind it.</sub>

</div>

---

## Contents

|  |  |
|---|---|
| **Start here** | [What it does](#what-it-does) · [Install](#install) · [Your first scan](#your-first-scan) |
| **Understand the answer** | [Reading the output](#reading-the-output) · [**With a key and without**](#with-a-key-and-without) · [Ranking](#ranking) |
| **Understand the machine** | [How it works](#how-it-works) · [The web sweep](#the-web-sweep) · [Where the fingerprints come from](#where-the-fingerprints-come-from) · [Scanning politely](#scanning-politely) |
| **Reference** | [Options](#options) · [Where to keep the API key](#where-to-keep-the-api-key) · [Machine-readable output](#machine-readable-output) |
| **When something is off** | [Troubleshooting](#troubleshooting) · [FAQ](#faq) |

## What it does

nmap already tells you **what software** is listening on a port. This tells you
**what is wrong with it**.

You run one command. For every open port, the script takes the software nmap
identified, asks vulners.com what is known about it, and prints the answer
under that port - ordered so the things people are actually being attacked with
come first, rather than merely the things with the highest score.

It works with no account and no API key. A free key makes each answer richer,
and [With a key and without](#with-a-key-and-without) shows exactly how, with
the same scan run both ways.

## Install

**macOS, Linux, Kali, WSL** - one line, no arguments:

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.sh | sh
```

**Windows** - PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.ps1 | iex
```

The installer asks nmap where it keeps its data, copies the script there,
rebuilds the script database, and then checks that `--script vulners` really
resolves to what it just installed - nmap ships a `vulners.nse` of its own, and
this replaces it. It also offers to store an API key, if you have one.

<details>
<summary><b>Without root, and other options</b></summary>

```sh
# into ~/.nmap, no sudo; the installer prints the NMAPDIR line to add to your profile
curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.sh | sh -s -- --user

# a specific directory
./install.sh --prefix /usr/local/share/nmap

# a specific release
./install.sh --ref v2.0

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
cloned. Running the script straight out of the checkout works too:

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
`sudo nmap --script-updatedb`. There is nothing else to place - the script
downloads its fingerprint data at scan time and writes nothing to disk - and so
nothing to forget, which used to produce a script that ran, found nothing, and
said nothing about why.

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

## Your first scan

```sh
nmap -sV --script vulners scanme.nmap.org
```

That is the whole interface. Two parts of it matter:

* **`-sV` is not optional.** It is the flag that makes nmap work out which
  software is behind each port. Without it nmap reports "port 80 is open" and
  nothing more - there is no software to ask about, and this script has nothing
  to do. This is the single most common reason for an empty result.
* **`--script vulners`** runs the script. It is deliberately not in nmap's
  `default` set, so a plain `-sC` will not run it: sending the identity of your
  target's software to a third party should be something you asked for.

You get your usual nmap report, with a block added under each port that has
something known against it.

## Reading the output

The first line of the block is nmap's own; everything indented under it is this
script. Here is the shape, with three of its rows:

```
80/tcp    open  http    Apache httpd 2.4.7 ((Ubuntu))
| vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 56 exploitable
|   SEVERITY  CVSS    AI  FLAGS    LINK
|   ========  ====  ====  =======  ==============================================================
|   CRITICAL  10.0   8.8  EXP      https://vulners.com/gitee/3E6BA608-776F-5B1F-9BA5-589CD2A5A351
|   CRITICAL   9.8   9.9  EXP      https://vulners.com/zdt/1337DAY-ID-39214
|   CRITICAL   9.8   9.9           https://vulners.com/cve/CVE-2021-44790
```

**The header line** names one piece of software and counts what was found
against it:

| Part | Means |
|---|---|
| `cpe:/a:apache:http_server:2.4.7` | The software identity - kind, vendor, product, version. Everything indented below belongs to this one piece of software. A single port can produce several of these blocks: a web server, the PHP behind it, a jQuery on the page |
| `272 findings` | How many records vulners.com holds for that exact version |
| `56 exploitable` | How many of them either **are** published exploit code, or have some. This number goes up with an API key - see [With a key and without](#with-a-key-and-without) |

**The columns:**

| Column | Means |
|---|---|
| `SEVERITY` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, derived from the CVSS score |
| `CVSS` | The severity score, 0.0 to 10.0. How bad it is **if** exploited - not how likely that is |
| `AI` or `EPSS` | **This column changes depending on your key.** Both are estimates of likelihood, not severity. [With a key and without](#with-a-key-and-without) explains which you get and why |
| `FLAGS` | `KEV` - confirmed exploited in the wild by CISA. `EXP` - working exploit code is published. Empty means neither is known |
| `LINK` | The vulners.com page for this finding. Always a full URL, never shortened |

**Only the top ten per software are printed**, and the block closes by saying
how many it held back:

```
|_  262 more not shown; -v shows all, -vv adds where each was found
```

The other 262 are not lost. They are always in the machine-readable `-oX`
output, whatever your verbosity. To see them on screen:

```sh
nmap -sV --script vulners -v  <target>    # every finding, not just the top ten
nmap -sV --script vulners -vv <target>    # and which URL each identity was found on
```

## With a key and without

This is the question people ask most, so it is answered four times over: in
short, then as the same scan printed both ways, then as a table, and finally
in detail for the one capability a key adds outright.

### The short answer

**Do I find fewer vulnerabilities without a key?**
For every piece of software nmap managed to identify, no - you get the same
list. Measured across four products: for a given software identity, the free
lookup returns exactly the same CVEs as the paid one. The exception is a port
nmap could **not** identify, which a keyless scan cannot report on at all; that
is [smart audit](#smart-audit), further down.

**Then what actually changes?**
How well the findings are sorted, and how much you know about each one.
Without a key you get the *what*; with a key you also get the *how likely* and
the *is it happening right now*.

**Does it cost money?**
No. A key is free, and the detail a key unlocks costs nothing. There is exactly
one paid operation - [smart
audit](#smart-audit), which
gets findings out of ports that have no software identity at all. It never runs
for a port that has one, and `vulners.max_items=0` switches it off.

**Can a key find me *more* vulnerabilities, or just describe them better?**
Both, but by different mechanisms. For software nmap identified, the answer is
the same either way - a key describes it better. For a port nmap could **not**
identify, smart audit can turn a blank into a full set of findings. Your
keyless scan says at the end how many such ports it saw.

**Do I have to configure a mode?**
No, and there is no mode flag. The script looks for a key in the usual places,
and uses whatever the key it finds is good for. Give it a key and it does more;
take the key away and it quietly does less. Nothing to switch.

### The same scan, both ways

Same host, same software, same 272 findings. Without a key:

```
| vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 56 exploitable
|   SEVERITY  CVSS    AI  FLAGS    LINK
|   ========  ====  ====  =======  ==============================================================
|   CRITICAL  10.0   8.8  EXP      https://vulners.com/gitee/3E6BA608-776F-5B1F-9BA5-589CD2A5A351
|   CRITICAL   9.8   9.9  EXP      https://vulners.com/zdt/1337DAY-ID-39214
|   CRITICAL   9.8   9.6  EXP      https://vulners.com/packetstorm/PACKETSTORM:171631
|   CRITICAL   9.8   9.9           https://vulners.com/cve/CVE-2021-44790
|   CRITICAL   9.8   9.8           https://vulners.com/cve/CVE-2023-25690
|_  262 more not shown; -v shows all, -vv adds where each was found
```

With a free key:

```
| vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 78 exploitable
|   SEVERITY  CVSS  EPSS  FLAGS    LINK
|   ========  ====  ====  =======  ==============================================================
|   CRITICAL   9.1  >99%  KEV EXP  https://vulners.com/cve/CVE-2024-38475
|   CRITICAL   9.0  >99%  KEV EXP  https://vulners.com/cve/CVE-2021-40438
|   CRITICAL   9.1  >99%  KEV      https://vulners.com/cnvd/CNVD-2024-36387
|   CRITICAL  10.0   71%  EXP      https://vulners.com/gitee/3E6BA608-776F-5B1F-9BA5-589CD2A5A351
|   CRITICAL   9.8   97%  EXP      https://vulners.com/cve/CVE-2021-44790
|_  262 more not shown; -v shows all, -vv adds where each was found
```

Both are real answers from vulners.com, captured against a local server
presenting that banner, and both are abridged to five rows. Three things
changed, and each one is worth understanding:

**1. `56 exploitable` became `78 exploitable`.**
An exploit record lists the vulnerabilities it exploits. That list only comes
back with a key. Without it the script can see that an exploit exists, but
cannot connect it to the CVE it attacks - so only the exploit records
themselves get counted and flagged. With a key, the 22 CVEs those exploits
target are marked too. The vulnerabilities did not change; the script's ability
to join them up did.

**2. The `AI` column became `EPSS`.**
Both answer "how likely is this to be used against me", and the script prints
whichever one the answer carried:

* **AI** is Vulners' own model score, 0 to 10. It comes back on the free
  lookup.
* **EPSS** is the [Exploit Prediction Scoring System](https://www.first.org/epss/),
  an industry-standard published probability that a vulnerability will be
  exploited in the next 30 days. `>99%` is not a rounding of 100 - EPSS never
  reaches either end, and a value that would round away is shown as a bound
  instead of a misleading `0.0%`.

The column follows the data rather than the licence: a signal that did not
arrive loses its column instead of showing blank cells, because a blank EPSS
reads as "this one is quiet", and an absent field cannot support that claim.

**3. `KEV` flags appeared.**
[CISA's Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
is a list of vulnerabilities confirmed to be under attack in the real world.
Not predicted - observed. It is the strongest signal on the page, and it only
arrives with a key.

**And so the top row is different**, which is the whole point. Without a key
the list opens with a 10.0 that may never have been used against anyone. With a
key it opens with a 9.1 that CISA has recorded as actively exploited and that
EPSS puts above 99%. The second list is the one that tells you what to fix
first.

### The same thing as a table

| | Without a key | With a free key |
|---|---|---|
| Which vulnerabilities are found | all of them | **the same ones** |
| Severity (CVSS, and the SEVERITY label) | yes | yes |
| Link to each finding | yes | yes |
| Exploit code exists (`EXP`) | for exploit records only | also for the CVEs those exploits attack |
| Confirmed exploited in the wild (`KEV`) | - | yes |
| Probability of exploitation | Vulners' AI score | EPSS, the published standard |
| Titles, publication dates, upstream advisory links | - | yes |
| Ranking quality | good | better - the "confirmed exploited" bands can actually fill |
| Findings for a port nmap could **not** identify | none - there is nothing to ask about | [smart audit](#smart-audit) names it and reports on it. The only paid part, and the only way the count goes up |
| Price | free, no account | free, [register here](https://vulners.com/userinfo) |

### Smart audit

Everything above is free. There is one more capability that is not, and it is
the only part of a keyed scan that can raise the number of findings rather than
merely describe them better.

**The problem it solves.** Every lookup so far needs an identity - a CPE like
`cpe:/a:apache:http_server:2.4.7`. Some ports never produce one. nmap probes an
appliance, gets a banner it has no rule for, and reports the port as open with
no product and no version. There is nothing to ask about, so a keyless scan
prints nothing for that port. Not "clean" - nothing.

**What smart audit does.** With a key, the script can hand raw text to Vulners
and ask it to work out what the software is. The answer comes back as an
identification, often including a real CPE, together with the bulletins for it.
Those bulletins then go through the same enrichment as every other finding, so
they arrive with the same columns and the same ranking.

**When it fires.** Two cases, both narrow:

| Case | What is sent |
|---|---|
| The port produced **no identity at all** | nmap's own `product version` text if it has one, otherwise the raw service banner, cleaned of nmap's metadata |
| A CPE was looked up and the service **positively could not resolve it** | that CPE, as text |

The second case is easy to miss and worth understanding. Vulners echoes back
which product it matched a lookup to. When what it matched is not what was
asked, the CPE is a name nothing recognises - often one nmap assembled from a
banner - and the empty answer means "unknown identity", not "no known
vulnerabilities". Re-asking it as text is what turns that silence into
findings.

**When it never fires**, which is the case that keeps the bill at zero:

* **never for a port whose CPE resolved**, even if the answer was empty. A
  correctly identified, fully patched service produces no findings, and *clean
  is an answer*. Gating on "nothing was found" instead would have charged a
  credit for every well-maintained host - the better the network, the higher
  the bill.
* **never without a key.** There is no keyless path to it.

**Why it raises the finding count.** For a port with an identity, a credit buys
nothing: measured across four products, the free lookup returns the same CVEs
as the paid one for the same CPE. For a port *without* one, it is the
difference between a report and a blank. Asking about `"Apache httpd"` as free
text returns nothing useful, while `cpe:/a:apache:http_server:2.4.7` returned
342 findings - and smart audit is what gets from the first to the second.

**The keyless scan tells you when it would have helped.** The notice at the end
of a scan with no key counts the ports that showed a banner and produced no
usable identity:

```
  Ran without an API key.
  A key adds more detail per finding - exploitation status, titles
  and dates - and can identify software this scan could not name
  (3 service(s) here showed a banner that produced no usable identity).
```

Those three are exactly the ports smart audit would have worked on. If that
count is zero on your network, a key buys you better sorting and richer
findings, but no additional ones.

**What it costs, and the four things that bound it:**

* **one credit per distinct string**, not per port and not per host;
* **answers are cached for the whole scan**, so a /24 of identical appliances
  pays once rather than 254 times;
* **capped by `vulners.max_items`**, default **32**, for the entire scan. The
  very first billed call is additionally capped at five items, because the
  wallet balance is not known until one call has answered;
* **`--script-args vulners.max_items=0` switches it off entirely**, and every
  other keyed feature keeps working.

Reaching the ceiling stops the spending and nothing else - the key stays in
use for the enrichment that is free.

## How it works

```
  nmap -sV --script vulners <target>
    |
    |  1. nmap does its usual job and names the software on each port
    |        22/tcp  OpenSSH 6.6.1p1     ->  cpe:/a:openbsd:openssh:6.6.1p1
    |        80/tcp  Apache httpd 2.4.7  ->  cpe:/a:apache:http_server:2.4.7
    |
    |  2. on a web port only: the script goes looking for what nmap
    |     cannot see. It requests a list of known paths and reads the
    |     Server header, X-Powered-By, cookies, the page title, meta
    |     tags, script filenames and the body
    |        ->  cpe:/a:apache:tomcat:7.0.70  behind a "Coyote" banner
    |        ->  cpe:/a:php:php:5.6.38        behind a reverse proxy
    |
    |  3. for a service nmap could not name at all: its raw banner is
    |     matched against rules for FTP, SMTP, SSH, MySQL, DNS, NTP,
    |     LDAP and more. This costs no extra request
    |
    |  4. every identity found so far is looked up at vulners.com
    |     one request per identity, cached for the whole scan, so a
    |     hundred identical servers cost one lookup
    |
    |  5. with a key only: anything still unidentified goes to smart
    |     audit as plain text - a port that produced no identity at
    |     all, and any CPE the service could not resolve. It works out
    |     what the software is and answers with its bulletins. The one
    |     billed step, and the only one that can ADD findings rather
    |     than describe them better
    |
    |  6. findings are ranked - confirmed exploited first, merely
    |     high-scoring last - and filtered by your mincvss
    |
    v  7. printed under the port, and written to -oX for your tools
```

**What it finds, it gives back to nmap.** Every identity the sweep discovers is
written onto the port itself, not just into this script's own block. So a
Tomcat version that only the sweep could see appears in nmap's `<service>`
element in `-oX` output, where your other tooling reads it. It does not
masquerade as one of nmap's own findings: the port keeps the detection method
and confidence nmap gave it, so nothing downstream is told a version probe
matched when none did.

Two extra abilities are worth naming, because they are what finds software that
a pattern alone cannot:

* **It reads nmap's own service banner.** When `-sV` could not settle what a
  service is, nmap still records the raw text it saw. Matching that costs no
  extra request, and it is exactly the case where a port would otherwise report
  nothing at all.
* **It asks a product that will not say.** A CMS that names itself and hides
  its version is common, and no amount of pattern matching extracts a number
  that is not on the page. When the product is recognised and the version is
  not, one request goes to the place that answers - `/CHANGELOG.txt` for
  Drupal, `/administrator/manifests/files/joomla.xml` for Joomla. A host
  running none of the six probed products is sent nothing extra.

<details>
<summary><b>What goes over the network, exactly</b></summary>

Three kinds of request reach vulners.com, and they have different rules:

| What | Key | Cost | When |
|---|---|---|---|
| Look up a software identity | never sent, even if you have one | free | once per identity per scan |
| Fetch the detail of findings | required | free | once per 100 findings |
| Identify software from text ([smart audit](#smart-audit)) | required | 1 credit per distinct string | only for a port with no identity at all, or a CPE the service could not resolve |

The lookup deliberately travels without your key even when you have one. It is
served from a CDN cache shared by every user of this script, and attaching a
key would take you off that cache for an answer that is not improved by it.

A request carries a software name and a version. It carries nothing about the
host it came from.

</details>

## Ranking

Facts outrank predictions. Findings are ordered:

1. **CISA KEV** - recorded as exploited in the wild
2. **SSVC `active`** - a coordinator's judgement that exploitation is happening
3. **an exploit exists** - the code is published, for this or for a CVE it names
4. **high EPSS** - a model expects exploitation
5. everything else

CVSS breaks ties inside a band, not across them: an exploited 7.5 is a worse
problem than an unexploited 9.8, and this is the order that says so.

Bands 3 and 5 work without a key. Bands 1, 2 and 4 need the data a key brings,
and a band whose data did not arrive is skipped rather than filled with
guesses - which is the mechanical reason a keyed report is better sorted.

## The web sweep

On an HTTP port the script requests every path its catalogue publishes - 939
paths - and matches all 721 rules against every answer. The paths come from
WhatWeb, nuclei and FingerprintHub: places where a product is known to be
recognisable, rather than guesses.

Even a path belonging to software you are not running is worth the request,
because the answer still carries `Server`, `X-Powered-By`, a cookie and a
title, and those are where the rules find the stack in front of it.

**How fast that goes is your `-T`**, not a setting of ours. The list never
shrinks; the rate does:

| | batches | wait between them | measured, one web port |
|---|---|---|---|
| `-T0` paranoid | 188 x 5 | 2 s | 11 m 22 s |
| `-T1` sneaky | 94 x 10 | 1 s | 1 m 56 s |
| `-T2` polite | 38 x 25 | 0.5 s | 26.2 s |
| `-T3` normal (default) | 10 x 100 | 0.1 s | 7.6 s |
| `-T4` aggressive | 4 x 250 | none | 6.7 s |
| `-T5` insane | 1 | none | 6.6 s |

All six measured in one run against the same local server. `-sV` alone against
it is 6.1 s, so at the default rate the sweep costs about a second and a half.
The two slow rows are `-T0` and `-T1` doing their job: 188 and 94 batches, with
a deliberate wait between each.

The requests are pipelined over 34-48 connections with at most four open at
once, which is nselib's `pipeline_go` - the same machinery nmap's own
`http-enum` uses, honouring the server's `Keep-Alive: max=` and
`--script-args http.max-pipeline=N`.

`--script-args vulners.paths=none` turns the sweep off entirely.

## Where the fingerprints come from

The script does not carry them. It downloads them once per scan, before the
first host is touched:

```
https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/
    index.json          what exists, at which serial
    fingerprints.json   721 product and version rules
    paths.json          939 paths the sweep requests
    probes.json         6 targeted version probes
```

That is four requests per scan - one per file, not per host and not per port -
for 40 KB compressed out of 250 KB of JSON, in nmap's pre-scan phase. Measured
against the published branch. An installed script therefore picks up new
fingerprints without being reinstalled.

**It writes nothing to your filesystem.** The data is held for the duration of
the scan and dropped, which is how every script nmap ships behaves: of the 611
of them, 26 open a file for writing and every one writes only where a script
argument told it to. None keeps a cache, and neither does this.

**If it cannot be downloaded, the scan still runs.** This data feeds the web
fingerprinting and nothing else, so a machine with no route to GitHub loses
that and keeps everything else: the software nmap itself identified is still
looked up. The report says which capability was missing, rather than leaving
you to read an empty result as a clean network.

| argument | what it does |
|---|---|
| `vulners.catalog_url=<url>` | fetch from a mirror instead - for an airgapped network. A host name or an IPv6 address in brackets, `http://[fd00::1]/catalog/` |
| `vulners.catalog=none` | do not fetch at all; look up only what nmap named |

## Scanning politely

Two different parties deserve restraint here, and they need different things.

**To vulners.com**, a scan of a whole network asks far less than it looks:

* one request per software **identity**, not per port and not per host, with
  every answer cached for the rest of the scan - a hundred identical servers
  cost one lookup
* a lookup another port already has in flight is waited for, not repeated
* discovery goes to a **CDN-cached** endpoint, deliberately *without* your key
  even when you have one, so it lands on the cache the whole user base shares
  rather than on the origin
* a rate limit or an outage stops that leg of the scan rather than being
  retried once per host, and a key that stops working drops to the free path
  instead of silencing the scan
* credits are spent only where the free path could not answer at all

**To the target**, the sweep is the only thing that makes real noise:

* it goes over a handful of **pipelined connections** rather than one per path,
  and asks for compressed pages
* its rate is entirely yours - see the `-T` table in [The web
  sweep](#the-web-sweep) - and `vulners.paths=none` removes it
* it stops matching a response once it has spent its byte budget, so an
  enormous page cannot turn into an enormous amount of work
* nothing else in the script touches the target: everything after the sweep is
  a conversation with vulners.com about text nmap already collected

## Options

All are passed with `--script-args`. A bare name works too, so
`--script-args mincvss=7` is enough.

**The ones you are likely to want:**

| Argument | Default | Meaning |
|---|---|---|
| `vulners.mincvss` | `0` | Hide findings scored below this. Unscored bulletins and anything with a known exploit are shown whatever the threshold |
| `vulners.width` | `80` | Terminal width the table is laid out for |
| `vulners.paths` | all 939 | Paths for the web sweep. `none` switches the sweep off; a Lua list, or one string naming a file with one path per line, replaces it. A file you name that cannot be read stops the sweep and says so, rather than quietly falling back to the published list |
| `vulners.max_items` | `32` | Ceiling on paid identifications for the whole scan. `0` disables spending entirely |

**Telling it about your key** - see [Where to keep the API
key](#where-to-keep-the-api-key) for which of these to prefer:

| Argument | Default | Meaning |
|---|---|---|
| `vulners.api_key_file` | - | Absolute path to a file whose first line is the token |
| `vulners.api_key` | - | The token itself. Leaky: nmap copies its own command line into `-oX` |

**Rarely needed:**

| Argument | Default | Meaning |
|---|---|---|
| `vulners.catalog_url` | GitHub | Fetch the fingerprint data from a mirror instead |
| `vulners.catalog` | fetch it | `none` to run with no web fingerprinting and no request for it |
| `vulners.api_host` | `vulners.com` | Host name of the API |
| `vulners.api_port` | `443` | Port on `api_host` |

The 1.x argument names still work for one release: `vulners_enterprise.*` for
the key, host, port and mincvss arguments, and `http-vulners-regex.paths` for
the sweep. Using one prints a deprecation notice naming its replacement.

### Worked examples

```sh
# only findings scored 7.0 and above
nmap -sV --script vulners --script-args mincvss=7 <target>

# no web sweep - just look up what nmap itself identified
nmap -sV --script vulners --script-args vulners.paths=none <target>

# never spend a credit, whatever the scan turns up
nmap -sV --script vulners --script-args vulners.max_items=0 <target>

# quiet on the target, and patient
nmap -sV -T2 --script vulners <target>

# a wider terminal, and every finding rather than the top ten
nmap -sV --script vulners --script-args vulners.width=140 -v <target>
```

## Where to keep the API key

There are four places the script will find a key. They differ in how safe they
are, and - separately - in which one wins when you have more than one. Those
two orders are opposites, so they are worth reading together:

| Where | How safe | Wins over |
|---|---|---|
| `~/.nmap/vulners.key`, one line, mode 600 | **safest** - never on a command line, never in a report. The installer offers to write it for you | nothing; it is the last resort |
| `VULNERS_API_KEY` in the environment | safe, but inherited by whatever else you launch from that shell | the key file |
| `--script-args vulners.api_key_file=/absolute/path` | safe; only the *path* is on the command line | the environment |
| `--script-args vulners.api_key=<token>` | **leaky** - see below | everything |

Read the table downwards for what to choose, and upwards for what wins. The
most explicit setting takes precedence, which is what you want when you are
overriding a stored key for one scan - and it is exactly why the most explicit
one is also the most exposed.

**Why the last row is leaky:** nmap copies its own command line into every
report, so a token passed that way ends up in the `args` attribute of `-oX`
output and in your shell history. It is fine for a throwaway test and wrong for
anything recorded.

The script itself never writes the token anywhere, including its debug output -
there are regression tests that say so, in the offline suite and against the
live service.

A key file you name explicitly and that cannot be read stops the run rather
than quietly falling back - an operator who names a file means that file - and
the report says which file it was. A mistyped path cannot look like a clean
scan.

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
      <elem key="source_href">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-40438</elem>
    </table>
  </table>
</script>
```

`mode` says which way the scan ran - `free` or `keyed` - so a report can be
read without guessing which fields to expect.

New in 2.0: `schema`, `mode`, `severity`, `exploit_known`, `kev`, `epss`,
`epss_percentile`, `exploitation`, `ai_score`, `title`, `published`, `href`,
`source_href` and `found_on`. Every one is present-or-absent, never empty.
Nothing is nested more deeply than before, because a third table level is
invisible to every importer examined.

`href` is always the vulners.com page for the finding, in both modes. The
endpoint's own `href` is the **upstream** address - nvd.nist.gov for a CVE,
github.com for a scraped exploit - and that travels separately, as
`source_href`, so neither field's meaning depends on which mode produced it.

The structured output always carries every finding that passed `mincvss`, even
the ones the verbosity ladder hides from the text - so no automation loses
findings by not passing `-v`.

**The rendered text is a break from 1.x.** The `*EXPLOIT*` and `*HAS EXPLOIT*`
tokens and the tab-delimited layout are gone, replaced by the aligned table
above. The per-row vulners.com link stayed: it is the last column, and it is
the one cell the layout will not shorten, because half a URL is not a URL.
Text-scraping consumers need updating; `-oX` consumers do not.

## Troubleshooting

**It printed nothing for a host I know is vulnerable.** Work down this list -
the first two account for most cases:

1. **Did you pass `-sV`?** Without it nmap names no software, and there is
   nothing to look up. `nmap --script vulners <target>` alone will almost
   always print nothing.
2. **Did nmap print a version?** Look at the `VERSION` column of nmap's own
   output. `nginx` with no number cannot be looked up - there is no version to
   ask about. `-sV --version-all` tries harder and sometimes gets one. If nmap
   named nothing at all, and the end-of-scan notice counts the port among the
   services that "showed a banner that produced no usable identity", then a key
   is the answer: see [smart
   audit](#smart-audit).
3. **Is the software simply clean?** A fully patched service produces no
   findings, and that looks identical to a failure. Check against a host you
   know is old.
4. **Look at what it had to work with.** The script asks about exactly the
   software identities attached to the port, so those are what to check.
   `-oX` lists them, including the ones the sweep added:

   ```sh
   nmap -sV --script vulners -oX - <target> | grep cpe
   ```

   No `<cpe>` line means nothing was identified, and nothing identified means
   nothing to look up. Add `-vv` to see which URL each swept identity came
   from.

5. **Then ask what went wrong.** `-d` prints what the script refused or could
   not do - an identity it judged unreal, a ceiling it hit, an API error, a
   catalogue file that would not parse:

   ```sh
   nmap -sV --script vulners -d <target> 2>&1 | grep -i "vulners\|catalogue\|api"
   ```

**The report says the fingerprint catalogue could not be downloaded.** Then the
web fingerprinting did not run and everything else did - the software nmap
itself named was still looked up. It is said out loud for that reason: a
capability that did not run reads exactly like a capability that found nothing.
The two causes have separate wording. "Could not be downloaded" is your network
or GitHub; "answered, but one of its dictionaries could not be read" is the
mirror you pointed `vulners.catalog_url` at.

**The scan is slow.** On a web port, almost all of it is the 939-path sweep,
and its rate is your `-T` - see [The web sweep](#the-web-sweep). Either raise
the timing (`-T4`) or turn the sweep off with
`--script-args vulners.paths=none`. Note that against internet hosts the sweep
costs about a minute per web port at the default `-T3`, where on a local
network it costs seconds; the difference is entirely round-trip time.

**`-sC` stopped finding web software after I upgraded from 1.x.** Because
`vulners` is not in nmap's `default` category, and neither is the fingerprint
sweep that used to live in `http-vulners-regex.nse`. Run `--script vulners`
explicitly.

**The table is cut off / wrapped badly.** It is laid out for an 80-column
terminal by default. `--script-args vulners.width=140` matches a wider one. The
link column is allowed to overflow on purpose - half a URL is useless.

**My key does not seem to be used.** Run with `-d`: the script reports which
source the key came from and how long it is, never the key itself. If that
names a source you did not expect, something more explicit is overriding you -
see the precedence column in [Where to keep the API
key](#where-to-keep-the-api-key). One trap is worth knowing on top of that:
nmap resolves `~/.nmap` through your real account rather than `$HOME`, so under
`sudo` it looks in root's home. The installer handles that when it writes the
key for you.

**The notice at the end says "Ran without a usable API key".** A key was found
but stopped working, and the sentence names what happened. The scan did not
stop: it carried on with the free lookup, which is why you still got findings.
Check the key at [vulners.com/userinfo](https://vulners.com/userinfo). A scan
with no key at all says "Ran without an API key" instead, with no reason
attached - the two are worth telling apart.

## FAQ

**Does it exploit anything?** No. It reads banners and pages and asks a
database - it sends no payload and tries no credential. It is categorised
`discovery, intrusive, vuln, external` rather than `safe`, for one reason: the
path sweep requests 939 paths of a web port, and nmap's definition of `safe`
excludes scripts that use large amounts of bandwidth. nmap's own `http-enum`
requests 2 204 and is `discovery, intrusive, vuln` for the same reason - this
script adds `external` on top, because its lookups leave your network. Your
`-T` sets how fast those requests go out and never how many, and
`--script-args vulners.paths=none` turns the sweep off altogether.

**Does it work without an API key?** Yes - see [With a key and
without](#with-a-key-and-without). For any software nmap identified, the free
lookup returns the same vulnerabilities as the paid one; a key adds detail and
sorts them better. The one thing a keyless scan cannot do is report on a port
whose software nmap could **not** identify, which is what [smart
audit](#smart-audit) is
for. Your keyless scan says at the end how many such ports it met, so you can
tell whether that matters on your network.

**What is a CPE?** The identity string nmap and this script use for a piece of
software: `cpe:/a:apache:http_server:2.4.7` is application / vendor `apache` /
product `http_server` / version `2.4.7`. It is what makes a lookup exact rather
than a text search.

**Why does one finding show `cvss2.0` and another `cvss3.1`?** The label names
the scale the score is on. Vulners returns whichever the source published; a v2
score of 9.3 is not a v3 score of 9.3.

**Why is a low-scoring entry shown when I set `mincvss`?** Because it has a
known exploit, or because the source never scored it. Both are deliberate: a
threshold should not hide working exploit code, and an unscored bulletin is not
a low-scoring one.

**Why is an exploit listed separately from the CVE it exploits?** They are
different documents, and both are worth seeing. At the same score the
vulnerability leads and its exploit follows; the `EXP` flag on the CVE is what
tells you they are one problem.

**Does it send anything about my hosts to Vulners?** A request carries a
software name and a version. It carries nothing about the host it came from,
nothing about your network, and no scan results.

## Development

The tests, the hygiene gate and `CONTRIBUTING.md` are in the git repository
only; the release archive ships the script and its data. Eight gates, all
offline except where noted, and CI runs exactly these:

```sh
nmap -sn -Pn --script ./tests/run.nse --script-args testdir=tests,root=. 127.0.0.1
python3 tests/e2e/run_e2e.py
python3 tools/check.py
python3 tools/catalog.py --check
python3 tools/xml_contract.py --selftest
python3 tools/fingerprints/selftest.py
python3 tools/catalog_diff.py --selftest
python3 tools/nmap_style.py
```

273 unit cases run inside nmap against the real NSE libraries; 64 end-to-end
cases drive the real nmap binary against a local web server and a stand-in
Vulners API that enforces what the real one enforces; the hygiene gate keeps
secrets, scan output and editor clutter out of the tree and refuses a global
read that NSE would turn into a lost result; and the last four hold the data
and the tools that publish it - the catalogue's shape, the XML contract every
importer reads, the pattern translator, and the gate that decides a rebuild is
safe to publish. The last one holds the whole repository to
[Nmap's own Code Standards](https://secwiki.org/w/Nmap/Code_Standards), which
`HACKING` names as the authority for a script that wants to live in nmap's
tree: no tabs, no trailing whitespace, lines under 80 columns, no semicolons,
private NSEdoc opening with `--;`, PEP 8 for the Python.
`python3 tests/e2e/run_e2e.py --live` adds checks against the real service.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

The script is licensed the same as Nmap itself - see [LICENSE](LICENSE) for the
Nmap Public Source License, and
[nmap.org/npsl](https://nmap.org/npsl/) for what it means.

Vulnerability data comes from [Vulners](https://vulners.com) and is subject to
their terms.

## Related

* [vulners.com](https://vulners.com) - the database behind this script
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
