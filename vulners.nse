description = [[
Finds known vulnerabilities in the software an nmap scan identified, using the
vulners.com database.

For every open port it takes the software identities nmap produced - the CPEs
from -sV - looks them up, and prints what is known about them, ranked so that
the findings somebody is actually being attacked with come first.

On an HTTP port it also fingerprints the web stack itself: a list of paths is
requested in pipelined batches, paced by nmap's own -T, and matched against a
downloaded pattern set which names software nmap's own service probe cannot
see - an application framework, a CMS, a PHP version behind a reverse proxy.
Those CPEs are looked up too, and published onto the port so the rest of the
scan can use them.

The pattern set is not carried in this file. It is fetched once per scan, before
the first host is touched, and held in memory for the rest of it; nothing is
written to disk. A scan that cannot reach it loses the web fingerprinting and
keeps everything else.

Without an API key it uses the free endpoint and says so once the scan ends.
With a key it adds detail to each finding, and can identify software that has
no CPE at all from its raw banner. There is no mode switch: the script uses
whatever the key it finds is good for.

Every answer is cached for the whole scan, so scanning a network does not
re-ask about software it has already seen.

NB: the vulnerability database is far too large to ship, so lookups are remote.
A request carries a software name and a version, and nothing about the host it
came from.
]]

---
-- @usage
-- nmap -sV --script vulners <target>
-- nmap -sV --script vulners --script-args vulners.mincvss=7 <target>
--
-- @args vulners.mincvss Hide findings scored below this. Unscored bulletins and
--       anything with a known exploit are shown whatever the threshold.
-- @args vulners.paths Paths for the web sweep: a list of strings, one string
--       naming a file with one path per line, or "none" to disable the sweep.
--       Defaults to every path the catalogue publishes. How fast they go out
--       is nmap's own -T: batches of 5 two seconds apart at -T0, of 100 a
--       tenth of a second apart at the default -T3, all at once at -T5.
-- @args vulners.catalog "none" to run without the fingerprint catalogue: no
--       web fingerprinting, and no request for it. Defaults to fetching it.
-- @args vulners.catalog_url Base URL to fetch the catalogue from, for a mirror
--       on a network that cannot reach raw.githubusercontent.com.
-- @args vulners.width Terminal width the table is laid out for. Defaults to 80.
-- @args vulners.max_items Ceiling on billed items for the whole scan.
-- @args vulners.api_key API token. Leaky: nmap copies its own command line
--       into -oX, so a key passed this way lands in the report.
-- @args vulners.api_key_file Absolute path to a file whose first line is the token.
-- @args vulners.api_host Domain name of the vulners API. Defaults to vulners.com.
-- @args vulners.api_port Port on api_host. Defaults to 443.
--
-- @output
-- 80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
-- | vulners: cpe:/a:apache:http_server:2.4.7  272 findings, 78 exploitable
-- |   SEVERITY  CVSS  EPSS  FLAGS    LINK
-- |   ========  ====  ====  =======  ==============================================================
-- |   CRITICAL   9.1  >99%  KEV EXP  https://vulners.com/cve/CVE-2024-38475
-- |   CRITICAL   9.0  >99%  KEV EXP  https://vulners.com/cve/CVE-2021-40438
-- |   CRITICAL   9.1  >99%  KEV      https://vulners.com/cnvd/CNVD-2024-36387
-- |   CRITICAL  10.0   71%  EXP      https://vulners.com/gitee/3E6BA608-776F-5B1F-9BA5-589CD2A5A351
-- |_  262 more not shown; -v shows all, -vv adds where each was found
--
-- @xmloutput
-- <elem key="schema">2.0</elem>
-- <elem key="mode">keyed</elem>
-- <table key="cpe:/a:f5:nginx:1.13.4">
--   <table>
--     <elem key="id">CVE-2021-41773</elem>
--     <elem key="type">cve</elem>
--     <elem key="severity">CRITICAL</elem>
--     <elem key="cvss">9.8</elem>
--     <elem key="cvss_type">cvss3.1</elem>
--     <elem key="is_exploit">false</elem>
--     <elem key="kev">true</elem>
--     <elem key="epss">0.94</elem>
--     <elem key="href">https://vulners.com/cve/CVE-2021-41773</elem>
--     <elem key="source_href">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-41773</elem>
--   </table>
-- </table>

author = "Vulners Team (info@vulners.com)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- "default" is deliberately absent. This script sends the identity of the
-- target's software to a third party, and a plain -sC must not do that without
-- being asked. nmap's own shipped copy is {"vuln","safe","external"} for the
-- same reason.
--
-- "safe" is deliberately absent too, and that is a change from 1.x. nmap's own
-- definition excludes scripts that "use large amounts of network bandwidth",
-- and the sweep requests every path the catalogue publishes - 939 of them
-- today - of every web port, at every timing level. nmap's own http-enum
-- requests 2 204 and is categorised {"discovery","intrusive","vuln"}; this
-- script does the same kind of thing to a server, so it carries the same label.
-- "external" stays, because the lookups leave the operator's network.
categories = {"discovery", "intrusive", "vuln", "external"}

local http = require "http"
local io = require "io"
local json = require "json"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
local url = require "url"

local api_version = "2.0"

-- The User-Agent is a wire contract, not decoration: the free endpoint sits
-- behind a CDN rule that answers 403 to any keyless request whose UA does not
-- contain this exact substring. Measured - "Vulners NMAP Enterprise 1.8" and
-- "vulners nmap plugin" are both refused.
local USER_AGENT = "Vulners NMAP Plugin " .. api_version

local BURP_PATH = "/api/v3/burp/software/"
local SEARCH_ID_PATH = "/api/v3/search/id/"
local AUDIT_SMART_PATH = "/api/v4/audit/smart"

-- The id endpoint accepts at most 100 ids per call.
local ID_CHUNK_SIZE = 100

-- nmap decompresses a gzip body only when it was built with zlib, and
-- nselib/http.lua checks the same way. Asking for gzip on a build without it
-- would leave the answer compressed and unparsable, so the header is set only
-- when it can be honoured. It is worth asking for: answers are 8-12 times
-- smaller compressed (115 KB -> 9 KB for one Apache lookup, measured).
local ACCEPT_ENCODING = pcall(require, "zlib") and "gzip, deflate" or nil

local MAX_ATTEMPTS = 3
local PENDING_WAIT_STEP = 0.2
local PENDING_WAIT_LIMIT = 30
local RETRY_AFTER_CAP = 60
local REQUEST_TIMEOUT = 10000

-- How many times the sweep is re-queued for the paths still unanswered.
local MAX_FETCH_ROUNDS = 4
-- How many hops a redirected path is followed.
local MAX_REDIRECTS = 2

-- Lua pattern matching does not yield, so the whole NSE scheduler stops while
-- the downloaded patterns run over a body. Measured: 0.068 s for 63 KB, 0.479 s
-- for 511 KB, 1.863 s for 2 MiB - against nmap's 2 MiB default body cap, over
-- every path the catalogue publishes. truncated_ok is not optional: without it
-- nselib/http.lua treats an oversized body as an error and discards the
-- response whole, so the path looks unanswered and is re-queued every round.
local MAX_BODY_SIZE = 131072
local SWEEP_BYTE_BUDGET = 4 * 1024 * 1024

-- Default ceiling on billed items for one scan. Only audit/smart is billed,
-- and only for a service that produced no CPE at all, so this is generous.
local DEFAULT_MAX_ITEMS = 32
-- The wallet balance is only learnable from the header of a previous billed
-- call, so the first one is kept small purely to learn it.
local COLD_START_ITEMS = 5

local DEFAULT_WIDTH = 80

-- How many findings the default verbosity prints per software identity. -v
-- prints every one that passed mincvss, and the structured output always
-- carries them all, so nothing is lost by not printing it.
local MAX_DEFAULT_ROWS = 10

-- ...of which no single ranking band may take more than this.
--
-- Without the cap the summary can be filled entirely by one band, and on the
-- free path it always is: with no key there is no cvelist, so an exploit can
-- never be attributed to the CVE it exploits - every exploit bulletin sits in
-- band 3 and every CVE in band 5. Measured against the live service, all ten
-- rows for a real Apache 2.4.7 were exploit ids, not one of which names what it
-- exploits, while the CVEs a reader could act on sat below the cut.
local MAX_BAND_ROWS = 6

-- nginx is published under three vendor spellings for one product. The service
-- answers them with very different amounts of data (measured on 1.13.4: f5 124
-- bulletins, nginx 4, igor_sysoev none), and nmap's own service fingerprint
-- emits the igor_sysoev one, so all three are asked and the answers merged.
-- This costs nothing: discovery runs on the free endpoint.
local NGINX_SPELLINGS = {":f5:nginx", ":nginx:nginx", ":igor_sysoev:nginx"}

-- Severity bands. NVD's own boundaries, so a reader who knows CVSS reads the
-- same word the NVD page shows.
local SEVERITY_BANDS = {
  {9.0, "CRITICAL"},
  {7.0, "HIGH"},
  {4.0, "MEDIUM"},
  {0.1, "LOW"},
}


-- The fingerprint data is NOT in this file.
--
-- The rules, the swept paths and the targeted probes are three dictionaries
-- published separately and fetched at scan time - see the Catalog seam below.
-- They used to be generated into this file by tools/embed.py, which meant a
-- corpus that changes weekly could only reach a user through a new release of a
-- script that does not.
--
--   catalog/fingerprints.json   product and version rules
--   catalog/paths.json          the paths the sweep requests
--   catalog/probes.json         targeted version probes
--   catalog/index.json          the manifest: schema and serial
--
-- What a scan does without them is the point of the design: everything except
-- web fingerprinting. The identities nmap itself produced are still looked up.

-- What catalog() answers when nothing was loaded, so every reader can index it
-- without asking whether it exists first.
local EMPTY_CATALOG = {fingerprints = {}, paths = {}, probes = {}, rule_count = 0}

-- The catalogue format this script can read. A published catalogue declaring a
-- HIGHER schema is refused rather than half-read: that is what makes it safe to
-- change the format later, because an old script says "I am too old" instead of
-- silently misreading a file it was never taught.
local CATALOG_SCHEMA = 1

-- A GitHub branch that holds only the dictionaries, so publishing a catalogue
-- never touches the code history and vice versa.
local CATALOG_BASE =
  "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/"

-- One attempt, briefly. This runs before the scan and must not become the
-- reason a scan feels slow; if it fails the scan proceeds without a sweep.
local CATALOG_TIMEOUT = 10000

-- Ceilings on a file that arrived intact but is not what it should be. Sized
-- well above the real catalogue (722 rules, 939 paths, 6 probes) and far below
-- anything that would hurt.
local MAX_CATALOG_BYTES = 8 * 1024 * 1024
local MAX_CATALOG_RULES = 20000
local MAX_CATALOG_PATHS = 2000
local MAX_CATALOG_PROBES = 500
local MAX_CATALOG_STRING = 2048

-- The dictionaries, and the order they are fetched in.
local CATALOG_FILES = {"fingerprints", "paths", "probes"}

-- The whole published list is always requested. What nmap's timing template
-- changes is the RATE: how many paths go out together, and how long the sweep
-- waits between batches. Asking less would mean finding less, which is not what
-- -T is for; -T is the operator saying how much of the target's attention this
-- scan may take.
--
-- nmap's own templates set a delay between probes - 5 min at -T0, 15 s at -T1,
-- 0.4 s at -T2, none above - and applying those per REQUEST to a 939-path sweep
-- would take four hours at -T1. So the delay is per batch, which makes the
-- ladder land where the operator would expect it. Against the published list:
--
--   0 paranoid     188 batches of  5, 2.0 s apart   ~6 min per web port
--   1 sneaky        94 batches of 10, 1.0 s apart   ~1.5 min
--   2 polite        38 batches of 25, 0.5 s apart   ~19 s
--   3 normal        10 batches of 100, 0.1 s apart  ~1 s   (the default)
--   4 aggressive     4 batches of 250, no wait
--   5 insane         one batch, no wait
--
-- Pipelining inside a batch is nselib's, and it already honours the server's
-- own Keep-Alive limit and the http.max-pipeline script argument.
local PACE_BY_TIMING = {
  [0] = {5, 2.0},
  [1] = {10, 1.0},
  [2] = {25, 0.5},
  [3] = {100, 0.1},
  [4] = {250, 0},
  [5] = {math.huge, 0},
}
local DEFAULT_PACE = {100, 0.1}

-- ---------------------------------------------------------------- 1. Util

--- Index a chain of keys in somebody else's JSON without raising.
--
-- Every field below this line comes from an HTTP response. A record that is a
-- string where a table was expected must skip the port's finding, not take the
-- whole scan down with it.
local function dig(value, ...)
  for _, key in ipairs({...}) do
    if type(value) ~= "table" then
      return nil
    end
    value = value[key]
  end
  return value
end

--- The value only if it is a table, otherwise an empty one.
local function as_table(value)
  return type(value) == "table" and value or {}
end

--- The value only if it is a non-empty string.
local function as_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
end

--- Cut text to a limit, leaving a mark that says something was cut.
local function clip(text, limit)
  if limit and #text > limit then
    return text:sub(1, math.max(1, limit - 1)) .. "~"
  end
  return text
end

--- Text that survives nmap's own output escaping unchanged.
--
-- escape_for_screen() in output.cc passes TAB, LF and 0x20-0x7E and rewrites
-- everything else as the literal text \xHH - in the screen output, in -oN and
-- in -oX alike. A title arriving with a typographic quote would therefore be
-- displayed as \xE2\x80\x9C, so it is folded here instead.
local function ascii(value, limit)
  local text = tostring(value or ""):gsub("[^\32-\126]", " ")
  return clip(text:gsub("%s+", " "):gsub("^ ", ""):gsub(" $", ""), limit)
end

--- ascii(), except that line breaks survive.
--
-- The banner channel matches each line of a probe response on its own, because
-- recog's banner patterns are written against a single greeting line: 143 of
-- the 163 shipped banner rules are anchored with ^ or $. Folding a payload with
-- ascii() collapses its newlines into spaces, which left fingerprint_banner
-- splitting a single line and every one of those rules unable to fire unless
-- its software happened to open the first probe response.
local function ascii_lines(value, limit)
  local text = tostring(value or ""):gsub("[^\32-\126\n]", " ")
  -- Runs of blanks collapse as they do in ascii(); a newline absorbs the blanks
  -- around it rather than being absorbed by them.
  text = text:gsub("[ \t]+", " "):gsub(" *\n *", "\n"):gsub("\n\n+", "\n")
  return clip(text:gsub("^%s+", ""):gsub("%s+$", ""), limit)
end

--- A score, or nil when the API did not score the bulletin.
--
-- Two of 102 rows measured on one real CPE carry score 0.0 with vector "NONE".
-- Read as 0.0 they sort below every MEDIUM finding; read as absent they sort as
-- unscored, which is what they are.
local function score_of(cvss)
  if type(cvss) ~= "table" then
    return nil
  end
  if cvss.version == "NONE" or cvss.vector == "NONE" then
    return nil
  end
  local score = tonumber(cvss.score)
  if score == nil then
    return nil
  end
  -- CVSS is defined on 0-10. A "score" outside it is not a score, and one of
  -- 12345.678 formats into a four-column cell as 12345.7, shifting that row
  -- clear of the header and the rule.
  if score < 0 or score > 10 then
    return nil
  end
  -- A score of exactly 0.0 is not a score. The free endpoint gives every
  -- exploit bulletin 0 - 1.x carried the note "exploits seem to have cvss == 0,
  -- so print them anyway" - and two of 102 rows measured on one real CPE pair
  -- it with vector "NONE". Read as 0.0 those sort below every MEDIUM finding;
  -- read as absent they sort as unscored, which is what they are, and
  -- enrichment can still supply a real score later.
  if score == 0 then
    return nil
  end
  -- tostring() on a table yields its address, which would put a heap pointer in
  -- the report - different on every run, which defeats the whole point of
  -- deterministic output.
  local kind
  local version = as_string(cvss.version) or tonumber(cvss.version)
  if version ~= nil and version ~= "NONE" then
    kind = "cvss" .. tostring(version)
  end
  return score, kind
end

--- A score only if it is on the 0-10 scale everything here is laid out for.
local function bounded_score(value)
  if value == nil or value < 0 or value > 10 then
    return nil
  end
  return value
end

--- The NVD severity word for a score.
local function severity_of(score)
  if score == nil then
    return "Unknown"
  end
  for _, band in ipairs(SEVERITY_BANDS) do
    if score >= band[1] then
      return band[2]
    end
  end
  return "NONE"
end

-- ----------------------------------------------------------------- 2. Cpe

--- The same CPE under every nginx spelling, or nil if it is not nginx.
local function nginx_variants(cpe)
  for _, spelling in ipairs(NGINX_SPELLINGS) do
    if cpe:find(spelling, 1, true) then
      local variants = {}
      for _, other in ipairs(NGINX_SPELLINGS) do
        variants[#variants + 1] = (cpe:gsub(spelling, other, 1))
      end
      return variants
    end
  end
end

--- One key for a product that has three names, so it is reported once.
local function canonical_cpe(cpe)
  local variants = nginx_variants(cpe)
  return variants and variants[1] or cpe
end

--- The version and the trailing update part of a CPE.
local CPE_VERSION_PATTERN = ":([%d%.%-%_]+)([^:]*)$"

-- The longest identity worth asking about. nmap builds CPEs out of banner text,
-- so a hostile banner can make one arbitrarily long: measured, a 4000-character
-- version produced an 8 KB request line, which most servers refuse outright and
-- which puts 8 KB of the target's choosing into the report as a group key.
--
-- Measured against the 8 396 CPE templates nmap ships: median 26 characters,
-- 99th percentile 50, longest 80 before its version is filled in. 256 is four
-- times the realistic maximum, so refusing beyond it cannot cost a real lookup.
-- Refused rather than truncated: a truncated CPE is a DIFFERENT identity, and
-- asking about the wrong one produces a silent false negative.
local MAX_IDENTITY = 256

-- How many identities one SOURCE on a port may contribute, and how many the
-- whole scan may look up. MAX_IDENTITY caps the LENGTH of one identity, not the
-- NUMBER of them: measured, an 8 KB body of repeated "Server: nginx/9.x.y"
-- lines produced 301 <cpe> elements on nmap's own service element and 903 GETs
-- to the API, from a scan the operator did not ask for - with the count chosen
-- by the target. A real web stack has fewer than ten.
--
-- Per source, not per port: the banner channel and the path sweep each count
-- their own, so a port that has both can reach twice this. That is deliberate -
-- they read different things and neither should be able to crowd the other out
-- - and the scan-wide ceiling below is what actually bounds the requests.
local MAX_IDENTITIES_PER_PORT = 24
local MAX_LOOKUPS_PER_SCAN = 512

-- How long the pattern set may run on one port - ONE budget, shared by the
-- banner pass, the sweep and the probes. Each used to start its own, so a port
-- that did all three could spend three times this in non-yielding matching
-- while the constant said otherwise. The byte budget was calibrated
-- on benign HTML at roughly a second per megabyte, but cost is not a function of
-- length: two shipped jQuery patterns are lazy and unanchored, which is O(n^2)
-- on adversarial text, and 128 KB of the substring "jquery" - one response the
-- body cap already allows - was measured at 24.9 s. Pattern matching does not
-- yield, so that is the whole scan frozen. Bytes remain as a second barrier.
local SWEEP_TIME_BUDGET = 3.0

-- What a rule is allowed to SEE, which is the only thing that actually bounds
-- it. Every budget in this file bounds work BETWEEN calls to string.find; none
-- can pre-empt one, because Lua pattern matching neither yields nor returns
-- until it is done. Measured against the shipped rule "Bootstrap, body" on a
-- body of "<link href=bootstrap" repeated with no ">": 2 KB took 0.064 s, 4 KB
-- 0.50 s, 8 KB 3.9 s, 16 KB 31.8 s - cubic, so the 128 KB the body cap already
-- admits is roughly four and a half HOURS inside one uninterruptible call, with
-- the whole nmap scheduler stopped. The 3 s budget is consulted before the call
-- and passes.
--
-- A rule's anchor is a literal its pattern cannot match without, so the pattern
-- only ever needs the text around that literal. All 74 body-channel rules carry
-- one; only 12 of 722 rules have none at all, and none of those read a body.
-- Sized by measurement, not by eye. The same shipped rule against the same
-- adversarial body: 256 B costs 0.7 ms, 512 B 7 ms, 1 KB 64 ms, 2 KB 917 ms.
-- 512 plus 256 of lookbehind is far more than any real <link href=...> tag needs
-- and keeps one rule under ~7 ms, so the time budget below can actually bound
-- the pass.
local MATCH_LOOKBEHIND = 256
local MATCH_WINDOW = 512
-- A rule with no anchor cannot be centred on anything, so it reads from the
-- start - generously, because a header block is not a body, and no body-channel
-- rule is anchorless (measured: 12 of 722 rules have no anchor, none on body).
local UNANCHORED_WINDOW = 4096
-- How many times one rule's anchor is chased through one subject. A body of ten
-- thousand "bootstrap"s is not a page being fingerprinted.
local MAX_ANCHOR_HITS = 8

-- How many targeted version probes one port may send. A probe only fires when a
-- product was positively identified and no rule produced a version for it, so
-- on a host running none of the products in the probe table this is zero
-- requests. Three is the ceiling for the pathological case: a page that
-- deliberately carries every detector at once, which a target can trivially
-- build, and which must not turn into one request per probe in the table.
local MAX_PROBES_PER_PORT = 3

-- There is deliberately no CPE-to-dictionary converter here, and no call to
-- POST /api/v4/audit/software/. That endpoint rejects nmap's CPE 2.2 form with
-- a 400, so using it needs a converter - and a converter needs to percent-decode
-- each component, which is where the hazard lives: nmap builds CPEs out of
-- banner text, so a hostile banner can carry %2A, which decodes to "*", the ANY
-- wildcard, turning one lookup into "every CVE for this product".
--
-- Nothing here decodes anything. The free endpoint takes the CPE verbatim,
-- byte-identical to what nmap emitted, which is both what keeps its answers on
-- the shared CDN cache and the reason no injection is possible. An earlier draft
-- carried the converter and its guard for a fallback that is not written; that
-- is scaffolding, and the guard read as load-bearing while protecting nothing.
-- If burp is ever retired, this comment is the warning to whoever writes it.

-- --------------------------------------------------------------- 3. State

--- Everything that outlives one action() call, under one registry key.
--
-- The chunk is re-executed once per open port, so nothing here can be a
-- file-level table. The registry is shared with every other script in the run,
-- which is why the API key is never put in it - only the derived mode is.
local function state()
  local shared = nmap.registry.vulners
  if not shared then
    shared = {
      lookups = {},   -- burp answers, keyed by CPE or software label
      looked_up = 0,  -- identities asked about this scan, capped scan-wide
      docs = {},      -- enriched documents, keyed by bulletin id
      claimed = {},   -- ids in flight
      pending = {},   -- lookups in flight
      failed = {free = false, keyed = false},
      spent = 0,      -- billed items this scan
      balance = nil,  -- last x-vulners-wallet-amount seen
      unnamed = 0,    -- services that produced no usable identity
      -- Separate from mode on purpose. Reaching a spending ceiling must not
      -- withdraw the token: POST /api/v3/search/id/ needs it and costs nothing,
      -- so conflating the two made a BUDGET limit silently switch off a FREE
      -- feature for every remaining host - punishing the operator who set a low
      -- ceiling with a worse report on the hosts they were not spending on.
      billed = {},    -- audit/smart answers, keyed by the string bought
      billing_off = false,
      deprecated = {},-- legacy argument names already warned about, once each
      mode = "free",
      degraded = nil, -- why the scan dropped to the free path
      consulted = false,
      -- Set as they are learnt rather than declared here, because assigning nil
      -- creates no key: catalog, catalog_loaded and catalog_note come from the
      -- prerule, free_stopped from a dead free leg, billing_stopped from
      -- stop_billing.
    }
    nmap.registry.vulners = shared
  end
  return shared
end

--- Wait, briefly, for a lookup another host started.
--
-- nmap runs the port scripts of a host group concurrently, so a network of
-- identical servers would otherwise ask the same question once per host before
-- the first answer arrives. The wait is bounded: an owner that died must not
-- hang the scan.
local function wait_for_pending(pending, key)
  local waited = 0
  while pending[key] and waited < PENDING_WAIT_LIMIT do
    stdnse.sleep(PENDING_WAIT_STEP)
    waited = waited + PENDING_WAIT_STEP
  end
end

--- Drop to the free path for the rest of the scan, and record why.
--
-- The 1.x enterprise script set one scan-wide "failed" flag, which in a merged
-- script would silence the free path too - so a user whose trial key expired
-- would get strictly less than a user with no key at all, and silently.
local function degrade(reason)
  local shared = state()
  if shared.mode ~= "free" then
    stdnse.verbose1("vulners: %s; continuing without the key", reason)
  end
  shared.mode = "free"
  shared.degraded = shared.degraded or reason
end

--- Stop one leg for the rest of the scan, and remember why.
--
-- Both halves matter, and each was missing on a different path.
--
-- A dead KEYED leg has to drop the mode, or the free fallback stays suppressed
-- and a user whose key was rate-limited gets strictly less than a user with no
-- key at all - which is the exact regression the degrade ladder exists to
-- prevent, and it was reachable through every door except 401/402/403.
--
-- A dead FREE leg has to be reported, or a scan that checked nothing looks
-- exactly like a scan that found nothing: the burp GET carries no key, so a 403
-- there is a CDN verdict that silences every port on every host while the
-- postrule prints the ordinary "get a key" advertisement.
local function stop_leg(leg, reason)
  local shared = state()
  shared.failed[leg] = true
  if leg == "keyed" then
    degrade("the vulners key stopped working: " .. reason)
  else
    shared.free_stopped = shared.free_stopped or reason
    stdnse.verbose1("vulners: %s; no lookups could be made", reason)
  end
end

--- Stop buying identifications for the rest of the scan, and say why once.
--
-- Beside stop_leg because it is the same kind of decision and the opposite
-- verdict: this one stops SPENDING and nothing else. Reaching a spending
-- ceiling must never withdraw the token, because search/id needs it and costs
-- nothing.
local function stop_billing(reason)
  local shared = state()
  shared.billing_off = true
  shared.billing_stopped = reason
  stdnse.verbose1("vulners: %s; identification stops, everything else continues",
    reason)
end

-- -------------------------------------------------------------- 4. Config

--- Read a script argument, accepting the 1.x names for one release.
--
-- stdnse.get_script_args(a, b) returns ONE VALUE PER NAME, not the first
-- non-nil, so passing two names and reading one result silently ignores the
-- second. Probed: flat(two names) -> nil, braced(one set) -> the legacy value.
-- The braces are what make the compatibility layer work at all.
local function arg_value(name, legacy)
  local qualified = SCRIPT_NAME .. "." .. name
  if legacy == nil then
    return stdnse.get_script_args(qualified)
  end
  local value = stdnse.get_script_args({qualified, legacy})
  if value ~= nil and stdnse.get_script_args(qualified) == nil then
    -- Once for the scan, not once per port. The chunk is re-executed for every
    -- open port and config() re-reads every argument each time, so a host with
    -- twenty open ports printed the same advice twenty times.
    local said = state().deprecated
    if not said[legacy] then
      said[legacy] = true
      stdnse.verbose1("vulners: --script-args %s is deprecated, use %s",
        legacy, qualified)
    end
  end
  return value
end

--- Is this token one that can safely be put in a header?
--
-- nselib concatenates a header as name .. ": " .. value with no validation
-- (http.lua:1314-1316), so a CR or LF in the token injects whatever follows it
-- into the request. The file reader has always rejected control characters -
-- a Windows-written key file leaves a CR - but a key from --script-args or from
-- the environment reached the header unchecked.
local function usable_token(key)
  return key ~= nil and not key:find("%c")
end

--- The first line of a key file, or nil plus the reason it could not be read.
local function key_from_file(path)
  local file = io.open(path, "r")
  if file == nil then
    return nil, "cannot be opened"
  end
  local line = file:read("*line")
  file:close()
  if line == nil then
    return nil, "is empty"
  end
  -- A file written on Windows leaves a carriage return on the key, which the
  -- service answers with 401 - and a 401 used to silence the script for the
  -- whole scan with nothing to say why.
  local key = line:match("^%s*(.-)%s*$")
  if key == "" then
    return nil, "is blank"
  end
  if not usable_token(key) then
    return nil, "contains a control character"
  end
  return key
end

--- Where the key comes from, in order of how explicit the operator was.
--
-- A file the operator NAMED and that cannot be read is fatal for the run: it
-- matches this project's existing rule for a named paths file - an operator who
-- names a file means that file. Only the implicit lookups fall through quietly.
local function discover_key(named_file)
  local key = as_string(arg_value("api_key", "vulners_enterprise.api_key"))
  if key then
    if not usable_token(key) then
      return nil, nil, "the vulners.api_key argument contains a control character"
    end
    return key, "script argument"
  end

  if named_file then
    local from_file, why = key_from_file(named_file)
    if from_file then
      return from_file, "api_key_file"
    end
    return nil, nil, string.format("the key file %s %s", named_file, why)
  end

  key = as_string(os.getenv("VULNERS_API_KEY"))
  if key then
    if not usable_token(key) then
      return nil, nil, "VULNERS_API_KEY contains a control character"
    end
    return key, "VULNERS_API_KEY"
  end

  -- fetchfile honours --datadir, $NMAPDIR, ~/.nmap and %APPDATA%\nmap.
  local found = nmap.fetchfile("vulners.key")
  if found then
    local from_file = key_from_file(found)
    if from_file then
      return from_file, found
    end
  end

  local home = os.getenv("HOME")
  if home then
    local from_file = key_from_file(home .. "/.nmap/vulners.key")
    if from_file then
      return from_file, "~/.nmap/vulners.key"
    end
  end

  return nil
end

--- Everything the run needs from its arguments, resolved once per chunk.
local config_cache = nil

local function config()
  if config_cache then
    return config_cache
  end

  local mincvss = tonumber(arg_value("mincvss", "vulners_enterprise.mincvss")) or 0.0
  -- Floored: string.rep demands an integer, so a width of 80.5 propagated a
  -- fraction into the column arithmetic and raised inside action() - which nmap
  -- turns into "Script execution failed", losing every finding for that port in
  -- both the text and the XML.
  -- tointeger as well as floor: math.floor(1e308) returns the FLOAT 1e308,
  -- because that value has no integer representation, and it then travels into
  -- string.rep as a float and raises inside action() - losing the port's whole
  -- result, which is the very failure the floor was added to prevent. Bounded
  -- above too: a title column computed from an absurd width is not a table.
  local width = math.tointeger(
    math.floor(tonumber(arg_value("width")) or DEFAULT_WIDTH)) or DEFAULT_WIDTH
  local max_items = tonumber(arg_value("max_items")) or DEFAULT_MAX_ITEMS
  local host = as_string(arg_value("api_host", "vulners_enterprise.api_host"))
  -- Script arguments always arrive as strings, while http needs a number.
  local port = tonumber(arg_value("api_port", "vulners_enterprise.api_port"))
  local key_file = as_string(arg_value("api_key_file",
    "vulners_enterprise.api_key_file"))

  local key, source, fatal = discover_key(key_file)

  -- Where the dictionaries come from, and whether to go at all. A mirror is
  -- the airgapped answer, the same way api_host is for the lookups; "none" is
  -- for a scan that must make no request but the ones it was asked for.
  local catalog_url = as_string(arg_value("catalog_url"))
  if catalog_url and catalog_url:sub(-1) ~= "/" then
    catalog_url = catalog_url .. "/"
  end
  local catalog_mode = (as_string(arg_value("catalog")) or "auto"):lower()
  if catalog_mode ~= "none" then
    catalog_mode = "auto"
  end

  config_cache = {
    mincvss = mincvss,
    width = math.min(1000, math.max(40, width)),
    max_items = max_items,
    paths_arg = arg_value("paths", "http-vulners-regex.paths"),
    api_host = host or "vulners.com",
    api_port = port or 443,
    key = key,
    key_source = source,
    fatal = fatal,
    catalog_url = catalog_url or CATALOG_BASE,
    catalog_mode = catalog_mode,
  }

  if key then
    stdnse.debug1("Api key is set (%d characters) from %s", #key, tostring(source))
    -- Only if the scan has not already given up on the key. The chunk is
    -- re-executed once per OPEN port, so this line runs again on every port -
    -- and it used to overwrite the mode that degrade() had set on an earlier
    -- one. A key the service rejected therefore came back to life on port 2:
    -- the free fallback was skipped because the mode read "keyed" again, and
    -- audit_smart was dead behind failed.keyed, so the port reported NOTHING.
    -- Strictly less than a user with no key at all - the exact regression the
    -- degrade ladder exists to prevent.
    local shared = state()
    if not shared.degraded then
      shared.mode = "keyed"
    end
  end

  return config_cache
end

-- ---------------------------------------------------------------- 5. Http

--- Is this request allowed to carry the key?
--
-- http.get/post without options.scheme route through comm.tryssl, which tries
-- PLAINTEXT FIRST for any port outside its likely-SSL list - probed, 443 and
-- 8443 try ssl first while 8080 and 9999 do not. So the scheme is always set
-- explicitly, and the key travels only when the transport is actually https or
-- the host is loopback, which is what the offline test harness uses.
local function key_is_safe_here(cfg)
  if cfg.api_port == 443 then
    return true
  end
  local host = cfg.api_host
  return host == "127.0.0.1" or host == "localhost" or host == "::1"
end

--- A whole number the service sent, or nil when it sent something else.
--
-- Validated, because these are bytes from a response like any other. A
-- fractional amount reached string.format("%d") and raised in the postrule.
local function whole(value)
  local number = tonumber(value)
  if number == nil then
    return nil
  end
  number = math.tointeger(number)
  if number == nil or number < 0 or number > 1e12 then
    return nil
  end
  return number
end

--- What the service says this billed call cost, or nil if it did not say.
--
-- ONE function, because two readers ask this question and they must agree. They
-- did not: record_wallet charged only a VALID cost, while audit_smart released
-- its reservation on the header merely being PRESENT. So
-- "x-vulners-wallet-cost: abc" charged nothing and refunded everything -
-- shared.spent never advanced, and vulners.max_items became a ceiling the
-- service itself could disarm. A present-but-unreadable header must mean
-- exactly what an absent one means: we do not know, so the reservation stands.
local function billed_cost(response)
  return whole(dig(response, "header", "x-vulners-wallet-cost"))
end

--- Read the wallet headers the billed endpoints send back.
local function record_wallet(response)
  local shared = state()
  local amount = whole(dig(response, "header", "x-vulners-wallet-amount"))
  if amount then
    shared.balance = amount
  end
  local cost = billed_cost(response)
  if cost then
    shared.spent = shared.spent + cost
  end
end

--- One request, retried when retrying can change the answer.
--
-- Transport failures, 408, 429 and 5xx are retried; everything else is final.
-- 5xx is retried on the billed endpoints too: the service bills on a 200, so a
-- retried 500 cannot double-charge.
--
-- The verb is not a parameter: it follows from whether there is a body, which
-- is the only shape this script ever needs. A `method` argument used to sit in
-- the signature and no line read it, so a caller passing "POST" with no body
-- would have got a GET and been told nothing.
--
-- @param leg "free" or "keyed" - the two keep independent failure flags, so a
--        rejected key never silences the free path.
-- @param billed true when the service charges for this call. It changes one
--        thing: a transport failure is NOT retried. "Billing happens on a 200,
--        so a retried 5xx cannot double-charge" is sound for a 5xx, because the
--        client saw the server's verdict - it is not sound for a timeout, where
--        the server may have completed and charged while the client gave up.
local function request(leg, path, body, billed)
  local cfg = config()
  local shared = state()

  if shared.failed[leg] then
    stdnse.debug1("Skipping %s request, that leg already failed in this scan", leg)
    return nil
  end

  local header = {
    ["User-Agent"] = USER_AGENT,
    ["Accept-Encoding"] = ACCEPT_ENCODING,
  }
  if body then
    header["Content-Type"] = "application/json"
  end
  -- The burp request never carries the key, in any mode. Measured: a keyed
  -- burp GET answers cf-cache-status DYNAMIC, an unkeyed one is cached for four
  -- hours. Sending the key would take every user of this script off the shared
  -- warm cache and onto the origin, and buy nothing - the endpoint does not
  -- need a key and its answer does not improve with one.
  if leg == "keyed" and cfg.key and key_is_safe_here(cfg) then
    header["X-Api-Key"] = cfg.key
  end

  local options = {
    header = header,
    any_af = true,
    scheme = cfg.api_port == 443 and "https" or "http",
    timeout = REQUEST_TIMEOUT,
  }

  local attempt = 1
  local asked_to_wait_longer = false
  while attempt <= MAX_ATTEMPTS do
    local response
    if body then
      response = http.post(cfg.api_host, cfg.api_port, path, options, nil, body)
    else
      response = http.get(cfg.api_host, cfg.api_port, path, options)
    end
    local status = response and response.status

    if status == 200 then
      record_wallet(response)
      return response
    end

    -- 401 and 403 are verdicts on the TOKEN, so they stop the keyed leg. 402 is
    -- a verdict on the WALLET, and only the billed endpoint can give one: taking
    -- the leg down for it switched off search/id - which needs the token and
    -- costs nothing - for every later host, which is the exact regression
    -- stop_billing exists to prevent, arriving through the other door.
    if status == 401 or status == 403 then
      stop_leg(leg, string.format("the API answered %d", status))
      return nil
    end
    if status == 402 then
      if billed then
        stop_billing("the vulners wallet is out of credits")
      else
        stop_leg(leg, "the API answered 402")
      end
      return nil
    end

    if status ~= nil and status ~= 408 and status ~= 429 and status < 500 then
      stdnse.debug1("Response is %d, giving up on this request", status)
      return nil
    end

    if status == nil and billed then
      stdnse.debug1("A billed call did not answer; not re-sending it, because " ..
        "the service may have completed and charged for it")
      return nil
    end

    if attempt == MAX_ATTEMPTS then
      if status == nil then
        stop_leg(leg, "the API could not be reached")
        stdnse.debug1("Could not reach the API in %d attempts", MAX_ATTEMPTS)
      elseif status == 429 then
        -- Same distinction: the billed endpoint rate-limiting says nothing
        -- about the token, and the free-of-charge keyed call must survive it.
        if billed then
          stop_billing("the identification endpoint rate-limited this scan")
        else
          stop_leg(leg, "the API rate-limited this scan")
        end
        stdnse.debug1("The API is rate limiting this scan; stopping requests")
      elseif asked_to_wait_longer then
        -- A Retry-After beyond what we are willing to wait is the service
        -- saying "not soon", which is a statement about the service and not
        -- about this request. Without this, a 503 answering
        -- "Retry-After: 99999" cost 120 s of sleep PER IDENTITY: a scan with
        -- ten of them would have spent twenty minutes asleep to learn the same
        -- thing ten times.
        --
        -- A bare 5xx is deliberately NOT treated this way: it can be one
        -- malformed identity upsetting the backend, and turning the whole leg
        -- off would report every later host as having nothing known.
        stop_leg(leg, "the API asked for more delay than this scan will wait")
        stdnse.debug1("The API asked for more delay than this scan will wait; " ..
          "stopping requests")
      else
        stdnse.debug1("The API kept answering %d, giving up", status)
      end
      return nil
    end

    local delay = attempt
    local retry_after = tonumber(dig(response, "header", "retry-after"))
    if retry_after then
      -- A header of "-1" would otherwise reach stdnse.sleep, which raises.
      delay = math.max(0, math.min(retry_after, RETRY_AFTER_CAP))
      -- >=, not >. A Retry-After of exactly the cap clamped to the cap, slept
      -- twice for it, and then missed this branch entirely - so every identity
      -- paid 120 s again. Measured: a service answering "Retry-After: 60" turned
      -- a six-second scan into 307 seconds.
      if retry_after >= RETRY_AFTER_CAP then
        asked_to_wait_longer = true
      end
    end
    stdnse.sleep(delay)
    attempt = attempt + 1
  end
end

-- ----------------------------------------------------------------- 6. Api

--- Decode a response body, distinguishing the three envelopes in use.
--
-- v3 answers {result = "OK"|"warning"|"error", data = {...}} where result is a
-- STRING; v4 answers {result = {...}} where result is an ARRAY; a v4 validation
-- failure answers {errors = [...]} with neither. Code that tests result == "OK"
-- rejects a good v4 answer, and code that iterates result on a v3 answer walks
-- the characters of "OK", so the dispatch is on the TYPE of result.
--
-- @return kind ("v3"|"v4"|"errors"), payload, message
local function envelope(response)
  if response == nil then
    return nil
  end

  local ok, body = json.parse(response.body or "")
  if not ok or type(body) ~= "table" then
    stdnse.debug1("Unable to parse the response as json")
    return nil
  end

  if type(body.errors) == "table" and body.result == nil then
    local first = as_table(body.errors[1])
    stdnse.debug1("The API rejected the request: %s", tostring(first.msg))
    stdnse.debug1("Offending input: %s", tostring(first.input))
    return "errors", body.errors
  end

  if type(body.result) == "table" then
    return "v4", body.result
  end

  if type(body.result) == "string" then
    -- "OK" with a data field that is not an object is not a clean answer, it is
    -- a malfunction. Coercing it to an empty table made the scan remember the
    -- software as having nothing known about it, for the rest of the run - which
    -- is the one thing the caching rule forbids.
    if type(body.data) ~= "table" then
      stdnse.debug1("A v3 answer carried result=%s with no usable data",
        tostring(body.result))
      return nil
    end
    return "v3", body.data, body.result
  end

  return nil
end

--- Look one software identity up on the free endpoint.
--
-- One request per identity: the endpoint does not batch, and a list is silently
-- mangled into one nonsense CPE. GET rather than POST, because only GET is
-- CDN-cached.
--
-- @return rows, answered, explain
--         answered is false when the request itself failed, which must never be
--         remembered as "this software is clean".
local function burp_lookup(software, version, kind)
  local parts = {}
  for _, pair in ipairs({{"software", software}, {"version", version},
                         {"type", kind}}) do
    if pair[2] ~= nil then
      -- Sent the way nmap's own shipped copy sends it: verbatim apart from what
      -- would change the meaning of the request. ':' and '/' are legal in a
      -- query (RFC 3986 3.4), and leaving them alone means the lookup does not
      -- depend on the endpoint decoding anything - which mattered on
      -- 2026-08-18, when escaped values were answered with errorCode 303 for a
      -- few hours while the raw form kept working. '+' is escaped, because the
      -- endpoint reads it as a space.
      -- Note there is no "*" in this class. It is the ANY wildcard, and a CPE
      -- carrying one - which any other script can put in host.registry - would
      -- widen one lookup into "every vulnerability for this product".
      local escaped = tostring(pair[2]):gsub("[^!$'(),%-./0-9:;@A-Z_a-z~]",
        function(char) return ("%%%02X"):format(char:byte()) end)
      parts[#parts + 1] = pair[1] .. "=" .. escaped
    end
  end

  local response = request("free", BURP_PATH .. "?" .. table.concat(parts, "&"))
  local kind_of, data, result = envelope(response)

  if kind_of ~= "v3" then
    return nil, false
  end

  local explain = as_table(data.search_explain)

  if result == "warning" then
    -- An authoritative empty answer: the identity resolved and has nothing.
    -- The CDN caches error bodies for four hours too, so this is only treated
    -- as "nothing found" when the service actually said so.
    return {}, true, explain
  end

  if result ~= "OK" then
    stdnse.debug1("The free endpoint answered result=%s", tostring(result))
    return nil, false, explain
  end

  local rows = {}
  for _, hit in ipairs(as_table(data.search)) do
    -- burp answers are Elasticsearch-shaped: the payload is under _source.
    local source = as_table(as_table(hit)._source)
    local id = as_string(source.id)
    if id then
      local score, kind_name = score_of(source.cvss)
      rows[#rows + 1] = {
        id = id,
        type = as_string(source.type) or "unknown",
        family = as_string(source.bulletinFamily),
        cvss = score,
        cvss_type = kind_name,
        -- Range-checked exactly as score_of checks cvss, and for the same
        -- measured reason: a value of 12345.678 formats into a four-column cell
        -- and shifts that row clear of the header and the rule.
        ai_score = bounded_score(tonumber(dig(source, "ai_score", "value"))),
      }
    end
  end

  return rows, true, explain
end

--- The fields the enrichment call asks for, on every id, every time.
--
-- Asked for unconditionally: a licence that does not grant one simply omits it,
-- and the renderer follows what arrives. An earlier draft asked for "metrics"
-- only on CVE-family documents, reasoning that an exploit bulletin has no ADP
-- container. That is false and expensively so - measured over a 100-document
-- batch, 55 of the 62 exploit-family documents carry metrics, and BOTH KEV hits
-- in the batch were on exploit documents. The partition would have emptied the
-- top ranking bucket outright.
--
-- "enchantments" is deliberately absent: 11.3 KB per document against 1.3 KB
-- for metrics, and what it buys is a different exploitation signal rather than
-- a cheaper route to the same one.
local SEARCH_ID_FIELDS = {
  "id", "type", "bulletinFamily", "title", "href", "published", "cvss",
  "epss", "cvelist", "metrics",
}

--- Normalise one enriched document into the fields the report uses.
local function read_document(document)
  local id = as_string(document.id)
  if not id then
    return nil
  end

  local score, kind = score_of(document.cvss)
  local metrics = as_table(document.metrics)
  local adp = as_table(metrics.adp)

  -- epss is a list of objects, one per CVE. Taking element 1 read whichever CVE
  -- the service happened to list first: a distro advisory covering three CVEs
  -- put another CVE's probability on this row, and moved the row between
  -- ranking bands depending on list order. The entry for this document wins;
  -- failing that the worst of them, which is the honest summary for a record
  -- that covers several.
  local epss, percentile
  for _, entry in ipairs(as_table(document.epss)) do
    if type(entry) == "table" then
      local value = tonumber(entry.epss)
      local rank = tonumber(entry.percentile)
      if as_string(entry.cve) == id then
        epss, percentile = value, rank
        break
      end
      if value and (epss == nil or value > epss) then
        epss = value
      end
      if rank and (percentile == nil or rank > percentile) then
        percentile = rank
      end
    end
  end

  -- metrics.adp.ssvc.options is a list of single-key objects, so the decision
  -- has to be searched for rather than indexed.
  local ssvc
  for _, option in ipairs(as_table(dig(adp, "ssvc", "options"))) do
    if type(option) == "table" and option.Exploitation ~= nil then
      ssvc = as_string(option.Exploitation)
    end
  end

  local cvelist = {}
  for _, cve in ipairs(as_table(document.cvelist)) do
    if as_string(cve) then
      cvelist[#cvelist + 1] = cve
    end
  end

  return {
    id = id,
    type = as_string(document.type),
    family = as_string(document.bulletinFamily),
    title = as_string(document.title),
    href = as_string(document.href),
    published = as_string(document.published),
    cvss = score,
    cvss_type = kind,
    epss = epss,
    epss_percentile = percentile,
    -- adp.kev is the CVE Program's own container, meaning CISA listed the CVE
    -- this record concerns. It arrives on exploit records too, which is why it
    -- is attributed onwards through cvelist rather than read only off CVEs.
    kev = dig(adp, "kev", "dateAdded") ~= nil or nil,
    ssvc = ssvc,
    cvelist = cvelist,
  }
end

--- Walk a list in chunks no larger than the endpoint accepts.
local function in_chunks(list, size, consume)
  for first = 1, #list, size do
    local chunk = {}
    for index = first, math.min(first + size - 1, #list) do
      chunk[#chunk + 1] = list[index]
    end
    consume(chunk)
  end
end

--- Ask for one chunk of ids and keep every document that came back.
--
-- @return true when the service answered at all. "The request failed" and "this
--         id has no document" are different facts, and only the second is worth
--         remembering.
local function enrich_chunk(chunk)
  local shared = state()
  local body = json.generate({id = chunk, fields = SEARCH_ID_FIELDS})
  local kind, data, result = envelope(request("keyed", SEARCH_ID_PATH, body))
  -- The result STRING matters, not just the envelope kind. Vulners reports
  -- business errors inside an HTTP 200 - {"result":"error","data":{...}} - and
  -- data is a table, so the envelope is a perfectly good "v3". Taking that as an
  -- answer made the caller write docs[id] = false for the whole chunk, so one
  -- transient error permanently marked up to 100 bulletins "asked, nothing
  -- there" for the rest of the scan: every later host silently lost titles,
  -- EPSS, KEV and cvelist, and losing cvelist also disarms exploit attribution.
  -- burp_lookup has always made this distinction; this call never did.
  if kind ~= "v3" or (result ~= "OK" and result ~= "warning") then
    return false
  end

  for _, document in pairs(as_table(data.documents)) do
    if type(document) == "table" then
      local row = read_document(document)
      if row then
        shared.docs[row.id] = row
      end
    end
  end
  return true
end

--- Enrich a set of bulletin ids, at most 100 per call, once per scan.
--
-- search/id needs a key and costs no credits, so this runs for every finding
-- whatever discovered it. It is a POST and therefore never CDN-cached, which
-- makes the scan-wide cache load-bearing rather than an optimisation: one
-- Apache CPE alone answers with 342 ids, and a host with five web ports on
-- overlapping software pools a couple of thousand.
--
-- Claiming is per id, not per port. A port claims the ids nobody holds, asks
-- only about its own claims, and waits for the rest - so the overlap between
-- two ports is fetched once for the scan instead of once per port.
local function enrich(ids)
  local shared = state()
  local cfg = config()

  if not cfg.key or shared.mode ~= "keyed" then
    return
  end

  local mine, waiting = {}, {}
  local queued = {}
  for _, id in ipairs(ids) do
    if shared.docs[id] == nil and not queued[id] then
      queued[id] = true
      if shared.claimed[id] then
        waiting[#waiting + 1] = id
      else
        shared.claimed[id] = true
        mine[#mine + 1] = id
      end
    end
  end

  in_chunks(mine, ID_CHUNK_SIZE, function(chunk)
    local answered = enrich_chunk(chunk)
    for _, id in ipairs(chunk) do
      shared.claimed[id] = nil
    end
    if not answered then
      stdnse.debug1("Could not enrich a chunk of %d ids", #chunk)
      return
    end
    -- An id the answer did not carry is one the service holds nothing for.
    -- Leaving it unmarked made every later port re-ask about it for the whole
    -- scan: a /24 spent 254 POSTs re-learning one negative.
    for _, id in ipairs(chunk) do
      if shared.docs[id] == nil then
        shared.docs[id] = false
      end
    end
  end)

  -- Wait for the ids somebody else claimed, then take over the ones that never
  -- arrived. Without the second half a port that died mid-enrichment cost every
  -- other port its enrichment for those ids for the whole scan - and the design
  -- says a claim whose owner died is re-claimed after the timeout, so this was
  -- documented behaviour that was not there.
  -- ONE bound for the whole set, not one per id. wait_for_pending resets its own
  -- counter on every call, so waiting per id multiplied the bound by the number
  -- of ids: one Apache CPE answers with 342, and a port whose owner died left
  -- the next port asleep for nearly three hours before it printed a line.
  --
  -- The first still-held id is waited for; by the time that bound expires the
  -- owner is gone for all of them, so the rest are swept without waiting again.
  local orphaned = {}
  local waited_once = false
  for _, id in ipairs(waiting) do
    if shared.claimed[id] and not waited_once then
      wait_for_pending(shared.claimed, id)
      waited_once = true
    end
    if shared.docs[id] == nil then
      orphaned[#orphaned + 1] = id
    end
  end

  if #orphaned == 0 then
    return
  end

  stdnse.debug1("Re-claiming %d enrichment ids whose owner never answered",
    #orphaned)
  in_chunks(orphaned, ID_CHUNK_SIZE, function(chunk)
    -- Claimed before the request: without this every port that waited out the
    -- same dead owner issues the same chunk at the same moment.
    for _, id in ipairs(chunk) do
      shared.claimed[id] = true
    end
    enrich_chunk(chunk)
    -- The claim is released even though it was not ours to take: its owner
    -- waited out the whole bound without answering, so it is gone. Leaving the
    -- claim would make every later port wait the same bound for the same dead
    -- owner. A duplicate request is the cheaper mistake.
    for _, id in ipairs(chunk) do
      shared.claimed[id] = nil
    end
  end)
end

--- Identify software from free-form text. The only billed call in the design.
--
-- This is what a credit buys: measured, "Apache httpd" sent to the free
-- endpoint as text returned 0 results where the CPE returned 342. A port that
-- already has a CPE never reaches here, because the free path was measured to
-- return the same CVEs as the paid one for a CPE.
--
-- Sent in batches, because the two ceilings that bound one are learnt at
-- different times: vulners.max_items is known from the start, and the wallet
-- balance is only ever readable from a previous billed call's header. The first
-- call of a scan is therefore capped purely to learn the balance, and the rest
-- of the queue follows in this same loop. Stopping after the capped call
-- instead reported five of six identities while blaming a ceiling the operator
-- never set.
local function audit_smart(strings)
  local shared = state()
  local cfg = config()

  if not cfg.key or shared.mode ~= "keyed" or #strings == 0 then
    return nil
  end

  -- Answers already bought are served from the cache, and the strings behind
  -- them are not bought again. Without this the only BILLED call in the design
  -- was the only one with no cache: a /24 of identical appliances paid 254
  -- credits for 254 copies of one answer, and the script's own description
  -- promises the opposite.
  local answers, queue = {}, {}
  for _, text in ipairs(strings) do
    local cached = shared.billed[text]
    if cached ~= nil then
      if cached ~= false then
        answers[text] = cached
      end
    else
      queue[#queue + 1] = text
    end
  end

  local first = 1
  while first <= #queue and not shared.billing_off do
    local room = cfg.max_items - shared.spent
    if room <= 0 then
      stop_billing("the scan reached its vulners.max_items ceiling")
      break
    end

    -- The balance is unknown until a billed call has answered, so on the first
    -- one this cap is the only thing standing between a large queue and an
    -- empty wallet. It is deliberately not applied afterwards.
    local ceiling = room
    if shared.balance == nil then
      ceiling = math.min(room, COLD_START_ITEMS)
    end

    local batch = {}
    for index = first, math.min(first + ceiling - 1, #queue) do
      batch[#batch + 1] = queue[index]
    end
    -- The loop's own termination proof, and not a formality. `first` advances by
    -- the size of the batch, so an empty batch is an iteration that changes
    -- nothing - and because an empty batch also sends no request, nothing in it
    -- yields, so the coroutine spins without ever handing the scheduler back:
    -- the whole nmap scan hangs, not just this port. Reaching it needs a ceiling
    -- of zero or less, which the guard above rules out today; this makes the
    -- loop safe without depending on that guard staying correct. Found by
    -- mutating that guard away, which hung the test run.
    if #batch == 0 then
      break
    end
    if shared.balance ~= nil and shared.balance < #batch then
      stop_billing("the vulners wallet is short of credits")
      break
    end

    -- Reserved BEFORE the request, not after it. nmap runs port scripts as
    -- concurrent coroutines and an http POST yields, so every port in flight
    -- used to compute its room from a "spent" that could not move until its own
    -- answer came back: two ports with 30 items each billed 61 against a ceiling
    -- of 32. The reservation is reconciled with the wallet header below.
    shared.spent = shared.spent + #batch

    local body = json.generate({software = batch, fields = {"type"}})
    local response = request("keyed", AUDIT_SMART_PATH, body, true)
    local kind, result = envelope(response)

    -- record_wallet already added the header's cost, so the reservation comes
    -- off when the service told us what it really charged. With no header the
    -- reservation stands: billing is per item, so the batch size is the honest
    -- estimate, and without it vulners.max_items would be an inert number.
    if billed_cost(response) then
      shared.spent = shared.spent - #batch
    end

    if kind ~= "v4" then
      break
    end

    for _, raw in ipairs(as_table(result)) do
      local entry = as_table(raw)
      local input = as_string(entry.input)
      if input then
        local ids = {}
        for _, record in ipairs(as_table(entry.vulnerabilities)) do
          local id = as_string(as_table(record).id)
          if id then
            ids[#ids + 1] = id
          end
        end
        answers[input] = {
          ids = ids,
          -- The smart entry carries these without being asked, which is why the
          -- field list is only {"type"}.
          cpe = as_string(entry.cpe),
          confidence = tonumber(entry.confidence),
        }
        shared.billed[input] = answers[input]
      end
    end

    -- A string the service answered nothing for is remembered too: "smart could
    -- not name this either" is an answer, and paying to be told so twice is the
    -- same mistake as paying for it twice.
    for _, text in ipairs(batch) do
      if shared.billed[text] == nil then
        shared.billed[text] = false
      end
    end

    first = first + #batch
  end

  if first <= #queue then
    -- Never drop coverage silently: a bounded scan that says nothing about the
    -- bound reads exactly like a scan that found nothing there. Said afterwards
    -- rather than before, so it names what actually stopped the queue.
    stdnse.verbose1("vulners: identified %d of %d unnamed services here; %s",
      first - 1, #queue,
      shared.billing_stopped or "the identification call did not answer")
  end

  return next(answers) ~= nil and answers or nil
end

-- --------------------------------------------------------------- 7. Model

--- Merge what enrichment knows into a discovered row.
local function enrich_row(row)
  local document = state().docs[row.id]
  -- false means "asked, and the service holds nothing" - an answer, not a gap.
  if not document or document == false then
    return row
  end
  row.title = document.title
  row.href = document.href
  row.published = document.published
  row.epss = document.epss
  row.epss_percentile = document.epss_percentile
  row.kev = document.kev
  row.ssvc = document.ssvc
  row.cvelist = document.cvelist
  row.family = row.family or document.family
  row.type = row.type or document.type
  if row.cvss == nil then
    row.cvss = document.cvss
    row.cvss_type = document.cvss_type
  elseif row.cvss_type == nil then
    -- The free endpoint answers some entries with a score and no version, so a
    -- bare number was reported on an unstated scale even when enrichment knew
    -- which one it was. A v2 7.5 and a v3.1 7.5 are different claims.
    row.cvss_type = document.cvss_type
  end
  return row
end

--- An exploit is what the service says it is.
--
-- The 1.x list of exploit TYPES drifted: measured on one real CPE it dropped 17
-- of 58 exploit references (9 zdt, 8 exploitpack), and across four products the
-- live type set also included gitee, canvas, dsquare and seebug. bulletinFamily
-- is the service's own classification, arrives on every hit from both
-- endpoints, and needs no maintenance.
local function is_exploit(row)
  local family = row.family
  return type(family) == "string" and family:lower() == "exploit"
end

--- Spread what an exploit knows onto the CVEs it exploits.
--
-- cvelist comes back on 100/100 enriched documents, so inverting it is free.
-- It carries two facts outward: that an exploit exists, and - because adp.kev
-- rides on the exploit record rather than on the CVE - that CISA listed it.
local function attribute_exploits(rows)
  local exploited, kev = {}, {}

  for _, row in ipairs(rows) do
    if is_exploit(row) then
      for _, cve in ipairs(row.cvelist or {}) do
        exploited[cve] = true
        if row.kev then
          kev[cve] = true
        end
      end
    end
  end

  for _, row in ipairs(rows) do
    if exploited[row.id] then
      row.exploit_known = true
    end
    if kev[row.id] then
      row.kev = true
    end
    if is_exploit(row) then
      row.exploit_known = true
    end
  end

  return rows
end

--- Which ranking bucket a row falls in. Lower sorts first.
--
-- Facts outrank predictions: KEV means observed in the wild, SSVC "active" is a
-- coordinator's judgement that exploitation is happening now, an exploit
-- bulletin means the code exists, EPSS is a model's expectation.
--
-- A bucket is evaluated when its data arrived and skipped when it did not, so
-- this works with or without a key and with any licence behind the key. B3 and
-- B5 need only what the free endpoint returns, so they always work.
local function bucket(row)
  if row.kev then
    return 1
  end
  if row.ssvc == "active" then
    return 2
  end
  if row.exploit_known or row.ssvc == "poc" then
    return 3
  end
  local epss, percentile = row.epss, row.epss_percentile
  if (epss and epss >= 0.10) or (percentile and percentile >= 0.95) then
    return 4
  end
  return 5
end

--- The one order findings are ever read in.
--
-- Named, because the summary re-sorts its selection and a second comparator
-- would drift: it did, and the exploit block came out with its AI scores
-- shuffled while the rest of the table was ordered correctly.
local function ranks_before(a, b)
  if a.bucket ~= b.bucket then
    return a.bucket < b.bucket
  end
  local left, right = a.cvss or -1, b.cvss or -1
  if left ~= right then
    return left > right
  end
  -- At the same score, the vulnerability leads and its exploit follows. They
  -- are one problem, and the FLAGS column already says an exploit exists - so
  -- listing the exploit first fills the bounded default view with evidence
  -- instead of findings. Measured against the live service: all ten default
  -- rows for a real Apache 2.4.7 were exploit ids, none of which names what it
  -- exploits, while the CVEs at the same score sat just below the cut.
  local a_exploit, b_exploit = is_exploit(a), is_exploit(b)
  if a_exploit ~= b_exploit then
    return b_exploit
  end
  local ai_left, ai_right = a.ai_score or -1, b.ai_score or -1
  if ai_left ~= ai_right then
    return ai_left > ai_right
  end
  return a.id < b.id
end
--- Order findings by how likely they are to be used against the target.
local function rank(rows)
  for _, row in ipairs(rows) do
    row.bucket = bucket(row)
  end
  table.sort(rows, ranks_before)
  return rows
end

--- Hide what the operator asked to hide.
--
-- mincvss stays a filter on the score and keeps its 1.x carve-out: an unscored
-- bulletin and anything with a known exploit are shown whatever the threshold.
-- Ranking is ordering, not filtering; the two are separate on purpose.
local function apply_mincvss(rows, mincvss)
  if mincvss <= 0 then
    return rows
  end
  local kept = {}
  for _, row in ipairs(rows) do
    if row.cvss == nil or row.exploit_known or is_exploit(row)
       or row.cvss >= mincvss then
      kept[#kept + 1] = row
    end
  end
  return kept
end

--- Concatenate result lists, dropping ids already present.
--
-- table.pack, not {...}: a nil argument leaves a hole that ipairs stops at, so
-- merge_rows(nil, rows) would silently return nothing. That is not theoretical
-- - it dropped the richest of the three nginx spellings before an end-to-end
-- run caught it.
local function merge_rows(...)
  local merged, seen = {}, {}
  local lists = table.pack(...)
  for index = 1, lists.n do
    local list = lists[index]
    for _, row in ipairs(list or {}) do
      if row.id and not seen[row.id] then
        seen[row.id] = true
        merged[#merged + 1] = row
      end
    end
  end
  return merged
end

-- -------------------------------------------------------------- 8. Catalog

--- Where the dictionaries come from, and what to do when they do not arrive.
--
-- The script carries no fingerprint data. The rules, the swept paths and the
-- probes are three dictionaries published to a GitHub branch and fetched at
-- scan time, so the catalogue can grow without shipping a new script - which is
-- the whole point, because the useful half of this plugin is a corpus that
-- changes weekly and a matcher that does not.
--
-- What that costs, stated plainly: a scan with no route to
-- raw.githubusercontent.com does not fingerprint web stacks. It still does
-- everything else - the identities nmap itself produced are still looked up -
-- because the catalogue feeds the sweep and the probes and nothing else. That is
-- the same degrade ladder the API key uses: lose a capability, never the whole
-- report.
--
-- Fetched once per scan, in the prerule, and held in the registry for the rest
-- of it. **Nothing is written to disk**, and no argument makes it: of the 611
-- scripts nmap ships, 26 open a file for writing and every one writes only
-- where a script argument pointed it; none keeps a cache. The whole catalogue
-- is 34 KB gzipped, which is what a scan costs - one response, once, before the
-- first host is touched - so there was never much for a cache to save.
--
-- There is deliberately no signature and no per-file hash. HTTPS to GitHub is
-- the trust boundary the maintainer has accepted. What IS checked is the shape
-- of every dictionary before a single rule is used, because these are Lua
-- patterns this script will run against target data: a malformed one raises
-- inside the matcher, and an unbounded one is a denial of service the operator
-- did not ask for. Validation here is not about trust, it is about a file that
-- arrived intact but wrong.

--- Fetch one catalogue file and parse it, or nil.
local function catalog_fetch(address)
  local options = {
    header = {["User-Agent"] = USER_AGENT},
    max_body_size = MAX_CATALOG_BYTES,
    timeout = CATALOG_TIMEOUT,
    -- The same flag every API request carries, and for the same reason:
    -- without it nselib stays in the address family the scan is running in, so
    -- a mirror that answers only over IPv6 was unreachable even by name.
    -- Measured against a catalogue served on ::1 alone: nil without, 200 with.
    any_af = true,
  }

  -- A URL naming an IPv6 address has to bracket it, and nselib's url.parse
  -- leaves the brackets on the host, so http.get_url asks the resolver for
  -- "[::1]" and gets nothing. Taking them off and calling http.get directly
  -- answers 200 for the same address. Only this shape takes the branch; the
  -- ordinary https URL keeps going through get_url, which knows more about
  -- redirects and defaults than is worth restating here.
  local parsed = url.parse(address) or {}
  local literal = (parsed.host or ""):match("^%[(.*)%]$")
  local response
  if literal then
    local secure = parsed.scheme == "https"
    local port = tonumber(parsed.port) or (secure and 443 or 80)
    local path = parsed.path or "/"
    if parsed.query then
      path = path .. "?" .. parsed.query
    end
    options.scheme = secure and "https" or "http"
    -- Set by hand: nselib fills Host from the host argument, which is now
    -- unbracketed, and an unbracketed IPv6 literal in a Host header is not a
    -- valid authority.
    options.header["Host"] = parsed.host .. (parsed.port and (":" .. parsed.port) or "")
    response = http.get(literal, port, path, options)
  else
    response = http.get_url(address, options)
  end

  if response == nil or response.status ~= 200 then
    stdnse.debug1("Catalogue fetch of %s answered %s", address,
      tostring(response and response.status))
    return nil
  end

  -- A truncated body is not a special case: it stops being JSON, so it fails
  -- here and is discarded like any other malformed answer.
  local ok, document = json.parse(tostring(response.body or ""))
  if not ok or type(document) ~= "table" then
    stdnse.debug1("Catalogue file %s did not parse as JSON", address)
    return nil
  end
  return document, tostring(response.body)
end

--- Is this string safe to put in a pattern position?
--
-- A malformed pattern raises inside string.find, and in the matcher that means
-- nmap replaces the port's ENTIRE result with "Script execution failed" - one
-- bad rule in a downloaded dictionary costing every finding on that host.
--
-- So it is walked, not compiled. `pcall(string.find, "", text)` looks like a
-- compile check and is not one: Lua parses a pattern only as far as matching
-- needs it, so against an empty subject the matcher fails on the first literal
-- and never reaches anything malformed after it. Measured - "unclosed [class
-- ([%d.]+)" comes back from that check as perfectly good.
--
-- The walk also counts captures, because the matcher builds
-- `alias .. ":" .. version` out of exactly one. None can never produce an
-- identity; more than one silently reports whichever came first as the version.
-- @param wanted how many captures the caller needs; nil means "any number".
local function usable_pattern(text, wanted)
  if type(text) ~= "string" or text == "" or #text > MAX_CATALOG_STRING then
    return false
  end

  local captures, depth, index = 0, 0, 1
  while index <= #text do
    local char = text:sub(index, index)

    if char == "%" then
      local next_char = text:sub(index + 1, index + 1)
      if next_char == "" then
        return false                        -- a pattern may not end in %
      end
      if next_char:match("%d") then
        -- %0 is the whole match and %1-%9 are back-references. Neither is a
        -- character class, and string.find raises "invalid capture index" for
        -- any index the pattern did not open - measured against Lua 5.4,
        -- "(%d)([%d.]+)%2" and "nginx/([%d.]+)%0" both raise, and a raise inside
        -- the matcher costs the port its ENTIRE result. The capture count below
        -- cannot catch this: the walk reads %2 as an ordinary escape.
        --
        -- Rejected outright rather than checked against the count, because no
        -- rule here has anything to refer back to: a rule captures exactly one
        -- version. The generator refuses PCRE back-references too, which is why
        -- nothing published has one - and precisely why this reader must not
        -- depend on that writer staying correct.
        return false
      end
      if next_char == "b" then
        if #text < index + 3 then
          return false                      -- %b needs both delimiters
        end
        index = index + 3
      elseif next_char == "f" then
        if text:sub(index + 2, index + 2) ~= "[" then
          return false                      -- %f must be followed by a class
        end
        index = index + 1
      else
        index = index + 1
      end

    elseif char == "[" then
      local close = index + 1
      if text:sub(close, close) == "^" then
        close = close + 1
      end
      if text:sub(close, close) == "]" then
        close = close + 1                   -- a ] in first position is a member
      end
      while true do
        local inner = text:sub(close, close)
        if inner == "" then
          return false                      -- unterminated class
        elseif inner == "%" then
          close = close + 2
        elseif inner == "]" then
          break
        else
          close = close + 1
        end
      end
      index = close

    elseif char == "(" then
      if text:sub(index + 1, index + 1) == ")" then
        -- A position capture yields an offset, not text, so it would put a
        -- number where the version belongs.
        return false
      end
      captures = captures + 1
      depth = depth + 1

    elseif char == ")" then
      depth = depth - 1
      if depth < 0 then
        return false
      end
    end

    index = index + 1
  end

  if depth ~= 0 then
    return false
  end
  if wanted == nil then
    return true
  end
  return captures == wanted
end

-- The response parts that are not named after something in the response. The
-- other two channels are "hdr:<name>" and "meta:<name>", which subjects_of
-- builds from whatever the response actually carried.
local FIXED_CHANNELS = {
  raw = true, body = true, title = true,
  script = true, banner = true, cookie = true,
}

--- Is this a channel key the matcher will ever look up?
local function usable_channel(key)
  if type(key) ~= "string" then
    return false
  end
  return FIXED_CHANNELS[key] == true
      or key:match("^hdr:[%w%-_.]+$") ~= nil
      or key:match("^meta:[%w%-_.:]+$") ~= nil
end

--- Is this a CPE prefix the endpoint can be addressed with?
local function usable_alias(alias)
  return type(alias) == "string" and #alias <= MAX_CATALOG_STRING
     and alias:match("^cpe:/[aoh]:[^:]+:[^:]+$") ~= nil
end

--- Is this a path this script would put on the wire?
local function usable_path(path)
  return type(path) == "string" and path:sub(1, 1) == "/"
     and #path <= MAX_CATALOG_STRING and path:find("[%s\r\n]") == nil
end

--- The list a dictionary carries, once the file is one this script can read.
--
-- The schema gate lives here rather than in the caller so that each reader is
-- safe on its own: they are the seam the tests drive directly, and a reader
-- that trusted somebody else to have checked would be a reader that could be
-- called wrongly.
local function catalog_list(payload, field)
  if type(payload) ~= "table" or payload.schema ~= CATALOG_SCHEMA then
    return nil
  end
  local list = payload[field]
  if type(list) ~= "table" then
    return nil
  end
  return list
end

--- The rule dictionary, grouped by the response part each rule reads.
--
-- @return the grouped table and the number of rules kept, or nil
local function read_fingerprints(payload)
  local rules = catalog_list(payload, "rules")
  if rules == nil then
    return nil
  end

  -- Sorted, because the group order reaches the report and pairs() over string
  -- keys walks them in an order Lua seeds per process - two scans of one
  -- unchanged host produced their groups in different orders once already.
  local names = {}
  for name in pairs(rules) do
    if type(name) == "string" then
      names[#names + 1] = name
    end
  end
  table.sort(names)

  local grouped, kept, refused = {}, 0, 0
  for _, name in ipairs(names) do
    if kept >= MAX_CATALOG_RULES then
      break
    end
    local rule = rules[name]
    if type(rule) == "table" and usable_channel(rule.channel)
        and usable_alias(rule.alias) and usable_pattern(rule.regex, 1) then
      local anchor = rule.anchor
      if type(anchor) ~= "string" or #anchor > MAX_CATALOG_STRING then
        anchor = ""
      end
      local group = grouped[rule.channel]
      if group == nil then
        group = {}
        grouped[rule.channel] = group
      end
      -- Slot 1 records whether the pattern is start-anchored, which the matcher
      -- needs and nothing else does. It used to hold the rule's NAME, which no
      -- reader ever looked at - 722 strings kept alive for nothing.
      --
      -- It is needed because string.find(s, pat, init) re-anchors "^" AT init:
      -- measured, "^nginx/([%d.]+)" against "nginx/1.2.3nginx/9.9.9" matches
      -- TWICE, at 1 and at 12. 373 of the shipped rules start with "^", and
      -- every spurious match mints a CPE that is reported, published onto the
      -- port and spent as an outbound lookup - with the count chosen by the
      -- target.
      group[#group + 1] = rule.regex:sub(1, 1) == "^"
      group[#group + 1] = rule.alias
      group[#group + 1] = anchor:lower()
      group[#group + 1] = rule.regex
      kept = kept + 1
    else
      refused = refused + 1
    end
  end

  if refused > 0 then
    stdnse.debug1("Catalogue: %d rule(s) refused as unusable", refused)
  end
  if kept == 0 then
    return nil
  end
  return grouped, kept
end

--- The swept path list.
local function read_paths(payload)
  local listed = catalog_list(payload, "paths")
  if listed == nil then
    return nil
  end

  local paths, seen = {}, {}
  for _, path in ipairs(listed) do
    if #paths >= MAX_CATALOG_PATHS then
      break
    end
    if usable_path(path) and not seen[path] then
      seen[path] = true
      paths[#paths + 1] = path
    end
  end

  if #paths == 0 then
    return nil
  end
  return paths
end

--- The targeted version probes.
local function read_probes(payload)
  local listed = catalog_list(payload, "probes")
  if listed == nil then
    return nil
  end

  local probes = {}
  for _, entry in ipairs(listed) do
    if #probes >= MAX_CATALOG_PROBES then
      break
    end
    if type(entry) == "table" and usable_alias(entry.alias)
        and type(entry.detect) == "table" and type(entry.extract) == "table"
        and type(entry.paths) == "table" then

      local detect = {}
      for _, rule in ipairs(entry.detect) do
        -- A detector reports presence, so it needs no capture - only a pattern
        -- that compiles and a channel something will read.
        -- A detector reports presence, so it needs no capture - but it must
        -- still be a pattern that cannot raise, for the same reason.
        -- The pattern is validated EXACTLY as it will be run. It used to be
        -- wrapped in parentheses first, to force the one capture usable_pattern
        -- insisted on - and that wrap validated a different string from the one
        -- stored. Measured: the raw pattern "X)%" is refused while "(X)%)" is
        -- accepted, because the prepended "(" absorbs the stray ")" and the
        -- trailing "%" escapes the appended one. The same wrap also laundered a
        -- non-string through tostring(), since "table: 0x..." is itself a
        -- perfectly good one-capture pattern. Both cost the port its entire
        -- result, which is the one outcome this whole section exists to prevent.
        --
        -- A detector reports presence, so it needs no capture and no shipped
        -- one has any; nil says the count is not what is being checked here.
        if type(rule) == "table" and usable_channel(rule.channel)
            and usable_pattern(rule.regex) then
          detect[#detect + 1] = rule.channel
          detect[#detect + 1] = type(rule.anchor) == "string"
            and rule.anchor:lower() or ""
          detect[#detect + 1] = rule.regex
        end
      end

      local extract = {}
      for _, rule in ipairs(entry.extract) do
        if type(rule) == "table" and usable_pattern(rule.regex, 1) then
          extract[#extract + 1] = type(rule.anchor) == "string"
            and rule.anchor:lower() or ""
          extract[#extract + 1] = rule.regex
        end
      end

      local paths = {}
      for _, path in ipairs(entry.paths) do
        if usable_path(path) then
          paths[#paths + 1] = path
        end
      end

      -- All three or nothing: a probe that cannot be triggered, cannot be sent
      -- or cannot read an answer is not a probe.
      if #detect > 0 and #extract > 0 and #paths > 0 then
        probes[#probes + 1] = {
          name = type(entry.name) == "string" and entry.name or entry.alias,
          alias = entry.alias,
          detect = detect,
          extract = extract,
          paths = paths,
        }
      end
    end
  end

  return probes
end

--- Turn three parsed dictionaries into what the matcher reads, or nil.
local function assemble(parsed)
  local fingerprints, count = read_fingerprints(parsed.fingerprints)
  if fingerprints == nil then
    return nil
  end
  local paths = read_paths(parsed.paths)
  if paths == nil then
    return nil
  end
  -- Probes are optional in a way the other two are not: a catalogue with none
  -- is a catalogue that simply does not probe, which is a valid state.
  local probes = read_probes(parsed.probes) or {}

  return {
    fingerprints = fingerprints,
    rule_count = count,
    paths = paths,
    probes = probes,
  }
end

--- The schema an index declares, or nil when it declares nothing readable.
local function index_schema_of(index)
  return type(index) == "table" and index.schema or nil
end

--- Fetch every dictionary the index lists and validate it.
local function catalog_from_network(base, index)
  local parsed = {}
  for _, kind in ipairs(CATALOG_FILES) do
    local listed = dig(index, "catalogs", kind)
    local filename = as_string(listed and listed.file) or (kind .. ".json")
    -- A file name from the index reaches a URL, so it may name a file and
    -- nothing else. Excluding characters was not enough: "." was inside the
    -- permitted class, so ".." matched nothing and passed, and the fetch walked
    -- to the parent of the operator's catalog_url. Required to LOOK like a
    -- catalogue file instead.
    if not filename:match("^[%w_%-]+%.json$") then
      stdnse.debug1("Catalogue index names an unusable file %q", filename)
      return nil
    end

    local payload = catalog_fetch(base .. filename)
    if payload == nil then
      return nil
    end
    parsed[kind] = payload
  end

  local catalog = assemble(parsed)
  if catalog == nil then
    return nil
  end

  -- Integer, not merely a number: it reaches string.format("%d") in the debug
  -- line below, which raises on a float, and index.serial is off the wire.
  catalog.serial = math.tointeger(tonumber(index.serial) or 0) or 0
  return catalog
end

--- Load the catalogue once per scan.
--
-- Called from the prerule, which is the one place that runs before any port and
-- exactly once - so the fetch cannot race itself across the per-port chunk
-- re-executions, and a hundred open ports cost one request rather than a
-- hundred.
local function load_catalog()
  local shared = state()
  if shared.catalog_loaded then
    return shared.catalog
  end
  shared.catalog_loaded = true

  local cfg = config()
  if cfg.catalog_mode == "none" then
    shared.catalog_note = "the catalogue is off (vulners.catalog=none), " ..
      "so no web fingerprinting was done"
    return nil
  end

  local base = cfg.catalog_url
  local index = catalog_fetch(base .. "index.json")

  local declared = tonumber(index_schema_of(index))
  if declared then
    if declared > CATALOG_SCHEMA then
      -- Refused, not half-read. This is the whole reason the schema exists.
      -- %s, not %d. string.format("%d", 2.5) RAISES in Lua 5.3+, and the
      -- schema is a number this script just parsed out of somebody else's JSON:
      -- a published index declaring 2.5 killed the prerule outright.
      shared.catalog_note = string.format(
        "the published catalogue is schema %s and this script reads %d; " ..
        "update nmap-vulners to use it", tostring(declared), CATALOG_SCHEMA)
      stdnse.verbose1("vulners: %s", shared.catalog_note)
      return nil
    end

    local fetched = catalog_from_network(base, index)
    if fetched then
      shared.catalog = fetched
      stdnse.debug1("Catalogue serial %d fetched, %d rules",
        fetched.serial, fetched.rule_count)
      return fetched
    end

    -- index.json arrived and parsed, so the base URL is reachable and the
    -- manifest is sound: what failed is one of the files it names. The
    -- catch-all below says "could not be downloaded", which is the wrong
    -- diagnosis here - measured against a mirror serving a broken
    -- fingerprints.json, it sends the operator to check the network instead
    -- of the file they just published, and vulners.catalog_url exists for
    -- exactly those operators.
    shared.catalog_note = string.format(
      "the catalogue at %s answered, but one of its dictionaries could not " ..
      "be read, so no web fingerprinting was done; the software nmap itself " ..
      "identified was still looked up", base)
    stdnse.verbose1("vulners: %s", shared.catalog_note)
    return nil
  end

  shared.catalog_note = "the fingerprint catalogue could not be downloaded, " ..
    "so no web fingerprinting was done; the software nmap itself identified " ..
    "was still looked up"
  stdnse.verbose1("vulners: %s", shared.catalog_note)
  return nil
end

--- The loaded catalogue, or an empty one.
--
-- Never fetches. The prerule owns the loading; anything reached without one -
-- a port action in a run where the prerule did not fire - reads what is there
-- and does without the rest, rather than opening a socket from inside the
-- per-port path where several ports would race.
local function catalog()
  local shared = state()
  return shared.catalog or EMPTY_CATALOG
end

-- --------------------------------------------------------- 9. Fingerprint

--- How fast the sweep may go, from nmap's own timing template.
--
-- @return paths per batch, seconds to wait between batches
local function sweep_pace()
  local ok, level = pcall(nmap.timing_level)
  local pace = ok and type(level) == "number" and PACE_BY_TIMING[level]
  pace = pace or DEFAULT_PACE
  return pace[1], pace[2]
end

--- The paths to sweep, from the argument or the catalogue.
--
-- An operator who names a file means that file: a named file that yields
-- nothing stops the sweep rather than quietly substituting the catalogue list,
-- which would send a scan somewhere it was told not to go.
local function sweep_paths(paths_arg)
  local chosen

  if type(paths_arg) == "table" then
    -- Normalised exactly like the file branch. Taking the list as-is meant
    -- --script-args "vulners.paths={index.php}" put "GET index.php HTTP/1.1" on
    -- the wire - a malformed request line every strict server answers with 400,
    -- so the operator's chosen list silently fingerprinted nothing while the
    -- same list in a file worked. nmap also parses "{}" as one empty string.
    chosen = {}
    for _, entry in ipairs(paths_arg) do
      if type(entry) == "string" then
        local path = entry:match("^%s*(.-)%s*$")
        if path ~= "" and not path:find("^#") then
          if not path:find("^/") then
            path = "/" .. path
          end
          chosen[#chosen + 1] = path
        end
      end
    end
    if #chosen == 0 then
      stdnse.verbose1("vulners: the paths argument holds no usable path; " ..
        "requesting nothing")
      state().sweep_note = "the vulners.paths argument holds no usable path, " ..
        "so no web fingerprinting was done"
      return {}
    end
  elseif type(paths_arg) == "string" then
    if paths_arg:lower() == "none" then
      return {}
    end
    chosen = {}
    local file = io.open(paths_arg, "r")
    if file == nil then
      stdnse.verbose1("vulners: cannot read the paths file %s; requesting nothing",
        paths_arg)
      state().sweep_note = string.format(
        "the paths file %s could not be read, so no web fingerprinting was done",
        paths_arg)
      return {}
    end
    for line in file:lines() do
      -- A file written on Windows ends its lines with CR, which would travel
      -- into the request line and earn a 400 from every strict server.
      local path = line:match("^%s*(.-)%s*$")
      if path ~= "" and not path:find("^#") then
        if not path:find("^/") then
          path = "/" .. path
        end
        chosen[#chosen + 1] = path
      end
    end
    file:close()
    if #chosen == 0 then
      stdnse.verbose1("vulners: no usable paths in %s; requesting nothing", paths_arg)
      state().sweep_note = string.format(
        "the paths file %s holds no usable path, so no web fingerprinting was done",
        paths_arg)
      return {}
    end
  end

  if chosen == nil or #chosen == 0 then
    chosen = catalog().paths
  end

  -- The catalogue's own order is load-bearing and the argument's is the
  -- operator's, so neither is sorted. It used to be sorted alphabetically for
  -- determinism, which a file already provides - and which threw away the one
  -- thing the order carries: the paths most likely to answer are published
  -- first, so a sweep that is cut short by a dead server has already asked its
  -- best questions.
  -- Held to the rule the catalogue's own paths are held to. usable_path refuses
  -- whitespace, control characters and absurd length for a downloaded path, for
  -- stated reasons - and the same string arriving from the operator's file or
  -- argument reached the request line unchecked, so an interior CR or space
  -- became a second request line's worth of text. MAX_CATALOG_PATHS applies
  -- here too: an accidental file is not a path list.
  local unique, seen = {}, {}
  local refused = 0
  for _, path in ipairs(chosen) do
    if #unique >= MAX_CATALOG_PATHS then
      break
    end
    local text = type(path) == "string" and path or tostring(path)
    if not usable_path(text) then
      refused = refused + 1
    elseif not seen[text] then
      seen[text] = true
      unique[#unique + 1] = text
    end
  end
  if refused > 0 then
    stdnse.verbose1("vulners: %d path(s) are not ones this script would " ..
      "request, and were dropped", refused)
  end
  return unique
end

--- Options for one request the sweep makes.
--
-- A NEW table each time, never one shared between requests. nselib assigns
-- `options.scheme = u.scheme or options.scheme` INTO THE CALLER'S TABLE when it
-- parses a Location, and it does so before deciding whether the redirect may be
-- followed (nselib/http.lua:1794-1802) - so it happens even to a caller that
-- does not follow redirects at all. One path answering a redirect to an https
-- URL therefore pinned https for every later fetch on a plaintext port, and the
-- rest of the sweep failed. Caught in follow_redirects first, then again in the
-- probe loop, which is why it is one function now.
--
-- Safe to reuse across a pipeline: pipeline_add takes its own copy
-- (nselib/http.lua:1962), and pipeline_go never parses a Location.
local function sweep_options()
  return {
    header = {["Accept-Encoding"] = ACCEPT_ENCODING},
    max_body_size = MAX_BODY_SIZE,
    truncated_ok = true,
  }
end

--- Request one slice of the path list, keeping what a broken pipeline dropped.
--
-- http.pipeline_go returns responses in queue order and stops as soon as the
-- first request on a fresh connection fails, so one path a tarpit or a WAF
-- refuses costs every path queued behind it. The rounds are what get those
-- back.
local function fetch_batch(host, port, paths, pending, options, responses)
  for _ = 1, MAX_FETCH_ROUNDS do
    if #pending == 0 then
      break
    end

    local requests
    for _, index in ipairs(pending) do
      requests = http.pipeline_add(paths[index], options, requests, "GET")
    end

    local answered = http.pipeline_go(host, port, requests) or {}
    local left = {}

    for position, index in ipairs(pending) do
      local response = answered[position]
      if response and response.status then
        responses[index] = response
      else
        left[#left + 1] = index
      end
    end

    if #left == #pending then
      -- Nothing came back at all, and the library gives up on the request at
      -- the head of the queue, so that is the one being refused. The rest have
      -- not had their turn yet.
      stdnse.debug1("No response for %s, continuing without it", paths[left[1]])
      table.remove(left, 1)
    end

    pending = left
  end
end

--- Request every path, at the rate nmap's timing template allows.
--
-- The whole list, always: asking less would find less. What -T changes is how
-- many go out together and how long the sweep waits in between, so an operator
-- who said "be quiet" gets a quiet sweep of the same list rather than a loud
-- sweep of a shorter one.
--
-- stdnse.sleep yields to the script scheduler, so the wait costs this port's
-- sweep time and nothing else: other hosts keep running through it.
local function fetch_paths(host, port, paths)
  local options = sweep_options()
  local responses = {}
  local batch_size, delay = sweep_pace()

  local first = 1
  while first <= #paths do
    local last = math.min(first + batch_size - 1, #paths)
    local pending = {}
    for index = first, last do
      pending[#pending + 1] = index
    end

    fetch_batch(host, port, paths, pending, options, responses)

    first = last + 1
    if first <= #paths and delay > 0 then
      stdnse.sleep(delay)
    end
  end

  return responses
end

-- What a scheme implies when a Location does not spell the port out.
local DEFAULT_SCHEME_PORT = {http = 80, https = 443}

--- The path a redirect points at, when it stays on the port being scanned.
local function redirect_target(host, port, response)
  local location = dig(response, "header", "location")
  if not location then
    return nil
  end

  local parsed = url.parse(location)
  if not parsed then
    return nil
  end

  if parsed.host and parsed.host ~= host.targetname and parsed.host ~= host.ip then
    -- Somebody else's server is not ours to fingerprint.
    return nil
  end

  -- Nor is another port of this host. The target would be fetched from the port
  -- being swept, so "https://host:8443/admin" reads /admin off port 80 and
  -- attributes whatever it says to a service that never served it. nmap's own
  -- redirect policy refuses the same thing, on the same reasoning
  -- (nselib/http.lua, redirect_ok_rules rule 3), and a relative Location - the
  -- common case - names no port and is unaffected.
  local target_port = tonumber(parsed.port) or DEFAULT_SCHEME_PORT[parsed.scheme]
  if target_port and target_port ~= port.number then
    return nil
  end

  local path = parsed.path
  if not path or path == "" then
    return nil
  end

  local target = parsed.query and (path .. "?" .. parsed.query) or path
  -- Held to the same rule as a catalogue path, and for the same reason: nselib
  -- builds the request line as method .. " " .. path .. " HTTP/1.1" verbatim
  -- (http.lua:1312), so "Location: /x HTTP/1.0" - which url.parse hands back as
  -- the path "/x HTTP/1.0" - would put a second request line's worth of text
  -- into the first. usable_path already refused exactly this for the catalogue.
  if not usable_path(target) then
    return nil
  end
  return target
end

--- Fetch what the redirecting paths actually point at.
--
-- Without this the sweep only ever sees the 3xx envelope, and a site whose
-- paths redirect to its application is fingerprinted from its Server header
-- alone. Distinct targets are fetched once, so a host that redirects everything
-- to one page costs one request.
local function follow_redirects(host, port, responses)
  local fetched = {}

  for index, first in pairs(responses) do
    local response = first
    local hops = 0

    while response and response.status and response.status >= 300
        and response.status < 400 and hops < MAX_REDIRECTS do
      local target = redirect_target(host, port, response)
      if not target then
        break
      end

      if fetched[target] == nil then
        fetched[target] = http.get(host, port, target, sweep_options()) or false
      end

      -- Only replaced when the redirect actually produced something. Otherwise
      -- a host answering every path with a 302 to a page it then refuses lost
      -- even the Server header of the 302 itself, and was never fingerprinted.
      local followed = fetched[target] or nil
      if followed and followed.status then
        response = followed
        responses[index] = followed
      else
        break
      end
      hops = hops + 1
    end
  end
end

--- What a pattern captured, as a version - or nil when it is not one.
--
-- Two things this catches, both measured against the shipped rules:
--
-- * **surrounding space.** Wappalyzer writes CMSimple's rule as
--   `CMSimple( [\d.]+)`, with the separator INSIDE the group, so the capture is
--   " 5.4" and the request line carried `cpe:/a:cmsimple:cmsimple: 5.4`. Ten
--   rules capture a leading space; every one produced a malformed identity.
-- * **a capture that is not a version at all.** Several rules capture whatever
--   follows a product name - `(%S+)`, or a whole header value - and recog has
--   two that capture a Debian codename. `sarge` appended to a CPE asks the
--   service about a release that does not exist under that name, which spends
--   a lookup to learn nothing and reports a clean host.
--
-- Requiring a digit is the cheapest test that admits every real version -
-- 4.1.1a@1.791 on a BIG-IP, V5R3M0 on IBM HTTP Server, 3.3(2) on a Cisco MDS -
-- while rejecting a word.
local function version_of(captured)
  local version = captured:match("^%s*(.-)%s*$")
  -- A digit alone was too weak. Some rules capture the prose around the number
  -- as well, and the result was published onto the port, printed in the report
  -- and sent to the API as a CPE that cannot match anything - a silent false
  -- negative wearing the clothes of a finding.
  --
  -- What separates those from a real version is measured, not guessed. Across
  -- the 526 rules carrying a recorded example, the whole non-alphanumeric
  -- vocabulary is . - @ _ + ( ) [ ] / and space. Whitespace appears in eight
  -- examples, six of them plainly prose ("7 (build 7)", "Release 7",
  -- "9 (Shrike)"), and a space cannot occur in a CPE URI in any case; a slash
  -- appears in exactly one, "OTP/7", which is a prefix the rule failed to
  -- exclude. Everything else in that vocabulary belongs to a real format -
  -- "4.1.1a@1.791", "3.3(2)", "3.7.4.post0" - and those keep working.
  if version == "" or not version:find("%d")
      or version:find("%s") or version:find("/") then
    return nil
  end
  return version
end

--- Run one group of rules against the one subject that group is written for.
--
-- Rules are filed under the part of a response they read - "hdr:server",
-- "meta:generator", "title", "body" - so a response with twelve headers runs
-- the rules for those twelve names and no others. That indexing is what makes
-- the whole rule set cheaper than the 178 that used to be run against every
-- byte of everything: it removes the work rather than budgeting for it.
--
-- Each rule also carries a literal it cannot match without. Searching for that
-- literal is a memory scan where running the pattern is an interpreter loop, so
-- the pattern only runs on a subject that could possibly match it.
--
-- @param deadline os.clock() value after which matching stops
-- @param lowered  a lowercase copy of the subject, when the caller already has one
local function match_group(key, subject, found, seen, deadline, lowered)
  local group = catalog().fingerprints[key]
  if group == nil or subject == nil or subject == "" then
    return
  end

  -- One lowercase copy per subject, not per rule. The anchors are lowercase
  -- because a case-folded pattern has no literal run left to search for.
  lowered = lowered or subject:lower()

  local hits = 0
  for i = 1, #group, 4 do
    hits = 0
    -- Every rule, not every sixteenth. That was affordable when one call could
    -- cost seconds; now that MATCH_WINDOW holds one call to a few milliseconds,
    -- reading the clock sixteen times less often is what would let the budget
    -- overshoot. os.clock is the right clock here because nothing in this loop
    -- yields.
    if os.clock() >= deadline then
      return
    end

    local anchored, alias = group[i], group[i + 1]
    local anchor, regex = group[i + 2], group[i + 3]

    -- The pattern runs over a WINDOW, never over the whole subject. Which
    -- window depends on what the rule told us about itself:
    --
    --   start-anchored   one window, at the start - "^" has only one start
    --   anchored on a    one window around each occurrence of that literal, up
    --   literal          to MAX_ANCHOR_HITS of them; the pattern cannot match
    --                    anywhere the literal is absent, so nothing is lost
    --   neither          the first MATCH_WINDOW bytes, which is all a rule with
    --                    nothing to say about itself has earned
    --
    -- Chasing the ANCHOR rather than the pattern also keeps the old behaviour
    -- of reading every occurrence: a reverse-proxied host names the same product
    -- in two headers, and the second version is often the one actually exposed.
    local at, exhausted = 1, false
    repeat
      local first, last = 1, UNANCHORED_WINDOW
      if anchored or anchor == "" then
        exhausted = true
      else
        at = lowered:find(anchor, at, true)
        if at == nil then
          break
        end
        first, last = math.max(1, at - MATCH_LOOKBEHIND), at + MATCH_WINDOW
        at = at + 1
      end

      -- Every occurrence WITHIN the window, not only the first: a reverse-proxied
      -- host names the same product in two headers, and both usually land in one
      -- window. Looping here is safe in a way looping over the whole subject was
      -- not - the window is bounded, so the scan is too.
      local window = subject:sub(first, last)
      local init = 1
      while true do
        local at_from, at_to, vers = window:find(regex, init)
        if not at_from then
          break
        end

        -- A capture that crossed a line boundary means the pattern is unbounded;
        -- accepting it would put whatever followed - a Set-Cookie value, say -
        -- into the CPE, into the report and into the API request.
        if vers ~= nil and not vers:find("[\r\n]") then
          local version = version_of(vers)
          if version then
            local cpe = alias .. ":" .. version
            if not seen[cpe] then
              found[#found + 1] = cpe
              seen[cpe] = true
            end
          end
        end

        if anchored then
          -- "^" has only one start, and find re-anchors it at init.
          break
        end
        init = (at_to >= at_from) and at_to + 1 or at_from + 1
      end

      hits = hits + 1
    until exhausted or hits >= MAX_ANCHOR_HITS
  end
end

--- Run one downloaded probe pattern over the windows its anchor allows.
--
-- The probes reach here rather than through match_group because they are not
-- rules: a detector answers yes or no, and an extractor is asked for exactly
-- one capture. The bound is the same one, for the same reason - a Lua pattern
-- neither yields nor can be interrupted, so the only thing that can be limited
-- is what it is allowed to SEE.
--
-- Both call sites used to run over the WHOLE body. Measured on the shipped
-- Tomcat extractor against a body of "apache tomcat" repeated: 16 KB cost
-- 0.22 s, 32 KB 0.90 s, 64 KB 3.60 s - quadratic, so the 128 KB the body cap
-- admits is roughly fourteen seconds with every script in the scan stopped,
-- and the target picks the body. The anchor prefilter did not help: the anchor
-- IS "apache tomcat", so that body passes it and then pays in full.
--
-- Every shipped detector and extractor carries an anchor (measured), so no
-- probe loses reach by being windowed.
--
-- @return true and the first capture, or false
local function match_probe(text, lowered, anchor, regex)
  local at, hits = 1, 0
  repeat
    local first, last = 1, UNANCHORED_WINDOW
    if anchor ~= "" then
      at = lowered:find(anchor, at, true)
      if at == nil then
        return false
      end
      first, last = math.max(1, at - MATCH_LOOKBEHIND), at + MATCH_WINDOW
      at = at + 1
    end

    local from, _, captured = text:sub(first, last):find(regex)
    if from ~= nil then
      return true, captured
    end
    hits = hits + 1
  until anchor == "" or hits >= MAX_ANCHOR_HITS
  return false
end

-- How many of one kind of tag the sweep will read out of one body. A document
-- with ten thousand <script> elements is not a web application being
-- fingerprinted, it is a body chosen to make this loop expensive.
local MAX_TAGS_PER_BODY = 64

-- The longest tag attribute worth matching against. A src= or content= longer
-- than this is not a filename or a generator string.
local MAX_TAG_VALUE = 512

--- The text of <title>, or nil.
--
-- Bounded with [^<] rather than the obvious lazy .-, because a lazy match
-- rescans to the end of the body from every <title it finds, and a body of
-- repeated "<title" is then quadratic. Every extraction here is written that
-- way for the same reason.
local function title_of(body)
  local text = body:match("<[tT][iI][tT][lL][eE][^>]*>([^<]*)")
  if text == nil then
    return nil
  end
  text = text:gsub("%s+", " "):match("^%s*(.-)%s*$")
  return text ~= "" and text:sub(1, MAX_TAG_VALUE) or nil
end

--- One attribute out of a tag's attribute text, unquoted or quoted.
local function attribute(text, name)
  local value = text:match(name .. "%s*=%s*\"([^\"]*)\"")
      or text:match(name .. "%s*=%s*'([^']*)'")
      or text:match(name .. "%s*=%s*([^%s>]+)")
  if value == nil or value == "" then
    return nil
  end
  return value:sub(1, MAX_TAG_VALUE)
end

--- Every (channel, text) pair one response offers, built once.
--
-- Built once and reused, because two things read it: the fingerprint rules,
-- which turn it into identities, and the probe detectors, which decide whether
-- a targeted request is worth making. Extracting the tags twice would double
-- the only part of this that scans the whole body.
local function subjects_of(response, deadline)
  local subjects = {}

  local function offer(key, text)
    if key ~= nil and text ~= nil and text ~= "" then
      subjects[#subjects + 1] = {key = key, text = text}
    end
  end

  local header = response.header or {}

  -- Sorted, not pairs(): Lua seeds its string hash per process, so iterating
  -- the header map directly discovered identities in an order that differed
  -- between two runs against an unchanged host - and the order decides which
  -- ones survive MAX_IDENTITIES_PER_PORT.
  local names = {}
  for name in pairs(header) do
    if type(name) == "string" then
      names[#names + 1] = name
    end
  end
  table.sort(names)

  for _, name in ipairs(names) do
    local value = header[name]
    if type(value) == "string" then
      offer("hdr:" .. name, value)
      if name == "set-cookie" then
        offer("cookie", value)
      end
    end
  end

  -- The whole header block, for the rules this repository already shipped:
  -- they are written as "Server:%s*Foo" and read the block, not a value.
  local rawheaders = response.rawheader
  if rawheaders and #rawheaders > 0 then
    offer("raw", table.concat(rawheaders, "\n"))
  end

  -- response.body, NOT response.rawbody. nselib sets rawbody to the UNDECODED
  -- bytes and then replaces body with the decoded ones (nselib/http.lua:953-968),
  -- so rawbody is always present and "rawbody or body" always chose the
  -- compressed form. Since this script asks for gzip, it was handing itself
  -- gzip bytes to match against: the same WordPress page yields
  -- cpe:/a:wordpress:wordpress:5.5.1 served plain and nothing at all served
  -- gzipped.
  -- NOT stdnse.string_or_blank: its second argument is the SUBSTITUTE, and
  -- passing nil selects the default substitute "<blank>" rather than disabling
  -- substitution (nselib/stdnse.lua:376-386). Every 204, 304 and body-less 302
  -- therefore ran the whole body rule group and every probe detector against a
  -- seven-byte string this script invented, and the guard below was dead.
  local body = tostring(response.body or "")
  if body ~= "" then
    offer("title", title_of(body))

    local tags = 0
    for text in body:gmatch("<[mM][eE][tT][aA]([^>]*)>") do
      tags = tags + 1
      if tags > MAX_TAGS_PER_BODY or os.clock() >= deadline then
        break
      end
      local name = attribute(text, "[nN][aA][mM][eE]")
          or attribute(text, "[pP][rR][oO][pP][eE][rR][tT][yY]")
      local content = attribute(text, "[cC][oO][nN][tT][eE][nN][tT]")
      if name and content then
        offer("meta:" .. name:lower(), content)
      end
    end

    tags = 0
    for text in body:gmatch("<[sS][cC][rR][iI][pP][tT]([^>]*)>") do
      tags = tags + 1
      if tags > MAX_TAGS_PER_BODY or os.clock() >= deadline then
        break
      end
      offer("script", attribute(text, "[sS][rR][cC]"))
    end

    offer("body", body)
  end

  for _, subject in ipairs(subjects) do
    subject.lowered = subject.text:lower()
  end
  return subjects
end

--- Everything one response says about the software behind it.
local function match_subjects(subjects, found, seen, deadline)
  for _, subject in ipairs(subjects) do
    match_group(subject.key, subject.text, found, seen, deadline, subject.lowered)
  end
end

--- Which targeted probes this response makes worth sending.
--
-- A probe's detector says only "this product is here". It is deliberately
-- cheap and deliberately versionless - a versioned rule would have produced an
-- identity already, and then there would be nothing to probe for.
local function detect_probes(subjects, triggered, deadline)
  local probes = catalog().probes
  for index = 1, #probes do
    if not triggered[index] then
      local detect = probes[index].detect
      for i = 1, #detect, 3 do
        -- The same budget match_group honours, for the same reason: these are
        -- downloaded patterns run against a body the target chose. Measured on
        -- a shipped detector, one 128 KB body cost 11 s of non-yielding work -
        -- the whole scan frozen - and nothing here was watching the clock.
        if os.clock() >= deadline then
          return
        end
        local key, anchor, regex = detect[i], detect[i + 1], detect[i + 2]
        for _, subject in ipairs(subjects) do
          if subject.key == key
              and match_probe(subject.text, subject.lowered, anchor, regex) then
            triggered[index] = true
            break
          end
        end
        if triggered[index] then
          break
        end
      end
    end
  end
end

--- Go and ask a product that would not say, and read the version off the answer.
--
-- Sent only when all three of these hold, which is what keeps a probing script
-- from knocking on doors:
--
-- * a detector fired, so the product really is here;
-- * nothing has produced a version for it, so the request can teach us
--   something the sweep did not already have;
-- * the port has not already spent its probe budget.
--
-- A CMS that names itself and hides its version is the normal case for exactly
-- the software worth checking, and it is the one case the passive rules cannot
-- win: no amount of pattern matching extracts a number that is not on the page.
--
-- @return map of cpe -> the path it was found on
local function run_probes(host, port, triggered, discovered, deadline)
  local found = {}
  if next(triggered) == nil then
    return found
  end

  -- What is already known, by identity rather than by CPE: a probe for Drupal is
  -- pointless once anything has produced a Drupal version, even a different one.
  --
  -- Read from nmap's own findings as well as the sweep's. Consulting only the
  -- sweep meant a service -sV had already named AND versioned - Tomcat behind a
  -- Coyote banner, say - was still probed, spending a request to learn what was
  -- in hand before the script started.
  local known = {}
  local function remember(cpe)
    if type(cpe) == "string" then
      known[cpe:match("^(.-):[^:]*$") or cpe] = true
    end
  end
  for cpe in pairs(discovered) do
    remember(cpe)
  end
  for _, cpe in ipairs(dig(port, "version", "cpe") or {}) do
    remember(cpe)
  end

  local sent = 0

  -- Sorted, so the same host probed twice sends the same requests in the same
  -- order, and so the budget cuts off the same probes both times.
  local order = {}
  for index in pairs(triggered) do
    order[#order + 1] = index
  end
  table.sort(order)

  local all = catalog().probes
  for _, index in ipairs(order) do
    local probe = all[index]
    if sent >= MAX_PROBES_PER_PORT then
      break
    end
    if not known[probe.alias] then
      for _, path in ipairs(probe.paths) do
        if sent >= MAX_PROBES_PER_PORT then
          break
        end
        sent = sent + 1
        local response = http.get(host, port, path, sweep_options())
        if response and response.status and response.status >= 200
            and response.status < 300 then
          local body = tostring(response.body or "")
          local lowered = body:lower()
          local extract = probe.extract
          local hit = false
          for i = 1, #extract, 2 do
            local anchor, regex = extract[i], extract[i + 1]
            local _, captured = match_probe(body, lowered, anchor, regex)
            if captured then
              local version = version_of(captured)
              if version then
                found[probe.alias .. ":" .. version] = path
                hit = true
                break
              end
            end
          end
          if hit then
            -- One answer per product. The remaining paths are fallbacks for
            -- when the first does not answer, not extra evidence.
            break
          end
        end
        if os.clock() >= deadline then
          break
        end
      end
    end
  end

  if sent > 0 then
    stdnse.debug1("Sent %d targeted version probe(s)", sent)
  end
  return found
end

--- The software banner inside nmap's service fingerprint.
--
-- service_fp is not a banner: it is a record of the probing. A header of nmap's
-- own metadata, then one %r(Probe,length,"payload") record per probe that
-- answered, wrapped across lines with "SF:" continuations.
--
-- Sending it whole bought a credit for a string that is mostly not software,
-- and it carries %Time= - so two identical appliances produce DIFFERENT strings
-- and no cache could ever match them.
--
-- @return the distinct probe payloads, or nil when there is no payload at all
local function service_fp_payloads(fingerprint)
  -- Unwrap with this substitution and nothing else: a trailing backslash at a
  -- line end is data, and the obvious wrong parse glues "SF:" into the banner.
  local unwrapped = fingerprint:gsub("\nSF:", "")

  local seen, payloads = {}, {}
  for payload in unwrapped:gmatch('%%r%([^,]*,[^,]*,"(.-)"%)') do
    -- Undo nmap's escaping so the endpoint sees what the service actually sent.
    -- The hex form goes first, or its backslash is eaten as a literal escape.
    local text = payload:gsub("\\x(%x%x)", function(hex)
      return string.char(tonumber(hex, 16))
    end)
    text = text:gsub("\\r", "\r"):gsub("\\n", "\n"):gsub("\\t", "\t")
    text = text:gsub("\\(.)", "%1")
    text = ascii_lines(text, 256)
    -- 22 probes were measured to produce one distinct string, so deduplicating
    -- is most of the saving.
    if text ~= "" and not seen[text] then
      seen[text] = true
      payloads[#payloads + 1] = text
    end
  end

  if #payloads == 0 then
    return nil
  end
  return payloads
end

--- The banner as one string, for the endpoint that is asked about text.
--
-- ascii() rather than ascii_lines(): the endpoint is asked about a piece of
-- text, not matched line by line, so collapsing the payload's newlines back
-- into spaces is what it wants.
local function decode_service_fp(fingerprint)
  local payloads = service_fp_payloads(fingerprint)
  if payloads == nil then
    return nil
  end
  return ascii(table.concat(payloads, " "), 512)
end

--- The CPEs nmap's own service banner names.
--
-- Free in every sense: the text is already in hand, so this costs no request,
-- no credit and no time on the wire, and it runs with or without a token.
--
-- The subject is nmap's service fingerprint, which nmap records when its own
-- probes did NOT settle the service - which is exactly the case worth trying. A
-- port nmap could not name is a port with no CPE, and a port with no CPE is one
-- that would otherwise cost a credit at audit/smart, or go unreported entirely
-- in a keyless scan. Identities nmap can already emit itself were dropped when
-- the rules were imported, because this script reads port.version.cpe anyway
-- and re-deriving them would be 286 KB of weight for nothing.
--
-- Matched line by line rather than as one blob: a recog banner pattern is
-- written against a single greeting line and most of them are anchored with ^,
-- so concatenating the payloads would leave every anchor but the first unable
-- to match.
--
-- @return map of cpe -> where it was found
local function fingerprint_banner(port, deadline)
  local banner = as_string(dig(port, "version", "service_fp"))
  if banner == nil then
    return {}
  end

  local payloads = service_fp_payloads(banner)
  if payloads == nil then
    return {}
  end

  local found, seen = {}, {}
  -- Defaulted, because the tests drive this function directly; production hands
  -- it the port's one budget.
  deadline = deadline or (os.clock() + SWEEP_TIME_BUDGET)
  for _, payload in ipairs(payloads) do
    for line in (payload .. "\n"):gmatch("([^\r\n]*)[\r\n]") do
      if line ~= "" then
        match_group("banner", line, found, seen, deadline)
      end
    end
  end

  local where, count = {}, 0
  for _, cpe in ipairs(found) do
    if count >= MAX_IDENTITIES_PER_PORT then
      break
    end
    count = count + 1
    where[cpe] = "service banner"
  end
  return where
end

--- Fingerprint the web stack of one port.
--
-- @return map of cpe -> the path it was found on
local function fingerprint(host, port, paths, deadline)
  if #paths == 0 then
    return {}
  end

  local responses = fetch_paths(host, port, paths)
  follow_redirects(host, port, responses)

  if next(responses) == nil then
    return {}
  end

  local seen, where = {}, {}
  local spent = 0
  deadline = deadline or (os.clock() + SWEEP_TIME_BUDGET)
  local discovered_here = 0
  -- Which targeted probes the responses make worth sending. Collected while the
  -- subjects are in hand and acted on afterwards, so that a probe is only sent
  -- once every passive rule has had its chance to make it unnecessary.
  local triggered = {}

  for index, path in ipairs(paths) do
    local response = responses[index]
    if response and response.status and os.clock() < deadline
       and discovered_here < MAX_IDENTITIES_PER_PORT then
      local found = {}

      -- Bytes remain as a second barrier behind the clock. The two bound
      -- different things: the clock bounds how long matching may take, which is
      -- what an adversarial body attacks, and this bounds how much is read at
      -- all, which is what a slow-but-honest one costs.
      if spent < SWEEP_BYTE_BUDGET then
        spent = spent + #tostring(response.body or "")
        local rawheaders = response.rawheader
        if rawheaders then
          for _, line in ipairs(rawheaders) do
            spent = spent + #line
          end
        end
        local subjects = subjects_of(response, deadline)
        match_subjects(subjects, found, seen, deadline)
        detect_probes(subjects, triggered, deadline)
      end

      for _, cpe in ipairs(found) do
        if discovered_here >= MAX_IDENTITIES_PER_PORT then
          stdnse.verbose1("vulners: this port produced more than %d identities; " ..
            "the rest are ignored", MAX_IDENTITIES_PER_PORT)
          break
        end
        discovered_here = discovered_here + 1
        where[cpe] = path
      end
    end
  end

  if os.clock() >= deadline then
    stdnse.verbose1("vulners: the fingerprint sweep ran out of its time budget " ..
      "on this port; some paths were not matched")
  end

  for cpe, path in pairs(run_probes(host, port, triggered, where, deadline)) do
    where[cpe] = path
  end

  return where
end

--- Publish what the sweep found, so the rest of the scan can use it.
--
-- Both writes matter. The registry is what a third-party script reads; the
-- port.version.cpe list is what puts the CPE into the <service> element of the
-- report, and that is the only reason a header-only identity like
-- cpe:/a:php:php:5.6.38 appears there at all - nmap's own probe cannot see it.
-- Appending blindly would duplicate <cpe> elements, so both lists are checked.
local function publish_cpes(host, port, discovered)
  if next(discovered) == nil then
    return
  end

  host.registry.vulners_cpe = host.registry.vulners_cpe or {}
  host.registry.vulners_cpe[port.number] = host.registry.vulners_cpe[port.number] or {}
  local registry = host.registry.vulners_cpe[port.number]

  local in_registry = {}
  for _, cpe in ipairs(registry) do
    in_registry[cpe] = true
  end

  local version = port.version or {}
  version.cpe = version.cpe or {}
  local in_port = {}
  for _, cpe in ipairs(version.cpe) do
    in_port[cpe] = true
  end

  -- Sorted for the same reason: these become <cpe> children of nmap's own
  -- <service> element, and they were appended in a per-process random order.
  local found = {}
  for cpe in pairs(discovered) do
    found[#found + 1] = cpe
  end
  table.sort(found)

  for _, cpe in ipairs(found) do
    if not in_registry[cpe] then
      in_registry[cpe] = true
      registry[#registry + 1] = cpe
    end
    if not in_port[cpe] then
      in_port[cpe] = true
      version.cpe[#version.cpe + 1] = cpe
    end
  end

  port.version = version
  -- The probestate matters, and the default is a lie here. Measured on nmap
  -- 7.991 against a real listener with no -sV:
  --
  --   without this script   <service name="http-alt" method="table"  conf="3"/>
  --   set_port_version(h,p) <service name="http-alt" method="probed" conf="10">
  --
  -- so the two-argument form makes nmap report a hard version-probe match for a
  -- service no version probe ever touched, in the XML other tools consume.
  -- "incomplete" keeps method/conf as they were and still attaches the <cpe>.
  -- It is NOT passed unconditionally: on a genuine -sV hardmatch it would
  -- DOWNGRADE method="probed" conf="10" back to method="table" conf="3".
  local probed = dig(port, "version", "service_dtype") == "probed"
  nmap.set_port_version(host, port, probed and "hardmatched" or "incomplete")
end

-- -------------------------------------------------------------- 10. Render

--- Which optional columns this set of findings can actually fill.
--
-- The columns follow the data rather than the licence: the script does not
-- detect what its key is entitled to, it looks at what arrived. A column whose
-- data is missing is dropped, never blanked - a blank EPSS cell reads as "this
-- finding is quiet", which is a claim an absent field does not support.
local function columns_for(rows)
  local has = {epss = false, ai = false, title = false}
  for _, row in ipairs(rows) do
    if row.epss ~= nil then has.epss = true end
    if row.ai_score ~= nil then has.ai = true end
    if ascii(row.title, 200) ~= "" then has.title = true end
  end
  return has
end

--- The vulners.com page for one finding.
--
-- Composed, never read off the response. The enrich endpoint does return an
-- href and it is the UPSTREAM source, not a vulners.com page: measured, it
-- answers web.nvd.nist.gov for a cve, github.com for a githubexploit,
-- 0day.today for a zdt and rapid7.com for a metasploit module. The free
-- endpoint sends no href at all - 272 of 272 rows on one real CPE. The format
-- below is the one nmap's own shipped 1.x copy of this script prints.
local function vulners_link(row)
  return string.format("https://vulners.com/%s/%s", row.type or "bulletin", row.id)
end

--- The FLAGS cell: fixed-width tokens, greppable, its own legend.
local function flags_of(row)
  local flags = {}
  if row.kev then
    flags[#flags + 1] = "KEV"
  end
  if row.exploit_known or is_exploit(row) then
    flags[#flags + 1] = "EXP"
  end
  return table.concat(flags, " ")
end

--- One EPSS value in four characters.
--
-- A probability of 0.00001 formatted as a percentage to one decimal reads
-- "0.0%", which a person reads as "zero" - and zero is the one thing EPSS never
-- reports. Anything that would round to nothing is shown as a bound instead.
local function epss_cell(epss)
  -- Bounded at the top for the same reason as the bottom: EPSS is a
  -- probability, and printing "100%" asserts a certainty the model never states.
  if epss >= 0.995 then
    return ">99%"
  end
  if epss >= 0.01 then
    return string.format("%d%%", math.floor(epss * 100 + 0.5))
  end
  if epss >= 0.001 then
    return string.format("%.1f%%", epss * 100)
  end
  return "<.1%"
end

--- Lay findings out as an aligned ASCII table.
--
-- Everything here is printable ASCII: nmap's escape_for_screen() passes only
-- TAB, LF and 0x20-0x7E, so colour and box-drawing are not a stylistic choice
-- that was rejected, they are impossible. Expressiveness comes from alignment,
-- fixed-width tokens and the sort order.
local function render_rows(rows, width, verbosity)
  local lines = {}

  local shown = rows
  local hidden = 0
  if verbosity < 2 then
    -- Default verbosity shows the top of the ranking and says how much it is
    -- not showing. A severity filter is not enough on its own: one real Apache
    -- 2.4.7 answers with 272 findings of which 24 are CRITICAL and 56 carry an
    -- exploit, so "HIGH and above" is still dozens of rows and nobody reads
    -- them. The whole point of ranking by exploitability is that the first
    -- rows are the ones worth acting on, which makes a bound on the count the
    -- honest way to use it.
    shown = {}
    local taken, skipped = {}, {}
    for _, row in ipairs(rows) do
      if #shown >= MAX_DEFAULT_ROWS then
        break
      end
      local band = row.bucket
      if (taken[band] or 0) < MAX_BAND_ROWS then
        taken[band] = (taken[band] or 0) + 1
        shown[#shown + 1] = row
      else
        skipped[#skipped + 1] = row
      end
    end
    -- A band that hit its cap still fills the summary when nothing else can.
    for _, row in ipairs(skipped) do
      if #shown >= MAX_DEFAULT_ROWS then
        break
      end
      shown[#shown + 1] = row
    end
    -- Back into rank order: the caps above pick WHICH rows are worth the
    -- summary, not what order they are read in.
    table.sort(shown, ranks_before)
    hidden = #rows - #shown
  end

  -- Computed on the rows that will actually be printed. Reading every row meant
  -- a column could be created for data only the hidden rows carry, and then
  -- every visible cell in it was blank - the "this finding is quiet" reading the
  -- design forbids, and 56 of 100 columns spent saying nothing.
  local has = columns_for(shown)

  -- A link is atomic: it cannot be folded and cutting it produces something
  -- that is no longer a link. It is bounded all the same, because the id inside
  -- it is unvalidated response data - measured across 272 real findings on one
  -- CPE, a vulners.com link runs 36 to 78 characters, so anything past this is
  -- pathological and clipping is then the lesser evil.
  local MAX_LINK = 120

  local links = {}
  local longest_link = 0
  for _, row in ipairs(shown) do
    local link = ascii(vulners_link(row), MAX_LINK)
    links[row] = link
    longest_link = math.max(longest_link, #link)
  end

  -- Two for nmap's own "| " prefix, two for the indent, two between columns.
  local function measure(without)
    local header, widths = {"SEVERITY", "CVSS"}, {8, 4}
    if not without then
      if has.epss then
        header[#header + 1] = "EPSS"
        widths[#widths + 1] = 4
      elseif has.ai then
        header[#header + 1] = "AI"
        widths[#widths + 1] = 4
      end
    end
    header[#header + 1] = "FLAGS"
    widths[#widths + 1] = 7

    local used = 4
    for _, w in ipairs(widths) do
      used = used + w + 2
    end
    return header, widths, used
  end

  -- The optional numeric column is dropped when dropping it is what makes the
  -- table fit: at 40 columns - the narrowest the arguments allow - keeping it
  -- produced a 47-column line, so the promise to fit was quietly broken by the
  -- one column that carries the least. It is NOT dropped for a link too long to
  -- fit either way, because losing EPSS buys nothing there.
  local header, widths, used = measure(false)
  local drop_numeric = false
  if width - used - 2 < longest_link then
    local plain_header, plain_widths, plain_used = measure(true)
    if width - plain_used - 2 >= longest_link then
      header, widths, used, drop_numeric = plain_header, plain_widths, plain_used, true
    end
  end

  local title_width = width - used - longest_link - 2
  if has.title and title_width >= 16 then
    header[#header + 1] = "TITLE"
    widths[#widths + 1] = title_width
  else
    title_width = nil
  end

  header[#header + 1] = "LINK"
  widths[#widths + 1] = longest_link

  local show_epss = has.epss and not drop_numeric
  local show_ai = has.ai and not has.epss and not drop_numeric

  -- Padded by hand rather than with string.format("%-<w>s"): Lua accepts at
  -- most two digits of field width, so a 100-byte bulletin id - which is
  -- unvalidated response data - raised "invalid conversion specification" and
  -- the port lost every finding it had, in the text AND in the XML.
  local function pad(text, width, right)
    text = text or ""
    local short = width - #text
    if short <= 0 then
      return text
    end
    if right then
      return string.rep(" ", short) .. text
    end
    return text .. string.rep(" ", short)
  end

  local function row_text(cells)
    local parts = {}
    for index, cell in ipairs(cells) do
      local numeric = index == 2 or header[index] == "EPSS" or header[index] == "AI"
      if index == #cells then
        parts[#parts + 1] = cell or ""
      else
        parts[#parts + 1] = pad(cell, widths[index], numeric)
      end
    end
    return "  " .. table.concat(parts, "  "):gsub("%s+$", "")
  end

  lines[#lines + 1] = row_text(header)
  local rule = {}
  for index in ipairs(header) do
    rule[index] = string.rep("=", widths[index])
  end
  lines[#lines + 1] = row_text(rule)

  for _, row in ipairs(shown) do
    local cells = {row.severity, row.cvss and string.format("%.1f", row.cvss) or ""}
    if show_epss then
      cells[#cells + 1] = row.epss and epss_cell(row.epss) or ""
    end
    if show_ai then
      cells[#cells + 1] = row.ai_score and string.format("%.1f", row.ai_score) or ""
    end
    cells[#cells + 1] = flags_of(row)
    if title_width then
      cells[#cells + 1] = ascii(row.title or "", title_width)
    end
    cells[#cells + 1] = links[row]
    lines[#lines + 1] = row_text(cells)

    if verbosity >= 3 and row.found_on then
      -- Folded like every other cell. This was one of the two response values
      -- that reached the terminal raw: a newline inside it printed a second
      -- line of script output that nmap prefixes exactly like a real finding,
      -- so the API could forge rows in the human report.
      lines[#lines + 1] = "      found on " .. ascii(row.found_on, 40)
    end
  end

  if hidden > 0 then
    -- "ranked below these" was false whenever the per-band cap fired: the cap
    -- deliberately hides rows that outrank ones it shows, so the sentence told
    -- the operator the opposite of what happened.
    local footer = string.format("  %d more not shown; -v shows all", hidden)
    local full = footer .. ", -vv adds where each was found"
    if #full + 2 <= width then
      footer = full
    end
    lines[#lines + 1] = footer
  end

  return table.concat(lines, "\n")
end

--- The structured element for one finding.
--
-- stdnse.output_table(), never a plain table: a plain one renders its elements
-- in hash order, and five consecutive runs of the same scan produced five
-- different orders. Consumers diffing two reports would see phantom changes.
--
-- Extra elements are ignored harmlessly by every consumer examined; extra
-- NESTING would be invisible to them, which is why nothing here is a table.
local function report_row(row)
  local element = stdnse.output_table()
  element.id = ascii(row.id, 120)
  element.type = ascii(row.type, 40)
  if element.type == "" then
    element.type = "unknown"
  end
  -- Emitted on every row, unlike cvss: DefectDojo indexes a severity key
  -- unguarded, and an unscored bulletin still needs one. Fabricating a score
  -- instead would be read as Info, which is a different and false statement.
  element.severity = row.severity
  if row.cvss ~= nil then
    element.cvss = string.format("%.1f", row.cvss)
    local kind = ascii(row.cvss_type, 20)
    if kind ~= "" then
      element.cvss_type = kind
    end
  end
  element.is_exploit = tostring(is_exploit(row) or false)
  if row.exploit_known then
    element.exploit_known = "true"
  end
  if row.kev then
    element.kev = "true"
  end
  local ssvc = ascii(row.ssvc, 20)
  if ssvc ~= "" then
    element.exploitation = ssvc
  end
  if row.epss ~= nil then
    element.epss = string.format("%.5f", row.epss)
  end
  if row.epss_percentile ~= nil then
    element.epss_percentile = string.format("%.5f", row.epss_percentile)
  end
  if row.ai_score ~= nil then
    element.ai_score = string.format("%.1f", row.ai_score)
  end
  -- Folded before the decision, not after. ascii() maps every byte outside
  -- 0x20-0x7E to a space and then strips, so a title with no Latin characters
  -- folds to "" - and guarding on the RAW value emitted an empty element and a
  -- column of blank cells. Not hypothetical: this script's own example output
  -- lists a CNVD entry, and CNVD titles are Chinese.
  local title = ascii(row.title, 200)
  if title ~= "" then
    element.title = title
  end
  local published = ascii(row.published, 40)
  if published ~= "" then
    element.published = published
  end
  element.href = ascii(vulners_link(row), 300)
  -- The upstream page, when the endpoint named one. Kept apart from href
  -- because they are different things: href has always been documented as the
  -- vulners.com page, and the free endpoint has no source link to publish, so
  -- letting one field mean either would make its meaning depend on the mode.
  local source = ascii(row.href, 300)
  if source ~= "" then
    element.source_href = source
  end
  local found_on = ascii(row.found_on, 120)
  if found_on ~= "" then
    element.found_on = found_on
  end
  return element
end

-- ---------------------------------------------------------------- rules

--- The union of what the three 1.x rules admitted, plus the banner.
--
-- No clause reproduces today's coverage alone: probed against real listeners,
-- shortport.http matches 8080 and 8443 where the version clause is false, and
-- the version clause matches ssh and mysql where shortport.http is false. The
-- registry clause keeps working for anything that seeded CPEs before this
-- script ran.
--
-- The service_fp clause is the banner channel's, and without it that channel
-- was dead where it was meant to pay. nmap records a service fingerprint
-- exactly when its own probes did NOT settle the service - measured against a
-- listener greeting with an unrecognised banner, nmap hands the script a
-- 2 209-byte service_fp and leaves name, product, version and cpe all empty. So
-- every other clause is false precisely on the ports the banner rules were
-- imported for, and a keyed scan never reached audit/smart for them either:
-- both features were unreachable through the front door.
portrule = function(host, port)
  if shortport.http(host, port) then
    return true
  end
  local version = port.version
  if version and (version.version ~= nil or version.service_fp ~= nil) then
    return true
  end
  local found = host.registry.vulners_cpe
  return found ~= nil and found[port.number] ~= nil
end

--- Collect the identities worth asking about, deduplicated.
--
-- @return list, refused - the count of identities turned away for being absurd.
--         The caller needs that separately: a port whose only CPE was refused
--         is a port with a BAD identity, not a port with none, and treating the
--         two alike sent it to the billed endpoint. The trigger is
--         attacker-controlled, since nmap builds CPEs out of banner text - so
--         the target would have been choosing whether the operator pays.
local function collect_cpes(host, port, discovered)
  local list, seen = {}, {}
  local refused = 0

  local function add(cpe)
    if type(cpe) ~= "string" or cpe == "" then
      return
    end
    if #cpe > MAX_IDENTITY then
      stdnse.debug1("Refusing an identity of %d bytes; it cannot be real", #cpe)
      refused = refused + 1
      return
    end
    local canonical = canonical_cpe(cpe)
    if seen[canonical] then
      return
    end
    seen[canonical] = true
    list[#list + 1] = cpe
  end

  for _, cpe in ipairs(dig(port, "version", "cpe") or {}) do
    add(cpe)
  end
  -- Best-effort compatibility rather than a contract: dependencies is what puts
  -- a script in a later runlevel, and with the 1.x scripts gone there is no
  -- ordering guarantee that a third-party producer runs first.
  for _, cpe in ipairs(dig(host, "registry", "vulners_cpe", port.number) or {}) do
    add(cpe)
  end
  -- Sorted, because pairs() over string keys walks them in an order Lua seeds
  -- per process: identical scans of an unchanged host produced their groups in
  -- different orders, and stdnse.output_table() faithfully preserved an
  -- insertion order that was random to begin with. Anyone diffing two reports
  -- saw phantom changes - the very thing the ordered output exists to prevent.
  local swept = {}
  for cpe in pairs(discovered) do
    swept[#swept + 1] = cpe
  end
  table.sort(swept)
  for _, cpe in ipairs(swept) do
    add(cpe)
  end

  return list, refused
end

--- Ask the free endpoint about one CPE, reusing what the scan already knows.
--
-- Only an answer is remembered. A rate limit or an exhausted retry budget
-- leaves the cache untouched, so the next host asks again instead of inheriting
-- a silent "no vulnerabilities" for the rest of the scan.
local function lookup(key, software, version, kind)
  local shared = state()

  -- A ceiling nothing in a response can move. The number of identities is
  -- target-controlled through the sweep, and one hostile page was measured to
  -- turn into 903 outbound requests.
  if shared.lookups[key] == nil and shared.looked_up >= MAX_LOOKUPS_PER_SCAN then
    stdnse.debug1("This scan reached its ceiling of %d identities",
      MAX_LOOKUPS_PER_SCAN)
    return nil, false
  end

  -- A cache entry means the service answered, and it carries the provenance
  -- with it. Both halves matter: the entry used to be either a row list or the
  -- literal false, which made "resolved and has nothing" indistinguishable
  -- from "the request failed" on the second host that asked - and the
  -- provenance was read out of a table nothing ever wrote. Either fault alone
  -- was invisible; together they made every later host of a network scan
  -- re-decide whether to spend a credit on a CPE already known to be clean.
  local function from_cache(entry)
    return entry.rows, true, entry.explain
  end

  -- Two passes: wait once for a lookup in flight, then ask for ourselves if
  -- that lookup produced nothing. The wait happens on the FIRST pass only.
  -- Waiting on both passes made a contended identity cost 2 x
  -- PENDING_WAIT_LIMIT, which the three-spelling nginx fan-out turns into three
  -- minutes on one port - and the whole point of the bound is that an owner
  -- which died must not hang the scan.
  for attempt = 1, 2 do
    local cached = shared.lookups[key]
    if cached ~= nil then
      return from_cache(cached)
    end

    if attempt == 1 and shared.pending[key] then
      wait_for_pending(shared.pending, key)
    else
      -- On the second pass the claim may still be held by whoever died with it;
      -- it is left alone rather than cleared, because it is not ours to release.
      local ours = not shared.pending[key]
      if ours then
        shared.pending[key] = true
      end
      shared.looked_up = shared.looked_up + 1
      local rows, answered, explain = burp_lookup(software, version, kind)
      if ours then
        shared.pending[key] = nil
      end
      if answered then
        shared.lookups[key] = {
          rows = rows and #rows > 0 and rows or nil,
          explain = explain,
        }
      end
      return rows, answered, explain
    end
  end
end

--- Did burp resolve the identity it was asked about?
--
-- The endpoint reports this in search_explain, by echoing back the CPE it
-- matched. Three answers, and the third is the one that earns the function:
-- an answer that says nothing either way - no search_explain at all, or one
-- half of it missing - is not evidence, and the safe reading of "nothing either
-- way" is not to bill for it. Reading only search_cpe left every clean CPE
-- billing again the moment the service omitted matched_cpe.
--
-- @return true resolved, false positively unresolved, nil no evidence either way
local function resolution_of(explain)
  local asked = as_string(dig(explain, "search_cpe"))
  local matched = as_string(dig(explain, "matched_cpe"))
  if asked == nil or matched == nil then
    return nil
  end
  return matched == asked
end

--- Look a CPE up, asking every nginx spelling and merging the answers.
--
-- "Did this identity resolve" is a question about the PRODUCT, not about one of
-- its three vendor spellings, so the verdict is formed here across all of them
-- rather than handed outwards as one spelling's search_explain. Both halves of
-- it are aggregated, and that symmetry is the point:
--
--   * any spelling resolving means the identity resolved, even if the others
--     said nothing - otherwise a product :nginx:nginx: resolved cleanly still
--     billed a credit, because :f5: is always asked first;
--   * one spelling positively failing to resolve stands, even if the others
--     said nothing - otherwise the same first-wins reading in the other
--     direction let an unidentifiable service report clean, because
--     as_string(dig(nil, ...)) and an empty search_explain are the same nil.
--
-- @return rows, answered, resolution
--         resolution is true resolved, false positively unresolved, nil when
--         nothing said either way. Only false may cost a credit.
local function lookup_cpe(cpe)
  local rows, answered
  local variants = nginx_variants(cpe) or {cpe}

  local resolution
  local function observe(why)
    local verdict = resolution_of(why)
    if verdict == true then
      resolution = true
    elseif verdict == false and resolution == nil then
      resolution = false
    end
  end

  for _, variant in ipairs(variants) do
    local vers, patch = variant:match(CPE_VERSION_PATTERN)
    if vers then
      local got, ok, why = lookup(variant, variant, vers, "cpe")
      rows = merge_rows(rows, got)
      -- Any spelling answering is the identity being answered: they are three
      -- names for one product, not three questions.
      answered = answered or ok
      observe(why)

      -- The 1.x retry: maybe the version and its patch level need separating.
      if (not got or #got == 0) and patch and patch ~= "" then
        local split = variant:gsub(CPE_VERSION_PATTERN, ":%1:%2")
        local retry, retry_ok, retry_why = lookup(split, split, vers, "cpe")
        rows = merge_rows(rows, retry)
        -- The PRIMARY request decides whether this identity was answered. A
        -- transient failure on the secondary used to poison it, which skipped
        -- the credit decision entirely and reported an unidentifiable service
        -- as clean - silently, since the unnamed counter needs #cpes == 0.
        if retry_ok then
          observe(retry_why)
        end
      end
    end
  end

  return rows, answered, resolution
end

--- What one port contributes to the report.
local function port_action(host, port)
  local cfg = config()
  local shared = state()
  shared.consulted = true

  if cfg.fatal then
    -- An operator who names a key file means that file; falling back to the
    -- free path silently would hide a typo in a path for the whole scan.
    stdnse.verbose1("vulners: %s", cfg.fatal)
    return nil
  end

  -- The sweep is gated here rather than in the portrule, because the portrule
  -- must stay wide enough to look up a versioned SSH or MySQL port. Without
  -- this gate, D4 read literally would fire the whole path sweep at every
  -- versioned SSH, SMTP and RDP port - measured at roughly 494 requests per
  -- port once the retry rounds are counted, on the 125-path list, and the list
  -- is longer now. shortport.http is "port number OR service name", so on the
  -- eleven likely HTTP ports the number wins even when -sV positively
  -- identified something else - and SSH on 8000 was swept in full. A service
  -- nmap named, that is not an HTTP one, is not swept.
  --
  -- Only a service nmap PROBED counts as named. Without -sV, port.service is
  -- nmap's ports-file guess, and the guess is wrong for two of the eleven
  -- numbers shortport.http admits: measured against real HTTP listeners, 7080
  -- is guessed "empowerid" and 8088 "radan-http", neither of which is in
  -- LIKELY_HTTP_SERVICES - so the sweep was silently skipped on exactly the
  -- ports the portrule was widened to reach.
  --
  -- LIKELY_HTTP_SERVICES is a LIST, not a set, so indexing it by name yields nil
  -- for every service including "http" itself. tableaux.contains with the array
  -- flag is how shortport.service itself reads that same list
  -- (nselib/shortport.lua:110), so this asks the question exactly as nmap does.
  local probed = dig(port, "version", "service_dtype") == "probed"
  local named = as_string(port.service) or as_string(dig(port, "version", "name"))
  local misidentified = probed and named ~= nil
    and not tableaux.contains(shortport.LIKELY_HTTP_SERVICES, named, true)
  -- The banner rules run on EVERY port, HTTP or not, because their subject is
  -- nmap's own service fingerprint - text already in hand. An SSH, SMTP or
  -- MySQL port that nmap could not name is exactly where this pays: it is a
  -- port with no CPE, which in a keyless scan is a port that reports nothing at
  -- all, and in a keyed one is a port about to spend a credit.
  -- One budget for everything this port matches: the banner pass, the sweep and
  -- the probe extraction all read the same clock.
  local deadline = os.clock() + SWEEP_TIME_BUDGET
  local discovered = fingerprint_banner(port, deadline)

  if shortport.http(host, port) and not misidentified then
    for cpe, where in pairs(
        fingerprint(host, port, sweep_paths(cfg.paths_arg), deadline)) do
      discovered[cpe] = where
    end
  end
  publish_cpes(host, port, discovered)

  local groups, order = {}, {}
  local all_rows = {}

  local function group(key, rows, identity)
    if not rows or #rows == 0 then
      return
    end
    if groups[key] == nil then
      groups[key] = {rows = {}, identity = identity}
      order[#order + 1] = key
    end
    groups[key].rows = merge_rows(groups[key].rows, rows)
  end

  local cpes, refused_identities = collect_cpes(host, port, discovered)
  local unresolved = {}

  for _, cpe in ipairs(cpes) do
    local rows, answered, resolution = lookup_cpe(cpe)
    if rows then
      -- Copied, never annotated in place. These row tables live in the
      -- scan-wide cache and are handed to every later host by reference, so
      -- writing this host's sweep path onto them reported a path on hosts the
      -- scanner never swept - a fabricated observation in somebody's report.
      local path = discovered[cpe]
      if path then
        local annotated = {}
        for index, row in ipairs(rows) do
          local copy = {}
          for key, value in pairs(row) do
            copy[key] = value
          end
          copy.found_on = path
          annotated[index] = copy
        end
        rows = annotated
      end
      group(cpe, rows)
    end
    -- Spend a credit only where the identity itself failed to resolve. burp
    -- reports that in search_explain: when it echoes back the CPE it matched,
    -- the lookup worked and an empty answer means the software is clean.
    -- Spend only on POSITIVE evidence that the identity failed to resolve,
    -- which is what false - rather than nil - says.
    if answered and (not rows or #rows == 0) and resolution == false then
      unresolved[#unresolved + 1] = cpe
    end
  end

  -- The 1.x fallback, kept: when the CPE lookups found nothing, ask about the
  -- product and version as text. Without a key that is all there is; with one,
  -- the smart endpoint answers far better.
  local version = port.version or {}
  local label
  if next(groups) == nil and version.product and version.version then
    label = version.product .. " " .. version.version
    if #label > MAX_IDENTITY then
      stdnse.debug1("Refusing a software label of %d bytes", #label)
      label = nil
    end
  end

  -- A port with NO CPE goes to audit/smart instead when there is a token: that
  -- was measured to answer where this free text lookup does not ("Apache httpd"
  -- as text returned 0 where the CPE returned 342).
  --
  -- But a port that HAS a CPE never reaches audit/smart - by design, since a
  -- CPE must not cost a credit - so without this clause a keyed scan reported
  -- strictly LESS than a keyless one for a port whose CPE resolved clean and
  -- whose product and version the free endpoint could still answer. Paying for
  -- a key made the report worse, which is the regression the degrade ladder
  -- exists to prevent.
  if label and (shared.mode ~= "keyed" or #cpes > 0) then
    local rows = lookup(label, version.product, version.version, "software")
    group(label, rows, "software")
  end

  -- Tier 2: the one billed call, for a service the free path cannot name.
  --
  -- The gate is "#cpes == 0", not "nothing was found". A port that carries a
  -- CPE never costs a credit even when the answer was empty: "this software is
  -- clean" IS an answer, and the free endpoint was measured to give the same
  -- one the paid endpoint gives. Gating on emptiness instead billed a credit
  -- for every correctly identified, fully patched service - so a network of
  -- well maintained hosts cost the most, which is precisely backwards.
  if shared.mode == "keyed" then
    local strings = {}
    if #cpes == 0 and refused_identities == 0 then
      if label then
        strings[#strings + 1] = label
      else
        local banner = as_string(version.service_fp)
        if banner then
          -- Only the probe payloads, deduplicated: a string that is mostly
          -- nmap's own metadata is not worth a credit, and one carrying %Time=
          -- can never be deduplicated across two identical hosts.
          local decoded = decode_service_fp(banner)
          if decoded then
            strings[#strings + 1] = decoded
          end
        end
      end
    end
    for _, cpe in ipairs(unresolved) do
      strings[#strings + 1] = cpe
    end

    if #strings > 0 then
      local answers = audit_smart(strings)
      -- Walked in the order the strings were SENT, not in the order the answers
      -- happen to hash: the same three inputs came back in three different group
      -- orders on three runs.
      local answered = answers or {}
      for _, input in ipairs(strings) do
        local answer = answered[input]
        if answer ~= nil then
          local rows = {}
          for _, id in ipairs(answer.ids) do
            rows[#rows + 1] = {id = id}
          end
          -- The CPE the service resolved is a real identity; the raw label is
          -- not, and is marked so a consumer can tell them apart rather than
          -- being handed an invented CPE.
          --
          -- Written out rather than as a conditional expression: the form
          -- "answer.cpe and nil or ..." is always the right-hand branch in Lua,
          -- because "X and nil" is falsy. Every group was stamped "software",
          -- including the ones keyed by a real CPE the service resolved -
          -- telling every importer that a valid CPE key was not a CPE.
          local identity = nil
          if answer.cpe == nil then
            identity = "software"
          end
          group(answer.cpe or input, rows, identity)
        end
      end
    end
  end

  if next(groups) == nil then
    -- Counted only when there was no usable identity at all. A port whose CPE
    -- resolved to nothing was identified perfectly well, and telling the user a
    -- key would have named it is simply false.
    if #cpes == 0 and refused_identities == 0 and (label or version.service_fp) then
      shared.unnamed = shared.unnamed + 1
    end
    return nil
  end

  for _, key in ipairs(order) do
    for _, row in ipairs(groups[key].rows) do
      all_rows[#all_rows + 1] = row
    end
  end

  -- One enrichment call covers every finding, whatever discovered it.
  local ids = {}
  for _, row in ipairs(all_rows) do
    ids[#ids + 1] = row.id
  end
  enrich(ids)

  local output = stdnse.output_table()
  output.schema = "2.0"
  output.mode = shared.mode
  -- The group key can come from the API (audit/smart answers with it), and
  -- output_table replaces an existing key in place - so a service answering
  -- with the cpe "schema" overwrote the schema element with a table.
  local RESERVED = {schema = true, mode = true}
  local text = {}
  local reported = false

  for _, key in ipairs(order) do
    local rows = groups[key].rows
    for _, row in ipairs(rows) do
      enrich_row(row)
    end
    attribute_exploits(rows)
    rows = apply_mincvss(rows, cfg.mincvss)
    for _, row in ipairs(rows) do
      row.severity = severity_of(row.cvss)
    end
    rank(rows)

    if #rows > 0 then
      reported = true
      local group_table = {}
      for index, row in ipairs(rows) do
        group_table[index] = report_row(row)
      end
      if groups[key].identity then
        -- No CPE is invented for a human label: a made-up product name would
        -- make an importer attach findings to software that does not exist.
        group_table.identity = groups[key].identity
      end
      local element_key = key
      if RESERVED[element_key] then
        element_key = element_key .. " "
      end
      output[element_key] = group_table

      local exploitable = 0
      for _, row in ipairs(rows) do
        if row.exploit_known or is_exploit(row) then
          exploitable = exploitable + 1
        end
      end

      -- Returning a plain string loses nmap's own "| <key>:" grouping lines, so
      -- each group opens with its own header.
      -- The suffix is measured, not assumed, and the allowance is nmap's real
      -- prefix: the FIRST line of a script's output carries "| vulners: ", which
      -- is 11 columns, not 2. Assuming a flat 30 put every group header over
      -- budget at every width - 48 columns at a configured 40.
      local suffix = string.format("  %d finding%s, %d exploitable",
        #rows, #rows == 1 and "" or "s", exploitable)
      local room = cfg.width - #suffix - 11
      text[#text + 1] = ascii(key, math.max(12, room)) .. suffix
      text[#text + 1] = render_rows(rows, cfg.width, nmap.verbosity())
    end
  end

  if not reported then
    return nil
  end

  return output, table.concat(text, "\n")
end

--- What the scan says once, at the end.
local function post_action()
  local shared = nmap.registry.vulners
  if not shared or not shared.consulted then
    -- Nothing was looked up, so there is nothing to advertise. A -sn sweep that
    -- consulted no port gets no advertisement.
    return nil
  end

  -- Said in every branch below, because it is independent of the API key: a
  -- scan can have a perfectly good key and still have done no web
  -- fingerprinting, and the operator has to be able to tell that from a network
  -- where nothing was found. Silence about a capability that did not run reads
  -- as a capability that found nothing.
  local function with_notes(text)
    local notes = {}
    if shared.catalog_note then
      notes[#notes + 1] = shared.catalog_note
    end
    -- The same class of fact as the catalogue one, and it used to be told only
    -- at -v: a paths file that could not be read stops the sweep completely,
    -- and a sweep that did not run reads as a sweep that found nothing.
    if shared.sweep_note then
      notes[#notes + 1] = shared.sweep_note
    end
    if #notes == 0 then
      return text
    end
    -- Wrapped by hand, like every other notice here: nmap does not wrap script
    -- output, so a sentence written as one string arrives as one line however
    -- wide the terminal is.
    local wrapped = {}
    for _, note in ipairs(notes) do
      local line = "  "
      for word in (note .. "."):gmatch("%S+") do
        if #line + #word + 1 > 74 then
          wrapped[#wrapped + 1] = line
          line = "  " .. word
        else
          line = (line == "  ") and (line .. word) or (line .. " " .. word)
        end
      end
      wrapped[#wrapped + 1] = line
    end

    local notice = "\n" .. table.concat(wrapped, "\n")
    return text and (text .. "\n" .. notice) or notice
  end

  -- Said before anything else, and instead of everything else. An operator who
  -- names a key file means that file, so a file that cannot be read stops the
  -- run - port_action returns nothing for every port. That was reported only to
  -- stdnse.verbose1, so without -v the scan produced an empty report and a
  -- notice offering a free key to somebody who already has one and mistyped its
  -- path. Measured against a live scan: the same host reports 272 findings with
  -- no key at all, and nothing whatever with an unreadable one.
  local fatal = config().fatal
  if fatal then
    return nil, with_notes("\n  Nothing was looked up: " .. fatal .. "." ..
      "\n  Naming a key means the scan will not quietly fall back to the" ..
      "\n  keyless endpoint. Correct that argument, or drop it to run" ..
      "\n  without a key.")
  end

  -- Said first, and independently of everything else. A scan whose lookups
  -- never happened must not read as a clean network - and this used to be
  -- printed only in the two branches BELOW the spend summary, so a keyed scan
  -- that spent a credit and then lost the free leg reported "3 credits spent"
  -- and not one word about having checked nothing.
  local function nothing_was_checked()
    if not shared.free_stopped then
      return nil
    end
    return {
      "  No vulnerability lookups were made: " .. shared.free_stopped .. ".",
      "  Nothing on this scan was checked - this is not a",
      "  report that the software is free of known problems.",
    }
  end

  -- Reported before the mode is even looked at. Every path that stops the
  -- spending also drops the mode to free or sets billing_off, so reporting the
  -- spend inside the keyed branch suppressed the number at exactly the moment
  -- the user most needed it: the scan that hit a ceiling or ran the wallet down.
  if shared.spent > 0 then
    local lines = {}
    for _, line in ipairs(nothing_was_checked() or {}) do
      lines[#lines + 1] = line
    end
    local balance = shared.balance and string.format(", %d remaining", shared.balance) or ""
    lines[#lines + 1] = string.format("%d credit%s spent%s",
      shared.spent, shared.spent == 1 and "" or "s", balance)
    if shared.billing_stopped then
      lines[#lines + 1] = "  Identification stopped: " .. shared.billing_stopped ..
        ". Everything else ran normally."
    end
    if shared.degraded then
      lines[#lines + 1] = "  " .. shared.degraded .. "."
    end
    return nil, with_notes(" " .. table.concat(lines, "\n"))
  end

  if shared.mode == "keyed" then
    local warning = nothing_was_checked()
    if warning then
      return nil, with_notes("\n" .. table.concat(warning, "\n"))
    end
    -- Silence is the right output for a script with nothing to report, and CPE
    -- lookups cost nothing, so the common keyed scan says nothing at all -
    -- unless the catalogue is missing, which is never silent.
    if shared.catalog_note or shared.sweep_note then
      return nil, with_notes(nil)
    end
    return nil
  end

  local lines = {""}
  for _, line in ipairs(nothing_was_checked() or {}) do
    lines[#lines + 1] = line
  end
  if shared.free_stopped then
    lines[#lines + 1] = ""
  end
  if shared.degraded then
    lines[#lines + 1] = "  Ran without a usable API key: " .. shared.degraded .. "."
  else
    lines[#lines + 1] = "  Ran without an API key."
  end
  -- Deliberately unspecific about which fields a key adds: what comes back
  -- depends on the licence behind it, and a notice promising EPSS to somebody
  -- whose licence withholds it would have lied.
  lines[#lines + 1] = "  A key adds more detail per finding - exploitation status, titles"
  lines[#lines + 1] = "  and dates - and can identify software this scan could not name"
  if shared.unnamed > 0 then
    lines[#lines + 1] = string.format(
      "  (%d service%s here showed a banner that produced no usable identity).",
      shared.unnamed, shared.unnamed == 1 and "" or "s")
  else
    lines[#lines + 1] = "  from its raw banner alone."
  end
  lines[#lines + 1] = "  Get a free key at https://vulners.com/userinfo"
  lines[#lines + 1] = "  (register first at https://vulners.com/), then either:"
  lines[#lines + 1] = "    * put it in ~/.nmap/vulners.key   - picked up automatically"
  lines[#lines + 1] = "    * or set VULNERS_API_KEY in the environment"

  return nil, with_notes(table.concat(lines, "\n"))
end

--- Load the catalogue, once, before any host is touched.
--
-- The prerule exists for exactly this. It is the only phase that runs once per
-- scan rather than once per open port, so the dictionaries are fetched a single
-- time however many ports answer - and no two ports can race each other into
-- the same download.
--
-- It reports nothing. A catalogue that could not be loaded is a fact about the
-- whole scan, so it is said once at the end, next to the other scan-wide
-- notices, rather than at the top where it would scroll away.
local function pre_action()
  load_catalog()
  return nil
end

local actions = {prerule = pre_action, portrule = port_action, postrule = post_action}

-- SCRIPT_TYPE is read inside action() and never at file scope: it is undeclared
-- in the load-time environment, where a top-level read kills the whole script
-- engine rather than just this script.

prerule = function() return true end
postrule = function() return true end

action = function(...)
  return actions[SCRIPT_TYPE](...)
end

-- The one deliberate export: the seam the tests drive, and nothing else.
-- nse_main.lua hard-requires only action, categories and dependencies, so this
-- costs nothing at scan time.
--
-- Kept honest by deletion. Sixteen names were exported that no test reached,
-- which reads as a tested seam and is not one - and four of them named the very
-- functions a reader would assume were covered. Anything reachable only through
-- a full action() call belongs here the day a case calls it, not before.
_TEST = {
  config = config,
  decode_service_fp = decode_service_fp,
  enrich = enrich,
  catalog = catalog,
  load_catalog = load_catalog,
  read_fingerprints = read_fingerprints,
  read_paths = read_paths,
  read_probes = read_probes,
  match_subjects = match_subjects,
  subjects_of = subjects_of,
  detect_probes = detect_probes,
  version_of = version_of,
  fingerprint_banner = fingerprint_banner,
  service_fp_payloads = service_fp_payloads,
  render_rows = render_rows,
  severity_of = severity_of,
  state = state,
}
