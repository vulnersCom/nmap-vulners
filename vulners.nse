description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

Every answer is cached for the whole scan, so scanning a network does not
re-ask the API about software it has already seen.

NB:
Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db.
So we do make requests to a remote service. Still all the requests contain just two fields - the
software name and its version (or CPE), so one can still have the desired privacy.
]]

---
-- @usage
-- nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>
--
-- @args vulners.mincvss Limit CVEs shown to those with this CVSS score or
--       greater. Bulletins the API does not score, and entries with a known
--       exploit, are reported whatever the threshold.
-- @args vulners.api_host domain name of the vulners API. Defaults to vulners.com
-- @args vulners.api_port port number on the api_host. Defaults to 443
--
-- @output
--
-- 53/tcp   open     domain             ISC BIND DNS
-- | vulners:
-- |   ISC BIND DNS:
-- |     CVE-2012-1667    cvss2.0: 8.5    https://vulners.com/cve/CVE-2012-1667
-- |     CVE-2002-0651    cvss2.0: 7.5    https://vulners.com/cve/CVE-2002-0651
-- |     CVE-2002-0029    cvss2.0: 7.5    https://vulners.com/cve/CVE-2002-0029
-- |     CVE-2015-5986    cvss2.0: 7.1    https://vulners.com/cve/CVE-2015-5986
-- |     CVE-2010-3615    cvss2.0: 5.0    https://vulners.com/cve/CVE-2010-3615
-- |     CVE-2006-0987    cvss2.0: 5.0    https://vulners.com/cve/CVE-2006-0987
-- |_    CVE-2014-3214    cvss2.0: 5.0    https://vulners.com/cve/CVE-2014-3214
--
-- @xmloutput
-- <table key="cpe:/a:isc:bind:9.8.2rc1">
--   <table>
--     <elem key="is_exploit">false</elem>
--     <elem key="cvss">8.5</elem>
--     <elem key="cvss_type">cvss2.0</elem>
--     <elem key="id">CVE-2012-1667</elem>
--     <elem key="type">cve</elem>
--   </table>
--   <table>
--     <elem key="is_exploit">false</elem>
--     <elem key="cvss">7.8</elem>
--     <elem key="cvss_type">cvss3.1</elem>
--     <elem key="id">CVE-2015-4620</elem>
--     <elem key="type">cve</elem>
--   </table>
-- </table>

dependencies = {"http-vulners-regex"}
author = "Vulners Team (info@vulners.com)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external", "default"}


local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"

local api_version = "1.9"

local API_PATH = "/api/v3/burp/software/"

-- Retry budget for a single request. Only transport failures, 429 and 5xx are
-- worth repeating; a 4xx answers the same way however often it is asked.
-- nmap decompresses a gzip body only when it was built with zlib; nselib/http.lua
-- checks the same way. Asking for gzip on a build without it would leave the
-- answer compressed and unparsable, so the header is set only when it can be
-- honoured. It is worth asking for: the API answers are 8-12 times smaller
-- compressed (115 KB -> 9 KB for one Apache lookup, measured against the live
-- endpoint).
local ACCEPT_ENCODING = pcall(require, "zlib") and "gzip, deflate" or nil

local MAX_ATTEMPTS = 3
-- How long a host waits for a lookup another host already started.
local PENDING_WAIT_STEP = 0.2
local PENDING_WAIT_LIMIT = 30
local RETRY_AFTER_CAP = 60

local mincvss = stdnse.get_script_args(SCRIPT_NAME .. ".mincvss", "vulners.mincvss")
mincvss = tonumber(mincvss) or 0.0

local api_host = stdnse.get_script_args(SCRIPT_NAME .. ".api_host")
api_host = api_host or 'vulners.com'

local api_port = stdnse.get_script_args(SCRIPT_NAME .. ".api_port")
-- Script arguments always arrive as strings, while http needs a number.
api_port = tonumber(api_port) or 443

portrule = function(host, port)
  local vers = port.version
  local found = host.registry.vulners_cpe or {}
  return vers ~= nil and vers.version ~= nil or (found[port.number] ~= nil)
end

local cve_meta = {
  __tostring = function(me)
      -- An unscored bulletin gets no score column rather than an empty one.
      local score = me.cvss and ("\t%s: %s"):format(me.cvss_type or "cvss", me.cvss) or ""
      return ("\t%s%s\thttps://vulners.com/%s/%s%s"):format(me.id, score, me.type, me.id, me.is_exploit and '\t*EXPLOIT*' or '')
  end,
}


---
-- Scan-wide state, shared through the nmap registry.
--
-- The same software turns up on many hosts of a network, so an answer is worth
-- keeping for the whole scan. <code>failed</code> stops the script from
-- hammering an API that has already proven unreachable.
--
local function scan_state()
  local state = nmap.registry.vulners
  if not state then
    state = {cache = {}, pending = {}, failed = false}
    nmap.registry.vulners = state
  end
  return state
end


---
-- Sort rows by CVSS, highest first.
--
-- Unscored entries sort last: comparing nil raises, and dropping them would
-- silently hide bulletins the API did report.
--
local function sort_rows(rows)
  local function score(row)
    return row.cvss or -1
  end

  table.sort(rows, function(a, b)
      return score(a) > score(b) or (score(a) == score(b) and a.id > b.id)
    end)

  return rows
end


---
-- Return a string with all the found cve's and correspondent links
--
-- @param vulns a table with the parsed json response from the vulners server
--
local function make_links(vulns)
  local output = {}
  local seen = {}

  if not vulns or not vulns.data or not vulns.data.search then
    return
  end

  for _, vuln in ipairs(vulns.data.search) do
    -- The answer is somebody else's data structure; an entry that is not a
    -- table, or a bulletin with no id, must be skipped rather than crash the
    -- port's whole result.
    local source = type(vuln) == "table" and type(vuln._source) == "table"
      and vuln._source or {}
    local cvss = source.cvss
    local score, cvss_type

    -- Not every bulletin is scored, and a scored one may carry no version.
    if type(cvss) == "table" and cvss.version ~= "NONE" then
      score = tonumber(cvss.score)
      if cvss.version then
        cvss_type = "cvss" .. cvss.version
      end
    end

    local family = source.bulletinFamily
    local v = {
      id = source.id,
      type = source.type,
      -- Mark the exploits out
      is_exploit = type(family) == "string" and family:lower() == "exploit",
      cvss = score,
      cvss_type = cvss_type,
    }

    -- NOTE[gmedian]: exploits seem to have cvss == 0, so print them anyway
    if type(v.id) == "string" and not seen[v.id]
       and (not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss) then
      seen[v.id] = true
      setmetatable(v, cve_meta)
      output[#output + 1] = v
    end
  end

  if #output > 0 then
    return sort_rows(output)
  end
end


---
-- Build the query string for the burp endpoint.
--
-- The value is sent the way the version of this script that ships with nmap
-- has always sent it: verbatim, apart from the characters that would change
-- the meaning of the request itself. ':' and '/' are legal in a query string
-- (RFC 3986 section 3.4), and keeping them unescaped means the lookup does not
-- depend on the endpoint decoding anything - which mattered on 2026-08-18,
-- when escaped values were answered with errorCode 303 for a few hours while
-- the raw form kept working.
--
-- @param value string to place in the query
-- @return the value, safe to concatenate into a query string
--
local function escape_value(value)
  -- '+' is escaped with the rest: the endpoint reads it as a space, so a
  -- version like 1.0+deb8u1 would otherwise arrive as "1.0 deb8u1".
  local escaped = tostring(value):gsub("[^!$'()*,%-./0-9:;@A-Z_a-z~]", function(char)
    return ("%%%02X"):format(char:byte())
  end)
  return escaped
end


---
-- @param query table of query arguments
-- @return the query string, arguments always in the same order
--
local function build_query(query)
  local parts = {}
  for _, name in ipairs({"software", "version", "type"}) do
    if query[name] ~= nil then
      parts[#parts + 1] = ("%s=%s"):format(name, escape_value(query[name]))
    end
  end
  return table.concat(parts, "&")
end


---
-- Issue one request, retrying when it is worth retrying.
--
-- @param query table of query arguments
-- @return the response table, or nil when the request could not be completed
--
local function make_http_request(query)
  local state = scan_state()
  if state.failed then
    stdnse.debug1("Skipping request, the API was already unreachable in this scan.")
    return
  end

  local path = ("%s?%s"):format(API_PATH, build_query(query))
  local option = {
    header = {
      ['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version),
      ['Accept-Encoding'] = ACCEPT_ENCODING,
    },
    any_af = true,
  }

  local attempt = 1
  while attempt <= MAX_ATTEMPTS do
    stdnse.debug1("Attempt %d to contact vulners.", attempt)
    local response = http.get(api_host, api_port, path, option)
    local status = response.status

    if status == 200 then
      return response
    end

    if status ~= nil and status ~= 429 and status < 500 then
      stdnse.debug1("Response from vulners is not 200 but %d, giving up.", status)
      return
    end

    if attempt == MAX_ATTEMPTS then
      if status == nil then
        -- Nothing answered at all: the rest of the scan should not keep trying.
        state.failed = true
        stdnse.debug1("Failed to contact vulners in %d attempts.", MAX_ATTEMPTS)
      elseif status == 429 then
        -- The budget is exhausted and the service is still refusing. Sleeping
        -- another minute per CPE would stall the scan without producing
        -- anything, so the rest of it stops asking.
        state.failed = true
        stdnse.debug1("Vulners is rate limiting this scan; stopping requests.")
      else
        stdnse.debug1("Vulners kept answering %d, giving up.", status)
      end
      return
    end

    local delay = attempt
    if status ~= nil then
      local retry_after = tonumber(response.header and response.header["retry-after"])
      if retry_after then
        -- A header of "-1" would otherwise reach stdnse.sleep, which raises.
        delay = math.max(0, math.min(retry_after, RETRY_AFTER_CAP))
      end
      stdnse.debug1("Response from vulners is %d, retrying in %ss.", status, delay)
    end
    stdnse.sleep(delay)
    attempt = attempt + 1
  end
end


---
-- Issues the requests, receives json and parses it, calls <code>make_links</code> when successfull
--
-- @param what string, future value for the software query argument
-- @param vers string, the version query argument
-- @param lookup_type string, the type query argument
--
local function get_results(what, vers, lookup_type)
  stdnse.debug1("Trying to get vulns of %s for type %s", what, lookup_type)

  local response = make_http_request({
    software = what,
    version = vers,
    type = lookup_type,
  })

  if response == nil then
    -- According to the NSE way we will die silently rather than spam user with error messages
    return nil, false
  end

  local status, vulns = json.parse(response.body)

  if not status or type(vulns) ~= "table" then
    stdnse.debug1("Unable to parse json.")
    stdnse.debug2("%s", response.body)
    return nil, false
  end

  if vulns.result ~= "OK" then
    stdnse.debug1("Response from vulners is not OK.")
    stdnse.debug2("%s", response.body)
    return nil, false
  end

  stdnse.debug1("Response from vulners is OK.")
  return make_links(vulns), true
end


---
-- Calls <code>get_results</code> for type="software"
--
-- It is called from <code>action</code> when nothing is found for the available cpe's
--
-- @param software string, the software name
-- @param version string, the software version
--
local function get_vulns_by_software(software, version)
  return get_results(software, version, "software")
end


---
-- Calls <code>get_results</code> for type="cpe"
--
-- Takes the version number from the given <code>cpe</code> and tries to get the result.
-- If none found, changes the given <code>cpe</code> a bit in order to possibly separate version number from the patch version
-- And makes another attempt.
-- Having failed returns an empty string.
--
-- @param cpe string, the given cpe
--
local function get_vulns_by_cpe(cpe)
  local vers_regexp = ":([%d%.%-%_]+)([^:]*)$"

  -- TODO[gmedian]: add check for cpe:/a  as we might be interested in software rather than in OS (cpe:/o) and hardware (cpe:/h)
  -- TODO[gmedian]: work not with the LAST part but simply with the THIRD one (according to cpe doc it must be version)

  -- NOTE[gmedian]: take only the numeric part of the version
  local _, _, vers, patch = cpe:find(vers_regexp)

  if not vers then
    return
  end

  stdnse.debug1("Got cpe %s with version %s and patch %s", cpe, vers, patch or "nil")

  local output, answered = get_results(cpe, vers, "cpe")

  if not output and patch and patch ~= "" then
    -- Maybe the version and its patch level need separating.
    local new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
    stdnse.debug1("Forming new cpe for another attempt %s", new_cpe)
    local retry, retry_answered = get_results(new_cpe, vers, "cpe")
    output = retry
    -- The lookup counts as answered only if nothing failed on the way: a
    -- failure must not be remembered as "this software is clean".
    answered = answered and retry_answered
  end

  return output, answered
end


---
-- Wait, briefly, for a lookup another host started.
--
-- nmap runs the port scripts of a host group concurrently, so a network of
-- identical servers would otherwise ask the API the same question once per
-- host before the first answer arrives. Waiting is bounded: if the owner of
-- the lookup dies or takes too long, the caller asks for itself rather than
-- hanging the scan.
--
-- @param state the scan-wide state table
-- @param key the cache key being waited for
--
local function wait_for_pending(state, key)
  local waited = 0

  while state.pending[key] and waited < PENDING_WAIT_LIMIT do
    stdnse.sleep(PENDING_WAIT_STEP)
    waited = waited + PENDING_WAIT_STEP
  end
end


---
-- Look a CPE up, reusing what this scan already asked about.
--
-- Only an answer is remembered. A rate limit or a 5xx that exhausted the
-- retries leaves the cache untouched, so the next host asks again instead of
-- inheriting a silent "no vulnerabilities" for the rest of the scan.
--
local function lookup_cpe(cpe)
  local state = scan_state()

  -- Two passes: wait for a lookup in flight, then ask for ourselves if that
  -- lookup produced no answer.
  for _ = 1, 2 do
    local cached = state.cache[cpe]
    if cached ~= nil then
      return cached or nil
    end

    if state.pending[cpe] then
      wait_for_pending(state, cpe)
    else
      state.pending[cpe] = true
      local rows, answered = get_vulns_by_cpe(cpe)
      state.pending[cpe] = nil

      if answered then
        state.cache[cpe] = rows or false
      end
      return rows
    end
  end

  return state.cache[cpe] or nil
end


-- nginx is published under three vendor spellings for one product. The service
-- answers them with very different amounts of data (measured on 1.13.4: f5 124
-- bulletins, nginx 4, igor_sysoev none), and nmap's own service fingerprint
-- emits the igor_sysoev one, so all three are asked and the answers merged.
local NGINX_SPELLINGS = {":f5:nginx", ":nginx:nginx", ":igor_sysoev:nginx"}


---
-- @param cpe string
-- @return the same CPE under every nginx spelling, or nil if it is not nginx
--
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


---
-- One key for a product that has three names, so it is reported once.
--
local function canonical_cpe(cpe)
  local variants = nginx_variants(cpe)
  return variants and variants[1] or cpe
end


---
-- Concatenate two result lists, keeping the CVSS order.
--
-- The two nginx vendor spellings describe one product and the API answers both
-- with largely the same bulletins, so the lists overlap; an id already present
-- is dropped instead of being reported twice.
--
local function merge_rows(left, right)
  if not left then return right end
  if not right then return left end

  local merged, seen = {}, {}
  for _, list in ipairs({left, right}) do
    for _, row in ipairs(list) do
      if row.id and not seen[row.id] then
        seen[row.id] = true
        merged[#merged + 1] = row
      end
    end
  end

  return sort_rows(merged)
end


action = function(host, port)
  local tab = stdnse.output_table()
  local changed = false
  -- portrule also lets ports through that have no version data at all, as long
  -- as http-vulners-regex left CPEs for this host in the registry.
  local version = port.version or {}

  -- Collect every CPE worth asking about, deduplicated: the registry and the
  -- port version table often carry the same entries.
  local cpe_list = {}
  local seen_cpe = {}

  local function add_cpe(cpe)
    if cpe == nil then
      return
    end
    local canonical = canonical_cpe(cpe)
    if seen_cpe[canonical] then
      return
    end
    seen_cpe[canonical] = true
    cpe_list[#cpe_list + 1] = cpe
  end

  for _, cpe in ipairs(version.cpe or {}) do
    add_cpe(cpe)
  end

  -- NOTE[gmedian]: check whether we have pre-matched CPEs in registry (from http-vulners-regex.nse in particular)
  local from_regex = (host.registry.vulners_cpe or {})[port.number]
  if from_regex ~= nil then
    for _, cpe in ipairs(from_regex) do
      add_cpe(cpe)
    end
  end

  for _, cpe in ipairs(cpe_list) do
    stdnse.debug1("Analyzing cpe %s", cpe)
    local output = lookup_cpe(cpe)

    for _, alternate in ipairs(nginx_variants(cpe) or {}) do
      if alternate ~= cpe then
        stdnse.debug1("Now going to analyze the other spelling %s", alternate)
        output = merge_rows(output, lookup_cpe(alternate))
      end
    end

    if output then
      tab[cpe] = output
      changed = true
    end
  end

  -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
  -- nmap may report a version without a product name; there is nothing to ask
  -- the software endpoint about in that case.
  if not changed and version.product and version.version then
    local vendor_version = version.product .. " " .. version.version
    local state = scan_state()
    local output = state.cache[vendor_version]

    if output == nil then
      local rows, answered = get_vulns_by_software(version.product, version.version)
      if answered then
        state.cache[vendor_version] = rows or false
      end
      output = rows
    else
      output = output or nil
    end
    if output then
      tab[vendor_version] = output
      changed = true
    end
  end

  if (not changed) then
    return
  end

  return tab
end
