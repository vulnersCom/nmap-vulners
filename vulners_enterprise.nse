description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

All the CPEs of a port are audited in a single request, and every answer is
cached for the whole scan, so scanning a network does not re-ask the API about
software it has already seen.

NB:
Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db.
So we do make requests to a remote service. Still all the requests contain just two fields - the
software name and its version (or CPE), so one can still have the desired privacy.

NB2:
This script requires a valid API token. You can either specify it on the CLI using the 'api_key' script argument,
set it into an envirotnment variable VULNERS_API_KEY, or store it in a file readable by the user running nmap.
In this case you must specify the absolute path to the file using the 'api_key_file' script argument.
]]

---
-- @usage
-- nmap -sV --script vulners_enterprise [--script-args mincvss=<arg_val>,api_key=<api_key>,api_key_file=<absolute_path>,api_host=<host_name>,api_port=<port>] <target>
--
-- @args vulners_enterprise.mincvss Limit CVEs shown to those with this CVSS score or
--       greater. Bulletins the API does not score, and entries with a known
--       exploit, are reported whatever the threshold.
-- @args vulners_enterprise.api_key API token to be used in the requests
-- @args vulners_enterprise.api_key_file Absolute path to the file with a single line containing the API token
-- @args vulners_enterprise.api_host domain name to vulners API. Defaults to vulners.com
-- @args vulners_enterprise.api_port port number on the api_host. Defaults to 443
--
-- @output
--
-- 22/tcp open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
-- | vulners_enterprise:
-- |   cpe:/a:openbsd:openssh:7.4:
-- |            F0979183-AE88-53B4-86CF-3AF0523F3807    cvss3.1: 9.8    https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807  *HAS EXPLOIT*
-- |            CVE-2023-38408  cvss3.1: 9.8    https://vulners.com/cve/CVE-2023-38408
-- |            B8190CDB-3EB9-5631-9828-8064A1575B23    cvss3.1: 9.8    https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  *HAS EXPLOIT*
-- |            8FC9C5AB-3968-5F3C-825E-E8DB5379A623    cvss3.1: 9.8    https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623  *HAS EXPLOIT*
-- |            8AD01159-548E-546E-AA87-2DE89F3927EC    cvss3.1: 9.8    https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC  *HAS EXPLOIT*
-- |            5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    cvss3.1: 9.8    https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A  *HAS EXPLOIT*
-- |            2227729D-6700-5C8F-8930-1EEAFD4B9FF0    cvss3.1: 9.8    https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0  *HAS EXPLOIT*
-- |            0221525F-07F5-5790-912D-F4B9E2D1B587    cvss3.1: 9.8    https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587  *HAS EXPLOIT*
-- |            54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    cvss3.1: 5.9    https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C  *HAS EXPLOIT*
-- |            EDB-ID:45939    cvss3.1: 5.3    https://vulners.com/exploitdb/EDB-ID:45939      *HAS EXPLOIT*
-- |            EDB-ID:45233    cvss3.1: 5.3    https://vulners.com/exploitdb/EDB-ID:45233      *HAS EXPLOIT*
-- |            CVE-2018-20685  cvss3.1: 5.3    https://vulners.com/cve/CVE-2018-20685
-- |            CVE-2018-15919  cvss3.0: 5.3    https://vulners.com/cve/CVE-2018-15919
-- |            CVE-2018-15473  cvss3.1: 5.3    https://vulners.com/cve/CVE-2018-15473
-- |            CVE-2017-15906  cvss3.1: 5.3    https://vulners.com/cve/CVE-2017-15906
-- |            CVE-2016-20012  cvss3.1: 5.3    https://vulners.com/cve/CVE-2016-20012
-- |            CVE-2025-32728  cvss3.1: 4.3    https://vulners.com/cve/CVE-2025-32728
-- |_           CVE-2021-36368  cvss3.1: 3.7    https://vulners.com/cve/CVE-2021-36368
--
-- @xmloutput
-- <table key="cpe:/a:openbsd:openssh:7.4">
-- <table>
--   <elem key="cvss">9.8</elem>
--   <elem key="id">F0979183-AE88-53B4-86CF-3AF0523F3807</elem>
--   <elem key="type">githubexploit</elem>
--   <elem key="is_exploit">true</elem>
--   <elem key="cvss_type">cvss3.1</elem>
-- </table>
-- <table>
--   <elem key="id">CVE-2023-38408</elem>
--   <elem key="type">cve</elem>
--   <elem key="cvss">9.8</elem>
--   <elem key="cvss_type">cvss3.1</elem>
-- </table>
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
local os = require "os"

local api_version = "1.14"

-- The id endpoint accepts at most 100 ids per call.
local ID_CHUNK_SIZE = 100

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

local EXPLOIT_TYPES = {
  exploitdb = true,
  githubexploit = true,
  metasploit = true,
  packetstorm = true,
}

local mincvss = stdnse.get_script_args(SCRIPT_NAME .. ".mincvss")
mincvss = tonumber(mincvss) or 0.0

local api_key_file = stdnse.get_script_args(SCRIPT_NAME .. ".api_key_file")
api_key_file = api_key_file or ""

local api_host = stdnse.get_script_args(SCRIPT_NAME .. ".api_host")
api_host = api_host or 'vulners.com'

local api_port = stdnse.get_script_args(SCRIPT_NAME .. ".api_port")
-- Script arguments always arrive as strings; http.post() needs a number and
-- raises otherwise, so an explicit api_port used to abort the whole script.
api_port = tonumber(api_port) or 443

local api_key = stdnse.get_script_args(SCRIPT_NAME .. ".api_key")
api_key = api_key or os.getenv("VULNERS_API_KEY")

portrule = function(host, port)
  local vers = port.version
  local found = host.registry.vulners_cpe or {}
  return vers ~= nil and vers.version ~= nil or (found[port.number] ~= nil)
end

local cve_meta = {
  __tostring = function(me)
      -- An unscored bulletin gets no score column rather than an empty one.
      local score = me.cvss and ("\t%s: %s"):format(me.cvss_type or "cvss", me.cvss) or ""
      return ("\t%s%s\thttps://vulners.com/%s/%s%s"):format(me.id, score, me.type, me.id, me.is_exploit and '\t*HAS EXPLOIT*' or '')
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
  local state = nmap.registry.vulners_enterprise
  if not state then
    state = {cache = {}, pending = {}, failed = false}
    nmap.registry.vulners_enterprise = state
  end
  return state
end


---
-- Return a string read from api_key_file to be used as an API_KEY
--
local function read_api_key_file()

  stdnse.debug1("api_key not specified. Trying to read api_key_file.")

  if api_key_file == nil or api_key_file == "" then
    stdnse.debug1("No api_key_file set")
    return ""
  end

  local file = io.open(api_key_file, "r")
  if file == nil then
    stdnse.debug1("Failed to open api_key_file %s", api_key_file)
    return ""
  end

  local key = file:read("*line")

  file:close()

  if key == nil then
    return ""
  end

  -- A file written on Windows leaves a carriage return on the key, which the
  -- service answers with 401 - and a 401 silences the script for the whole
  -- scan, with nothing to say why.
  key = key:match("^%s*(.-)%s*$")

  if key:find("%c") then
    stdnse.debug1("The api_key_file contains a control character; ignoring it.")
    return ""
  end

  return key
end


---
-- Issues the requests, encapsulates logic of re-attempting when unsuccessfull initially.
--
-- Transport failures, 429 and 5xx are retried, honouring a Retry-After header
-- when the server sends one. Any other status is final.
--
-- @param api_endpoint URL path, where to call
-- @param postbody json stringified body
-- @return the response table, or nil when the request could not be completed
--
local function make_http_request(api_endpoint, postbody)
  local state = scan_state()
  if state.failed then
    stdnse.debug1("Skipping request, the API was already unreachable in this scan.")
    return
  end

  local option = {
    header = {
      ['User-Agent'] = string.format('Vulners NMAP Enterprise %s', api_version),
      ['Accept-Encoding'] = ACCEPT_ENCODING,
      ['Content-Type'] = "application/json",
      ['X-Api-Key'] = api_key
    },
    any_af = true,
  }

  stdnse.debug1("Trying to send data to: %s with a body of %d bytes", api_endpoint, #postbody)
  stdnse.debug2("Request body: %s", postbody)

  local attempt = 1
  while attempt <= MAX_ATTEMPTS do
    stdnse.debug1("Attempt %d to contact vulners.", attempt)
    local response = http.post(api_host, api_port, api_endpoint, option, nil, postbody)
    local status = response.status

    if status == 200 then
      return response
    end

    if status ~= nil and status ~= 429 and status < 500 then
      -- 4xx: a bad key or a malformed request will not fix itself.
      if status == 401 or status == 403 then
        -- The key is the same for every host, so stop asking altogether.
        state.failed = true
        stdnse.debug1("Vulners rejected the API key (%d), stopping for this scan.", status)
      else
        stdnse.debug1("Response from vulners is not 200 but %d, giving up.", status)
      end
      return
    end

    if attempt == MAX_ATTEMPTS then
      if status == nil then
        -- Nothing answered at all: the rest of the scan should not keep trying.
        state.failed = true
        stdnse.debug1("Failed to contact vulners server in %d attempts.", MAX_ATTEMPTS)
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
-- Parse a response body.
--
-- The two API generations disagree on the envelope: the v4 audit answers with
-- result as a list, while the v3 id endpoint answers with result "OK" and the
-- payload under data. Business errors arrive inside an HTTP 200 as
-- {"result":"error","data":{...}}, so the caller checks the shape it expects.
--
-- @param response the http response table
-- @return the parsed body, or nil
--
local function parse_body(response)
  if response == nil then
    return
  end

  local status, body = json.parse(response.body)
  if not status or type(body) ~= "table" then
    stdnse.debug1("Unable to parse json response.")
    stdnse.debug2("%s", response.body)
    return
  end

  return body
end


---
-- Turn one API vulnerability record into the rows the user sees.
--
-- A record yields its own row plus one row per referenced exploit, so software
-- that is known to be exploitable is visible as such.
--
-- @param record a vulnerability or document table from the API
-- @param output the list rows are appended to
--
local function collect_rows(record, output, seen)
  seen = seen or {}

  -- Everything below indexes fields of an answer this script did not build.
  -- A record that is not a table, or one without an id, would otherwise raise
  -- and take the whole port's results with it.
  if type(record) ~= "table" or type(record.id) ~= "string" then
    return
  end

  local metrics = type(record.metrics) == "table" and record.metrics or {}
  -- The v4 audit nests the score under metrics; the v3 id endpoint keeps it at
  -- the top level.
  local cvss = metrics.cvss or record.cvss
  local score, cvss_type

  -- Not every bulletin is scored, and a scored one may carry no version.
  if type(cvss) == "table" and cvss.version ~= "NONE" then
    score = tonumber(cvss.score)
    if cvss.version then
      cvss_type = "cvss" .. cvss.version
    end
  end

  local enchantments = type(record.enchantments) == "table" and record.enchantments or {}
  local dependencies = type(enchantments.dependencies) == "table" and enchantments.dependencies or {}
  local references = type(dependencies.references) == "table" and dependencies.references or {}

  for _, ref in ipairs(references) do
    if type(ref) == "table" and EXPLOIT_TYPES[ref.type] then
      local id_list = type(ref.idList) == "table" and ref.idList or {}
      for _, exploit_id in ipairs(id_list) do
        -- Several vulnerabilities of the same software often point at one
        -- exploit; it is worth listing once.
        if not seen[exploit_id] then
          seen[exploit_id] = true
          -- An available exploit outweighs the score threshold.
          output[#output + 1] = setmetatable({
            id = exploit_id,
            type = ref.type,
            is_exploit = true,
            cvss = score,
            cvss_type = cvss_type,
          }, cve_meta)
        end
      end
    end
  end

  if (not score or mincvss <= score) and not seen[record.id] then
    seen[record.id] = true
    output[#output + 1] = setmetatable({
      id = record.id,
      type = record.type,
      cvss = score,
      cvss_type = cvss_type,
    }, cve_meta)
  end
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
-- Resolve bare vulnerability ids into scored documents.
--
-- Needed only for the smart endpoint: the software audit already answers with
-- metrics and enchantments, while smart returns ids with no scores attached.
--
-- @param ids list of vulnerability ids
-- @return list of rows
--
local function resolve_ids(ids)
  local output = {}
  local seen = {}

  for first = 1, #ids, ID_CHUNK_SIZE do
    local chunk = {}
    for i = first, math.min(first + ID_CHUNK_SIZE - 1, #ids) do
      chunk[#chunk + 1] = ids[i]
    end

    stdnse.debug1("Resolving %d ids", #chunk)

    local postbody = json.generate({
      id = chunk,
      fields = {'type', 'cvss', 'enchantments'},
    })

    local body = parse_body(make_http_request("/api/v3/search/id/", postbody))
    local documents = body and body.data and body.data.documents

    if type(documents) == "table" then
      for _, document in pairs(documents) do
        collect_rows(document, output, seen)
      end
    else
      -- One failed chunk should not discard the others.
      stdnse.debug1("Could not resolve a chunk of ids.")
    end
  end

  return output
end


---
-- Key an audited item the same way the response echoes it back.
--
local function audit_key(input)
  if type(input) == "table" then
    -- The update part has to be in the key: nmap reports both "7.4" and
    -- "7.4p1", and dropping it made one answer stand for both.
    return string.format("%s:%s:%s:%s:%s", input.part or "", input.vendor or "",
      input.product or "", input.version or "", input.update or "")
  end
  return tostring(input)
end


---
-- Audit a batch of software items in a single request.
--
-- @param items list of CPE tables (cpe lookup) or strings (smart lookup)
-- @param lookup_type either "cpe" or "software"
-- @return map from the item key to its list of rows, or nil when the request
--         itself failed - a failure must not be remembered as "nothing found"
--
local function audit(items, lookup_type)
  local answers = {}

  if #items == 0 then
    return answers
  end

  local api_endpoint
  if lookup_type == "cpe" then
    api_endpoint = "/api/v4/audit/software/"
  elseif lookup_type == "software" then
    api_endpoint = "/api/v4/audit/smart"
  else
    stdnse.debug1("Unexpected request type %s.", tostring(lookup_type))
    return
  end

  local postbody = json.generate({
    software = items,
    fields = {'type', 'metrics', 'enchantments'},
  })

  local body = parse_body(make_http_request(api_endpoint, postbody))
  local result = body and body.result

  if type(result) ~= "table" then
    stdnse.debug1("Response from vulners carries no usable result.")
    return
  end

  for _, entry in ipairs(result) do
    local vulns = type(entry) == "table" and entry.vulnerabilities or nil

    if type(vulns) == "table" and #vulns > 0 then
      local rows

      if lookup_type == "cpe" then
        -- The software audit already carries scores and exploit references.
        rows = {}
        local seen = {}
        for _, record in ipairs(vulns) do
          collect_rows(record, rows, seen)
        end
      else
        -- The smart endpoint answers with ids only, so they need resolving.
        local ids = {}
        for _, record in ipairs(vulns) do
          ids[#ids + 1] = record.id
        end
        rows = resolve_ids(ids)
      end

      if #rows > 0 then
        -- The API does not answer in request order, so an entry is matched back
        -- by the input it echoes.
        answers[audit_key(entry.input)] = sort_rows(rows)
      end
    end
  end

  return answers
end


---
-- Split a CPE into the fields the audit endpoint expects.
--
-- @param cpe string, for example cpe:/a:openbsd:openssh:7.4
-- @return table with part, vendor, product, version, update - or nil
--
local function parse_cpe(cpe)
  local cpe_regexp = "^cpe:/(%l):([^:]+):([^:]+):([%d%.%-%_]+)([^:]*)$"
  local _, _, part, vendor, product, vers, update = cpe:find(cpe_regexp)

  if not vers then
    return
  end

  stdnse.debug1("Got cpe %s with part %s vendor %s product %s version %s and update %s",
    cpe, part, vendor, product, vers, (update ~= "" and update) or "nil")

  return {
    ['part'] = part,
    ['vendor'] = vendor,
    ['product'] = product,
    ['version'] = vers,
    ['update'] = update,
  }
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
-- The lists merged here answer two spellings of one product, so they can carry
-- the same bulletin twice; an id already present is dropped instead of being
-- reported again.
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
-- Audit everything in <code>wanted</code> that this scan has no answer for.
--
-- Items another host is asking about right now are waited for rather than
-- asked again, so a network of identical servers costs one request instead of
-- one per host.
--
-- @param state the scan-wide state table
-- @param wanted list of {key = cache key, item = software item}
--
local function audit_missing(state, wanted)
  local batch, owned, queued = {}, {}, {}
  local pending_keys = {}

  for _, want in ipairs(wanted) do
    if state.cache[want.key] == nil and not queued[want.key] then
      queued[want.key] = true
      if state.pending[want.key] then
        pending_keys[#pending_keys + 1] = want.key
      else
        state.pending[want.key] = true
        owned[#owned + 1] = want.key
        batch[#batch + 1] = want.item
      end
    end
  end

  if #batch > 0 then
    stdnse.debug1("Auditing %d software items in one request", #batch)
    local answers = audit(batch, "cpe")

    for _, key in ipairs(owned) do
      state.pending[key] = nil
      -- Only an answer is remembered. A rate limit or a 5xx that exhausted the
      -- retries leaves the cache empty, so the next host asks again rather
      -- than inheriting a silent "no vulnerabilities" for the whole scan.
      if answers then
        state.cache[key] = answers[key] or false
      end
    end
  end

  for _, key in ipairs(pending_keys) do
    wait_for_pending(state, key)
  end
end


action = function(host, port)
  local tab = stdnse.output_table()
  local changed = false
  -- portrule also lets ports through that have no version data at all, as long
  -- as http-vulners-regex left CPEs for this host in the registry.
  local version = port.version or {}

  api_key = api_key or read_api_key_file()

  if api_key == nil or api_key == "" then
    stdnse.debug1("Api key is not set in either arg, ENV or file. Exiting.")
    return
  end

  stdnse.debug1("Api file is set to %s", api_key_file)
  stdnse.debug1("Host is set to %s", api_host)
  stdnse.debug1("Port is set to %d", api_port)
  -- Never log the key itself: nmap -d output ends up in bug reports and in
  -- shared scan logs.
  stdnse.debug1("Api key is set (%d characters)", #api_key)

  local state = scan_state()

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

  -- Everything this port wants to know about, in one list; what is not
  -- already answered becomes a single batched request below.
  local wanted = {}

  for _, cpe in ipairs(cpe_list) do
    local alternates = nginx_variants(cpe) or {cpe}

    for _, alternate in ipairs(alternates) do
      local item = parse_cpe(alternate)
      if item then
        wanted[#wanted + 1] = {cpe = cpe, key = audit_key(item), item = item}
      end
    end
  end

  -- Twice: the second pass asks for whatever the lookup we waited on did not
  -- answer, instead of reporting a host as clean because someone else's
  -- request failed.
  audit_missing(state, wanted)
  audit_missing(state, wanted)

  for _, want in ipairs(wanted) do
    local rows = state.cache[want.key]
    if rows then
      tab[want.cpe] = merge_rows(tab[want.cpe], rows)
      changed = true
    end
  end

  -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
  -- nmap may report a version without a product name; there is nothing to ask
  -- the software endpoint about in that case.
  if not changed and version.product and version.version then
    local vendor_version = version.product .. " " .. version.version
    local rows = state.cache[vendor_version]

    if rows == nil then
      local answers = audit({vendor_version}, "software")
      if answers then
        rows = answers[vendor_version] or false
        state.cache[vendor_version] = rows
      end
    end

    if rows then
      tab[vendor_version] = rows
      changed = true
    end
  end

  if (not changed) then
    return
  end

  return tab
end
