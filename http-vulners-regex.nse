description = [[
Identifies the used software for each found http port and builds CPEs for the identified versions.

* Requests a list of paths from the open http port, "/" included, in one HTTP pipeline; a redirect is followed to the page it points at.
* Uses a local copy of Vulners regular expressions (defaults to http-vulners-regex.json) to identify software mentioned in the headers and on the pages of the HTTP service, and forms CPEs for the found entries
* Outputs the CPEs found on each page, and hands them to vulners.nse / vulners_enterprise.nse for the port they were found on

The path list defaults to http-vulners-paths.txt, which ships with over a
hundred entries. Use the paths argument to request fewer.
]]

---
-- @usage
-- nmap -sV --script http-vulners-regex.nse [--script-args paths={"/"}] <target>
--
-- @args http-vulners-regex.paths Specify paths to make requests to. Either a
--       list of strings, or one string naming a file with one path per line.
--       A file that cannot be read stops the script rather than falling back to
--       the shipped list.
--
-- @output
--
-- 80/tcp open  http    syn-ack Apache httpd 2.4.10
-- | http-vulners-regex:
-- |   /:
-- |     cpe:/a:f5:nginx:1.13.4
-- |_    cpe:/a:php:php:5.6.38
--
-- @xmloutput
--
-- <table key="/">
--   <elem>cpe:/a:f5:nginx:1.13.4</elem>
--   <elem>cpe:/a:php:php:5.6.38</elem>
-- </table>

author = "Vulners Team (info@vulners.com)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "default"}


local shortport = require "shortport"
local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local url = require "url"
local stdnse = require "stdnse"

---
-- Load the pattern file once per scan.
--
-- Parsing the pattern file is not free, and action() runs for every http port of
-- every host, so the result is kept in the nmap registry.
--
-- @return the pattern table, or nil when the file is unusable
--
-- nmap decompresses a gzip body only when it was built with zlib; asking for
-- it otherwise would leave every page compressed and unmatchable.
local ACCEPT_ENCODING = pcall(require, "zlib") and "gzip, deflate" or nil

-- How many times the whole sweep is re-queued for the paths still unanswered.
local MAX_FETCH_ROUNDS = 4
-- How many hops a redirected path is followed.
local MAX_REDIRECTS = 2


---
-- Request every path, keeping the ones a broken pipeline dropped.
--
-- http.pipeline_go returns responses in queue order and stops as soon as the
-- first request on a fresh connection fails (nselib/http.lua), so a single
-- path a tarpit or a WAF refuses costs every path queued behind it - and the
-- queue is sorted, which makes that deterministic rather than unlucky.
--
-- @return table, response by path index; missing entries were never answered
--
local function fetch_paths(host, port, paths)
  local options = {header = {['Accept-Encoding'] = ACCEPT_ENCODING}}
  local responses = {}
  local pending = {}

  for index = 1, #paths do
    pending[#pending + 1] = index
  end

  for _ = 1, MAX_FETCH_ROUNDS do
    if #pending == 0 then
      break
    end

    local requests
    for _, index in ipairs(pending) do
      stdnse.debug2("Queue path %s", paths[index])
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
      -- Nothing at all came back, and the library gives up on the request at
      -- the head of the queue, so that is the one being refused. The rest have
      -- not had their turn yet.
      stdnse.debug1("No response for %s, continuing without it", paths[left[1]])
      table.remove(left, 1)
    end

    pending = left
  end

  return responses
end


---
-- The path a redirect points at, when it stays on the host being scanned.
--
local function redirect_target(host, response)
  local location = response.header and response.header.location
  if not location then
    return
  end

  local parsed = url.parse(location)
  if not parsed then
    return
  end

  if parsed.host and parsed.host ~= host.targetname and parsed.host ~= host.ip then
    -- Somebody else's server is not ours to fingerprint.
    return
  end

  local path = parsed.path
  if not path or path == "" then
    return
  end

  return parsed.query and (path .. "?" .. parsed.query) or path
end


---
-- Fetch what the redirecting paths actually point at.
--
-- Without this the sweep only ever sees the 3xx envelope, and a site whose
-- paths redirect to its application - a front controller, a vhost redirect -
-- is fingerprinted from its Server header alone. Distinct targets are fetched
-- once, so a host that redirects everything to one page costs one request.
--
local function follow_redirects(host, port, paths, responses)
  local options = {header = {['Accept-Encoding'] = ACCEPT_ENCODING}}
  local fetched = {}

  for index, first in pairs(responses) do
    local response = first
    local hops = 0

    while response and response.status and response.status >= 300
        and response.status < 400 and hops < MAX_REDIRECTS do
      local target = redirect_target(host, response)
      if not target then
        break
      end

      if fetched[target] == nil then
        stdnse.debug2("Following %s to %s", paths[index], target)
        fetched[target] = http.get(host, port, target, options) or false
      end

      response = fetched[target] or nil
      responses[index] = response
      hops = hops + 1
    end
  end
end


local function load_patterns()
  if nmap.registry.vulners_regex_patterns ~= nil then
    return nmap.registry.vulners_regex_patterns or nil
  end

  local regex_filename = 'http-vulners-regex.json'
  local regex_filename_full = nmap.fetchfile('nselib/data/' .. regex_filename)
  if not regex_filename_full then
    stdnse.debug1("No file found at nselib/data/%s, using local copy", regex_filename)
    regex_filename_full = regex_filename
  end

  local file = io.open(regex_filename_full, "r")
  if file == nil then
    stdnse.debug1("Failed to open the json file")
    nmap.registry.vulners_regex_patterns = false
    return
  end

  local status, parsed = json.parse(file:read("*all"))
  file:close()

  -- json.parse signals failure with false, not nil, and returns the error
  -- message in place of the table.
  if not status or type(parsed) ~= "table" then
    stdnse.debug1("Unable to parse json from file read.")
    nmap.registry.vulners_regex_patterns = false
    return
  end

  nmap.registry.vulners_regex_patterns = parsed
  return parsed
end
local default_paths = {
        "/",
        "/index.html",
        "/index.php",
        "/wp-admin/login.php",
        "/about.html",
        "/about.php",
        "/500.html",
        "/theonethatdoesnotexist" -- cause why not
      }

portrule = shortport.http


---
-- Collects the CPEs mentioned in one piece of text.
--
-- @param patterns table, the parsed pattern file
-- @param field string, the header block or the response body
-- @param found table, list of CPEs found for the current path
-- @param seen  table, set of CPEs already recorded for the current host
--
function get_cpes(patterns, field, found, seen)
  for _, pattern in pairs(patterns) do
    local init = 1

    -- Every occurrence, not only the first: a reverse-proxied host names the
    -- same product in two headers, and the second version is often the one
    -- exposed to the internet.
    while true do
      local from, to, vers = field:find(pattern.regex, init)
      if not from then
        break
      end

      -- A capture that crossed a line boundary means the pattern is unbounded;
      -- accepting it would put whatever followed - a Set-Cookie value, say -
      -- into the CPE, into the report and into the API request.
      if vers ~= nil and not vers:find("[\r\n]") then
        local cpe = pattern.alias .. ":" .. vers
        if not seen[cpe] then
          table.insert(found, cpe)
          seen[cpe] = 1
        end
      end

      init = (to >= from) and to + 1 or from + 1
    end
  end
end

function get_paths_from_file(filename)
  local file, filename_full, status
  local paths = {}

  filename_full = nmap.fetchfile('nselib/data/' .. filename)
  if not(filename_full) then
  stdnse.debug1("No file found at nselib/data/%s, using local copy", filename)
    filename_full = filename
  end

  file = io.open(filename_full, "r")
  if file == nil then
  stdnse.debug1("Failed to open a file with paths")
    return {}
  end
  file:close()
  for line in io.lines(filename_full) do
    -- A file written on Windows ends its lines with CR, which would travel
    -- into the request line and earn a 400 from every strict server.
    local path = line:match("^%s*(.-)%s*$")

    if path ~= "" and not path:find("^#") then
      if not path:find("^/") then
        path = "/" .. path
      end
      paths[#paths + 1] = path
    end
  end
  return paths
end

---
-- Builds the set of paths to request.
--
-- @param paths_arg the script argument: a list of paths or a file name
-- @return table, a set whose keys are the paths to request
--
function get_paths(paths_arg)
  local paths = {}
  local default_paths_file = 'http-vulners-paths.txt'

  if type(paths_arg) == 'table' then
    -- Just do nothing whether it has entries or is an empty one
    do end
  elseif type(paths_arg) == 'string' then
    stdnse.debug1("Trying to read paths from a specified file " .. paths_arg)
    paths_arg = get_paths_from_file(paths_arg)

    -- An operator who names a file means that file. Quietly substituting the
    -- shipped 125-path list would send a scan somewhere it was told not to go.
    if #paths_arg == 0 then
      stdnse.verbose1("No usable paths in the file given as the paths argument; requesting nothing.")
      return {}
    end
  else
    stdnse.debug1("Paths arguments should be a filename or a list of paths to use. Ignoring the argument")
    paths_arg = {}
  end

  -- If provided file could not be found, try the default one
  if #paths_arg == 0 then
    stdnse.debug1("Trying to read paths from a default file " .. default_paths_file)
    paths_arg = get_paths_from_file(default_paths_file)
  end

  -- Fall back to the hardcoded values when the default file could not be found as well
  if #paths_arg == 0 then
    stdnse.debug1("Using the default hardcoded paths.")
    paths_arg = default_paths
  end

  for _, path in ipairs(paths_arg) do
    paths[path] = 1
  end

  return paths
end

action = function(host, port)
  local output = stdnse.output_table()
  local changed = false
  local paths_arg = stdnse.get_script_args(SCRIPT_NAME .. ".paths") or {}

  local patterns = load_patterns()
  if not patterns then
    return
  end

  if port.version == nil or port.version.cpe == nil then
    stdnse.debug1("port.version (or .cpe) table is nil")
    return
  end

  -- Sorted, so a scan of the same target twice reports the same paths in the
  -- same order.
  local paths = {}
  for path in pairs(get_paths(paths_arg)) do
    paths[#paths + 1] = (type(path) == 'string' and path) or tostring(path)
  end
  table.sort(paths)

  if #paths == 0 then
    return
  end

  -- One pipeline instead of one request per path: the default list holds well
  -- over a hundred entries, and the server usually serves them on a handful of
  -- kept-alive connections.
  --
  -- Pages are requested compressed where the server offers it: a real index
  -- page measured 6974 bytes plain and 2068 gzipped, and nmap hands the script
  -- the decoded body either way. The header is only sent when this nmap was
  -- built with zlib, since without it the body would arrive still compressed
  -- and no pattern would match.
  local responses = fetch_paths(host, port, paths)
  follow_redirects(host, port, paths, responses)

  if next(responses) == nil then
    stdnse.debug1("Got no responses from the pipeline")
    return
  end

  -- Per-host state: nmap reuses one loaded script instance for every host and
  -- port it scans, so findings must not leak from one action() call into the
  -- next one.
  local seen = {}

  for index, path in ipairs(paths) do
    local response = responses[index]

    if response == nil or not response.status then
      -- A single unreachable path must not discard what the other paths found.
      stdnse.debug1("HTTP Error retrieving %s", path)
    else
      local found = {}

      local body = response.rawbody or tostring(response.body)
      body = stdnse.string_or_blank(body, nil)
      if body ~= nil then
        get_cpes(patterns, body, found, seen)
      end

      local rawheaders = response.rawheader
      if rawheaders == nil or #rawheaders == 0 then
        stdnse.debug1("Rawheaders are empty...")
      else
        -- Matching the whole header block at once keeps the pattern set from
        -- being applied once per header line. No shipped pattern is anchored,
        -- so joining the lines changes nothing but the amount of work.
        get_cpes(patterns, table.concat(rawheaders, "\n"), found, seen)
      end

      if #found > 0 then
        output[path] = found
        changed = true
      end
    end
  end

  if (not changed) then
    return
  end

  -- NOTE[gmedian]: store the results in a somewhat persistent storage for other scripts to access
  -- It so happens that sometimes port.version.cpe does not contain the CPEs found by the  predecessing script
  -- So have to additionally store the results separately
  --
  -- Keyed by port: what a web server on 80 runs says nothing about the service
  -- on 22, and a host-wide list made the lookup scripts repeat the web findings
  -- under every open port of the host.
  -- Both lists may already carry these CPEs: the registry from another port of
  -- this host, port.version.cpe from nmap's own service fingerprint. Appending
  -- blindly duplicates <cpe> elements in the XML report and makes every
  -- consumer that counts them count twice.
  host.registry.vulners_cpe = host.registry.vulners_cpe or {}
  host.registry.vulners_cpe[port.number] = host.registry.vulners_cpe[port.number] or {}
  local registry = host.registry.vulners_cpe[port.number]

  local in_registry = {}
  for _, cpe in ipairs(registry) do
    in_registry[cpe] = true
  end

  local in_port = {}
  for _, cpe in ipairs(port.version.cpe) do
    in_port[cpe] = true
  end

  for cpe in pairs(seen) do
    if not in_registry[cpe] then
      stdnse.debug1("Add CPE %s to host registry", cpe)
      in_registry[cpe] = true
      table.insert(registry, cpe)
    end
    if not in_port[cpe] then
      in_port[cpe] = true
      table.insert(port.version.cpe, cpe)
    end
  end

  nmap.set_port_version(host, port)

  return output
end
