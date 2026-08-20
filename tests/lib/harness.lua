--- Test harness for the nmap-vulners NSE scripts.
--
-- The scripts under test are ordinary Lua chunks that nmap loads with the NSE
-- libraries available through require(). Tests therefore run *inside* nmap
-- (see tests/run.nse), so json, stdnse, url and shortport are the real
-- implementations shipped with nmap - no re-implementation can drift from
-- them.
--
-- Only two things are faked:
--   * "http"          - so no test ever touches the network
--   * script arguments - written into nmap.registry.args before loading
--
-- A script is loaded into its own environment table, so the globals it
-- defines (action, portrule, description, ...) never leak between tests and
-- a script can be reloaded with different arguments.

local stdnse = require "stdnse"
local nmap = require "nmap"
local table = require "table"
local string = require "string"
local io = require "io"
local json = require "json"
local os = require "os"

local M = {}

-- ---------------------------------------------------------------- assertions

local function fail(msg, level)
  error({harness_failure = msg}, (level or 2) + 1)
end
M.fail = fail

--; Render any value as a stable, readable string for failure messages.
local function repr(v, seen)
  local t = type(v)
  if t == "string" then return string.format("%q", v) end
  if t ~= "table" then return tostring(v) end

  seen = seen or {}
  if seen[v] then return "<cycle>" end
  seen[v] = true

  local keys, out = {}, {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  for _, k in ipairs(keys) do
    out[#out + 1] = string.format("%s = %s", tostring(k), repr(v[k], seen))
  end
  seen[v] = nil
  return "{" .. table.concat(out, ", ") .. "}"
end
M.repr = repr

function M.is_true(value, msg)
  if not value then
    fail(string.format("%s: expected truthy, got %s", msg or "is_true",
      repr(value)))
  end
  return value
end

function M.is_false(value, msg)
  if value then
    fail(string.format("%s: expected falsy, got %s", msg or "is_false",
      repr(value)))
  end
end

function M.is_nil(value, msg)
  if value ~= nil then
    fail(string.format("%s: expected nil, got %s", msg or "is_nil",
      repr(value)))
  end
end

function M.equals(actual, expected, msg)
  if actual ~= expected then
    fail(string.format("%s: expected %s, got %s",
      msg or "equals", repr(expected), repr(actual)))
  end
  return actual
end

--; Recursive value comparison; metatables are ignored on purpose, the scripts
-- attach __tostring metatables to their result rows.
local function deep_equal(a, b)
  if a == b then return true end
  if type(a) ~= "table" or type(b) ~= "table" then return false end
  for k, v in pairs(a) do
    if not deep_equal(v, b[k]) then return false end
  end
  for k in pairs(b) do
    if a[k] == nil then return false end
  end
  return true
end
function M.same(actual, expected, msg)
  if not deep_equal(actual, expected) then
    fail(string.format("%s: expected %s, got %s",
      msg or "same", repr(expected), repr(actual)))
  end
end

function M.matches(haystack, pattern, msg)
  if type(haystack) ~= "string" or not haystack:find(pattern) then
    fail(string.format("%s: %s does not match %q",
      msg or "matches", repr(haystack), pattern))
  end
end

--- Assert that a list contains the given value.
function M.contains(list, expected, msg)
  if type(list) == "table" then
    for _, value in ipairs(list) do
      if value == expected then return end
    end
  end
  fail(string.format("%s: %s is not in %s",
    msg or "contains", repr(expected), repr(list)))
end

function M.length(value, expected, msg)
  -- Both halves have to be present. "value and #value or nil" collapsed "no
  -- value" and "no expectation" onto the same nil, so t.length(nil) and
  -- t.length(false) passed while measuring nothing at all.
  if expected == nil then
    fail((msg or "length") .. ": no expected length was given")
  end
  if type(value) ~= "table" and type(value) ~= "string" then
    fail(string.format("%s: expected something with a length, got %s",
      msg or "length", repr(value)))
  end
  local n = #value
  if n ~= expected then
    fail(string.format("%s: expected length %s, got %s (%s)",
      msg or "length", tostring(expected), tostring(n), repr(value)))
  end
end

--- Assert that calling fn(...) does not raise. Returns whatever fn returns.
function M.no_error(fn, msg, ...)
  local results = table.pack(pcall(fn, ...))
  if not results[1] then
    local err = results[2]
    if type(err) == "table" and err.harness_failure then
      err = err.harness_failure
    end
    fail(string.format("%s: unexpected error: %s", msg or "no_error",
      tostring(err)))
  end
  return table.unpack(results, 2, results.n)
end

--- Assert that calling fn(...) raises an error (used for regression tests
-- that pin down a crash before it is fixed).
function M.raises(fn, msg, ...)
  local ok, err = pcall(fn, ...)
  if ok then
    fail(string.format("%s: expected an error, call succeeded",
      msg or "raises"))
  end
  -- An assertion that fails INSIDE the body raises too, and this used to
  -- report that as the error it was hoping for - so any assertion nested in a
  -- raises() body was inert. M.no_error already unwraps this wrapper; the
  -- difference is that there it means failure and here it meant success.
  if type(err) == "table" and err.harness_failure then
    fail(string.format("%s: the body failed an assertion instead of " ..
      "raising: %s",
      msg or "raises", tostring(err.harness_failure)))
  end
  return err
end

--- Split the query string of a request path into its arguments.
-- @param path string, a path of the form "/endpoint?a=1&b=2"
-- @return table of "name=value" strings, in the order they were sent
function M.split_query(path)
  local args = {}
  local query = path:match("%?(.*)$") or ""
  for part in query:gmatch("[^&]+") do
    args[#args + 1] = part
  end
  return args
end


-- --------------------------------------------------------------- http double

--- Build a fake response in the shape nmap's http library returns.
-- @param opts table with optional status, body, header, rawheader fields
function M.response(opts)
  opts = opts or {}
  -- Two things nselib does that this double has to do as well.
  --
  -- Lowercased, because nselib does it unconditionally (http.lua:769, name =
  -- string.lower(name)), so response.header in the field NEVER carries a
  -- capital. A double that kept the fixture spelling let a case pass
  -- {["Server"] = ...} and believe it exercised the hdr:server channel when
  -- the match was really coming through raw - and it would equally have
  -- "proved" a rule filed as hdr:Server, which is dead in every real scan.
  --
  -- Sorted, never pairs(). Lua seeds its string hash per process, so building
  -- these in table order gave a DIFFERENT raw channel on every nmap run: one
  -- fixture produced five distinct header orders across six runs, and the raw
  -- channel is table.concat(response.rawheader, "\n"). Any rule spanning two
  -- header lines then passed or failed by hash seed.
  local names = {}
  for name in pairs(opts.header or {}) do
    names[#names + 1] = name
  end
  table.sort(names, function(a, b) return tostring(a) < tostring(b) end)

  local header = {}
  for _, name in ipairs(names) do
    local value = opts.header[name]
    local key = type(name) == "string" and name:lower() or name
    -- Two spellings of one header name collide on the lowercase key. nselib
    -- joins repeated headers with ", " (http.lua:771-776) rather than letting
    -- the last one win, and two Set-Cookie lines is the commonest real
    -- response there is.
    header[key] = header[key] and (header[key] .. ", " .. value) or value
  end

  local rawheader = opts.rawheader
  if not rawheader then
    rawheader = {}
    for _, name in ipairs(names) do
      rawheader[#rawheader + 1] = string.format("%s: %s", name,
        opts.header[name])
    end
    -- The blank line that ends the header block. nselib splits the raw header
    -- on newlines, so the trailing empty element is always there.
    rawheader[#rawheader + 1] = ""
  end
  -- rawbody defaults to body, because that is the only shape nselib produces.
  -- nselib/http.lua sets rawbody to the UNDECODED bytes and then replaces body
  -- with the decoded ones, so rawbody is ALWAYS present - while this double
  -- left it nil unless a test asked for it. That let every case exercise a
  -- branch production never takes, and hid a script that was matching its
  -- patterns against gzip bytes on every server that compresses.
  --
  -- Pass rawbody explicitly to model a compressed response: rawbody is what
  -- arrived on the wire, body is what nmap decoded for the script. A response
  -- nmap could not get is NOT a response with an empty body. nselib builds it
  -- in http_error (http.lua:1208) and sets body = nil, rawbody = nil. This
  -- double returned "" for both, so every "the server could not be reached"
  -- case in the suite ran against a string - and an `or ""` dropped anywhere
  -- on a failure path would stay green here while a real scan raised and lost
  -- the port its entire result.
  if opts.status == nil then
    return {
      status = nil,
      ["status-line"] = opts["status-line"] or "Error creating socket.",
      header = {},
      rawheader = {},
      body = nil,
      rawbody = nil,
      incomplete = opts.incomplete,
    }
  end

  return {
    status = opts.status,
    ["status-line"] = opts["status-line"] or
      string.format("HTTP/1.1 %d", opts.status),
    header = header,
    rawheader = rawheader,
    body = opts.body or "",
    rawbody = opts.rawbody or opts.body or "",
  }
end

--- A programmable stand-in for the "http" NSE library.
--
-- Every call is recorded in .requests; the reply comes from .handler, which
-- receives a normalised request table:
--   {method, url, host, port, path, options, body}
-- Returning nil from the handler models "nmap could not reach the server"
-- (http returns a table whose .status is nil), which is what the retry loops
-- in the scripts under test react to.
function M.http_double()
  local double = {requests = {}}

  local function record(req)
    -- Snapshot rather than read back later: options is the CALLER's table and
    -- the write-back below mutates it, so a recorded reference would show
    -- every request carrying whatever the last one ended up with.
    req.scheme = req.options and req.options.scheme

    double.requests[#double.requests + 1] = req
    local reply = double.handler and double.handler(req, #double.requests)
    if reply == nil then
      return M.response({status = nil})
    end

    -- What nselib does, and the reason it matters. On a redirect it assigns
    -- `options.scheme = u.scheme or options.scheme` INTO THE CALLER'S TABLE
    -- (nselib/http.lua:1799), so a caller that reuses one options table across
    -- requests has its scheme changed out from under it by the target's own
    -- Location header. Without this line the double is wrong in a direction
    -- nselib never produces, and a case written to catch that bug passes
    -- against code that has it.
    local status = type(reply) == "table" and reply.status or nil
    if req.options and status and status >= 300 and status < 400 then
      local location = reply.header
        and (reply.header.location or reply.header.Location)
      local scheme = type(location) == "string"
        and location:match("^(%a[%w+.-]*)://")
      if scheme then
        req.options.scheme = scheme:lower()
      end
    end

    return reply
  end

  function double.get_url(url, options)
    return record({method = "GET", url = url, options = options})
  end

  function double.get(host, port, path, options)
    return record({method = "GET", host = host, port = port,
                   path = path, options = options})
  end

  function double.post(host, port, path, options, ignored, body)
    return record({method = "POST", host = host, port = port,
                   path = path, options = options, body = body})
  end

  --- Queue one request, mirroring http.pipeline_add.
  function double.pipeline_add(path, options, all_requests, method)
    all_requests = all_requests or {}
    all_requests[#all_requests + 1] = {method = method or "GET", path = path,
                                       options = options}
    return all_requests
  end

  --- Run a queued pipeline, mirroring http.pipeline_go.
  --
  -- Responses come back in queue order. The real implementation may return a
  -- shorter list than requested when a connection breaks, which the handler
  -- models by returning the string "cut_short", and nil when it could not open
  -- a connection at all, which the handler models with "no_connection".
  function double.pipeline_go(host, port, all_requests)
    if all_requests == nil or #all_requests == 0 then
      return {}
    end

    local responses = {}
    for _, request in ipairs(all_requests) do
      local reply = record({method = request.method, host = host, port = port,
                            path = request.path, options = request.options,
                            pipelined = true})
      if reply == "no_connection" then
        return nil
      end
      if reply == "cut_short" then
        break
      end
      responses[#responses + 1] = reply
    end
    return responses
  end

  --- Requests whose URL or path contains the given substring.
  function double.matching(needle)
    local out = {}
    for _, req in ipairs(double.requests) do
      local target = req.url or req.path or ""
      if target:find(needle, 1, true) then out[#out + 1] = req end
    end
    return out
  end

  return double
end

--- A stand-in for "stdnse" that records everything the script logs.
--
-- Used to assert on what ends up in nmap's debug output, which is where an
-- API key must never appear.
function M.stdnse_double()
  local double = {messages = {}}

  local function record(fmt, ...)
    local ok, rendered = pcall(string.format, tostring(fmt), ...)
    double.messages[#double.messages + 1] = ok and rendered or tostring(fmt)
  end

  -- verbose1..verbose5 as well as verbose: the numbered forms are what the
  -- script uses for everything it says to the operator - the degrade ladder,
  -- the catalogue notes, the deprecation warnings. Without them those messages
  -- fell through the metatable to the real library and a case that asserted on
  -- one was asserting on an empty log.
  for _, name in ipairs({"debug1", "debug2", "debug3", "debug4", "debug5",
                         "debug", "print_debug",
                         "verbose1", "verbose2", "verbose3", "verbose4",
                         "verbose5", "verbose", "print_verbose"}) do
    double[name] = function(first, ...)
      -- stdnse.debug(level, fmt, ...) takes the level first, the rest do not.
      if name == "debug" or name == "print_debug" or name == "verbose"
         or name == "print_verbose" then
        if type(first) == "number" then return record(...) end
      end
      return record(first, ...)
    end
  end

  --- All logged text joined together, for substring assertions.
  function double.log()
    return table.concat(double.messages, "\n")
  end

  return setmetatable(double, {__index = stdnse})
end

-- ------------------------------------------------------------- nmap fixtures

--- A host table shaped like the one NSE scripts receive.
function M.host(opts)
  opts = opts or {}
  return {
    ip = opts.ip or "127.0.0.1",
    targetname = opts.targetname,
    registry = opts.registry or {},
  }
end

--- A port table shaped like the one NSE scripts receive after -sV.
function M.port(opts)
  opts = opts or {}
  local version = nil
  if opts.version ~= false then
    version = {
      product = opts.product,
      version = opts.version,
      cpe = opts.cpe or {},
      name = opts.name or "http",
      -- What nmap writes when its own probes did NOT settle the service. The
      -- banner channel and the paid audit/smart call both read it, and until
      -- this field existed no case could build a port that had one.
      service_fp = opts.service_fp,
      -- "probed" when -sV settled the service, "table" when the name is only
      -- nmap's ports-file guess. The sweep gate reads it, because a guess is
      -- not nmap naming anything: 7080 is guessed "empowerid" and 8088
      -- "radan-http", and both are real HTTP ports this script must sweep.
      service_dtype = opts.service_dtype,
    }
  end
  return {
    number = opts.number or 80,
    protocol = opts.protocol or "tcp",
    state = opts.state or "open",
    service = opts.service or "http",
    version = version,
  }
end

--- A stand-in for the "nmap" library.
--
-- The real one is kept for everything except the calls that only make sense
-- while nmap is actually scanning a host: set_port_version() rejects a
-- synthetic host table, and fetchfile() resolves paths inside the nmap
-- installation rather than the checkout.
--
-- @param opts fetchfile - function(name) used by the script under test
--             timing   - the -T level the script should see (0..5)
function M.nmap_double(opts)
  opts = opts or {}
  local double = {
    set_port_version_calls = {},
    registry = nmap.registry,
  }

  -- The sweep asks nmap how aggressive this scan may be, and the answer
  -- decides how much of the catalogue goes on the wire. Faked, because the
  -- real one returns whatever -T the suite itself was run with.
  if opts.timing ~= nil then
    function double.timing_level()
      return opts.timing
    end
  end

  function double.set_port_version(host, port, detail)
    double.set_port_version_calls[#double.set_port_version_calls + 1] = {
      host = host, port = port, detail = detail,
    }
  end

  function double.fetchfile(name)
    if opts.fetchfile then return opts.fetchfile(name) end
    -- Nothing is installed under the nmap data directory during tests, which
    -- is exactly the situation the script's local-copy fallback handles.
    return nil
  end

  return setmetatable(double, {__index = nmap})
end

--- A stand-in for "os" whose getenv only sees what a test declares.
--
-- The merged script discovers its API key from the environment and from
-- $HOME/.nmap/vulners.key, so a suite that does not fake this reads the
-- developer's real key: the same case would pass on a machine with no key and
-- fail on the maintainer's laptop. The environment is always faked, never
-- merely overridden - unsetting a variable in the test process would not help,
-- because the developer's shell is what exported it.
--
-- @param vars table of variable name -> value; everything else reads as unset
function M.os_double(vars, files)
  vars = vars or {}
  local double = {removed = {}, renamed = {}}

  function double.getenv(name)
    return vars[name]
  end

  -- Nothing in the script renames or removes a file, and these are here to
  -- keep it that way: the metatable falls through to the real os, so a
  -- regression that started moving files would move the developer's, quietly,
  -- instead of being recorded and asserted on.
  if files then
    function double.remove(path)
      double.removed[#double.removed + 1] = path
      files[path] = nil
      return true
    end
    function double.rename(from, to)
      double.renamed[#double.renamed + 1] = from .. " -> " .. to
      if files[from] == nil then
        return nil, from .. ": No such file or directory"
      end
      files[to] = files[from]
      files[from] = nil
      return true
    end
  end

  return setmetatable(double, {__index = os})
end

--- A stand-in for "io" that only knows the files a test declares.
--
-- @param files table of path -> contents
function M.io_double(files)
  files = files or {}
  -- .written records what the script put on disk. The script is not supposed
  -- to write anything at all, so this exists to CATCH a write rather than to
  -- serve one: without it, an io.open(path, "w") would fall through the
  -- metatable to the real library and create the file on the developer's
  -- machine, and the case asserting nothing was written would pass.
  local double = {opened = {}, written = {}, files = files}

  function double.open(path, mode)
    double.opened[#double.opened + 1] = path

    if mode and mode:find("[wa]") then
      local buffer = {}
      if mode:find("a") and files[path] then
        buffer[1] = files[path]
      end
      local handle = {}
      function handle:write(text)
        buffer[#buffer + 1] = tostring(text)
        return handle
      end
      function handle:close()
        local text = table.concat(buffer)
        files[path] = text
        double.written[path] = text
        return true
      end
      function handle:read() return nil end
      function handle:lines() return function() return nil end end
      return handle
    end

    local contents = files[path]
    if contents == nil then
      return nil, path .. ": No such file or directory"
    end

    local position = 1
    local handle = {}
    function handle:read(what)
      if position > #contents then return nil end
      if what == "*all" or what == "a" then
        local rest = contents:sub(position)
        position = #contents + 1
        return rest
      end
      local line, next_position = contents:match("([^\n]*)\n?()", position)
      if next_position == position then return nil end
      position = next_position
      return line
    end
    function handle:lines()
      return function() return handle:read("*line") end
    end
    function handle:close() return true end
    return handle
  end

  return setmetatable(double, {__index = io})
end

-- ---------------------------------------------------------------- script load

local script_arg_backup = nil

--; Replace nmap.registry.args for the duration of one test.
--
-- Scripts read their arguments at different moments: vulners.nse reads
-- mincvss while loading, http-vulners-regex.nse reads paths inside action().
-- So the arguments must stay in place until the test is over, not just until
-- the chunk has run. tests/run.nse restores them after every test case.
local function set_script_args(args)
  if script_arg_backup == nil then
    script_arg_backup = nmap.registry.args or {}
  end
  nmap.registry.args = args or {}
end

--; Registry keys the scripts under test use for scan-wide caches.
-- They survive between action() calls by design, so a test must start clean.
-- One key, because 2.0 keeps everything scan-wide under it. The 1.x names are
-- gone with the scripts that wrote them, and host.registry.vulners_cpe is on
-- host table, which every case builds fresh anyway.
local REGISTRY_KEYS = {"vulners"}

--- Drop every scan-wide cache the scripts keep in nmap.registry.
function M.reset_registry()
  for _, key in ipairs(REGISTRY_KEYS) do
    nmap.registry[key] = nil
  end
end

function M.restore_script_args()
  if script_arg_backup ~= nil then
    nmap.registry.args = script_arg_backup
    script_arg_backup = nil
  end
end

--- Load an .nse script into an isolated environment.
--
-- @param path       path to the .nse file
-- @param opts       table: args    - script arguments,
--                     e.g. {["vulners.mincvss"] = "7"} modules - libraries to
--                     inject, e.g. {http = double} env     - extra globals to
--                     expose to the script
-- @return the script environment: env.action, env.portrule, ...
function M.load_script(path, opts)
  opts = opts or {}

  local name = path:match("([^/\\]+)%.nse$") or path
  -- Exactly what nse_main.lua:619-624 puts in the LOAD-TIME environment, and
  -- nothing else. SCRIPT_TYPE is deliberately absent: nmap sets it per thread
  -- (nse_main.lua:467-472), never at load time, so a file-scope read of it is
  -- fatal in the field - "variable 'SCRIPT_TYPE' is not declared", verified
  -- against real nmap - while the harness, which pre-declared it, loaded the
  -- file happily. vulners.nse carries a comment warning about that exact trap,
  -- and the harness was the one thing that could not catch a regression on it.
  local env = setmetatable({}, {__index = _G})
  env.SCRIPT_NAME = opts.script_name or name
  env.SCRIPT_PATH = path
  env.categories = {}
  env.dependencies = {}
  for k, v in pairs(opts.env or {}) do env[k] = v end

  -- Swap the requested libraries in package.loaded, so the script's own
  -- require() calls pick up the doubles, then put the originals back.
  -- The previous value is wrapped, because a module that was not loaded before
  -- has none: storing a plain nil would drop the key, the restore loop would
  -- never see it, and the double would stay installed for the rest of the
  -- nmap process - every later case included.
  local swapped = {}
  for modname, replacement in pairs(opts.modules or {}) do
    swapped[modname] = {previous = package.loaded[modname]}
    package.loaded[modname] = replacement
  end

  set_script_args(opts.args)

  local chunk, load_err = loadfile(path, "t", env)
  if not chunk then
    M.restore_script_args()
    for modname, entry in pairs(swapped) do
      package.loaded[modname] = entry.previous
    end
    error(string.format("cannot load %s: %s", path, tostring(load_err)), 0)
  end

  local ok, run_err = pcall(chunk)

  -- The script captured the doubles in its own locals during the chunk run,
  -- so package.loaded can go back to the real libraries immediately.
  -- Script arguments stay in place until the test case ends.
  for modname, entry in pairs(swapped) do
    package.loaded[modname] = entry.previous
  end

  if not ok then
    error(string.format("error while loading %s: %s", path,
      tostring(run_err)), 0)
  end

  -- Now, and not before: nmap gives the running thread its SCRIPT_TYPE after
  -- the chunk has been loaded, so this is where a case can read or override
  -- it.
  env.SCRIPT_TYPE = opts.script_type or "portrule"

  return env
end

--- A stand-in for "stdnse" whose sleep() is counted instead of performed.
--
-- Installed by load_vulners for EVERY case, not only the ones that measure a
-- wait. The retry ladder sleeps 1 s, then 2, then 3 before it gives up, so any
-- case that let a request go unanswered paid six real seconds for it - and
-- enough of them did that the suite took 23 seconds, 22 of which were spent
-- asleep. Counting the sleep makes those paths instant and turns "did it wait,
-- and how long for" into something a test can assert instead of something it
-- endures.
--
-- Everything else falls through to the real library, including output_table
-- and get_script_args, which the script needs to work at all.
function M.clock_double()
  local double = {sleeps = 0, slept = 0}
  function double.sleep(seconds)
    double.sleeps = double.sleeps + 1
    double.slept = double.slept + seconds
  end
  return setmetatable(double, {__index = stdnse})
end

--; The catalogue documents this repository publishes, read from disk.
--
-- Cached across cases: the rule dictionary is 220 KB and 148 cases load a
-- script, so re-reading and re-parsing it every time turned a four-second
-- suite into a much longer one for no extra coverage.
local published_cache = nil
function M.published_catalog(root)
  if published_cache then
    return published_cache
  end

  local documents = {}
  for _, kind in ipairs({"fingerprints", "paths", "probes"}) do
    local handle = io.open(root .. "/catalog/" .. kind .. ".json", "r")
    if handle == nil then
      error({harness_failure = "catalog/" .. kind ..
        ".json is missing; the suite reads the published catalogue"})
    end
    local text = handle:read("a")
    handle:close()
    local ok, document = json.parse(text)
    if not ok then
      error({harness_failure = "catalog/" .. kind .. ".json is not valid " ..
        "JSON"})
    end
    documents[kind] = document
  end

  published_cache = documents
  return documents
end

--- Hand a loaded script its catalogue, through its own readers.
--
-- Through the readers rather than around them: a case that hand-built the
-- runtime tables would pass against a script whose validation rejects the very
-- data it ships, which is the failure the readers exist to prevent.
function M.give_catalog(env, documents)
  local shared = env._TEST.state()
  local fingerprints, count =
    env._TEST.read_fingerprints(documents.fingerprints)
  local paths = env._TEST.read_paths(documents.paths)

  if fingerprints == nil or paths == nil then
    error({harness_failure = "the catalogue handed to the script was " ..
      "refused " ..
      "by its own readers"})
  end

  shared.catalog = {
    fingerprints = fingerprints,
    rule_count = count,
    paths = paths,
    probes = env._TEST.read_probes(documents.probes) or {},
    serial = 0,
    fetched = 0,
    source = "test",
  }
  shared.catalog_loaded = true
  return shared.catalog
end

--- Load the merged vulners.nse with everything that reaches outside faked.
--
-- Every case declares its mode, because 2.0 behaves differently with a token
-- and the difference is not cosmetic: an authenticated run enriches through
-- search/id and can spend a credit on audit/smart. A case that leaves it to
-- chance is really testing whoever ran it.
--
-- The path sweep is off unless a case asks for it. The merged action sweeps
-- every port shortport.http accepts, and harness.port() defaults to 80/http,
-- so without this almost every case would count 126 requests it never meant to
-- make.
--
-- The catalogue is injected, not downloaded. The script now carries no
-- fingerprint data at all - it fetches three dictionaries at scan time - so a
-- case that did not supply them would exercise a script that recognises
-- nothing, and would pass while measuring that. By default the REAL published
-- catalogue is read from catalog/ and handed to the script through its own
-- readers, so the sweep cases keep asserting against the rules that ship.
--
-- @param opts  root    - repository root (required)
--              token   - API token, or nil for the free path
--              paths   - sweep paths; nil means "none", a table enables them
--              args    - extra script arguments
--              env     - extra environment variables
--              files   - files io.open should find
--              http    - an existing http double to reuse
--              clock   - a clock_double to reuse; one is made otherwise, so
--                        no case ever sleeps for real
--              catalog - false for a script with no catalogue at all, a table
--                        of catalogue documents to inject those instead, or
--                        nil for the published one
-- @return env, http, io_double, clock
function M.load_vulners(opts)
  opts = opts or {}
  local http = opts.http or M.http_double()
  local clock = opts.clock or M.clock_double()

  local args = {}
  for name, value in pairs(opts.args or {}) do args[name] = value end
  if args["vulners.paths"] == nil then
    -- The sentinel "embedded" leaves the argument unset, which is how a case
    -- asks for the shipped path list. An empty table used to mean that by
    -- accident; it now means what it says - request nothing - so the intent
    -- has to be spelled out.
    if opts.paths ~= "embedded" then
      args["vulners.paths"] = opts.paths or "none"
    end
  end

  local environment = {}
  for name, value in pairs(opts.env or {}) do environment[name] = value end
  if opts.token then
    environment.VULNERS_API_KEY = opts.token
  end

  local files = opts.files or {}
  local disk = M.io_double(files)
  local env = M.load_script((opts.root or ".") .. "/vulners.nse", {
    args = args,
    script_type = opts.script_type,
    modules = {
      http = http,
      nmap = opts.nmap or M.nmap_double(),
      os = M.os_double(environment, files),
      io = disk,
      stdnse = clock,
    },
  })

  if opts.catalog ~= false then
    M.give_catalog(env, opts.catalog or M.published_catalog(opts.root or "."))
  end

  -- The io double is returned so a case can assert on what reached the
  -- filesystem, and the clock so it can assert on what the script waited for.
  return env, http, disk, clock
end

-- ------------------------------------------------------------------- helpers

--- Collect an stdnse.output_table() result into a plain table plus key order,
-- so tests can assert on both content and ordering.
function M.collect_output(output)
  local plain, order = {}, {}
  if output == nil then return nil, order end
  for key, value in pairs(output) do
    plain[key] = value
    order[#order + 1] = key
  end
  return plain, order
end

return M
