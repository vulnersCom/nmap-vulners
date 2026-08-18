--- Test harness for the nmap-vulners NSE scripts.
--
-- The scripts under test are ordinary Lua chunks that nmap loads with the
-- NSE libraries available through require(). Tests therefore run *inside*
-- nmap (see tests/run.nse), so json, stdnse, url and shortport are the real
-- implementations shipped with nmap - no re-implementation can drift from them.
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

local M = {}

-- ---------------------------------------------------------------- assertions

local function fail(msg, level)
  error({harness_failure = msg}, (level or 2) + 1)
end
M.fail = fail

--- Render any value as a stable, readable string for failure messages.
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
    fail(string.format("%s: expected truthy, got %s", msg or "is_true", repr(value)))
  end
  return value
end

function M.is_false(value, msg)
  if value then
    fail(string.format("%s: expected falsy, got %s", msg or "is_false", repr(value)))
  end
end

function M.is_nil(value, msg)
  if value ~= nil then
    fail(string.format("%s: expected nil, got %s", msg or "is_nil", repr(value)))
  end
end

function M.equals(actual, expected, msg)
  if actual ~= expected then
    fail(string.format("%s: expected %s, got %s",
      msg or "equals", repr(expected), repr(actual)))
  end
  return actual
end

--- Recursive value comparison; metatables are ignored on purpose, the scripts
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
M.deep_equal = deep_equal

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
  local n = value and #value or nil
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
    if type(err) == "table" and err.harness_failure then err = err.harness_failure end
    fail(string.format("%s: unexpected error: %s", msg or "no_error", tostring(err)))
  end
  return table.unpack(results, 2, results.n)
end

--- Assert that calling fn(...) raises an error (used for regression tests
-- that pin down a crash before it is fixed).
function M.raises(fn, msg, ...)
  local ok, err = pcall(fn, ...)
  if ok then
    fail(string.format("%s: expected an error, call succeeded", msg or "raises"))
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
  local header = opts.header or {}
  local rawheader = opts.rawheader
  if not rawheader then
    rawheader = {}
    for name, value in pairs(header) do
      rawheader[#rawheader + 1] = string.format("%s: %s", name, value)
    end
  end
  return {
    status = opts.status,
    ["status-line"] = opts["status-line"] or
      (opts.status and string.format("HTTP/1.1 %d", opts.status) or "no response"),
    header = header,
    rawheader = rawheader,
    body = opts.body or "",
    rawbody = opts.rawbody,
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
    double.requests[#double.requests + 1] = req
    local reply = double.handler and double.handler(req, #double.requests)
    if reply == nil then
      return M.response({status = nil})
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

  for _, name in ipairs({"debug1", "debug2", "debug3", "debug4", "debug5",
                         "debug", "print_debug", "verbose", "print_verbose"}) do
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
function M.nmap_double(opts)
  opts = opts or {}
  local double = {
    set_port_version_calls = {},
    registry = nmap.registry,
  }

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

-- ---------------------------------------------------------------- script load

local script_arg_backup = nil

--- Replace nmap.registry.args for the duration of one test.
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

--- Registry keys the scripts under test use for scan-wide caches.
-- They survive between action() calls by design, so a test must start clean.
local REGISTRY_KEYS = {"vulners_enterprise", "vulners", "vulners_cpe",
                        "vulners_regex_patterns"}

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
-- @param opts       table:
--                     args    - script arguments, e.g. {["vulners.mincvss"] = "7"}
--                     modules - libraries to inject, e.g. {http = double}
--                     env     - extra globals to expose to the script
-- @return the script environment: env.action, env.portrule, ...
function M.load_script(path, opts)
  opts = opts or {}

  local name = path:match("([^/\\]+)%.nse$") or path
  local env = setmetatable({}, {__index = _G})
  env.SCRIPT_NAME = opts.script_name or name
  env.SCRIPT_PATH = path
  env.SCRIPT_TYPE = opts.script_type or "portrule"
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
    for modname, entry in pairs(swapped) do package.loaded[modname] = entry.previous end
    fail(string.format("cannot load %s: %s", path, tostring(load_err)))
  end

  local ok, run_err = pcall(chunk)

  -- The script captured the doubles in its own locals during the chunk run,
  -- so package.loaded can go back to the real libraries immediately.
  -- Script arguments stay in place until the test case ends.
  for modname, original in pairs(swapped) do package.loaded[modname] = original end

  if not ok then
    fail(string.format("error while loading %s: %s", path, tostring(run_err)))
  end

  return env
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

--- Render one result row through the script's __tostring metatable, which is
-- what the user actually sees in nmap output.
function M.render(row)
  return tostring(row)
end

M.stdnse = stdnse

return M
