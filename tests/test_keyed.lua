--- Everything an API token unlocks in the merged vulners.nse.
--
-- 1.x had a separate vulners_enterprise.nse whose whole job was the batched
-- POST /api/v4/audit/software/ endpoint. 2.0 does not call it on any default
-- path, so what this suite now owns is the pair of endpoints a token actually
-- reaches, plus the rule that losing the token costs detail and never silence.
--
-- The three shapes below were captured from the live API, so the doubles here
-- cannot drift into something the server never sends:
--
--   GET /api/v3/burp/software/?software=<cpe>&version=<v>&type=cpe
--     free, unkeyed, CDN-cached, one identity per request
--     {"result":"OK","data":{"search":[{"_source":{id,type,bulletinFamily,
--                                                  cvss:{score,version}}}],
--                            "search_explain":{search_cpe,matched_cpe}}}
--     {"result":"warning","data":{...}}  - resolved, and nothing is known
--
--   POST /api/v3/search/id/        needs a token, costs no credit, max 100 ids
--     {"result":"OK","data":{"documents":{"<id>":{id,type,bulletinFamily,
--                                                 cvss,epss,cvelist,metrics}}}}
--
--   POST /api/v4/audit/smart       needs a token, costs a credit
--     {"result":[{"input":"<text>","cpe":"cpe:2.3:...","confidence":90,
--                 "vulnerabilities":[{"id","type"}]}]}
--     note the v4 envelope: result is an ARRAY, not the string "OK".
--
-- Every case declares its mode. A keyed run enriches and can spend a credit, a
-- keyless one cannot, and a case that leaves the choice to the machine it runs
-- on is testing the developer's shell rather than the script.

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local KEY = "FAKE-TEST-KEY-NOT-A-REAL-TOKEN"
local CPE = "cpe:/a:openbsd:openssh:7.4"

-- Requests are told apart by ENDPOINT, never by host: with a token the free
-- lookups and the keyed calls all go to the same host.
local BURP = "/api/v3/burp/"
local SEARCH_ID = "/api/v3/search/id/"
local SMART = "/api/v4/audit/smart"

--- A keyed load. The token travels through the faked environment, so nothing
-- here can pick up the developer's real one.
local function keyed(opts)
  opts = opts or {}
  opts.root = root
  if opts.token == nil then opts.token = KEY end
  return t.load_vulners(opts)
end

--- A keyed load whose bounded waits are instant and countable.
local function keyed_with_clock(opts)
  opts = opts or {}
  opts.clock = t.clock_double()
  local env, http = keyed(opts)
  return env, http, opts.clock
end

--- A keyless load, spelled out rather than implied.
local function keyless(opts)
  opts = opts or {}
  opts.root = root
  opts.token = nil
  return t.load_vulners(opts)
end

-- ------------------------------------------------------------ response parts

--- One burp hit's _source, as the free endpoint returns it.
local function bulletin(opts)
  local source = {
    id = opts.id,
    type = opts.type or "cve",
    -- B4: bulletinFamily is what makes something an exploit; the 1.x list of
    -- exploit TYPES is gone.
    bulletinFamily = opts.family or "NVD",
  }
  if opts.cvss ~= nil then
    source.cvss = {score = opts.cvss, version = opts.cvss_version or "3.1"}
  elseif opts.cvss_none then
    source.cvss = {score = 0, version = "NONE"}
  elseif opts.cvss_unversioned then
    -- Seen in the wild: a score with no version at all.
    source.cvss = {score = opts.cvss_unversioned}
  end
  return source
end

--- The query of a burp GET, percent-decoded back into a name -> value map.
local function query_args(path)
  local args = {}
  for _, part in ipairs(t.split_query(path)) do
    local name, value = part:match("^([^=]*)=(.*)$")
    if name then
      args[name] = (value:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
      end))
    end
  end
  return args
end

--- Answer the endpoints a 2.0 run really uses.
--
-- The 1.x double ended in t.fail for anything that was not the v4 audit, which
-- under the merge kills every case on its first request: the action sweeps an
-- http port and then asks burp about each identity.
--
-- @param opts software - software query value -> list of bulletin() sources;
--                        an absent key answers "warning", i.e. resolved and clean
--             docs     - bulletin id -> enrichment document
--             pages    - sweep path -> t.response() options
--             smart    - function(req) answering POST /api/v4/audit/smart
--             handler  - first refusal on every request, for error injection
--- json.parse gives back whatever the body held; a list is what we expect.
local function as_list(value)
  return type(value) == "table" and value or {}
end

local function serve(http, opts)
  opts = opts or {}
  local answers = opts.software or {}
  local docs = opts.docs or {}
  local pages = opts.pages or {}

  http.handler = function(req, index)
    if opts.handler then
      local reply = opts.handler(req, index)
      if reply ~= nil then return reply end
    end

    -- The sweep talks to the target, and http.get(host_table, ...) is how it
    -- says so; every API call carries api_host as a plain string.
    if type(req.host) == "table" then
      local page = pages[req.path]
      if page == nil then
        return t.response({status = 404})
      end
      return t.response({status = page.status or 200, body = page.body,
                         header = page.header})
    end

    if req.path:find(BURP, 1, true) then
      local asked = query_args(req.path)
      -- matched_cpe echoing search_cpe is how burp says the identity resolved.
      -- Without it the port treats an empty answer as "could not be named" and
      -- spends a credit on audit/smart, which most cases here do not mean.
      local explain = {search_cpe = asked.software, matched_cpe = asked.software}
      local rows = answers[asked.software]
      if rows == nil then
        return t.response({status = 200, body = json.generate({
          result = "warning", data = {search_explain = explain},
        })})
      end
      local search = {}
      for _, source in ipairs(rows) do
        search[#search + 1] = {_source = source}
      end
      return t.response({status = 200, body = json.generate({
        result = "OK", data = {search = search, search_explain = explain},
      })})
    end

    if req.path:find(SEARCH_ID, 1, true) then
      local ok, body = json.parse(req.body)
      t.is_true(ok, "the enrichment body must be valid json")
      -- The endpoint's own limit, asserted on every case that reaches it.
      t.is_true(#body.id <= 100, "no enrichment chunk may exceed 100 ids")
      local documents = {}
      for _, id in ipairs(body.id) do
        if docs[id] ~= nil then documents[id] = docs[id] end
      end
      return t.response({status = 200, body = json.generate({
        result = "OK", data = {documents = documents},
      })})
    end

    if req.path:find(SMART, 1, true) then
      if type(opts.smart) == "function" then
        local reply = opts.smart(req)
        if reply ~= nil then return reply end
      elseif type(opts.smart) == "table" then
        -- A map of input string -> the ids the service names for it, which is
        -- what most cases want; a function stays available for the ones that
        -- need to inspect the request itself.
        local ok, body = json.parse(req.body)
        local result = {}
        for _, input in ipairs(ok and as_list(body.software) or {}) do
          local ids = opts.smart[input]
          if ids then
            local vulns = {}
            for _, id in ipairs(ids) do
              vulns[#vulns + 1] = {id = id, type = "cve"}
            end
            result[#result + 1] = {input = input, cpe = nil, confidence = 50,
                                   vulnerabilities = vulns}
          end
        end
        return t.response({status = 200,
                           body = json.generate({result = result})})
      end
      return t.response({status = 200, body = json.generate({result = {}})})
    end

    t.fail("unexpected request to " .. tostring(req.path))
  end
end

local function ids_of(rows)
  local out = {}
  for _, row in ipairs(rows or {}) do out[#out + 1] = row.id end
  return out
end

local function by_id(rows)
  local out = {}
  for _, row in ipairs(rows or {}) do out[row.id] = row end
  return out
end

--- The group keys of a result, past the schema and mode elems 2.0 adds.
local function group_keys(order)
  local keys = {}
  for _, key in ipairs(order or {}) do
    if key ~= "schema" and key ~= "mode" then keys[#keys + 1] = key end
  end
  return keys
end

local function port_with_cpe()
  return t.port({product = "OpenSSH", version = "7.4", cpe = {CPE}})
end

--- A port carrying the CPE and nothing else.
--
-- Kept because it keeps a case about one endpoint. It is no longer needed to
-- avoid audit/smart: a port that carries a CPE never reaches the billed call at
-- all, whatever else it carries. The case below is what says so.
local function port_cpe_only()
  return t.port({cpe = {CPE}})
end

local suite = {}

-- ------------------------------------------------------------- key handling

suite[#suite + 1] = {
  name = "a keyless run falls back to the free path and says so once",
  fn = function()
    -- B2: 1.x answered a missing key with silence, so a user with no key got
    -- strictly nothing. 2.0 owes them the free path plus one notice.
    local env, http = keyless()
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"}, "a keyless run still reports")
    t.equals(plain.mode, "free", "and says which path produced it")
    t.length(http.matching(SEARCH_ID), 0, "enrichment needs a token")
    for _, request in ipairs(http.requests) do
      t.is_nil(request.options.header["X-Api-Key"], "there is no key to send")
    end

    env.SCRIPT_TYPE = "postrule"
    local structured, notice = env.action()
    t.is_nil(structured, "the notice is text, not a finding")
    t.matches(notice, "Ran without an API key")
    t.matches(notice, "https://vulners%.com/userinfo")
  end,
}

suite[#suite + 1] = {
  name = "the API key is sent to search/id and never on the burp request",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local enrichment = http.matching(SEARCH_ID)
    t.length(enrichment, 1, "a keyed run must enrich its findings")
    t.equals(enrichment[1].options.header["X-Api-Key"], KEY)

    -- A keyed burp GET is answered cf-cache-status DYNAMIC, an unkeyed one is
    -- cached for four hours, and the key buys nothing there.
    local burp = http.matching(BURP)
    t.length(burp, 1)
    t.is_nil(burp[1].options.header["X-Api-Key"],
      "sending the key would take every user off the shared CDN cache")
  end,
}

suite[#suite + 1] = {
  name = "the API key can come from the environment",
  fn = function()
    local env, http = keyed({token = "ENV-FAKE-KEY"})
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local enrichment = http.matching(SEARCH_ID)
    t.length(enrichment, 1, "VULNERS_API_KEY must be picked up")
    t.equals(enrichment[1].options.header["X-Api-Key"], "ENV-FAKE-KEY")
  end,
}

suite[#suite + 1] = {
  name = "the API key can come from a file",
  fn = function()
    -- io is faked, so the path is a name the test declares rather than a file
    -- on disk; a real path here would read whatever the developer keeps there.
    local keyfile = "/etc/nmap/vulners-test.key"
    local env, http = keyed({
      token = false,
      args = {["vulners_enterprise.api_key_file"] = keyfile},
      files = {[keyfile] = KEY .. "\n"},
    })
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local enrichment = http.matching(SEARCH_ID)
    t.length(enrichment, 1, "api_key_file must be read")
    t.equals(enrichment[1].options.header["X-Api-Key"], KEY)
  end,
}

suite[#suite + 1] = {
  name = "a key file that cannot be read stops the run without crashing",
  fn = function()
    -- An operator who NAMES a file means that file: falling back to the free
    -- path here would hide a typo in the path for the whole scan. The same
    -- rule the sweep applies to a named paths file.
    local env, http = keyless({
      args = {["vulners_enterprise.api_key_file"] = "/etc/nmap/absent.key"},
    })
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    t.is_nil(t.no_error(function() return env.action(t.host(), port_with_cpe()) end,
      "an unreadable key file must not raise"))
    t.length(http.requests, 0, "and the run asks nothing at all")
  end,
}

suite[#suite + 1] = {
  name = "the API key never reaches the debug log",
  fn = function()
    -- load_vulners cannot fake stdnse, so the hermetic load is spelled out here
    -- with the recording double added: nmap -d output travels in bug reports.
    local http = t.http_double()
    local logger = t.stdnse_double()
    local env = t.load_script(root .. "/vulners.nse", {
      args = {["vulners.paths"] = "none"},
      modules = {
        http = http,
        nmap = t.nmap_double(),
        os = t.os_double({VULNERS_API_KEY = KEY}),
        io = t.io_double(),
        stdnse = logger,
      },
    })
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local log = logger.log()
    t.matches(log, "Api key is set %(%d+ characters%)",
      "the script must log that it has a key, so this case cannot pass on silence")
    t.is_nil(log:find(KEY, 1, true),
      "the key itself must not be written to debug output")
  end,
}

-- ---------------------------------------------------------------- endpoints

suite[#suite + 1] = {
  name = "a CPE lookup goes to the free burp endpoint, not the v4 audit",
  fn = function()
    -- B5: the batched POST /api/v4/audit/software/ is on no default path any
    -- more. A CPE is asked about one identity per GET, and for free.
    local env, http = keyed()
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local burp = http.matching("/api/v3/burp/software/")
    t.length(burp, 1)
    t.equals(burp[1].method, "GET")

    local asked = query_args(burp[1].path)
    t.equals(asked.software, CPE)
    t.equals(asked.version, "7.4")
    t.equals(asked.type, "cpe")
    t.is_true(burp[1].path:find("software=" .. CPE, 1, true),
      "the CPE travels verbatim: the endpoint does not decode it")
  end,
}

suite[#suite + 1] = {
  name = "api_host and api_port are honoured",
  fn = function()
    local env, http = keyed({args = {
      ["vulners_enterprise.api_host"] = "vulners.internal",
      ["vulners_enterprise.api_port"] = 8443,
    }})
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local burp = http.matching(BURP)
    t.length(burp, 1)
    t.equals(burp[1].host, "vulners.internal")
    t.equals(burp[1].port, 8443)
  end,
}

suite[#suite + 1] = {
  name = "api_port given on the command line reaches http as a number",
  fn = function()
    -- nmap hands script arguments over as strings, and http.get() raises on a
    -- string port, which used to abort the script for anyone who set it.
    local env, http = keyed({args = {
      ["vulners_enterprise.api_host"] = "127.0.0.1",
      ["vulners_enterprise.api_port"] = "8443",
    }})
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local burp = http.matching(BURP)
    t.length(burp, 1)
    t.equals(type(burp[1].port), "number", "the port must be a number")
    t.equals(burp[1].port, 8443)
  end,
}

suite[#suite + 1] = {
  name = "an unusable api_port falls back to 443",
  fn = function()
    local env, http = keyed({args = {["vulners_enterprise.api_port"] = "not-a-port"}})
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}}})

    env.action(t.host(), port_with_cpe())

    local burp = http.matching(BURP)
    t.length(burp, 1)
    t.equals(burp[1].port, 443, "garbage must not break the default")
  end,
}

-- -------------------------------------------------------------- scan caching

suite[#suite + 1] = {
  name = "software already looked up in this scan is not asked about again",
  fn = function()
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}},
      docs = {["CVE-2023-38408"] = {id = "CVE-2023-38408", type = "cve",
                                    bulletinFamily = "NVD"}},
    })

    local first = t.collect_output(env.action(t.host({ip = "10.0.0.1"}), port_with_cpe()))
    local burp_after_first = #http.matching(BURP)
    local enrich_after_first = #http.matching(SEARCH_ID)
    t.is_true(burp_after_first > 0 and enrich_after_first > 0,
      "the first host must have asked, or the comparison below compares nothing")

    local second = t.collect_output(env.action(t.host({ip = "10.0.0.2"}), port_with_cpe()))

    t.equals(#http.matching(BURP), burp_after_first,
      "the second host must be served from the scan cache")
    t.equals(#http.matching(SEARCH_ID), enrich_after_first,
      "and its ids are already enriched")
    t.same(ids_of(second[CPE]), ids_of(first[CPE]),
      "and it must still get the same answer")
  end,
}

suite[#suite + 1] = {
  name = "every nginx vendor spelling is asked about and the answers merge",
  fn = function()
    -- The service answers the three spellings with very different amounts of
    -- data, so all three are asked. Discovery is free, so this costs nothing.
    local env, http = keyed()
    serve(http, {software = {
      ["cpe:/a:nginx:nginx:1.13.4"] = {bulletin({id = "CVE-2018-16843", cvss = 7.5})},
      ["cpe:/a:igor_sysoev:nginx:1.13.4"] = {bulletin({id = "CVE-2009-2629", cvss = 9.0})},
    }})

    local port = t.port({product = "nginx", version = "1.13.4",
      cpe = {"cpe:/a:nginx:nginx:1.13.4"}})
    local plain, order = t.collect_output(env.action(t.host(), port))

    local asked = {}
    for _, request in ipairs(http.matching(BURP)) do
      asked[query_args(request.path).software] = true
    end
    t.is_true(asked["cpe:/a:f5:nginx:1.13.4"], "the f5 spelling must be queried")
    t.is_true(asked["cpe:/a:nginx:nginx:1.13.4"], "the nginx:nginx spelling must be queried")
    t.is_true(asked["cpe:/a:igor_sysoev:nginx:1.13.4"],
      "the igor_sysoev spelling must be queried")

    t.length(group_keys(order), 1, "both answers belong to one result key")
    t.same(ids_of(plain["cpe:/a:nginx:nginx:1.13.4"]),
      {"CVE-2009-2629", "CVE-2018-16843"}, "merged results stay sorted by CVSS")
  end,
}

suite[#suite + 1] = {
  name = "a CPE the sweep repeats is looked up once",
  fn = function()
    -- The sweep and nmap's own -sV routinely name the same software; asking
    -- twice would double the request count of every real scan.
    local env, http = keyed({paths = {"/"}})
    serve(http, {
      pages = {["/"] = {header = {["X-Powered-By"] = "PHP/5.6.38"}}},
      software = {["cpe:/a:php:php:5.6.38"] =
        {bulletin({id = "CVE-2019-11043", cvss = 9.8})}},
    })

    local host = t.host()
    local port = t.port({product = "PHP", version = "5.6.38",
      cpe = {"cpe:/a:php:php:5.6.38"}})
    local plain = t.collect_output(env.action(host, port))

    -- Without this the case would pass on a sweep that found nothing at all,
    -- which is the failure mode this whole migration exists to prevent.
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:php:php:5.6.38",
      "the sweep must have produced the duplicate in the first place")
    t.length(http.matching(BURP), 1, "the duplicate must be dropped before asking")
    t.same(ids_of(plain["cpe:/a:php:php:5.6.38"]), {"CVE-2019-11043"})
  end,
}

suite[#suite + 1] = {
  name = "a bulletin answered for two nginx spellings is reported once",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {
      ["cpe:/a:nginx:nginx:1.13.4"] = {bulletin({id = "CVE-2018-16843", cvss = 7.5})},
      ["cpe:/a:igor_sysoev:nginx:1.13.4"] = {bulletin({id = "CVE-2018-16843", cvss = 7.5})},
    }})

    local port = t.port({product = "nginx", version = "1.13.4",
      cpe = {"cpe:/a:nginx:nginx:1.13.4"}})
    local plain, order = t.collect_output(env.action(t.host(), port))

    local keys = group_keys(order)
    t.length(keys, 1, "one product means one result key")
    t.same(ids_of(plain[keys[1]]), {"CVE-2018-16843"},
      "the shared bulletin is not printed twice")
  end,
}

suite[#suite + 1] = {
  name = "a failed lookup is not remembered as an empty answer",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {
      ["cpe:/a:isc:bind:9.8.2"] = {bulletin({id = "CVE-2012-1667", cvss = 8.5})},
    }})
    local healthy = http.handler
    http.handler = function() return t.response({status = 500, body = ""}) end

    local port = port_cpe_only()
    port.version.cpe = {"cpe:/a:isc:bind:9.8.2"}
    t.is_nil(env.action(t.host(), port), "the failing lookup reports nothing")

    http.handler = healthy
    local plain = t.collect_output(env.action(t.host({ip = "127.0.0.2"}), port))
    t.same(ids_of(plain["cpe:/a:isc:bind:9.8.2"]), {"CVE-2012-1667"},
      "the next host asks again and gets the answer")
  end,
}

suite[#suite + 1] = {
  name = "versions differing only in the update part are cached apart",
  fn = function()
    -- nmap reports both "7.4" and "7.4p1"; a cache key without the update part
    -- let whichever was scanned first stand for the other.
    local env, http = keyed()
    serve(http, {software = {
      ["cpe:/a:openbsd:openssh:7.4p1"] = {bulletin({id = "CVE-2016-10009", cvss = 7.5})},
      ["cpe:/a:openbsd:openssh:7.4"] = {bulletin({id = "CVE-2018-15473", cvss = 5.3})},
    }})

    local first = t.collect_output(env.action(t.host(),
      t.port({version = "7.4p1", cpe = {"cpe:/a:openbsd:openssh:7.4p1"}})))
    local second = t.collect_output(env.action(t.host({ip = "127.0.0.2"}),
      t.port({version = "7.4", cpe = {"cpe:/a:openbsd:openssh:7.4"}})))

    t.same(ids_of(first["cpe:/a:openbsd:openssh:7.4p1"]), {"CVE-2016-10009"},
      "the update-suffixed version gets its own answer")
    t.same(ids_of(second["cpe:/a:openbsd:openssh:7.4"]), {"CVE-2018-15473"},
      "the plain version is not served the other one's answer")
  end,
}

suite[#suite + 1] = {
  name = "two nginx spellings on one port are reported under a single key",
  fn = function()
    -- nmap's own probe emits the igor_sysoev spelling; the sweep's Server
    -- header pattern emits the f5 one. They are one product and one finding.
    local env, http = keyed({paths = {"/"}})
    serve(http, {
      pages = {["/"] = {header = {["Server"] = "nginx/1.13.4"}}},
      software = {["cpe:/a:f5:nginx:1.13.4"] =
        {bulletin({id = "CVE-2018-16843", cvss = 7.5})}},
    })

    local host = t.host()
    local port = t.port({product = "nginx", version = "1.13.4",
      cpe = {"cpe:/a:igor_sysoev:nginx:1.13.4"}})
    local plain, order = t.collect_output(env.action(host, port))

    -- Both spellings have to be on the port before "reported once" means
    -- anything: a sweep that found nothing would pass this case for free.
    t.contains(port.version.cpe, "cpe:/a:igor_sysoev:nginx:1.13.4")
    t.contains(port.version.cpe, "cpe:/a:f5:nginx:1.13.4",
      "the sweep must have published its own spelling onto the port")

    local keys = group_keys(order)
    t.length(keys, 1, "one product must not be reported twice")
    t.same(ids_of(plain[keys[1]]), {"CVE-2018-16843"},
      "and the one key carries the merged answer")
  end,
}

suite[#suite + 1] = {
  name = "an exploit referenced by several vulnerabilities is listed once",
  fn = function()
    -- 2.0 inverts the 1.x direction: the exploit document carries the cvelist,
    -- and the flag travels outwards from it onto the CVEs it exploits.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {
        bulletin({id = "CVE-2023-38408", cvss = 9.8}),
        bulletin({id = "CVE-2018-15473", cvss = 5.3}),
        bulletin({id = "PACKETSTORM:142013", type = "packetstorm", family = "exploit"}),
      }},
      docs = {["PACKETSTORM:142013"] = {
        id = "PACKETSTORM:142013", type = "packetstorm", bulletinFamily = "exploit",
        cvelist = {"CVE-2023-38408", "CVE-2018-15473"},
      }},
    })

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    local count = 0
    for _, row in ipairs(plain[CPE]) do
      if row.id == "PACKETSTORM:142013" then count = count + 1 end
    end
    t.equals(count, 1, "the same exploit must not be printed twice")

    local rows = by_id(plain[CPE])
    t.equals(rows["CVE-2023-38408"].exploit_known, "true",
      "the exploit's cvelist marks the CVEs it exploits")
    t.equals(rows["CVE-2018-15473"].exploit_known, "true")
  end,
}

-- -------------------------------------------------------------------- output

suite[#suite + 1] = {
  name = "vulnerabilities are reported sorted by CVSS",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {[CPE] = {
      bulletin({id = "CVE-2018-15473", cvss = 5.3}),
      bulletin({id = "CVE-2023-38408", cvss = 9.8}),
    }}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    -- Neither is exploited, so both land in the last ranking bucket, where the
    -- tie-break is still CVSS descending.
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408", "CVE-2018-15473"})
  end,
}

suite[#suite + 1] = {
  name = "cvss version is reported alongside the score",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8,
      cvss_version = "3.1"})}}})

    local output, text = env.action(t.host(), port_with_cpe())
    local plain = t.collect_output(output)
    local row = plain[CPE][1]

    t.equals(row.cvss, "9.8", "the score reaches the structured output")
    t.equals(row.cvss_type, "cvss3.1")
    -- O5: the score now lives in a column of an aligned table, not in a
    -- "cvss3.1: 9.8" fragment glued into a text line.
    t.matches(text, "SEVERITY  CVSS", "the table has a CVSS column")
    t.matches(text, "CRITICAL   9%.8", "and the score is in it")
  end,
}

suite[#suite + 1] = {
  name = "a score without a cvss version does not crash the run",
  fn = function()
    -- Regression: the live API returns such records, and building the label by
    -- concatenation aborted the whole script.
    local env, http = keyed()
    serve(http, {software = {[CPE] =
      {bulletin({id = "CNVD-2018-22805", cvss_unversioned = 7.8})}}})

    local output, text = t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "a cvss block without a version must not raise")
    local plain = t.collect_output(output)

    t.is_true(plain and plain[CPE], "the vulnerability must still be reported")
    t.equals(plain[CPE][1].cvss, "7.8")
    t.is_nil(plain[CPE][1].cvss_type, "no version means no label")
    t.matches(text, "CNVD%-2018%-22805", "and it still renders")
  end,
}

suite[#suite + 1] = {
  name = "a document scored NONE is reported without a score",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {[CPE] =
      {bulletin({id = "VULNERS:UNSCORED", cvss_none = true})}}})

    local output, text = t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "an unscored document must not raise")
    local plain = t.collect_output(output)

    t.is_true(plain and plain[CPE], "the document must still be reported")
    t.is_nil(plain[CPE][1].cvss, "and it must carry no score")
    t.equals(plain[CPE][1].severity, "Unknown",
      "severity is emitted on every row, unlike cvss")
    -- Nothing but whitespace between the severity word and the link means the
    -- CVSS column was left blank rather than filled with a fabricated 0.0.
    t.matches(text, "Unknown%s+https://vulners%.com/cve/VULNERS:UNSCORED")
  end,
}

suite[#suite + 1] = {
  name = "exploits are listed as their own rows and flagged",
  fn = function()
    local env, http = keyed()
    serve(http, {software = {[CPE] = {
      bulletin({id = "CVE-2023-38408", cvss = 9.8}),
      bulletin({id = "F0979183-AE88-53B4-86CF-3AF0523F3807",
                type = "githubexploit", family = "exploit"}),
    }}})

    local output, text = env.action(t.host(), port_with_cpe())
    local plain = t.collect_output(output)

    t.length(plain[CPE], 2, "the cve and its exploit are separate rows")
    local exploit_row = plain[CPE][1]
    t.equals(exploit_row.id, "F0979183-AE88-53B4-86CF-3AF0523F3807",
      "an exploit outranks an unexploited 9.8")
    t.equals(exploit_row.type, "githubexploit")
    t.equals(exploit_row.is_exploit, "true")
    t.equals(plain[CPE][2].id, "CVE-2023-38408", "the cve itself stays in the report")
    -- O5: *EXPLOIT* and *HAS EXPLOIT* are gone; the marker is a fixed-width
    -- token in the FLAGS column.
    t.matches(text, "EXP%s+https://vulners%.com/githubexploit/F0979183", "the user must see the exploit marker")
  end,
}

suite[#suite + 1] = {
  name = "a KEV flag on an exploit reaches the CVEs it exploits",
  fn = function()
    -- adp.kev is the CVE Program's own container and arrives on the EXPLOIT
    -- record, so reading it only off CVE documents would lose every hit. It is
    -- attributed onwards through cvelist.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {
        bulletin({id = "CVE-2023-38408", cvss = 9.8}),
        bulletin({id = "PACKETSTORM:142013", type = "packetstorm", family = "exploit"}),
      }},
      docs = {["PACKETSTORM:142013"] = {
        id = "PACKETSTORM:142013", type = "packetstorm", bulletinFamily = "exploit",
        cvelist = {"CVE-2023-38408"},
        metrics = {adp = {kev = {dateAdded = "2023-09-13"}}},
      }},
    })

    local output, text = env.action(t.host(), port_with_cpe())
    local rows = by_id(t.collect_output(output)[CPE])

    t.equals(rows["CVE-2023-38408"].kev, "true",
      "CISA listed the CVE, and the listing rode in on the exploit record")
    t.equals(rows["CVE-2023-38408"].exploit_known, "true")
    t.matches(text, "KEV EXP  https://vulners%.com/cve/CVE%-2023%-38408",
      "both flags share one greppable column")
  end,
}

suite[#suite + 1] = {
  name = "href is the vulners page and the endpoint's own href travels beside it",
  fn = function()
    -- Measured against the live service: the enrich endpoint's href is the
    -- UPSTREAM address - web.nvd.nist.gov for a cve, www.exploit-db.com for an
    -- exploitdb entry - and the free endpoint sends no href at all, on any of
    -- 272 rows for one real CPE. Publishing that under href would have made the
    -- meaning of the field depend on which mode produced the report.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {
        bulletin({id = "CVE-2023-38408", cvss = 9.8}),
        bulletin({id = "EDB-ID:45233", type = "exploitdb", family = "exploit"}),
      }},
      docs = {
        ["CVE-2023-38408"] = {
          id = "CVE-2023-38408", type = "cve", bulletinFamily = "NVD",
          href = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2023-38408",
        },
        ["EDB-ID:45233"] = {
          id = "EDB-ID:45233", type = "exploitdb", bulletinFamily = "exploit",
          href = "https://www.exploit-db.com/exploits/45233",
        },
      },
    })

    local output, text = env.action(t.host(), port_with_cpe())
    local rows = by_id(t.collect_output(output)[CPE])

    t.equals(rows["CVE-2023-38408"].href, "https://vulners.com/cve/CVE-2023-38408",
      "href is the vulners page, composed from the type and the id")
    t.equals(rows["CVE-2023-38408"].source_href,
      "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2023-38408",
      "and what the endpoint called href is published as what it is")
    t.equals(rows["EDB-ID:45233"].href, "https://vulners.com/exploitdb/EDB-ID:45233",
      "the same for an exploit, whose page is under its own type")

    t.matches(text, "https://vulners%.com/cve/CVE%-2023%-38408",
      "the rendered table links to vulners, on every row")
    t.is_nil(text:match("nvd%.nist%.gov"), "and never to the upstream page")
  end,
}

suite[#suite + 1] = {
  name = "exploits are shown even when they score below mincvss",
  fn = function()
    local env, http = keyed({args = {["vulners_enterprise.mincvss"] = "9.0"}})
    -- The free endpoint scores exploit bulletins 0, which is not a score.
    serve(http, {software = {[CPE] = {
      bulletin({id = "CVE-2018-15473", cvss = 5.3}),
      bulletin({id = "EDB-ID:45233", type = "exploitdb", family = "exploit"}),
    }}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.is_true(plain and plain[CPE], "a working exploit outranks the score threshold")
    t.same(ids_of(plain[CPE]), {"EDB-ID:45233"},
      "the 5.3 cve itself is filtered out by mincvss=9.0")
  end,
}

suite[#suite + 1] = {
  name = "mincvss filters plain vulnerabilities",
  fn = function()
    local env, http = keyed({args = {["vulners_enterprise.mincvss"] = "7.0"}})
    serve(http, {software = {[CPE] = {
      bulletin({id = "CVE-2023-38408", cvss = 9.8}),
      bulletin({id = "CVE-2018-15473", cvss = 5.3}),
    }}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"}, "5.3 is below mincvss=7.0")
  end,
}

-- ------------------------------------------------------------- the billed leg

suite[#suite + 1] = {
  name = "a port with no CPE reaches audit/smart and its ids are resolved",
  fn = function()
    -- B1: the one billed call, and only for a service the free path could not
    -- name. The smart answer carries bare ids, which search/id then scores.
    local env, http = keyed()
    serve(http, {
      smart = function(req)
        local ok, body = json.parse(req.body)
        t.is_true(ok, "the smart body must be valid json")
        t.same(body.software, {"OpenSSH 7.4"},
          "the raw software label is what a credit buys an identity for")
        return t.response({status = 200, body = json.generate({result = {{
          input = body.software[1],
          cpe = "cpe:2.3:a:openbsd:openssh:7.4",
          confidence = 90,
          vulnerabilities = {{id = "CVE-2023-38408", type = "cve"}},
        }}})})
      end,
      docs = {["CVE-2023-38408"] = {id = "CVE-2023-38408", type = "cve",
        bulletinFamily = "NVD", cvss = {score = 9.8, version = "3.1"}}},
    })

    local port = t.port({product = "OpenSSH", version = "7.4", cpe = {}})
    local plain = t.collect_output(env.action(t.host(), port))

    t.length(http.matching(BURP), 0, "there is no CPE to ask the free endpoint about")
    t.length(http.matching(SMART), 1, "the smart endpoint must be used")
    t.length(http.matching(SEARCH_ID), 1, "smart ids need resolving")

    local group = plain["cpe:2.3:a:openbsd:openssh:7.4"]
    t.is_true(group, "the identity the service resolved is the group key")
    t.equals(group[1].id, "CVE-2023-38408")
    t.equals(group[1].cvss, "9.8", "the resolved score must be reported")
  end,
}

suite[#suite + 1] = {
  name = "enrichment is split into chunks of at most 100 ids",
  fn = function()
    local env, http = keyed()
    local rows, docs = {}, {}
    for i = 1, 150 do
      local id = string.format("CVE-2020-%04d", i)
      rows[#rows + 1] = bulletin({id = id, cvss = 5.0})
      docs[id] = {id = id, type = "cve", bulletinFamily = "NVD",
                  cvss = {score = 5.0, version = "3.1"}}
    end
    serve(http, {software = {[CPE] = rows}, docs = docs})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.length(http.matching(SEARCH_ID), 2, "150 ids must be split into two calls")
    t.length(plain[CPE], 150, "every resolved id must be reported")
  end,
}

suite[#suite + 1] = {
  name = "a pool past two chunks enriches every id exactly once",
  fn = function()
    -- 201 is deliberately one past two full chunks: an off-by-one in the chunk
    -- loop loses a single id, which no count of calls would show.
    local env, http = keyed()
    local rows, docs, wanted = {}, {}, {}
    for i = 1, 201 do
      local id = string.format("CVE-2021-%04d", i)
      wanted[#wanted + 1] = id
      rows[#rows + 1] = bulletin({id = id, cvss = 5.0})
      docs[id] = {id = id, type = "cve", bulletinFamily = "NVD",
                  cvss = {score = 5.0, version = "3.1"}}
    end
    serve(http, {software = {[CPE] = rows}, docs = docs})

    env.action(t.host(), port_with_cpe())

    local calls = http.matching(SEARCH_ID)
    t.length(calls, 3, "201 ids need three calls")

    local seen = {}
    for _, call in ipairs(calls) do
      local ok, body = json.parse(call.body)
      t.is_true(ok)
      t.is_true(#body.id <= 100, "no chunk may exceed 100 ids")
      for _, id in ipairs(body.id) do
        t.is_nil(seen[id], "id " .. id .. " was enriched twice")
        seen[id] = true
      end
    end
    for _, id in ipairs(wanted) do
      t.is_true(seen[id], "id " .. id .. " was never enriched")
    end
  end,
}

-- ----------------------------------------------------------- error handling

suite[#suite + 1] = {
  name = "a bulletin missing every optional field does not crash the run",
  fn = function()
    -- Every field below the wire is somebody else's json: a record that omits
    -- what the renderer reads must skip the field, not take the scan down.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {{id = "CVE-2023-38408"}}},
      docs = {["CVE-2023-38408"] = {id = "CVE-2023-38408"}},
    })

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "a record without cvss, family or cvelist must not raise"))

    t.is_true(plain and plain[CPE], "the vulnerability must still be reported")
    t.equals(plain[CPE][1].severity, "Unknown")
  end,
}

suite[#suite + 1] = {
  name = "an API level error body does not crash the run",
  fn = function()
    local env, http = keyed()
    http.handler = function()
      -- Vulners reports business errors inside an HTTP 200 answer.
      return t.response({status = 200, body = json.generate({
        result = "error", data = {error = "quota exceeded", errorCode = 401},
      })})
    end

    t.is_nil(t.no_error(function() return env.action(t.host(), port_cpe_only()) end,
      "an error body must be handled"))
    t.is_true(#http.matching(BURP) > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "an unparsable body does not crash the run",
  fn = function()
    local env, http = keyed()
    http.handler = function()
      return t.response({status = 200, body = "<html>not json</html>"})
    end

    t.is_nil(t.no_error(function() return env.action(t.host(), port_cpe_only()) end,
      "a broken body must be handled"))
    t.is_true(#http.matching(BURP) > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "a 4xx answer is not retried and degrades the scan to the free path",
  fn = function()
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}},
      handler = function(req)
        if type(req.host) == "string" and req.path:find(SEARCH_ID, 1, true) then
          return t.response({status = 403, body = "forbidden"})
        end
      end,
    })

    local plain = t.collect_output(env.action(t.host({ip = "10.0.0.1"}), port_with_cpe()))

    t.length(http.matching(SEARCH_ID), 1,
      "a rejected request will not fix itself by asking again")
    t.equals(plain.mode, "free", "a refused key drops the scan to the free path")
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"},
      "and the free findings still stand")

    env.action(t.host({ip = "10.0.0.2"}), port_with_cpe())
    t.length(http.matching(SEARCH_ID), 1,
      "the rest of the scan must not keep offering the refused key")
  end,
}

suite[#suite + 1] = {
  name = "a 401 mid-scan keeps reporting instead of silencing the script",
  fn = function()
    -- 1.x set one scan-wide "failed" flag, which in a merged script would
    -- silence the free path too: a user whose trial key expired would get
    -- strictly less than a user with no key at all, and silently.
    local env, http = keyed()
    serve(http, {
      software = {
        [CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})},
        ["cpe:/a:isc:bind:9.8.2"] = {bulletin({id = "CVE-2012-1667", cvss = 8.5})},
      },
      handler = function(req)
        if type(req.host) == "string" and req.path:find(SEARCH_ID, 1, true) then
          return t.response({status = 401, body = "unauthorized"})
        end
      end,
    })

    local first = t.collect_output(env.action(t.host({ip = "10.0.0.1"}), port_with_cpe()))
    t.same(ids_of(first[CPE]), {"CVE-2023-38408"},
      "the findings the free path produced survive a refused key")
    t.equals(first.mode, "free")

    local port = port_cpe_only()
    port.version.cpe = {"cpe:/a:isc:bind:9.8.2"}
    local second = t.collect_output(env.action(t.host({ip = "10.0.0.2"}), port))
    t.same(ids_of(second["cpe:/a:isc:bind:9.8.2"]), {"CVE-2012-1667"},
      "and the next host is still looked up")
    t.length(http.matching(SEARCH_ID), 1, "the refused key is not tried again")
  end,
}

suite[#suite + 1] = {
  name = "a 5xx answer is retried",
  fn = function()
    local env, http = keyed()
    http.handler = function() return t.response({status = 503, body = "busy"}) end

    t.is_nil(env.action(t.host(), port_cpe_only()))
    t.is_true(#http.matching(BURP) > 1,
      "a transient server error deserves another try")
  end,
}

suite[#suite + 1] = {
  name = "a 429 answer is retried and the Retry-After hint is read",
  fn = function()
    local env, http = keyed()
    local attempts = 0
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2023-38408", cvss = 9.8})}},
      handler = function(req)
        if type(req.host) == "string" and req.path:find(BURP, 1, true) then
          attempts = attempts + 1
          if attempts == 1 then
            return t.response({status = 429, header = {["retry-after"] = "1"},
                               body = "slow down"})
          end
        end
      end,
    })

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.is_true(attempts >= 2, "a rate-limited request must be retried")
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"},
      "and the retry result must be reported")
  end,
}

suite[#suite + 1] = {
  name = "an unreachable API is retried, then left alone for the rest of the scan",
  fn = function()
    local env, http = keyed()
    http.handler = function() return nil end

    t.is_nil(env.action(t.host({ip = "10.0.0.1"}), port_cpe_only()))
    local attempts = #http.matching(BURP)
    t.is_true(attempts > 1, "one failed attempt must not be the end of it")

    -- A dead API must not be hammered once per host of a network.
    t.is_nil(env.action(t.host({ip = "10.0.0.2"}), port_cpe_only()))
    t.equals(#http.matching(BURP), attempts,
      "after giving up, the rest of the scan must not keep trying")
  end,
}

-- ------------------------------------------------------- defensive behaviour

suite[#suite + 1] = {
  name = "a port without a version table is swept and reported without crashing",
  fn = function()
    -- shortport.http admits a port nmap never version-scanned, so publish_cpes
    -- has to build the version table it writes into rather than assume one.
    local env, http = keyed({paths = {"/"}})
    serve(http, {
      pages = {["/"] = {header = {["Server"] = "nginx/1.13.4"}}},
      software = {["cpe:/a:f5:nginx:1.13.4"] =
        {bulletin({id = "CVE-2018-16843", cvss = 7.5})}},
    })

    local host = t.host()
    local port = t.port({version = false})
    local output = t.no_error(function() return env.action(host, port) end,
      "a port without a version table must not raise")
    local plain = t.collect_output(output)

    t.same(ids_of(plain["cpe:/a:f5:nginx:1.13.4"]), {"CVE-2018-16843"},
      "what the sweep found must still be looked up")
    t.equals(plain["cpe:/a:f5:nginx:1.13.4"][1].found_on, "/",
      "and carry the path it was found on")
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "the finding is published for the rest of the scan")
  end,
}

suite[#suite + 1] = {
  name = "a version without a product name does not crash the software lookup",
  fn = function()
    local env, http = keyed()
    -- A catch-all: anything reaching the API here is itself the defect.
    http.handler = function()
      return t.response({status = 200, body = json.generate({result = {}})})
    end

    local port = t.port({product = nil, version = "7.4", cpe = {}})
    t.no_error(function() return env.action(t.host(), port) end,
      "a missing product name must not raise")
    t.length(http.requests, 0,
      "half an identity is not a software label, so there is nothing to buy")
  end,
}

suite[#suite + 1] = {
  name = "a port whose CPE resolved to nothing costs no credit",
  fn = function()
    local env, http = keyed()
    -- No entry for this CPE, so the double answers result="warning" with
    -- matched_cpe echoing search_cpe: the endpoint resolved the identity and
    -- knows nothing about it. The port also has a product and a version, so a
    -- software label exists.
    serve(http, {software = {}})

    local result = env.action(t.host(), port_with_cpe())

    t.is_nil(result, "a clean port reports nothing")
    t.length(http.matching(SMART), 0,
      "\"clean\" is an answer, and the free endpoint was measured to give the " ..
      "same one the paid endpoint gives - so identifying a fully patched " ..
      "service must not cost a credit. Gating this on \"nothing was found\" " ..
      "instead of \"no CPE at all\" billed every well maintained host, which " ..
      "is precisely backwards")
    t.is_true(#http.matching(BURP) > 0,
      "the free lookup still happened")
  end,
}

suite[#suite + 1] = {
  name = "the keyless notice counts only services that had no identity",
  fn = function()
    local env, http = keyless()
    serve(http, {software = {}})

    -- Same port: a CPE that resolved to nothing. It was identified perfectly
    -- well, so telling the user a key would have named it is false.
    env.action(t.host(), port_with_cpe())
    t.equals(env._TEST.state().unnamed, 0,
      "a resolved-but-clean CPE is not an unnamed service")

    t.reset_registry()
    local env2, http2 = keyless()
    serve(http2, {software = {}})
    -- No CPE at all, only a banner: this one really had no usable identity.
    env2.action(t.host(), t.port({product = "Frobnicator", version = "1.0",
                                  cpe = {}}))
    t.equals(env2._TEST.state().unnamed, 1,
      "a service with no CPE is what the notice is counting")
  end,
}

suite[#suite + 1] = {
  name = "the token never travels to a host that is not https or loopback",
  fn = function()
    -- http.get/http.post without options.scheme route through comm.tryssl,
    -- which tries PLAINTEXT FIRST for any port outside its likely-SSL list -
    -- probed, 8080 and 9999 do. So --script-args api_port=8080 used to put the
    -- token on the wire in the clear, to a host the operator named.
    local env, http = keyed({args = {["vulners.api_host"] = "vulners.example",
                                     ["vulners.api_port"] = "8080"}})
    serve(http, {software = {[CPE] = {bulletin({id = "CVE-2021-1", cvss = 9.8})}}})
    env.action(t.host(), port_with_cpe())

    t.is_true(#http.requests > 0, "the scan still made requests")
    for _, req in ipairs(http.requests) do
      if type(req.host) ~= "table" then
        t.is_nil(req.options and req.options.header
                 and req.options.header["X-Api-Key"],
          "no request to a plaintext host may carry the token: " .. req.path)
        t.is_true(req.options and req.options.scheme ~= nil,
          "every API request states its scheme rather than letting comm guess")
      end
    end
  end,
}

suite[#suite + 1] = {
  name = "the token does travel on https, and to loopback for the test harness",
  fn = function()
    for _, case in ipairs({
      {host = "vulners.example", port = "443", why = "https"},
      {host = "127.0.0.1", port = "8080", why = "loopback"},
    }) do
      t.reset_registry()
      local env, http = keyed({args = {["vulners.api_host"] = case.host,
                                       ["vulners.api_port"] = case.port}})
      serve(http, {software = {[CPE] = {bulletin({id = "CVE-2021-1", cvss = 9.8})}},
                   docs = {["CVE-2021-1"] = {id = "CVE-2021-1", type = "cve"}}})
      env.action(t.host(), port_with_cpe())

      local seen = false
      for _, req in ipairs(http.matching(SEARCH_ID)) do
        seen = seen or (req.options.header["X-Api-Key"] == KEY)
      end
      t.is_true(seen, "the token must reach the keyed endpoint over " .. case.why)
    end
  end,
}

suite[#suite + 1] = {
  name = "an enrichment id whose owner never answered is taken over, not abandoned",
  fn = function()
    local env, http, clock = keyed_with_clock()
    serve(http, {docs = {["CVE-2012-1667"] = {id = "CVE-2012-1667", type = "cve",
                                              title = "taken over"}}})
    env._TEST.config()

    -- Another port claimed this id and died with the claim. The design says a
    -- claim whose owner died is re-claimed after the timeout; it was not, so
    -- every other port lost its enrichment for that id for the whole scan.
    env._TEST.state().claimed["CVE-2012-1667"] = true
    env._TEST.enrich({"CVE-2012-1667"})

    t.is_true(clock.slept >= 29 and clock.slept <= 40, string.format(
      "the wait must be bounded, slept %.1fs", clock.slept))
    t.is_true(#http.matching(SEARCH_ID) > 0,
      "after the bound the id is fetched rather than given up on")
    t.is_true(env._TEST.state().docs["CVE-2012-1667"] ~= nil,
      "and the document reaches the cache")
    -- The dead owner's claim is released too, or every later port waits the same
    -- bound for the same absent owner.
    t.is_nil(env._TEST.state().claimed["CVE-2012-1667"],
      "the stale claim is released")
  end,
}

suite[#suite + 1] = {
  name = "an id another port already enriched costs no wait and no request",
  fn = function()
    local env, http, clock = keyed_with_clock()
    serve(http, {})
    env._TEST.config()
    env._TEST.state().docs["CVE-2012-1667"] = {id = "CVE-2012-1667", type = "cve"}

    env._TEST.enrich({"CVE-2012-1667"})

    t.equals(clock.sleeps, 0, "a cached document must not sleep")
    t.length(http.matching(SEARCH_ID), 0, "nor be fetched again")
  end,
}

suite[#suite + 1] = {
  name = "a degrade survives into the next port's chunk execution",
  fn = function()
    -- The chunk runs once per OPEN port, so the only faithful way to model a
    -- second port is to load the script again against the same registry. Doing
    -- it in one load is what let this ship: config() re-ran its
    -- state().mode = "keyed" side effect on every port and undid the degrade.
    local function serve_dead_key(http)
      http.handler = function(req)
        if req.path:find(BURP, 1, true) then
          return t.response({status = 200, body = json.generate({
            result = "OK",
            data = {search = {{_source = bulletin({id = "CVE-2017-15906",
                                                   cvss = 5.3})}},
                    search_explain = {}},
          })})
        end
        return t.response({status = 401, body = json.generate({
          result = "error", data = {error = "Unknown api key", errorCode = 157},
        })})
      end
    end

    local port = t.port({number = 22, service = "ssh",
                         product = "OpenSSH", version = "7.4", cpe = {}})

    local first, first_http = keyed()
    serve_dead_key(first_http)
    first.action(t.host(), port)
    t.equals(first._TEST.state().mode, "free", "the rejected key degrades the scan")

    local second, second_http = keyed()
    serve_dead_key(second_http)
    local result = second.action(t.host(), port)

    t.equals(second._TEST.state().mode, "free",
      "and the degrade is still in force on the next port")
    t.is_true(result ~= nil,
      "a port after the degrade still reports what the free path found - " ..
      "without this it reported nothing at all, which is strictly less than " ..
      "a user with no key at all would have got")
    t.is_true(#second_http.matching(BURP) > 0,
      "because the free lookup runs again")
  end,
}

suite[#suite + 1] = {
  name = "a string already bought is not bought again",
  fn = function()
    -- The only BILLED call was the only one with no cache, so a network of
    -- identical appliances paid once per host for one answer.
    local env, http = keyed()
    serve(http, {smart = {["Frobnicator 1.0"] = {"CVE-2021-1"}}})

    local port = t.port({number = 9999, service = "unknown",
                         product = "Frobnicator", version = "1.0", cpe = {}})
    for _ = 1, 4 do
      env.action(t.host(), port)
    end

    t.length(http.matching(SMART), 1,
      "four identical hosts must cost one credit, not four")
    t.equals(env._TEST.state().spent, 1, "and the spend must say so")
  end,
}

suite[#suite + 1] = {
  name = "a billed call that never answers is not re-sent",
  fn = function()
    -- "Billing happens on a 200, so a retried 5xx cannot double-charge" is
    -- sound for a 5xx, where the client saw the verdict. It is not sound for a
    -- timeout: the service may have completed and charged while we gave up.
    local env, http = keyed()
    http.handler = function(req)
      if req.path:find(SMART, 1, true) then
        return nil
      end
      return t.response({status = 200, body = json.generate({
        result = "warning", data = {search_explain = {}},
      })})
    end

    env.action(t.host(), t.port({number = 9999, service = "unknown",
                                 product = "Frobnicator", version = "1.0",
                                 cpe = {}}))

    t.length(http.matching(SMART), 1,
      "a billed call is attempted once when the answer never arrives")
  end,
}

suite[#suite + 1] = {
  name = "reaching the spending ceiling does not switch off free enrichment",
  fn = function()
    -- search/id needs the token and costs nothing, so a BUDGET limit must not
    -- withdraw a FREE feature from every later host.
    local env, http = keyed({args = {["vulners.max_items"] = "1"}})
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2012-1667", cvss = 8.5})}},
      docs = {["CVE-2012-1667"] = {id = "CVE-2012-1667", type = "cve",
                                   title = "still enriched"}},
      smart = {["Frobnicator 1.0"] = {"CVE-2021-1"}},
    })

    -- Two unnamed ports running DIFFERENT software, so the second really is
    -- over the ceiling. Scanning the same product twice tests the cache
    -- instead: the second port costs nothing, so nothing stops it, and the
    -- assertion below then passes for a reason it does not name.
    for _, product in ipairs({"Frobnicator", "Widgetron"}) do
      env.action(t.host(), t.port({number = 9999, service = "unknown",
                                   product = product, version = "1.0",
                                   cpe = {}}))
    end
    t.is_true(env._TEST.state().billing_off, "the ceiling stops the spending")
    t.equals(env._TEST.state().mode, "keyed",
      "but the token is still in use: the ceiling is a budget, not a rejection")

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    local rows = plain and plain[CPE]
    t.is_true(rows ~= nil and rows[1] ~= nil, "a later port still reports")
    t.equals(rows[1].title, "still enriched",
      "and is still enriched, because enrichment was never what cost anything")
  end,
}


-- ------------------------------------------------------------- the wallet
--
-- The balance is only ever learnable from a previous billed call's header, so
-- every guard that reads it is unreachable until the SECOND billed call of a
-- scan. Until these cases existed no test made two, and no test sent the wallet
-- headers at all - so the entire ladder ran only in production.

--- A smart handler that answers with the wallet headers the service sends.
local function billing(opts)
  opts = opts or {}
  local answers = opts.answers or {}
  return function(req)
    local ok, body = json.parse(req.body)
    local result = {}
    for _, input in ipairs(ok and as_list(body.software) or {}) do
      local ids = answers[input]
      if ids then
        local vulns = {}
        for _, id in ipairs(ids) do
          vulns[#vulns + 1] = {id = id, type = "cve"}
        end
        result[#result + 1] = {input = input, confidence = 50,
                               vulnerabilities = vulns}
      end
    end
    local header = {}
    if opts.amount ~= nil then
      header["x-vulners-wallet-amount"] = tostring(opts.amount)
    end
    if opts.cost ~= nil then
      header["x-vulners-wallet-cost"] = tostring(opts.cost)
    end
    return t.response({status = 200, header = header,
                       body = json.generate({result = result})})
  end
end

--- A port carrying a product and version but no CPE, which is what reaches the
-- billed endpoint. Named and numbered off the web ports so nothing is swept.
local function unnamed_port(product, version, number)
  return t.port({product = product, version = version, cpe = {},
                 name = "unknown", service = "unknown", number = number})
end

local SMART_DOCS = {
  ["CVE-2023-38408"] = {id = "CVE-2023-38408", type = "cve",
    bulletinFamily = "NVD", cvss = {score = 9.8, version = "3.1"}},
  ["CVE-2011-2523"] = {id = "CVE-2011-2523", type = "cve",
    bulletinFamily = "NVD", cvss = {score = 9.8, version = "3.1"}},
}

suite[#suite + 1] = {
  name = "a second billed call still works once the balance is known",
  fn = function()
    local env, http = keyed()
    serve(http, {docs = SMART_DOCS, smart = billing({amount = 100, cost = 1,
      answers = {["OpenSSH 7.4"] = {"CVE-2023-38408"},
                 ["vsftpd 3.0.3"] = {"CVE-2011-2523"}}})})

    local host = t.host()
    env.action(host, unnamed_port("OpenSSH", "7.4", 22))
    t.equals(env._TEST.state().balance, 100,
      "the first billed answer must teach the scan its balance")

    local plain = t.collect_output(t.no_error(function()
      return env.action(host, unnamed_port("vsftpd", "3.0.3", 21))
    end, "a second billed call must not raise once the balance is known"))

    t.is_true(plain and plain["vsftpd 3.0.3"],
      "the second port's findings must still be reported")
    t.length(http.matching(SMART), 2, "both ports must reach the billed call")
  end,
}

suite[#suite + 1] = {
  name = "a wallet short of credits stops the billed calls and says so",
  fn = function()
    local env, http = keyed()
    serve(http, {docs = SMART_DOCS, smart = billing({amount = 0, cost = 1,
      answers = {["OpenSSH 7.4"] = {"CVE-2023-38408"}}})})

    local host = t.host()
    env.action(host, unnamed_port("OpenSSH", "7.4", 22))
    env.action(host, unnamed_port("vsftpd", "3.0.3", 21))

    t.length(http.matching(SMART), 1,
      "an empty wallet must stop the billed calls, not keep buying refusals")
    t.is_true(env._TEST.state().billing_off,
      "the scan must remember that identification stopped")

    env.SCRIPT_TYPE = "postrule"
    local _, text = env.action()
    t.matches(text, "short of credits",
      "and the report must say why it stopped")
  end,
}

suite[#suite + 1] = {
  name = "the first billed call is capped to learn the balance, then resumes",
  fn = function()
    -- COLD_START_ITEMS keeps the first billed call small purely to learn the
    -- balance. What it must NOT do is drop the identities that did not fit:
    -- the port had six unresolved CPEs and reported on five, blaming a ceiling
    -- the operator never set.
    local env, http = keyed()
    local sent = {}
    serve(http, {
      -- burp answers every CPE with a matched_cpe that is NOT the one asked
      -- about, which is how the service says "I could not resolve this" - the
      -- one thing that sends a CPE to the billed endpoint.
      handler = function(req)
        if type(req.host) ~= "table" and req.path:find(BURP, 1, true) then
          return t.response({status = 200, body = json.generate({
            result = "warning",
            data = {search_explain = {search_cpe = query_args(req.path).software,
                                      matched_cpe = "cpe:/a:other:other:1.0"}},
          })})
        end
      end,
      smart = function(req)
        local ok, body = json.parse(req.body)
        t.is_true(ok, "the smart body must be valid json")
        sent[#sent + 1] = #body.software
        return t.response({status = 200,
          header = {["x-vulners-wallet-amount"] = "100",
                    ["x-vulners-wallet-cost"] = tostring(#body.software)},
          body = json.generate({result = {}})})
      end,
    })

    local cpes = {}
    for i = 1, 6 do
      cpes[i] = string.format("cpe:/a:vendor%d:product%d:1.0", i, i)
    end
    env.action(t.host(), t.port({cpe = cpes, name = "unknown",
                                 service = "unknown", number = 4444}))

    t.same(sent, {5, 1},
      "the cold-start call is capped at five, and the sixth still goes out")
  end,
}


-- ------------------------------------------- what the credit decision reads
--
-- Every case below was written because a mutation of the script survived the
-- suite: the logic that decides whether a CPE costs a credit was described in
-- comments as hard-won, and measured by nothing.

local NGINX = "cpe:/a:f5:nginx:1.13.4"
local SPELLINGS = {"cpe:/a:f5:nginx:1.13.4", "cpe:/a:nginx:nginx:1.13.4",
                   "cpe:/a:igor_sysoev:nginx:1.13.4"}

--- Answer each nginx spelling however the case says, and count what smart got.
--
-- @param explains  spelling -> the search_explain to answer with, or the string
--                  "error" for a 200 whose envelope is not a clean answer
local function burp_explaining(http, explains, bought)
  http.handler = function(req)
    if type(req.host) == "table" then
      return t.response({status = 404})
    end
    if req.path:find(BURP, 1, true) then
      local asked = query_args(req.path).software
      local explain = explains[asked]
      if explain == "error" then
        -- A 200 whose envelope is not a clean answer: burp_lookup reports this
        -- as "not answered" without killing the free leg for the whole scan.
        return t.response({status = 200,
          body = json.generate({result = "error", data = "nope"})})
      end
      return t.response({status = 200, body = json.generate({
        result = "warning",
        data = explain and {search_explain = explain} or {},
      })})
    end
    if req.path:find(SMART, 1, true) then
      local ok, body = json.parse(req.body)
      for _, input in ipairs(ok and as_list(body.software) or {}) do
        bought[#bought + 1] = input
      end
      return t.response({status = 200, body = json.generate({result = {}})})
    end
    return t.response({status = 200,
      body = json.generate({result = "OK", data = {documents = {}}})})
  end
end

local function nginx_port()
  return t.port({number = 8081, service = "unknown", name = "unknown",
                 cpe = {NGINX}})
end

suite[#suite + 1] = {
  name = "one nginx spelling failing does not cost the identity its verdict",
  fn = function()
    -- A CPE is asked under three vendor spellings, and "did this identity
    -- resolve" is a question about the product, not about one spelling. A
    -- transient failure on the last one used to poison the answer, which
    -- skipped the credit decision entirely and reported an unidentifiable
    -- service as clean - silently, because the unnamed counter needs no CPE.
    local env, http = keyed()
    local bought = {}
    local unresolved = {search_cpe = "asked", matched_cpe = "something else"}
    burp_explaining(http, {
      [SPELLINGS[1]] = unresolved,
      [SPELLINGS[2]] = unresolved,
      [SPELLINGS[3]] = "error",
    }, bought)

    env.action(t.host(), nginx_port())

    t.contains(bought, NGINX,
      "two spellings said they could not resolve it; the third failing must " ..
      "not turn that into silence")
  end,
}

suite[#suite + 1] = {
  name = "an answer with no search_explain never costs a credit",
  fn = function()
    -- Spend only on POSITIVE evidence that the identity failed to resolve. An
    -- answer that says nothing either way is not evidence, and the safe reading
    -- of "nothing either way" is not to bill for it.
    local env, http = keyed()
    local bought = {}
    burp_explaining(http, {}, bought)

    env.action(t.host(), nginx_port())

    t.length(bought, 0,
      "an empty answer with no explanation is not proof the CPE was unknown")
  end,
}

suite[#suite + 1] = {
  name = "one spelling saying nothing does not overrule another saying no",
  fn = function()
    -- The mirror of the case above. Silence from one spelling is not evidence
    -- of resolution either: reading "no explanation" as "it resolved" makes a
    -- genuinely unidentifiable service report clean, which is the failure the
    -- billed call exists to prevent.
    local env, http = keyed()
    local bought = {}
    burp_explaining(http, {
      [SPELLINGS[2]] = {search_cpe = "asked", matched_cpe = "something else"},
    }, bought)

    env.action(t.host(), nginx_port())

    t.contains(bought, NGINX,
      "one spelling answered that it could not resolve this, and that stands")
  end,
}

suite[#suite + 1] = {
  name = "a spelling that resolved is not overruled by a later one that did not",
  fn = function()
    -- The three nginx spellings are asked precisely BECAUSE the service answers
    -- them differently, so "one of them resolved" and "a later one did not" is
    -- the ordinary case rather than a contrived one. A verdict that simply took
    -- the last answer would buy a credit for a product already named.
    local env, http = keyed()
    local bought = {}
    burp_explaining(http, {
      [SPELLINGS[1]] = {search_cpe = SPELLINGS[1], matched_cpe = SPELLINGS[1]},
      [SPELLINGS[3]] = {search_cpe = "asked", matched_cpe = "something else"},
    }, bought)

    env.action(t.host(), nginx_port())

    t.length(bought, 0,
      "the identity resolved under one of its names, so it is named")
  end,
}

-- --------------------------------------------- what enrichment remembers

suite[#suite + 1] = {
  name = "an id the service holds nothing for is not asked about twice",
  fn = function()
    -- "The answer did not carry this id" is an answer. Leaving it unmarked made
    -- every later port re-ask for the whole scan: a /24 spent 254 POSTs
    -- re-learning one negative.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2020-1", cvss = 5.0}),
                           bulletin({id = "CVE-2020-2", cvss = 5.0})}},
      -- Only one of the two ids has a document; the other is a negative the
      -- scan must remember.
      docs = {["CVE-2020-1"] = {id = "CVE-2020-1", type = "cve",
                                title = "known"}},
    })

    local host = t.host()
    env.action(host, port_with_cpe())
    env.action(host, t.port({product = "OpenSSH", version = "7.4",
                             cpe = {CPE}, number = 2222}))

    t.length(http.matching(SEARCH_ID), 1,
      "the second port must ask about nothing: one id was enriched and the " ..
      "other was answered with silence, which is also an answer")
  end,
}

suite[#suite + 1] = {
  name = "an enrichment request that failed is asked again, not cached",
  fn = function()
    -- The other half of the same rule. "The request failed" and "this id has no
    -- document" are different facts, and remembering the first as the second
    -- costs every later port its enrichment for the rest of the scan.
    local env, http = keyed()
    local calls = 0
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2020-1", cvss = 5.0})}},
      docs = {["CVE-2020-1"] = {id = "CVE-2020-1", type = "cve",
                                title = "enriched at last"}},
      handler = function(req)
        if req.path:find(SEARCH_ID, 1, true) then
          calls = calls + 1
          if calls == 1 then
            -- A 200 carrying an envelope that is not a clean answer.
            return t.response({status = 200,
              body = json.generate({result = "error", data = "nope"})})
          end
        end
      end,
    })

    local host = t.host()
    env.action(host, port_with_cpe())
    local plain = t.collect_output(env.action(host, t.port({
      product = "OpenSSH", version = "7.4", cpe = {CPE}, number = 2222})))

    t.equals(calls, 2, "the failed chunk must be asked about again")
    t.equals(plain[CPE][1].title, "enriched at last",
      "and the second port must get the enrichment the first one lost")
  end,
}


-- ------------------------------ what the deep review found unmeasured

suite[#suite + 1] = {
  name = "a business error inside a 200 is not cached as an empty enrichment",
  fn = function()
    -- Vulners reports business errors inside an HTTP 200, and `data` is a
    -- TABLE, so the envelope is a perfectly good "v3". Reading only the kind
    -- made the scan write docs[id] = false for the whole chunk: one transient
    -- error permanently marked up to 100 bulletins "asked, nothing there", so
    -- every later host silently lost titles, EPSS, KEV and cvelist.
    local env, http = keyed()
    local calls = 0
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2020-1", cvss = 5.0})}},
      docs = {["CVE-2020-1"] = {id = "CVE-2020-1", type = "cve",
                                title = "enriched at last"}},
      handler = function(req)
        if req.path:find(SEARCH_ID, 1, true) then
          calls = calls + 1
          if calls == 1 then
            return t.response({status = 200, body = json.generate({
              result = "error",
              data = {error = "quota exceeded", errorCode = 401},
            })})
          end
        end
      end,
    })

    local host = t.host()
    env.action(host, port_with_cpe())
    t.is_nil(env._TEST.state().docs["CVE-2020-1"],
      "an error must leave no verdict behind, not a negative one")

    local plain = t.collect_output(env.action(host, t.port({
      product = "OpenSSH", version = "7.4", cpe = {CPE}, number = 2222})))
    t.equals(calls, 2, "the chunk must be asked about again")
    t.equals(plain[CPE][1].title, "enriched at last",
      "and the second port must get the enrichment the first one lost")
  end,
}

suite[#suite + 1] = {
  name = "an unreadable cost header is treated exactly like no header",
  fn = function()
    -- The charge was gated on the header being VALID and the refund on it being
    -- PRESENT, so "x-vulners-wallet-cost: abc" charged nothing and refunded
    -- everything - shared.spent never advanced and vulners.max_items became a
    -- ceiling the service itself could disarm.
    local env, http = keyed()
    serve(http, {smart = billing({amount = 100, cost = "abc",
      answers = {["OpenSSH 7.4"] = {"CVE-2023-38408"}}}),
      docs = SMART_DOCS})

    env.action(t.host(), unnamed_port("OpenSSH", "7.4", 22))

    t.equals(env._TEST.state().spent, 1,
      "the reservation must stand when the service said nothing readable")
  end,
}

suite[#suite + 1] = {
  name = "402 from the billed endpoint stops spending, not the token",
  fn = function()
    -- 401 and 403 are verdicts on the TOKEN; 402 is a verdict on the WALLET and
    -- only the billed endpoint can give one. Taking the keyed leg down for it
    -- switched off search/id - which needs the token and costs nothing - for
    -- every later host: the exact regression stop_billing exists to prevent,
    -- arriving through the other door.
    local env, http = keyed()
    serve(http, {
      software = {[CPE] = {bulletin({id = "CVE-2012-1667", cvss = 8.5})}},
      docs = {["CVE-2012-1667"] = {id = "CVE-2012-1667", type = "cve",
                                   title = "still enriched"}},
      smart = function() return t.response({status = 402, body = "{}"}) end,
    })

    local host = t.host()
    env.action(host, unnamed_port("OpenSSH", "7.4", 22))

    local shared = env._TEST.state()
    t.is_true(shared.billing_off, "the wallet is empty, so spending stops")
    t.equals(shared.mode, "keyed",
      "but the token is untouched: 402 says nothing about it")

    local plain = t.collect_output(env.action(host, port_with_cpe()))
    t.equals(plain[CPE][1].title, "still enriched",
      "and the free-of-charge keyed call still runs for every later port")
  end,
}

suite[#suite + 1] = {
  name = "a string smart could not name either is remembered as answered",
  fn = function()
    -- The positive half of this cache has a case; the negative half had none.
    -- "smart looked and found nothing" is an ANSWER, and it costs a credit to
    -- get - so not remembering it means every later host running the same
    -- unnameable product buys the same silence again. Measured: deleting the
    -- negative write left all 254 cases green.
    local env, http = keyed()
    serve(http, {smart = {}})

    local port = t.port({number = 9999, service = "unknown",
                         product = "Frobnicator", version = "1.0", cpe = {}})
    for _ = 1, 4 do
      env.action(t.host(), port)
    end

    t.length(http.matching(SMART), 1,
      "an answer of 'nothing' is still an answer, and is bought once")
  end,
}

suite[#suite + 1] = {
  name = "a wallet header carrying a float does not kill the end-of-scan notice",
  fn = function()
    -- The service controls these headers. string.format("%d", x) RAISES in Lua
    -- 5.3+ when x has no integer representation, and post_action formats both
    -- the remaining balance and the spend - so a single "99.5" would have
    -- taken out the whole post-scan notice, on every host in the scan, from a
    -- value the target's own service supplied. The existing header case covers
    -- only a NON-NUMERIC value, which tonumber already rejects.
    local env, http = keyed()
    serve(http, {smart = billing({amount = "99.5", cost = "1.5",
      answers = {["OpenSSH 7.4"] = {"CVE-2023-38408"}}}),
      docs = SMART_DOCS})

    env.action(t.host(), unnamed_port("OpenSSH", "7.4", 22))

    env.SCRIPT_TYPE = "postrule"
    t.no_error(env.action, "the notice must survive a fractional wallet header")
  end,
}
return suite
