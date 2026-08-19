--- Tests for the path sweep, which is now a phase of the merged vulners.nse.
--
-- The sweep is what http-vulners-regex.nse used to be: it fetches a list of
-- paths, follows the redirects they answer with, matches headers and bodies
-- against the embedded patterns, and publishes what it recognised. What changed
-- in 2.0 is where the answer goes. There is no path-keyed listing of its own any
-- more (O5): a CPE the sweep finds reaches host.registry.vulners_cpe[number] and
-- port.version.cpe, and becomes a group key of the report, with the path that
-- produced it on the found_on element of every row in that group.
--
-- Two things every case here declares, because the script is not three scripts
-- any more:
--
--   * the sweep is OFF unless the case turns it on. The merged action sweeps
--     every port shortport.http accepts and t.port() is 80/http, so a case that
--     forgot would silently request every path the catalogue publishes.
--   * free mode - no case here passes a token. The only other traffic is then
--     the burp GET fired for each published CPE, and that is what the request
--     counts below exclude. The discriminator is the endpoint, never the host:
--     a keyed run sends search/id to the same host as the free lookup.

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local NGINX = "cpe:/a:f5:nginx:1.13.4"
local BUGZILLA = "cpe:/a:mozilla:bugzilla:5.0.4"

--- A single-path sweep keeps the cases fast: the published list has 939 entries.
local ONE_PATH = {"/"}

local API_ENDPOINT = "/api/v3/burp/"

--- One bulletin, in the shape the free endpoint answers with.
--
-- Needed by every case that reads found_on: the provenance rides on the rows of
-- a finding, and a group is only opened for a CPE the API answered something
-- for. Publishing happens either way, which is why the registry assertions do
-- not depend on this body.
local API_BODY = json.generate({
  result = "OK",
  data = {
    search = {
      {_source = {id = "CVE-2012-1667", type = "cve", bulletinFamily = "NVD",
                  cvss = {score = 8.5, version = "2.0"}}},
    },
  },
})

--- Is this request the API leg rather than the sweep?
local function is_api(request)
  return (request.path or ""):find(API_ENDPOINT, 1, true) ~= nil
end

--- Only the requests the sweep sent to the scanned target.
local function sweep_requests(http)
  local out = {}
  for _, request in ipairs(http.requests) do
    if not is_api(request) then
      out[#out + 1] = request
    end
  end
  return out
end

--- Answer the API, and let `reply` answer everything the sweep asks for.
--
-- The API has to be answered even where a case asserts nothing about it: an
-- unanswered request spends the whole retry budget, and the retry budget sleeps.
local function serve(http, reply)
  http.handler = function(request, index)
    if is_api(request) then
      return t.response({status = 200, body = API_BODY})
    end
    return reply(request, index)
  end
end

--- Answer every swept path with the same response.
local function always(http, opts)
  serve(http, function() return t.response(opts) end)
end

--- Load the merged script with the sweep turned on for this case.
--
-- Hermetic by construction: t.load_vulners fakes os and io, so no case can pick
-- up the developer's API token from the environment or from the key file under
-- $HOME, and run keyed on one machine and free on another.
local function load(opts)
  opts = opts or {}
  return t.load_vulners({
    root = root,
    paths = opts.paths,
    args = opts.args,
    files = opts.files,
    nmap = opts.nmap,
  })
end

--- The path a reported group says its CPE was found on.
local function found_on(plain, cpe)
  local group = plain and plain[cpe]
  t.is_true(group and group[1], "nothing was reported under " .. cpe)
  return group[1].found_on
end

local suite = {}

suite[#suite + 1] = {
  name = "portrule accepts http ports and rejects others",
  fn = function()
    -- The sweep stays off: the rule is decided before any request is made.
    local env = load()
    t.is_true(env.portrule(t.host(), t.port({number = 80, service = "http"})),
      "port 80/http must be in scope")
    t.is_false(env.portrule(t.host(), t.port({number = 22, service = "ssh",
      protocol = "tcp", state = "open"})), "ssh must be out of scope")
  end,
}

suite[#suite + 1] = {
  name = "a service nmap named as something else is not swept",
  fn = function()
    -- The portrule is deliberately wider than the sweep: a versioned SSH or
    -- MySQL port is worth a CPE lookup and must not be worth 939 HTTP requests -
    -- measured at roughly 494 requests per port on the old 125-path list once
    -- the retry rounds are counted.
    --
    -- Port 8000, not 22, and that is the whole case. shortport.http is "port
    -- number OR service name", and 8000 is one of the eleven numbers, so the
    -- port clause is TRUE here and the service gate is the only thing that can
    -- stop the sweep. Written against port 22 - as it was - shortport.http is
    -- false on its own and the case passes with the gate deleted.
    local env, http = load({paths = {"/never-swept"}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local queued = 0
    local pipeline_add = http.pipeline_add
    http.pipeline_add = function(...)
      queued = queued + 1
      return pipeline_add(...)
    end

    local host = t.host()
    -- service_dtype="probed" is what makes this nmap NAMING the service rather
    -- than guessing it from its ports file. Without it the gate must let the
    -- sweep run, because 7080 and 8088 are guessed as non-HTTP names while
    -- being ordinary HTTP ports.
    local port = t.port({number = 8000, service = "ssh", name = "ssh",
      service_dtype = "probed", product = "OpenSSH", version = "7.4"})
    t.is_true(env.portrule(host, port),
      "the port must be in scope, or this case witnesses nothing")
    t.is_true(require("shortport").http(host, port),
      "and shortport.http must accept it, or the gate is not what stopped it")

    env.action(host, port)

    t.equals(queued, 0, "no path may be queued for a service nmap has named")
    t.length(http.matching("/never-swept"), 0, "and none may be requested")
    t.is_nil(host.registry.vulners_cpe,
      "nothing was fingerprinted, so nothing may be published")
  end,
}

suite[#suite + 1] = {
  name = "an HTTP service on that same port is swept",
  fn = function()
    -- The control. The gate must turn away a service nmap named as something
    -- else, not every service on a port nmap happened to name - a gate that
    -- refused both would be indistinguishable in the case above and would have
    -- switched the sweep off for the ports it exists for.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port({number = 8000, service = "http", name = "http"}))

    t.length(sweep_requests(http), 1, "a named HTTP service is swept")
    t.contains(host.registry.vulners_cpe[8000], NGINX,
      "and what it says is published")
  end,
}

suite[#suite + 1] = {
  name = "a port with no service name at all is swept",
  fn = function()
    -- The other edge of the same gate: nmap names nothing when -sV was not run,
    -- and "nmap did not say" is not "nmap said it is not HTTP". Reading the two
    -- alike would switch the sweep off for every scan without -sV.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port({number = 80, service = false, version = false}))

    t.length(sweep_requests(http), 1, "an unnamed service on port 80 is swept")
  end,
}

suite[#suite + 1] = {
  name = "finds a CPE in a response header",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port({product = "nginx", version = "1.13.4"})
    local plain = t.collect_output(env.action(host, port))

    t.contains(host.registry.vulners_cpe[80], NGINX)
    t.contains(port.version.cpe, NGINX)
    t.equals(found_on(plain, NGINX), "/",
      "the group must still say which path produced the CPE")
  end,
}

suite[#suite + 1] = {
  name = "finds a CPE in the response body",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    always(http, {
      status = 200,
      header = {["Server"] = "unknown"},
      body = '<span id="information" class="header_addl_info">version 5.0.4</span>',
    })

    local host, port = t.host(), t.port()
    local plain = t.collect_output(env.action(host, port))

    t.same(host.registry.vulners_cpe[80], {BUGZILLA},
      "the body match is the only identity this port has")
    t.same(port.version.cpe, {BUGZILLA})
    t.equals(found_on(plain, BUGZILLA), "/")
  end,
}

suite[#suite + 1] = {
  name = "a body over the size cap is truncated, not discarded",
  fn = function()
    -- nselib/http.lua treats an oversized body as an ERROR rather than a
    -- truncation: without truncated_ok it returns nil and drops the response
    -- whole, headers included, so the path looks unanswered and is re-queued for
    -- every round - four fetches of a large page and zero matches, which is
    -- worse than not capping at all.
    local env, http = load({paths = ONE_PATH})
    local marker = '<span id="information" class="header_addl_info">version 5.0.4</span>'

    serve(http, function()
      local body = marker .. string.rep("x", 131072 - #marker)
      local response = t.response({status = 200,
        header = {["Server"] = "nginx/1.13.4"}, body = body})
      -- What the library hands back once truncated_ok is set: the body cut at
      -- max_body_size, and the flag saying so.
      response.truncated = true
      return response
    end)

    local host = t.host()
    env.action(host, t.port())

    local swept = sweep_requests(http)
    t.is_true(#swept > 0, "the sweep must have asked for something")
    for _, request in ipairs(swept) do
      t.equals(request.options.truncated_ok, true,
        "an oversized body must arrive truncated, not as an error")
      t.is_true((request.options.max_body_size or 0) > 0,
        "and the sweep must cap it: pattern matching does not yield")
    end

    t.contains(host.registry.vulners_cpe[80], BUGZILLA,
      "a truncated page must still identify the software it names")
    t.contains(host.registry.vulners_cpe[80], NGINX,
      "and its headers must still be matched")
  end,
}

suite[#suite + 1] = {
  name = "publishes findings to host.registry and port.version.cpe",
  fn = function()
    local nmap = t.nmap_double()
    local env, http = load({paths = ONE_PATH, nmap = nmap})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port()
    env.action(host, port)

    t.contains(host.registry.vulners_cpe[80], NGINX,
      "a third-party script reads the CPEs from here")
    t.contains(port.version.cpe, NGINX,
      "the CPE must also reach the port version table")
    -- The second write is the externally visible one: it is what puts a
    -- header-only identity like cpe:/a:php:php:5.6.38 into the <service> element
    -- of the report, which nmap's own probe cannot produce at all.
    t.is_true(#nmap.set_port_version_calls > 0,
      "the port version must be published, or the <service> element loses it")
  end,
}

suite[#suite + 1] = {
  name = "reports nothing when no pattern matches",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "totally-unknown"},
      body = "<html>nothing to see</html>"})

    -- The keyless notice belongs to the postrule, not to a port, so a port with
    -- nothing to say still says nothing.
    t.is_nil(env.action(t.host(), t.port()), "no match must produce no output")
  end,
}

suite[#suite + 1] = {
  name = "does not repeat the same CPE found on several paths",
  fn = function()
    local env, http = load({paths = {"/", "/index.php"}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port())

    local seen = 0
    for _, cpe in ipairs(host.registry.vulners_cpe[80]) do
      if cpe == NGINX then seen = seen + 1 end
    end
    t.equals(seen, 1, "the same CPE seen twice must be registered once")
  end,
}

suite[#suite + 1] = {
  name = "requests every configured path",
  fn = function()
    local env, http = load({paths = {"/", "/index.php", "/about.html"}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local seen = {}
    for _, request in ipairs(sweep_requests(http)) do seen[request.path] = true end
    for _, path in ipairs({"/", "/index.php", "/about.html"}) do
      t.is_true(seen[path], "path " .. path .. " was never requested")
    end
  end,
}

suite[#suite + 1] = {
  name = "one unreachable path does not discard the other results",
  fn = function()
    local env, http = load({paths = {"/dead", "/alive"}})
    serve(http, function(request)
      if request.path == "/dead" then
        return t.response({status = nil})
      end
      return t.response({status = 200, header = {["Server"] = "nginx/1.13.4"},
        body = ""})
    end)

    local host = t.host()
    local plain = t.collect_output(env.action(host, t.port()))

    t.contains(host.registry.vulners_cpe[80], NGINX,
      "a failing path must not discard what the others found")
    t.equals(found_on(plain, NGINX), "/alive",
      "and the finding is attributed to the path that answered")
  end,
}

suite[#suite + 1] = {
  name = "state is not carried over between hosts",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local first = t.host({ip = "10.0.0.1"})
    env.action(first, t.port())

    -- nmap reuses a loaded script for every host it scans, and 2.0 additionally
    -- caches API answers for the whole scan. The second host must get its own
    -- findings rather than an empty result because the first one saw that CPE.
    local second = t.host({ip = "10.0.0.2"})
    local plain = t.collect_output(env.action(second, t.port()))

    t.equals(found_on(plain, NGINX), "/", "second host must get its own output")
    t.contains(second.registry.vulners_cpe[80], NGINX,
      "second host must get its own registry entry")
  end,
}

suite[#suite + 1] = {
  name = "paths given as a file name are read from that file",
  fn = function()
    -- io is faked, so the file exists for this case only - which is also what
    -- keeps the suite off the developer's filesystem.
    local pathfile = testdir .. "/fixtures/paths_small.txt"
    local env, http = load({
      paths = pathfile,
      files = {[pathfile] = "/fixture-one\n/fixture-two\n"},
    })
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local swept = sweep_requests(http)
    local seen = {}
    for _, request in ipairs(swept) do seen[request.path] = true end
    t.is_true(seen["/fixture-one"], "path from the file must be requested")
    t.is_true(seen["/fixture-two"], "path from the file must be requested")
    t.length(swept, 2, "only the paths from the file must be requested")
  end,
}

suite[#suite + 1] = {
  name = "falls back to the shipped path list when the argument is unusable",
  fn = function()
    local env, http = load({paths = 42})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    -- The embedded list ships over a hundred entries; the exact number may
    -- change, the fallback must simply not collapse to nothing.
    local swept = sweep_requests(http)
    t.is_true(#swept > 10,
      "expected the embedded path list, got " .. #swept .. " requests")
  end,
}

suite[#suite + 1] = {
  name = "a port with no version table is swept without crashing",
  fn = function()
    -- Under the union portrule shortport.http alone puts a port in scope, so the
    -- sweep runs on a port nmap never versioned - and publishing has to build
    -- the version table it is about to write into.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port({version = false})
    t.no_error(function() return env.action(host, port) end,
      "a port without version data must not take the scan down")

    t.contains(host.registry.vulners_cpe[80], NGINX)
    t.contains(port.version.cpe, NGINX,
      "the missing version table is created, not skipped")
  end,
}

suite[#suite + 1] = {
  name = "all paths travel in one pipeline",
  fn = function()
    local env, http = load({paths = {"/", "/index.php", "/about.html"}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    -- Counted on the sweep alone: the CPE it finds costs one burp GET per nginx
    -- vendor spelling, and those land in http.requests too.
    local swept = sweep_requests(http)
    t.length(swept, 3, "each path is requested exactly once")
    for _, request in ipairs(swept) do
      t.is_true(request.pipelined,
        "requests must go through the pipeline, not one by one")
    end
  end,
}

suite[#suite + 1] = {
  name = "a pipeline that comes back short does not lose the served paths",
  fn = function()
    local env, http = load({paths = {"/first", "/second", "/third"}})
    serve(http, function(request)
      if request.path == "/third" then
        -- The connection dies mid-pipeline; nmap returns a shorter list.
        return "cut_short"
      end
      return t.response({status = 200, header = {["Server"] = "nginx/1.13.4"},
        body = ""})
    end)

    local host = t.host()
    local plain = t.collect_output(env.action(host, t.port()))

    t.contains(host.registry.vulners_cpe[80], NGINX,
      "what was served before the cut must still be published")
    t.equals(found_on(plain, NGINX), "/first",
      "and must still carry the path it came from")
  end,
}

suite[#suite + 1] = {
  name = "paths are requested in the order they were given",
  fn = function()
    -- Stable, and no longer sorted. The catalogue publishes its paths most
    -- likely to answer first, and the script requests a prefix of that list
    -- bounded by -T, so sorting them alphabetically threw away the one thing
    -- the order carried - and made the budget keep an arbitrary slice.
    local given = {"/zeta", "/alpha", "/mid"}
    local env, http = load({paths = given})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local order = {}
    for _, request in ipairs(sweep_requests(http)) do
      order[#order + 1] = request.path
    end
    t.same(order, given, "the order given is the order requested")
  end,
}

--- A catalogue whose path list is long enough to be cut by a budget.
local function many_paths(count)
  local list = {}
  for index = 1, count do
    list[index] = string.format("/p%03d", index)
  end
  return list
end

--- Sweep `count` catalogue paths at a faked -T level.
--
-- @return how many requests went out, and the clock that counted the waiting
local function with_timing(count, timing)
  local documents = t.published_catalog(root)
  local env, http, _, clock = t.load_vulners({
    root = root,
    paths = "embedded",
    nmap = t.nmap_double({timing = timing}),
    catalog = {
      fingerprints = documents.fingerprints,
      paths = {schema = 1, paths = many_paths(count)},
      probes = {schema = 1, probes = {}},
    },
  })
  always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})
  env.action(t.host(), t.port())
  return #sweep_requests(http), clock
end

suite[#suite + 1] = {
  name = "every published path is requested, whatever the timing template",
  fn = function()
    -- -T decides how FAST, never how much. Asking less would find less, and
    -- what an operator says with -T is how much of the target's attention this
    -- scan may take - not which questions it may ask.
    for level = 0, 5 do
      t.equals((with_timing(1000, level)), 1000,
        string.format("-T%d must still request every path", level))
    end
  end,
}

suite[#suite + 1] = {
  name = "how fast the sweep goes is what nmap's -T says",
  fn = function()
    -- Batches, with a wait between them. nmap's own templates delay between
    -- PROBES - 15 s at -T1 - which applied per request to a thousand-path sweep
    -- would take four hours, so the wait is per batch. The clock is counted,
    -- not performed.
    for _, case in ipairs({
      -- level, batch size, seconds between batches
      {0, 5, 2.0},
      {1, 10, 1.0},
      {2, 25, 0.5},
      {3, 100, 0.1},
    }) do
      local level, batch, delay = case[1], case[2], case[3]
      local _, clock = with_timing(1000, level)
      local waits = math.ceil(1000 / batch) - 1
      t.equals(clock.sleeps, waits, string.format(
        "-T%d must send %d batches of %d, so wait %d times",
        level, waits + 1, batch, waits))
      t.is_true(math.abs(clock.slept - waits * delay) < 0.001, string.format(
        "-T%d must wait %.1fs between batches, slept %.2fs in total",
        level, delay, clock.slept))
    end
  end,
}

suite[#suite + 1] = {
  name = "an aggressive timing template does not wait at all",
  fn = function()
    local _, four = with_timing(1000, 4)
    local _, five = with_timing(1000, 5)

    t.equals(four.sleeps, 0, "-T4 sends its batches back to back")
    t.equals(five.sleeps, 0, "-T5 sends one batch")
  end,
}

suite[#suite + 1] = {
  name = "a list shorter than one batch costs no waiting",
  fn = function()
    local sent, clock = with_timing(20, 3)

    t.equals(sent, 20, "all of it goes out")
    t.equals(clock.sleeps, 0, "and there is nothing to wait between")
  end,
}

suite[#suite + 1] = {
  name = "a path list the operator supplied is paced the same way",
  fn = function()
    -- The rate is about the target, not about where the list came from.
    local mine = many_paths(300)
    local env, http, _, clock = t.load_vulners({
      root = root, paths = mine,
      nmap = t.nmap_double({timing = 2}),
    })
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.equals(#sweep_requests(http), 300, "the whole list goes out")
    t.equals(clock.sleeps, math.ceil(300 / 25) - 1,
      "in batches of 25, because -T2 is what the operator asked for")
  end,
}

suite[#suite + 1] = {
  name = "matches software listed in the shipped pattern set",
  fn = function()
    local cases = {
      {header = {["X-Powered-By"] = "PHP/5.6.38"}, cpe = "cpe:/a:php:php:5.6.38"},
      {header = {["X-Jenkins"] = "2.121.1"}, cpe = "cpe:/a:jenkins:jenkins:2.121.1"},
      {header = {["Server"] = "lighttpd/1.4.45"}, cpe = "cpe:/a:lighttpd:lighttpd:1.4.45"},
      {header = {["Server"] = "Apache/2.4.7 (Ubuntu)"},
       cpe = "cpe:/a:apache:http_server:2.4.7"},
    }

    for _, case in ipairs(cases) do
      local env, http = load({paths = ONE_PATH})
      always(http, {status = 200, header = case.header, body = ""})

      local host, port = t.host(), t.port()
      env.action(host, port)

      t.contains(host.registry.vulners_cpe[80] or {}, case.cpe,
        "no CPE published for header " .. t.repr(case.header))
      t.contains(port.version.cpe, case.cpe,
        "and none reached the port for header " .. t.repr(case.header))
    end
  end,
}

suite[#suite + 1] = {
  name = "a capture is not allowed to run past its header line",
  fn = function()
    -- The header block is matched in one pass, so an unbounded pattern used to
    -- swallow every following header - a session cookie among them - into the
    -- CPE, the report and the API request.
    --
    -- The rule is INJECTED rather than taken from the published corpus. The
    -- shipped rule that fires on this response captures through "[%d.]+",
    -- which can never hold a CR or an LF - so the guard could be deleted and
    -- this case stayed green, measuring a bound that its own fixture made
    -- unreachable. A capture that CAN cross the line is what witnesses it.
    local env, http = t.load_vulners({
      root = root,
      paths = ONE_PATH,
      catalog = {
        fingerprints = {schema = 1, rules = {
          -- The greedy one: "." matches a newline in Lua, so its capture runs
          -- off the end of the Server line and into the Set-Cookie that
          -- follows. This is the rule the guard exists for.
          ["Greedy, raw"] = {alias = "cpe:/a:oracle:iplanet_web_server",
                             channel = "raw", anchor = "sun-java-system",
                             regex = "Sun%-Java%-System%-Web%-Server/(.+)"},
          -- The bounded one, so "the version is still found" is witnessed by a
          -- rule that can legitimately find it. Without this the case could
          -- pass simply because nothing matched at all.
          ["Bounded, raw"] = {alias = "cpe:/a:oracle:iplanet_web_server",
                              channel = "raw", anchor = "sun-java-system",
                              regex = "Sun%-Java%-System%-Web%-Server/([%d.]+)"},
        }},
        paths = {schema = 1, paths = ONE_PATH},
        probes = {schema = 1, probes = {}},
      },
    })
    serve(http, function()
      return t.response({
        status = 200,
        rawheader = {
          "Server: Sun-Java-System-Web-Server/7.0",
          "Set-Cookie: JSESSIONID=8F3A9C2E1D7B4A6F; Path=/",
        },
        body = "",
      })
    end)

    local host = t.host()
    env.action(host, t.port())

    t.is_true(#(host.registry.vulners_cpe[80] or {}) > 0, "the version is still found")
    for _, cpe in ipairs(host.registry.vulners_cpe[80] or {}) do
      t.is_nil(cpe:find("JSESSIONID", 1, true), "no cookie may reach a CPE: " .. cpe)
      t.is_nil(cpe:find("[\r\n]"), "no CPE may span two lines: " .. cpe)
    end
  end,
}

suite[#suite + 1] = {
  name = "a pattern is matched in every header line, not only the first",
  fn = function()
    -- A reverse proxy names the same product twice; the version behind the proxy
    -- and the one in front of it are different findings.
    local env, http = load({paths = ONE_PATH})
    serve(http, function()
      return t.response({
        status = 200,
        rawheader = {"Server: nginx/1.13.4", "Via: nginx/1.21.0"},
        body = "",
      })
    end)

    local host = t.host()
    env.action(host, t.port())

    t.contains(host.registry.vulners_cpe[80], NGINX)
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.21.0",
      "the second occurrence must be found too")
  end,
}

suite[#suite + 1] = {
  name = "a path a server refuses does not take the rest of the sweep with it",
  fn = function()
    -- pipeline_go stops at the first request a fresh connection cannot serve,
    -- and the queue is sorted, so one refused path used to cost every path
    -- queued behind it - deterministically, for that host.
    local env, http = load({paths = {"/one", "/two"}})
    serve(http, function() end)

    local rounds = 0
    http.pipeline_go = function(host, port, requests)
      rounds = rounds + 1
      if rounds == 1 then
        return {}
      end
      local answers = {}
      for index = 1, #requests do
        answers[index] = t.response({
          status = 200,
          rawheader = {"Server: nginx/1.13.4"},
          body = "",
        })
      end
      return answers
    end

    local host = t.host()
    env.action(host, t.port())

    t.is_true(rounds > 1, "the unanswered paths must be asked again")
    t.contains(host.registry.vulners_cpe[80], NGINX,
      "the paths behind the refused one still produce their findings")
  end,
}

suite[#suite + 1] = {
  name = "a pipeline that answers nothing at all does not loop forever",
  fn = function()
    -- More paths than the round budget: a sweep that gave up one path per round
    -- would take six rounds, so the assertion witnesses the cap rather than the
    -- list running out.
    local env, http = load({paths = {"/one", "/two", "/three", "/four", "/five",
      "/six"}})
    serve(http, function() end)

    local rounds = 0
    http.pipeline_go = function()
      rounds = rounds + 1
      return nil
    end

    t.is_nil(env.action(t.host(), t.port()), "nothing was found, nothing is reported")
    t.is_true(rounds <= 4, "the retry is bounded, got " .. rounds .. " rounds")
  end,
}

suite[#suite + 1] = {
  name = "a redirect is followed to the page it points at",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    serve(http, function(request)
      if request.path == "/real" then
        return t.response({status = 200, rawheader = {"Server: nginx/1.13.4"},
          body = ""})
      end
      return t.response({status = 302, header = {location = "/real"}, body = ""})
    end)

    local host = t.host()
    env.action(host, t.port())

    t.contains(host.registry.vulners_cpe[80], NGINX,
      "the CPE lives on the redirect target, not in the 302 envelope")
  end,
}

suite[#suite + 1] = {
  name = "a redirect target is fetched once, however many paths point at it",
  fn = function()
    local env, http = load({paths = {"/one", "/two", "/three"}})
    local target_requests = 0
    serve(http, function(request)
      if request.path == "/real" then
        target_requests = target_requests + 1
        return t.response({status = 200, rawheader = {"Server: nginx/1.13.4"},
          body = ""})
      end
      return t.response({status = 301, header = {location = "/real"}, body = ""})
    end)

    env.action(t.host(), t.port())
    t.equals(target_requests, 1,
      "a site that redirects everything to one page must cost one request")
  end,
}

suite[#suite + 1] = {
  name = "a redirect to another port on this host is not followed",
  fn = function()
    -- The host check alone lets "https://<same host>:8443/admin" through, and
    -- the target is then fetched from the port being swept - so /admin is read
    -- off port 80 and its identity attributed to a page that never served it.
    -- nmap's own redirect policy refuses a cross-port redirect for exactly this
    -- reason (nselib/http.lua redirect_ok_rules, rule 3).
    local env, http = load({paths = ONE_PATH})
    serve(http, function(request)
      if request.path == "/admin" then
        return t.response({status = 200, rawheader = {"Server: nginx/1.13.4"},
          body = ""})
      end
      return t.response({status = 302, body = "",
        header = {location = "https://127.0.0.1:8443/admin"}})
    end)

    local host = t.host()
    env.action(host, t.port())

    t.length(http.matching("/admin"), 0,
      "a page on another port is not ours to read off this one")
    t.is_nil(host.registry.vulners_cpe,
      "and nothing it says may be published against this port")
  end,
}

suite[#suite + 1] = {
  name = "a redirect leaving the host is not followed",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    serve(http, function()
      return t.response({
        status = 302,
        header = {location = "http://example.com/elsewhere"},
        body = "",
      })
    end)

    env.action(t.host(), t.port())
    t.length(http.matching("elsewhere"), 0,
      "somebody else's server is not ours to fingerprint")
  end,
}

suite[#suite + 1] = {
  name = "paths from a CRLF file arrive without the carriage return",
  fn = function()
    local pathfile = testdir .. "/fixtures/paths_crlf.txt"
    local env, http = load({
      paths = pathfile,
      files = {[pathfile] = "/one\r\n/two\r\n\r\nthree\r\n"},
    })
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local swept = sweep_requests(http)
    t.is_true(#swept > 0, "the file must still be usable")
    for _, request in ipairs(swept) do
      t.is_nil(request.path:find("[\r\n]"),
        "a bare CR in the request line earns a 400 from every strict server")
      t.matches(request.path, "^/", "a path without its slash is given one")
    end
  end,
}

suite[#suite + 1] = {
  name = "a named paths file that cannot be read stops the sweep",
  fn = function()
    -- An operator who names a file means that file; quietly falling back to the
    -- embedded 125 paths sends the scan where it was told not to go.
    local missing = testdir .. "/fixtures/no_such_paths_file.txt"
    local env, http = load({paths = missing, files = {}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.length(http.requests, 0, "nothing may be requested")
  end,
}

suite[#suite + 1] = {
  name = "a CPE nmap already published is not added to the port a second time",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port({cpe = {NGINX}})
    env.action(host, port)

    t.contains(host.registry.vulners_cpe[80], NGINX,
      "the finding must have been made in the first place")

    local count = 0
    for _, cpe in ipairs(port.version.cpe) do
      if cpe == NGINX then count = count + 1 end
    end
    t.equals(count, 1, "a duplicate <cpe> element makes every consumer count twice")
  end,
}

suite[#suite + 1] = {
  name = "the site root is in the shipped path list",
  fn = function()
    -- Fifty of the shipped patterns fingerprint the HTML of a home page; the
    -- list used to ask for everything except "/". "embedded" is how a case asks
    -- for the shipped list, since the harness turns the sweep off by default -
    -- an empty table now means what it says, which is "request nothing".
    local env, http = load({paths = "embedded"})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local asked = {}
    for _, request in ipairs(sweep_requests(http)) do asked[request.path] = true end
    t.is_true(asked["/"], "the home page must be requested")
  end,
}

suite[#suite + 1] = {
  name = "what one port runs is not attributed to another port",
  fn = function()
    -- The hand-off used to be host-wide, so a web server's CPEs were reported
    -- again under every other open port of the host - nginx CVEs filed against
    -- the SSH service.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port({number = 80}))

    t.is_true(host.registry.vulners_cpe[80] ~= nil, "the web port has its findings")
    t.is_nil(host.registry.vulners_cpe[22],
      "a port that was never fingerprinted must stay empty")
  end,
}

suite[#suite + 1] = {
  name = "a port that stops accepting connections is reported, not crashed on",
  fn = function()
    -- pipeline_go returns nil when it cannot open a connection; a target that
    -- goes away between the port scan and the script phase is ordinary on
    -- rate-limiting hosts. Nothing is found, so no API request follows either.
    local env, http = load({paths = ONE_PATH})
    http.handler = function() return "no_connection" end

    t.is_nil(env.action(t.host(), t.port()), "nothing found, nothing reported")
  end,
}

suite[#suite + 1] = {
  name = "patterns are matched against the decoded body, not the compressed one",
  fn = function()
    -- nselib sets rawbody to the bytes that arrived and then replaces body with
    -- the decoded ones, so on any server that compresses - the default for nginx
    -- and Apache - reading rawbody means running 178 patterns over gzip. Every
    -- body-derived fingerprint was dead there, silently, and the harness could
    -- not show it because its response() left rawbody nil, a shape nselib never
    -- produces.
    local page = [[<html><meta name="generator" content="WordPress 5.5.1"/></html>]]
    local env, http = t.load_vulners({root = root, paths = ONE_PATH})
    http.handler = function(req)
      if type(req.host) == "table" then
        return t.response({
          status = 200,
          header = {["content-encoding"] = "gzip"},
          -- What nmap handed the script after decoding...
          body = page,
          -- ...and what actually arrived on the wire.
          rawbody = "\31\139\8\0compressed-nonsense-that-matches-nothing",
        })
      end
      -- An authoritative empty answer: the sweep is what this case is about.
      return t.response({status = 200, body = json.generate({
        result = "warning", data = {search_explain = {}},
      })})
    end

    local host = t.host()
    env.action(host, t.port({product = "nginx", version = "1.13.4", cpe = {}}))

    t.contains(host.registry.vulners_cpe[80], "cpe:/a:wordpress:wordpress:5.5.1",
      "the decoded body must be what the patterns see")
  end,
}

-- ---------------------------------------------------------------------------
-- Targeted version probes.
--
-- A probe is the one thing here that makes a request the operator did not ask
-- for by listing a path, so every case below pins a bound rather than a
-- feature: when it fires, when it does not, and how many requests it can ever
-- cost. A product that names itself and hides its version is the case the
-- passive rules cannot win - no pattern extracts a number that is not on the
-- page - but "send a request when in doubt" is how a safe script stops being
-- one.

--- A body carrying Drupal's detector and no version anywhere.
local DRUPAL_PAGE =
  '<html><head><link rel="stylesheet" href="/sites/default/themes/x/style.css">' ..
  "</head><body>hello</body></html>"

--- What /CHANGELOG.txt answers, with the version the probe is written to read.
local DRUPAL_CHANGELOG = '<span class="site-version">9.4.5</span>'

--- Requests the sweep sent that are not one of the paths it was told to fetch.
local function probe_requests(http, swept)
  local out = {}
  for _, request in ipairs(sweep_requests(http)) do
    local asked = false
    for _, path in ipairs(swept) do
      if request.path == path then asked = true end
    end
    if not asked then out[#out + 1] = request.path end
  end
  return out
end

suite[#suite + 1] = {
  name = "a product detected without a version is asked for one",
  fn = function()
    local env, http = load({paths = ONE_PATH})
    serve(http, function(request)
      if request.path == "/CHANGELOG.txt" then
        return t.response({status = 200, body = DRUPAL_CHANGELOG})
      end
      return t.response({status = 200, body = DRUPAL_PAGE})
    end)

    local plain = t.collect_output(env.action(t.host(), t.port()))

    t.is_true(plain and plain["cpe:/a:drupal:drupal:9.4.5"] ~= nil,
      "the probe must turn a versionless detection into an identity")
    t.equals(found_on(plain, "cpe:/a:drupal:drupal:9.4.5"), "/CHANGELOG.txt",
      "and must say where it got it, not claim the swept path")
  end,
}

suite[#suite + 1] = {
  name = "nothing is probed when no detector fired",
  fn = function()
    -- The ordinary case, and the one that decides whether this feature is
    -- acceptable at all: a host running none of the probed products must cost
    -- exactly the paths the operator asked for and not one request more.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, body = "<html>an ordinary page</html>"})

    env.action(t.host(), t.port())

    t.length(probe_requests(http, ONE_PATH), 0,
      "a host running nothing recognisable must not be probed")
  end,
}

suite[#suite + 1] = {
  name = "a product that already gave its version is not asked again",
  fn = function()
    -- The probe exists to fill a gap. When the sweep has already produced a
    -- version for that identity the request could only confirm it, and a
    -- request that cannot change the answer is one a scanner should not send.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200,
      body = DRUPAL_PAGE .. '<meta name="generator" content="Drupal 7.59" />'})

    env.action(t.host(), t.port())

    t.length(probe_requests(http, ONE_PATH), 0,
      "the version was already known, so the probe must be skipped")
  end,
}

suite[#suite + 1] = {
  name = "a version nmap already found suppresses the probe too",
  fn = function()
    -- The probe asks "does anything know this version yet", and the answer has
    -- to include what nmap itself put on the port. Consulting only the sweep's
    -- own findings meant a service -sV had already named and versioned was
    -- probed anyway, spending a request to learn what arrived with the port.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, body = DRUPAL_PAGE})

    local port = t.port()
    port.version = port.version or {}
    port.version.cpe = {"cpe:/a:drupal:drupal:9.4.5"}

    env.action(t.host(), port)

    t.length(probe_requests(http, ONE_PATH), 0,
      "nmap had already versioned it, so there was nothing to ask")
  end,
}

suite[#suite + 1] = {
  name = "a page carrying every detector cannot make the scan knock on every door",
  fn = function()
    -- The count is the target's to choose otherwise: a page that carries the
    -- detector of every probe in the table would buy one request each, from a
    -- script in nmap's "safe" category.
    local env, http = load({paths = ONE_PATH})
    local everything = {}
    for _, probe in ipairs(env._TEST.catalog().probes) do
      everything[#everything + 1] = probe.name
    end
    t.is_true(#everything > 1, "the probe table must hold more than one entry")

    -- Detectors for Drupal, concrete5 and WordPress at once, none of which the
    -- probe responses will satisfy.
    local bait = DRUPAL_PAGE ..
      '<script src="/concrete/js/build/x.js"></script>' ..
      '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    serve(http, function(request)
      if request.path == "/" then
        return t.response({status = 200, body = bait})
      end
      return t.response({status = 200, body = "nothing useful"})
    end)

    env.action(t.host(), t.port())

    local sent = probe_requests(http, ONE_PATH)
    t.is_true(#sent <= 3, string.format(
      "a bait page bought %d probe requests; the ceiling is 3", #sent))
  end,
}

suite[#suite + 1] = {
  name = "one probe redirected to https does not pin https for the next",
  fn = function()
    -- nselib writes options.scheme from a Location it parsed into the CALLER's
    -- own table (nselib/http.lua:1799). A single options table shared across
    -- the probe loop therefore turns one redirect into a scheme change for
    -- every later request on a plaintext port. follow_redirects was caught by
    -- exactly this, which is why it builds its options per request; this pins
    -- the same property for the probe loop.
    local env, http = load({paths = ONE_PATH})

    -- Both Drupal and concrete5 detected, so more than one probe is sent.
    local bait = DRUPAL_PAGE ..
      '<script src="/concrete/js/build/x.js"></script>'
    serve(http, function(request)
      if request.path == "/" then
        return t.response({status = 200, body = bait})
      end
      -- Every probe path answers with a redirect to an https URL, which is what
      -- makes nselib write the scheme back.
      return t.response({status = 302, body = "",
        header = {location = "https://" .. t.host().ip .. "/moved"}})
    end)

    env.action(t.host(), t.port())

    -- Anchored first. The loop below used to walk sweep_requests(), which
    -- always holds the one "/" GET whose scheme is nil - so it passed whenever
    -- the probes stopped firing at all: measured, capping MAX_PROBES_PER_PORT
    -- at 1, and making run_probes return nothing, both left it green. There is
    -- no property here to observe until a SECOND probe has been sent.
    local sent = probe_requests(http, ONE_PATH)
    t.is_true(#sent >= 2,
      "two products were detected, so two probes must have gone out")

    for _, request in ipairs(sweep_requests(http)) do
      t.is_true(request.scheme == nil or request.scheme == "http", string.format(
        "%s was requested over %s; a redirect in one probe must not change the "
        .. "scheme of the next", request.path, tostring(request.scheme)))
    end
  end,
}

suite[#suite + 1] = {
  name = "probes are sent in the order the table holds them",
  fn = function()
    -- Asserting only that two runs agree would measure nothing: `triggered` is
    -- keyed by integers, and Lua's per-process hash seeding disturbs string
    -- keys, not integer ones - so a version of this case that compared two runs
    -- to each other passed with the ordering removed entirely. What is worth
    -- pinning is the order itself, against the table, so that a scan can be
    -- reproduced and a diff of two reports means something.
    local env, http = load({paths = ONE_PATH})
    serve(http, function(request)
      if request.path == "/" then
        return t.response({status = 200, body = DRUPAL_PAGE ..
          '<script src="/concrete/js/build/x.js"></script>'})
      end
      return t.response({status = 404, body = ""})
    end)
    env.action(t.host(), t.port())

    local sent = probe_requests(http, ONE_PATH)
    t.is_true(#sent >= 2, "both detected products must be probed")

    -- Which probe each request belongs to, by position in the table.
    local position = {}
    for index, probe in ipairs(env._TEST.catalog().probes) do
      for _, path in ipairs(probe.paths) do
        position[path] = position[path] or index
      end
    end

    local previous = 0
    for _, path in ipairs(sent) do
      local at = position[path]
      t.is_true(at ~= nil, "an unexpected path was requested: " .. path)
      t.is_true(at >= previous, string.format(
        "%s belongs to probe %d, sent after probe %d - the table order is the "
        .. "documented one", path, at, previous))
      previous = at
    end
  end,
}


-- ------------------------------ what the deep review found unmeasured

suite[#suite + 1] = {
  name = "nmap is not told a service was probed when it was not",
  fn = function()
    -- Measured on nmap 7.991 against a real listener with no -sV: the two-arg
    -- set_port_version turns <service method="table" conf="3"> into
    -- <service method="probed" conf="10">, so the report claims a hard version
    -- match for a service no probe ever touched.
    local double = t.nmap_double()
    local env, http = t.load_vulners({root = root, paths = ONE_PATH,
                                      nmap = double})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port({service = "http", name = "http"}))

    local call = double.set_port_version_calls[1]
    t.is_true(call, "the CPE must still be published onto the port")
    t.equals(call.detail, "incomplete",
      "a port -sV never settled must not be reported as probed")
  end,
}

suite[#suite + 1] = {
  name = "a service nmap only guessed from its ports file is still swept",
  fn = function()
    -- 7080 is guessed "empowerid" and 8088 "radan-http" - names that are not in
    -- LIKELY_HTTP_SERVICES - so reading the guess as a naming silently skipped
    -- the sweep on two of the eleven ports shortport.http exists to admit.
    local env, http = load({paths = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port({number = 7080, service = "empowerid",
                             name = "empowerid"}))

    t.length(sweep_requests(http), 1,
      "nmap guessed this name from a table; it did not name the service")
    t.contains(host.registry.vulners_cpe[7080], NGINX)
  end,
}

suite[#suite + 1] = {
  name = "an operator's path is held to the rule a published path is held to",
  fn = function()
    -- nselib builds the request line as method .. " " .. path verbatim, so an
    -- interior space or CR from the operator's own file put a second request
    -- line's worth of text into the first. usable_path already refused exactly
    -- that for the catalogue.
    local pathfile = testdir .. "/fixtures/paths_bad.txt"
    local env, http = load({
      paths = pathfile,
      files = {[pathfile] = "/good\n/a b\n/car\rriage\n"},
    })
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.length(sweep_requests(http), 1, "only the usable path may go on the wire")
    t.equals(sweep_requests(http)[1].path, "/good")
  end,
}

suite[#suite + 1] = {
  name = "a probe reads a window around its anchor, not the whole body",
  fn = function()
    -- The detector and the extractor both ran their downloaded pattern over the
    -- WHOLE body, with the anchor as nothing but a prefilter - and a prefilter
    -- does not help when the anchor IS the payload. Measured on the SHIPPED
    -- Tomcat extractor against a body of "apache tomcat" repeated: 16 KB cost
    -- 0.22 s, 32 KB 0.90 s, 64 KB 3.60 s. Quadratic, so the 128 KB the body cap
    -- admits is about fourteen seconds of non-yielding matching with every
    -- script in the scan stopped - and the target chooses the body.
    --
    -- match_group was given this bound; the probe path was not. This pins it
    -- from both ends, as the fingerprint window case does: the extractor still
    -- reads a version beside its anchor, and does not reach one parked past it.
    local function scan(probe_body)
      local env, http = t.load_vulners({
        root = root,
        paths = "embedded",
        catalog = {
          fingerprints = {schema = 1, rules = {
            ["Filler, body"] = {alias = "cpe:/a:acme:filler", channel = "body",
                                anchor = "filler", regex = "filler/([%d.]+)"},
          }},
          paths = {schema = 1, paths = {"/"}},
          probes = {schema = 1, probes = {{
            name = "Widget", alias = "cpe:/a:acme:widget",
            -- A lazy span, the shape the real corpus is full of, and exactly
            -- what backtracks catastrophically over a long subject.
            detect = {{channel = "body", anchor = "widget-app",
                       regex = "widget%-app"}},
            extract = {{anchor = "widget/", regex = "widget/[^!]-([%d.]+)"}},
            paths = {"/probe"},
          }}},
        },
      })
      serve(http, function(request)
        if request.path == "/probe" then
          return t.response({status = 200, body = probe_body})
        end
        return t.response({status = 200, body = "<p>widget-app here</p>"})
      end)
      return t.collect_output(env.action(t.host(), t.port()))
    end

    local near = scan("<p>widget/1.2.3</p>")
    t.is_true(near and near["cpe:/a:acme:widget:1.2.3"] ~= nil,
      "the extractor must still read a version beside its anchor")

    -- One anchor at the start, and the version the pattern would need parked
    -- 8 KB past it - far outside the window, well inside the body cap. The
    -- filler carries no digit and no dot, so the only way to reach "9.9.9" is
    -- to let the lazy span cross all 8 KB of it.
    local far = scan("widget/" .. string.rep("x", 8000) .. "9.9.9")
    t.is_true(far == nil or far["cpe:/a:acme:widget:9.9.9"] == nil,
      "and must not reach a match parked beyond the window; without that bound "
      .. "one hostile body freezes every script in the scan")
  end,
}

suite[#suite + 1] = {
  name = "a probe detector reads a window around its anchor too",
  fn = function()
    -- The extractor case above pins the second half of the probe path. This is
    -- the first half, and it costs more when it is wrong: detect_probes runs
    -- every detector of every untriggered probe against every subject, so an
    -- unbounded detector pays its cost once per probe rather than once per
    -- answered request. Reverting the extractor alone leaves this green, which
    -- is how it was found.
    local function sent_for(body)
      local env, http = t.load_vulners({
        root = root,
        paths = "embedded",
        catalog = {
          fingerprints = {schema = 1, rules = {
            ["Filler, body"] = {alias = "cpe:/a:acme:filler", channel = "body",
                                anchor = "filler", regex = "filler/([%d.]+)"},
          }},
          paths = {schema = 1, paths = {"/"}},
          probes = {schema = 1, probes = {{
            name = "Widget", alias = "cpe:/a:acme:widget",
            detect = {{channel = "body", anchor = "widget-app",
                       regex = "widget%-app[^!]-marker"}},
            extract = {{anchor = "widget/", regex = "widget/([%d.]+)"}},
            paths = {"/probe"},
          }}},
        },
      })
      serve(http, function(request)
        if request.path == "/probe" then
          return t.response({status = 200, body = "<p>widget/1.2.3</p>"})
        end
        return t.response({status = 200, body = body})
      end)
      env.action(t.host(), t.port())
      return probe_requests(http, ONE_PATH)
    end

    t.length(sent_for("<p>widget-app marker</p>"), 1,
      "a detector must still fire on evidence beside its anchor")

    -- The evidence the detector needs is 8 KB past its anchor: reachable only
    -- by letting the lazy span cross the whole body.
    t.length(sent_for("widget-app" .. string.rep("x", 8000) .. "marker"), 0,
      "and must not reach evidence parked beyond the window; an unbounded "
      .. "detector runs once per probe, not once per answered request")
  end,
}

suite[#suite + 1] = {
  name = "every answered path is matched, not only the first",
  fn = function()
    -- SWEEP_BYTE_BUDGET bounds how much of a port's responses reach the
    -- matcher. Nothing pinned that the budget is big enough to reach the
    -- SECOND answer: measured, cutting it to a single byte still left all 254
    -- cases green, because every multi-path case either served the same header
    -- everywhere or attributed its finding to the first path. Two paths, two
    -- different identities, and both have to arrive.
    local env, http = load({paths = {"/one", "/two"}})
    serve(http, function(request)
      if request.path == "/two" then
        return t.response({status = 200,
          header = {["X-Powered-By"] = "PHP/5.6.38"}, body = ""})
      end
      return t.response({status = 200,
        header = {["Server"] = "nginx/1.13.4"}, body = ""})
    end)

    local host = t.host()
    env.action(host, t.port())

    local published = host.registry.vulners_cpe[80]
    t.contains(published, NGINX, "the first answered path must be matched")
    t.contains(published, "cpe:/a:php:php:5.6.38",
      "and so must the second; a budget that stops after one is a sweep that "
      .. "asks for pages it never reads")
  end,
}
return suite
