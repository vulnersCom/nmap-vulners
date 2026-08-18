--- Tests for http-vulners-regex.nse.
--
-- The script fetches a list of paths, matches the response headers and body
-- against the shipped Lua patterns, and publishes the resulting CPEs both in
-- the script output and in host.registry.vulners_cpe[80], which vulners.nse and
-- vulners_enterprise.nse consume afterwards. All three effects are checked.

local t, testdir, root = ...

local string = require "string"
local table = require "table"

local SCRIPT = root .. "/http-vulners-regex.nse"

--- Load the script with a fresh http double.
-- @param opts args - script arguments for this load
-- @return env, http_double
local function load(opts)
  opts = opts or {}
  local http = t.http_double()
  local nmap = t.nmap_double()
  local env = t.load_script(SCRIPT, {
    args = opts.args,
    modules = {http = http, nmap = nmap},
  })
  return env, http, nmap
end

--- Reply to every request with the same headers and body.
local function always(http, opts)
  http.handler = function()
    return t.response(opts)
  end
end

--- A single-path argument keeps the tests fast and deterministic: the default
-- path list has over a hundred entries.
local ONE_PATH = {["http-vulners-regex.paths"] = {"/"}}

local suite = {}

suite[#suite + 1] = {
  name = "portrule accepts http ports and rejects others",
  fn = function()
    local env = load()
    t.is_true(env.portrule(t.host(), t.port({number = 80, service = "http"})),
      "port 80/http must be in scope")
    t.is_false(env.portrule(t.host(), t.port({number = 22, service = "ssh",
      protocol = "tcp", state = "open"})), "ssh must be out of scope")
  end,
}

suite[#suite + 1] = {
  name = "finds a CPE in a response header",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port({product = "nginx", version = "1.13.4"})
    local output = env.action(host, port)
    local plain = t.collect_output(output)

    t.is_true(plain, "expected output for a matching header")
    t.contains(plain["/"], "cpe:/a:f5:nginx:1.13.4")
  end,
}

suite[#suite + 1] = {
  name = "finds a CPE in the response body",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {
      status = 200,
      header = {["Server"] = "unknown"},
      body = '<span id="information" class="header_addl_info">version 5.0.4</span>',
    })

    local output = env.action(t.host(), t.port())
    local plain = t.collect_output(output)

    t.is_true(plain and plain["/"], "expected a CPE from the body")
    t.same(plain["/"], {"cpe:/a:mozilla:bugzilla:5.0.4"})
  end,
}

suite[#suite + 1] = {
  name = "publishes findings to host.registry and port.version.cpe",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host, port = t.host(), t.port()
    env.action(host, port)

    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "vulners.nse reads the CPEs from here")
    t.contains(port.version.cpe, "cpe:/a:f5:nginx:1.13.4",
      "the CPE must also reach the port version table")
  end,
}

suite[#suite + 1] = {
  name = "reports nothing when no pattern matches",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "totally-unknown"},
      body = "<html>nothing to see</html>"})

    t.is_nil(env.action(t.host(), t.port()), "no match must produce no output")
  end,
}

suite[#suite + 1] = {
  name = "does not repeat the same CPE found on several paths",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] = {"/", "/index.php"}}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local host = t.host()
    env.action(host, t.port())

    local seen = 0
    for _, cpe in ipairs(host.registry.vulners_cpe[80]) do
      if cpe == "cpe:/a:f5:nginx:1.13.4" then seen = seen + 1 end
    end
    t.equals(seen, 1, "the same CPE seen twice must be registered once")
  end,
}

suite[#suite + 1] = {
  name = "requests every configured path",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] =
      {"/", "/index.php", "/about.html"}}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local seen = {}
    for _, req in ipairs(http.requests) do seen[req.path] = true end
    for _, path in ipairs({"/", "/index.php", "/about.html"}) do
      t.is_true(seen[path], "path " .. path .. " was never requested")
    end
  end,
}

suite[#suite + 1] = {
  name = "one unreachable path does not discard the other results",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] = {"/dead", "/alive"}}})
    http.handler = function(req)
      if req.path == "/dead" then
        return t.response({status = nil})
      end
      return t.response({status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})
    end

    local host = t.host()
    local output = env.action(host, t.port())
    local plain = t.collect_output(output)

    t.is_true(plain and plain["/alive"],
      "a failing path must not abort the scan of the remaining paths")
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4")
  end,
}

suite[#suite + 1] = {
  name = "state is not carried over between hosts",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local first = t.host({ip = "10.0.0.1"})
    env.action(first, t.port())

    -- nmap reuses a loaded script for every host it scans; the second host
    -- must get its own findings rather than an empty result because the
    -- first one already saw that CPE.
    local second = t.host({ip = "10.0.0.2"})
    local output = env.action(second, t.port())
    local plain = t.collect_output(output)

    t.is_true(plain and plain["/"], "second host must get its own output")
    t.contains(second.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "second host must get its own registry entry")
  end,
}

suite[#suite + 1] = {
  name = "paths given as a file name are read from that file",
  fn = function()
    local pathfile = testdir .. "/fixtures/paths_small.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = pathfile}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local seen = {}
    for _, req in ipairs(http.requests) do seen[req.path] = true end
    t.is_true(seen["/fixture-one"], "path from the file must be requested")
    t.is_true(seen["/fixture-two"], "path from the file must be requested")
    t.length(http.requests, 2, "only the paths from the file must be requested")
  end,
}

suite[#suite + 1] = {
  name = "falls back to the shipped path list when the argument is unusable",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] = 42}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    -- http-vulners-paths.txt ships over a hundred entries; the exact number
    -- may change, the fallback must simply not collapse to nothing.
    t.is_true(#http.requests > 10,
      "expected the default path list, got " .. #http.requests .. " requests")
  end,
}

suite[#suite + 1] = {
  name = "no output and no crash when the port has no version table",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local port = t.port({version = false})
    t.is_nil(env.action(t.host(), port), "a port without version data yields nothing")
    t.length(http.requests, 0, "and no request should be issued")
  end,
}

suite[#suite + 1] = {
  name = "all paths travel in one pipeline",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] =
      {"/", "/index.php", "/about.html"}}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.length(http.requests, 3, "each path is requested exactly once")
    for _, req in ipairs(http.requests) do
      t.is_true(req.pipelined, "requests must go through the pipeline, not one by one")
    end
  end,
}

suite[#suite + 1] = {
  name = "the pattern file is parsed once per scan, not once per port",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local reads = 0
    local nmap = t.nmap_double({fetchfile = function(name)
      reads = reads + 1
      return nil
    end})
    env = t.load_script(SCRIPT, {args = ONE_PATH, modules = {http = http, nmap = nmap}})

    env.action(t.host({ip = "10.0.0.1"}), t.port())
    env.action(t.host({ip = "10.0.0.2"}), t.port())
    env.action(t.host({ip = "10.0.0.3"}), t.port())

    t.equals(reads, 1, "the pattern file must be looked up once for the whole scan")
  end,
}

suite[#suite + 1] = {
  name = "a pipeline that comes back short does not lose the served paths",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] =
      {"/first", "/second", "/third"}}})
    http.handler = function(req)
      if req.path == "/third" then
        -- The connection dies mid-pipeline; nmap returns a shorter list.
        return "cut_short"
      end
      return t.response({status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})
    end

    local host = t.host()
    local plain = t.collect_output(env.action(host, t.port()))

    t.is_true(plain and plain["/first"], "the paths that did answer must be reported")
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4")
  end,
}

suite[#suite + 1] = {
  name = "paths are requested in a stable order",
  fn = function()
    local env, http = load({args = {["http-vulners-regex.paths"] =
      {"/zeta", "/alpha", "/mid"}}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local order = {}
    for _, req in ipairs(http.requests) do order[#order + 1] = req.path end
    t.same(order, {"/alpha", "/mid", "/zeta"},
      "a rescan of the same target must report the same paths")
  end,
}

suite[#suite + 1] = {
  name = "a malformed pattern file is reported, not crashed on",
  fn = function()
    local http = t.http_double()
    local broken = testdir .. "/fixtures/broken_regex.json"
    local nmap = t.nmap_double({fetchfile = function() return broken end})
    local env = t.load_script(SCRIPT, {
      args = ONE_PATH,
      modules = {http = http, nmap = nmap},
    })
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local output = t.no_error(function()
      return env.action(t.host(), t.port())
    end, "truncated json must not raise")
    t.is_nil(output, "an unusable pattern file yields no output")
  end,
}

suite[#suite + 1] = {
  name = "matches software listed in the shipped pattern set",
  fn = function()
    local cases = {
      {header = {["X-Powered-By"] = "PHP/5.6.38"}, cpe = "cpe:/a:php:php:5.6.38"},
      {header = {["X-Jenkins"] = "2.121.1"}, cpe = "cpe:/a:jenkins:jenkins:2.121.1"},
      {header = {["Server"] = "lighttpd/1.4.45"}, cpe = "cpe:/a:lighttpd:lighttpd:1.4.45"},
      {header = {["Server"] = "Apache/2.4.7 (Ubuntu)"}, cpe = "cpe:/a:apache:http_server:2.4.7"},
    }

    for _, case in ipairs(cases) do
      local env, http = load({args = ONE_PATH})
      always(http, {status = 200, header = case.header, body = ""})

      local output = env.action(t.host(), t.port())
      local plain = t.collect_output(output)
      t.is_true(plain and plain["/"],
        "no CPE for header " .. t.repr(case.header))

      local found = false
      for _, cpe in ipairs(plain["/"]) do
        if cpe == case.cpe then found = true end
      end
      t.is_true(found, string.format("expected %s among %s",
        case.cpe, t.repr(plain["/"])))
    end
  end,
}

suite[#suite + 1] = {
  name = "a capture is not allowed to run past its header line",
  fn = function()
    -- The header block is matched in one pass, so an unbounded pattern used to
    -- swallow every following header - a session cookie among them - into the
    -- CPE, the report and the API request.
    local env, http = load({args = ONE_PATH})
    http.handler = function()
      return t.response({
        status = 200,
        rawheader = {
          "Server: Sun-Java-System-Web-Server/7.0",
          "Set-Cookie: JSESSIONID=8F3A9C2E1D7B4A6F; Path=/",
        },
        body = "",
      })
    end

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
    -- A reverse proxy names the same product twice; the version behind the
    -- proxy and the one in front of it are different findings.
    local env, http = load({args = ONE_PATH})
    http.handler = function()
      return t.response({
        status = 200,
        rawheader = {"Server: nginx/1.13.4", "Via: nginx/1.21.0"},
        body = "",
      })
    end

    local host = t.host()
    env.action(host, t.port())

    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4")
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
    local pathfile = testdir .. "/fixtures/paths_small.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = pathfile}})

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
    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "the paths behind the refused one still produce their findings")
  end,
}

suite[#suite + 1] = {
  name = "a pipeline that answers nothing at all does not loop forever",
  fn = function()
    local pathfile = testdir .. "/fixtures/paths_small.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = pathfile}})

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
    local env, http = load({args = ONE_PATH})
    http.handler = function(req)
      if req.path == "/real" then
        return t.response({status = 200, rawheader = {"Server: nginx/1.13.4"}, body = ""})
      end
      return t.response({status = 302, header = {location = "/real"}, body = ""})
    end

    local host = t.host()
    env.action(host, t.port())

    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "the CPE lives on the redirect target, not in the 302 envelope")
  end,
}

suite[#suite + 1] = {
  name = "a redirect target is fetched once, however many paths point at it",
  fn = function()
    local pathfile = testdir .. "/fixtures/paths_small.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = pathfile}})
    local target_requests = 0
    http.handler = function(req)
      if req.path == "/real" then
        target_requests = target_requests + 1
        return t.response({status = 200, rawheader = {"Server: nginx/1.13.4"}, body = ""})
      end
      return t.response({status = 301, header = {location = "/real"}, body = ""})
    end

    env.action(t.host(), t.port())
    t.equals(target_requests, 1,
      "a site that redirects everything to one page must cost one request")
  end,
}

suite[#suite + 1] = {
  name = "a redirect leaving the host is not followed",
  fn = function()
    local env, http = load({args = ONE_PATH})
    http.handler = function(req)
      return t.response({
        status = 302,
        header = {location = "http://example.com/elsewhere"},
        body = "",
      })
    end

    env.action(t.host(), t.port())
    t.length(http.matching("elsewhere"), 0,
      "somebody else's server is not ours to fingerprint")
  end,
}

suite[#suite + 1] = {
  name = "paths from a CRLF file arrive without the carriage return",
  fn = function()
    local pathfile = testdir .. "/fixtures/paths_crlf.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = pathfile}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.is_true(#http.requests > 0, "the file must still be usable")
    for _, req in ipairs(http.requests) do
      t.is_nil(req.path:find("[\r\n]"),
        "a bare CR in the request line earns a 400 from every strict server")
      t.matches(req.path, "^/", "a path without its slash is given one")
    end
  end,
}

suite[#suite + 1] = {
  name = "a named paths file that cannot be read stops the sweep",
  fn = function()
    -- An operator who names a file means that file; quietly falling back to
    -- the shipped 125 paths sends the scan where it was told not to go.
    local missing = testdir .. "/fixtures/no_such_paths_file.txt"
    local env, http = load({args = {["http-vulners-regex.paths"] = missing}})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    t.length(http.requests, 0, "nothing may be requested")
  end,
}

suite[#suite + 1] = {
  name = "a CPE nmap already published is not added to the port a second time",
  fn = function()
    local env, http = load({args = ONE_PATH})
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    local port = t.port({cpe = {"cpe:/a:f5:nginx:1.13.4"}})
    local host = t.host()
    env.action(host, port)

    t.contains(host.registry.vulners_cpe[80], "cpe:/a:f5:nginx:1.13.4",
      "the finding must have been made in the first place")

    local count = 0
    for _, cpe in ipairs(port.version.cpe) do
      if cpe == "cpe:/a:f5:nginx:1.13.4" then count = count + 1 end
    end
    t.equals(count, 1, "a duplicate <cpe> element makes every consumer count twice")
  end,
}

suite[#suite + 1] = {
  name = "the site root is in the shipped path list",
  fn = function()
    -- Fifty of the shipped patterns fingerprint the HTML of a home page; the
    -- list used to ask for everything except "/".
    local env, http = load()
    always(http, {status = 200, header = {["Server"] = "nginx/1.13.4"}, body = ""})

    env.action(t.host(), t.port())

    local asked = {}
    for _, req in ipairs(http.requests) do asked[req.path] = true end
    t.is_true(asked["/"], "the home page must be requested")
  end,
}

suite[#suite + 1] = {
  name = "what one port runs is not attributed to another port",
  fn = function()
    -- The hand-off used to be host-wide, so a web server's CPEs were reported
    -- again under every other open port of the host - nginx CVEs filed against
    -- the SSH service.
    local env, http = load({args = ONE_PATH})
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
    -- rate-limiting hosts.
    local env, http = load({args = ONE_PATH})
    http.handler = function() return "no_connection" end

    t.is_nil(env.action(t.host(), t.port()), "nothing found, nothing reported")
  end,
}

return suite
