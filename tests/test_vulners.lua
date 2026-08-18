--- Tests for vulners.nse (the free, key-less variant).
--
-- The script turns CPEs into requests against the Vulners burp API, filters
-- the answer by CVSS and renders one line per vulnerability. Everything below
-- exercises that pipeline through action(), i.e. the way nmap calls it.

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local SCRIPT = root .. "/vulners.nse"

local function load(opts)
  opts = opts or {}
  local http = t.http_double()
  local env = t.load_script(SCRIPT, {
    args = opts.args,
    modules = {http = http, nmap = t.nmap_double()},
  })
  return env, http
end

--- One entry as the burp API returns it.
local function vuln(opts)
  return {
    _source = {
      id = opts.id,
      type = opts.type or "cve",
      bulletinFamily = opts.family or "NVD",
      -- The live burp endpoint answers with score, severity, version, vector.
      cvss = {score = opts.cvss, version = opts.cvss_version},
    },
  }
end

--- A complete, successful API response body.
local function api_body(vulns)
  return json.generate({result = "OK", data = {search = vulns}})
end

--- Answer every request with the same body.
local function answer(http, body, status)
  http.handler = function()
    return t.response({status = status or 200, body = body})
  end
end

--- Extract the ids from a result list, in order.
local function ids(rows)
  local out = {}
  for _, row in ipairs(rows or {}) do out[#out + 1] = row.id end
  return out
end

local CPE = "cpe:/a:isc:bind:9.8.2"

local suite = {}

-- ----------------------------------------------------------------- portrule

suite[#suite + 1] = {
  name = "portrule requires a version or a CPE from the registry",
  fn = function()
    local env = load()
    t.is_true(env.portrule(t.host(), t.port({version = "1.0"})),
      "a detected version puts the port in scope")
    t.is_false(env.portrule(t.host(), t.port({})),
      "no version and no registry means nothing to ask about")
    t.is_true(env.portrule(t.host({registry = {vulners_cpe = {[80] = {CPE}}}}), t.port({})),
      "CPEs from http-vulners-regex put the port in scope")
  end,
}

-- ------------------------------------------------------------------ requests

suite[#suite + 1] = {
  name = "asks the API for the CPE and its version",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    t.length(http.requests, 1, "one CPE means one request")
    local request = http.requests[1]
    t.equals(request.host, "vulners.com", "the default API host is used")
    t.equals(request.port, 443, "the default API port is used")
    t.matches(request.path, "^/api/v3/burp/software/%?", "the burp endpoint is used")
    t.matches(request.path, "type=cpe", "the request must be typed as a CPE lookup")
    t.matches(request.path, "version=9%.8%.2", "the version goes into the query")
    t.matches(request.path, "software=cpe:/a:isc:bind:9%.8%.2",
      "the CPE goes into the query exactly as it is")
  end,
}

suite[#suite + 1] = {
  name = "the CPE is not percent-encoded, the API does not decode it",
  fn = function()
    -- The lookup must not depend on the endpoint decoding anything: on
    -- 2026-08-18 escaped values were refused for a few hours while the raw
    -- form, which nmap's own copy of this script sends, kept working.
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local path = http.requests[1].path
    t.is_nil(path:find("%%3A"), "a colon must travel as a colon")
    t.is_nil(path:find("%%2F"), "a slash must travel as a slash")
  end,
}

suite[#suite + 1] = {
  name = "characters that would corrupt the query are escaped",
  fn = function()
    local env, http = load()
    http.handler = function(req)
      if req.path:find("type=cpe") then
        return t.response({status = 200, body = api_body({})})
      end
      return t.response({status = 200, body = api_body({
        vuln({id = "CVE-2012-1667", cvss = 8.5}),
      })})
    end

    -- A version banner is attacker-controlled text; it must not be able to add
    -- a query argument of its own or break the request line.
    local port = t.port({product = "Foo & Bar", version = "1.0 beta", cpe = {CPE}})
    env.action(t.host(), port)

    local software = http.matching("type=software")
    t.is_true(#software > 0, "the software lookup is still issued")
    local path = software[1].path
    t.matches(path, "software=Foo%%20%%26%%20Bar", "space and ampersand are escaped")
    t.is_nil(path:find("+", 1, true),
      "a plus would be read back as a space, so it is escaped too")
    t.matches(path, "version=1%.0%%20beta", "the version keeps its own argument")
    t.length(t.split_query(path), 3, "exactly three query arguments are sent")
  end,
}

suite[#suite + 1] = {
  name = "identifies itself with a User-Agent",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local headers = http.requests[1].options.header
    t.matches(headers["User-Agent"], "^Vulners NMAP Plugin %d+%.%d+$",
      "vulners.com tells plugin generations apart by this string")
  end,
}

suite[#suite + 1] = {
  name = "retries a few times when the server cannot be reached",
  fn = function()
    local env, http = load()
    http.handler = function() return nil end

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(env.action(t.host(), port), "an unreachable API yields no output")
    t.is_true(#http.requests > 1,
      "a single failed attempt must not be the end of it")
  end,
}

-- -------------------------------------------------------------------- output

suite[#suite + 1] = {
  name = "sorts vulnerabilities by CVSS, highest first",
  fn = function()
    local env, http = load()
    answer(http, api_body({
      vuln({id = "CVE-2010-3615", cvss = 5.0}),
      vuln({id = "CVE-2012-1667", cvss = 8.5}),
      vuln({id = "CVE-2015-5986", cvss = 7.1}),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)

    t.same(ids(plain[CPE]), {"CVE-2012-1667", "CVE-2015-5986", "CVE-2010-3615"})
  end,
}

suite[#suite + 1] = {
  name = "mincvss hides everything below the threshold",
  fn = function()
    local env, http = load({args = {["vulners.mincvss"] = "7.0"}})
    answer(http, api_body({
      vuln({id = "CVE-2010-3615", cvss = 5.0}),
      vuln({id = "CVE-2012-1667", cvss = 8.5}),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)

    t.same(ids(plain[CPE]), {"CVE-2012-1667"}, "only the 8.5 entry passes mincvss=7.0")
  end,
}

suite[#suite + 1] = {
  name = "marks exploits and renders them with a link",
  fn = function()
    local env, http = load()
    answer(http, api_body({
      vuln({id = "EDB-ID:45233", type = "exploitdb", family = "exploit", cvss = 0},
        "exploit"),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)
    local row = plain[CPE][1]

    t.is_true(row.is_exploit, "bulletinFamily=exploit marks the row as an exploit")
    local rendered = t.render(row)
    t.matches(rendered, "EXPLOIT", "the user must see the exploit marker")
    t.matches(rendered, "https://vulners%.com/exploitdb/EDB%-ID:45233",
      "the row links to the vulners page")
  end,
}

suite[#suite + 1] = {
  name = "exploits stay visible even below mincvss",
  fn = function()
    local env, http = load({args = {["vulners.mincvss"] = "9.0"}})
    answer(http, api_body({
      vuln({id = "EDB-ID:45233", type = "exploitdb", family = "exploit", cvss = 0}),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)

    t.is_true(plain and plain[CPE], "a working exploit is worth showing regardless")
  end,
}

suite[#suite + 1] = {
  name = "the cvss version is reported when the API sends one",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5, cvss_version = "3.1"})}))

    local plain = t.collect_output(env.action(t.host(),
      t.port({version = "9.8.2", cpe = {CPE}})))
    local row = plain[CPE][1]

    t.equals(row.cvss_type, "cvss3.1")
    t.matches(t.render(row), "cvss3%.1: 8%.5", "the rendered line shows the cvss version")
  end,
}

suite[#suite + 1] = {
  name = "an unscored entry renders without an empty score column",
  fn = function()
    local env, http = load()
    answer(http, api_body({{_source = {id = "VULNERS:NOSCORE", type = "cve",
      bulletinFamily = "NVD"}}}))

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    end, "a bulletin without cvss must not raise"))

    t.is_true(plain and plain[CPE], "it must still be reported")
    t.is_nil(t.render(plain[CPE][1]):find("cvss:"),
      "an unscored row must not print an empty score column")
  end,
}

suite[#suite + 1] = {
  name = "api_host and api_port are honoured",
  fn = function()
    local env, http = load({args = {
      ["vulners.api_host"] = "vulners.internal",
      ["vulners.api_port"] = "8443",
    }})
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    t.equals(http.requests[1].host, "vulners.internal")
    t.equals(http.requests[1].port, 8443, "the port must arrive as a number")
  end,
}

suite[#suite + 1] = {
  name = "a CPE already looked up in this scan is not asked about again",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host({ip = "10.0.0.1"}), t.port({version = "9.8.2", cpe = {CPE}}))
    local after_first = #http.requests

    local second = t.collect_output(
      env.action(t.host({ip = "10.0.0.2"}), t.port({version = "9.8.2", cpe = {CPE}})))

    t.equals(#http.requests, after_first, "the second host is served from the cache")
    t.is_true(second[CPE], "and still gets the answer")
  end,
}

suite[#suite + 1] = {
  name = "a CPE listed twice is looked up once",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    -- The registry and the port version table commonly overlap.
    local host = t.host({registry = {vulners_cpe = {[80] = {CPE}}}})
    env.action(host, t.port({version = "9.8.2", cpe = {CPE}}))

    t.length(http.requests, 1, "the duplicate must be dropped before asking")
  end,
}

-- ----------------------------------------------------------- error handling

suite[#suite + 1] = {
  name = "a non-200 answer produces no output and no crash",
  fn = function()
    local env, http = load()
    answer(http, "gateway is down", 502)

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(t.no_error(function() return env.action(t.host(), port) end,
      "HTTP 502 must be handled"))
    t.is_true(#http.requests > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "an unparsable body produces no output and no crash",
  fn = function()
    local env, http = load()
    answer(http, "<html>not json at all</html>")

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(t.no_error(function() return env.action(t.host(), port) end,
      "a broken body must be handled"))
    t.is_true(#http.requests > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "a 4xx answer is not retried",
  fn = function()
    local env, http = load()
    answer(http, "forbidden", 403)

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    t.length(http.requests, 1,
      "exactly one request: it was made, and a 4xx is not retried")
  end,
}

suite[#suite + 1] = {
  name = "an unreachable API is left alone for the rest of the scan",
  fn = function()
    local env, http = load()
    http.handler = function() return nil end

    env.action(t.host({ip = "10.0.0.1"}), t.port({version = "9.8.2", cpe = {CPE}}))
    local attempts = #http.requests
    t.is_true(attempts > 1, "the first host must have tried, and retried")

    env.action(t.host({ip = "10.0.0.2"}), t.port({version = "9.8.2", cpe = {CPE}}))
    t.equals(#http.requests, attempts,
      "after giving up, the rest of the scan must not keep trying")
  end,
}

suite[#suite + 1] = {
  name = "result other than OK produces no output",
  fn = function()
    local env, http = load()
    answer(http, json.generate({result = "error", data = {error = "quota exceeded"}}))

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(env.action(t.host(), port), "an API level error is not a result")
    t.is_true(#http.requests > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "an entry without a CVSS score does not break sorting",
  fn = function()
    local env, http = load()
    -- Vulners does not score every bulletin; such rows used to reach
    -- table.sort with cvss == nil.
    answer(http, api_body({
      vuln({id = "CVE-2012-1667", cvss = 8.5}),
      vuln({id = "VULNERS:NOSCORE"}),
    }))

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    local output = t.no_error(function() return env.action(t.host(), port) end,
      "a missing CVSS score must not raise")
    local plain = t.collect_output(output)
    t.is_true(plain and plain[CPE], "the scored entry must still be reported")
  end,
}

-- ------------------------------------------------------------------ lookups

suite[#suite + 1] = {
  name = "retries a CPE with the update part split off",
  fn = function()
    local env, http = load()
    local answered = false
    http.handler = function(req)
      -- Only the second shape of the CPE has an answer.
      if req.path:find("rc1") and not answered then
        answered = true
        return t.response({status = 200, body = api_body({})})
      end
      return t.response({status = 200, body = api_body({
        vuln({id = "CVE-2012-1667", cvss = 8.5}),
      })})
    end

    local cpe = "cpe:/a:isc:bind:9.8.2rc1"
    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {cpe}}))

    t.is_true(#http.requests >= 2,
      "an empty answer for a versioned CPE must be retried in another shape")
    t.is_true(t.collect_output(output), "the retry result must be reported")
  end,
}

suite[#suite + 1] = {
  name = "falls back to a software lookup when no CPE matched",
  fn = function()
    local env, http = load()
    http.handler = function(req)
      if req.path:find("type=cpe") then
        return t.response({status = 200, body = api_body({})})
      end
      return t.response({status = 200, body = api_body({
        vuln({id = "CVE-2012-1667", cvss = 8.5}),
      })})
    end

    local port = t.port({product = "ISC BIND", version = "9.8.2", cpe = {CPE}})
    local output = env.action(t.host(), port)
    local plain = t.collect_output(output)

    t.is_true(plain["ISC BIND 9.8.2"],
      "the software lookup is keyed by product and version")
    t.is_true(#http.matching("type=software") > 0, "a software lookup must be issued")
  end,
}

suite[#suite + 1] = {
  name = "looks up CPEs published by http-vulners-regex",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2018-16843", cvss = 7.5})}))

    local registry_cpe = "cpe:/a:nginx:nginx:1.13.4"
    local host = t.host({registry = {vulners_cpe = {[80] = {registry_cpe}}}})
    local output = env.action(host, t.port({version = "1.13.4", cpe = {}}))
    local plain = t.collect_output(output)

    t.is_true(plain[registry_cpe],
      "CPEs discovered by the regex script must be looked up as well")
  end,
}

suite[#suite + 1] = {
  name = "queries both nginx vendor spellings and merges the answers",
  fn = function()
    local env, http = load()
    http.handler = function(req)
      if req.path:find("igor") then
        return t.response({status = 200, body = api_body({
          vuln({id = "CVE-2009-2629", cvss = 9.0}),
        })})
      end
      return t.response({status = 200, body = api_body({
        vuln({id = "CVE-2018-16843", cvss = 7.5}),
      })})
    end

    local output = env.action(t.host(),
      t.port({version = "1.13.4", cpe = {"cpe:/a:nginx:nginx:1.13.4"}}))
    local plain, order = t.collect_output(output)

    t.length(order, 1, "both spellings belong to one result key")
    local merged = plain[order[1]]
    t.same(ids(merged), {"CVE-2009-2629", "CVE-2018-16843"},
      "merged results stay sorted by CVSS")
  end,
}

suite[#suite + 1] = {
  name = "a bulletin returned for both nginx spellings is reported once",
  fn = function()
    -- The API answers both vendor spellings with the same nginx bulletins, so
    -- concatenating the two lists prints every shared entry twice.
    local env, http = load()
    answer(http, api_body({
      vuln({id = "CVE-2018-16843", cvss = 7.5}),
      vuln({id = "CVE-2009-2629", cvss = 9.0}),
    }))

    local output = env.action(t.host(),
      t.port({version = "1.13.4", cpe = {"cpe:/a:nginx:nginx:1.13.4"}}))
    local plain, order = t.collect_output(output)

    t.same(ids(plain[order[1]]), {"CVE-2009-2629", "CVE-2018-16843"},
      "each bulletin appears exactly once")
  end,
}

suite[#suite + 1] = {
  name = "a failed request is not remembered as an empty answer",
  fn = function()
    -- A rate limit or a 5xx used to be cached as "this software is clean" for
    -- the rest of the scan, so every later host was silently reported clean.
    local env, http = load()
    local fail = true
    http.handler = function()
      if fail then
        return t.response({status = 500, body = ""})
      end
      return t.response({status = 200,
        body = api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})})})
    end

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(env.action(t.host(), port), "the failing lookup reports nothing")

    fail = false
    local plain = t.collect_output(env.action(t.host({ip = "127.0.0.2"}), port))
    t.same(ids(plain[CPE]), {"CVE-2012-1667"},
      "the next host asks again and gets the answer")
  end,
}

suite[#suite + 1] = {
  name = "an empty answer is remembered, unlike a failure",
  fn = function()
    local env, http = load()
    answer(http, api_body({}))

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    env.action(t.host(), port)
    local after_first = #http.requests

    env.action(t.host({ip = "127.0.0.2"}), port)
    t.equals(#http.requests, after_first,
      "a CPE the API answered about is not asked again")
  end,
}

suite[#suite + 1] = {
  name = "the request is byte-identical to the one nmap's own copy sends",
  fn = function()
    -- The answers are cached at the CDN for four hours, keyed by the URL. The
    -- copy of this script that ships with nmap sends
    -- "?software=<raw>&version=<raw>&type=<raw>", so sending anything else -
    -- a different argument order, or escaped characters - would miss every
    -- entry that population has already warmed and add load to the origin.
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    t.equals(http.requests[1].path,
      "/api/v3/burp/software/?software=" .. CPE .. "&version=9.8.2&type=cpe",
      "the query must match what the installed plugin sends, argument for argument")
  end,
}

-- ------------------------------------------------------- defensive behaviour

suite[#suite + 1] = {
  name = "a port without CPEs but with registry CPEs does not crash",
  fn = function()
    local env, http = load()
    answer(http, api_body({vuln({id = "CVE-2018-16843", cvss = 7.5})}))

    -- portrule lets this through: no version data at all, but the regex
    -- script left CPEs for this host.
    local host = t.host({registry = {vulners_cpe = {[80] = {"cpe:/a:nginx:nginx:1.13.4"}}}})
    local port = t.port({version = false})

    local output = t.no_error(function() return env.action(host, port) end,
      "a port without a version table must not raise")
    t.is_true(t.collect_output(output), "registry CPEs must still be reported")
  end,
}

suite[#suite + 1] = {
  name = "a version without a product name does not crash the software lookup",
  fn = function()
    local env, http = load()
    answer(http, api_body({}))

    -- nmap can report a version while leaving product unset.
    local port = t.port({product = nil, version = "9.8.2", cpe = {}})
    t.no_error(function() return env.action(t.host(), port) end,
      "a missing product name must not raise")
  end,
}

return suite
