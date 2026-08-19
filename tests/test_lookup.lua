--- Discovery on the free path of vulners.nse.
--
-- This suite owns one question: what does a key-less run ask, of which
-- endpoint, how often, and what does it remember. The CPEs a port carries turn
-- into GET /api/v3/burp/software/ lookups, the answers are cached for the whole
-- scan, filtered by mincvss and ranked; everything below exercises that through
-- action(), i.e. the way nmap calls it.
--
-- Two things every case here has to state, because 2.0 made both variable:
--
--   * The MODE. A run that finds a token adds POST /api/v3/search/id/ to every
--     finding and can spend a credit on /api/v4/audit/smart, which changes both
--     the request count and the shape of the answer. load_free() below fakes os
--     and io, so no case can pick up the developer's real VULNERS_API_KEY or
--     ~/.nmap/vulners.key: the suite is the free path on every machine.
--   * The SWEEP. The merged action fingerprints every port shortport.http
--     accepts, and the harness port defaults to 80/http, so a case that counted
--     http.requests would be counting 125 sweep paths. The sweep is therefore
--     off unless a case asks for it, and request counts select the API leg by
--     its ENDPOINT - burp() below - never by its host: with a token, search/id
--     and audit/smart reach that same host.

local t, testdir, root = ...

local json = require "json"

--- Load the merged script on the free path, with the path sweep off.
--
-- Named for the mode on purpose: a case reads "load_free()" and its reader
-- knows which of the two request programmes is under test.
local function load_free(opts)
  opts = opts or {}
  return t.load_vulners({root = root, args = opts.args, clock = opts.clock})
end

--- The requests that went to the lookup endpoint.
--
-- The discriminator is the path, not the host. Both the enrichment POST and the
-- billed audit call go to the same host as these, so a host filter would stop
-- telling free traffic from keyed traffic the moment a case gained a token.
local function burp(http)
  return http.matching("/api/v3/burp/")
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

--- The finding groups of a result, without the two scalar elems 2.0 opens with.
--
-- output.schema and output.mode are elements of the same table as the CPE
-- groups, so "how many things were reported" has to skip them.
local function group_keys(order)
  local keys = {}
  for _, key in ipairs(order or {}) do
    if key ~= "schema" and key ~= "mode" then keys[#keys + 1] = key end
  end
  return keys
end

--- The rendered line that mentions a given id, from action's second value.
local function line_with(text, needle)
  for line in tostring(text or ""):gmatch("[^\n]+") do
    if line:find(needle, 1, true) then return line end
  end
end

local CPE = "cpe:/a:isc:bind:9.8.2"

local suite = {}

-- ----------------------------------------------------------------- portrule

suite[#suite + 1] = {
  name = "portrule requires a version or a CPE from the registry",
  fn = function()
    local env = load_free()

    -- 2.0's portrule is the union of the three 1.x rules and tests
    -- shortport.http first, so on the harness default of 80/http it answers
    -- true on its own. The version and registry branches can only be witnessed
    -- on a port shortport.http rejects - otherwise these assertions pass
    -- through the wrong clause and measure nothing.
    t.is_true(env.portrule(t.host(),
      t.port({number = 22, service = "ssh", version = "1.0"})),
      "a detected version puts a non-http port in scope")
    t.is_false(env.portrule(t.host(), t.port({number = 22, service = "ssh"})),
      "no version and no registry means nothing to ask about")
    t.is_true(env.portrule(t.host({registry = {vulners_cpe = {[22] = {CPE}}}}),
      t.port({number = 22, service = "ssh"})),
      "CPEs another script left in the registry put the port in scope")

    t.is_true(env.portrule(t.host(), t.port({})),
      "and an http port is in scope with nothing known about it at all")
  end,
}

-- ------------------------------------------------------------------ requests

suite[#suite + 1] = {
  name = "asks the API for the CPE and its version",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local lookups = burp(http)
    t.length(lookups, 1, "one CPE means one lookup")
    local request = lookups[1]
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
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local path = burp(http)[1].path
    t.is_nil(path:find("%%3A"), "a colon must travel as a colon")
    t.is_nil(path:find("%%2F"), "a slash must travel as a slash")
  end,
}

suite[#suite + 1] = {
  name = "characters that would corrupt the query are escaped",
  fn = function()
    local env, http = load_free()
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

    -- The product+version leg only exists on the free path: with a token, an
    -- empty CPE answer is routed to the billed audit/smart endpoint instead.
    t.length(http.matching("/api/v4/audit/"), 0,
      "a key-less run never reaches a billed endpoint")

    local software = http.matching("type=software")
    t.is_true(#software > 0, "the software lookup is still issued")
    t.is_nil(software[1].options.header["X-Api-Key"],
      "and it carries no key: the burp endpoint is never authenticated")
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
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local headers = burp(http)[1].options.header
    t.matches(headers["User-Agent"], "^Vulners NMAP Plugin %d+%.%d+$",
      "vulners.com tells plugin generations apart by this string")
    t.is_nil(headers["X-Api-Key"], "there is no key on the free path to send")
  end,
}

suite[#suite + 1] = {
  name = "retries a few times when the server cannot be reached",
  fn = function()
    local env, http = load_free()
    http.handler = function() return nil end

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(env.action(t.host(), port), "an unreachable API yields no output")
    t.is_true(#burp(http) > 1,
      "a single failed attempt must not be the end of it: the retry budget is spent here")
  end,
}

-- -------------------------------------------------------------------- output

suite[#suite + 1] = {
  name = "sorts vulnerabilities by CVSS within one ranking bucket, highest first",
  fn = function()
    -- 2.0 ranks by exploitability first: KEV, then an active SSVC decision,
    -- then a known exploit, then EPSS, and only inside one of those buckets by
    -- CVSS. All three fixtures are plain unexploited CVEs with nothing the free
    -- endpoint could rank them by, so they share the last bucket and the
    -- tie-break - CVSS, descending - is what this case witnesses.
    local env, http = load_free()
    answer(http, api_body({
      vuln({id = "CVE-2010-3615", cvss = 5.0}),
      vuln({id = "CVE-2012-1667", cvss = 8.5}),
      vuln({id = "CVE-2015-5986", cvss = 7.1}),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)

    t.equals(plain.mode, "free", "the run must have taken the free path")
    t.same(ids(plain[CPE]), {"CVE-2012-1667", "CVE-2015-5986", "CVE-2010-3615"})
  end,
}

suite[#suite + 1] = {
  name = "mincvss hides everything below the threshold",
  fn = function()
    local env, http = load_free({args = {["vulners.mincvss"] = "7.0"}})
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
    local env, http = load_free()
    answer(http, api_body({
      vuln({id = "EDB-ID:45233", type = "exploitdb", family = "exploit", cvss = 0}),
    }))

    local output, text = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)
    local row = plain[CPE][1]

    -- What makes something an exploit is bulletinFamily, and nothing else:
    -- the 1.x list of exploit types is gone.
    t.equals(row.is_exploit, "true", "bulletinFamily=exploit marks the row as an exploit")
    t.equals(row.href, "https://vulners.com/exploitdb/EDB-ID:45233",
      "the row carries the vulners page as a structured element")

    -- The rendered marker is no longer the word EXPLOIT next to the line: it is
    -- a fixed-width token in the FLAGS column of the aligned table that action
    -- returns as its second value.
    t.matches(text, "FLAGS", "the rendered table must have a FLAGS column")
    local line = line_with(text, "EDB-ID:45233")
    t.is_true(line, "the exploit must appear in the rendered table")
    t.matches(line, "EXP", "the user must see the exploit flag on that row")
  end,
}

suite[#suite + 1] = {
  name = "exploits stay visible even below mincvss",
  fn = function()
    -- The carve-out has to be witnessed by a SCORED exploit. 2.0 reads a score
    -- of 0.0 as "not scored" - the free endpoint gives every exploit bulletin
    -- one - and mincvss never filters an unscored row, so an exploit at cvss=0
    -- would survive the threshold whether the carve-out existed or not.
    local env, http = load_free({args = {["vulners.mincvss"] = "9.0"}})
    answer(http, api_body({
      vuln({id = "EDB-ID:45233", type = "exploitdb", family = "exploit", cvss = 5.0}),
      vuln({id = "CVE-2010-3615", cvss = 5.0}),
    }))

    local output = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)

    t.same(ids(plain[CPE]), {"EDB-ID:45233"},
      "a working exploit is worth showing regardless, the equally scored CVE is not")
  end,
}

suite[#suite + 1] = {
  name = "the cvss version is reported when the API sends one",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5, cvss_version = "3.1"})}))

    local output, text = env.action(t.host(),
      t.port({version = "9.8.2", cpe = {CPE}}))
    local plain = t.collect_output(output)
    local row = plain[CPE][1]

    t.equals(row.cvss_type, "cvss3.1")
    t.equals(row.cvss, "8.5", "the score is a structured element of its own")
    -- The score is no longer printed as "cvss3.1: 8.5" beside the id; it has a
    -- column, and the version travels in the structured output only.
    local line = line_with(text, "CVE-2012-1667")
    t.is_true(line, "the finding must appear in the rendered table")
    t.matches(line, "8%.5", "the CVSS column carries the score")
  end,
}

suite[#suite + 1] = {
  name = "an unscored entry renders without an empty score column",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({{_source = {id = "VULNERS:NOSCORE", type = "cve",
      bulletinFamily = "NVD"}}}))

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    end, "a bulletin without cvss must not raise"))

    t.is_true(plain and plain[CPE], "it must still be reported")
    local row = plain[CPE][1]
    -- The cvss elem is emitted only when the API scored the bulletin, so an
    -- unscored row has no score to misread as 0.0 - but it still has a
    -- severity, because consumers index that key unguarded.
    t.is_nil(row.cvss, "an unscored row must not carry a score element")
    t.equals(row.severity, "Unknown", "and must still say what it does not know")
  end,
}

suite[#suite + 1] = {
  name = "api_host and api_port are honoured",
  fn = function()
    local env, http = load_free({args = {
      ["vulners.api_host"] = "vulners.internal",
      ["vulners.api_port"] = "8443",
    }})
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local request = burp(http)[1]
    t.equals(request.host, "vulners.internal")
    t.equals(request.port, 8443, "the port must arrive as a number")
  end,
}

suite[#suite + 1] = {
  name = "a CPE already looked up in this scan is not asked about again",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host({ip = "10.0.0.1"}), t.port({version = "9.8.2", cpe = {CPE}}))
    local after_first = #burp(http)

    local second = t.collect_output(
      env.action(t.host({ip = "10.0.0.2"}), t.port({version = "9.8.2", cpe = {CPE}})))

    t.equals(#burp(http), after_first, "the second host is served from the cache")
    t.is_true(second[CPE], "and still gets the answer")
  end,
}

suite[#suite + 1] = {
  name = "a CPE listed twice is looked up once",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    -- The registry and the port version table commonly overlap.
    local host = t.host({registry = {vulners_cpe = {[80] = {CPE}}}})
    env.action(host, t.port({version = "9.8.2", cpe = {CPE}}))

    t.length(burp(http), 1, "the duplicate must be dropped before asking")

    -- The overlap that actually happens on a web port is not two identical
    -- strings: nmap's own probe emits the igor_sysoev spelling of nginx while
    -- the sweep emits the f5 one, so the same product arrives twice under two
    -- names. Deduplicating on the literal string would report it twice.
    t.reset_registry()
    local env2, http2 = load_free()
    answer(http2, api_body({vuln({id = "CVE-2018-16843", cvss = 7.5})}))

    local spelt_twice = t.host({registry = {vulners_cpe =
      {[80] = {"cpe:/a:igor_sysoev:nginx:1.13.4"}}}})
    local output = env2.action(spelt_twice,
      t.port({version = "1.13.4", cpe = {"cpe:/a:f5:nginx:1.13.4"}}))
    local plain, order = t.collect_output(output)

    t.length(burp(http2), 3, "one product means one fan-out, not two")
    t.length(group_keys(order), 1, "and one entry in the report, not the same product twice")
    t.same(ids(plain[group_keys(order)[1]]), {"CVE-2018-16843"})
  end,
}

-- ----------------------------------------------------------- error handling

suite[#suite + 1] = {
  name = "a non-200 answer produces no output and no crash",
  fn = function()
    local env, http = load_free()
    answer(http, "gateway is down", 502)

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(t.no_error(function() return env.action(t.host(), port) end,
      "HTTP 502 must be handled"))
    t.is_true(#burp(http) > 0,
      "the lookup must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "an unparsable body produces no output and no crash",
  fn = function()
    local env, http = load_free()
    answer(http, "<html>not json at all</html>")

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(t.no_error(function() return env.action(t.host(), port) end,
      "a broken body must be handled"))
    t.is_true(#burp(http) > 0,
      "the lookup must have been made: otherwise this case passes on silence")

    -- The dangerous shape is not HTML. A failed parse hands back an error
    -- STRING, and indexing a string in Lua is legal and yields nil, so the page
    -- above never reaches the envelope's type guard. A body that is valid JSON
    -- but not an object hands back a NUMBER, and indexing that raises - which
    -- is the branch worth pinning.
    t.reset_registry()
    local env2, http2 = load_free()
    answer(http2, "12345")

    t.is_nil(t.no_error(function() return env2.action(t.host(), port) end,
      "a body that parses to something other than an object must be handled"))
    t.is_true(#burp(http2) > 0, "and that lookup must have been made too")
  end,
}

suite[#suite + 1] = {
  name = "a 4xx answer is not retried",
  fn = function()
    -- Two statuses, because they leave the retry loop by different doors: 403
    -- is the "this client is not welcome" door, which also stops the free leg
    -- for the rest of the scan, and 404 is the general rule that a 4xx cannot
    -- be fixed by asking again. Only 403 was covered before, so the general
    -- rule could be deleted with the case still green.
    local env, http = load_free()
    answer(http, "forbidden", 403)

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    t.length(burp(http), 1,
      "exactly one lookup: it was made, and a 403 is not retried")

    -- A new scan: the 403 above marks the free leg dead for the current one,
    -- which would hide whether the next status is retried or merely skipped.
    t.reset_registry()
    local env2, http2 = load_free()
    answer(http2, "no such thing", 404)

    env2.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))
    t.length(burp(http2), 1, "and a 404 is not retried either")
  end,
}

suite[#suite + 1] = {
  name = "an unreachable API is left alone for the rest of the scan",
  fn = function()
    local env, http = load_free()
    http.handler = function() return nil end

    env.action(t.host({ip = "10.0.0.1"}), t.port({version = "9.8.2", cpe = {CPE}}))
    local attempts = #burp(http)
    t.is_true(attempts > 1, "the first host must have tried, and retried")

    env.action(t.host({ip = "10.0.0.2"}), t.port({version = "9.8.2", cpe = {CPE}}))
    t.equals(#burp(http), attempts,
      "after giving up, the rest of the scan must not keep trying")
  end,
}

suite[#suite + 1] = {
  name = "result other than OK produces no output",
  fn = function()
    local env, http = load_free()
    local failing = true
    http.handler = function()
      if failing then
        return t.response({status = 200,
          body = json.generate({result = "error", data = {error = "quota exceeded"}})})
      end
      return t.response({status = 200,
        body = api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})})})
    end

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    t.is_nil(env.action(t.host(), port), "an API level error is not a result")
    t.is_true(#burp(http) > 0,
      "the lookup must have been made: otherwise this case passes on silence")

    -- The whole cost of this one is in the cache. A quota error arrives inside
    -- a 200 whose data block simply has no search results, so reading the HTTP
    -- status alone would file it as "this software is clean" and report every
    -- later host in the scan clean along with it.
    failing = false
    local plain = t.collect_output(env.action(t.host({ip = "127.0.0.2"}), port))
    t.same(ids(plain[CPE]), {"CVE-2012-1667"},
      "and it is not remembered as an empty answer either")
  end,
}

suite[#suite + 1] = {
  name = "an entry without a CVSS score does not break sorting",
  fn = function()
    local env, http = load_free()
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
    local env, http = load_free()
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

    t.is_true(#burp(http) >= 2,
      "an empty answer for a versioned CPE must be retried in another shape")
    t.is_true(#http.matching("software=cpe:/a:isc:bind:9.8.2:rc1") > 0,
      "and the other shape is the one with the update part split off")

    local plain = t.collect_output(output)
    t.same(ids(plain[cpe]), {"CVE-2012-1667"}, "the retry result must be reported")
  end,
}

suite[#suite + 1] = {
  name = "falls back to a software lookup when no CPE matched",
  fn = function()
    local env, http = load_free()
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

    -- Both halves of this are free-path behaviour: with a token the same empty
    -- CPE answer goes to audit/smart, and the group is keyed by whatever
    -- identity that endpoint resolved rather than by the human label.
    t.equals(plain.mode, "free", "the run must have taken the free path")
    t.is_true(plain["ISC BIND 9.8.2"],
      "the software lookup is keyed by product and version")
    t.is_true(#http.matching("type=software") > 0, "a software lookup must be issued")
  end,
}

suite[#suite + 1] = {
  name = "looks up CPEs another script left in the registry",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2018-16843", cvss = 7.5})}))

    -- host.registry.vulners_cpe is where 1.x's http-vulners-regex published
    -- what it found. That script is gone, but the read stays as best-effort
    -- compatibility for any third-party producer.
    local registry_cpe = "cpe:/a:nginx:nginx:1.13.4"
    local host = t.host({registry = {vulners_cpe = {[80] = {registry_cpe}}}})
    local output = env.action(host, t.port({version = "1.13.4", cpe = {}}))
    local plain = t.collect_output(output)

    t.is_true(plain[registry_cpe],
      "CPEs another script discovered must be looked up as well, under their own key")
  end,
}

suite[#suite + 1] = {
  name = "queries both nginx vendor spellings and merges the answers",
  fn = function()
    local env, http = load_free()
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
    local keys = group_keys(order)

    t.length(keys, 1, "all three spellings belong to one result key")
    local merged = plain[keys[1]]
    t.same(ids(merged), {"CVE-2009-2629", "CVE-2018-16843"},
      "merged results stay sorted by CVSS")
  end,
}

suite[#suite + 1] = {
  name = "a bulletin returned for both nginx spellings is reported once",
  fn = function()
    -- The API answers every vendor spelling with the same nginx bulletins, so
    -- concatenating the lists prints every shared entry two or three times.
    local env, http = load_free()
    answer(http, api_body({
      vuln({id = "CVE-2018-16843", cvss = 7.5}),
      vuln({id = "CVE-2009-2629", cvss = 9.0}),
    }))

    local output = env.action(t.host(),
      t.port({version = "1.13.4", cpe = {"cpe:/a:nginx:nginx:1.13.4"}}))
    local plain, order = t.collect_output(output)
    local keys = group_keys(order)

    t.length(keys, 1, "one product, one group")
    t.same(ids(plain[keys[1]]), {"CVE-2009-2629", "CVE-2018-16843"},
      "each bulletin appears exactly once")
  end,
}

suite[#suite + 1] = {
  name = "a failed request is not remembered as an empty answer",
  fn = function()
    -- A rate limit or a 5xx used to be cached as "this software is clean" for
    -- the rest of the scan, so every later host was silently reported clean.
    local env, http = load_free()
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
    local env, http = load_free()
    answer(http, api_body({}))

    local port = t.port({version = "9.8.2", cpe = {CPE}})
    env.action(t.host(), port)
    local after_first = #burp(http)

    env.action(t.host({ip = "127.0.0.2"}), port)
    t.equals(#burp(http), after_first,
      "a CPE the API answered about is not asked again")

    -- The endpoint has a second way of saying "nothing here": result=warning,
    -- which means the identity resolved and has no bulletins. It is the only
    -- other answer that may be cached, because it is the service stating a
    -- fact rather than a CDN replaying an error body.
    t.reset_registry()
    local env2, http2 = load_free()
    answer(http2, json.generate({result = "warning", data = {search = {}}}))

    env2.action(t.host(), port)
    local after_warning = #burp(http2)
    t.is_true(after_warning > 0, "the lookup must have been made")

    env2.action(t.host({ip = "127.0.0.2"}), port)
    t.equals(#burp(http2), after_warning,
      "an authoritative empty answer is remembered too")
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
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    local lookups = burp(http)
    t.length(lookups, 1, "one CPE, one lookup, nothing else on that endpoint")
    t.equals(lookups[1].path,
      "/api/v3/burp/software/?software=" .. CPE .. "&version=9.8.2&type=cpe",
      "the query must match what the installed plugin sends, argument for argument")
  end,
}

-- ------------------------------------------------------- defensive behaviour

suite[#suite + 1] = {
  name = "a port without CPEs but with registry CPEs does not crash",
  fn = function()
    local env, http = load_free()
    answer(http, api_body({vuln({id = "CVE-2018-16843", cvss = 7.5})}))

    -- portrule lets this through: no version table at all, but another script
    -- left CPEs for this host, and publish_cpes must not write through the nil.
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
    local env, http = load_free()
    answer(http, api_body({}))

    -- nmap can report a version while leaving product unset, and the free-path
    -- fallback builds its query out of "product .. ' ' .. version".
    local port = t.port({product = nil, version = "9.8.2", cpe = {}})
    t.no_error(function() return env.action(t.host(), port) end,
      "a missing product name must not raise")
  end,
}

suite[#suite + 1] = {
  name = "every malformed answer is survived, and none is remembered as clean",
  fn = function()
    -- Every byte below came from an HTTP response, so every one of these shapes
    -- is something a hostile or malfunctioning service can send. Two things are
    -- asserted for each: the port's whole result is not lost to a raise, and an
    -- answer that is not an authoritative "nothing known" is NOT cached - the
    -- CDN caches error bodies for four hours, so remembering one as clean would
    -- silence the software for the rest of the scan.
    local shapes = {
      {"a v3 error inside a 200",
       [[{"result":"error","data":{"error":"nope","errorCode":103}}]], false},
      {"a v4 array envelope on a v3 endpoint",
       [[{"result":[{"input":"X"}]}]], false},
      {"a pydantic validation failure",
       [[{"errors":[{"type":"literal_error","msg":"Value error","input":"X"}]}]], false},
      {"a bare JSON number", [[12345]], false},
      {"a bare JSON string", [["OK"]], false},
      -- Quoted rather than long-bracketed: [[[1,2,3]]] is ambiguous in Lua.
      {"a JSON array at the top level", "[1,2,3]", false},
      {"JSON null", [[null]], false},
      {"an empty body", "", false},
      {"HTML from a proxy", [[<html><body>403</body></html>]], false},
      -- result "OK" with unusable data is a malfunction, not a clean answer.
      {"data where a table is expected", [[{"result":"OK","data":"not a table"}]], false},

      -- These ARE answers, however odd: the entries are skipped, the answer is
      -- remembered, and the next host does not re-ask.
      {"search entries that are not tables",
       [[{"result":"OK","data":{"search":["x",7,null]}}]], true},
      {"a hit with no _source",
       [[{"result":"OK","data":{"search":[{"index":"y"}]}}]], true},
      {"a bulletin whose id is a number",
       [[{"result":"OK","data":{"search":[{"_source":{"id":42}}]}}]], true},
      {"cvss as a string",
       [[{"result":"OK","data":{"search":[{"_source":{"id":"CVE-2","cvss":"9.8"}}]}}]], true},
      {"a score and version of the wrong types",
       [[{"result":"OK","data":{"search":[{"_source":{"id":"CVE-3","cvss":{"score":"x","version":[]}}}]}}]], true},
      {"an authoritative empty answer",
       [[{"result":"warning","data":{"search_explain":{}}}]], true},
    }

    for _, shape in ipairs(shapes) do
      local name, body, should_remember = shape[1], shape[2], shape[3]
      t.reset_registry()
      local env, http = load_free()
      http.handler = function()
        return t.response({status = 200, body = body})
      end

      t.no_error(function()
        env.action(t.host(), t.port({product = "Foo", version = "1.0",
                                     cpe = {CPE}}))
      end, name .. " must not take the port's results down with it")

      local remembered = env._TEST.state().lookups[CPE] ~= nil
      t.equals(remembered, should_remember, string.format(
        "%s: cached=%s", name, tostring(remembered)))
    end
  end,
}

suite[#suite + 1] = {
  name = "waiting for a lookup somebody else holds is bounded, and then it asks anyway",
  fn = function()
    -- Wall-clock waits are why this needs a counted clock: the bound is 30
    -- seconds, so a case that measured it honestly would take longer than
    -- anyone runs a suite for.
    local clock = t.clock_double()
    local env, http = load_free({clock = clock})
    answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

    -- Somebody else claimed this identity and never finished.
    env._TEST.state().pending[CPE] = true
    local result = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    -- One bound, not one per pass. The two-pass loop used to wait in both, so a
    -- contended identity cost 60 seconds - and the nginx fan-out, which looks up
    -- three spellings, turned that into three minutes on a single port.
    t.is_true(clock.slept <= 31,
      string.format("the wait must be bounded once, slept %.1fs", clock.slept))
    t.is_true(clock.slept >= 29,
      string.format("and it really did wait, slept %.1fs", clock.slept))
    t.is_true(#burp(http) > 0,
      "after the bound it asks for itself rather than reporting nothing")
    t.is_true(result ~= nil, "and reports what it got")
  end,
}

suite[#suite + 1] = {
  name = "an answer another port already cached costs no wait and no request",
  fn = function()
    local clock = t.clock_double()
    local env, http = load_free({clock = clock})
    env._TEST.state().lookups[CPE] = {
      rows = {{id = "CVE-2012-1667", type = "cve", cvss = 8.5, family = "NVD"}},
      explain = {search_cpe = CPE, matched_cpe = CPE},
    }

    local result = env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}}))

    t.equals(clock.sleeps, 0, "a cached answer must not sleep")
    t.length(burp(http), 0, "nor ask again")
    t.is_true(result ~= nil, "and it is still reported")
  end,
}

suite[#suite + 1] = {
  name = "a Retry-After longer than the cap stops the leg; a bare 5xx does not",
  fn = function()
    -- The distinction matters. A bare 5xx can be one malformed identity
    -- upsetting the backend, so turning the leg off would report every later
    -- host as having nothing known. A Retry-After beyond what this scan will
    -- wait is the service saying "not soon", which is about the service.
    for _, case in ipairs({
      {header = "99999", stops = true,  why = "a delay beyond the cap"},
      {header = nil,     stops = false, why = "a bare 5xx"},
      {header = "abc",   stops = false, why = "an unparsable header"},
      {header = "5",     stops = false, why = "a delay within the cap"},
    }) do
      t.reset_registry()
      local clock = t.clock_double()
      local env, http = load_free({clock = clock})
      http.handler = function()
        return t.response({status = 503,
                           header = case.header and {["retry-after"] = case.header} or {}})
      end

      env.action(t.host(), t.port({product = "ISC BIND", version = "9.8.2",
                                   cpe = {CPE}}))
      t.equals(env._TEST.state().failed.free, case.stops,
        string.format("%s: expected the free leg stopped=%s",
          case.why, tostring(case.stops)))

      -- Nothing is ever cached from a failure, whichever way the leg went.
      t.is_nil(env._TEST.state().lookups[CPE],
        case.why .. ": a failure must not be remembered")
      t.is_true(clock.slept <= 130,
        string.format("%s: slept %.1fs, which is too long to be a retry budget",
          case.why, clock.slept))
    end
  end,
}

suite[#suite + 1] = {
  name = "a hostile identity cannot inject into the request or bloat it",
  fn = function()
    -- nmap builds CPEs out of banner text, so every one of these is something a
    -- target can arrange to be handed to this script.
    local hostile = {
      {"a query separator", "cpe:/a:foo:foo:1.0&type=software"},
      {"an extra parameter", "cpe:/a:foo:foo:1.0&software=evil"},
      {"a fragment", "cpe:/a:foo:foo:1.0#frag"},
      {"a percent-encoded wildcard", "cpe:/a:foo:foo:1.0%2A"},
      {"a literal wildcard", "cpe:/a:foo:foo:*"},
      {"a newline", "cpe:/a:foo:foo:1.0\nHost: evil"},
      {"a carriage return", "cpe:/a:foo:foo:1.0\r\nX: y"},
      {"a NUL", "cpe:/a:foo:foo:1.0\0evil"},
      {"high bytes", "cpe:/a:foo:foo:1.0\226\128\156"},
      {"a hostile vsftpd banner",
       "cpe:/a:vsftpd:vsftpd:3.0.3%3A%2A%3Apwned_\\_%22quoted%22_%25s"},
      -- Measured: a 4000-character version produced an 8 KB request line, which
      -- most servers refuse and which puts 8 KB of the target's choosing into
      -- the report as a group key.
      {"an absurdly long version", "cpe:/a:foo:foo:" .. string.rep("9", 4000)},
    }

    for _, case in ipairs(hostile) do
      local label, cpe = case[1], case[2]
      t.reset_registry()
      local env, http = load_free()
      answer(http, api_body({vuln({id = "CVE-2012-1667", cvss = 8.5})}))

      t.no_error(function()
        env.action(t.host(), t.port({product = "Foo", version = "1.0",
                                     cpe = {cpe}}))
      end, label .. " must not raise")

      for _, req in ipairs(http.requests) do
        local path = req.path or ""
        local query = path:match("%?(.*)$") or ""
        local parameters = 0
        for _ in query:gmatch("[^&]+") do parameters = parameters + 1 end

        -- software, version and type. Anything more is a parameter the target
        -- added, not one this script sent.
        t.is_true(parameters <= 3, string.format(
          "%s: %d query parameters in %s", label, parameters, path))
        t.is_nil(path:find("[\r\n%z]"), label .. ": a control byte reached the path")
        t.is_nil(path:find("[^\32-\126]"), label .. ": a non-ASCII byte reached the path")
        t.is_nil(path:find("#"), label .. ": an unescaped fragment marker reached the path")

        -- A bare * is the ANY wildcard: it would widen one lookup into "every
        -- vulnerability for this product", chosen by the target.
        local software = query:match("software=([^&]*)") or ""
        t.is_true(not software:find("%*") or software:find("%%2A") ~= nil,
          label .. ": a bare wildcard reached software=")

        t.is_true(#path < 1024, string.format(
          "%s: the request line grew to %d bytes", label, #path))
      end
    end
  end,
}

suite[#suite + 1] = {
  name = "a score of zero is read as unscored, not as a score of zero",
  fn = function()
    -- The free endpoint gives every exploit bulletin a score of 0.0, which
    -- means "nobody scored this" and not "this is harmless". Reading it as a
    -- number would put a CRITICAL/HIGH/LOW word and a 0.0 in the table for a
    -- finding nothing has actually rated. Two cases in this repository say so
    -- in their comments; neither built a row with cvss = 0 to prove it, so
    -- deleting the guard left all 254 green.
    local env, http = load_free({})
    answer(http, api_body({
      vuln({id = "EDB-ID:1", type = "exploitdb", family = "exploit", cvss = 0}),
    }))

    local plain = t.collect_output(
      env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}})))
    local row = plain[CPE][1]

    t.is_nil(row.cvss, "a score of zero must not reach the report as a score")
    t.equals(row.severity, "Unknown",
      "and the row must say the severity is unknown rather than naming a band")
  end,
}

suite[#suite + 1] = {
  name = "a score outside the CVSS range is refused rather than laid out",
  fn = function()
    -- CVSS runs 0-10. A larger number is the service saying something this
    -- script does not understand, and laying it out shifts every column of the
    -- row clear of the table - the guard exists for that, and nothing measured
    -- it: dropping "or score > 10" left all 254 cases green.
    local env, http = load_free({})
    answer(http, api_body({
      vuln({id = "CVE-2010-3615", cvss = 12345.678}),
    }))

    local plain = t.collect_output(
      env.action(t.host(), t.port({version = "9.8.2", cpe = {CPE}})))
    local row = plain[CPE][1]

    t.is_nil(row.cvss, "a score outside 0-10 is not a score")
    t.equals(row.severity, "Unknown")
  end,
}
return suite
