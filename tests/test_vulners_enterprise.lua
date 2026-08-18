--- Tests for vulners_enterprise.nse (the API-key variant).
--
-- The response shapes used here were captured from the live Vulners API, so
-- the doubles cannot drift into something the server never sends:
--
--   POST /api/v4/audit/software/   (CPE audit)
--     {"result":[{"input":{part,vendor,product,version,update},
--                 "matched_criteria":"cpe:2.3:...",
--                 "vulnerabilities":[{"id","type",
--                                     "metrics":{"cvss":{score,version,...}},
--                                     "enchantments":{"dependencies":{"references":[...]}}}]}]}
--
--   POST /api/v4/audit/smart       (free-form "product version")
--     the same envelope, but "input" is the string and the vulnerabilities
--     carry neither metrics nor enchantments - ids only.
--
--   POST /api/v3/search/id/        (resolves those ids, max 100 per call)
--     {"result":"OK","data":{"documents":{"<id>":{"id","type","cvss":{...},
--                                                 "enchantments":{...}}}}}

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local SCRIPT = root .. "/vulners_enterprise.nse"
local KEY = "FAKE-TEST-KEY-NOT-A-REAL-TOKEN"
local CPE = "cpe:/a:openbsd:openssh:7.4"

--- Load the script with doubles for http, nmap, stdnse and optionally os.
local function load(opts)
  opts = opts or {}
  local http = t.http_double()
  local stdnse = t.stdnse_double()
  local modules = {http = http, nmap = t.nmap_double(), stdnse = stdnse}

  -- The environment is always faked, never merely overridden: a developer who
  -- exported VULNERS_API_KEY for the live end-to-end run would otherwise see
  -- the key-handling cases fail for reasons that have nothing to do with the
  -- change under test.
  modules.os = setmetatable({
    getenv = function(name)
      if name == "VULNERS_API_KEY" then return opts.env_key end
      return os.getenv(name)
    end,
  }, {__index = os})

  local args = opts.args or {}
  if opts.key ~= false and args["vulners_enterprise.api_key"] == nil
     and opts.env_key == nil and args["vulners_enterprise.api_key_file"] == nil then
    args["vulners_enterprise.api_key"] = KEY
  end

  local env = t.load_script(SCRIPT, {args = args, modules = modules})
  return env, http, stdnse
end

-- ------------------------------------------------------------ response parts

--- One vulnerability as the v4 software audit returns it.
local function vuln(opts)
  local record = {id = opts.id, type = opts.type or "cve"}

  if opts.cvss ~= nil then
    record.metrics = {cvss = {
      score = opts.cvss,
      version = opts.cvss_version or "3.1",
      severity = "HIGH",
    }}
  elseif opts.cvss_none then
    record.metrics = {cvss = {score = 0, version = "NONE"}}
  elseif opts.cvss_without_version then
    -- Seen in the wild: a score with no version at all.
    record.metrics = {cvss = {score = opts.cvss_without_version}}
  end

  if not opts.no_enchantments then
    record.enchantments = opts.enchantments or {dependencies = {references = {}}}
  end

  return record
end

--- An enchantments block advertising exploits.
local function exploits(type_name, ids)
  return {dependencies = {references = {{type = type_name, idList = ids}}}}
end

--- Serve a CPE audit from a map of cpe -> list of vulnerabilities.
--
-- The reply is built in reverse order of the request on purpose: the live API
-- does not answer in request order, so position must never be relied upon.
local function serve_audit(http, by_cpe, extra)
  extra = extra or {}
  http.handler = function(req)
    if req.path:find("/api/v4/audit/software/", 1, true) then
      local ok, body = json.parse(req.body)
      t.is_true(ok, "the audit body must be valid json")

      local result = {}
      for i = #body.software, 1, -1 do
        local item = body.software[i]
        local cpe = string.format("cpe:/%s:%s:%s:%s%s", item.part, item.vendor,
          item.product, item.version, item.update or "")
        result[#result + 1] = {
          input = item,
          matched_criteria = "cpe:2.3:" .. item.part .. ":" .. item.vendor,
          vulnerabilities = by_cpe[cpe] or {},
        }
      end
      return t.response({status = 200, body = json.generate({result = result})})
    end

    if extra.handler then
      local reply = extra.handler(req)
      if reply then return reply end
    end

    if req.path:find("/api/v4/audit/smart", 1, true) then
      -- The script falls back to the smart endpoint when the CPE audit found
      -- nothing; an empty answer keeps such tests focused on the audit call.
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

local function port_with_cpe()
  return t.port({product = "OpenSSH", version = "7.4", cpe = {CPE}})
end

local suite = {}

-- ------------------------------------------------------------- key handling

suite[#suite + 1] = {
  name = "without an API key the script stays silent and issues no request",
  fn = function()
    local env, http = load({key = false, args = {}, env_key = false})
    t.is_nil(env.action(t.host(), port_with_cpe()), "no key means no result")
    t.length(http.requests, 0, "and no request may be sent")
  end,
}

suite[#suite + 1] = {
  name = "the API key is sent in the X-Api-Key header",
  fn = function()
    local env, http = load()
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.is_true(#http.requests > 0, "a keyed run must talk to the API")
    t.equals(http.requests[1].options.header["X-Api-Key"], KEY)
  end,
}

suite[#suite + 1] = {
  name = "the API key can come from the environment",
  fn = function()
    local env, http = load({env_key = "ENV-FAKE-KEY", args = {}})
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.is_true(#http.requests > 0, "VULNERS_API_KEY must be picked up")
    t.equals(http.requests[1].options.header["X-Api-Key"], "ENV-FAKE-KEY")
  end,
}

suite[#suite + 1] = {
  name = "the API key can come from a file",
  fn = function()
    local keyfile = testdir .. "/fixtures/key_file_sample.txt"
    local env, http = load({args = {["vulners_enterprise.api_key_file"] = keyfile}})
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.is_true(#http.requests > 0, "api_key_file must be read")
    t.equals(http.requests[1].options.header["X-Api-Key"], KEY)
  end,
}

suite[#suite + 1] = {
  name = "a missing key file is handled without a crash",
  fn = function()
    local env, http = load({
      args = {["vulners_enterprise.api_key_file"] = testdir .. "/fixtures/nope.txt"},
    })
    t.is_nil(t.no_error(function() return env.action(t.host(), port_with_cpe()) end,
      "an unreadable key file must not raise"))
    t.length(http.requests, 0, "and nothing may be sent without a key")
  end,
}

suite[#suite + 1] = {
  name = "the API key never reaches the debug log",
  fn = function()
    local env, http, stdnse = load()
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    -- nmap -d output travels in bug reports and shared scan logs.
    local log = stdnse.log()
    t.matches(log, "Api key is set %(%d+ characters%)",
      "the script must log that it has a key, so this case cannot pass on silence")
    t.is_nil(log:find(KEY, 1, true),
      "the key itself must not be written to debug output")
  end,
}

-- ---------------------------------------------------------------- endpoints

suite[#suite + 1] = {
  name = "a CPE lookup hits the v4 software audit endpoint",
  fn = function()
    local env, http = load()
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    local request = http.requests[1]
    t.equals(request.path, "/api/v4/audit/software/")
    t.equals(request.method, "POST")

    local ok, body = json.parse(request.body)
    t.is_true(ok, "the audit body must be valid json")
    t.equals(body.software[1].part, "a")
    t.equals(body.software[1].vendor, "openbsd")
    t.equals(body.software[1].product, "openssh")
    t.equals(body.software[1].version, "7.4")
  end,
}

suite[#suite + 1] = {
  name = "api_host and api_port are honoured",
  fn = function()
    local env, http = load({args = {
      ["vulners_enterprise.api_host"] = "vulners.internal",
      ["vulners_enterprise.api_port"] = 8443,
    }})
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.equals(http.requests[1].host, "vulners.internal")
    t.equals(http.requests[1].port, 8443)
  end,
}

suite[#suite + 1] = {
  name = "api_port given on the command line reaches http as a number",
  fn = function()
    -- nmap hands script arguments over as strings, and http.post() raises on
    -- a string port, which used to abort the script for anyone who set it.
    local env, http = load({args = {
      ["vulners_enterprise.api_host"] = "127.0.0.1",
      ["vulners_enterprise.api_port"] = "8443",
    }})
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.equals(type(http.requests[1].port), "number", "the port must be a number")
    t.equals(http.requests[1].port, 8443)
  end,
}

suite[#suite + 1] = {
  name = "an unusable api_port falls back to 443",
  fn = function()
    local env, http = load({args = {["vulners_enterprise.api_port"] = "not-a-port"}})
    serve_audit(http, {})

    env.action(t.host(), port_with_cpe())

    t.equals(http.requests[1].port, 443, "garbage must not break the default")
  end,
}

-- ------------------------------------------------------------------ batching

suite[#suite + 1] = {
  name = "every CPE of a port is audited in one request",
  fn = function()
    local env, http = load()
    serve_audit(http, {})

    local port = t.port({product = "nginx", version = "1.13.4", cpe = {
      "cpe:/a:openbsd:openssh:7.4",
      "cpe:/a:php:php:5.6.38",
    }})
    env.action(t.host(), port)

    local audits = http.matching("/api/v4/audit/software/")
    t.length(audits, 1, "two CPEs must still be one request")

    local ok, body = json.parse(audits[1].body)
    t.is_true(ok)
    t.length(body.software, 2, "both CPEs must travel in the same batch")
  end,
}

suite[#suite + 1] = {
  name = "answers are matched back by their input, not by position",
  fn = function()
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:openbsd:openssh:7.4"] = {vuln({id = "CVE-2023-38408", cvss = 9.8})},
      ["cpe:/a:php:php:5.6.38"] = {vuln({id = "CVE-2019-11043", cvss = 9.8})},
    })

    local port = t.port({product = "php", version = "5.6.38", cpe = {
      "cpe:/a:openbsd:openssh:7.4",
      "cpe:/a:php:php:5.6.38",
    }})
    local plain = t.collect_output(env.action(t.host(), port))

    t.same(ids_of(plain["cpe:/a:openbsd:openssh:7.4"]), {"CVE-2023-38408"},
      "the openssh answer must land under the openssh CPE")
    t.same(ids_of(plain["cpe:/a:php:php:5.6.38"]), {"CVE-2019-11043"},
      "the php answer must land under the php CPE")
  end,
}

suite[#suite + 1] = {
  name = "software already audited in this scan is not asked about again",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "CVE-2023-38408", cvss = 9.8})}})

    local first = t.collect_output(env.action(t.host({ip = "10.0.0.1"}), port_with_cpe()))
    local requests_after_first = #http.requests

    local second = t.collect_output(env.action(t.host({ip = "10.0.0.2"}), port_with_cpe()))

    t.equals(#http.requests, requests_after_first,
      "the second host must be served from the scan cache")
    t.same(ids_of(second[CPE]), ids_of(first[CPE]),
      "and must still get the same answer")
  end,
}

suite[#suite + 1] = {
  name = "both nginx vendor spellings are audited and merged under one key",
  fn = function()
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:nginx:nginx:1.13.4"] = {vuln({id = "CVE-2018-16843", cvss = 7.5})},
      ["cpe:/a:igor_sysoev:nginx:1.13.4"] = {vuln({id = "CVE-2009-2629", cvss = 9.0})},
    })

    local port = t.port({product = "nginx", version = "1.13.4",
      cpe = {"cpe:/a:nginx:nginx:1.13.4"}})
    local plain, order = t.collect_output(env.action(t.host(), port))

    local audits = http.matching("/api/v4/audit/software/")
    t.length(audits, 1, "both spellings belong to the same batch")

    local ok, body = json.parse(audits[1].body)
    t.is_true(ok)
    local vendors = {}
    for _, item in ipairs(body.software) do vendors[item.vendor] = true end
    t.is_true(vendors["nginx"], "the nginx:nginx spelling must be queried")
    t.is_true(vendors["igor_sysoev"], "the igor_sysoev spelling must be queried")

    t.length(order, 1, "both answers belong to one result key")
    t.same(ids_of(plain["cpe:/a:nginx:nginx:1.13.4"]),
      {"CVE-2009-2629", "CVE-2018-16843"}, "merged results stay sorted by CVSS")
  end,
}

suite[#suite + 1] = {
  name = "a CPE listed twice is audited once",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "CVE-2023-38408", cvss = 9.8})}})

    -- The registry and the port version table commonly overlap.
    local host = t.host({registry = {vulners_cpe = {[80] = {CPE}}}})
    env.action(host, port_with_cpe())

    local ok, body = json.parse(http.matching("/api/v4/audit/software/")[1].body)
    t.is_true(ok)
    t.length(body.software, 1, "the duplicate must be dropped before asking")
  end,
}

suite[#suite + 1] = {
  name = "a bulletin answered for both nginx spellings is reported once",
  fn = function()
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:nginx:nginx:1.13.4"] = {vuln({id = "CVE-2018-16843", cvss = 7.5})},
      ["cpe:/a:igor_sysoev:nginx:1.13.4"] = {vuln({id = "CVE-2018-16843", cvss = 7.5})},
    })

    local port = t.port({product = "nginx", version = "1.13.4",
      cpe = {"cpe:/a:nginx:nginx:1.13.4"}})
    local plain, order = t.collect_output(env.action(t.host(), port))

    t.length(order, 1, "one product means one result key")
    t.same(ids_of(plain[order[1]]), {"CVE-2018-16843"},
      "the shared bulletin is not printed twice")
  end,
}

suite[#suite + 1] = {
  name = "a failed audit is not remembered as an empty answer",
  fn = function()
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:isc:bind:9.8.2"] = {vuln({id = "CVE-2012-1667", cvss = 8.5})},
    })
    local healthy = http.handler
    http.handler = function(req)
      return t.response({status = 500, body = ""})
    end

    local port = t.port({version = "9.8.2", cpe = {"cpe:/a:isc:bind:9.8.2"}})
    t.is_nil(env.action(t.host(), port), "the failing audit reports nothing")

    http.handler = healthy
    local plain = t.collect_output(env.action(t.host({ip = "127.0.0.2"}), port))
    t.same(ids_of(plain["cpe:/a:isc:bind:9.8.2"]), {"CVE-2012-1667"},
      "the next host audits again and gets the answer")
  end,
}

suite[#suite + 1] = {
  name = "versions differing only in the update part are cached apart",
  fn = function()
    -- nmap reports both "7.4" and "7.4p1"; a key without the update part let
    -- whichever was scanned first stand for the other.
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:openbsd:openssh:7.4p1"] = {vuln({id = "CVE-2016-10009", cvss = 7.5})},
      ["cpe:/a:openbsd:openssh:7.4"] = {vuln({id = "CVE-2018-15473", cvss = 5.3})},
    })

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
  name = "the two nginx spellings are reported under a single key",
  fn = function()
    local env, http = load()
    serve_audit(http, {
      ["cpe:/a:nginx:nginx:1.13.4"] = {vuln({id = "CVE-2018-16843", cvss = 7.5})},
      ["cpe:/a:igor_sysoev:nginx:1.13.4"] = {vuln({id = "CVE-2009-2629", cvss = 9.0})},
    })

    -- http-vulners-regex publishes both spellings for the same server.
    local host = t.host({registry = {vulners_cpe = {[80] = {
      "cpe:/a:nginx:nginx:1.13.4",
      "cpe:/a:igor_sysoev:nginx:1.13.4",
    }}}})
    local _, order = t.collect_output(env.action(host, t.port({version = false})))

    t.length(order, 1, "one product must not be reported twice")
  end,
}

suite[#suite + 1] = {
  name = "an exploit referenced by several vulnerabilities is listed once",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {
      vuln({id = "CVE-2023-38408", cvss = 9.8,
        enchantments = exploits("packetstorm", {"PACKETSTORM:142013"})}),
      vuln({id = "CVE-2018-15473", cvss = 5.3,
        enchantments = exploits("packetstorm", {"PACKETSTORM:142013"})}),
    }})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    local count = 0
    for _, row in ipairs(plain[CPE]) do
      if row.id == "PACKETSTORM:142013" then count = count + 1 end
    end
    t.equals(count, 1, "the same exploit must not be printed twice")
  end,
}

-- -------------------------------------------------------------------- output

suite[#suite + 1] = {
  name = "vulnerabilities are reported sorted by CVSS",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {
      vuln({id = "CVE-2018-15473", cvss = 5.3}),
      vuln({id = "CVE-2023-38408", cvss = 9.8}),
    }})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408", "CVE-2018-15473"})
  end,
}

suite[#suite + 1] = {
  name = "cvss version is reported alongside the score",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "CVE-2023-38408", cvss = 9.8,
      cvss_version = "3.1"})}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    local row = plain[CPE][1]

    t.equals(row.cvss, 9.8)
    t.equals(row.cvss_type, "cvss3.1")
    t.matches(t.render(row), "cvss3%.1: 9%.8", "the rendered line shows the cvss version")
  end,
}

suite[#suite + 1] = {
  name = "a score without a cvss version does not crash the run",
  fn = function()
    -- Regression: the live API returns such records, and building the label by
    -- concatenation aborted the whole script.
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "CNVD-2018-22805", cvss_without_version = 7.8})}})

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "a cvss block without a version must not raise"))

    t.is_true(plain and plain[CPE], "the vulnerability must still be reported")
    t.equals(plain[CPE][1].cvss, 7.8)
    t.is_nil(plain[CPE][1].cvss_type, "no version means no label")
    t.matches(t.render(plain[CPE][1]), "CNVD%-2018%-22805", "and it still renders")
  end,
}

suite[#suite + 1] = {
  name = "a document scored NONE is reported without a score",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "VULNERS:UNSCORED", cvss_none = true})}})

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "an unscored document must not raise"))

    t.is_true(plain and plain[CPE], "the document must still be reported")
    t.is_nil(plain[CPE][1].cvss, "and it must carry no score")
    t.is_nil(t.render(plain[CPE][1]):find("cvss:"),
      "an unscored row must not print an empty score column")
  end,
}

suite[#suite + 1] = {
  name = "exploits referenced by a vulnerability are listed separately",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({
      id = "CVE-2023-38408",
      cvss = 9.8,
      enchantments = exploits("githubexploit", {"F0979183-AE88-53B4-86CF-3AF0523F3807"}),
    })}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.length(plain[CPE], 2, "the cve and its exploit are separate rows")
    local exploit_row = plain[CPE][1]
    t.equals(exploit_row.id, "F0979183-AE88-53B4-86CF-3AF0523F3807")
    t.equals(exploit_row.type, "githubexploit")
    t.is_true(exploit_row.is_exploit)
    t.matches(t.render(exploit_row), "HAS EXPLOIT", "the user must see the exploit marker")
    t.equals(plain[CPE][2].id, "CVE-2023-38408", "the cve itself stays in the report")
  end,
}

suite[#suite + 1] = {
  name = "non-exploit references are ignored",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({
      id = "CVE-2023-38408",
      cvss = 9.8,
      enchantments = {dependencies = {references = {
        {type = "alpinelinux", idList = {"ALPINE:CVE-2023-38408"}},
        {type = "aix", idList = {"OPENSSH_ADVISORY19.ASC"}},
      }}},
    })}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"},
      "distro advisories are not exploits and must not be listed")
  end,
}

suite[#suite + 1] = {
  name = "exploits are shown even when they score below mincvss",
  fn = function()
    local env, http = load({args = {["vulners_enterprise.mincvss"] = "9.0"}})
    serve_audit(http, {[CPE] = {vuln({
      id = "CVE-2018-15473",
      cvss = 5.3,
      enchantments = exploits("exploitdb", {"EDB-ID:45233"}),
    })}})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.is_true(plain and plain[CPE], "a working exploit outranks the score threshold")
    t.same(ids_of(plain[CPE]), {"EDB-ID:45233"},
      "the 5.3 cve itself is filtered out by mincvss=9.0")
  end,
}

suite[#suite + 1] = {
  name = "mincvss filters plain vulnerabilities",
  fn = function()
    local env, http = load({args = {["vulners_enterprise.mincvss"] = "7.0"}})
    serve_audit(http, {[CPE] = {
      vuln({id = "CVE-2023-38408", cvss = 9.8}),
      vuln({id = "CVE-2018-15473", cvss = 5.3}),
    }})

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))
    t.same(ids_of(plain[CPE]), {"CVE-2023-38408"}, "5.3 is below mincvss=7.0")
  end,
}

-- ------------------------------------------------------------- software path

suite[#suite + 1] = {
  name = "a software lookup hits the smart endpoint and resolves the ids",
  fn = function()
    local env, http = load()
    http.handler = function(req)
      if req.path:find("/api/v4/audit/software/", 1, true) then
        return t.response({status = 200, body = json.generate({result = {}})})
      end

      if req.path:find("/api/v4/audit/smart", 1, true) then
        local ok, body = json.parse(req.body)
        t.is_true(ok)
        -- The smart endpoint answers with ids and no scores.
        return t.response({status = 200, body = json.generate({result = {{
          input = body.software[1],
          cpe = "cpe:2.3:a:openbsd:openssh:7.4",
          confidence = 90,
          vulnerabilities = {{id = "CVE-2023-38408", type = "cve"}},
        }}})})
      end

      if req.path:find("/api/v3/search/id/", 1, true) then
        return t.response({status = 200, body = json.generate({
          result = "OK",
          data = {documents = {["CVE-2023-38408"] = {
            id = "CVE-2023-38408", type = "cve",
            cvss = {score = 9.8, version = "3.1"},
            enchantments = {dependencies = {references = {}}},
          }}},
        })})
      end

      t.fail("unexpected request to " .. tostring(req.path))
    end

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.length(http.matching("/api/v4/audit/smart"), 1, "the smart endpoint must be used")
    t.length(http.matching("/api/v3/search/id/"), 1, "smart ids need resolving")
    t.is_true(plain["OpenSSH 7.4"], "the software lookup is keyed by product and version")
    t.equals(plain["OpenSSH 7.4"][1].cvss, 9.8, "the resolved score must be reported")
  end,
}

suite[#suite + 1] = {
  name = "smart results with more than 100 ids are resolved in chunks",
  fn = function()
    local env, http = load()
    local vulns, documents = {}, {}
    for i = 1, 150 do
      local id = string.format("CVE-2020-%04d", i)
      vulns[#vulns + 1] = {id = id, type = "cve"}
      documents[id] = {id = id, type = "cve", cvss = {score = 5.0, version = "3.1"},
                       enchantments = {dependencies = {references = {}}}}
    end

    http.handler = function(req)
      if req.path:find("/api/v4/audit/software/", 1, true) then
        return t.response({status = 200, body = json.generate({result = {}})})
      end
      if req.path:find("/api/v4/audit/smart", 1, true) then
        local _, body = json.parse(req.body)
        return t.response({status = 200, body = json.generate({result = {{
          input = body.software[1], vulnerabilities = vulns,
        }}})})
      end
      if req.path:find("/api/v3/search/id/", 1, true) then
        local ok, body = json.parse(req.body)
        t.is_true(ok and #body.id <= 100, "no chunk may exceed 100 ids")
        local wanted = {}
        for _, id in ipairs(body.id) do wanted[id] = documents[id] end
        return t.response({status = 200, body = json.generate({
          result = "OK", data = {documents = wanted},
        })})
      end
      t.fail("unexpected request to " .. tostring(req.path))
    end

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.length(http.matching("/api/v3/search/id/"), 2, "150 ids must be split into two calls")
    t.length(plain["OpenSSH 7.4"], 150, "every resolved id must be reported")
  end,
}

-- ----------------------------------------------------------- error handling

suite[#suite + 1] = {
  name = "a vulnerability without enchantments does not crash the run",
  fn = function()
    local env, http = load()
    serve_audit(http, {[CPE] = {vuln({id = "CVE-2023-38408", cvss = 9.8,
      no_enchantments = true})}})

    local plain = t.collect_output(t.no_error(function()
      return env.action(t.host(), port_with_cpe())
    end, "a record without enchantments must not raise"))

    t.is_true(plain and plain[CPE], "the vulnerability must still be reported")
  end,
}

suite[#suite + 1] = {
  name = "an API level error body does not crash the run",
  fn = function()
    local env, http = load()
    http.handler = function()
      -- Vulners reports business errors inside an HTTP 200 answer.
      return t.response({status = 200, body = json.generate({
        result = "error", data = {error = "quota exceeded", errorCode = 401},
      })})
    end

    t.is_nil(t.no_error(function() return env.action(t.host(), port_with_cpe()) end,
      "an error body must be handled"))
    t.is_true(#http.requests > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "an unparsable body does not crash the run",
  fn = function()
    local env, http = load()
    http.handler = function()
      return t.response({status = 200, body = "<html>not json</html>"})
    end

    t.is_nil(t.no_error(function() return env.action(t.host(), port_with_cpe()) end,
      "a broken body must be handled"))
    t.is_true(#http.requests > 0,
      "the request must have been made: otherwise this case passes on silence")
  end,
}

suite[#suite + 1] = {
  name = "a 4xx answer is not retried",
  fn = function()
    local env, http = load()
    http.handler = function()
      return t.response({status = 403, body = "forbidden"})
    end

    t.is_nil(env.action(t.host(), port_with_cpe()))
    t.length(http.matching("/api/v4/audit/software/"), 1,
      "a rejected request will not fix itself by asking again")
  end,
}

suite[#suite + 1] = {
  name = "a 5xx answer is retried",
  fn = function()
    local env, http = load()
    http.handler = function()
      return t.response({status = 503, body = "busy"})
    end

    t.is_nil(env.action(t.host(), port_with_cpe()))
    t.is_true(#http.matching("/api/v4/audit/software/") > 1,
      "a transient server error deserves another try")
  end,
}

suite[#suite + 1] = {
  name = "a 429 answer is retried and the Retry-After hint is read",
  fn = function()
    local env, http = load()
    local attempts = 0
    http.handler = function(req)
      attempts = attempts + 1
      if attempts == 1 then
        return t.response({status = 429, header = {["retry-after"] = "1"}, body = "slow down"})
      end
      local ok, body = json.parse(req.body)
      t.is_true(ok)
      return t.response({status = 200, body = json.generate({result = {{
        input = body.software[1],
        vulnerabilities = {vuln({id = "CVE-2023-38408", cvss = 9.8})},
      }}})})
    end

    local plain = t.collect_output(env.action(t.host(), port_with_cpe()))

    t.is_true(attempts >= 2, "a rate-limited request must be retried")
    t.is_true(plain and plain[CPE], "and the retry result must be reported")
  end,
}

suite[#suite + 1] = {
  name = "an unreachable API is retried, then left alone for the rest of the scan",
  fn = function()
    local env, http = load()
    http.handler = function() return nil end

    t.is_nil(env.action(t.host({ip = "10.0.0.1"}), port_with_cpe()))
    local attempts = #http.requests
    t.is_true(attempts > 1, "one failed attempt must not be the end of it")

    -- A dead API must not be hammered once per host of a network.
    t.is_nil(env.action(t.host({ip = "10.0.0.2"}), port_with_cpe()))
    t.equals(#http.requests, attempts,
      "after giving up, the rest of the scan must not keep trying")
  end,
}

-- ------------------------------------------------------- defensive behaviour

suite[#suite + 1] = {
  name = "a port without version data but with registry CPEs does not crash",
  fn = function()
    local env, http = load()
    serve_audit(http, {["cpe:/a:nginx:nginx:1.13.4"] =
      {vuln({id = "CVE-2018-16843", cvss = 7.5})}})

    local host = t.host({registry = {vulners_cpe = {[80] = {"cpe:/a:nginx:nginx:1.13.4"}}}})
    local output = t.no_error(function() return env.action(host, t.port({version = false})) end,
      "a port without a version table must not raise")
    t.is_true(t.collect_output(output), "registry CPEs must still be reported")
  end,
}

suite[#suite + 1] = {
  name = "a version without a product name does not crash the software lookup",
  fn = function()
    local env, http = load()
    http.handler = function()
      return t.response({status = 200, body = json.generate({result = {}})})
    end

    local port = t.port({product = nil, version = "7.4", cpe = {}})
    t.no_error(function() return env.action(t.host(), port) end,
      "a missing product name must not raise")
  end,
}

return suite
