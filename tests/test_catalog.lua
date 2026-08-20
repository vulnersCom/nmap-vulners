--- Tests for the catalogue: how the dictionaries are fetched, and refused.
--
-- The script carries no fingerprint data any more. It downloads three
-- dictionaries at scan time, so this file covers the one thing that decides
-- whether the plugin recognises anything at all - and the several ways that
-- can go wrong without anybody noticing, because a scan that recognised
-- nothing looks exactly like a network where nothing is running.
--
-- Three properties are load-bearing and every case here is really about one of
-- them:
--
--   * a scan that cannot reach the catalogue must still be a working scan. The
--     identities nmap itself produced do not need a dictionary, so losing the
--     catalogue costs web fingerprinting and nothing else.
--   * nothing from the network is used before it is checked. These are Lua
--     patterns this script will run against target data, and one that does not
--     compile raises inside the matcher, where nmap turns it into "Script
--     execution failed" and the port's whole result is lost.
--   * nothing is written to disk. Not by default, not behind an argument, not
--     at all - see the "no file is ever opened for writing" case.

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local CATALOG_URL = "https://catalog.example/"

--; A rule dictionary with one usable rule in it.
local function fingerprints(rules)
  return {schema = 1, rules = rules or {
    ["Nginx, server"] = {
      alias = "cpe:/a:f5:nginx",
      channel = "hdr:server",
      anchor = "nginx/",
      regex = "nginx/([%d.]+)",
    },
  }}
end

local function paths(list)
  return {schema = 1, paths = list or {"/"}}
end

local function probes(list)
  return {schema = 1, probes = list or {}}
end

--; One probe, in the shape read_probes accepts.
local function probe(overrides)
  local entry = {
    name = "Drupal",
    alias = "cpe:/a:drupal:drupal",
    detect = {{channel = "hdr:x-generator", regex = "Drupal"}},
    extract = {{regex = "Drupal ([%d.]+)"}},
    paths = {"/CHANGELOG.txt"},
  }
  for name, value in pairs(overrides or {}) do entry[name] = value end
  return entry
end

--; Serve a whole catalogue at CATALOG_URL, and count what was asked for.
local function serve_catalog(http, opts)
  opts = opts or {}
  local documents = {
    ["index.json"] = opts.index or {
      schema = 1,
      serial = opts.serial or 7,
      catalogs = {
        fingerprints = {file = "fingerprints.json"},
        paths = {file = "paths.json"},
        probes = {file = "probes.json"},
      },
    },
    ["fingerprints.json"] = opts.fingerprints or fingerprints(),
    ["paths.json"] = opts.paths or paths(),
    ["probes.json"] = opts.probes or probes(),
  }

  http.handler = function(request)
    local name = (request.url or ""):match("([^/]+)$")
    if name and documents[name] then
      return t.response({status = 200, body = json.generate(documents[name])})
    end
    if request.url then
      return t.response({status = 404, body = ""})
    end
    -- Anything that is not a catalogue fetch is the API; answer it so no case
    -- spends its time in a retry loop.
    return t.response({status = 200, body = json.generate({
      result = "warning", data = {search_explain = {}},
    })})
  end
end

--; Which catalogue files were requested, in order.
local function fetched(http)
  local names = {}
  for _, request in ipairs(http.requests) do
    if request.url then
      names[#names + 1] = request.url:match("([^/]+)$")
    end
  end
  return names
end

--; A loaded script with nothing but what the case gave it.
local function load(opts)
  opts = opts or {}
  local args = {["vulners.catalog_url"] = CATALOG_URL}
  for name, value in pairs(opts.args or {}) do args[name] = value end

  return t.load_vulners({
    root = root,
    catalog = false,          -- this suite is about loading it, not using it
    script_type = "prerule",
    args = args,
    env = {HOME = opts.home or "/home/tester"},
    files = opts.files,
    http = opts.http,
  })
end

--; Load, run the prerule, and hand back the catalogue that resulted.
local function loaded(opts)
  local env, http, disk = load(opts)
  env.action()
  return env._TEST.catalog(), env, http, disk
end

local suite = {}

-- ------------------------------------------------------------ fetching it

suite[#suite + 1] = {
  name = "a scan downloads the index and every dictionary, once",
  fn = function()
    local http = t.http_double()
    serve_catalog(http)

    local catalog = loaded({http = http})

    t.equals(catalog.rule_count, 1, "the rule must have been loaded")
    t.equals(catalog.serial, 7, "the serial must come from the index")
    t.equals(#catalog.paths, 1, "the path list must have been loaded")

    local asked = fetched(http)
    t.equals(asked[1], "index.json", "the index is asked for first")
    t.length(asked, 4, "the index and three dictionaries, once each")
  end,
}

suite[#suite + 1] = {
  name = "no file is ever opened for writing",
  fn = function()
    -- The behaviour this script is expected to have, and there is no argument
    -- that changes it. Of the 611 scripts nmap ships, 26 write a file and
    -- every one writes only where a script argument pointed it; none keeps a
    -- cache. An earlier version of this cached under ~/.nmap, which is worse
    -- than it sounds - that is a nmap DATADIR, read for nmap-services and
    -- scripts/, not a place for a plugin's scratch state.
    local http = t.http_double()
    serve_catalog(http)

    local catalog, _, _, disk = loaded({http = http, files = {}})

    t.equals(catalog.rule_count, 1,
      "the catalogue must load - it is simply never written down")

    local wrote = {}
    for path in pairs(disk.written) do wrote[#wrote + 1] = path end
    t.length(wrote, 0,
      "a scan must touch no file: " .. table.concat(wrote, ", "))
  end,
}

suite[#suite + 1] = {
  name = "the catalogue is loaded once, however many ports answer",
  fn = function()
    -- The chunk re-executes once per open port, so "load it again" happens on
    -- every one of them. With no cache to stop it, the guard is the only thing
    -- between a hundred open ports and a hundred downloads.
    local http = t.http_double()
    serve_catalog(http)
    local catalog, env = loaded({http = http})
    local requests = #fetched(http)

    env._TEST.load_catalog()
    env._TEST.load_catalog()

    t.equals(#fetched(http), requests, "asking again must not fetch again")
    t.equals(env._TEST.catalog().rule_count, catalog.rule_count,
      "and must hand back the same catalogue")
  end,
}

suite[#suite + 1] = {
  name = "a port reached without a prerule uses an empty catalogue, not a " ..
    "fetch",
  fn = function()
    -- The port action must never open a socket for the catalogue: several
    -- ports run concurrently and would race into the same download. Whatever
    -- the prerule left is what a port gets.
    local http = t.http_double()
    serve_catalog(http)
    local env = load({http = http})

    local catalog = env._TEST.catalog()

    t.equals(catalog.rule_count, 0, "nothing was loaded, so nothing is there")
    t.length(catalog.paths, 0, "and there is nothing to sweep")
    t.length(fetched(http), 0, "and reading it must not have fetched anything")
  end,
}

suite[#suite + 1] = {
  name = "a mirror is used verbatim, and a missing slash is added",
  fn = function()
    -- The airgapped answer, and the one an operator is most likely to get
    -- slightly wrong: without the trailing slash the URL would be
    -- "http://mirror/catalogueindex.json".
    local http = t.http_double()
    serve_catalog(http)
    local env = load({http = http,
                      args = {["vulners.catalog_url"] = "http://mirror/cat"}})

    env.action()

    t.is_true(#http.requests > 0, "something must have been requested")
    t.equals(http.requests[1].url, "http://mirror/cat/index.json",
      "the mirror must be used as given, with one slash added")
  end,
}

-- ------------------------------------------------------- refusing to load it

suite[#suite + 1] = {
  name = "a catalogue declaring a newer schema is refused, not half read",
  fn = function()
    -- The whole reason the schema exists. An old script must say "I am too
    -- old" rather than read a file whose meaning it was never taught.
    local http = t.http_double()
    serve_catalog(http, {index = {
      schema = 99, serial = 12,
      catalogs = {fingerprints = {file = "fingerprints.json"}},
    }})

    local catalog, env = loaded({http = http})

    t.equals(catalog.rule_count, 0,
      "nothing from a schema this script cannot read may be used")
    t.length(fetched(http), 1, "and no dictionary may be fetched either")
    local note = env._TEST.state().catalog_note
    t.is_true(note ~= nil and note:find("schema", 1, true) ~= nil,
      "the operator must be told why, got: " .. tostring(note))
  end,
}

suite[#suite + 1] = {
  name = "an index with no schema at all is refused",
  fn = function()
    -- Not a catalogue index: a login page, a CDN error document, an S3
    -- listing. All parse as JSON and none of them declare a schema.
    local http = t.http_double()
    serve_catalog(http, {index = {message = "Not Found"}})

    local catalog, env = loaded({http = http})

    t.equals(catalog.rule_count, 0,
      "an unlabelled document is not a catalogue")
    t.is_true(env._TEST.state().catalog_note ~= nil, "and it is not silent")
  end,
}

suite[#suite + 1] = {
  name = "every catalogue fetch may leave the address family the scan runs in",
  fn = function()
    -- nselib stays in the scan's own family unless the request says otherwise,
    -- so without this flag a mirror that answers only over IPv6 is unreachable
    -- even by name. Measured against a catalogue served on ::1 alone:
    -- http.get_url answered nil without any_af and 200 with it. Every API
    -- request in this script has carried the flag from the start; the
    -- catalogue fetch did not.
    local http = t.http_double()
    serve_catalog(http)

    local catalog = loaded({http = http})

    t.is_true(catalog.rule_count > 0, "the catalogue must have loaded")
    local checked = 0
    for _, request in ipairs(http.requests) do
      if request.url then
        checked = checked + 1
        t.is_true(request.options ~= nil and request.options.any_af == true,
          "no catalogue fetch may be pinned to one address family: " ..
          tostring(request.url))
      end
    end
    t.is_true(checked >= 4,
      string.format("there must have been fetches to check, saw %d", checked))
  end,
}

suite[#suite + 1] = {
  name = "a mirror named by IPv6 address is asked for by address",
  fn = function()
    -- A URL has to bracket an IPv6 literal, and nselib's url.parse leaves the
    -- brackets on the host, so http.get_url asks the resolver for "[fd00::1]"
    -- and gets nothing. Measured against a real catalogue on ::1: get_url
    -- answered nil, http.get with the brackets taken off answered 200. The
    -- operator running a mirror on an IPv6 network without DNS has no other
    -- way to name it.
    local http = t.http_double()
    local bodies = {
      ["/index.json"] = {
        schema = 1, serial = 7,
        catalogs = {
          fingerprints = {file = "fingerprints.json"},
          paths = {file = "paths.json"},
          probes = {file = "probes.json"},
        },
      },
      ["/fingerprints.json"] = fingerprints(),
      ["/paths.json"] = paths(),
      ["/probes.json"] = probes(),
    }
    http.handler = function(request)
      local document = request.path and bodies[request.path]
      if document then
        return t.response({status = 200, body = json.generate(document)})
      end
      return t.response({status = 404, body = ""})
    end

    local catalog = loaded({
      http = http,
      args = {["vulners.catalog_url"] = "http://[fd00::1]:8000/"},
    })

    t.is_true(catalog.rule_count > 0,
      "a mirror named by address must be reachable")
    local first = http.requests[1]
    t.is_nil(first.url,
      "get_url cannot resolve a bracketed host, so it must not be used")
    t.equals(first.host, "fd00::1", "the brackets come off the host")
    t.equals(first.port, 8000, "and the port comes from the URL")
    t.equals(first.path, "/index.json")
    t.equals(first.options.header["Host"], "[fd00::1]:8000",
      "and stay on in Host, which has to be a valid authority")
  end,
}

suite[#suite + 1] = {
  name = "an unreachable catalogue leaves a working scan and says so",
  fn = function()
    -- The airgapped case. It must not be an error and must not be silent: the
    -- lookups that do not need a dictionary still run, and the operator is
    -- told which capability was missing so an empty report cannot be misread.
    local http = t.http_double()
    http.handler = function() return nil end

    local catalog, env = loaded({http = http})

    t.equals(catalog.rule_count, 0, "there is nothing to load")
    t.length(catalog.paths, 0, "and nothing to sweep")
    local note = env._TEST.state().catalog_note
    t.is_true(note ~= nil,
      "a scan with no catalogue must not be silent about it")
    t.is_true(note:find("still looked up", 1, true) ~= nil,
      "and must say what DID happen, got: " .. tostring(note))
  end,
}

suite[#suite + 1] = {
  name = "one missing dictionary refuses the whole catalogue",
  fn = function()
    -- Half a catalogue is the dangerous outcome: rules with no paths sweep
    -- nothing, paths with no rules recognise nothing, and either would look
    -- exactly like a quiet network.
    local http = t.http_double()
    serve_catalog(http)
    local answer = http.handler
    http.handler = function(request)
      if (request.url or ""):find("paths.json", 1, true) then
        return t.response({status = 404, body = ""})
      end
      return answer(request)
    end

    local catalog, env = loaded({http = http})

    t.equals(catalog.rule_count, 0, "the rules must not be used without paths")
    t.length(catalog.paths, 0, "and there must be no path list")
    -- The index arrived and parsed, so the network is demonstrably fine and
    -- the repair is at the publisher. Reporting this as a failed download
    -- pointed the one operator who can fix it at the wrong thing.
    local note = env._TEST.state().catalog_note
    t.is_true(note ~= nil and note:find("could not be read", 1, true) ~= nil,
      "a reachable catalogue with an unusable file is not a failed " ..
        "download, " ..
      "got: " .. tostring(note))
    t.is_true(note:find("still looked up", 1, true) ~= nil,
      "and it must still say what DID happen")
  end,
}

suite[#suite + 1] = {
  name = "a dictionary that is not JSON is refused whole",
  fn = function()
    local http = t.http_double()
    http.handler = function(request)
      local name = (request.url or ""):match("([^/]+)$")
      if name == "index.json" then
        return t.response({status = 200, body = json.generate({
          schema = 1, serial = 4,
          catalogs = {fingerprints = {file = "fingerprints.json"},
                      paths = {file = "paths.json"},
                      probes = {file = "probes.json"}},
        })})
      end
      -- Truncated: what a CDN serving a partial body actually looks like.
      return t.response({status = 200, body = '{"schema": 1, "rules": {"a'})
    end

    local catalog, env = loaded({http = http})

    t.equals(catalog.rule_count, 0,
      "half a dictionary must not become half a catalogue")
    local note = env._TEST.state().catalog_note
    t.is_true(note ~= nil and note:find("could not be read", 1, true) ~= nil,
      "a truncated body is a publisher's problem, not a network one, got: " ..
      tostring(note))
  end,
}

suite[#suite + 1] = {
  name = "a dictionary of the wrong schema is refused",
  fn = function()
    -- The index says 1 and the file says 2. Whichever is the mistake, reading
    -- the file as though it were schema 1 is the one outcome nobody wants.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = {schema = 2, rules = {
      ["Nginx, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                           regex = "nginx/([%d.]+)"},
    }}})

    t.equals(loaded({http = http}).rule_count, 0,
      "a file's own schema is checked, not only the index's")
  end,
}

suite[#suite + 1] = {
  name = "an index naming a path outside the catalogue is refused",
  fn = function()
    -- The file name from the index reaches a URL. Without a check it could
    -- walk out of the catalogue directory entirely.
    local http = t.http_double()
    serve_catalog(http, {index = {
      schema = 1, serial = 3,
      catalogs = {fingerprints = {file = "../../../etc/passwd"}},
    }})

    local catalog, _, request_log = loaded({http = http})

    t.equals(catalog.rule_count, 0, "nothing may be loaded")
    for _, name in ipairs(fetched(request_log)) do
      t.is_true(name ~= "passwd", "no request may be made for it either")
    end
  end,
}

suite[#suite + 1] = {
  name = "vulners.catalog=none makes no request at all",
  fn = function()
    local http = t.http_double()
    serve_catalog(http)

    local catalog, env = loaded({http = http,
      args = {["vulners.catalog"] = "none"}})

    t.length(fetched(http), 0, "an operator who said no must be obeyed")
    t.equals(catalog.rule_count, 0, "and nothing must be loaded")
    local note = env._TEST.state().catalog_note
    t.is_true(note ~= nil and note:find("none", 1, true) ~= nil,
      "the report must say the catalogue was off, got: " .. tostring(note))
  end,
}

suite[#suite + 1] = {
  name = "an unknown catalogue mode is treated as the default, not as off",
  fn = function()
    -- A typo must not silently disable fingerprinting for the whole scan.
    local http = t.http_double()
    serve_catalog(http)

    t.equals(loaded({http = http,
      args = {["vulners.catalog"] = "yes"}}).rule_count,
      1, "an unrecognised mode falls back to fetching")
  end,
}

--- The published catalogue, read the way a real scan reads it.
--
-- Everything above proves the readers REFUSE what they must. This proves they
-- ACCEPT what actually ships, which is the other half and the one nothing was
-- watching: a rule the readers drop costs a detection silently, and a scan
-- that recognises less looks exactly like a network running less.
suite[#suite + 1] = {
  name = "the published catalogue survives this script's own readers intact",
  fn = function()
    -- `tools/catalog.py --check` says it asks "the same questions the script
    -- asks". It does not - it never looks at a regex - so a hand-edited rule
    -- with no capture, two captures, a position capture or a back-reference
    -- passes every gate in CI and is dropped here instead, in the field.
    --
    -- Asserted THROUGH the readers rather than by reimplementing them: a
    -- second copy of usable_pattern in Python would be a second thing to keep
    -- in step, and this repository has already been bitten by two spellings of
    -- one rule drifting apart.
    local documents = t.published_catalog(root)
    local env = t.load_vulners({root = root, catalog = false})

    local _, kept = env._TEST.read_fingerprints(documents.fingerprints)
    local paths = env._TEST.read_paths(documents.paths)
    local probes = env._TEST.read_probes(documents.probes)

    local published = 0
    for _ in pairs(documents.fingerprints.rules) do
      published = published + 1
    end

    t.equals(kept, published,
      "every published rule must be one this script will actually use")
    t.length(paths, #documents.paths.paths,
      "every published path must be one it will actually request")
    t.length(probes, #documents.probes.probes,
      "every published probe must be one it can trigger, send and read")
  end,
}

-- ------------------------------------------------------ refusing single rules

suite[#suite + 1] = {
  name = "a rule whose pattern does not compile is dropped, not the catalogue",
  fn = function()
    -- A pattern that raises inside string.find costs the port its entire
    -- result, because nmap replaces the output of a script that errored. One
    -- bad rule in a dictionary of hundreds must cost that rule only.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      -- One capture, so it is not dropped for that; it simply does not
      -- compile, because a Lua pattern may not end in a bare %. The first
      -- version of this case used an unclosed character class, which fails the
      -- capture count as well - so it passed with the compile check removed.
      ["Broken, server"] = {alias = "cpe:/a:x:y", channel = "hdr:server",
                            regex = "nginx/([%d.]+)%"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1,
      "the good rule survives and the broken one does not")
  end,
}

suite[#suite + 1] = {
  name = "a rule carrying a back-reference is dropped",
  fn = function()
    -- The validator's whole contract is that no rule it keeps can raise inside
    -- string.find. A back-reference slips through a walk that only counts
    -- captures: "(%d)%2" names a group that does not exist and "(%d)%0" names
    -- the whole match, and BOTH raise "invalid capture index" at match time -
    -- which costs the port its entire result. Measured against real Lua 5.4.
    --
    -- The generator refuses PCRE back-references, so nothing in the published
    -- catalogue has one; that is exactly why this belongs here rather than in
    -- the generator's own tests. The reader must not depend on the writer.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      ["Backref, server"] = {alias = "cpe:/a:x:y", channel = "hdr:server",
                             regex = "nginx/([%d.]+)%2"},
      ["Whole match, server"] = {alias = "cpe:/a:x:z", channel = "hdr:server",
                                 regex = "nginx/([%d.]+)%0"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1,
      "only the rule that cannot raise may ship")
  end,
}

suite[#suite + 1] = {
  name = "a rule that cannot produce a version is dropped",
  fn = function()
    -- match_group builds `alias .. ":" .. version` out of the one capture. No
    -- capture can never produce an identity; two silently report whichever
    -- came first as the version, which is a wrong CPE rather than a missing
    -- one.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      ["No capture, server"] = {alias = "cpe:/a:x:y", channel = "hdr:server",
                                regex = "nginx"},
      ["Two captures, server"] = {alias = "cpe:/a:x:z", channel = "hdr:server",
                                  regex = "(%w+)/([%d.]+)"},
      ["Position capture, server"] = {alias = "cpe:/a:x:w",
        channel = "hdr:server",
                                      regex = "nginx()"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1,
      "only the rule with exactly one text capture may ship")
  end,
}

suite[#suite + 1] = {
  name = "a rule filed where nothing looks is dropped",
  fn = function()
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      ["Nowhere"] = {alias = "cpe:/a:x:y", channel = "sideband",
                     regex = "x([%d.]+)"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1,
      "a channel the matcher never reads is data that can never fire")
  end,
}

suite[#suite + 1] = {
  name = "a rule whose alias is not a CPE prefix is dropped",
  fn = function()
    -- The alias is concatenated with the version and sent to the endpoint as a
    -- CPE. Anything else produces a query that can only ever answer nothing,
    -- and a group heading that looks like a finding.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      ["Bare name"] = {alias = "nginx", channel = "hdr:server",
                       regex = "nginx/([%d.]+)"},
      ["Wrong part"] = {alias = "cpe:/x:f5:nginx", channel = "hdr:server",
                        regex = "nginx/([%d.]+)"},
      ["Already versioned"] = {alias = "cpe:/a:f5:nginx:1.0",
        channel = "hdr:server",
                               regex = "nginx/([%d.]+)"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1,
      "only a vendor:product prefix may ship")
  end,
}

suite[#suite + 1] = {
  name = "every channel the matcher reads is accepted",
  fn = function()
    -- The other side of the "filed where nothing looks" case: a channel list
    -- that drifted narrower than the matcher would silently drop good rules,
    -- and nothing else would notice.
    local rules = {}
    for _, channel in ipairs({"raw", "body", "title", "script", "banner",
                              "cookie", "hdr:x-powered-by",
                              "meta:generator"}) do
      rules[channel] = {alias = "cpe:/a:x:y", channel = channel,
                        regex = "x/([%d.]+)"}
    end
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints(rules)})

    t.equals(loaded({http = http}).rule_count, 8,
      "every channel the fingerprinter reads must be loadable")
  end,
}

suite[#suite + 1] = {
  name = "an absurdly long pattern is dropped",
  fn = function()
    -- A ceiling on a file that arrived intact and is not what it should be.
    local http = t.http_double()
    serve_catalog(http, {fingerprints = fingerprints({
      ["Huge"] = {alias = "cpe:/a:x:y", channel = "hdr:server",
                  regex = "(" .. string.rep("a", 4096) .. ")"},
      ["Good, server"] = {alias = "cpe:/a:f5:nginx", channel = "hdr:server",
                          regex = "nginx/([%d.]+)"},
    })})

    t.equals(loaded({http = http}).rule_count, 1, "the ceiling must hold")
  end,
}

-- ------------------------------------------------------------- paths, probes

suite[#suite + 1] = {
  name = "a path that is not one is dropped, and duplicates collapse",
  fn = function()
    local http = t.http_double()
    serve_catalog(http, {paths = paths({
      "/wp-login.php",
      "/wp-login.php",             -- a duplicate costs a request per host
      "relative",                  -- would be resolved against nothing
      "/two words",                -- would not survive the request line
      "/with\nnewline",            -- header injection, if it ever got out
      42,                          -- not a string at all
      "/ok",
    })})

    local catalog = loaded({http = http})

    t.same(catalog.paths, {"/wp-login.php", "/ok"},
      "only usable, unique paths may reach the sweep")
  end,
}

suite[#suite + 1] = {
  name = "a catalogue with no usable path is refused",
  fn = function()
    -- Rules with nowhere to send them recognise only what the front page
    -- shows, which is a quiet, partial scan rather than an obvious failure.
    local http = t.http_double()
    serve_catalog(http, {paths = paths({"relative", "/no good"})})

    t.equals(loaded({http = http}).rule_count, 0,
      "no paths means no catalogue, said loudly")
  end,
}

suite[#suite + 1] = {
  name = "a usable probe survives the readers intact",
  fn = function()
    local http = t.http_double()
    serve_catalog(http, {probes = probes({probe()})})

    local catalog = loaded({http = http})

    t.length(catalog.probes, 1, "the probe must be loaded")
    t.equals(catalog.probes[1].alias, "cpe:/a:drupal:drupal", "with its alias")
    t.equals(catalog.probes[1].name, "Drupal", "and its name")
    t.same(catalog.probes[1].paths, {"/CHANGELOG.txt"}, "and its paths")
  end,
}

suite[#suite + 1] = {
  name = "a probe missing any of its three parts is dropped",
  fn = function()
    -- A probe that cannot be triggered, cannot be sent, or cannot read an
    -- answer is not a probe. Each part is dropped by a different check, so
    -- each is a separate way to ship one that does nothing.
    local http = t.http_double()
    serve_catalog(http, {probes = probes({
      probe({detect = {{channel = "sideband", regex = "Drupal"}}}),
      probe({extract = {{regex = "Drupal [%d.]+"}}}),   -- no capture
      probe({paths = {"relative"}}),
      probe({alias = "drupal"}),
      probe(),
    })})

    t.length(loaded({http = http}).probes, 1, "only the whole one may ship")
  end,
}

suite[#suite + 1] = {
  name = "a broken probe file still leaves the rules and paths working",
  fn = function()
    -- Probes are optional in a way the other two dictionaries are not: a
    -- catalogue with none is a catalogue that does not probe, which is a valid
    -- state and much better than no catalogue at all.
    local http = t.http_double()
    serve_catalog(http, {probes = {schema = 1, probes = "not a list"}})

    local catalog = loaded({http = http})

    t.equals(catalog.rule_count, 1, "the rules must survive")
    t.length(catalog.probes, 0, "and the probes are simply absent")
  end,
}


suite[#suite + 1] = {
  name = "a detect rule is validated exactly as it will be run",
  fn = function()
    -- The gate used to wrap the pattern in parentheses to force the one
    -- capture it insisted on, which validated a DIFFERENT string from the one
    -- stored. Measured against real Lua: the raw pattern "X)%" is refused
    -- while "(X)%)" is accepted - the prepended "(" absorbs the stray ")" and
    -- the trailing "%" escapes the appended one - so the probe shipped and the
    -- raw pattern went to string.find, costing the port its entire result.
    local http = t.http_double()
    serve_catalog(http, {probes = {schema = 1, probes = {
      {name = "wrapped-only", alias = "cpe:/a:x:y",
       detect = {{channel = "body", regex = "X)%"}},
       extract = {{regex = "v([%d.]+)"}}, paths = {"/v"}},
      {name = "good", alias = "cpe:/a:x:z",
       detect = {{channel = "body", regex = "zed"}},
       extract = {{regex = "v([%d.]+)"}}, paths = {"/v"}},
    }}})

    local catalog = loaded({http = http})
    t.length(catalog.probes, 1,
      "a pattern that only survives its own wrapper may not ship")
    t.equals(catalog.probes[1].alias, "cpe:/a:x:z")
  end,
}

suite[#suite + 1] = {
  name = "a detect rule whose regex is not a string is dropped, not run",
  fn = function()
    -- The gate validated tostring(rule.regex) and stored the raw value, and
    -- tostring({}) is "table: 0x...", which is a perfectly good one-capture
    -- pattern. The probe was kept and string.find then raised "string
    -- expected, got table" - costing the port its entire result, which is the
    -- one outcome this whole section exists to prevent.
    local http = t.http_double()
    serve_catalog(http, {probes = {schema = 1, probes = {
      {name = "bad", alias = "cpe:/a:x:y",
       detect = {{channel = "body", regex = {}}},
       extract = {{regex = "v([%d.]+)"}}, paths = {"/v"}},
      {name = "good", alias = "cpe:/a:x:z",
       detect = {{channel = "body", regex = "zed"}},
       extract = {{regex = "v([%d.]+)"}}, paths = {"/v"}},
    }}})

    local catalog = loaded({http = http})
    t.length(catalog.probes, 1,
      "only the probe whose detector is a pattern may ship")
    t.equals(catalog.probes[1].alias, "cpe:/a:x:z")
  end,
}

suite[#suite + 1] = {
  name = "an index naming a file that is not one is refused",
  fn = function()
    -- The guard excluded characters rather than requiring a shape, and "." was
    -- inside the permitted class - so ".." matched nothing, passed, and the
    -- fetch walked to the parent of the operator's catalog_url.
    local http = t.http_double()
    serve_catalog(http, {index = {
      schema = 1, serial = 9,
      catalogs = {fingerprints = {file = ".."}, paths = {file = "paths.json"},
                  probes = {file = "probes.json"}},
    }})

    -- The parent directory has to ANSWER, or this case passes for the wrong
    -- reason: with the guard removed the fetch would simply 404 and the
    -- catalogue would be refused anyway, measuring nothing.
    local inner = http.handler
    http.handler = function(request)
      if (request.url or ""):sub(-2) == ".." then
        return t.response({status = 200, body = json.generate(fingerprints())})
      end
      return inner(request)
    end

    t.equals(loaded({http = http}).rule_count, 0,
      "an index that does not name a catalogue file is not a catalogue, " ..
      "however willingly the server answers")
  end,
}
return suite
