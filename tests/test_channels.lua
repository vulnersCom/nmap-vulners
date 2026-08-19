--- Tests for the channels: which part of a response a rule is matched against.
--
-- A rule declares its subject and is filed under it, which is what took the
-- matcher from 178 rules in 30 ms to 722 in 1 ms. The cost of that design is
-- that a channel nothing builds is a channel whose rules can never fire, and
-- nothing else in the suite would notice: the rules load, the catalogue
-- validates, the scan runs, and one whole class of identity is silently absent.
--
-- Two of the eight were covered before this file - `hdr:` and `body`, through
-- the sweep - so the rest are checked here against a single response that
-- carries all of them, and the banner channel against a real nmap service
-- fingerprint.
--
-- Matched through `subjects_of` and `match_subjects` rather than through a
-- scan: those two are the whole of the channel design, and going through the
-- sweep would add a hundred lines of plumbing to test the same two calls.

local t, testdir, root = ...

local os = require "os"
local string = require "string"
local table = require "table"

-- One page carrying every subject the sweep can build, so a channel that stops
-- being offered fails its own case rather than all of them.
local PAGE = table.concat({
  "<html><head>",
  "<title>Kibana 7.10.2 dashboard</title>",
  '<meta name="generator" content="Joomla! 3.9.24" />',
  '<script src="/static/vue-2.6.11.min.js"></script>',
  "</head><body>",
  "Powered by Grafana 8.5.3",
  "</body></html>",
}, "\n")

-- Lowercase keys, because that is what nselib hands a script.
local HEADERS = {
  ["server"] = "nginx/1.18.0",
  ["set-cookie"] = "ci_session=abc1; path=/",
  ["x-powered-by"] = "PHP/7.4.3",
}

local RAW = {
  "Server: nginx/1.18.0",
  "X-Custom-Backend: WebLogic 12.2.1",
  "Set-Cookie: ci_session=abc1; path=/",
}

--- One rule per channel, each with an alias of its own, so which channel fired
-- is readable straight off the CPE.
local CHANNELS = {
  {"hdr:server",      "cpe:/a:f5:nginx",               "nginx/([%d.]+)",
   "cpe:/a:f5:nginx:1.18.0"},
  {"raw",             "cpe:/a:oracle:weblogic_server", "WebLogic ([%d.]+)",
   "cpe:/a:oracle:weblogic_server:12.2.1"},
  {"cookie",          "cpe:/a:codeigniter:codeigniter", "ci_session=(%w+)",
   "cpe:/a:codeigniter:codeigniter:abc1"},
  {"title",           "cpe:/a:elastic:kibana",         "Kibana ([%d.]+)",
   "cpe:/a:elastic:kibana:7.10.2"},
  {"meta:generator",  "cpe:/a:joomla:joomla",          "Joomla! ([%d.]+)",
   "cpe:/a:joomla:joomla:3.9.24"},
  {"script",          "cpe:/a:vuejs:vue_js",           "vue%-(.-)%.min",
   "cpe:/a:vuejs:vue_js:2.6.11"},
  {"body",            "cpe:/a:grafana:grafana",        "Grafana ([%d.]+)",
   "cpe:/a:grafana:grafana:8.5.3"},
}

--- A catalogue holding exactly the rules a case asks for.
--
-- A filler rule always ships: the readers refuse a dictionary with nothing
-- usable in it, which is correct behaviour and would otherwise make a case
-- about the banner fail as a broken catalogue.
local function catalog_of(rules)
  local dictionary = {
    ["Filler, server"] = {alias = "cpe:/a:example:filler", channel = "hdr:x-filler",
                          anchor = "", regex = "filler/([%d.]+)"},
  }
  for _, rule in ipairs(rules or {}) do
    dictionary[rule[2] .. " on " .. rule[1]] = {
      alias = rule[2], channel = rule[1], anchor = "", regex = rule[3],
    }
  end
  return {
    fingerprints = {schema = 1, rules = dictionary},
    paths = {schema = 1, paths = {"/"}},
    probes = {schema = 1, probes = {}},
  }
end

--- A loaded script whose catalogue holds those rules and nothing else.
local function load(rules)
  return t.load_vulners({root = root, catalog = catalog_of(rules)})
end

--- Every CPE those rules find in one response.
local function matched(env, response)
  local T = env._TEST
  local deadline = os.clock() + 5
  local found, seen = {}, {}
  T.match_subjects(T.subjects_of(response, deadline), found, seen, deadline)
  table.sort(found)
  return found
end

--- The response every channel case is matched against.
local function page(opts)
  opts = opts or {}
  return t.response({
    status = 200,
    body = opts.body or PAGE,
    header = opts.header or HEADERS,
    rawheader = opts.rawheader or RAW,
  })
end

local function has(list, wanted)
  for _, value in ipairs(list) do
    if value == wanted then return true end
  end
  return false
end

local suite = {}

suite[#suite + 1] = {
  name = "every channel the fingerprinter builds produces its identity",
  fn = function()
    -- One response, one rule per channel, all at once: a channel that stopped
    -- being offered is named in the failure rather than hidden in a total.
    local env = load(CHANNELS)
    local found = matched(env, page())

    local missing = {}
    for _, rule in ipairs(CHANNELS) do
      if not has(found, rule[4]) then
        missing[#missing + 1] = rule[1]
      end
    end
    t.length(missing, 0,
      "no channel may stop firing: " .. table.concat(missing, ", ") ..
      "\n        found: " .. table.concat(found, ", "))
  end,
}

suite[#suite + 1] = {
  name = "a channel is matched against its own subject and nothing else",
  fn = function()
    -- The precision half of the design, and the reason the channel is part of
    -- the rule: the same pattern over the whole header block could match inside
    -- a different header entirely, so an anchored `hdr:server` rule can mean it.
    local env = load({
      {"hdr:server", "cpe:/a:x:server_only", "^nginx/([%d.]+)"},
      {"hdr:x-powered-by", "cpe:/a:php:php", "PHP/([%d.]+)"},
    })
    local found = matched(env, page())

    t.is_true(has(found, "cpe:/a:x:server_only:1.18.0"),
      "an anchored rule matches its own header: " .. table.concat(found, ", "))
    t.is_true(has(found, "cpe:/a:php:php:7.4.3"),
      "and another header's rule reads that header")
    t.length(found, 2, "and neither reads anything else")
  end,
}

suite[#suite + 1] = {
  name = "a meta tag is read by name, whichever order its attributes are in",
  fn = function()
    local env = load({
      {"meta:generator", "cpe:/a:joomla:joomla", "Joomla! ([%d.]+)"},
      {"meta:og:title", "cpe:/a:x:og", "Not a generator ([%d.]+)"},
    })

    local found = matched(env, page({body = table.concat({
      '<meta charset="utf-8">',
      '<meta property="og:title" content="Not a generator 9.9">',
      '<meta content="Joomla! 3.9.24" name="generator">',
    }, "\n")}))

    t.is_true(has(found, "cpe:/a:joomla:joomla:3.9.24"),
      "reversed attributes must still be read: " .. table.concat(found, ", "))
    t.is_true(has(found, "cpe:/a:x:og:9.9"),
      "and property= names a subject as well as name=")
  end,
}

suite[#suite + 1] = {
  name = "a Set-Cookie is a cookie subject as well as a header one",
  fn = function()
    -- Both, deliberately: the shipped rules include ones written against the
    -- header line and ones written against the cookie value.
    local env = load({
      {"cookie", "cpe:/a:x:by_cookie", "ci_session=(%w+)"},
      {"hdr:set-cookie", "cpe:/a:x:by_header", "ci_session=(%w+)"},
    })
    local found = matched(env, page())

    t.is_true(has(found, "cpe:/a:x:by_cookie:abc1"), "the cookie subject exists")
    t.is_true(has(found, "cpe:/a:x:by_header:abc1"), "and so does the header one")
  end,
}

suite[#suite + 1] = {
  name = "a response with no body still offers its headers",
  fn = function()
    -- A HEAD-like answer, a 304, a redirect. Every body-derived subject is
    -- absent and the header ones must not be.
    local env = load(CHANNELS)
    local found = matched(env, page({body = ""}))

    t.is_true(has(found, "cpe:/a:f5:nginx:1.18.0"), "the header still matches")
    t.is_false(has(found, "cpe:/a:elastic:kibana:7.10.2"),
      "and nothing is invented from a body that is not there")
  end,
}

-- ------------------------------------------------------------- the banner

-- What nmap actually writes into port.version.service_fp: its own metadata,
-- then one %r(Probe,length,"payload") record per probe that answered, wrapped
-- across lines with SF: continuations and escaped throughout.
local SERVICE_FP = table.concat({
  'SF-Port8080-TCP:V=7.94%I=7%D=8/19%Time=68A3B1C2%P=x86_64-apple-darwin%r(Get',
  'SF:Request,7B,"HTTP/1\\.1\\x20200\\x20OK\\r\\nServer:\\x20CouchDB/2\\.3\\.1\\x20\\',
  'SF:(Erlang\\x20OTP/19\\)\\r\\n\\r\\n")%r(HTTPOptions,7B,"HTTP/1\\.1\\x20200\\x20OK',
  'SF:\\r\\nServer:\\x20CouchDB/2\\.3\\.1\\x20\\(Erlang\\x20OTP/19\\)\\r\\n\\r\\n");',
}, "\n")

local COUCHDB = {{"banner", "cpe:/a:apache:couchdb", "CouchDB/([%d.]+)"}}

suite[#suite + 1] = {
  name = "nmap's own service fingerprint is unwrapped into its probe payloads",
  fn = function()
    local payloads = load({})._TEST.service_fp_payloads(SERVICE_FP)

    t.length(payloads, 1,
      "two probes answered identically, so there is one distinct payload")
    t.matches(payloads[1], "Server: CouchDB/2%.3%.1 %(Erlang OTP/19%)",
      "the SF: wrapping and every escape must be undone")
    t.is_true(payloads[1]:find("SF:", 1, true) == nil,
      "no continuation marker may survive into the banner")
    t.is_true(payloads[1]:find("Time=", 1, true) == nil,
      "nor nmap's own metadata, which differs between two identical hosts")
  end,
}

suite[#suite + 1] = {
  name = "a banner rule names software nmap itself could not",
  fn = function()
    -- Free in every sense: the text is already in hand, so a banner identity
    -- costs no request, no credit and no time on the wire. nmap records a
    -- fingerprint exactly when its own probes did NOT settle the service, which
    -- is the case worth trying - a port with no CPE is one that would otherwise
    -- spend a credit at audit/smart or go unreported.
    local env = load(COUCHDB)
    local port = t.port({service_fp = SERVICE_FP})

    t.equals(env._TEST.fingerprint_banner(port)["cpe:/a:apache:couchdb:2.3.1"],
      "service banner",
      "the banner must produce the identity, and say where it came from")
  end,
}

suite[#suite + 1] = {
  name = "a banner is matched line by line, not as one blob",
  fn = function()
    -- Recog's banner patterns are written against a single greeting line and
    -- most are anchored with ^. Matched against the whole payload, an anchored
    -- pattern fires only if the software happens to be on the first line.
    local env = load({{"banner", "cpe:/a:apache:couchdb",
                       "^Server: CouchDB/([%d.]+) %(Erlang OTP/19%)$"}})
    local port = t.port({service_fp = SERVICE_FP})

    t.equals(env._TEST.fingerprint_banner(port)["cpe:/a:apache:couchdb:2.3.1"],
      "service banner",
      "an anchored rule must see the start of each line, not of the payload")
  end,
}

suite[#suite + 1] = {
  name = "a port nmap could not name is in scope, on its banner alone",
  fn = function()
    -- The whole point of the channel, and it was unreachable: nmap records a
    -- service fingerprint exactly when its own probes did NOT settle the
    -- service, and then leaves name, product, version and cpe empty. Measured
    -- against a real listener greeting with an unrecognised banner: a 2 209-byte
    -- service_fp and nothing else, so every other clause of the portrule was
    -- false on precisely the ports the 163 banner rules were imported for.
    local env = load(COUCHDB)
    local host = t.host()
    local unnamed = t.port({number = 4200, service = "unknown", name = nil,
                            service_fp = SERVICE_FP})

    t.is_true(env.portrule(host, unnamed),
      "a port whose only identity is its banner must be in scope")

    -- And nothing else changes: a port with neither a banner nor a version nor
    -- a CPE is still out of scope, or the script would run on every open port.
    t.is_false(env.portrule(host, t.port({number = 4201, service = "unknown",
                                          name = nil})),
      "a port with nothing at all must stay out of scope")
  end,
}

suite[#suite + 1] = {
  name = "a banner port is read, not swept",
  fn = function()
    -- Being in scope must not turn into 125 HTTP requests at something that is
    -- not a web server. The banner costs no request at all: the text is already
    -- in hand.
    local env, http = load(COUCHDB), nil
    local host = t.host()
    local port = t.port({number = 4200, service = "unknown", name = nil,
                         service_fp = SERVICE_FP})

    env.action(host, port)

    t.contains(port.version.cpe, "cpe:/a:apache:couchdb:2.3.1",
      "the identity must be published onto the port")
  end,
}

suite[#suite + 1] = {
  name = "a fingerprint with no probe payload yields nothing, not a crash",
  fn = function()
    local env = load(COUCHDB)

    t.is_nil(env._TEST.service_fp_payloads("SF-Port80-TCP:V=7.94%I=7%D=8/19"),
      "metadata with no %r record is not a banner")
    t.same(env._TEST.fingerprint_banner(t.port()), {},
      "and a port with no fingerprint at all is simply not a banner port")
  end,
}

suite[#suite + 1] = {
  name = "the decoded banner is one bounded string for the paid endpoint",
  fn = function()
    -- What audit/smart is asked about when a port has no CPE at all. Sending
    -- the fingerprint whole bought a credit for a string that is mostly nmap's
    -- own metadata - and one carrying %Time= can never be matched against the
    -- scan cache, so two identical hosts would each pay.
    local decoded = load({})._TEST.decode_service_fp(SERVICE_FP)

    t.matches(decoded, "CouchDB/2%.3%.1", "the software must survive")
    t.is_true(#decoded <= 512, "and the string must be bounded")
    t.is_true(decoded:find("Time=", 1, true) == nil,
      "the metadata must not be bought")
  end,
}

return suite
