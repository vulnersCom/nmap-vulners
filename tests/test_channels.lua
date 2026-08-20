--- Tests for the channels: which part of a response a rule is matched against.
--
-- A rule declares its subject and is filed under it, which is what took the
-- matcher from 178 rules in 30 ms to 722 in 1 ms. The cost of that design is
-- that a channel nothing builds is a channel whose rules can never fire, and
-- nothing else in the suite would notice: the rules load, the catalogue
-- validates, the scan runs, and one whole class of identity is silently
-- absent.
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

--; One rule per channel, each with an alias of its own, so which channel fired
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

--; A catalogue holding exactly the rules a case asks for.
--
-- A filler rule always ships: the readers refuse a dictionary with nothing
-- usable in it, which is correct behaviour and would otherwise make a case
-- about the banner fail as a broken catalogue.
local function catalog_of(rules)
  local dictionary = {
    ["Filler, server"] = {alias = "cpe:/a:example:filler",
      channel = "hdr:x-filler",
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

--; A loaded script whose catalogue holds those rules and nothing else.
local function load(rules, opts)
  opts = opts or {}
  return t.load_vulners({root = root, catalog = catalog_of(rules),
                         paths = opts.paths})
end

--; Every CPE those rules find in one response.
local function matched(env, response)
  local T = env._TEST
  local deadline = os.clock() + 5
  local found, seen = {}, {}
  T.match_subjects(T.subjects_of(response, deadline), found, seen, deadline)
  table.sort(found)
  return found
end

--; The response every channel case is matched against.
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
    -- the rule: the same pattern over the whole header block could match
    -- inside a different header entirely, so an anchored `hdr:server` rule can
    -- mean it.
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

    t.is_true(has(found, "cpe:/a:x:by_cookie:abc1"),
      "the cookie subject exists")
    t.is_true(has(found, "cpe:/a:x:by_header:abc1"),
      "and so does the header one")
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
  'SF-Port8080-TCP:V=7.94%I=7%D=8/19%Time=68A3B1C2' ..
    '%P=x86_64-apple-darwin%r(Get',
  'SF:Request,7B,"HTTP/1\\.1\\x20200\\x20OK' ..
    '\\r\\nServer:\\x20CouchDB/2\\.3\\.1\\x20\\',
  'SF:(Erlang\\x20OTP/19\\)\\r\\n\\r\\n")%r(HTTPOptions,7B,' ..
    '"HTTP/1\\.1\\x20200\\x20OK',
  'SF:\\r\\nServer:\\x20CouchDB/2\\.3\\.1\\x20' ..
    '\\(Erlang\\x20OTP/19\\)\\r\\n\\r\\n");',
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
    -- fingerprint exactly when its own probes did NOT settle the service,
    -- which is the case worth trying - a port with no CPE is one that would
    -- otherwise spend a credit at audit/smart or go unreported.
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
    -- against a real listener greeting with an unrecognised banner: a 2
    -- 209-byte service_fp and nothing else, so every other clause of the
    -- portrule was false on precisely the ports the 163 banner rules were
    -- imported for.
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
    -- not a web server. The banner costs no request at all: the text is
    -- already in hand. The sweep is given a real path to request, so "not
    -- swept" is something this case can actually witness. It used to bind
    -- `http` to nil and load with the sweep switched off, which made the
    -- second half of its own name unobservable: the gate could be deleted
    -- outright and this stayed green.
    local env, http = load(COUCHDB, {paths = {"/never-swept"}})
    local host = t.host()
    local port = t.port({number = 4200, service = "unknown", name = nil,
                         service_fp = SERVICE_FP})

    env.action(host, port)

    t.contains(port.version.cpe, "cpe:/a:apache:couchdb:2.3.1",
      "the identity must be published onto the port")
    t.length(http.matching("/never-swept"), 0,
      "a banner costs no request: the text was already in hand")
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

-- A real fingerprint, captured rather than imagined: a local service was made
-- to answer with a banner carrying every sequence the decoding is delicate
-- about, and `nmap -sV --version-all` was pointed at it. What came back is
-- pasted below unchanged, and it settles how nmap escapes:
--
--   "  -> \"      )  -> \)      (  -> \(      .  -> \.
--   \  -> \\      NUL -> \0     space -> \x20
--
-- Two consequences. A bare ") never occurs inside a payload, so the record
-- terminator is not ambiguous. And a literal backslash in the data arrives as
-- \\, which is what makes undoing the escapes in SEQUENTIAL passes wrong: the
-- pass for \t sees the second half of a \\ followed by a t and rewrites data
-- as though it were an escape.
local ODD_FP = table.concat({
  'SF-Port9077-TCP:V=7.991%I=9%D=8/20%Time=6A86AA59' ..
    '%P=arm-apple-darwin25.6.0%',
  'SF:r(NULL,31,"ODD/1\\.0\\x20say\\x20\\"\\)\\"\\x20here' ..
    '\\x20\\0\\0\\x20back\\\\slash\\x20',
  'SF:\\(paren\\)\\x20done\\r\\n");',
}, "\n")

suite[#suite + 1] = {
  name = "every escape nmap writes is undone once, and only as an escape",
  fn = function()
    local payloads = load({})._TEST.service_fp_payloads(ODD_FP)

    t.length(payloads, 1, "one probe answered, so one payload")
    local text = payloads[1]

    -- ascii_lines() maps a byte outside 32..126 to a space and then collapses
    -- runs of blanks, so two NULs decoded correctly leave "here back". The
    -- digits are the tell: \0 falling through to a catch-all that strips the
    -- backslash arrives as the character "0", survives the ascii filter, and
    -- puts a number the service never sent into a banner that is matched
    -- against version rules and sent to the endpoint as software text.
    t.is_true(text:find("here back", 1, true) ~= nil,
      "\\0 is a NUL byte, which the ascii filter then drops")
    t.is_true(text:find("here 00 back", 1, true) == nil,
      "and must not arrive as the digit zero")

    -- Windows paths are the common case, not a contrived one: an error page
    -- naming C:\temp arrives as C:\\temp, and a pass for \t turns it into a
    -- tab.
    t.is_true(text:find("back\\slash", 1, true) ~= nil,
      "a literal backslash must survive as one backslash")
    t.is_true(text:find("\t") == nil,
      "and must not be re-read as the escape that follows it")

    -- The other direction, so the fix cannot be an over-correction that stops
    -- undoing escapes at all.
    t.is_true(text:find('say ")" here', 1, true) ~= nil,
      "an escaped quote and paren are still data, and still get unescaped")
    t.is_true(text:find("(paren)", 1, true) ~= nil,
      "as is an escaped paren pair")
    t.is_true(text:find("ODD/1.0", 1, true) ~= nil,
      "and an escaped dot is a dot")
  end,
}

suite[#suite + 1] = {
  name = "a literal escape sequence in a banner is text, not an escape",
  fn = function()
    -- The same defect seen from the side that matters for identity: text that
    -- merely LOOKS like an escape must not be executed. nmap writes the four
    -- characters \x28 as \\x28; decoding the hex form before the backslash
    -- form turns them into "(" - a character the service never sent.
    --
    -- Assembled here rather than captured, because a service answering with a
    -- Windows path is easier to describe than to stand up. The escaping is the
    -- capture's, verified above.
    local fp = 'SF-Port9077-TCP:V=7.991%I=9%D=8/20%r(NULL,10,' ..
      '"eval\\\\x28\\\\x29\\x20in\\x20C:\\\\temp\\\\report.log")'
    local payloads = load({})._TEST.service_fp_payloads(fp)

    t.length(payloads, 1, "one record, one payload")
    local text = payloads[1]

    t.is_true(text:find("eval\\x28\\x29", 1, true) ~= nil,
      "an escaped backslash protects what follows it from being decoded")
    -- The one every Windows error page hits. C:\temp arrives as C:\\temp, and
    -- a pass for \t reads the second backslash and the t as an escape.
    t.is_true(text:find("C:\\temp\\report.log", 1, true) ~= nil,
      "a Windows path survives as a path")
    t.is_true(text:find("\t") == nil,
      "with no tab invented where the service sent a backslash")
  end,
}

suite[#suite + 1] = {
  name = "a truncated hex escape is text, not a crash",
  fn = function()
    -- nmap always writes two digits, so this is a guard rather than a case
    -- from the field - but lpeg-utility asks for AT MOST two, and on one digit
    -- its tonumber("", 16) is nil and string.char(nil) raises. A raising
    -- script does not lose a banner, it loses the whole port: nmap replaces
    -- every finding the port had with "Script execution failed".
    local fp = 'SF-Port9077-TCP:V=7.991%I=9%D=8/20%r(NULL,8,' ..
      '"HTTP\\x20\\xZZ\\x2")'
    local payloads = load({})._TEST.service_fp_payloads(fp)

    t.length(payloads, 1, "the record still parses")
    -- Pinned rather than merely "did not crash": an escape that is not one
    -- loses its backslash and the rest is text, so \xZZ is xZZ and a trailing
    -- \x2 is x2. Asserting the whole string is what makes this case fail if
    -- the fallback ever starts swallowing the bytes instead.
    t.equals(payloads[1], "HTTP xZZx2",
      "a bad escape degrades to its own text, byte for byte")
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


-- ------------------------------------------------ what a rule may look at

suite[#suite + 1] = {
  name = "a rule reads a window around its anchor, not the whole body",
  fn = function()
    -- The only thing that bounds a Lua pattern is what it is allowed to SEE.
    -- Every budget in the script bounds work BETWEEN calls to string.find and
    -- none can pre-empt one, because pattern matching neither yields nor
    -- returns until it is done. Measured on the shipped "Bootstrap, body" rule
    -- against a body of "<link href=bootstrap" repeated with no ">": 2 KB
    -- costs 0.9 s, 4 KB 13.7 s, and the 128 KB the body cap admits is hours -
    -- with the whole nmap scheduler stopped, in the default keyless
    -- configuration.
    --
    -- So this case pins the bound from both ends: the rule still fires next to
    -- its anchor, and it does NOT reach a version parked far beyond the
    -- window.
    local env = load({})
    local T = env._TEST

    local rules = {
      -- A lazy span, which is the shape the real corpus is full of: the
      -- shipped Bootstrap rule is "<link[^>]*
      -- href=[^>]-bootstrap[^>]-(%d%d*)". Such a pattern is exactly what
      -- backtracks catastrophically, and exactly what the window has to stop
      -- from seeing the whole body.
      ["Widget, body"] = {alias = "cpe:/a:acme:widget", channel = "body",
                          anchor = "widget", regex = "widget[^!]-/([%d.]+)"},
    }
    t.give_catalog(env, {
      fingerprints = {schema = 1, rules = rules},
      paths = {schema = 1, paths = {"/"}},
      probes = {schema = 1, probes = {}},
    })

    local near = t.response({status = 200, body = "<p>widget/1.2.3</p>"})
    local found, seen = {}, {}
    T.match_subjects(T.subjects_of(near, os.clock() + 3), found, seen,
      os.clock() + 3)
    t.contains(found, "cpe:/a:acme:widget:1.2.3",
      "a rule must still fire on text beside its anchor")

    -- The anchor is at the start; the version sits far past the window.
    -- One anchor, and the text the pattern would need is 8 KB past it.
    local far = t.response({status = 200,
      body = "widget" .. string.rep(".", 8000) .. "/9.9.9"})
    local found_far, seen_far = {}, {}
    T.match_subjects(T.subjects_of(far, os.clock() + 3), found_far, seen_far,
      os.clock() + 3)
    t.length(found_far, 0,
      "and must not reach a match parked beyond the window; without that " ..
        "bound " ..
      "one hostile body freezes every script in the scan")
  end,
}


suite[#suite + 1] = {
  name = "a start-anchored rule matches only at the start",
  fn = function()
    -- string.find(s, pat, init) re-anchors "^" AT init, so the
    -- every-occurrence loop let an anchored rule fire at every offset:
    -- measured, "^nginx/([%d.]+)" against "nginx/1.2.3nginx/9.9.9" matched
    -- twice. 373 of the shipped rules start with "^", and each spurious match
    -- mints a CPE that is reported, published onto the port and spent as an
    -- outbound lookup.
    local env = load({})
    local T = env._TEST
    t.give_catalog(env, {
      fingerprints = {schema = 1, rules = {
        ["Anchored, hdr:server"] = {alias = "cpe:/a:f5:nginx",
          channel = "hdr:server", anchor = "nginx/",
          regex = "^nginx/([%d.]+)"},
      }},
      paths = {schema = 1, paths = {"/"}},
      probes = {schema = 1, probes = {}},
    })

    local response = t.response({status = 200,
      header = {["Server"] = "nginx/1.2.3nginx/9.9.9"}})
    local found, seen = {}, {}
    T.match_subjects(T.subjects_of(response, os.clock() + 3), found, seen,
      os.clock() + 3)

    t.same(found, {"cpe:/a:f5:nginx:1.2.3"},
      "there is one start, so there is one match")
  end,
}

suite[#suite + 1] = {
  name = "a response with no body offers no body subject",
  fn = function()
    -- stdnse.string_or_blank(x, nil) returns the LITERAL "<blank>": the second
    -- argument is the substitute, and nil selects the default one rather than
    -- disabling substitution. So every 204, 304 and body-less 302 ran the
    -- whole body rule group and every probe detector against a string this
    -- script invented, and the nil guard beside it was dead.
    local env = load({})
    local subjects = env._TEST.subjects_of(
      t.response({status = 204, header = {["Server"] = "nginx/1.13.4"}}),
      os.clock() + 3)

    -- Asserted before the loop, because a loop that iterates zero times
    -- asserts nothing: measured, making subjects_of return an empty list left
    -- this case green while every other channel case went red.
    t.is_true(#subjects > 0,
      "the header subjects must still be offered when there is no body")

    local keys = {}
    for _, subject in ipairs(subjects) do
      keys[#keys + 1] = subject.key
      t.is_false(subject.text:find("<blank>", 1, true),
        "no subject may be a string this script made up")
      t.is_false(subject.key == "body",
        "a response with no body has no body to match against")
    end
    t.contains(keys, "hdr:server",
      "and the header that IS present must be among them")
  end,
}


suite[#suite + 1] = {
  name = "a probe detector stops when the sweep's clock has run out",
  fn = function()
    -- The detectors run DOWNLOADED patterns against a body the target chose,
    -- and they alone were never given the budget match_group honours: measured
    -- on a shipped detector, one 128 KB body cost 11 s of non-yielding work,
    -- which is the whole nmap scheduler stopped.
    local env = load({})
    local T = env._TEST
    t.give_catalog(env, {
      fingerprints = {schema = 1, rules = {
        ["Zed, body"] = {alias = "cpe:/a:x:z", channel = "body",
                         anchor = "zed", regex = "zed/([%d.]+)"},
      }},
      paths = {schema = 1, paths = {"/"}},
      probes = {schema = 1, probes = {
        {name = "zed", alias = "cpe:/a:x:z",
         detect = {{channel = "body", regex = "zed"}},
         extract = {{regex = "zed/([%d.]+)"}}, paths = {"/v"}},
      }},
    })

    local subjects = T.subjects_of(t.response({status = 200,
      body = "zed here"}),
      os.clock() + 3)

    local live = {}
    T.detect_probes(subjects, live, os.clock() + 3)
    t.is_true(live[1], "the detector fires while there is budget left")

    local expired = {}
    T.detect_probes(subjects, expired, os.clock() - 1)
    t.is_nil(expired[1],
      "and runs no downloaded pattern once the budget is gone")
  end,
}


suite[#suite + 1] = {
  name = "the banner pass honours the port's budget rather than its own",
  fn = function()
    -- SWEEP_TIME_BUDGET says "how long the pattern set may run on ONE PORT",
    -- and three passes each used to start their own clock - so a port that did
    -- the banner, the sweep and the probes could spend three times the stated
    -- bound in non-yielding matching. They share one budget now, which only
    -- works if each pass actually reads the one it is handed.
    local env = load(COUCHDB)
    local port = t.port({service_fp = SERVICE_FP})

    t.is_true(next(env._TEST.fingerprint_banner(port)) ~= nil,
      "the banner names something when there is budget for it")
    t.is_nil(next(env._TEST.fingerprint_banner(port, os.clock() - 1)),
      "and matches nothing once the port's budget is gone")
  end,
}

suite[#suite + 1] = {
  name = "header subjects are offered in a stable order",
  fn = function()
    -- Lua seeds its string hash per process, so iterating a header table with
    -- pairs() offers the channels in a different order on every nmap run. That
    -- decides which identities survive MAX_IDENTITIES_PER_PORT, so two scans
    -- of one unchanged host could report different groups. subjects_of sorts
    -- for exactly that reason, and nothing asserted it: deleting the sort left
    -- all 254 cases green.
    local env = load({})
    local subjects = env._TEST.subjects_of(t.response({status = 200, header = {
      ["Z-Last"] = "z", ["A-First"] = "a", ["M-Middle"] = "m",
    }}), os.clock() + 3)

    local headers = {}
    for _, subject in ipairs(subjects) do
      if subject.key:find("^hdr:") then
        headers[#headers + 1] = subject.key
      end
    end

    t.same(headers, {"hdr:a-first", "hdr:m-middle", "hdr:z-last"},
      "the header channels must be offered in sorted order, every run")
  end,
}
return suite
