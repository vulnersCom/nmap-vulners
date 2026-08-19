--- Validation of the fingerprint rules vulners.nse downloads.
--
-- The rules are pure data, so nothing but a test protects them. Every case here
-- encodes an assumption the sweep actually relies on: match_group() does
-- `from, to, vers = subject:find(regex, init)` and then builds
-- `alias .. ":" .. vers`, so a pattern without exactly one capture can never
-- produce a CPE, and a malformed alias produces a malformed CPE.
--
-- The rules no longer live in the script. They are published as
-- catalog/fingerprints.json and fetched at scan time, so this suite reads that
-- file and hands it to the script's own readers - which is the same path a real
-- scan takes. A case that hand-built the runtime tables would pass against a
-- script whose validation rejects the very data it publishes.
--
-- The strongest case here is mechanical: the catalogue records, for almost every
-- rule, a subject an upstream observed in the field and the version it should
-- yield, and every shipped pattern is run against its own subject under nmap's
-- Lua - the interpreter that will run it during a scan.

local t, testdir, root = ...

local io = require "io"
local json = require "json"
local os = require "os"
local string = require "string"
local table = require "table"

--- The published dictionary, as name -> rule.
local function load_source()
  local handle = io.open(root .. "/catalog/fingerprints.json", "r")
  t.is_true(handle ~= nil,
    "catalog/fingerprints.json must be readable from " .. root)
  local text = handle:read("a")
  handle:close()

  local ok, document = json.parse(text)
  t.is_true(ok, "catalog/fingerprints.json must be valid JSON")
  t.equals(document.schema, 1, "the dictionary must declare schema 1")
  t.equals(type(document.rules), "table", "the dictionary must carry rules")
  return document.rules
end

--- The rules as the matcher will hold them: name -> {alias, anchor, regex, channel}.
--
-- Read back out of the loaded catalogue rather than out of the file, so that
-- anything the script's readers refuse is absent here too - a rule that ships
-- and is then rejected at load time is a rule that silently does nothing.
local function load_patterns()
  local env = t.load_vulners({root = root})
  local grouped = env._TEST.catalog().fingerprints
  t.equals(type(grouped), "table", "the loaded catalogue must hold rules")

  local patterns, count = {}, 0
  for channel, flat in pairs(grouped) do
    t.equals(type(channel), "string", "a channel key must be a string")
    t.equals(type(flat), "table", channel .. ": a channel must hold a flat list")
    t.equals(#flat % 4, 0,
      channel .. ": the flat table holds anchored, alias, anchor, regex quadruples")
    for i = 1, #flat, 4 do
      local regex = flat[i + 3]
      -- Slot 1 is the start-anchored flag the matcher reads to stop after the
      -- first match. It used to hold the rule's NAME, which nothing read - so
      -- the key here is now the rule's own identity, which is what the
      -- catalogue deduplicates on anyway.
      t.equals(flat[i], regex:sub(1, 1) == "^",
        channel .. ": the anchored flag must agree with the pattern")
      patterns[channel .. "|" .. tostring(flat[i + 1]) .. "|" .. tostring(regex)] = {
        alias = flat[i + 1],
        anchor = flat[i + 2],
        regex = regex,
        channel = channel,
      }
      count = count + 1
    end
  end
  t.is_true(count > 100, "expected the full rule set, got " .. count .. " rules")
  return patterns, count
end

--- Count Lua capture groups: '(' that is neither escaped with '%' nor inside a
-- character class.
--
-- The class is the part the first version of this function missed. A '(' inside
-- [^(] is a class member, not a capture, and reporting three captures for a
-- pattern that has one fails a rule that is perfectly correct - which is how a
-- test stops being a check and starts being an obstacle.
local function count_captures(pattern)
  local count, i, in_class = 0, 1, false
  while i <= #pattern do
    local c = pattern:sub(i, i)
    if c == "%" then
      i = i + 2
    else
      if c == "[" and not in_class then
        in_class = true
        -- A ']' in first position is a member, not the terminator.
        if pattern:sub(i + 1, i + 1) == "^" then i = i + 1 end
        if pattern:sub(i + 1, i + 1) == "]" then i = i + 1 end
      elseif c == "]" and in_class then
        in_class = false
      elseif c == "(" and not in_class then
        count = count + 1
      end
      i = i + 1
    end
  end
  return count
end

--- Sorted list of pattern names, so failures are reported deterministically.
local function sorted_names(patterns)
  local names = {}
  for name in pairs(patterns) do names[#names + 1] = name end
  table.sort(names)
  return names
end

-- Every channel key the matcher builds a subject for. A rule filed anywhere
-- else is dead data: nothing would ever look it up, and nothing would say so.
local FIXED_CHANNELS = {
  ["raw"] = true, ["body"] = true, ["title"] = true,
  ["script"] = true, ["banner"] = true, ["cookie"] = true,
}

local function known_channel(channel)
  return FIXED_CHANNELS[channel]
      or channel:match("^hdr:[%w%-_.]+$") ~= nil
      or channel:match("^meta:[%w%-_.:]+$") ~= nil
end

local suite = {}

suite[#suite + 1] = {
  name = "the published rule set loads and is grouped by channel",
  fn = function()
    local patterns, count = load_patterns()
    t.equals(type(patterns), "table", "the embedded patterns must be a table")
    t.is_true(count > 100, "expected the full rule set, got " .. count .. " rules")

    for _, name in ipairs(sorted_names(patterns)) do
      local channel = patterns[name].channel
      t.is_true(known_channel(channel), string.format(
        "%s: nothing builds a subject for channel %q, so the rule can never fire",
        name, channel))
    end
  end,
}

suite[#suite + 1] = {
  name = "every rule has an alias, an anchor slot and a regex",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local entry = patterns[name]
      t.equals(type(entry.alias), "string", name .. ": alias must be a string")
      t.equals(type(entry.regex), "string", name .. ": regex must be a string")
      t.equals(type(entry.anchor), "string",
        name .. ": anchor must be a string, empty when the rule has no literal")
    end
  end,
}

suite[#suite + 1] = {
  name = "every alias is a well formed CPE prefix without a version",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local alias = patterns[name].alias
      -- cpe:/<part>:<vendor>:<product> - the version is appended at runtime.
      local part, vendor, product = alias:match("^cpe:/([aoh]):([^:]+):([^:]+)$")
      t.is_true(part, string.format("%s: alias %q must look like cpe:/a:vendor:product",
        name, alias))
      t.is_true(vendor and #vendor > 0, name .. ": alias needs a vendor")
      t.is_true(product and #product > 0, name .. ": alias needs a product")
    end
  end,
}

suite[#suite + 1] = {
  name = "every regex compiles as a Lua pattern",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local regex = patterns[name].regex
      local ok, err = pcall(string.find, "probe string", regex)
      t.is_true(ok, string.format("%s: pattern %q does not compile: %s",
        name, regex, tostring(err)))
    end
  end,
}

suite[#suite + 1] = {
  name = "every regex has exactly one capture, otherwise no CPE can be built",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local regex = patterns[name].regex
      t.equals(count_captures(regex), 1,
        string.format("%s: pattern %q must capture exactly the version", name, regex))
    end
  end,
}

suite[#suite + 1] = {
  name = "the capture yields a version string, not an empty match",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local regex = patterns[name].regex
      -- An empty subject must never produce a version: that would attach a
      -- bogus CPE to every scanned page.
      local _, _, captured = ("").find("", regex)
      t.is_nil(captured, string.format("%s: pattern %q matches an empty body", name, regex))
    end
  end,
}

suite[#suite + 1] = {
  name = "no pattern contains an anchor that Lua treats as a literal",
  fn = function()
    local patterns = load_patterns()

    -- In a Lua pattern "^" anchors only at position 1 and "$" only at the very
    -- end; anywhere else they match those characters literally. Three shipped
    -- patterns carried such a caret and could never match a real response.
    for _, name in ipairs(sorted_names(patterns)) do
      local regex = patterns[name].regex
      local i, in_class = 1, false

      while i <= #regex do
        local c = regex:sub(i, i)
        if c == "%" then
          i = i + 2
        else
          if c == "[" and not in_class then
            in_class = true
            if regex:sub(i + 1, i + 1) == "^" then i = i + 1 end
          elseif c == "]" and in_class then
            in_class = false
          elseif not in_class and c == "^" and i > 1 then
            t.fail(string.format("%s: '^' at position %d is a literal, not an anchor: %q",
              name, i, regex))
          elseif not in_class and c == "$" and i < #regex then
            t.fail(string.format("%s: '$' at position %d is a literal, not an anchor: %q",
              name, i, regex))
          end
          i = i + 1
        end
      end
    end
  end,
}

suite[#suite + 1] = {
  name = "every shipped pattern extracts the version from its recorded subject",
  fn = function()
    -- Read straight from the published document, which is what carries both
    -- the pattern and the example. It used to join the RUNTIME tuple to the
    -- document by rule name, which quietly made the tuple's layout part of this
    -- case: when the name left the tuple, the join found nothing and the case
    -- reported "0 checked" rather than a translation error.
    local source = load_source()
    local names = {}
    for name in pairs(source) do names[#names + 1] = name end
    table.sort(names)

    -- This is the case that speaks for the whole import. Each rule that came
    -- from a catalogue carries a subject that catalogue observed in the field
    -- and the version it is meant to yield; the pattern is the result of
    -- translating a PCRE into a Lua pattern, and a translation that looks right
    -- and is wrong is exactly what this repository has been caught by before.
    local checked = 0
    for _, name in ipairs(names) do
      local entry = source[name]
      local example = entry and entry.example
      if example and example.subject and example.version then
        local _, _, captured = example.subject:find(entry.regex)
        t.equals(captured, example.version, string.format(
          "%s: pattern %q must extract %q from %q",
          name, entry.regex, example.version, example.subject))
        checked = checked + 1
      end
    end

    t.is_true(checked > 400, string.format(
      "expected most rules to carry a subject to be checked against, got %d",
      checked))
  end,
}

suite[#suite + 1] = {
  name = "an anchor really is a substring the pattern cannot match without",
  fn = function()
    local patterns = load_patterns()
    local source = load_source()

    -- The anchor is a prefilter: match_group() runs the pattern only when a
    -- plain find for the anchor succeeds on a LOWERCASED copy of the subject.
    -- An anchor that is not genuinely required silently switches the rule off,
    -- which is the worst failure this file can ship - a detection that is
    -- present, structurally valid, and never fires.
    -- Counted, because every assertion below sits behind the anchor test.
    -- With the anchors gone the loop body simply never runs, and this case
    -- reported success for a catalogue whose prefilter had been deleted -
    -- measured: replacing the anchor extraction in read_fingerprints with an
    -- empty string left all 254 cases green.
    local anchored = 0

    for _, name in ipairs(sorted_names(patterns)) do
      local anchor = patterns[name].anchor
      if anchor ~= "" then
        anchored = anchored + 1
        t.equals(anchor, anchor:lower(),
          name .. ": the anchor must be lowercase, the subject is lowercased")

        local entry = source[name]
        local example = entry and entry.example
        if example and example.subject then
          t.is_true(example.subject:lower():find(anchor, 1, true) ~= nil,
            string.format("%s: anchor %q is absent from its own subject %q, "
              .. "so the prefilter would never let the pattern run",
              name, anchor, example.subject))
        end
      end
    end

    t.is_true(anchored > 400, string.format(
      "expected most rules to carry an anchor, got %d; a rule without one "
      .. "reads only the first UNANCHORED_WINDOW bytes of its subject",
      anchored))
  end,
}

suite[#suite + 1] = {
  name = "no two rules share the same alias and pattern in the same channel",
  fn = function()
    local patterns = load_patterns()
    local seen = {}
    for _, name in ipairs(sorted_names(patterns)) do
      local entry = patterns[name]
      local key = entry.channel .. "|" .. entry.alias .. "|" .. entry.regex
      t.is_nil(seen[key], string.format("%s duplicates %s", name, tostring(seen[key])))
      seen[key] = name
    end
  end,
}

suite[#suite + 1] = {
  name = "no pattern uses a quantifier Lua does not have",
  fn = function()
    -- Lua patterns have no optional GROUP: "( x )?" is a literal question mark,
    -- so a pattern written that way can only match a banner that really ends in
    -- "?". Two shipped patterns did, and neither could ever have matched a real
    -- SunOS server - silently, because a pattern that matches nothing looks
    -- exactly like a product nobody is running.
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local regex = patterns[name].regex
      for _, quantifier in ipairs({"%)%?", "%)%*", "%)%+"}) do
        local position = regex:find(quantifier)
        t.is_nil(position, string.format(
          "%s applies a quantifier to a group, which Lua reads literally: %s",
          name, regex))
      end
    end
  end,
}

suite[#suite + 1] = {
  name = "a capture that is not a version does not become one",
  fn = function()
    local env = t.load_vulners({root = root})
    local version_of = env._TEST.version_of

    -- Surrounding space. Wappalyzer writes CMSimple's rule with the separator
    -- INSIDE the capture group, so the raw capture is " 5.4" and the request
    -- line carried a CPE with a space in it. Ten shipped rules do this.
    t.equals(version_of(" 5.4"), "5.4", "surrounding space must be trimmed off")
    t.equals(version_of("5.4\t"), "5.4", "including a tab")

    -- A capture with no digit is not a version. Two recog rules captured the
    -- Debian codenames "sarge" and "squeeze"; appending one to a CPE asks the
    -- service about a release that does not exist under that name, and the
    -- empty answer reads to an operator exactly like a clean host.
    t.is_nil(version_of("sarge"), "a codename is not a version")
    t.is_nil(version_of("q"), "a bare word is not a version")
    t.is_nil(version_of("."), "a bare separator is not a version")
    t.is_nil(version_of("   "), "whitespace is not a version")

    -- A capture that swallowed the prose around the number is not a version
    -- either, and this is the half that used to get through: every one of
    -- these was published onto a port, printed in the report and sent to the
    -- API as a CPE that can only ever come back empty. Whitespace and slash
    -- are what separates them from a real version, measured across the 526
    -- rules that carry a recorded example.
    t.is_nil(version_of("7 (build 7)"), "a build note is not a version")
    t.is_nil(version_of("Release 7"), "a word and a number is not a version")
    t.is_nil(version_of("9 (Shrike)"), "a codename beside a number is not one")
    t.is_nil(version_of("OTP/7"), "a prefix the rule failed to exclude is not one")
    t.is_nil(version_of("8.1 SP3"),
      "and neither is a service pack written with a space: a CPE URI cannot "
      .. "carry one, so the lookup could never match")

    -- What must still get through: real versions are not all dotted decimals.
    t.equals(version_of("4.1.1a@1.791"), "4.1.1a@1.791", "a BIG-IP version")
    t.equals(version_of("V5R3M0"), "V5R3M0", "an IBM HTTP Server version")
    t.equals(version_of("3.3(2)"), "3.3(2)", "a Cisco MDS version")
    t.equals(version_of("3.7.4.post0"), "3.7.4.post0", "a Python package version")
  end,
}

suite[#suite + 1] = {
  name = "a body chosen to be expensive cannot outrun the time budget",
  fn = function()
    local env = t.load_vulners({root = root})

    -- The defect this pins: the sweep's budget used to be checked once per
    -- fetched response, never inside the matcher, so the last body admitted
    -- before the deadline still ran every pattern to completion. Measured at
    -- 24.5 s for one 128 KB body of repeated "jquery", against a budget of 3 s,
    -- with the scheduler unable to preempt any of it.
    --
    -- Two things fixed it and both are exercised here: the deadline is now read
    -- between rules, and the patterns that were quadratic read <script src=>
    -- values rather than the whole document, so this body no longer reaches
    -- them at all.
    local hostile = string.rep("jquery", 22000)          -- 132 000 bytes
    t.is_true(#hostile > 131000, "the sample must exceed the body cap")

    local response = t.response({body = hostile, status = 200})
    local found, seen = {}, {}

    local started = os.clock()
    local deadline = started + 3.0
    env._TEST.match_subjects(env._TEST.subjects_of(response, deadline),
                             found, seen, deadline)
    local elapsed = os.clock() - started

    t.is_true(elapsed < 6.0, string.format(
      "matching a hostile body took %.1f s against a 3 s budget", elapsed))
  end,
}

return suite
