--- Tests for the post-scan notice: what the scan says once, at the end.
--
-- This is the only place the script speaks about the scan rather than about a
-- port, and every sentence in it is there because its absence was misleading:
-- a capability that did not run reads as a capability that found nothing, and
-- an empty report reads as a clean network. Until this file existed exactly one
-- of its branches was covered.
--
-- The postrule is reached the way nmap reaches it - by loading the script and
-- setting SCRIPT_TYPE - because the dispatch table is part of what is being
-- tested: an action() that ignored SCRIPT_TYPE would still pass a test that
-- called post_action directly.

local t, testdir, root = ...

local string = require "string"
local table = require "table"

--- Load the script, put the scan in the state a case describes, and ask the
-- postrule what it has to say.
--
-- @param setup function(shared) - mutates the scan-wide state
-- @return the notice text, or nil
local function notice(setup, opts)
  opts = opts or {}
  -- A fresh scan each time. The notice reads scan-wide state out of
  -- nmap.registry, which outlives a load, so a case that asks twice would be
  -- asking the second time about the first one's scan.
  t.reset_registry()
  local env = t.load_vulners({
    root = root,
    catalog = false,
    token = opts.token,
    args = opts.args,
  })
  local shared = env._TEST.state()
  -- Nothing is advertised to a scan that looked nothing up, so every case that
  -- expects to be told something has to have consulted a port first.
  shared.consulted = true
  if setup then setup(shared, env) end

  env.SCRIPT_TYPE = "postrule"
  local structured, text = env.action()
  t.is_nil(structured, "the notice is text, not a finding")
  return text
end

local suite = {}

suite[#suite + 1] = {
  name = "a scan that looked nothing up advertises nothing",
  fn = function()
    -- nmap -sn with this script loaded reaches the postrule having touched no
    -- port. Advertising a key to somebody who ran a ping sweep is noise.
    --
    -- The scan-wide state is created first, without marking anything consulted:
    -- the prerule makes it on every run, so "there is no state at all" is not
    -- the case being tested and a version that only checked for that would pass
    -- while advertising to every ping sweep.
    t.reset_registry()
    local env = t.load_vulners({root = root, catalog = false})
    local shared = env._TEST.state()
    t.is_false(shared.consulted, "nothing was looked up")

    env.SCRIPT_TYPE = "postrule"
    local structured, text = env.action()

    t.is_nil(structured, "nothing to report")
    t.is_nil(text, "and nothing to say")
  end,
}

suite[#suite + 1] = {
  name = "a keyed scan with nothing to say says nothing at all",
  fn = function()
    -- Silence is the right output for a script with nothing to report. A keyed
    -- scan that worked has no advertisement to make and no failure to explain.
    local text = notice(function(shared) shared.mode = "keyed" end,
                        {token = "FAKE-NOTICE-KEY"})

    t.is_nil(text, "a working keyed scan must be silent, got: " .. tostring(text))
  end,
}

suite[#suite + 1] = {
  name = "a keyless scan says so, and where to get a key",
  fn = function()
    local text = notice()

    t.matches(text, "Ran without an API key")
    t.matches(text, "https://vulners%.com/userinfo")
    t.matches(text, "VULNERS_API_KEY", "and both ways to supply one")
    t.matches(text, "~/%.nmap/vulners%.key")
    -- What a key returns depends on the licence behind it, so naming a field
    -- would be a promise the script cannot keep.
    t.is_true(text:find("EPSS", 1, true) == nil,
      "the notice must not promise fields a licence may withhold")
  end,
}

suite[#suite + 1] = {
  name = "a key the service rejected is reported as such, not as no key",
  fn = function()
    -- An operator whose token expired has a different problem from one who
    -- never had a token, and only one of them needs to be told where to
    -- register.
    local text = notice(function(shared)
      shared.degraded = "the vulners key stopped working: the API answered 401"
    end)

    t.matches(text, "Ran without a usable API key")
    t.matches(text, "answered 401", "and the reason must survive into the notice")
    t.is_true(text:find("Ran without an API key", 1, true) == nil,
      "the two cases must not both be reported")
  end,
}

suite[#suite + 1] = {
  name = "a scan whose lookups all failed says nothing was checked",
  fn = function()
    -- The most dangerous silence in the script: a report with no findings
    -- because nothing was asked looks exactly like a report with no findings
    -- because nothing is wrong.
    local text = notice(function(shared)
      shared.free_stopped = "the API could not be reached"
    end)

    t.matches(text, "No vulnerability lookups were made")
    t.matches(text, "could not be reached", "with the reason")
    t.matches(text, "not a\n  report that the software is free of known problems",
      "and in as many words")
  end,
}

suite[#suite + 1] = {
  name = "a keyed scan whose lookups all failed says it too",
  fn = function()
    -- The keyed branch returns early, so this sentence had to be written twice
    -- and can be lost from one of them without the other noticing.
    local text = notice(function(shared)
      shared.mode = "keyed"
      shared.free_stopped = "the API rate-limited this scan"
    end, {token = "FAKE-NOTICE-KEY"})

    t.matches(text, "No vulnerability lookups were made")
    t.matches(text, "rate%-limited")
  end,
}

suite[#suite + 1] = {
  name = "services that showed a banner nobody could name are counted",
  fn = function()
    -- The one concrete argument for getting a key: this scan saw software it
    -- could not identify. Said only when it is true.
    local one = notice(function(shared) shared.unnamed = 1 end)
    local many = notice(function(shared) shared.unnamed = 4 end)
    local none = notice()

    t.matches(one, "1 service here showed a banner")
    t.matches(many, "4 services here showed a banner")
    t.is_true(none:find("showed a banner", 1, true) == nil,
      "a scan that named everything must not offer to name more")
  end,
}

suite[#suite + 1] = {
  name = "credits spent are reported, with what is left",
  fn = function()
    -- Reported before the mode is looked at: every path that stops the spending
    -- also drops the mode to free, so reporting the spend inside the keyed
    -- branch suppressed the number at exactly the moment it mattered.
    local text = notice(function(shared)
      shared.mode = "keyed"
      shared.spent = 3
      shared.balance = 97
    end, {token = "FAKE-NOTICE-KEY"})

    t.matches(text, "3 credits spent")
    t.matches(text, "97 remaining")
  end,
}

suite[#suite + 1] = {
  name = "one credit is spelled in the singular",
  fn = function()
    local text = notice(function(shared)
      shared.mode = "keyed"
      shared.spent = 1
    end, {token = "FAKE-NOTICE-KEY"})

    t.matches(text, "1 credit spent")
    t.is_true(text:find("credits", 1, true) == nil, "not '1 credits spent'")
    t.is_true(text:find("remaining", 1, true) == nil,
      "and a balance nobody told us is not invented")
  end,
}

suite[#suite + 1] = {
  name = "a spend that stopped early says why, and still reports the spend",
  fn = function()
    local text = notice(function(shared)
      shared.mode = "keyed"
      shared.spent = 2
      shared.billing_stopped = "the scan reached its vulners.max_items ceiling"
    end, {token = "FAKE-NOTICE-KEY"})

    t.matches(text, "2 credits spent")
    t.matches(text, "Identification stopped")
    t.matches(text, "max_items")
    t.matches(text, "Everything else ran normally",
      "a stopped ceiling must not read as a failed scan")
  end,
}

suite[#suite + 1] = {
  name = "a catalogue that did not load is said once, at the end",
  fn = function()
    -- Independent of the key: a scan can have a perfectly good token and still
    -- have done no web fingerprinting.
    local text = notice(function(shared)
      shared.catalog_note = "the catalogue is off (vulners.catalog=none), " ..
        "so no web fingerprinting was done"
    end)

    -- Matched in pieces: the note is wrapped to fit a terminal, so any phrase
    -- long enough to be worth asserting on may have a newline in it.
    t.matches(text, "no web fingerprinting")
    t.matches(text, "Ran without an API key",
      "and it must not replace what the notice already said")
  end,
}

suite[#suite + 1] = {
  name = "a keyed scan with nothing else to say still reports the catalogue",
  fn = function()
    -- The branch that returns silence. Losing the note here is how a keyed scan
    -- would fingerprint nothing and never mention it.
    local text = notice(function(shared)
      shared.mode = "keyed"
      shared.catalog_note = "the fingerprint catalogue could not be downloaded"
    end, {token = "FAKE-NOTICE-KEY"})

    t.is_true(text ~= nil, "a missing catalogue is never silent")
    t.matches(text, "could not be downloaded")
  end,
}

suite[#suite + 1] = {
  name = "the catalogue note is wrapped to a terminal, not sent as one line",
  fn = function()
    -- nmap does not wrap script output, so a sentence written as one string
    -- arrives as one line however wide the terminal is.
    local text = notice(function(shared)
      shared.catalog_note = "the fingerprint catalogue could not be " ..
        "downloaded, so no web fingerprinting was done; the software nmap " ..
        "itself identified was still looked up"
    end)

    local longest, line_count = 0, 0
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
      longest = math.max(longest, #line)
      line_count = line_count + 1
    end
    t.is_true(longest <= 78,
      string.format("no line may exceed a narrow terminal, longest is %d", longest))
    t.is_true(line_count > 1, "and the note must actually have been broken up")
  end,
}

suite[#suite + 1] = {
  name = "every line of the notice is indented under nmap's own prefix",
  fn = function()
    -- nmap prefixes the first line with "| vulners: " and the rest with "|_",
    -- so a line that starts at column zero does not line up with anything.
    local text = notice(function(shared)
      shared.unnamed = 2
      shared.catalog_note = "the catalogue is off (vulners.catalog=none)"
    end)

    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
      t.is_true(line == "" or line:sub(1, 2) == "  ",
        string.format("line %q must be indented", line))
    end
  end,
}

return suite
