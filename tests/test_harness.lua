--- Tests for tests/lib/harness.lua itself.
--
-- The harness is the only thing every other suite trusts without checking, so
-- the guarantees it makes are pinned here: a script loaded through it must not
-- leave anything behind for the next case. A leak here is invisible where it
-- happens and shows up as an unrelated failure somewhere else.

local t, testdir, root = ...

-- Loading it here means package.loaded["http"] is populated before the first
-- case runs, so "restored to what it was" is a deterministic statement.
require "http"

local FIXTURE = testdir .. "/fixtures/require_probe.nse"

local suite = {}

suite[#suite + 1] = {
  name = "load_script puts a swapped module back exactly as it found it",
  fn = function()
    local before = package.loaded["http"]
    t.is_true(before ~= nil, "the real http library is loaded before the test")
    t.is_true(type(before) == "table" and before.get ~= nil,
      "and it is the library itself, not a leftover wrapper")

    t.load_script(FIXTURE, {modules = {http = t.http_double()}})

    t.equals(package.loaded["http"], before,
      "package.loaded.http must be the original library, not a wrapper")
  end,
}

suite[#suite + 1] = {
  name = "load_script removes a module that was not loaded before",
  fn = function()
    local MODULE = "harness_probe_absent"
    package.loaded[MODULE] = nil

    t.load_script(FIXTURE, {modules = {[MODULE] = {}}})

    t.is_nil(package.loaded[MODULE],
      "a module the process never had must not exist afterwards")
  end,
}

suite[#suite + 1] = {
  name = "load_script restores modules even when the chunk raises",
  fn = function()
    local before = package.loaded["http"]

    t.raises(function()
      t.load_script(FIXTURE, {
        modules = {http = t.http_double()},
        env = {RAISE_ON_LOAD = true},
      })
    end, "a chunk that raises is reported as a failure")

    t.equals(package.loaded["http"], before,
      "the failure path restores package.loaded too")
  end,
}

suite[#suite + 1] = {
  name = "a script sees the module double rather than the real library",
  fn = function()
    local double = t.http_double()
    local env = t.load_script(FIXTURE, {modules = {http = double}})

    t.equals(env.action().module_seen, double,
      "require() inside the script resolves to the double")
  end,
}

return suite
