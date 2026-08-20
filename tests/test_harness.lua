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

suite[#suite + 1] = {
  name = "an unreachable server is modelled the way nselib models it",
  fn = function()
    -- nselib builds this in http_error (http.lua:1208-1220) and sets body and
    -- rawbody to NIL, not to "". The double returned "" for both, so every
    -- "the server could not be reached" case ran against a string: an `or ""`
    -- dropped anywhere on a failure path stayed green here while a real scan
    -- raised, and nmap answers a raising script by discarding every finding
    -- the port had.
    local failed = t.response({})

    t.is_nil(failed.status, "a failure carries no status")
    t.is_nil(failed.body, "and no body, exactly as http_error leaves it")
    t.is_nil(failed.rawbody, "and no rawbody")
    t.same(failed.header, {}, "the header table is empty, not absent")
    t.same(failed.rawheader, {}, "and so is rawheader")
  end,
}

suite[#suite + 1] = {
  name = "a header the fixture spells in capitals arrives lowercased",
  fn = function()
    -- nselib lowercases every response header name unconditionally
    -- (http.lua:769), so response.header in the field NEVER carries a capital.
    -- A double that kept the fixture spelling let a case pass {["Server"]=...}
    -- and believe it had exercised hdr:server when the match really came
    -- through raw - and would equally have "proved" a rule filed as
    -- hdr:Server, which is dead in every real scan.
    local answered = t.response({status = 200,
      header = {["Server"] = "nginx/1.13.4", ["X-Powered-By"] = "PHP/8.2"}})

    t.equals(answered.header["server"], "nginx/1.13.4",
      "the lowercase key is the one a rule can reach")
    t.is_nil(answered.header["Server"],
      "and the fixture's spelling must not survive alongside it")
    t.equals(answered.header["x-powered-by"], "PHP/8.2")
  end,
}

suite[#suite + 1] = {
  name = "the raw header block is built in a stable order",
  fn = function()
    -- Lua seeds its string hash per process, so building rawheader with
    -- pairs() gave a different raw channel on every nmap run - measured, five
    -- distinct orders across six runs of one fixture. The raw channel is
    -- table.concat(rawheader, "\n"), so a rule spanning two header lines
    -- passed or failed by hash seed, which is the worst kind of green.
    local answered = t.response({status = 200, header = {
      ["Server"] = "nginx", ["X-Powered-By"] = "PHP",
      ["Content-Type"] = "text/html",
      ["Set-Cookie"] = "a=1", ["X-Generator"] = "Drupal",
    }})

    t.same(answered.rawheader, {
      "Content-Type: text/html",
      "Server: nginx",
      "Set-Cookie: a=1",
      "X-Generator: Drupal",
      "X-Powered-By: PHP",
      "",
    }, "sorted, and ended by the blank line nselib always leaves there")
  end,
}

suite[#suite + 1] = {
  name = "two spellings of one header name are joined, not overwritten",
  fn = function()
    -- nselib folds repeated headers with ", " (http.lua:771-776). The double
    -- let the last writer win, and which one that was depended on the hash
    -- seed. Two Set-Cookie lines is the commonest real response there is.
    local answered = t.response({status = 200,
      header = {["Set-Cookie"] = "a=1", ["set-cookie"] = "b=2"}})

    t.equals(answered.header["set-cookie"], "a=1, b=2",
      "both values survive, in a stable order")
  end,
}

return suite
