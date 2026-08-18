local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local os = require "os"

description = [[
Runs the nmap-vulners unit test suite inside nmap, so the scripts under test
see the real NSE libraries (json, stdnse, url, shortport) rather than
re-implementations that could drift from them.

Usage:
  nmap --script tests/run.nse [--script-args testdir=tests,root=.,filter=<pattern>] -sn -Pn 127.0.0.1

Exit status is non-zero when a test fails, which is what CI checks.
]]

author = "Vulners Team"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

prerule = function() return true end

--- Test files are listed explicitly: NSE has no directory listing, and an
-- explicit manifest also fails loudly when a file is renamed but not wired up.
local TEST_FILES = {
  "test_regex_data.lua",
  "test_http_vulners_regex.lua",
  "test_vulners.lua",
  "test_vulners_enterprise.lua",
}

local function describe_error(err)
  if type(err) == "table" and err.harness_failure then
    return err.harness_failure, true
  end
  return tostring(err), false
end

---
-- Everything the run needs before the first case can execute.
--
-- Kept apart from action() so that failing to get this far - a harness that was
-- renamed, moved or broken - ends the process with a non-zero status instead of
-- being swallowed by NSE, which prints "Script execution failed" and lets nmap
-- exit 0. A gate that cannot run has to be as loud as a gate that fails.
--
local function load_harness(testdir)
  local ok, harness = pcall(dofile, testdir .. "/lib/harness.lua")

  if not ok or type(harness) ~= "table" then
    print(string.format("FAIL  the test harness could not be loaded: %s",
      tostring(harness)))
    print("SUITE FAILED")
    os.exit(1)
  end

  return harness
end


action = function()
  local testdir = stdnse.get_script_args("testdir") or "tests"
  local root = stdnse.get_script_args("root") or (testdir .. "/..")
  local filter = stdnse.get_script_args("filter")
  local verbose = stdnse.get_script_args("verbose")

  local harness = load_harness(testdir)
  local results = {}
  local passed, failed, skipped = 0, 0, 0

  for _, filename in ipairs(TEST_FILES) do
    local path = testdir .. "/" .. filename
    local chunk, load_err = loadfile(path)

    if not chunk then
      failed = failed + 1
      results[#results + 1] = string.format("FAIL  %s  (cannot load: %s)",
        filename, tostring(load_err))
      goto next_file
    end

    do
      local ok, suite = pcall(chunk, harness, testdir, root)
      if not ok then
        failed = failed + 1
        local msg = describe_error(suite)
        results[#results + 1] = string.format("FAIL  %s  (error while building suite: %s)",
          filename, msg)
        goto next_file
      end

      for _, case in ipairs(suite) do
        local label = string.format("%s :: %s", filename:gsub("%.lua$", ""), case.name)
        if filter and not label:find(filter) then
          skipped = skipped + 1
        else
          harness.reset_registry()
          local case_ok, case_err = pcall(case.fn, harness)
          harness.restore_script_args()
          harness.reset_registry()
          if case_ok then
            passed = passed + 1
            if verbose then
              results[#results + 1] = "ok    " .. label
            end
          else
            failed = failed + 1
            local msg, expected = describe_error(case_err)
            results[#results + 1] = string.format("FAIL  %s\n        %s%s",
              label, msg, expected and "" or "  [unexpected Lua error]")
          end
        end
      end
    end

    ::next_file::
  end

  local summary = string.format("%d passed, %d failed%s",
    passed, failed, skipped > 0 and string.format(", %d skipped", skipped) or "")
  results[#results + 1] = summary
  results[#results + 1] = failed == 0 and "SUITE OK" or "SUITE FAILED"

  print(table.concat(results, "\n"))

  if failed > 0 then
    os.exit(1)
  end

  return summary
end
