--- A minimal script used by the harness's own tests.
--
-- It is deliberately not one of the scripts under test: the harness contract
-- it pins (module swapping, environment isolation, argument injection) has to
-- keep holding while those scripts are rewritten.
--
-- The flag is read with rawget() because NSE loads scripts into a strict
-- environment where reading an undeclared global raises - the same trap that
-- makes a file-scope read of SCRIPT_TYPE fatal.

local http = require "http"

if rawget(_ENV, "RAISE_ON_LOAD") then
  error("require_probe: deliberate failure")
end

description = "harness fixture"
categories = {"safe"}

portrule = function() return true end

action = function()
  return {module_seen = http}
end
