"""Run Lua patterns through a real Lua interpreter, in batches.

Nothing here reimplements Lua pattern matching. A reimplementation would be the
one component whose bugs are invisible - it would agree with the importer and
disagree with nmap, and the disagreement would only ever show up as a
fingerprint that silently stopped matching in the field.

The interpreter is spoken to over a pipe: a JSON array of jobs in, a JSON array
of captures out. `lua` on PATH is Lua 5.5 where nmap embeds 5.4, which for
`string.find` is the same engine; the authoritative re-check happens in the unit
suite, under nmap's own Lua, against the same recorded examples.
"""

import json
import shutil
import subprocess

LUA = shutil.which("lua") or shutil.which("lua5.4") or shutil.which("lua5.3")

# Reads jobs from stdin, writes one result row per job. A job is
# [pattern, subject]; the row is false when the pattern raised (an invalid
# pattern is a translator bug and must be visible, not silently unmatched),
# nil when it did not match, or the list of captures when it did.
DRIVER = r"""
local chunks = {}
for line in io.lines() do chunks[#chunks + 1] = line end
local text = table.concat(chunks, "\n")

-- A minimal JSON reader for the array-of-array-of-string shape written here.
local at = 1
local function skip()
  while true do
    local c = text:sub(at, at)
    if c == " " or c == "\n" or c == "\r" or c == "\t" then at = at + 1 else break end
  end
end
local function read_string()
  at = at + 1
  local out = {}
  while true do
    local c = text:sub(at, at)
    if c == '"' then at = at + 1 break end
    if c == "\\" then
      local e = text:sub(at + 1, at + 1)
      if e == "n" then out[#out+1] = "\n" at = at + 2
      elseif e == "r" then out[#out+1] = "\r" at = at + 2
      elseif e == "t" then out[#out+1] = "\t" at = at + 2
      elseif e == "b" then out[#out+1] = "\b" at = at + 2
      elseif e == "f" then out[#out+1] = "\f" at = at + 2
      elseif e == "u" then
        local hex = text:sub(at + 2, at + 5)
        local code = tonumber(hex, 16) or 63
        if code < 256 then out[#out+1] = string.char(code)
        else out[#out+1] = "?" end
        at = at + 6
      else out[#out+1] = e at = at + 2 end
    else
      out[#out+1] = c
      at = at + 1
    end
  end
  return table.concat(out)
end
local function read_array()
  at = at + 1
  local out = {}
  while true do
    skip()
    local c = text:sub(at, at)
    if c == "]" then at = at + 1 break end
    if c == "," then at = at + 1
    elseif c == "[" then out[#out+1] = read_array()
    elseif c == '"' then out[#out+1] = read_string()
    else error("unexpected " .. c .. " at " .. at) end
  end
  return out
end

skip()
local jobs = read_array()

local function quote(s)
  s = s:gsub('[\\"]', "\\%0"):gsub("\n", "\\n"):gsub("\r", "\\r")
  s = s:gsub("[%z\1-\31\127-\255]", function(c)
    return string.format("\\u%04x", string.byte(c))
  end)
  return '"' .. s .. '"'
end

local pieces = {}
for _, job in ipairs(jobs) do
  local pattern, subject = job[1], job[2]
  local ok, result = pcall(function()
    return {string.find(subject, pattern)}
  end)
  if not ok then
    pieces[#pieces + 1] = "false"
  elseif result[1] == nil then
    pieces[#pieces + 1] = "null"
  else
    local caps = {}
    for i = 3, #result do
      caps[#caps + 1] = quote(tostring(result[i]))
    end
    pieces[#pieces + 1] = "[" .. table.concat(caps, ",") .. "]"
  end
end
io.write("[", table.concat(pieces, ","), "]")
"""

# Sized so one interpreter start covers many jobs without building a command
# line or a pipe buffer large enough to deadlock.
BATCH = 4000


# Times one full scan of the subject the way the matcher does it - repeatedly,
# from just past each match - and reports seconds. Written separately from
# DRIVER because it must not build a capture list per match: the cost being
# measured is the pattern's, not the harness's.
TIMER = r"""
-- Both arguments arrive on stdin, separated by a NUL: a chunk given with -e
-- receives no varargs, so passing the pattern as a command-line argument
-- delivered nothing and every rule measured as instantaneous. A timing gate
-- that fails towards "fast" is worse than no gate, so this one raises instead.
local input = io.read("a")
local split = input:find("%z")
if not split then error("no NUL separator in input") end
local pattern = input:sub(1, split - 1)
local subject = input:sub(split + 1)

local started = os.clock()
local init = 1
while true do
  local from, to = subject:find(pattern, init)
  if not from then break end
  init = (to >= from) and to + 1 or from + 1
end
io.write(string.format("%.6f", os.clock() - started))
"""


class NoLua(Exception):
    """No Lua interpreter is available to check translations against."""


def time_pattern(pattern, subject, timeout=60):
    """Seconds one pattern spends scanning one subject, or None if it raised.

    Used to keep a quadratic pattern off the body channel. Lua patterns do not
    backtrack exponentially, but a lazy unanchored one restarts its scan at
    every occurrence, which is quadratic - and pattern matching does not yield,
    so the cost lands on the whole scan rather than on one script.
    """
    if LUA is None:
        raise NoLua("no lua interpreter on PATH")
    payload = (pattern + "\0" + subject).encode("latin-1", "replace")
    try:
        result = subprocess.run(
            [LUA, "-e", TIMER], input=payload,
            capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # It did not finish inside the timeout, which is the answer the caller
        # needs: this pattern is far past any budget worth having.
        return float(timeout)
    if result.returncode != 0:
        raise RuntimeError("timing %r failed: %s"
                           % (pattern[:60], result.stderr.decode()[:200]))
    return float(result.stdout.decode().strip())


def run(jobs):
    """Match each (pattern, subject) pair.

    @return list, one entry per job: False when the pattern raised, None when it
            did not match, or the list of captures when it did.
    """
    if LUA is None:
        raise NoLua("no lua interpreter on PATH; install lua to verify patterns")

    out = []
    for start in range(0, len(jobs), BATCH):
        chunk = [[pattern, subject] for pattern, subject in jobs[start:start + BATCH]]
        payload = json.dumps(chunk, ensure_ascii=True)
        result = subprocess.run(
            [LUA, "-e", DRIVER],
            input=payload, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("lua failed: %s" % result.stderr.strip()[:400])
        out.extend(json.loads(result.stdout))
    return out
