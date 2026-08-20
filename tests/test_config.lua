--- Tests for the Config seam: the key, and what the numbers do.
--
-- Almost nothing here is visible in a report, which is why it is worth a file
-- of its own. A key discovered from the wrong place is a scan that silently
-- takes the free path; a key file read without trimming is a 401 the operator
-- cannot explain; a width that arrives as a fraction reaches string.rep, which
-- demands an integer and raises - and nmap turns a raised script into "Script
-- execution failed", losing every finding on that port.
--
-- The environment, the filesystem and nmap's own datadir lookup are all faked,
-- so no case here can read the developer's real key.

local t, testdir, root = ...

local string = require "string"

local KEY = "FAKE-CONFIG-KEY-NOT-A-REAL-TOKEN"
local OTHER = "SECOND-FAKE-KEY-NOT-A-REAL-TOKEN"

--; Load the script and hand back its resolved configuration.
local function config_of(opts)
  opts = opts or {}
  local env = t.load_vulners({
    root = root,
    catalog = false,
    token = opts.token,
    args = opts.args,
    env = opts.env,
    files = opts.files,
    nmap = opts.nmap,
  })
  return env._TEST.config(), env
end

local suite = {}

-- ----------------------------------------------------------- where the key

suite[#suite + 1] = {
  name = "the key can be given on the command line",
  fn = function()
    -- Documented in the README and in @args, and until now never exercised:
    -- every other case reached the keyed path through the environment.
    local cfg = config_of({args = {["vulners.api_key"] = KEY}})

    t.equals(cfg.key, KEY, "the argument must be the key")
    t.equals(cfg.key_source, "script argument",
      "and it must say where it came from")
  end,
}

suite[#suite + 1] = {
  name = "a key on the command line beats one in the environment",
  fn = function()
    -- The order is the order of how explicit the operator was, and an argument
    -- is as explicit as it gets. Getting this backwards would send the wrong
    -- token on a machine where VULNERS_API_KEY happens to be exported.
    local cfg = config_of({
      args = {["vulners.api_key"] = KEY},
      env = {VULNERS_API_KEY = OTHER},
    })

    t.equals(cfg.key, KEY, "the argument wins")
  end,
}

suite[#suite + 1] = {
  name = "the 1.x argument name still works and says it is deprecated",
  fn = function()
    -- stdnse.get_script_args(a, b) returns one value PER NAME, so a
    -- compatibility layer written the obvious way silently ignores the old
    -- name. This is the case that would catch it going back.
    local logger = t.stdnse_double()
    local env = t.load_script(root .. "/vulners.nse", {
      args = {["vulners_enterprise.api_key"] = KEY,
              ["vulners.paths"] = "none"},
      modules = {
        http = t.http_double(),
        nmap = t.nmap_double(),
        os = t.os_double({}),
        io = t.io_double(),
        stdnse = logger,
      },
    })

    t.equals(env._TEST.config().key, KEY,
      "the 1.x name must still be honoured")
    t.matches(logger.log(), "deprecated",
      "and the operator must be told to move to the new one")
  end,
}

suite[#suite + 1] = {
  name = "the deprecation notice is printed once for the scan, not once " ..
    "per port",
  fn = function()
    -- The chunk is re-executed for every open port and config() re-reads every
    -- argument each time, so advice about a renamed argument was repeated once
    -- per port. The registry is what survives between those executions, which
    -- is why two loads sharing one registry is the shape of this case.
    t.reset_registry()
    local logger = t.stdnse_double()

    local function load_a_port()
      local env = t.load_script(root .. "/vulners.nse", {
        args = {["vulners_enterprise.api_key"] = KEY,
                ["vulners.paths"] = "none"},
        modules = {
          http = t.http_double(),
          nmap = t.nmap_double(),
          os = t.os_double({}),
          io = t.io_double(),
          stdnse = logger,
        },
      })
      env._TEST.config()
    end

    load_a_port()
    load_a_port()
    load_a_port()

    local said = 0
    for _ in logger.log():gmatch("is deprecated") do said = said + 1 end
    t.equals(said, 1, "three ports, one notice")
  end,
}

suite[#suite + 1] = {
  name = "a named key file beats the environment",
  fn = function()
    local path = "/etc/nmap/named.key"
    local cfg = config_of({
      args = {["vulners.api_key_file"] = path},
      env = {VULNERS_API_KEY = OTHER},
      files = {[path] = KEY .. "\n"},
    })

    t.equals(cfg.key, KEY,
      "the file the operator named is the one that counts")
    t.equals(cfg.key_source, "api_key_file", "and it must say so")
  end,
}

suite[#suite + 1] = {
  name = "a key file written on Windows arrives without its carriage return",
  fn = function()
    -- The service answers a key with a trailing CR with 401, and a 401 used to
    -- silence the script for the whole scan with nothing to say why. Editing
    -- the key file on Windows is the ordinary way to arrive at one.
    local path = "/etc/nmap/crlf.key"
    local cfg = config_of({
      args = {["vulners.api_key_file"] = path},
      files = {[path] = "  " .. KEY .. "\r\n"},
    })

    t.equals(cfg.key, KEY, "the key must be trimmed of whitespace and the CR")
  end,
}

suite[#suite + 1] = {
  name = "a named key file that is unusable is fatal, and says which and why",
  fn = function()
    -- An operator who NAMES a file means that file: falling back to the free
    -- path would hide a typo in the path for a whole scan. Each shape is
    -- refused by a different branch, so each is a way to ship a broken one.
    for _, case in ipairs({
      {"", "is empty"},
      {"\n", "is blank"},
      {"   \n", "is blank"},
      {"key\1with\1control\n", "control character"},
    }) do
      local path = "/etc/nmap/bad.key"
      local cfg = config_of({
        args = {["vulners.api_key_file"] = path},
        files = {[path] = case[1]},
      })

      t.is_nil(cfg.key, string.format("%q must not become a key", case[1]))
      t.is_true(cfg.fatal ~= nil and cfg.fatal:find(case[2], 1, true) ~= nil,
        string.format("%q must be refused as %s, got: %s",
          case[1], case[2], tostring(cfg.fatal)))
      t.is_true(cfg.fatal:find(path, 1, true) ~= nil,
        "and the message must name the file")
    end
  end,
}

suite[#suite + 1] = {
  name = "nmap's own datadir lookup finds the key when nothing names one",
  fn = function()
    -- fetchfile is what honours --datadir, $NMAPDIR and %APPDATA%\nmap, which
    -- is how a Windows install is expected to carry its key. Nothing else in
    -- the suite exercises it, so this is the only thing standing between that
    -- path and a silent removal.
    local found = "/opt/nmap/share/vulners.key"
    local cfg = config_of({
      nmap = t.nmap_double({fetchfile = function(name)
        return name == "vulners.key" and found or nil
      end}),
      files = {[found] = KEY .. "\n"},
    })

    t.equals(cfg.key, KEY, "a key in nmap's data directory must be picked up")
    t.equals(cfg.key_source, found,
      "and the report must name where it was found")
  end,
}

suite[#suite + 1] = {
  name = "~/.nmap/vulners.key is the last resort",
  fn = function()
    local cfg = config_of({
      env = {HOME = "/home/tester"},
      files = {["/home/tester/.nmap/vulners.key"] = KEY .. "\n"},
    })

    t.equals(cfg.key, KEY, "the documented place must work")
    t.matches(cfg.key_source, "vulners%.key", "and be named in the report")
  end,
}

suite[#suite + 1] = {
  name = "no key anywhere is not an error",
  fn = function()
    -- The whole free path depends on this staying quiet: a missing key is the
    -- ordinary case, not a misconfiguration.
    local cfg = config_of({env = {HOME = "/home/tester"}})

    t.is_nil(cfg.key, "there is no key to find")
    t.is_nil(cfg.fatal, "and that is not fatal")
  end,
}

-- --------------------------------------------------------------- the numbers

suite[#suite + 1] = {
  name = "a fractional width is floored rather than carried into the " ..
    "arithmetic",
  fn = function()
    -- string.rep demands an integer, so a width of 80.5 propagated a fraction
    -- into the column arithmetic and raised inside action() - which nmap turns
    -- into "Script execution failed", losing every finding for that port in
    -- both the text and the XML.
    local cfg = config_of({args = {["vulners.width"] = "80.5"}})

    t.equals(cfg.width, 80, "the width must be a whole number of columns")
    t.no_error(function() return string.rep("-", cfg.width) end,
      "and must be usable where the renderer uses it")
  end,
}

suite[#suite + 1] = {
  name = "a width below the floor is clamped, not honoured",
  fn = function()
    -- The narrowest table the renderer can lay out is 40 columns. Honouring a
    -- smaller number would not make the output narrower, it would make the
    -- column arithmetic go negative.
    t.equals(config_of({args = {["vulners.width"] = "10"}}).width, 40,
      "a width under the floor must become the floor")
    t.equals(config_of({args = {["vulners.width"] = "0"}}).width, 40,
      "and so must zero")
    t.equals(config_of({args = {["vulners.width"] = "-100"}}).width, 40,
      "and so must a negative one")
  end,
}

suite[#suite + 1] = {
  name = "a width that is not a number falls back to the default",
  fn = function()
    local given = config_of({args = {["vulners.width"] = "wide"}}).width
    local default = config_of({}).width

    t.equals(given, default, "nonsense must not become a width")
    t.is_true(default >= 40, "and the default must be usable")
  end,
}

suite[#suite + 1] = {
  name = "the mirror URL is normalised once, not on every use",
  fn = function()
    local plain =
      config_of({args = {["vulners.catalog_url"] = "http://m/cat"}})
    t.equals(plain.catalog_url,
      "http://m/cat/", "a missing trailing slash is added")
    local slashed =
      config_of({args = {["vulners.catalog_url"] = "http://m/cat/"}})
    t.equals(slashed.catalog_url,
      "http://m/cat/", "and one that is there is left alone")
  end,
}

suite[#suite + 1] = {
  name = "the configuration is resolved once per chunk",
  fn = function()
    -- The chunk re-executes once per open port and config() is called from
    -- several places in each. Re-reading the key file per call would be a file
    -- read per port per call, and re-running its side effects is what once
    -- resurrected a key the service had already rejected.
    local path = "/etc/nmap/once.key"
    local cfg, env = config_of({
      args = {["vulners.api_key_file"] = path},
      files = {[path] = KEY .. "\n"},
    })

    t.is_true(cfg == env._TEST.config(), "the same table must come back")
  end,
}

return suite
