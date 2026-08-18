--- Validation of http-vulners-regex.json.
--
-- The file is pure data, so nothing but a test protects it. Every rule here
-- encodes an assumption that http-vulners-regex.nse actually relies on:
-- get_cpes() does `_, _, vers = field:find(pattern.regex)` and then builds
-- `pattern.alias .. ":" .. vers`, so a pattern without exactly one capture
-- can never produce a CPE, and a malformed alias produces a malformed CPE.

local t, testdir, root = ...

local json = require "json"
local string = require "string"
local table = require "table"

local DATA_FILE = root .. "/http-vulners-regex.json"

--- Read and parse the shipped pattern file with nmap's own json library.
local function load_patterns()
  local file = io.open(DATA_FILE, "r")
  t.is_true(file, "http-vulners-regex.json must be readable at " .. DATA_FILE)
  local contents = file:read("*all")
  file:close()

  local ok, parsed = json.parse(contents)
  t.is_true(ok, "http-vulners-regex.json must be valid JSON for nmap's json library")
  return parsed
end

--- Count Lua capture groups, i.e. '(' that is not escaped with '%'
-- and not the position-capture '()'.
local function count_captures(pattern)
  local count, i = 0, 1
  while i <= #pattern do
    local c = pattern:sub(i, i)
    if c == "%" then
      i = i + 2
    else
      if c == "(" then count = count + 1 end
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

local suite = {}

suite[#suite + 1] = {
  name = "file parses with nmap's json library and is non-empty",
  fn = function()
    local patterns = load_patterns()
    t.equals(type(patterns), "table", "parsed patterns must be a table")
    local count = 0
    for _ in pairs(patterns) do count = count + 1 end
    t.is_true(count > 100, "expected the full pattern set, got " .. count .. " entries")
  end,
}

suite[#suite + 1] = {
  name = "every entry has exactly the alias and regex keys",
  fn = function()
    local patterns = load_patterns()
    for _, name in ipairs(sorted_names(patterns)) do
      local entry = patterns[name]
      t.equals(type(entry), "table", name .. ": entry must be an object")
      t.equals(type(entry.alias), "string", name .. ": alias must be a string")
      t.equals(type(entry.regex), "string", name .. ": regex must be a string")
      for key in pairs(entry) do
        if key ~= "alias" and key ~= "regex" then
          t.fail(string.format("%s: unexpected key %q", name, key))
        end
      end
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
  name = "patterns match the banners they were written for",
  fn = function()
    local patterns = load_patterns()

    -- A pattern can be structurally valid and still never match anything, so a
    -- handful of well known banners are checked against their entry.
    local samples = {
      {name = "Nginx, headers_0_0", text = "Server: nginx/1.13.4", version = "1.13.4"},
      {name = "PHP, headers_0_0", text = "X-Powered-By: PHP/5.6.38", version = "5.6.38"},
      {name = "Jenkins, headers", text = "X-Jenkins: 2.121.1", version = "2.121.1"},
      {name = "lighttpd, headers_1_0", text = "Server: lighttpd/1.4.45", version = "1.4.45"},
      {name = "Kibana, headers", text = "kbn-version: 6.4.2", version = "6.4.2"},
      {name = "Apache httpd, headers", text = "Server: Apache/2.4.7 (Ubuntu)",
       version = "2.4.7"},
      {name = "WordPress, html",
       text = '<meta name="generator" content="WordPress 6.4" />',
       version = "6.4"},
      {name = "Jetty, headers", text = "Server: Jetty(9.4.51.v20230217)",
       version = "9.4.51"},
      {name = "Linux, headers", text = "Server: Apache/2.2.15 (Linux 3.10.0-1160)",
       version = "3.10.0-1160"},
      {name = "Bugzilla, html",
       text = '<span id="information" class="header_addl_info">version 5.0.4</span>',
       version = "5.0.4"},
      {name = "WooCommerce, html_0_0_0",
       text = "<link rel='stylesheet' id='woocommerce-layout-css'  href='https://s.example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=3.5.1' type='text/css' />",
       version = "3.5.1"},
      {name = "WooCommerce, html_0_0_1",
       text = "<link rel='stylesheet' id='woocommerce-smallscreen-css'  href='https://s.example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=3.5.1' type='text/css' />",
       version = "3.5.1"},
      {name = "WooCommerce, html_0_0_2",
       text = "<link rel='stylesheet' id='woocommerce-general-css'  href='https://s.example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=3.5.1' type='text/css' />",
       version = "3.5.1"},
    }

    for _, sample in ipairs(samples) do
      local entry = patterns[sample.name]
      t.is_true(entry, "missing pattern: " .. sample.name)
      local _, _, captured = sample.text:find(entry.regex)
      t.equals(captured, sample.version,
        string.format("%s must extract the version from %q", sample.name, sample.text))
    end
  end,
}

suite[#suite + 1] = {
  name = "no two entries share the same name and pattern",
  fn = function()
    local patterns = load_patterns()
    local seen = {}
    for _, name in ipairs(sorted_names(patterns)) do
      local key = patterns[name].alias .. "|" .. patterns[name].regex
      t.is_nil(seen[key], string.format("%s duplicates %s", name, tostring(seen[key])))
      seen[key] = name
    end
  end,
}

return suite
