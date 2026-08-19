--- Tests for the rendered table.
--
-- The table is the release's headline feature and the part with the most edge
-- cases, because its width arithmetic has to hold for a 36-character exploit
-- UUID, a long title, several optional columns at once, and the narrowest width
-- the arguments allow - all while every byte stays inside what nmap's own
-- escape_for_screen() passes through.
--
-- These reach the renderer directly through _TEST rather than through action(),
-- because what is under test is the arithmetic, and driving it through a whole
-- scan would only make a failure harder to read.

local t, testdir, root = ...

local string = require "string"
local table = require "table"

-- nmap writes "| " in front of every line of script output, and the renderer
-- adds its own two-space indent inside that. A line that fits the configured
-- width has to fit it including both.
local NMAP_PREFIX = 2

local UUID = "3E6BA608-776F-5B1F-9BA5-589CD2A5A351"

local function load()
  return t.load_vulners({root = root})._TEST
end

--- One finding, with only the fields a case cares about.
local function finding(T, opts)
  return {
    id = opts.id or "CVE-2021-41773",
    type = opts.type or "cve",
    href = opts.href,
    cvss = opts.cvss,
    severity = T.severity_of(opts.cvss),
    epss = opts.epss,
    ai_score = opts.ai,
    title = opts.title,
    kev = opts.kev,
    exploit_known = opts.exploit,
    bucket = opts.bucket or 5,
  }
end

--- The widest line the terminal would actually show.
local function widest(text)
  local worst = 0
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    worst = math.max(worst, #line + NMAP_PREFIX)
  end
  return worst
end

--- The same, ignoring the last column.
--
-- The last column is the link, and a link is the one cell the layout may not
-- shorten: half a URL is not a URL. Every other column still has to fit the
-- width it was given, and that is what this measures. Columns are separated by
-- two spaces and no link contains one, so the final token is the link - or,
-- on the two heading lines, the word LINK and its rule.
local function widest_without_link(text)
  local worst = 0
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    worst = math.max(worst, #(line:gsub("%s%s%S+$", "")) + NMAP_PREFIX)
  end
  return worst
end

local suite = {}

suite[#suite + 1] = {
  name = "the table fits the width it was given, in every shape",
  fn = function()
    local T = load()
    local long_title = string.rep("Apache HTTP Server path traversal ", 5)

    local shapes = {
      {"everything at once", {
        finding(T, {id = UUID, cvss = 9.8, epss = 0.94, ai = 8.8,
                    title = long_title, kev = true, exploit = true}),
        finding(T, {id = "CVE-2021-34798", cvss = 7.5, epss = 0.003}),
      }},
      {"no epss, so the AI score takes its place", {
        finding(T, {id = UUID, cvss = 9.8, ai = 8.8, exploit = true}),
      }},
      {"nothing but an id", {finding(T, {id = "CVE-2021-1"})}},
      {"a long title and no room for it", {
        finding(T, {id = UUID, cvss = 9.8, epss = 0.5, title = long_title}),
      }},
    }

    for _, width in ipairs({40, 60, 80, 100, 200}) do
      for _, shape in ipairs(shapes) do
        local text = T.render_rows(shape[2], width, 1)
        local measured = widest_without_link(text)
        t.is_true(measured <= width, string.format(
          "%s at width %d rendered %d columns before the link",
          shape[1], width, measured))
        for _, row in ipairs(shape[2]) do
          local link = "https://vulners.com/cve/" .. row.id
          t.is_true(text:find(link, 1, true) ~= nil, string.format(
            "%s at width %d cut the link to %s", shape[1], width, row.id))
        end
      end
    end
  end,
}

suite[#suite + 1] = {
  name = "every row carries its vulners.com page, and never the upstream one",
  fn = function()
    local T = load()
    -- What the enrich endpoint really answers: href is the SOURCE, measured as
    -- web.nvd.nist.gov for a cve and www.exploit-db.com for an exploitdb entry.
    -- The table is a Vulners report and links to Vulners; the upstream address
    -- travels in the XML instead, under a name that says which it is.
    local rows = {
      finding(T, {id = "CVE-2021-40438", cvss = 9.8,
                  href = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-40438"}),
      finding(T, {id = "EDB-ID:45233", type = "exploitdb", cvss = 7.5,
                  href = "https://www.exploit-db.com/exploits/45233"}),
    }

    local text = T.render_rows(rows, 100, 1)
    t.is_true(text:find("https://vulners.com/cve/CVE-2021-40438", 1, true) ~= nil,
      "the cve row must link to its vulners page")
    t.is_true(text:find("https://vulners.com/exploitdb/EDB-ID:45233", 1, true) ~= nil,
      "the type is the path segment, so an exploit links to the exploit page")
    t.is_nil(text:match("nvd%.nist%.gov"), "the upstream link is not the report's")
    t.is_nil(text:match("exploit%-db%.com"), "nor is the exploit's own")
    t.matches(text, "LINK", "the column says what it holds")
    t.is_nil(text:match("  ID%f[%W]"), "and the bare id column is gone")
  end,
}

suite[#suite + 1] = {
  name = "a link is printed whole at every width, or it is not a link",
  fn = function()
    local T = load()
    local rows = {finding(T, {id = UUID, type = "githubexploit", cvss = 9.8,
                              epss = 0.94, kev = true, exploit = true})}
    local link = "https://vulners.com/githubexploit/" .. UUID

    for _, width in ipairs({40, 60, 80, 100, 200}) do
      local text = T.render_rows(rows, width, 1)
      t.is_true(text:find(link, 1, true) ~= nil,
        string.format("width %d cut a %d-character link", width, #link))
      t.is_nil(text:match("~"), "a clipped link would leave the clip mark")
    end
  end,
}

suite[#suite + 1] = {
  name = "-vv adds where an identity was found, and no second copy of the link",
  fn = function()
    local T = load()
    local rows = {finding(T, {id = "CVE-2021-41773", cvss = 9.8})}
    rows[1].found_on = "http://10.0.0.1:8080/CHANGELOG.txt"

    local quiet = T.render_rows(rows, 100, 1)
    t.is_nil(quiet:match("found on"), "provenance is a -vv detail, not a default")

    local loud = T.render_rows(rows, 100, 3)
    t.matches(loud, "found on http://10%.0%.0%.1:8080/CHANGELOG%.txt",
      "-vv says which request produced the identity")

    -- The link used to be printed here as well. It is a column now, so a second
    -- copy would be one line of noise per finding.
    local _, links = loud:gsub("https://vulners%.com/cve/CVE%-2021%-41773", "")
    t.equals(links, 1, "the link appears once, in its column")

    -- A row nobody swept has nothing to say, and says nothing.
    local bare = {finding(T, {id = "CVE-2021-34798", cvss = 7.5})}
    t.is_nil(T.render_rows(bare, 100, 3):match("found on"),
      "a row with no provenance must not print an empty line for it")
  end,
}

suite[#suite + 1] = {
  name = "the numeric column gives way exactly when that is what makes it fit",
  fn = function()
    local T = load()

    -- An id sized so that its link fits at 80 columns without the numeric
    -- column and not with it: 24 characters of "https://vulners.com/cve/" plus
    -- 23 is 47, and the room is 43 with EPSS and 49 without. The column
    -- carrying the least is the one that gives.
    local rows = {finding(T, {id = "CVE-2021-41773-0000-001", cvss = 9.8,
                              epss = 0.94, kev = true, exploit = true})}
    local squeeze = T.render_rows(rows, 80, 1)
    t.is_true(widest(squeeze) <= 80, "the 80-column table overflowed")
    t.is_nil(squeeze:match("EPSS"), "EPSS should be dropped, not squeezed")
    t.is_true(squeeze:find("KEV EXP", 1, true) ~= nil,
      "the flags are what the table is for and must survive")

    -- With room, it comes back.
    local wide = T.render_rows(rows, 100, 1)
    t.is_true(wide:find("EPSS", 1, true) ~= nil,
      "EPSS should be present when there is room for it")

    -- And a link that fits at neither width keeps it: dropping the column buys
    -- nothing there, and the operator loses a number for no gain.
    local long = {finding(T, {id = UUID, type = "githubexploit", cvss = 9.8,
                              epss = 0.94, kev = true, exploit = true})}
    local kept = T.render_rows(long, 80, 1)
    t.is_true(kept:find("EPSS", 1, true) ~= nil,
      "EPSS is kept when dropping it would not make the link fit")
  end,
}

suite[#suite + 1] = {
  name = "an EPSS that would round to zero is not shown as zero",
  fn = function()
    local T = load()
    local rows = {
      finding(T, {id = "CVE-2021-1", cvss = 9.8, epss = 0.00001}),
      finding(T, {id = "CVE-2021-2", cvss = 9.8, epss = 0.004}),
      finding(T, {id = "CVE-2021-3", cvss = 9.8, epss = 0.62}),
      finding(T, {id = "CVE-2021-4", cvss = 9.8, epss = 0.99992}),
    }
    local text = T.render_rows(rows, 80, 2)

    -- EPSS never reports zero, so a cell reading "0.0%" states something the
    -- data cannot: it is a rounding artefact that a reader takes as "no risk".
    t.is_nil(text:match("%f[%d]0%.0%%"),
      "a nonzero EPSS must never render as 0.0%: " .. text)
    t.is_true(text:find("<.1%", 1, true) ~= nil,
      "a negligible EPSS should render as a bound: " .. text)
    t.is_true(text:find("0.4%", 1, true) ~= nil, "0.004 should read as 0.4%")
    t.is_true(text:find("62%", 1, true) ~= nil, "0.62 should read as 62%")
    -- Bounded at the top for the same reason as the bottom: EPSS is a
    -- probability and never reaches 1, so "100%" asserts a certainty the model
    -- does not state.
    t.is_true(text:find(">99%", 1, true) ~= nil, "0.99992 should read as >99%")
    t.is_nil(text:match("100%%"), "and never as an even 100%")
  end,
}

suite[#suite + 1] = {
  name = "nothing outside printable ASCII, TAB and LF reaches the output",
  fn = function()
    local T = load()
    -- nmap's escape_for_screen() rewrites every other byte as the literal text
    -- \xHH, in the terminal, in -oN and in -oX alike - so a title arriving with
    -- a typographic quote would be displayed as \xE2\x80\x9C.
    local rows = {finding(T, {
      id = "CVE-2021-1", cvss = 9.8, epss = 0.5,
      title = "line\nbreak\ttab \226\128\156quoted\226\128\157 \1\2\3 caf\195\169",
    })}
    local text = T.render_rows(rows, 120, 3)

    local offending = text:find("[^\32-\126\n\t]")
    t.is_nil(offending, offending and string.format(
      "byte 0x%02X at %d survived into the output",
      text:byte(offending), offending) or nil)
  end,
}

suite[#suite + 1] = {
  name = "a format specifier in somebody else's data is not a format specifier",
  fn = function()
    local T = load()
    -- Every string here came from an HTTP response. If any of it reached a
    -- string.format as the format argument, this raises rather than renders.
    local rows = {finding(T, {
      id = "CVE-%s-%d", cvss = 9.8, epss = 0.5, title = "%s %d %q %%",
    })}
    local text = t.no_error(function()
      return T.render_rows(rows, 120, 3)
    end, "a title full of format specifiers")

    t.is_true(text:find("%s %d %q %%", 1, true) ~= nil,
      "the specifiers should appear literally: " .. text)
  end,
}

suite[#suite + 1] = {
  name = "the default verbosity is bounded, and says how much it is hiding",
  fn = function()
    local T = load()
    local rows = {}
    for index = 1, 40 do
      rows[index] = finding(T, {id = string.format("CVE-2021-%04d", index),
                                cvss = 9.8, bucket = 1})
    end

    -- A severity filter is not enough: one real Apache 2.4.7 answers with 272
    -- findings of which 24 are CRITICAL, so "HIGH and above" is still dozens of
    -- rows. The bound is what makes the ranking useful.
    local default_text = T.render_rows(rows, 80, 1)
    local shown = 0
    for _ in default_text:gmatch("CVE%-2021%-%d%d%d%d") do shown = shown + 1 end
    t.is_true(shown > 0 and shown <= 10,
      string.format("default verbosity showed %d rows", shown))
    t.is_true(default_text:find("more not shown", 1, true) ~= nil,
      "it must say how many it is not showing: " .. default_text)
    -- Not "ranked below these": the per-band cap deliberately hides rows that
    -- outrank ones it shows, so that wording stated the opposite of the truth.
    t.is_nil(default_text:match("ranked below these"),
      "and must not claim the hidden rows all rank lower")

    local verbose_text = T.render_rows(rows, 80, 2)
    local all = 0
    for _ in verbose_text:gmatch("CVE%-2021%-%d%d%d%d") do all = all + 1 end
    t.equals(all, 40, "-v shows every finding")
    t.is_nil(verbose_text:match("more not shown"),
      "and says nothing about hiding any")
  end,
}

suite[#suite + 1] = {
  name = "a column is absent rather than blank when its data never arrived",
  fn = function()
    local T = load()
    -- A blank EPSS cell asserts that the finding is quiet, which is a claim an
    -- absent field cannot support. The column has to go, not the value.
    local without = T.render_rows({finding(T, {cvss = 9.8})}, 80, 2)
    t.is_nil(without:match("EPSS"), "no EPSS column without EPSS data")
    t.is_nil(without:match("TITLE"), "no TITLE column without titles")

    local with = T.render_rows({finding(T, {cvss = 9.8, epss = 0.5})}, 80, 2)
    t.is_true(with:find("EPSS", 1, true) ~= nil, "the column follows the data")
  end,
}

suite[#suite + 1] = {
  name = "one ranking band cannot fill the whole summary",
  fn = function()
    local T = load()
    local rows = {}
    -- Twenty exploits, which rank above every CVE, and five CVEs below them.
    -- This is the live shape: without a token there is no cvelist, so an exploit
    -- can never be attributed to the CVE it exploits - every exploit sits in
    -- band 3 and every CVE in band 5.
    for index = 1, 20 do
      rows[#rows + 1] = finding(T, {id = string.format("EDB-ID:%d", index),
                                    cvss = 9.8, bucket = 3})
      rows[#rows].family = "exploit"
    end
    for index = 1, 5 do
      rows[#rows + 1] = finding(T, {id = string.format("CVE-2021-%04d", index),
                                    cvss = 9.8, bucket = 5})
    end

    local text = T.render_rows(rows, 80, 1)
    local exploits, cves = 0, 0
    for _ in text:gmatch("EDB%-ID:%d+") do exploits = exploits + 1 end
    for _ in text:gmatch("CVE%-2021%-%d%d%d%d") do cves = cves + 1 end

    t.is_true(cves > 0,
      "a summary of nothing but exploit ids names no problem a reader can act " ..
      "on: " .. text)
    t.is_true(exploits > 0, "and the exploits are still what leads: " .. text)
    t.is_true(exploits + cves <= 10, "the summary is still bounded: " .. text)

    -- The cap decides which rows are worth the summary, not what order they are
    -- read in: the exploits still come first.
    local first_cve = text:find("CVE%-2021")
    local last_exploit = 0
    for position in text:gmatch("()EDB%-ID:%d+") do last_exploit = position end
    t.is_true(last_exploit < first_cve,
      "rank order must survive the selection: " .. text)
  end,
}

suite[#suite + 1] = {
  name = "a score exactly on a band boundary takes the higher band",
  fn = function()
    -- Every fixture in this file uses 9.8, 8.5, 7.5 or 5.3, so none of them
    -- sits ON a boundary - and severity_of's ">=" could be turned into ">"
    -- with all 254 cases still green. That comparison decides the word in the
    -- table AND the "severity" element third parties index, so getting it
    -- wrong relabels every finding that lands exactly on a threshold.
    local T = load()

    t.equals(T.severity_of(9.0), "CRITICAL", "9.0 is the bottom of CRITICAL")
    t.equals(T.severity_of(7.0), "HIGH", "7.0 is the bottom of HIGH")
    t.equals(T.severity_of(4.0), "MEDIUM", "4.0 is the bottom of MEDIUM")
    t.equals(T.severity_of(0.1), "LOW", "and anything scored above zero is LOW")

    -- The value just below each boundary must fall to the band underneath, or
    -- the assertions above would also hold for a comparison that is too loose.
    t.equals(T.severity_of(8.9), "HIGH", "8.9 is not CRITICAL")
    t.equals(T.severity_of(6.9), "MEDIUM", "6.9 is not HIGH")
    t.equals(T.severity_of(3.9), "LOW", "3.9 is not MEDIUM")
  end,
}
return suite
