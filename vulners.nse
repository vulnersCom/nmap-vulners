description = [[
For each availible cpe it prints the known vulns (links to the correspondent info).

Its work is pretty simple:
- work only when some software version is identified for an open port
- take all the known cpe for that software (from the standard nmap output)
- ask whether some known vulns exist for that cpe
- print that info out
]]

---
-- @usage 
-- nmap -sV --script vulners <target>
--
-- @output
--
-- 22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
-- | vulners:
-- |   cpe:/a:openbsd:openssh:6.7p1:
-- |     CVE-2016-8858        https://vulners.com/cve/CVE-2016-8858
-- |     CVE-2016-0777        https://vulners.com/cve/CVE-2016-0777
-- |     CVE-2017-15906       https://vulners.com/cve/CVE-2017-15906
-- |_    CVE-2016-0778        https://vulners.com/cve/CVE-2016-0778 
--

author = 'gmedian AT vulners DOT com'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


local http = require "http"
local json = require "json"
local string = require "string"

local api_version="1.0"


portrule = function(host, port)
        local vers=port.version
        return vers ~= nil and vers.version ~= nil
end

---
-- Return a string with all the found cve's and correspondent links
-- 
-- @param vulns a table with the parsed json response from the vulners server 
--
function make_links(vulns)
    local output_str=""

    for _, vuln in ipairs(vulns.data.search) do
        output_str = string.format("%s\n\t%s", output_str, vuln._source.id .. '\t\thttps://vulners.com/' .. vuln._source.type .. '/' .. vuln._source.id)
    end

    return output_str
end


---
-- Issues the requests, receives json and parses it, calls <code>make_links</code> when successfull
--
-- @param what String, future value for the software query argument
-- @param vers string, the version query argument
-- @param type string, the type query argument
--
function get_results(what, vers, type)
    local v_host="vulners.com"
    local v_port=443 
    local response, path
    local status, vulns
    local option={header={}}

    option['header']['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)

    path = '/api/v3/burp/software/' .. '?software=' .. what .. '&version=' .. vers .. '&type=' .. type

    response = http.get(v_host, v_port, path, option)
    status, vulns = json.parse(response.body)

    if status == true then
        if vulns.result == "OK" then
            return make_links(vulns)
        end
    end

    return ""
end


---
-- Calls <code>get_results</code> for type="software"
-- 
-- It is called from <code>action</code> when nothing is found for the availible cpe's 
--
-- @param software string, the software name
-- @param version string, the software version
--
function get_vulns_by_software(software, version)
    return get_results(software, version, "software")
end


---
-- Calls <code>get_results</code> for type="cpe"
-- 
-- Takes the version number from the given <code>cpe</code> and tries to get the result.
-- If none found, changes the given <code>cpe</code> a bit in order to possibly separate version number from the patch version
-- And makes another attempt.
-- Having failed returns an empty string.
--
-- @param cpe string, the given cpe
--
function get_vulns_by_cpe(cpe)
    local vers
    local vers_regexp=":([%d%.%-%_]+)([^:]*)$"
    local output_str=""
    
    -- TODO[gmedian]: add check for cpe:/a  as we might be interested in software rather than in OS (cpe:/o) and hardware (cpe:/h)
	-- TODO[gmedian]: work not with the LAST part but simply with the THIRD one (according to cpe doc it must be version)

    -- NOTE[gmedian]: take just the numeric part of the version
    _, _, vers = cpe:find(vers_regexp)


    if not vers then
        return ""
    end

    output_str = get_results(cpe, vers, "cpe")

    if output_str == "" then
        local new_cpe

        new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
        output_str = get_results(new_cpe, vers, "cpe")
    end
    
    return output_str
end


action = function(host, port)
        local tab={}
        local changed=false
        local response
        local output_str=""

        for i, cpe in ipairs(port.version.cpe) do 
            output_str = get_vulns_by_cpe(cpe, port.version)
            if output_str ~= "" then
                tab[cpe] = output_str
                changed = true
            end
        end

        -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
        if not changed then
            local vendor_version = port.version.product .. " " .. port.version.version
            output_str = get_vulns_by_software(port.version.product, port.version.version)
            if output_str ~= "" then
                tab[vendor_version] = output_str
                changed = true
            end
        end
        
        if (not changed) then
            return
        end
        return tab
end

