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

author = 'gmedian at somewhere else'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


local http = require "http"
local json = require "json"
local string = require "string"

local api_version="0.1"


portrule = function(host, port)
        local vers=port.version
        return vers ~= nil and vers.version ~= nil
end


function make_links(vulns)
    local output_str=""

    for _, vuln in ipairs(vulns.data.search) do
        output_str = string.format("%s\n\t%s", output_str, vuln._source.id .. '\t\thttps://vulners.com/' .. vuln._source.type .. '/' .. vuln._source.id)
    end

    return output_str
end


function get_results(cpe, vers)
    local v_host="vulners.com"
    local v_port=443 
    local response, path
    local status, vulns
    local option={header={}}

    option['header']['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)

    -- NOTE[gmedian]: add quotes to version so that it is always a string for the backend
    path = '/api/v3/burp/software/' .. '?software=' .. cpe .. '&version="' .. vers .. '"&type=cpe'

    response = http.get(v_host, v_port, path, option)
    status, vulns = json.parse(response.body)

    if status == true then
        if vulns.result == "OK" then
            return make_links(vulns)
        end
    end

    return ""
end


function get_vulns(cpe, version)
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

    output_str = get_results(cpe, vers)

    if output_str == "" then
        local new_cpe

        new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
        output_str = get_results(new_cpe, vers)
    end
    
    return output_str
end


action = function(host, port)
        local tab={}
        local changed=false
        local response
        local output_str=""

        for i, cpe in ipairs(port.version.cpe) do 
            output_str = get_vulns(cpe, port.version.version)
            if output_str ~= "" then
                tab[cpe] = output_str
                changed = true
            end
        end

        if (not changed) then
            return
        end
        return tab
end

