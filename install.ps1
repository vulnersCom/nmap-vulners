<#
.SYNOPSIS
    Install the nmap-vulners scripts where the local nmap will find them.

.DESCRIPTION
    Copies vulners.nse into nmap's own script directory and rebuilds the
    script database. An existing copy is replaced: nmap ships a vulners.nse of
    its own, and leaving it in place means nmap keeps running that one.

    2.0 is a single file that downloads its dictionaries at scan time. The
    three files of 1.x are
    removed if they are found, because a leftover http-vulners-regex.nse still
    carries the "default" category and keeps sweeping targets under a plain
    -sC.

.PARAMETER User
    Install into %APPDATA%\nmap instead of the nmap program directory, which
    needs no administrator rights. nmap finds scripts there only when NMAPDIR
    points at it; the script prints the command to set that.

.PARAMETER Prefix
    Install into this directory instead of the one nmap reports.

.PARAMETER Ref
    Download this branch or tag instead of master (used when the script is run
    on its own, outside a checkout).

.PARAMETER Uninstall
    Remove the files this script installs, and any 1.x files beside them.

.PARAMETER NoKey
    Do not offer to store an API key.

.EXAMPLE
    .\install.ps1
    Installs system-wide. Run PowerShell as Administrator.

.EXAMPLE
    irm https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.ps1 | iex
    Installs without a checkout.

.EXAMPLE
    .\install.ps1 -User
    Installs into %APPDATA%\nmap, no administrator rights needed.
#>

[CmdletBinding()]
param(
    [switch]$User,
    [string]$Prefix,
    [string]$Ref = "master",
    [switch]$Uninstall,
    [switch]$NoKey
)

$ErrorActionPreference = "Stop"

$RepoRaw  = "https://raw.githubusercontent.com/vulnersCom/nmap-vulners"
$Scripts  = @("vulners.nse")
$DataFiles = @()
$LegacyScripts = @("http-vulners-regex.nse", "vulners_enterprise.nse")
$LegacyData    = @("http-vulners-regex.json", "http-vulners-paths.txt")

function Remove-LegacyFiles {
    param([string]$ScriptDir, [string]$DataSubDir)
    $removed = @()
    foreach ($name in $LegacyScripts) {
        $path = Join-Path $ScriptDir $name
        if (Test-Path $path) { Remove-Item $path -Force; $removed += "  scripts\$name" }
    }
    foreach ($name in $LegacyData) {
        $path = Join-Path $DataSubDir $name
        if (Test-Path $path) { Remove-Item $path -Force; $removed += "  nselib\data\$name" }
    }
    return $removed
}

# --------------------------------------------------------------- API key
#
# The script itself never asks: it runs inside nmap, where there is no terminal
# to prompt on and where writing a file would be a surprise. The installer is
# the one moment a person is present.

function Test-VulnersKey {
    param([string]$Token)
    try {
        $response = Invoke-WebRequest -Uri "https://vulners.com/api/v3/audit/getSupportedOS/" `
            -Headers @{ "X-Api-Key" = $Token
                        "User-Agent" = "Vulners NMAP Plugin installer" } `
            -UseBasicParsing -TimeoutSec 20
        if ($response.StatusCode -eq 200) { return "ok" }
        return "unknown"
    } catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        switch ($code) {
            401 { return "bad" }
            403 { return "bad" }
            402 { return "unlicensed" }
            429 { return "ratelimited" }
            default { return "unreachable" }
        }
    }
}

function Save-VulnersKey {
    param([string]$Token)
    # nmap looks in %APPDATA%\nmap on Windows.
    $dir = Join-Path $env:APPDATA "nmap"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir "vulners.key"
    $temp = "$file.tmp"

    # Written and renamed, so an interrupted install cannot leave half a token
    # behind that then fails every scan with a 401 and nothing to say why.
    Set-Content -Path $temp -Value $Token -Encoding ASCII

    # Readable only by its owner: inheritance is what would otherwise leave it
    # readable by every account on the machine.
    $acl = Get-Acl $temp
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $me, "FullControl", "Allow")))
    Set-Acl -Path $temp -AclObject $acl

    Move-Item -Path $temp -Destination $file -Force
    Write-Host "  saved to $file (readable only by $me)"
}

function Invoke-KeyEntry {
    if ($NoKey) { return }

    if ($env:VULNERS_API_KEY) {
        Write-Host ""
        Write-Host "VULNERS_API_KEY is already set in the environment; leaving it alone."
        return
    }
    $existing = Join-Path (Join-Path $env:APPDATA "nmap") "vulners.key"
    if (Test-Path $existing) {
        Write-Host ""
        Write-Host "A key is already stored in $existing; leaving it alone."
        return
    }
    # Piped through iex, or run by CI, there is nobody to answer.
    if ([Console]::IsInputRedirected) {
        Write-Host ""
        Write-Host "No API key configured. It works without one; to add a key later,"
        Write-Host "put it in $existing or set VULNERS_API_KEY."
        return
    }

    Write-Host ""
    Write-Host "An API key is optional. Without one the scan uses the free lookup."
    Write-Host "A free key adds detail per finding and can identify software the free"
    Write-Host "lookup cannot name. Get one at https://vulners.com/userinfo"
    Write-Host ""
    Write-Host "Anything you enter is sent to vulners.com once, to check it works,"
    Write-Host "and then stored in $existing."

    # Read without echoing: a token pasted into a console otherwise stays in the
    # scrollback and in any recording of the session.
    $secure = Read-Host -Prompt "Paste a key, or press Enter to skip" -AsSecureString
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if (-not $token) { $token = "" }
    $token = $token.Trim()

    if (-not $token) {
        Write-Host "No key entered; the scan will use the free lookup."
        return
    }

    Write-Host "Checking it with vulners.com..."
    switch (Test-VulnersKey $token) {
        "ok" {
            Write-Host "  the key works."
            Save-VulnersKey $token
        }
        "bad" {
            Write-Host "  vulners.com does not recognise that key; it was NOT saved."
            Write-Host "  Check it at https://vulners.com/userinfo"
        }
        "unlicensed" {
            Write-Host "  that key is recognised but has no active licence; it was NOT saved."
        }
        "ratelimited" {
            Write-Host "  vulners.com is rate limiting right now, so the key could not be"
            Write-Host "  checked. Saving it anyway - it is probably fine."
            Save-VulnersKey $token
        }
        default {
            Write-Host "  could not reach vulners.com to check it. Saving it unchecked."
            Save-VulnersKey $token
        }
    }
}

function Get-NmapExe {
    $nmap = Get-Command nmap -ErrorAction SilentlyContinue
    if ($nmap) { return $nmap.Source }

    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe",
        "$env:ProgramFiles\Nmap\nmap.exe"
    )) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }

    throw "nmap is not installed, or not in PATH. Get it from https://nmap.org/download.html"
}

function Get-NmapDataDir {
    param([string]$NmapExe)

    # nmap names every file it opens under -d2, and --script-help sends no
    # packets: the directory holding nse_main.lua is the one this nmap uses.
    $output = & $NmapExe -d2 --script-help nmap-vulners-install-probe 2>&1
    foreach ($line in $output) {
        if ("$line" -match '^Fetchfile found (.*)[\\/]nse_main\.lua$') {
            $dir = $Matches[1]
            if (Test-Path $dir) { return (Resolve-Path $dir).Path }
        }
    }

    $fallback = Split-Path -Parent $NmapExe
    if (Test-Path (Join-Path $fallback "nselib")) { return $fallback }

    throw "Cannot find nmap's data directory. Pass -Prefix 'C:\Program Files (x86)\Nmap'."
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$nmapExe = Get-NmapExe

if ($User) {
    $dataDir = Join-Path $env:APPDATA "nmap"
} elseif ($Prefix) {
    $dataDir = $Prefix
} else {
    $dataDir = Get-NmapDataDir -NmapExe $nmapExe
}

$scriptDir = Join-Path $dataDir "scripts"
$dataSubDir = Join-Path $dataDir "nselib\data"

if (-not $User -and -not (Test-Administrator)) {
    Write-Warning "Writing into $dataDir usually needs administrator rights."
    Write-Warning "Either start PowerShell as Administrator, or run: .\install.ps1 -User"
}

if ($Uninstall) {
    Write-Host "Removing nmap-vulners from $dataDir"
    foreach ($name in $Scripts) {
        $path = Join-Path $scriptDir $name
        if (Test-Path $path) { Remove-Item $path -Force; Write-Host "  scripts\$name" }
    }
    foreach ($line in (Remove-LegacyFiles $scriptDir $dataSubDir)) { Write-Host $line }
    if ($User) { $env:NMAPDIR = $dataDir }
    & $nmapExe --script-updatedb | Out-Null
    Write-Host "Done."
    return
}

New-Item -ItemType Directory -Force -Path $scriptDir, $dataSubDir | Out-Null

# In a checkout the files sit next to this script; otherwise fetch them.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { "" }
$source = $here
$temp = $null

if (-not $here -or -not (Test-Path (Join-Path $here "vulners.nse"))) {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("nmap-vulners-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    Write-Host "Downloading nmap-vulners ($Ref)"
    foreach ($name in ($Scripts + $DataFiles)) {
        Invoke-WebRequest -Uri "$RepoRaw/$Ref/$name" -OutFile (Join-Path $temp $name) -UseBasicParsing
    }
    # A ref that still carries 1.x answers with a 1.x vulners.nse, which this
    # installer would then put in place while deleting the two data files that
    # release cannot run without - a downgrade to something broken, silently.
    # 2.0 fetches its dictionaries at scan time, and the line naming where from
    # is what tells the two apart.
    $fetched = Join-Path $temp "vulners.nse"
    if (-not (Select-String -Path $fetched -Pattern '^local CATALOG_BASE' -Quiet)) {
        throw "$Ref does not carry the 2.x script; nothing was installed"
    }
    $source = $temp
}

try {
    Write-Host "Installing into $dataDir"
    foreach ($name in $Scripts) {
        $target = Join-Path $scriptDir $name
        # Replacing is the point: nmap ships its own vulners.nse, and the copy
        # left behind is the one nmap would keep running.
        $note = if (Test-Path $target) { "  (replacing the existing copy)" } else { "" }
        Copy-Item (Join-Path $source $name) $target -Force
        Write-Host "  scripts\$name$note"
    }
    $removed = Remove-LegacyFiles $scriptDir $dataSubDir
    if ($removed) {
        Write-Host ""
        Write-Host "Removed the 1.x files this release replaces:"
        foreach ($line in $removed) { Write-Host $line }
    }
} finally {
    if ($temp -and (Test-Path $temp)) { Remove-Item $temp -Recurse -Force }
}

Write-Host "Updating the script database"
if ($User) { $env:NMAPDIR = $dataDir }
& $nmapExe --script-updatedb | Out-Null

# Prove which copy nmap resolves, not merely that the name resolves: nmap has
# a vulners.nse of its own.
$resolved = $null
foreach ($line in (& $nmapExe -d2 --script-help vulners 2>&1)) {
    if ("$line" -match '^Fetchfile found (.*vulners\.nse)$') { $resolved = $Matches[1]; break }
}

if (-not $resolved) {
    throw "The files were copied but nmap does not list them; check $scriptDir"
}

$expected = Join-Path $scriptDir "vulners.nse"
if ((Resolve-Path $resolved).Path -ne (Resolve-Path $expected).Path) {
    Write-Warning "nmap resolves 'vulners' to $resolved, not to $expected."
    if ($User) {
        Write-Warning "Set NMAPDIR so this copy wins:  setx NMAPDIR `"$dataDir`""
    }
}

Write-Host ""
$installedVersion = (Select-String -Path $expected -Pattern '^local api_version = "(.*)"$' |
                    Select-Object -First 1).Matches.Groups[1].Value
Write-Host "Installed. vulners.nse $installedVersion is in place. Try it:"
if ($User) {
    Write-Host "  setx NMAPDIR `"$dataDir`"      # once, so new shells find it"
}
Write-Host "  nmap -sV --script vulners scanme.nmap.org"
Write-Host ""
Invoke-KeyEntry

Write-Host ""
Write-Host "It works without an API key. A free key adds more detail per finding"
Write-Host "and lets it identify software the free lookup cannot name:"
Write-Host "  https://vulners.com/userinfo   (register at https://vulners.com/ first)"
