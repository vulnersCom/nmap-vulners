<#
.SYNOPSIS
    Install the nmap-vulners scripts where the local nmap will find them.

.DESCRIPTION
    Copies the three NSE scripts and their data files into nmap's own
    directories and rebuilds the script database. An existing copy is replaced:
    nmap ships a vulners.nse of its own, and leaving it in place means nmap
    keeps running that one.

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
    Remove the files this script installs.

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
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$RepoRaw  = "https://raw.githubusercontent.com/vulnersCom/nmap-vulners"
$Scripts  = @("http-vulners-regex.nse", "vulners.nse", "vulners_enterprise.nse")
$DataFiles = @("http-vulners-regex.json", "http-vulners-paths.txt")

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
    foreach ($name in $DataFiles) {
        $path = Join-Path $dataSubDir $name
        if (Test-Path $path) { Remove-Item $path -Force; Write-Host "  nselib\data\$name" }
    }
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
    foreach ($name in $DataFiles) {
        Copy-Item (Join-Path $source $name) (Join-Path $dataSubDir $name) -Force
        Write-Host "  nselib\data\$name"
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
Write-Host "vulners_enterprise needs an API key from https://vulners.com :"
Write-Host "  `$env:VULNERS_API_KEY = '<token>'"
Write-Host "  nmap -sV --script vulners_enterprise <target>"
