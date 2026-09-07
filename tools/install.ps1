#Requires -Version 5.1
<#
.SYNOPSIS
    AgentCordon installer for Windows.

.DESCRIPTION
    Downloads the agentcordon CLI and broker binaries from GitHub Releases,
    installs them to %LOCALAPPDATA%\AgentCordon\bin, verifies SHA-256 checksums,
    and adds the install directory to the user PATH.

    Invocation:
        irm https://<server>/install.ps1 | iex

    Re-running the script is idempotent: binaries are overwritten in place and
    the PATH entry is only added once.
#>

[CmdletBinding()]
param(
    [string] $ServerUrl = "{SERVER_URL}",
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA "AgentCordon\bin"),
    # Pinned to the version of the server that served this script, not to
    # `latest`. `latest` is the newest *published* release, which on a server
    # built from source is older than the server itself — and v0.4.0 changed
    # the signed request payload, so a CLI and broker from the wrong side of
    # that change cannot talk to this server at all.
    [string] $Version    = "{VERSION}",
    [string] $ReleaseUrl = "https://github.com/agentcordon/agentcordon/releases/download/v{VERSION}"
)

$ErrorActionPreference = "Stop"

# --- Colors (best-effort — Write-Host -ForegroundColor works on PS 5.1+) ---
function Write-Banner($text) { Write-Host $text -ForegroundColor Magenta }
function Write-Info($text)   { Write-Host "  $text" -ForegroundColor Green }
function Write-Step($text)   { Write-Host "  $text" -ForegroundColor Cyan }
function Write-Warn2($text)  { Write-Host "  ! $text" -ForegroundColor Yellow }
function Write-Err($text)    { Write-Host "  x $text" -ForegroundColor Red }

# The pinned release is not on GitHub — the normal state of a server built
# from `main` between releases.
#
# Only an HTTP 404 means that. A proxy, a DNS failure or a rate-limit used to
# land here too, so a network problem was reported as "there is no release" and
# the user was told to build from source
# (uat/artifacts/reviews/ONBOARDING-empirical.md F7).
function Write-NoRelease {
    Write-Host ""
    Write-Err "No published release for AgentCordon v$Version."
    Write-Host ""
    Write-Host "  This server is running v$Version, and the installer only installs binaries"
    Write-Host "  from the matching release: a CLI and broker from a different version may"
    Write-Host "  not be able to talk to it."
    Write-Host ""
    Write-Host "  Build the CLI and broker from source instead (README, Building from Source):"
    Write-Host "    git clone https://github.com/agentcordon/agentcordon"
    Write-Host "    cd agentcordon; cargo build --release"
    Write-Host ""
    exit 1
}

# The request never completed: DNS, a proxy, TLS, a rate-limit. Distinct from a
# 404, which really does mean the release is not published.
function Write-Unreachable($url, $detail) {
    Write-Host ""
    Write-Err "Could not reach $url"
    if ($detail) { Write-Host "  $detail" }
    Write-Host ""
    Write-Host "  This is a network failure, not a missing release: the request did not"
    Write-Host "  complete. Check your connection, proxy settings and DNS, then run the"
    Write-Host "  installer again."
    Write-Host ""
    exit 1
}

# The HTTP status carried by a terminating web exception, or $null when the
# request never got far enough to have one.
function Get-HttpStatus($errorRecord) {
    $response = $errorRecord.Exception.Response
    if ($null -eq $response) { return $null }
    try { return [int] $response.StatusCode } catch { return $null }
}

# --- Banner ---
Write-Host ""
Write-Banner "AgentCordon installer"
Write-Banner "---------------------"
Write-Host  "  Server:  $ServerUrl"
Write-Host  "  Target:  $InstallDir"
Write-Host ""

# --- Architecture check ---
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "ARM64") {
    Write-Err "ARM64 Windows isn't supported yet; track https://github.com/agentcordon/agentcordon/issues for updates."
    exit 1
}
if ($arch -ne "AMD64") {
    Write-Err "Unsupported architecture: $arch (only x86_64/AMD64 is supported)."
    exit 1
}

# --- Ensure install directory ---
if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Info "Created $InstallDir"
}

# --- Binary definitions ---
$binaries = @(
    @{ Remote = "agentcordon-x86_64-pc-windows-msvc.exe";        Local = "agentcordon.exe" },
    @{ Remote = "agentcordon-broker-x86_64-pc-windows-msvc.exe"; Local = "agentcordon-broker.exe" }
)

# --- Fetch SHA256SUMS (optional on older releases) ---
$checksums = @{}
$sumsUrl = "$ReleaseUrl/SHA256SUMS"
try {
    Write-Step "Fetching SHA256SUMS..."
    $sumsResp = Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -ErrorAction Stop
    foreach ($line in ($sumsResp.Content -split "`n")) {
        $trim = $line.Trim()
        if ([string]::IsNullOrEmpty($trim)) { continue }
        # Format: "<hex>  <filename>"
        $parts = $trim -split '\s+', 2
        if ($parts.Length -eq 2) {
            $checksums[$parts[1].Trim()] = $parts[0].Trim().ToLowerInvariant()
        }
    }
    Write-Info "Checksums loaded ($($checksums.Count) entries)"
} catch {
    $status = Get-HttpStatus $_
    if ($status -eq 404) {
        Write-NoRelease
    } else {
        Write-Unreachable $sumsUrl $_.Exception.Message
    }
}

# --- Download + verify + install each binary ---
foreach ($bin in $binaries) {
    $remote = $bin.Remote
    $local  = $bin.Local
    $url    = "$ReleaseUrl/$remote"
    $dest   = Join-Path $InstallDir $local
    $tmp    = "$dest.download"

    Write-Step "Downloading $local..."
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp -ErrorAction Stop
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        $status = Get-HttpStatus $_
        if ($status -eq 404) {
            Write-NoRelease
        } else {
            Write-Unreachable $url $_.Exception.Message
        }
    }

    if ($checksums.ContainsKey($remote)) {
        $expected = $checksums[$remote]
        $actual   = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            Write-Err "Checksum mismatch for $remote"
            Write-Err "  expected: $expected"
            Write-Err "  actual:   $actual"
            Remove-Item -LiteralPath $tmp -Force
            exit 1
        }
        Write-Info "Verified $local (sha256 ok)"
    } else {
        # install.sh refuses here, and docs/installation.md describes the two
        # one-liners as equally verified. Warning and installing anyway made
        # Windows quietly the weaker of the two
        # (uat/artifacts/reviews/ONBOARDING-empirical.md F6).
        Write-Err "SHA256SUMS has no entry for $remote; refusing to install it."
        Remove-Item -LiteralPath $tmp -Force
        exit 1
    }

    Move-Item -LiteralPath $tmp -Destination $dest -Force
    Write-Info "Installed $local"
}

# --- Add to user PATH (idempotent) ---
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ([string]::IsNullOrEmpty($userPath)) { $userPath = "" }

$pathEntries = $userPath -split ';' | Where-Object { $_ -ne "" }
$alreadyOnPath = $false
foreach ($entry in $pathEntries) {
    if ($entry.TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) {
        $alreadyOnPath = $true
        break
    }
}

if ($alreadyOnPath) {
    Write-Info "PATH already contains $InstallDir"
} else {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Info "Added $InstallDir to user PATH"
    Write-Warn2 "Open a new terminal for the PATH change to take effect."
}

# --- Done ---
Write-Host ""
Write-Banner "Done."
Write-Host  "  Open a new terminal and run:"
Write-Host  "    agentcordon-broker --server-url $ServerUrl" -ForegroundColor White
Write-Host  "  then, from your project directory:"
Write-Host  "    agentcordon init" -ForegroundColor White
Write-Host  "      choose which agent runtimes to install the AgentCordon skill for"
Write-Host  "    agentcordon register --server-url $ServerUrl" -ForegroundColor White
Write-Host ""
exit 0
