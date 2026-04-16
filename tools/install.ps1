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
    [string] $ReleaseUrl = "https://github.com/agentcordon/agentcordon/releases/latest/download"
)

$ErrorActionPreference = "Stop"

# --- Colors (best-effort — Write-Host -ForegroundColor works on PS 5.1+) ---
function Write-Banner($text) { Write-Host $text -ForegroundColor Magenta }
function Write-Info($text)   { Write-Host "  $text" -ForegroundColor Green }
function Write-Step($text)   { Write-Host "  $text" -ForegroundColor Cyan }
function Write-Warn2($text)  { Write-Host "  ! $text" -ForegroundColor Yellow }
function Write-Err($text)    { Write-Host "  x $text" -ForegroundColor Red }

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
    Write-Warn2 "SHA256SUMS not found at $sumsUrl — continuing without checksum verification."
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
        Write-Err "Failed to download $url : $($_.Exception.Message)"
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        exit 1
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
        Write-Warn2 "No checksum entry for $remote — skipping verification."
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
Write-Host  "    agentcordon setup $ServerUrl" -ForegroundColor White
Write-Host ""
exit 0
