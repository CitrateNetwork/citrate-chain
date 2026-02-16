# scripts/packaging/windows/create-installer.ps1
# PowerShell wrapper to build the NSIS installer.
#
# Usage:
#   .\create-installer.ps1 [-Version "0.1.0"] [-CliDir "..\..\target\release"] [-GuiDir "..."]
#
# Prerequisites:
#   - NSIS installed (choco install nsis -y)
#   - CLI binary built: cargo build --release -p citrate-node
#   - GUI built (optional): cd gui\citrate-core && npm run tauri:build

param(
    [string]$Version = "0.1.0",
    [string]$CliDir = "",
    [string]$GuiDir = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\..\..\..\"

Write-Host "=== Citrate Windows Installer Builder ===" -ForegroundColor Cyan
Write-Host "  Version: $Version"

# Locate NSIS
$MakeNsis = Get-Command makensis -ErrorAction SilentlyContinue
if (-not $MakeNsis) {
    $NsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
    if (Test-Path $NsisPath) {
        $MakeNsis = Get-Item $NsisPath
    } else {
        Write-Error "NSIS not found. Install with: choco install nsis -y"
        exit 1
    }
}

# Locate CLI binary
if (-not $CliDir) {
    $CliDir = "$ProjectRoot\target\release"
}
if (-not (Test-Path "$CliDir\citrate.exe")) {
    Write-Error "citrate.exe not found in $CliDir. Build with: cargo build --release -p citrate-node"
    exit 1
}
Write-Host "  CLI: $CliDir\citrate.exe"

# Locate GUI binary
if (-not $GuiDir) {
    $GuiDir = "$ProjectRoot\gui\citrate-core\src-tauri\target\release"
}
if (Test-Path "$GuiDir\Citrate.exe") {
    Write-Host "  GUI: $GuiDir\Citrate.exe"
} else {
    Write-Host "  GUI: Not found (installer will contain CLI only)" -ForegroundColor Yellow
}

# Output directory
if (-not $OutputDir) {
    $OutputDir = "$ProjectRoot\dist"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build installer
Write-Host "`nBuilding NSIS installer..." -ForegroundColor Cyan

$NsiScript = "$ScriptDir\citrate.nsi"
$InstallerName = "CitrateSetup-${Version}-x64.exe"

& $MakeNsis.Source `
    "/DVERSION=$Version" `
    "/DCLI_DIR=$CliDir" `
    "/DGUI_DIR=$GuiDir" `
    $NsiScript

# Move installer to output directory
if (Test-Path "$ScriptDir\$InstallerName") {
    Move-Item -Force "$ScriptDir\$InstallerName" "$OutputDir\$InstallerName"
}

# Generate checksum
$Hash = Get-FileHash "$OutputDir\$InstallerName" -Algorithm SHA256
"$($Hash.Hash)  $InstallerName" | Out-File -Encoding ASCII "$OutputDir\$InstallerName.sha256"

$Size = (Get-Item "$OutputDir\$InstallerName").Length / 1MB
Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "  Installer: $OutputDir\$InstallerName"
Write-Host "  Checksum:  $OutputDir\$InstallerName.sha256"
Write-Host "  Size:      $([math]::Round($Size, 1)) MB"
