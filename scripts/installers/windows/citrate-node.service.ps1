# citrate-node.service.ps1 — Windows service registration for Citrate node
#
# Registers citrate-node as a Windows service using NSSM or sc.exe
# Run as Administrator for system-wide service, or as current user for user-level.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File citrate-node.service.ps1 [install|uninstall|start|stop|status]

param(
    [Parameter(Position=0)]
    [ValidateSet("install", "uninstall", "start", "stop", "status")]
    [string]$Action = "install"
)

$ServiceName = "CitrateNode"
$DisplayName = "Citrate Blockchain Node"
$Description = "Citrate AI-native Layer-1 blockchain node with GhostDAG consensus"
$DataDir = Join-Path $env:USERPROFILE ".citrate"
$LogDir = Join-Path $DataDir "logs"

# Locate the node binary (check sidecar location first, then PATH)
$AppDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$NodeBin = Join-Path $AppDir "citrate-node.exe"
if (-not (Test-Path $NodeBin)) {
    $NodeBin = (Get-Command citrate-node -ErrorAction SilentlyContinue).Source
}
if (-not $NodeBin -or -not (Test-Path $NodeBin)) {
    Write-Error "citrate-node.exe not found. Install Citrate first."
    exit 1
}

function Install-Service {
    Write-Host "Installing $ServiceName service..."

    # Ensure data directory exists
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $BinPath = "`"$NodeBin`" --data-dir `"$DataDir\db`" --config `"$DataDir\config.toml`""

    # Use sc.exe for native service registration
    sc.exe create $ServiceName `
        binPath= $BinPath `
        DisplayName= $DisplayName `
        start= auto `
        obj= "NT AUTHORITY\NetworkService"

    sc.exe description $ServiceName $Description

    # Configure failure recovery: restart after 10s, 30s, 60s
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000

    Write-Host "Service installed. Start with: .\citrate-node.service.ps1 start"
}

function Uninstall-Service {
    Write-Host "Removing $ServiceName service..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
        }
        sc.exe delete $ServiceName
        Write-Host "Service removed."
    } else {
        Write-Host "Service not found."
    }
}

function Start-CitrateService {
    Write-Host "Starting $ServiceName..."
    Start-Service -Name $ServiceName
    Write-Host "Service started."
}

function Stop-CitrateService {
    Write-Host "Stopping $ServiceName..."
    Stop-Service -Name $ServiceName -Force
    Write-Host "Service stopped."
}

function Get-ServiceStatus {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "Service: $($svc.DisplayName)"
        Write-Host "Status:  $($svc.Status)"
        Write-Host "Binary:  $NodeBin"
        Write-Host "DataDir: $DataDir"
    } else {
        Write-Host "Service not installed."
    }
}

# Configure Windows Firewall rules
function Set-FirewallRules {
    Write-Host "Configuring firewall rules..."

    # Allow inbound P2P traffic
    New-NetFirewallRule -DisplayName "Citrate P2P" `
        -Direction Inbound -Protocol TCP -LocalPort 30303 `
        -Action Allow -Profile Private,Domain `
        -Description "Citrate blockchain P2P networking" `
        -ErrorAction SilentlyContinue

    # Allow inbound RPC (localhost only by default)
    New-NetFirewallRule -DisplayName "Citrate RPC" `
        -Direction Inbound -Protocol TCP -LocalPort 8545 `
        -Action Allow -Profile Private `
        -RemoteAddress LocalSubnet `
        -Description "Citrate JSON-RPC endpoint" `
        -ErrorAction SilentlyContinue

    Write-Host "Firewall rules configured."
}

switch ($Action) {
    "install"   { Install-Service; Set-FirewallRules }
    "uninstall" { Uninstall-Service }
    "start"     { Start-CitrateService }
    "stop"      { Stop-CitrateService }
    "status"    { Get-ServiceStatus }
}
