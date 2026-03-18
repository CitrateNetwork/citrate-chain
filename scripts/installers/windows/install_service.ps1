# install_service.ps1 — Register Citrate as a Windows Service
# Run as Administrator

param(
    [string]$InstallDir = "$env:ProgramFiles\Citrate",
    [string]$DataDir = "$env:LOCALAPPDATA\Citrate"
)

$ServiceName = "CitrateNode"
$DisplayName = "Citrate Blockchain Node"
$Description = "Citrate AI-native blockchain node service"
$ExePath = Join-Path $InstallDir "citrate-node.exe"

# Create data directory
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$DataDir\logs" -Force | Out-Null
    New-Item -ItemType Directory -Path "$DataDir\keystore" -Force | Out-Null
    Write-Host "Created data directory: $DataDir"
}

# Register Windows Service
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' already exists. Stopping..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$BinPath = "`"$ExePath`" devnet --data-dir `"$DataDir`""
New-Service -Name $ServiceName `
    -BinaryPathName $BinPath `
    -DisplayName $DisplayName `
    -Description $Description `
    -StartupType Automatic | Out-Null

Write-Host "Service '$ServiceName' registered."

# Add firewall rules
$Rules = @(
    @{ Name = "Citrate RPC"; Port = 8545; Protocol = "TCP" },
    @{ Name = "Citrate WS"; Port = 8546; Protocol = "TCP" },
    @{ Name = "Citrate P2P"; Port = 30303; Protocol = "TCP" },
    @{ Name = "Citrate P2P UDP"; Port = 30303; Protocol = "UDP" }
)

foreach ($Rule in $Rules) {
    $Existing = Get-NetFirewallRule -DisplayName $Rule.Name -ErrorAction SilentlyContinue
    if (-not $Existing) {
        New-NetFirewallRule -DisplayName $Rule.Name `
            -Direction Inbound `
            -Protocol $Rule.Protocol `
            -LocalPort $Rule.Port `
            -Action Allow | Out-Null
        Write-Host "Firewall rule added: $($Rule.Name) ($($Rule.Protocol) $($Rule.Port))"
    }
}

Write-Host ""
Write-Host "=== Citrate Node installed ==="
Write-Host "Start: Start-Service $ServiceName"
Write-Host "Status: Get-Service $ServiceName"
Write-Host "Logs: $DataDir\logs\"
