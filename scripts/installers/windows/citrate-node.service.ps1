# citrate-node.service.ps1 - Windows service registration for Citrate node
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File citrate-node.service.ps1 [install|uninstall|start|stop|status]

param(
    [Parameter(Position = 0)]
    [ValidateSet("install", "uninstall", "start", "stop", "status")]
    [string]$Action = "install",

    [string]$NodeBin,

    [string]$DataDir = (Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "Citrate"),

    [string]$ConfigPath,

    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$ServiceName = "CitrateNode"
$DisplayName = "Citrate Blockchain Node"
$Description = "Citrate AI-native Layer-1 blockchain node with GhostDAG consensus"
$NetworkServiceSid = "S-1-5-20"
$NetworkServiceAccount = "NT AUTHORITY\NetworkService"
$ScExe = Join-Path $env:SystemRoot "System32\sc.exe"
$NodeBinWasSpecified = $PSBoundParameters.ContainsKey("NodeBin")
$ConfigPathWasSpecified = $PSBoundParameters.ContainsKey("ConfigPath")

function Resolve-NodeBinary {
    if ($NodeBinWasSpecified) {
        if ([string]::IsNullOrWhiteSpace($NodeBin)) {
            throw "NodeBin must not be empty."
        }

        return $NodeBin
    }

    $besideScript = Join-Path $PSScriptRoot "citrate-node.exe"
    if (Test-Path -LiteralPath $besideScript -PathType Leaf) {
        return $besideScript
    }

    try {
        $command = Get-Command "citrate-node.exe" -CommandType Application -ErrorAction Stop | Select-Object -First 1
    } catch [System.Management.Automation.CommandNotFoundException] {
        $command = $null
    }
    if ($command) {
        return $command.Source
    }

    throw "citrate-node.exe was not found beside this script or on PATH."
}

function Assert-SafePathText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Description path must not be empty."
    }

    if ($Path.IndexOf('"') -ge 0) {
        throw "$Description path must not contain a quote."
    }

    foreach ($character in $Path.ToCharArray()) {
        if ([char]::IsControl($character)) {
            throw "$Description path must not contain control characters."
        }
    }

    if ($Path.StartsWith("\\") -or $Path.StartsWith("//") -or $Path.StartsWith("\??\") -or $Path.StartsWith("\Device\")) {
        throw "$Description path must be a local drive path, not a UNC or device path."
    }

    if ($Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Description path must be absolute."
    }

    if ($Path.Substring(2).Contains(":")) {
        throw "$Description path must not use an alternate data stream."
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $root = [System.IO.Path]::GetPathRoot($Path)
    $current = $root
    $relative = $Path.Substring($root.Length)

    foreach ($part in $relative.Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Description path must not contain a reparse point: $current"
        }
    }
}

function Resolve-SafeExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("File", "Directory")]
        [string]$PathType,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [switch]$RequireNonEmpty
    )

    Assert-SafePathText -Path $Path -Description $Description

    try {
        $normalized = [System.IO.Path]::GetFullPath($Path)
        $item = Get-Item -LiteralPath $normalized -Force
    } catch {
        throw "$Description does not exist: $Path"
    }

    if ($PathType -eq "File" -and $item.PSIsContainer) {
        throw "$Description must be a file: $normalized"
    }
    if ($PathType -eq "Directory" -and -not $item.PSIsContainer) {
        throw "$Description must be a directory: $normalized"
    }
    if ($RequireNonEmpty -and $item.Length -eq 0) {
        throw "$Description must not be empty: $normalized"
    }

    Assert-NoReparsePoint -Path $normalized -Description $Description
    return $normalized
}

function Assert-NetworkServiceAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$RequiredRights,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    # NetworkService receives these well-known groups in its service token. Evaluating
    # SIDs directly avoids localized account names. The canonical DACL order is honored:
    # a deny ACE rejects rights not already granted by an earlier applicable allow ACE.
    $applicableSids = @(
        "S-1-5-20", # NetworkService
        "S-1-5-6",  # Service
        "S-1-5-80-0", # All Services
        "S-1-5-11", # Authenticated Users
        "S-1-5-32-545", # Builtin Users
        "S-1-1-0"   # Everyone
    )
    $remaining = [int64]$RequiredRights
    $acl = Get-Acl -LiteralPath $Path
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

    foreach ($rule in $rules) {
        if ($applicableSids -notcontains $rule.IdentityReference.Value) {
            continue
        }
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
            continue
        }

        $applicable = ([int64]$rule.FileSystemRights) -band $remaining
        if ($applicable -eq 0) {
            continue
        }

        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
            throw "NetworkService is denied required $Description access to: $Path"
        }

        $remaining = $remaining -band (-bnot $applicable)
        if ($remaining -eq 0) {
            return
        }
    }

    throw "NetworkService lacks required $Description access to: $Path"
}

function New-ServicePlan {
    $resolvedScExe = Resolve-SafeExistingPath -Path $ScExe -PathType File -Description "sc.exe" -RequireNonEmpty
    $resolvedNodeBin = Resolve-SafeExistingPath -Path (Resolve-NodeBinary) -PathType File -Description "NodeBin" -RequireNonEmpty
    if (-not [string]::Equals([System.IO.Path]::GetExtension($resolvedNodeBin), ".exe", [StringComparison]::OrdinalIgnoreCase)) {
        throw "NodeBin must be a .exe file."
    }
    $resolvedDataDir = Resolve-SafeExistingPath -Path $DataDir -PathType Directory -Description "DataDir"
    $databasePath = Resolve-SafeExistingPath -Path (Join-Path $resolvedDataDir "db") -PathType Directory -Description "Database directory"

    if ($ConfigPathWasSpecified) {
        if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
            throw "ConfigPath must not be empty."
        }
        $candidateConfigPath = $ConfigPath
    } else {
        $candidateConfigPath = Join-Path $resolvedDataDir "node.toml"
    }

    if (-not [string]::Equals([System.IO.Path]::GetFileName($candidateConfigPath), "node.toml", [StringComparison]::OrdinalIgnoreCase)) {
        throw "ConfigPath must use the canonical node.toml filename."
    }

    $resolvedConfigPath = Resolve-SafeExistingPath -Path $candidateConfigPath -PathType File -Description "ConfigPath" -RequireNonEmpty
    $nodeDirectory = Split-Path -Parent $resolvedNodeBin
    $configDirectory = Split-Path -Parent $resolvedConfigPath

    Assert-NetworkServiceAccess -Path $nodeDirectory -RequiredRights Traverse -Description "executable traversal"
    Assert-NetworkServiceAccess -Path $resolvedNodeBin -RequiredRights ReadAndExecute -Description "executable read/execute"
    Assert-NetworkServiceAccess -Path $resolvedDataDir -RequiredRights Traverse -Description "data directory traversal"
    if (-not [string]::Equals($resolvedDataDir, $configDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        Assert-NetworkServiceAccess -Path $configDirectory -RequiredRights Traverse -Description "config traversal"
    }
    Assert-NetworkServiceAccess -Path $resolvedConfigPath -RequiredRights Read -Description "config read"
    Assert-NetworkServiceAccess -Path $databasePath -RequiredRights Modify -Description "database modify"

    $imagePath = '"' + $resolvedNodeBin + '" --data-dir "' + $databasePath + '" --config "' + $resolvedConfigPath + '"'
    $scArguments = @(
        "create",
        $ServiceName,
        "binPath=",
        $imagePath,
        "DisplayName=",
        $DisplayName,
        "start=",
        "auto",
        "obj=",
        $NetworkServiceAccount
    )

    return [pscustomobject]@{
        ServiceName = $ServiceName
        Identity = [pscustomobject]@{
            Sid = $NetworkServiceSid
            Account = $NetworkServiceAccount
        }
        NodeBin = $resolvedNodeBin
        DataDir = $resolvedDataDir
        DatabasePath = $databasePath
        ConfigPath = $resolvedConfigPath
        ImagePath = $imagePath
        ScExecutable = $resolvedScExe
        ScArguments = $scArguments
    }
}

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Action '$Action' requires an elevated PowerShell session."
    }
}

function Invoke-Sc {
    param(
        [string]$Executable = $ScExe,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    try {
        $output = & $Executable @Arguments 2>&1
    } catch {
        throw "Unable to run sc.exe at '$Executable': $($_.Exception.Message)"
    }
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe at '$Executable' failed with exit code ${LASTEXITCODE}: $($output -join [Environment]::NewLine)"
    }
    $output
}

function Get-CitrateService {
    param(
        [string]$Name = $ServiceName
    )

    try {
        return Get-Service -Name $Name -ErrorAction Stop
    } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        if ($_.FullyQualifiedErrorId -like "NoServiceFoundForGivenName*") {
            return $null
        }

        throw "Unable to query Windows service '$Name': $($_.Exception.Message)"
    } catch {
        throw "Unable to query Windows service '$Name': $($_.Exception.Message)"
    }
}

function Assert-CitrateServiceAbsent {
    param(
        [string]$Name = $ServiceName
    )

    if (Get-CitrateService -Name $Name) {
        throw "Windows service '$Name' already exists. Uninstall it before installing CitrateNode."
    }
}

function Install-CitrateService {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Plan
    )

    Write-Host "Installing $ServiceName service..."
    Invoke-Sc -Executable $Plan.ScExecutable -Arguments $Plan.ScArguments
    Invoke-Sc -Executable $Plan.ScExecutable -Arguments @("description", $ServiceName, $Description)
    Invoke-Sc -Executable $Plan.ScExecutable -Arguments @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/10000/restart/30000/restart/60000")
    Write-Host "Service installed. Start with: .\citrate-node.service.ps1 start"
}

function Uninstall-CitrateService {
    Write-Host "Removing $ServiceName service..."
    $service = Get-CitrateService
    if (-not $service) {
        Write-Host "Service not found."
        return
    }

    if ($service.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
    }
    Invoke-Sc -Arguments @("delete", $ServiceName)
    Write-Host "Service removed."
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

function Get-CitrateServiceStatus {
    $service = Get-CitrateService
    if ($service) {
        Write-Host "Service: $($service.DisplayName)"
        Write-Host "Status:  $($service.Status)"
    } else {
        Write-Host "Service not installed."
    }
}

function Set-FirewallRules {
    Write-Host "Configuring firewall rules..."

    New-NetFirewallRule -DisplayName "Citrate P2P" `
        -Direction Inbound -Protocol TCP -LocalPort 30303 `
        -Action Allow -Profile Private,Domain `
        -Description "Citrate blockchain P2P networking" `
        -ErrorAction SilentlyContinue

    New-NetFirewallRule -DisplayName "Citrate RPC" `
        -Direction Inbound -Protocol TCP -LocalPort 8545 `
        -Action Allow -Profile Private `
        -RemoteAddress LocalSubnet `
        -Description "Citrate JSON-RPC endpoint" `
        -ErrorAction SilentlyContinue

    Write-Host "Firewall rules configured."
}

if ($ValidateOnly) {
    if ($Action -ne "install") {
        throw "ValidateOnly is supported only for the install action."
    }
    New-ServicePlan
    return
}

switch ($Action) {
    "install" {
        $plan = New-ServicePlan
        Assert-CitrateServiceAbsent
        Assert-Administrator
        Install-CitrateService -Plan $plan
        Set-FirewallRules
    }
    "uninstall" {
        Uninstall-CitrateService
    }
    "start" {
        Start-CitrateService
    }
    "stop" {
        Stop-CitrateService
    }
    "status" {
        Get-CitrateServiceStatus
    }
}
