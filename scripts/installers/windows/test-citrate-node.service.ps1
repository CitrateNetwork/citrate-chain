$ErrorActionPreference = "Stop"

$ServiceScript = Join-Path $PSScriptRoot "citrate-node.service.ps1"
$TestNetworkServiceSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")
$TestAuthenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
$TestSystemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$TestAdministratorsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$TestRoot = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) ("Citrate service test " + [guid]::NewGuid().ToString("N"))

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Assert-SequenceEqual {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Actual,

        [Parameter(Mandatory = $true)]
        [object[]]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Assert-Equal -Actual $Actual.Count -Expected $Expected.Count -Message "$Message item count differs."
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        Assert-Equal -Actual $Actual[$index] -Expected $Expected[$index] -Message "$Message item $index differs."
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$MessagePattern,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    try {
        & $Operation | Out-Null
    } catch {
        if ($_.Exception.Message -notmatch $MessagePattern) {
            throw "$Message Unexpected error: $($_.Exception.Message)"
        }
        return
    }

    throw "$Message Expected an error matching '$MessagePattern'."
}

function Grant-NetworkServiceAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$Rights
    )

    $acl = Get-Acl -LiteralPath $Path
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $TestNetworkServiceSid,
        $Rights,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-TestAccessRule {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$Rights,

        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None,

        [System.Security.AccessControl.PropagationFlags]$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None,

        [System.Security.AccessControl.AccessControlType]$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    )

    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Sid,
        $Rights,
        $InheritanceFlags,
        $PropagationFlags,
        $AccessControlType
    )
}

function Assert-NetworkServiceAccessRejected {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$MessagePattern,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $originalAcl = Get-Acl -LiteralPath $Path
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $pathItem = Get-Item -LiteralPath $Path -Force
    if ($pathItem.PSIsContainer) {
        $currentUserInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
            $childAcl = Get-Acl -LiteralPath $child.FullName
            $childInheritance = if ($child.PSIsContainer) { $currentUserInheritance } else { [System.Security.AccessControl.InheritanceFlags]::None }
            $null = $childAcl.AddAccessRule((New-TestAccessRule -Sid $currentUserSid -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) -InheritanceFlags $childInheritance))
            Set-Acl -LiteralPath $child.FullName -AclObject $childAcl
        }
    } else {
        $currentUserInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    try {
        $blockedAcl = Get-Acl -LiteralPath $Path
        $blockedAcl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @("S-1-5-20", "S-1-5-6", "S-1-5-80-0", "S-1-5-11", "S-1-5-32-545", "S-1-1-0")) {
            $blockedAcl.PurgeAccessRules((New-Object System.Security.Principal.SecurityIdentifier($sid)))
        }
        $currentUserRule = New-TestAccessRule -Sid $currentUserSid -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) -InheritanceFlags $currentUserInheritance
        $null = $blockedAcl.AddAccessRule($currentUserRule)
        Set-Acl -LiteralPath $Path -AclObject $blockedAcl
        Assert-Throws -Operation $Operation -MessagePattern $MessagePattern -Message $Message
    } finally {
        Set-Acl -LiteralPath $Path -AclObject $originalAcl
    }
}

function Get-TestTreeSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    return @($items | Sort-Object FullName | ForEach-Object {
        $relativePath = $_.FullName.Substring($Path.Length)
        $length = if ($_.PSIsContainer) { "directory" } else { $_.Length }
        $sddl = (Get-Acl -LiteralPath $_.FullName).Sddl
        "$relativePath|$length|$($_.Attributes)|$sddl"
    })
}

function Invoke-Validation {
    param(
        [string]$NodeBin,

        [string]$DataDir,

        [string]$ConfigPath
    )

    return & $ServiceScript -ValidateOnly -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
}

try {
    $parseErrors = @()
    $serviceAst = [System.Management.Automation.Language.Parser]::ParseFile($ServiceScript, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "The service script has parser errors."
    }
    $dataDirParameter = $serviceAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "DataDir" }
    if (-not $dataDirParameter -or $dataDirParameter.DefaultValue.Extent.Text -notmatch 'CommonApplicationData') {
        throw "DataDir does not default to CommonApplicationData."
    }
    if ($dataDirParameter.DefaultValue.Extent.Text -match 'USERPROFILE') {
        throw "DataDir still depends on USERPROFILE."
    }

    $DataDir = Join-Path $TestRoot "Program Data"
    $DatabasePath = Join-Path $DataDir "db"
    $NodeDirectory = Join-Path $TestRoot "Application Files"
    $NodeBin = Join-Path $NodeDirectory "citrate-node.exe"
    $ConfigPath = Join-Path $DataDir "node.toml"
    $ArgumentProbe = Join-Path $TestRoot "argument-probe.exe"

    $null = New-Item -ItemType Directory -Path $TestRoot
    $testRootAcl = Get-Acl -LiteralPath $TestRoot
    $testRootAcl.SetAccessRuleProtection($true, $false)
    $testRootInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        $TestSystemSid,
        $TestAdministratorsSid
    )) {
        $null = $testRootAcl.AddAccessRule((New-TestAccessRule `
            -Sid $sid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) `
            -InheritanceFlags $testRootInheritance))
    }
    Set-Acl -LiteralPath $TestRoot -AclObject $testRootAcl

    $null = New-Item -ItemType Directory -Path $DatabasePath -Force
    $null = New-Item -ItemType Directory -Path $NodeDirectory -Force
    [System.IO.File]::WriteAllText($NodeBin, "test executable")
    [System.IO.File]::WriteAllText($ConfigPath, "network = 'test'")
    Add-Type -TypeDefinition @'
using System;
using System.Text;

public static class ArgumentProbe
{
    public static int Main(string[] arguments)
    {
        foreach (string argument in arguments)
        {
            Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(argument)));
        }
        return 0;
    }
}
'@ -Language CSharp -OutputAssembly $ArgumentProbe -OutputType ConsoleApplication

    Grant-NetworkServiceAccess -Path $TestRoot -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Grant-NetworkServiceAccess -Path $DatabasePath -Rights ([System.Security.AccessControl.FileSystemRights]::Modify)

    $beforeSnapshot = Get-TestTreeSnapshot -Path $TestRoot
    $plan = Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    $defaultConfigPlan = & $ServiceScript -ValidateOnly -NodeBin $NodeBin -DataDir $DataDir
    $afterSnapshot = Get-TestTreeSnapshot -Path $TestRoot

    $expectedNodeBin = [System.IO.Path]::GetFullPath($NodeBin)
    $expectedDataDir = [System.IO.Path]::GetFullPath($DataDir)
    $expectedDatabasePath = [System.IO.Path]::GetFullPath($DatabasePath)
    $expectedConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
    $expectedImagePath = '"' + $expectedNodeBin + '" --data-dir "' + $expectedDatabasePath + '" --config "' + $expectedConfigPath + '"'
    $expectedScArguments = @(
        "create",
        "CitrateNode",
        "binPath=",
        $expectedImagePath,
        "DisplayName=",
        "Citrate Blockchain Node",
        "start=",
        "auto",
        "obj=",
        "NT AUTHORITY\NetworkService"
    )

    Assert-Equal -Actual $plan.ServiceName -Expected "CitrateNode" -Message "Service name differs."
    Assert-Equal -Actual $plan.Identity.Sid -Expected "S-1-5-20" -Message "Service SID differs."
    Assert-Equal -Actual $plan.Identity.Account -Expected "NT AUTHORITY\NetworkService" -Message "Service account differs."
    Assert-Equal -Actual $plan.NodeBin -Expected $expectedNodeBin -Message "Normalized NodeBin differs."
    Assert-Equal -Actual $plan.DataDir -Expected $expectedDataDir -Message "Normalized DataDir differs."
    Assert-Equal -Actual $plan.DatabasePath -Expected $expectedDatabasePath -Message "Normalized database path differs."
    Assert-Equal -Actual $plan.ConfigPath -Expected $expectedConfigPath -Message "Normalized config path differs."
    Assert-Equal -Actual $defaultConfigPlan.ConfigPath -Expected $expectedConfigPath -Message "Default ConfigPath is not DataDir\node.toml."
    Assert-Equal -Actual $plan.ImagePath -Expected $expectedImagePath -Message "ImagePath quoting differs."
    $expectedWindowsDirectory = Split-Path -Parent ([Environment]::SystemDirectory)
    Assert-Equal -Actual $plan.ScExecutable -Expected (Join-Path $expectedWindowsDirectory "System32\sc.exe") -Message "sc.exe path differs."
    if (-not [System.IO.Path]::IsPathRooted($plan.ScExecutable)) {
        throw "sc.exe path is not absolute."
    }
    Assert-SequenceEqual -Actual @($plan.ScArguments) -Expected $expectedScArguments -Message "sc.exe arguments differ."
    Assert-SequenceEqual -Actual $afterSnapshot -Expected $beforeSnapshot -Message "ValidateOnly mutated the test tree."
    if (Test-Path -LiteralPath (Join-Path $DataDir "logs")) {
        throw "ValidateOnly created a logs directory."
    }

    $missingConfig = Join-Path $DataDir "missing\node.toml"
    Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $missingConfig } -MessagePattern "does not exist" -Message "Missing config was accepted."
    if (Test-Path -LiteralPath $missingConfig) {
        throw "Validation created a missing config."
    }

    [System.IO.File]::WriteAllText($ConfigPath, "")
    Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must not be empty" -Message "Empty config was accepted."
    [System.IO.File]::WriteAllText($ConfigPath, "network = 'test'")

    $wrongConfig = Join-Path $DataDir "config.toml"
    [System.IO.File]::WriteAllText($wrongConfig, "network = 'test'")
    Grant-NetworkServiceAccess -Path $wrongConfig -Rights ([System.Security.AccessControl.FileSystemRights]::Read)
    Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $wrongConfig } -MessagePattern "canonical node.toml" -Message "Noncanonical config filename was accepted."

    $missingDatabaseDataDir = Join-Path $TestRoot "Missing Database"
    $null = New-Item -ItemType Directory -Path $missingDatabaseDataDir
    $missingDatabaseConfig = Join-Path $missingDatabaseDataDir "node.toml"
    [System.IO.File]::WriteAllText($missingDatabaseConfig, "network = 'test'")
    Grant-NetworkServiceAccess -Path $missingDatabaseDataDir -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Grant-NetworkServiceAccess -Path $missingDatabaseConfig -Rights ([System.Security.AccessControl.FileSystemRights]::Read)
    Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $missingDatabaseDataDir -ConfigPath $missingDatabaseConfig } -MessagePattern "Database directory does not exist" -Message "Missing database directory was accepted."

    $missingNodeBin = Join-Path $NodeDirectory "missing-citrate-node.exe"
    Assert-Throws -Operation { Invoke-Validation -NodeBin $missingNodeBin -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "NodeBin does not exist" -Message "Missing executable was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeDirectory -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must be a file" -Message "Executable directory was accepted as a file."
    $nonExecutableNodeBin = Join-Path $NodeDirectory "citrate-node.bin"
    [System.IO.File]::WriteAllText($nonExecutableNodeBin, "test executable")
    Grant-NetworkServiceAccess -Path $nonExecutableNodeBin -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    Assert-Throws -Operation { Invoke-Validation -NodeBin $nonExecutableNodeBin -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must be a .exe file" -Message "Non-.exe NodeBin was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin ".\citrate-node.exe" -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must be absolute" -Message "Relative path was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin "\\server\share\citrate-node.exe" -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "UNC or device path" -Message "UNC path was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin ("\\?\" + $NodeBin) -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "UNC or device path" -Message "Device path was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin "" -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must not be empty" -Message "Empty NodeBin was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin ($NodeBin + '"') -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "must not contain a quote" -Message "Quoted path was accepted."
    Assert-Throws -Operation { Invoke-Validation -NodeBin ($NodeBin + [char]1) -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "control characters" -Message "Control character was accepted."

    $temporaryDriveName = @("Z", "Y", "X", "W", "V", "U", "T") | Where-Object {
        -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue)
    } | Select-Object -First 1
    if (-not $temporaryDriveName) {
        throw "No unused drive letter was available for the mapped-drive validation test."
    }
    $substExe = Join-Path (Split-Path -Parent ([Environment]::SystemDirectory)) "System32\subst.exe"
    & $substExe ($temporaryDriveName + ":") $TestRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create the substituted-drive validation fixture."
    }
    try {
        $mappedDataDir = $temporaryDriveName + ":\Program Data"
        $mappedConfigPath = Join-Path $mappedDataDir "node.toml"
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $mappedDataDir -ConfigPath $mappedConfigPath
        } -MessagePattern "stable mounted local volume" -Message "A substituted drive was accepted."
    } finally {
        & $substExe ($temporaryDriveName + ":") "/d"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to remove the substituted-drive validation fixture."
        }
    }

    $originalNodeDirectoryAcl = Get-Acl -LiteralPath $NodeDirectory
    try {
        $writableNodeDirectoryAcl = Get-Acl -LiteralPath $NodeDirectory
        $null = $writableNodeDirectoryAcl.AddAccessRule((New-TestAccessRule `
            -Sid $TestAuthenticatedUsersSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Modify)))
        Set-Acl -LiteralPath $NodeDirectory -AclObject $writableNodeDirectoryAcl
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
        } -MessagePattern "grants untrusted write access" -Message "A user-writable executable directory was accepted."
    } finally {
        Set-Acl -LiteralPath $NodeDirectory -AclObject $originalNodeDirectoryAcl
    }

    Assert-NetworkServiceAccessRejected -Path $NodeDirectory -Operation {
        Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    } -MessagePattern "lacks required executable traversal access" -Message "Missing executable traversal access was accepted."
    Assert-NetworkServiceAccessRejected -Path $NodeBin -Operation {
        Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    } -MessagePattern "lacks required executable read/execute access" -Message "Missing executable read/execute access was accepted."
    Assert-NetworkServiceAccessRejected -Path $DataDir -Operation {
        Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    } -MessagePattern "lacks required data directory traversal access" -Message "Missing data-directory traversal access was accepted."
    Assert-NetworkServiceAccessRejected -Path $ConfigPath -Operation {
        Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    } -MessagePattern "lacks required config read access" -Message "Missing config read access was accepted."

    $loadedPlan = . $ServiceScript -ValidateOnly -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
    Assert-Equal -Actual $loadedPlan.ImagePath -Expected $expectedImagePath -Message "Dot-sourced validation plan differs."
    $encodedNativeArguments = @(Invoke-Sc -Executable $ArgumentProbe -Arguments $plan.ScArguments)
    $nativeArguments = @($encodedNativeArguments | ForEach-Object {
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
    })
    Assert-SequenceEqual -Actual $nativeArguments -Expected $expectedScArguments -Message "Native sc.exe argument marshalling differs."
    $knownService = Get-Service | Select-Object -First 1
    if (-not $knownService) {
        throw "No Windows service was available to test existing-service rejection."
    }
    Assert-Throws -Operation { Assert-CitrateServiceAbsent -Name $knownService.Name } -MessagePattern "already exists" -Message "An existing service was accepted for installation."
    $missingServiceName = "CitrateMissing" + [guid]::NewGuid().ToString("N")
    if (Get-CitrateService -Name $missingServiceName) {
        throw "A nonexistent service lookup returned a service."
    }

    $originalCombinedAcl = Get-Acl -LiteralPath $DatabasePath
    try {
        $combinedAcl = Get-Acl -LiteralPath $DatabasePath
        $combinedAcl.SetAccessRuleProtection($true, $false)
        $combinedAcl.PurgeAccessRules($TestNetworkServiceSid)
        $readAndExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        $remainingModifyRights = [System.Security.AccessControl.FileSystemRights](
            ([int64][System.Security.AccessControl.FileSystemRights]::Modify) -band
            (-bnot [int64]$readAndExecute)
        )
        $null = $combinedAcl.AddAccessRule((New-TestAccessRule -Sid $TestNetworkServiceSid -Rights $readAndExecute))
        $null = $combinedAcl.AddAccessRule((New-TestAccessRule -Sid $TestAuthenticatedUsersSid -Rights $remainingModifyRights))
        Set-Acl -LiteralPath $DatabasePath -AclObject $combinedAcl
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
        } -MessagePattern "grants untrusted write access" -Message "Database write access for Authenticated Users was accepted."
    } finally {
        Set-Acl -LiteralPath $DatabasePath -AclObject $originalCombinedAcl
    }

    $originalInheritableDatabaseAcl = Get-Acl -LiteralPath $DatabasePath
    try {
        $inheritableDatabaseAcl = Get-Acl -LiteralPath $DatabasePath
        $inheritableWriteRule = New-TestAccessRule `
            -Sid $TestAuthenticatedUsersSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Modify) `
            -InheritanceFlags ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) `
            -PropagationFlags ([System.Security.AccessControl.PropagationFlags]::InheritOnly)
        $null = $inheritableDatabaseAcl.AddAccessRule($inheritableWriteRule)
        Set-Acl -LiteralPath $DatabasePath -AclObject $inheritableDatabaseAcl
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
        } -MessagePattern "grants untrusted write access" -Message "Inheritable database write access for Authenticated Users was accepted."
    } finally {
        Set-Acl -LiteralPath $DatabasePath -AclObject $originalInheritableDatabaseAcl
    }

    $unsafeDatabaseFile = Join-Path $DatabasePath "unsafe-child.dat"
    [System.IO.File]::WriteAllText($unsafeDatabaseFile, "test")
    try {
        $unsafeDatabaseFileAcl = Get-Acl -LiteralPath $unsafeDatabaseFile
        $null = $unsafeDatabaseFileAcl.AddAccessRule((New-TestAccessRule `
            -Sid $TestAuthenticatedUsersSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Modify)))
        Set-Acl -LiteralPath $unsafeDatabaseFile -AclObject $unsafeDatabaseFileAcl
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
        } -MessagePattern "grants untrusted write access" -Message "An unsafe existing database child was accepted."
    } finally {
        Remove-Item -LiteralPath $unsafeDatabaseFile -Force
    }

    $databaseJunctionPath = Join-Path $DatabasePath "unsafe-link"
    $databaseJunctionCreated = $false
    try {
        $null = New-Item -ItemType Junction -Path $databaseJunctionPath -Target $NodeDirectory
        $databaseJunctionCreated = $true
        Assert-Throws -Operation {
            Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath
        } -MessagePattern "Database directory must not contain a reparse point" -Message "A database-child reparse point was accepted."
    } catch {
        if ($databaseJunctionCreated) {
            throw
        }
        Write-Host "SKIP: Junction creation is unavailable; database-child reparse validation was not exercised."
    } finally {
        if ($databaseJunctionCreated -and [System.IO.Directory]::Exists($databaseJunctionPath)) {
            [System.IO.Directory]::Delete($databaseJunctionPath)
        }
    }

    $originalDataAcl = Get-Acl -LiteralPath $DataDir
    $originalOrderedDatabaseAcl = Get-Acl -LiteralPath $DatabasePath
    try {
        $inheritOnlyDeny = New-TestAccessRule `
            -Sid $TestNetworkServiceSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Modify) `
            -InheritanceFlags ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) `
            -PropagationFlags ([System.Security.AccessControl.PropagationFlags]::InheritOnly) `
            -AccessControlType ([System.Security.AccessControl.AccessControlType]::Deny)
        $orderedDataAcl = Get-Acl -LiteralPath $DataDir
        $null = $orderedDataAcl.AddAccessRule($inheritOnlyDeny)
        Set-Acl -LiteralPath $DataDir -AclObject $orderedDataAcl
        Assert-NetworkServiceAccess `
            -Path $DatabasePath `
            -RequiredRights ([System.Security.AccessControl.FileSystemRights]::Modify) `
            -Description "database modify"
    } finally {
        Set-Acl -LiteralPath $DataDir -AclObject $originalDataAcl
        Set-Acl -LiteralPath $DatabasePath -AclObject $originalOrderedDatabaseAcl
    }

    $originalRootAcl = Get-Acl -LiteralPath $TestRoot
    try {
        $inheritedDeny = New-TestAccessRule `
            -Sid $TestNetworkServiceSid `
            -Rights ([System.Security.AccessControl.FileSystemRights]::Modify) `
            -InheritanceFlags ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) `
            -AccessControlType ([System.Security.AccessControl.AccessControlType]::Deny)
        $orderedRootAcl = Get-Acl -LiteralPath $TestRoot
        $null = $orderedRootAcl.AddAccessRule($inheritedDeny)
        Set-Acl -LiteralPath $TestRoot -AclObject $orderedRootAcl

        $databaseRules = (Get-Acl -LiteralPath $DatabasePath).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        $applicableInheritedDeny = @($databaseRules | Where-Object {
            $_.IsInherited -and
            $_.IdentityReference.Value -eq $TestNetworkServiceSid.Value -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
            ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
        })
        if ($applicableInheritedDeny.Count -eq 0) {
            throw "The ACL ordering test did not create an applicable inherited deny ACE."
        }
        Assert-NetworkServiceAccess `
            -Path $DatabasePath `
            -RequiredRights ([System.Security.AccessControl.FileSystemRights]::Modify) `
            -Description "database modify"
    } finally {
        Set-Acl -LiteralPath $TestRoot -AclObject $originalRootAcl
    }

    $originalDatabaseAcl = Get-Acl -LiteralPath $DatabasePath
    try {
        $blockedAcl = Get-Acl -LiteralPath $DatabasePath
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $TestNetworkServiceSid,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        $null = $blockedAcl.AddAccessRule($denyRule)
        Set-Acl -LiteralPath $DatabasePath -AclObject $blockedAcl
        Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $DataDir -ConfigPath $ConfigPath } -MessagePattern "denied required database modify access" -Message "Applicable deny ACE was ignored."
    } finally {
        Set-Acl -LiteralPath $DatabasePath -AclObject $originalDatabaseAcl
    }

    $junctionPath = Join-Path $TestRoot "Reparse Data"
    $junctionCreated = $false
    try {
        $null = New-Item -ItemType Junction -Path $junctionPath -Target $DataDir
        $junctionCreated = $true
        Assert-Throws -Operation { Invoke-Validation -NodeBin $NodeBin -DataDir $junctionPath -ConfigPath (Join-Path $junctionPath "node.toml") } -MessagePattern "reparse point" -Message "Reparse-point data directory was accepted."
    } catch {
        if ($junctionCreated) {
            throw
        }
        Write-Host "SKIP: Junction creation is unavailable; reparse-point validation was not exercised."
    } finally {
        if ($junctionCreated -and [System.IO.Directory]::Exists($junctionPath)) {
            [System.IO.Directory]::Delete($junctionPath)
        }
    }

    Write-Output "OK: citrate-node service validation tests passed."
} finally {
    if (Test-Path -LiteralPath $TestRoot) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}
