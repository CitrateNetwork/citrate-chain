param(
    [string]$Version = "0.1.0-p2",
    [string]$OutputDir = "",
    [string]$AiBundleDir = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..\..\..")
$ReleasePacket = Join-Path $ProjectRoot "gui\citrate_learning_center\release"
$Wxs = Join-Path $ReleasePacket "packaging\windows\CitrateLearningCenter.wxs"
$ProductVersion = ($Version -replace "-.*$", "")
$AiBundleWxs = Join-Path ([System.IO.Path]::GetTempPath()) ("CitrateLearningCenter.AiBundle.{0}.wxs" -f [guid]::NewGuid().ToString("N"))

function New-WixId {
    param(
        [string]$Prefix,
        [string]$Value
    )

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = [System.BitConverter]::ToString($sha1.ComputeHash($bytes)).Replace("-", "")
        return "{0}{1}" -f $Prefix, $hash.Substring(0, 24)
    } finally {
        $sha1.Dispose()
    }
}

function Escape-WixXml {
    param([string]$Value)
    return [System.Security.SecurityElement]::Escape($Value)
}

function Get-ManifestValue {
    param(
        [string]$ManifestPath,
        [string]$Key
    )

    $pattern = '^{0}\s*=\s*"(.*)"\s*$' -f [regex]::Escape($Key)
    foreach ($line in Get-Content -LiteralPath $ManifestPath) {
        if ($line -match $pattern) {
            return $matches[1]
        }
    }
    return ""
}

function Test-AiBundle {
    param([string]$BundleDir)

    if ([string]::IsNullOrWhiteSpace($BundleDir)) {
        return
    }

    $resolvedBundle = (Resolve-Path $BundleDir).Path
    $manifestPath = Join-Path $resolvedBundle "BUNDLE_MANIFEST.toml"
    if (!(Test-Path $manifestPath)) {
        throw "AI bundle directory is missing BUNDLE_MANIFEST.toml: $resolvedBundle"
    }

    $weightsPath = Get-ManifestValue -ManifestPath $manifestPath -Key "weights_path"
    $runtimePath = Get-ManifestValue -ManifestPath $manifestPath -Key "runtime_path"
    $weightsSha256 = Get-ManifestValue -ManifestPath $manifestPath -Key "weights_sha256"
    $runtimeSha256 = Get-ManifestValue -ManifestPath $manifestPath -Key "runtime_sha256"
    $licenseFile = Get-ManifestValue -ManifestPath $manifestPath -Key "license_file"
    $modelCard = Get-ManifestValue -ManifestPath $manifestPath -Key "model_card"

    if ([string]::IsNullOrWhiteSpace($weightsPath) -or
        [string]::IsNullOrWhiteSpace($runtimePath) -or
        [string]::IsNullOrWhiteSpace($weightsSha256) -or
        [string]::IsNullOrWhiteSpace($runtimeSha256) -or
        [string]::IsNullOrWhiteSpace($licenseFile) -or
        [string]::IsNullOrWhiteSpace($modelCard)) {
        throw "AI bundle manifest is incomplete and must define weights_path, runtime_path, weights_sha256, runtime_sha256, license_file, and model_card: $manifestPath"
    }

    $weightsAbs = Join-Path $resolvedBundle $weightsPath
    $runtimeAbs = Join-Path $resolvedBundle $runtimePath
    $licenseAbs = Join-Path $resolvedBundle $licenseFile
    $modelCardAbs = Join-Path $resolvedBundle $modelCard

    foreach ($path in @($weightsAbs, $runtimeAbs, $licenseAbs, $modelCardAbs)) {
        if (!(Test-Path $path -PathType Leaf)) {
            throw "AI bundle file not found: $path"
        }
    }

    $actualWeightsSha256 = (Get-FileHash -Algorithm SHA256 $weightsAbs).Hash.ToLowerInvariant()
    $actualRuntimeSha256 = (Get-FileHash -Algorithm SHA256 $runtimeAbs).Hash.ToLowerInvariant()
    if ($actualWeightsSha256 -ne $weightsSha256.ToLowerInvariant()) {
        throw "AI bundle weights checksum mismatch for $weightsAbs"
    }
    if ($actualRuntimeSha256 -ne $runtimeSha256.ToLowerInvariant()) {
        throw "AI bundle runtime checksum mismatch for $runtimeAbs"
    }
}

function New-AiBundleFragment {
    param(
        [string]$BundleDir,
        [string]$OutputPath
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('<?xml version="1.0" encoding="UTF-8"?>')
    $lines.Add('<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">')

    if ([string]::IsNullOrWhiteSpace($BundleDir)) {
        $lines.Add('  <Fragment>')
        $lines.Add('    <ComponentGroup Id="AiBundleComponents" />')
        $lines.Add('  </Fragment>')
        $lines.Add('</Wix>')
        Set-Content -Path $OutputPath -Value $lines -Encoding UTF8
        return
    }

    $resolvedBundle = (Resolve-Path $BundleDir).Path
    Test-AiBundle -BundleDir $resolvedBundle

    $componentIds = New-Object System.Collections.Generic.List[string]

    function Add-DirectoryTree {
        param(
            [string]$DirectoryPath,
            [string]$DirectoryId,
            [string]$DirectoryName,
            [string]$Indent
        )

        $escapedName = Escape-WixXml $DirectoryName
        $lines.Add("$Indent<Directory Id=""$DirectoryId"" Name=""$escapedName"">")

        foreach ($childDir in Get-ChildItem -LiteralPath $DirectoryPath -Directory | Sort-Object Name) {
            $childId = New-WixId "AiBundleDir" $childDir.FullName
            Add-DirectoryTree -DirectoryPath $childDir.FullName -DirectoryId $childId -DirectoryName $childDir.Name -Indent "$Indent  "
        }

        foreach ($childFile in Get-ChildItem -LiteralPath $DirectoryPath -File | Sort-Object Name) {
            $componentId = New-WixId "AiBundleCmp" $childFile.FullName
            $fileId = New-WixId "AiBundleFile" $childFile.FullName
            $sourcePath = Escape-WixXml $childFile.FullName

            $lines.Add("$Indent  <Component Id=""$componentId"" Guid=""*"">")
            $lines.Add("$Indent    <File Id=""$fileId"" Source=""$sourcePath"" KeyPath=""yes"" />")
            $lines.Add("$Indent  </Component>")
            $componentIds.Add($componentId) | Out-Null
        }

        $lines.Add("$Indent</Directory>")
    }

    $bundleName = Split-Path -Leaf $resolvedBundle
    $bundleDirId = New-WixId "AiBundleRoot" $resolvedBundle

    $lines.Add('  <Fragment>')
    $lines.Add('    <DirectoryRef Id="AIBUNDLESCONTAINER">')
    Add-DirectoryTree -DirectoryPath $resolvedBundle -DirectoryId $bundleDirId -DirectoryName $bundleName -Indent '      '
    $lines.Add('    </DirectoryRef>')
    $lines.Add('  </Fragment>')
    $lines.Add('  <Fragment>')
    $lines.Add('    <ComponentGroup Id="AiBundleComponents">')
    foreach ($componentId in $componentIds) {
        $lines.Add("      <ComponentRef Id=""$componentId"" />")
    }
    $lines.Add('    </ComponentGroup>')
    $lines.Add('  </Fragment>')
    $lines.Add('</Wix>')

    Set-Content -Path $OutputPath -Value $lines -Encoding UTF8
}

if ($OutputDir -eq "") {
    $OutputDir = Join-Path $ProjectRoot "dist\learning-center"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if ($AiBundleDir -eq "") {
    $AiBundleDir = $env:CITRATE_AI_BUNDLE_DIR
}

New-AiBundleFragment -BundleDir $AiBundleDir -OutputPath $AiBundleWxs

Push-Location $ProjectRoot
try {
    cargo build --release -p citrate-learning-center
} finally {
    Pop-Location
}

$BinaryPath = Join-Path $ProjectRoot "target\release\citrate-learning-center.exe"
if (!(Test-Path $BinaryPath)) {
    throw "Learning Center binary not found at $BinaryPath"
}

$MsiPath = Join-Path $OutputDir "CitrateLearningCenter-$Version-windows-x64.msi"

$Wix = Get-Command wix -ErrorAction SilentlyContinue
if ($Wix) {
    & $Wix.Source build $Wxs $AiBundleWxs `
        -d ProductVersion=$ProductVersion `
        -d BinaryPath=$BinaryPath `
        -d ReleasePacketPath=$ReleasePacket `
        -o $MsiPath
} else {
    $Candle = Get-Command candle.exe -ErrorAction SilentlyContinue
    $Light = Get-Command light.exe -ErrorAction SilentlyContinue
    if (!$Candle -or !$Light) {
        throw "WiX is required. Install WiX v4 (wix) or WiX v3 (candle.exe/light.exe), then rerun this script."
    }

    $MainObjPath = Join-Path $OutputDir "CitrateLearningCenter.wixobj"
    $AiObjPath = Join-Path $OutputDir "CitrateLearningCenter.AiBundle.wixobj"
    & $Candle.Source $Wxs `
        -dProductVersion=$ProductVersion `
        -dBinaryPath=$BinaryPath `
        -dReleasePacketPath=$ReleasePacket `
        -out $MainObjPath
    & $Candle.Source $AiBundleWxs -out $AiObjPath
    & $Light.Source $MainObjPath $AiObjPath -out $MsiPath
}

Get-FileHash -Algorithm SHA256 $MsiPath |
    ForEach-Object { "$($_.Hash.ToLowerInvariant())  $MsiPath" } |
    Set-Content -NoNewline "$MsiPath.sha256"

Remove-Item -Force $AiBundleWxs -ErrorAction SilentlyContinue

Write-Output $MsiPath
