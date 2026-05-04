param(
    [string]$InstallDir = "$env:ProgramFiles\Citrate Learning Center"
)

$ErrorActionPreference = "Stop"

$Exe = Join-Path $InstallDir "citrate-learning-center.exe"
$ReleaseDir = Join-Path $InstallDir "release"
$AiBundlesRoot = Join-Path $InstallDir "ai\bundles"

if (!(Test-Path $Exe)) { throw "Missing installed executable: $Exe" }
if (!(Test-Path (Join-Path $ReleaseDir "INSTALL.md"))) { throw "Missing INSTALL.md in release packet" }
if (!(Test-Path (Join-Path $ReleaseDir "P2_RELEASE_MANIFEST.toml"))) { throw "Missing P2_RELEASE_MANIFEST.toml" }
if (!(Test-Path (Join-Path $ReleaseDir "P2_CLOSURE_REPORT_2026-04-10.md"))) { throw "Missing P2 closure report" }
if (!(Test-Path (Join-Path $ReleaseDir "AI_GUIDE_MANIFEST.toml"))) { throw "Missing AI guide manifest" }
if (!(Test-Path (Join-Path $ReleaseDir "ai\GEMMA4_E2B_CANDIDATE_MANIFEST.toml"))) { throw "Missing Gemma candidate manifest" }
if (!(Test-Path (Join-Path $ReleaseDir "examples\credential-slip-sample.html"))) { throw "Missing credential slip sample" }
if (!(Test-Path (Join-Path $ReleaseDir "examples\guardian-setup-packet-sample.html"))) { throw "Missing guardian setup packet sample" }

$Policy = Get-ItemProperty -Path "HKLM:\Software\Citrate\LearningCenter" -ErrorAction SilentlyContinue
if (!$Policy -or $Policy.InstalledBy -ne "P2ManagedInstaller") {
    throw "Missing P2ManagedInstaller registry marker"
}

if ($env:CITRATE_DEMO_MODE -eq "true") {
    throw "CITRATE_DEMO_MODE must not be true in a pilot lab smoke"
}

$ExpectAiBundle = $env:CITRATE_EXPECT_AI_BUNDLE -eq "true"
if ($ExpectAiBundle) {
    $Manifest = Get-ChildItem $AiBundlesRoot -Recurse -Filter BUNDLE_MANIFEST.toml -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$Manifest) {
        throw "Expected an installed AI bundle manifest under $AiBundlesRoot"
    }
} elseif (Test-Path $AiBundlesRoot) {
    $BundledWeights = Get-ChildItem $AiBundlesRoot -Recurse -Include *.gguf,*.safetensors,*.bin -ErrorAction SilentlyContinue
    if ($BundledWeights) {
        throw "P-2 MSI must not silently bundle Gemma weights: $($BundledWeights[0].FullName)"
    }
}

Write-Output "OK: P-2 Windows lab smoke passed for $InstallDir"
