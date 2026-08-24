param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDir,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$artifacts = (Resolve-Path -LiteralPath $ArtifactsDir).Path
$rustSync = Join-Path $PSScriptRoot 'sync-spec-generated.ps1'
$embeddedSync = Join-Path $PSScriptRoot 'refresh-embedded-artifacts.py'

function Invoke-RustGeneratedSync {
    $rustArguments = @{
        ArtifactsDir = $artifacts
    }
    if ($Check) {
        $rustArguments.Check = $true
    }
    & $rustSync @rustArguments
}

function Invoke-EmbeddedArtifactSync {
    $embeddedArguments = @($embeddedSync)
    if ($Check) {
        $embeddedArguments += '--check'
    }
    $embeddedArguments += $artifacts
    & python @embeddedArguments
    if ($LASTEXITCODE -ne 0) {
        throw "embedded artifact synchronization failed with exit code $LASTEXITCODE"
    }
}

if (!$Check) {
    Invoke-RustGeneratedSync
    Invoke-EmbeddedArtifactSync
    Write-Host "Synchronized all SDK spec-derived surfaces from $artifacts"
    return
}

# Check both independent layers even when one has drifted, so a single CI run
# reports the complete synchronization state.
$syncFailures = @()
try {
    Invoke-RustGeneratedSync
}
catch {
    $syncFailures += "Rust generated surfaces: $($_.Exception.Message)"
}
try {
    Invoke-EmbeddedArtifactSync
}
catch {
    $syncFailures += "embedded artifact resources: $($_.Exception.Message)"
}

if ($syncFailures.Count -ne 0) {
    throw ("SDK spec-derived surface check failed:`n- " + ($syncFailures -join "`n- "))
}

Write-Host "All SDK spec-derived surfaces match $artifacts"
