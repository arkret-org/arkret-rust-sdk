param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDir,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$artifacts = (Resolve-Path -LiteralPath $ArtifactsDir).Path
$rustSync = Join-Path $PSScriptRoot 'sync-spec-generated.ps1'

function Invoke-RustGeneratedSync {
    $rustArguments = @{
        ArtifactsDir = $artifacts
    }
    if ($Check) {
        $rustArguments.Check = $true
    }
    & $rustSync @rustArguments
}

if (!$Check) {
    Invoke-RustGeneratedSync
    Write-Host "Synchronized all SDK spec-derived surfaces from $artifacts"
    return
}

$syncFailures = @()
try {
    Invoke-RustGeneratedSync
}
catch {
    $syncFailures += "Rust generated surfaces: $($_.Exception.Message)"
}
if ($syncFailures.Count -ne 0) {
    throw ("SDK spec-derived surface check failed:`n- " + ($syncFailures -join "`n- "))
}

Write-Host "All SDK spec-derived surfaces match $artifacts"
