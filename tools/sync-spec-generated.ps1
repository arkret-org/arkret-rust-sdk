param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDir,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$artifacts = (Resolve-Path -LiteralPath $ArtifactsDir).Path
$manifestPath = Join-Path $PSScriptRoot 'spec-generation-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

if ($manifest.version -ne 1) {
    throw "unsupported generation manifest version: $($manifest.version)"
}

$declaredOutputs = @(
    $manifest.entries |
        ForEach-Object { $_.outputs } |
        ForEach-Object { [string]$_ }
)
$duplicates = @(
    $declaredOutputs |
        Group-Object |
        Where-Object { $_.Count -ne 1 }
)
if ($duplicates.Count -ne 0) {
    throw "generation manifest declares duplicate outputs: $($duplicates.Name -join ', ')"
}

$targetRoot = $repoRoot
$temporaryRoot = $null
if ($Check) {
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'arkret-sdk-generated-' + [System.Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $targetRoot = $temporaryRoot
}

try {
    $eventOutput = Join-Path $targetRoot 'crates/wire/src/generated/event_kinds.rs'
    $profileOutput = Join-Path $targetRoot 'crates/policy/src/generated/profiles.rs'
    $requirementsOutput = Join-Path $targetRoot 'crates/schema/src/generated/profile_requirements.rs'
    @(
        $eventOutput,
        $profileOutput,
        $requirementsOutput
    ) | ForEach-Object {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $_) | Out-Null
    }

    & (Join-Path $PSScriptRoot 'generate-sdk-event-kinds.ps1') -ArtifactsDir $artifacts -OutputPath $eventOutput
    & (Join-Path $PSScriptRoot 'generate-sdk-profile-constants.ps1') -ArtifactsDir $artifacts -OutputPath $profileOutput
    & (Join-Path $PSScriptRoot 'generate-sdk-profile-requirements.ps1') -ArtifactsDir $artifacts -OutputPath $requirementsOutput

    & python (Join-Path $PSScriptRoot 'generate-registry-types.py') --artifacts-dir $artifacts --output-root $targetRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'registry type generation failed'
    }

    $allOutputs = @(
        $declaredOutputs |
            ForEach-Object { Join-Path $targetRoot $_ }
    )
    & rustfmt +nightly --edition 2024 --config-path (Join-Path $repoRoot '.rustfmt.toml') @allOutputs
    if ($LASTEXITCODE -ne 0) {
        throw 'rustfmt failed for registry generated outputs'
    }

    foreach ($relative in $declaredOutputs) {
        $generated = Join-Path $targetRoot $relative
        if (!(Test-Path -LiteralPath $generated)) {
            throw "generator did not produce declared output: $relative"
        }
        if ($Check) {
            $tracked = Join-Path $repoRoot $relative
            if (!(Test-Path -LiteralPath $tracked)) {
                throw "missing generated output: $relative"
            }
            $generatedBytes = [System.IO.File]::ReadAllBytes($generated)
            $trackedBytes = [System.IO.File]::ReadAllBytes($tracked)
            if (![System.Linq.Enumerable]::SequenceEqual($generatedBytes, $trackedBytes)) {
                throw "generated output drift: $relative"
            }
        }
    }

    $generatedRoots = @(
        'crates/wire/src/generated',
        'crates/wire/src/error_codes',
        'crates/policy/src/generated',
        'crates/schema/src/generated'
    )
    foreach ($relativeRoot in $generatedRoots) {
        $root = Join-Path $repoRoot $relativeRoot
        if (!(Test-Path -LiteralPath $root)) {
            continue
        }
        Get-ChildItem -LiteralPath $root -File -Filter '*.rs' | ForEach-Object {
            $text = Get-Content -LiteralPath $_.FullName -Raw
            if ($text -notmatch '@generated') {
                return
            }
            $relative = $_.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
            if ($relative -notin $declaredOutputs) {
                throw "stale or undeclared generated output: $relative"
            }
        }
    }

    if ($Check) {
        Write-Host "Generated registry surfaces match $artifacts"
    } else {
        Write-Host "Synchronized generated registry surfaces from $artifacts"
    }
}
finally {
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
