param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsDir,
    [switch]$Check
)

# Internal Rust-generation layer. Contributors and CI should normally invoke
# sync-spec.ps1 so every generated Rust surface stays aligned.

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

# Both modes generate into a scratch tree first. A generator that fails part
# way through - an artifact the Rust codegen rejects, a rustfmt error, an
# output a generator did not write - must not leave the checkout holding some
# refreshed files and some stale ones, because the half-refreshed tree looks
# exactly like a deliberate partial commit and has to be unpicked by hand.
# Nothing reaches the tracked tree until every generator, rustfmt and the
# manifest completeness check have all succeeded.
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'arkret-sdk-generated-' + [System.Guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$targetRoot = $temporaryRoot

try {
    $eventOutput = Join-Path $targetRoot 'crates/wire/src/generated/event_kinds.rs'
    $requirementsOutput = Join-Path $targetRoot 'crates/wire/src/generated/profile_requirements.rs'
    $latticeBindingsOutput = Join-Path $targetRoot 'crates/lattice-registry/src/generated/lattice_bindings.rs'
    $mlsSecurityFrontierOutput = Join-Path $targetRoot 'crates/state/src/generated/mls_security_frontier.rs'
    @(
        $eventOutput,
        $requirementsOutput,
        $latticeBindingsOutput
        $mlsSecurityFrontierOutput
    ) | ForEach-Object {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $_) | Out-Null
    }

    & (Join-Path $PSScriptRoot 'generate-sdk-event-kinds.ps1') -ArtifactsDir $artifacts -OutputPath $eventOutput
    & python (Join-Path $PSScriptRoot 'generate-sdk-profile-requirements.py') --artifacts-dir $artifacts --output $requirementsOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'profile requirement generation failed'
    }
    & python (Join-Path $PSScriptRoot 'generate-sdk-lattice-bindings.py') --artifacts-dir $artifacts --output $latticeBindingsOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'lattice binding generation failed'
    }

    & python (Join-Path $PSScriptRoot 'generate-mls-security-frontier.py') --artifacts-dir $artifacts --output $mlsSecurityFrontierOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'MLS security-frontier generation failed'
    }

    & python (Join-Path $PSScriptRoot 'generate-current-result-schemas.py') --artifacts-dir $artifacts --output (Join-Path $targetRoot 'crates/schema/src/generated/current_result_schemas.rs')
    if ($LASTEXITCODE -ne 0) { throw 'Current-result schema generation failed' }

    & cargo run --quiet --manifest-path (Join-Path $PSScriptRoot 'spec-codegen/Cargo.toml') -- --artifacts-dir $artifacts --output-root $targetRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Rust spec code generation failed'
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

    if (!$Check) {
        # Every declared output exists and is formatted. Copy is byte-for-byte
        # so the LF endings the generators pin survive the move, and it happens
        # only after the last thing that can fail has already succeeded.
        foreach ($relative in $declaredOutputs) {
            $generated = Join-Path $targetRoot $relative
            $tracked = Join-Path $repoRoot $relative
            $generatedBytes = [System.IO.File]::ReadAllBytes($generated)
            if ((Test-Path -LiteralPath $tracked) -and
                [System.Linq.Enumerable]::SequenceEqual(
                    $generatedBytes,
                    [System.IO.File]::ReadAllBytes($tracked)
                )) {
                # Keep unchanged output timestamps stable for downstream build gates.
                continue
            }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tracked) | Out-Null
            [System.IO.File]::WriteAllBytes($tracked, $generatedBytes)
        }
    }

    $generatedRoots = @(
        'crates/wire/src/generated',
        'crates/wire/src/error_codes',
        'crates/schema/src/generated',
        'crates/lattice-registry/src/generated'
        'crates/state/src/generated'
    )
    # Directories a generator actually writes into are derived from the manifest
    # rather than only listed here, so retiring or relocating an output cannot
    # leave its old directory unscanned. The literals above stay as the floor:
    # a directory whose last declared output was removed must keep being swept.
    $generatedRoots = @(
        $generatedRoots + @(
            $declaredOutputs | ForEach-Object { ($_ -replace '/[^/]+$', '') }
        ) | Sort-Object -Unique
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
            if ($relative -in $declaredOutputs) {
                return
            }
            # A `@generated` file the manifest no longer declares is a leftover
            # of a removed generator entry. Synchronizing removes it in the same
            # pass that writes the current outputs, so a generation run leaves
            # exactly the declared set behind. `-Check` must not mutate the
            # tracked tree, so there it stays a hard CI failure.
            if ($Check) {
                throw "stale or undeclared generated output: $relative"
            }
            Remove-Item -LiteralPath $_.FullName -Force
            Write-Host "Removed stale generated output: $relative"
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
