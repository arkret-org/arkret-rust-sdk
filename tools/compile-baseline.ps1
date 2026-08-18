[CmdletBinding()]
param(
    [string]$WorkspaceRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateRange(1, 9)]
    [int]$Runs = 3,
    [string]$OutputRoot = "",
    [switch]$IncludeIncremental,
    [string[]]$Scenario = @("umbrella", "floria", "bridges", "garth")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$workspace = (Resolve-Path -LiteralPath $WorkspaceRoot).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $workspace "_compile_analysis\baseline"
}
$output = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $output | Out-Null

$env:CARGO_INCREMENTAL = "1"
$env:CARGO_PROFILE_DEV_DEBUG = "0"
$env:CARGO_TERM_COLOR = "never"
$env:RUSTUP_TOOLCHAIN = "1.97"

$scenarios = @{
    "umbrella" = @{
        Root = Join-Path $workspace "arkret-rust-sdk"
        Args = @("check", "-p", "arkret", "--no-default-features", "--locked", "--timings")
    }
    "floria" = @{
        Root = Join-Path $workspace "floria"
        Args = @("check", "--locked", "--timings")
    }
    "bridges" = @{
        Root = Join-Path $workspace "bridges"
        Args = @("check", "--locked", "--timings")
    }
    "garth" = @{
        Root = Join-Path $workspace "garth"
        Args = @("check", "--locked", "--timings")
    }
}

function Invoke-CargoMeasurement {
    param(
        [string]$Name,
        [string]$Root,
        [string[]]$CargoArgs,
        [string]$TargetDirectory,
        [switch]$CaptureArtifacts
    )

    New-Item -ItemType Directory -Force -Path $TargetDirectory | Out-Null
    $env:CARGO_TARGET_DIR = $TargetDirectory
    $arguments = @($CargoArgs)
    if ($CaptureArtifacts) {
        $arguments = @($CargoArgs | Where-Object { $_ -ne "--timings" })
        $arguments += "--message-format=json"
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lines = & cargo @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $stopwatch.Stop()
    if ($exitCode -ne 0) {
        $lines | ForEach-Object { Write-Host $_ }
        throw "cargo measurement '$Name' failed with exit code $exitCode"
    }

    $compiled = @()
    if ($CaptureArtifacts) {
        foreach ($line in $lines) {
            try {
                $message = $line | ConvertFrom-Json -ErrorAction Stop
                if ($message.reason -eq "compiler-artifact" -and -not $message.fresh) {
                    $compiled += $message.target.name
                }
            } catch {
                continue
            }
        }
    }

    return [ordered]@{
        name = $Name
        root = $Root
        target_directory = $TargetDirectory
        elapsed_seconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
        compiled_targets = @($compiled | Sort-Object -Unique)
    }
}

$records = @()
foreach ($name in $Scenario) {
    if (-not $scenarios.ContainsKey($name)) {
        throw "unknown scenario '$name'"
    }
    $definition = $scenarios[$name]
    if (-not (Test-Path -LiteralPath $definition.Root)) {
        throw "scenario '$name' repository is missing: $($definition.Root)"
    }
    for ($run = 1; $run -le $Runs; $run++) {
        $target = Join-Path $output "$name\cold-$run\target"
        Write-Host "[$name] cold run $run/$Runs"
        $records += Invoke-CargoMeasurement -Name $name -Root $definition.Root `
            -CargoArgs $definition.Args -TargetDirectory $target
    }
}

$summary = @()
foreach ($name in $Scenario) {
    $samples = @($records | Where-Object { $_.name -eq $name } | ForEach-Object { $_.elapsed_seconds } | Sort-Object)
    $middle = [Math]::Floor($samples.Count / 2)
    $median = if ($samples.Count % 2 -eq 1) {
        $samples[$middle]
    } else {
        ($samples[$middle - 1] + $samples[$middle]) / 2
    }
    $summary += [ordered]@{
        name = $name
        samples_seconds = $samples
        median_seconds = [Math]::Round($median, 3)
    }
}

if ($IncludeIncremental) {
    $representative = Join-Path $workspace "arkret-rust-sdk\crates\models-collaboration\src\events_payloads\message.rs"
    if (-not (Test-Path -LiteralPath $representative)) {
        throw "representative model file is missing: $representative"
    }
    $originalTimestamp = (Get-Item -LiteralPath $representative).LastWriteTimeUtc
    try {
        foreach ($name in @("floria", "garth")) {
            $definition = $scenarios[$name]
            $target = Join-Path $output "$name\incremental\target"
            Invoke-CargoMeasurement -Name "$name-warmup" -Root $definition.Root `
                -CargoArgs $definition.Args -TargetDirectory $target | Out-Null
            (Get-Item -LiteralPath $representative).LastWriteTimeUtc = [DateTime]::UtcNow
            $records += Invoke-CargoMeasurement -Name "$name-incremental" -Root $definition.Root `
                -CargoArgs $definition.Args -TargetDirectory $target -CaptureArtifacts
        }
    } finally {
        (Get-Item -LiteralPath $representative).LastWriteTimeUtc = $originalTimestamp
    }
}

$result = [ordered]@{
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    rust_toolchain = $env:RUSTUP_TOOLCHAIN
    cargo_profile = "dev"
    cargo_incremental = $env:CARGO_INCREMENTAL
    runs = $Runs
    summary = $summary
    records = $records
}
$result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $output "summary.json")
$summary | Format-Table -AutoSize
