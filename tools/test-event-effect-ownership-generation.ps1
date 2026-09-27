param(
    [string]$ArtifactsDir = (Join-Path $PSScriptRoot '..\..\arkret-spec\spec\v1\artifacts')
)

$ErrorActionPreference = 'Stop'
$generator = Join-Path $PSScriptRoot 'generate-sdk-event-kinds.ps1'
$source = Get-Content -LiteralPath (Join-Path $ArtifactsDir 'registry\contract-registry.json') -Raw
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('arkret-effect-generator-' + [guid]::NewGuid().ToString('N'))
$registryDir = Join-Path $fixtureRoot 'registry'
$registryPath = Join-Path $registryDir 'contract-registry.json'
$outputPath = Join-Path $fixtureRoot 'event_kinds.rs'
New-Item -ItemType Directory -Path $registryDir | Out-Null

# Every mutation must be rejected before a Rust output can be published.
$cases = @(
    @{ Name = 'unknown owner'; Mutate = { param($a) $a.event_kind_registry.event_kinds[0].result_effect_ownership = [PSCustomObject]@{ kind = 'unknown' } }; Error = 'unknown effect ownership' },
    @{ Name = 'missing persistent owner'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).result_effect_ownership = $null }; Error = 'missing closed' },
    @{ Name = 'typed private scope'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).wire_scope = 'actor_private_event' }; Error = 'requires durable reducer' },
    @{ Name = 'typed nonreducer'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).reducer_input = $false }; Error = 'requires durable reducer' },
    @{ Name = 'typed empty writes'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).result_writes = @() }; Error = 'requires durable reducer' },
    @{ Name = 'nonboolean reducer'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).reducer_input = 'true' }; Error = 'must be a boolean' },
    @{ Name = 'unknown result family'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).result_writes[0].result_family = 'unregistered_family' }; Error = 'unknown result family' },
    @{ Name = 'open owner object'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).result_effect_ownership | Add-Member -NotePropertyName extra -NotePropertyValue 'unexpected' }; Error = 'must be a closed' },
    @{ Name = 'private shared reducer'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'private_service_effect' } | Select-Object -First 1).reducer_input = $true }; Error = 'cannot be a shared reducer' },
    @{ Name = 'private typed writes'; Mutate = { param($a) $rows = $a.event_kind_registry.event_kinds; ($rows | Where-Object { $_.result_effect_ownership.kind -eq 'private_service_effect' } | Select-Object -First 1) | Add-Member -Force -NotePropertyName result_writes -NotePropertyValue @((($rows | Where-Object { $_.result_effect_ownership.kind -eq 'typed_result_writer' } | Select-Object -First 1).result_writes[0])) }; Error = 'must not declare typed' },
    @{ Name = 'authority private scope'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'authority_commit_effect' } | Select-Object -First 1).wire_scope = 'actor_private_event' }; Error = 'authority effect requires' },
    @{ Name = 'unknown service owner'; Mutate = { param($a) ($a.event_kind_registry.event_kinds | Where-Object { $_.result_effect_ownership.kind -eq 'private_service_effect' } | Select-Object -First 1).result_effect_ownership.service_contract_id = 'unregistered_contract' }; Error = 'not uniquely active' }
)
try {
    foreach ($case in $cases) {
        $artifact = $source | ConvertFrom-Json
        & $case.Mutate $artifact
        $artifact | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $registryPath
        $rejected = $false
        try {
            & $generator -ArtifactsDir $fixtureRoot -OutputPath $outputPath
        } catch {
            if ($_.Exception.Message -notlike ('*' + $case.Error + '*')) { throw "wrong rejection for $($case.Name): $($_.Exception.Message)" }
            $rejected = $true
        }
        if (!$rejected) { throw "generator accepted $($case.Name)" }
        if (Test-Path -LiteralPath $outputPath) { throw "generator published invalid catalog for $($case.Name)" }
        Write-Host "PASS $($case.Name)"
    }
    & $generator -ArtifactsDir $ArtifactsDir -Check
    Write-Host "Verified $($cases.Count) rejected mutations and canonical catalog freshness"
} finally {
    if (Test-Path -LiteralPath $registryPath) { Remove-Item -LiteralPath $registryPath -Force }
    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    Remove-Item -LiteralPath $registryDir -Force
    Remove-Item -LiteralPath $fixtureRoot -Force
}
