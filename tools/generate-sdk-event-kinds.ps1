param(
    [string]$ArtifactsDir = (Join-Path $PSScriptRoot "..\..\arkret-spec\spec\v1\artifacts"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\crates\wire\src\generated\event_kinds.rs"),
    [switch]$Check
)

. (Join-Path $PSScriptRoot 'utf8-byte-order.ps1')

# Emits the clean-break Event kind surface. Ordering, finality and projection
# state no longer live in the producer Event. Effect ownership is local catalog
# metadata for implementation closure checks, never an additional wire member.
$registryPath = Join-Path $ArtifactsDir "registry\contract-registry.json"
if (!(Test-Path -LiteralPath $registryPath)) {
    throw "canonical contract registry artifact not found: $registryPath"
}

$artifact = Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json
$digest = (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($null -eq $artifact.event_kind_registry.event_kinds) {
    throw "contract-registry.json missing 'event_kind_registry.event_kinds' array"
}
$registry = $artifact.event_kind_registry

function ConvertTo-Variant {
    param([string]$Value, [string]$Prefix = '')
    $body = if ($Prefix -and $Value.StartsWith($Prefix)) { $Value.Substring($Prefix.Length) } else { $Value }
    (($body -split '[^A-Za-z0-9]+' | ForEach-Object {
        if ($_.Length -eq 0) { '' } else { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }
    }) -join '')
}

function ConvertTo-AssociatedName {
    param([string]$Kind)
    (($Kind -replace '^ak\.', '') -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
}

function ConvertTo-OptionString {
    param($Value)
    if ($null -eq $Value) { return 'None' }
    'Some(' + ([string]$Value | ConvertTo-Json -Compress) + ')'
}

function Get-EffectMetadata {
    param($Row)
    $kind = [string]$Row.event_kind
    $persistent = $Row.wire_scope -in @('durable_event', 'actor_private_event')
    $owner = $Row.result_effect_ownership
    if ($Row.reducer_input -isnot [bool]) { throw "$kind reducer_input must be a boolean" }
    if (!$persistent) {
        if ($null -ne $owner -or @($Row.result_writes).Count -gt 0) { throw "$kind has orphaned persistent effect metadata" }
        return $null
    }
    if ($null -eq $owner -or $owner -isnot [PSCustomObject]) { throw "$kind is missing closed result_effect_ownership" }
    if ($null -ne $Row.result_writes -and $Row.result_writes -isnot [Array]) { throw "$kind result_writes must be an array" }
    $writes = @($Row.result_writes | Where-Object { $null -ne $_ })
    $keys = switch ([string]$owner.kind) {
        'typed_result_writer' { @('kind') }
        'durable_fact_no_current_projection' { @('kind', 'defined_in') }
        'private_service_effect' { @('kind', 'service_contract_id') }
        'authority_commit_effect' { @('kind', 'service_contract_id') }
        'owned_gap' { @('kind', 'owner_report', 'closure_condition') }
        default { throw "$kind has unknown effect ownership '$($owner.kind)'" }
    }
    $actualKeys = @($owner.PSObject.Properties.Name)
    if (@(Compare-Object $keys $actualKeys).Count -ne 0) { throw "$kind effect ownership must be a closed $($owner.kind) object" }
    foreach ($key in $keys) {
        if ($owner.$key -isnot [string] -or [string]::IsNullOrWhiteSpace($owner.$key)) { throw "$kind ownership.$key must be a nonempty string" }
    }
    if ($owner.kind -eq 'typed_result_writer') {
        if ($Row.wire_scope -ne 'durable_event' -or !$Row.reducer_input -or $writes.Count -eq 0) { throw "$kind typed result owner requires durable reducer input and nonempty result_writes" }
    } elseif ($writes.Count -ne 0) {
        throw "$kind $($owner.kind) must not declare typed result_writes"
    }
    if ($owner.kind -eq 'private_service_effect' -and $Row.reducer_input) { throw "$kind private service effect cannot be a shared reducer input" }
    if ($owner.kind -eq 'authority_commit_effect' -and ($Row.wire_scope -ne 'durable_event' -or !$Row.reducer_input)) { throw "$kind authority effect requires a durable reducer input" }
    if ($owner.kind -eq 'durable_fact_no_current_projection' -and $owner.defined_in -notmatch '^zh/.+\.md$') { throw "$kind durable fact must cite normative zh prose" }
    if ($owner.kind -eq 'owned_gap' -and $owner.owner_report -notmatch '^arkret-work/tasks/spec-open/.+\.md$') { throw "$kind gap must cite its live specification owner" }
    if ($owner.kind -in @('private_service_effect', 'authority_commit_effect')) {
        $services = @($artifact.service_contracts | Where-Object { $_.contract_id -eq $owner.service_contract_id -and $_.status -eq 'active' })
        if ($services.Count -ne 1) { throw "$kind ownership service contract is not uniquely active" }
        $service = $services[0]
        $covering = @($service.branches | Where-Object {
            $_.event_kind -eq $kind -or @([regex]::Matches([string]$_.branch, '\bak\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\b') | ForEach-Object Value) -contains $kind
        })
        if ($covering.Count -ne 1) { throw "$kind service contract needs exactly one covering branch" }
        if ($owner.kind -eq 'authority_commit_effect' -and $service.contract_kind -ne 'authority_commit_effect_owner') { throw "$kind has the wrong authority effect service owner" }
        if ($service.contract_kind -eq 'actor_private_effect_owner' -and ($Row.wire_scope -ne 'actor_private_event' -or $service.wire_scope -ne 'actor_private_event')) { throw "$kind actor-private owner cannot own shared scope" }
    }
    $families = @($writes | ForEach-Object {
        if ($_ -isnot [PSCustomObject] -or [string]::IsNullOrWhiteSpace($_.result_family)) { throw "$kind result write has no registered family" }
        $family = [string]$_.result_family
        if (@($artifact.current_result_registry.result_kinds | Where-Object result_kind -eq $family).Count -ne 1) { throw "$kind writes unknown result family $family" }
        $family
    })
    [PSCustomObject]@{
        Ownership = ConvertTo-Variant -Value $owner.kind
        ResultFamilies = '&[' + (($families | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join ', ') + ']'
        ServiceContractId = ConvertTo-OptionString $owner.service_contract_id
        DefinedIn = ConvertTo-OptionString $owner.defined_in
        OwnerReport = ConvertTo-OptionString $owner.owner_report
        ClosureCondition = ConvertTo-OptionString $owner.closure_condition
    }
}

$rowsByKind = @{}
foreach ($row in $registry.event_kinds) {
    if ([string]$row.status -ne 'active') { continue }
    $kind = [string]$row.event_kind
    if ($rowsByKind.ContainsKey($kind)) { throw "duplicate active Event kind: $kind" }
    $rowsByKind[$kind] = $row
}
$kinds = Sort-Utf8ByteLexicographic -Values @($rowsByKind.Keys | ForEach-Object { [string]$_ })
$entries = @($kinds | ForEach-Object {
    $row = $rowsByKind[$_]
    $wireScope = switch ([string]$row.wire_scope) {
        'durable_event' { 'DurableEvent' }
        'actor_private_event' { 'ActorPrivateEvent' }
        'ephemeral_event' { 'EphemeralEvent' }
        default { throw "unsupported event wire scope: $($row.wire_scope)" }
    }
    [PSCustomObject]@{
        Kind = $_
        Variant = ConvertTo-Variant -Value $_ -Prefix 'ak.'
        AssociatedName = ConvertTo-AssociatedName -Kind $_
        Category = ConvertTo-Variant -Value ([string]$row.category)
        WireScope = $wireScope
        Admission = ConvertTo-OptionString -Value $row.admission
        PayloadSchemaRef = ConvertTo-OptionString -Value $row.payload_schema_ref
        ReducerInput = $(if ($row.reducer_input) { 'true' } else { 'false' })
        Effect = Get-EffectMetadata $row
    }
})

$variantOwners = @{}
foreach ($entry in $entries) {
    if ($variantOwners.ContainsKey($entry.Variant)) {
        throw "event-kind variant collision: '$($entry.Variant)' produced by '$($variantOwners[$entry.Variant])' and '$($entry.Kind)'"
    }
    $variantOwners[$entry.Variant] = $entry.Kind
}
$categories = Sort-Utf8ByteLexicographic -Values @($registry.event_kinds | Where-Object { $_.status -eq 'active' } | ForEach-Object { [string]$_.category })

$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$Line = '') $lines.Add($Line) | Out-Null }

Add-Line '//! Generated strongly-typed Arkret Event kind catalog.'
Add-Line '//!'
Add-Line '//! @generated by tools/generate-sdk-event-kinds.ps1 from'
Add-Line '//! arkret-spec/spec/v1/artifacts/registry/contract-registry.json#event_kind_registry; do not edit by hand.'
Add-Line "//! Input version: $($registry.version); sha256=$digest; active=$($entries.Count)."
Add-Line
Add-Line 'use serde::{Deserialize, Deserializer, Serialize, Serializer};'
Add-Line
Add-Line 'use crate::events::kinds::{EventProductClass, event_product_class, event_wire_scope};'
Add-Line
Add-Line '/// Count of active standard `ak.*` Event kinds.'
Add-Line "pub const EVENT_KIND_COUNT: usize = $($entries.Count);"
Add-Line '/// SHA-256 of the canonical contract registry used to generate this module.'
Add-Line "pub const EVENT_KIND_REGISTRY_SHA256: &str = `"$digest`";"
Add-Line
Add-Line '#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]'
Add-Line 'pub enum EventRegistryCategory {'
foreach ($category in $categories) { Add-Line "    $(ConvertTo-Variant -Value $category)," }
Add-Line '}'
Add-Line
Add-Line '/// Producer Event transport scope. Commit stream placement is carried by RealmCommit.'
Add-Line '#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]'
Add-Line 'pub enum EventWireScope {'
Add-Line '    DurableEvent,'
Add-Line '    ActorPrivateEvent,'
Add-Line '    EphemeralEvent,'
Add-Line '    Custom,'
Add-Line '}'
Add-Line
Add-Line '/// Non-wire classification of the registered effect owner.'
Add-Line '#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]'
Add-Line 'pub enum EventEffectOwnership {'
foreach ($owner in @('TypedResultWriter', 'DurableFactNoCurrentProjection', 'PrivateServiceEffect', 'AuthorityCommitEffect', 'OwnedGap')) { Add-Line "    $owner," }
Add-Line '}'
Add-Line
Add-Line '/// Local implementation metadata; these fields are never serialized into an Event.'
Add-Line '#[derive(Clone, Copy, Debug, PartialEq, Eq)]'
Add-Line 'pub struct EventEffectDescriptor {'
Add-Line '    pub ownership: EventEffectOwnership,'
Add-Line "    pub result_families: &'static [&'static str],"
Add-Line "    pub service_contract_id: Option<&'static str>,"
Add-Line "    pub defined_in: Option<&'static str>,"
Add-Line "    pub owner_report: Option<&'static str>,"
Add-Line "    pub closure_condition: Option<&'static str>,"
Add-Line '}'
Add-Line
Add-Line '/// Registry metadata that is intrinsic to the producer Event.'
Add-Line '#[derive(Clone, Copy, Debug, PartialEq, Eq)]'
Add-Line 'pub struct EventKindDescriptor {'
Add-Line "    pub kind: &'static str,"
Add-Line '    pub category: EventRegistryCategory,'
Add-Line '    pub wire_scope: EventWireScope,'
Add-Line "    pub admission: Option<&'static str>,"
Add-Line "    pub payload_schema_ref: Option<&'static str>,"
Add-Line '    pub reducer_input: bool,'
Add-Line '    pub effect: Option<EventEffectDescriptor>,'
Add-Line '}'
Add-Line
Add-Line '/// Canonical wire strings for active standard Event kinds.'
Add-Line 'pub mod event_kind_str {'
foreach ($entry in $entries) { Add-Line "    pub const $($entry.AssociatedName): &'static str = `"$($entry.Kind)`";" }
Add-Line '}'
Add-Line
Add-Line '/// Strongly typed Event kind with a forward-compatible unknown case.'
Add-Line '#[derive(Clone, Debug, PartialEq, Eq, Hash)]'
Add-Line '#[non_exhaustive]'
Add-Line 'pub enum EventKind {'
foreach ($entry in $entries) {
    Add-Line "    /// ``$($entry.Kind)``"
    Add-Line "    $($entry.Variant),"
}
Add-Line '    Unknown(String),'
Add-Line '}'
Add-Line
Add-Line 'impl EventKind {'
Add-Line "    pub const ALL: &'static [Self] = &["
foreach ($entry in $entries) { Add-Line "        Self::$($entry.Variant)," }
Add-Line '    ];'
Add-Line
Add-Line '    pub const fn as_str(&self) -> &str {'
Add-Line '        match self {'
foreach ($entry in $entries) { Add-Line "            Self::$($entry.Variant) => event_kind_str::$($entry.AssociatedName)," }
Add-Line '            Self::Unknown(raw) => raw.as_str(),'
Add-Line '        }'
Add-Line '    }'
Add-Line
Add-Line '    pub fn from_wire(value: &str) -> Self {'
Add-Line '        match value {'
foreach ($entry in $entries) { Add-Line "            event_kind_str::$($entry.AssociatedName) => Self::$($entry.Variant)," }
Add-Line '            _ => Self::Unknown(value.to_owned()),'
Add-Line '        }'
Add-Line '    }'
Add-Line
Add-Line '    pub fn try_new(value: &str) -> Option<Self> {'
Add-Line '        match Self::from_wire(value) {'
Add-Line '            Self::Unknown(_) => None,'
Add-Line '            known => Some(known),'
Add-Line '        }'
Add-Line '    }'
Add-Line
Add-Line '    pub fn is_standard(&self) -> bool { self.descriptor().is_some() }'
Add-Line
Add-Line "    pub fn descriptor(&self) -> Option<&'static EventKindDescriptor> {"
Add-Line '        EVENT_KIND_DESCRIPTORS'
Add-Line '            .binary_search_by_key(&self.as_str(), |descriptor| descriptor.kind)'
Add-Line '            .ok()'
Add-Line '            .map(|index| &EVENT_KIND_DESCRIPTORS[index])'
Add-Line '    }'
Add-Line
Add-Line '    pub fn registry_category(&self) -> Option<EventRegistryCategory> {'
Add-Line '        self.descriptor().map(|descriptor| descriptor.category)'
Add-Line '    }'
Add-Line
Add-Line "    pub fn effect_descriptor(&self) -> Option<&'static EventEffectDescriptor> {"
Add-Line '        self.descriptor().and_then(|descriptor| descriptor.effect.as_ref())'
Add-Line '    }'
Add-Line
Add-Line '    pub fn effect_ownership(&self) -> Option<EventEffectOwnership> {'
Add-Line '        self.effect_descriptor().map(|descriptor| descriptor.ownership)'
Add-Line '    }'
Add-Line
Add-Line '    pub fn product_class(&self) -> EventProductClass { event_product_class(self) }'
Add-Line
Add-Line '    /// Whether the registry declares this kind an input to the shared product'
Add-Line '    /// reducer. Unregistered kinds are never reducer inputs.'
Add-Line '    pub fn is_reducer_input(&self) -> bool {'
Add-Line '        self.descriptor().is_some_and(|descriptor| descriptor.reducer_input)'
Add-Line '    }'
Add-Line
Add-Line '    pub fn wire_scope(&self) -> EventWireScope {'
Add-Line '        self.descriptor()'
Add-Line '            .map(|descriptor| descriptor.wire_scope)'
Add-Line '            .unwrap_or_else(|| event_wire_scope(self.as_str()))'
Add-Line '    }'
Add-Line '}'
Add-Line
Add-Line 'impl std::fmt::Display for EventKind {'
Add-Line "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }"
Add-Line '}'
Add-Line
Add-Line 'impl AsRef<str> for EventKind { fn as_ref(&self) -> &str { self.as_str() } }'
Add-Line 'impl std::str::FromStr for EventKind {'
Add-Line '    type Err = std::convert::Infallible;'
Add-Line '    fn from_str(value: &str) -> Result<Self, Self::Err> { Ok(Self::from_wire(value)) }'
Add-Line '}'
Add-Line 'impl From<&str> for EventKind { fn from(value: &str) -> Self { Self::from_wire(value) } }'
Add-Line 'impl From<String> for EventKind { fn from(value: String) -> Self { Self::from_wire(&value) } }'
Add-Line 'impl From<&String> for EventKind { fn from(value: &String) -> Self { Self::from_wire(value) } }'
Add-Line 'impl PartialEq<str> for EventKind { fn eq(&self, other: &str) -> bool { self.as_str() == other } }'
Add-Line 'impl PartialEq<&str> for EventKind { fn eq(&self, other: &&str) -> bool { self.as_str() == *other } }'
Add-Line 'impl PartialEq<String> for EventKind { fn eq(&self, other: &String) -> bool { self.as_str() == other.as_str() } }'
Add-Line 'impl PartialEq<EventKind> for str { fn eq(&self, other: &EventKind) -> bool { self == other.as_str() } }'
Add-Line
Add-Line 'impl Serialize for EventKind {'
Add-Line '    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {'
Add-Line '        serializer.serialize_str(self.as_str())'
Add-Line '    }'
Add-Line '}'
Add-Line "impl<'de> Deserialize<'de> for EventKind {"
Add-Line "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {"
Add-Line '        let raw = String::deserialize(deserializer)?;'
Add-Line '        Ok(Self::from_wire(&raw))'
Add-Line '    }'
Add-Line '}'
Add-Line
Add-Line 'pub mod event_spec {'
Add-Line '    use super::{EventKind, event_kind_str};'
foreach ($entry in $entries) {
    Add-Line '    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]'
    Add-Line "    pub struct $($entry.Variant);"
    Add-Line "    impl $($entry.Variant) {"
    Add-Line "        pub const KIND: EventKind = EventKind::$($entry.Variant);"
    Add-Line "        pub const KIND_STR: &'static str = event_kind_str::$($entry.AssociatedName);"
    Add-Line '    }'
}
Add-Line '}'
Add-Line
Add-Line 'pub const REGISTERED_EVENT_KINDS: &[EventKind] = &['
foreach ($entry in $entries) { Add-Line "    EventKind::$($entry.Variant)," }
Add-Line '];'
Add-Line
Add-Line 'pub const REGISTERED_EVENT_KIND_WIRE_VALUES: &[&str] = &['
foreach ($entry in $entries) { Add-Line "    event_kind_str::$($entry.AssociatedName)," }
Add-Line '];'
Add-Line
Add-Line 'pub const EVENT_KIND_DESCRIPTORS: &[EventKindDescriptor] = &['
foreach ($entry in $entries) {
    Add-Line '    EventKindDescriptor {'
    Add-Line "        kind: event_kind_str::$($entry.AssociatedName),"
    Add-Line "        category: EventRegistryCategory::$($entry.Category),"
    Add-Line "        wire_scope: EventWireScope::$($entry.WireScope),"
    Add-Line "        admission: $($entry.Admission),"
    Add-Line "        payload_schema_ref: $($entry.PayloadSchemaRef),"
    Add-Line "        reducer_input: $($entry.ReducerInput),"
    if ($null -eq $entry.Effect) {
        Add-Line '        effect: None,'
    } else {
        Add-Line '        effect: Some(EventEffectDescriptor {'
        Add-Line "            ownership: EventEffectOwnership::$($entry.Effect.Ownership),"
        Add-Line "            result_families: $($entry.Effect.ResultFamilies),"
        Add-Line "            service_contract_id: $($entry.Effect.ServiceContractId),"
        Add-Line "            defined_in: $($entry.Effect.DefinedIn),"
        Add-Line "            owner_report: $($entry.Effect.OwnerReport),"
        Add-Line "            closure_condition: $($entry.Effect.ClosureCondition),"
        Add-Line '        }),'
    }
    Add-Line '    },'
}
Add-Line '];'
Add-Line
Add-Line '#[cfg(test)]'
Add-Line 'mod tests {'
Add-Line '    use super::*;'
Add-Line '    #[test]'
Add-Line '    fn every_standard_kind_resolves_through_the_sorted_descriptor_table() {'
Add-Line '        assert!(EVENT_KIND_DESCRIPTORS.windows(2).all(|pair| pair[0].kind < pair[1].kind));'
Add-Line '        for kind in EventKind::ALL {'
Add-Line '            assert_eq!(kind.descriptor().map(|descriptor| descriptor.kind), Some(kind.as_str()));'
Add-Line '        }'
Add-Line '    }'
@'
    #[test]
    fn effect_owners_preserve_scope_reducer_and_write_contracts() {
        for kind in EventKind::ALL {
            let descriptor = kind.descriptor().unwrap();
            if descriptor.wire_scope == EventWireScope::EphemeralEvent {
                assert!(kind.effect_descriptor().is_none());
                continue;
            }
            let effect = kind.effect_descriptor().expect("persistent kind needs an owner");
            assert_eq!(kind.effect_ownership(), Some(effect.ownership));
            match effect.ownership {
                EventEffectOwnership::TypedResultWriter => {
                    assert_eq!(descriptor.wire_scope, EventWireScope::DurableEvent);
                    assert!(descriptor.reducer_input);
                    assert!(!effect.result_families.is_empty());
                }
                EventEffectOwnership::PrivateServiceEffect => {
                    assert!(!descriptor.reducer_input);
                    assert!(effect.result_families.is_empty());
                    assert!(effect.service_contract_id.is_some());
                }
                EventEffectOwnership::AuthorityCommitEffect => {
                    assert_eq!(descriptor.wire_scope, EventWireScope::DurableEvent);
                    assert!(descriptor.reducer_input);
                    assert!(effect.result_families.is_empty());
                    assert!(effect.service_contract_id.is_some());
                }
                EventEffectOwnership::DurableFactNoCurrentProjection => {
                    assert!(effect.result_families.is_empty());
                    assert!(effect.defined_in.is_some());
                }
                EventEffectOwnership::OwnedGap => {
                    assert!(effect.result_families.is_empty());
                    assert!(effect.owner_report.is_some());
                    assert!(effect.closure_condition.is_some());
                }
            }
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::Value::String(kind.as_str().to_owned()));
        }
        let unknown = EventKind::from_wire("custom.effect-owner-test");
        assert!(unknown.effect_ownership().is_none());
        assert!(unknown.effect_descriptor().is_none());
    }
'@ -split '\r?\n' | ForEach-Object { Add-Line $_ }
Add-Line '}'

$generatedSource = $lines -join [Environment]::NewLine
foreach ($entry in $entries) {
    $quotedKind = '"' + $entry.Kind + '"'
    $literalCount = [regex]::Matches($generatedSource, [regex]::Escape($quotedKind)).Count
    if ($literalCount -ne 1) {
        throw "generated Event kind literal $quotedKind must occur exactly once, found $literalCount"
    }
}

$generationTarget = if ($Check) {
    Join-Path (Split-Path -Parent $OutputPath) (".event-kind-check-" + [guid]::NewGuid().ToString('N') + '.rs')
} else { $OutputPath }
try {
    Set-Content -LiteralPath $generationTarget -Value $generatedSource -NoNewline
    & rustfmt +nightly --edition 2024 $generationTarget
    if ($LASTEXITCODE -ne 0) { throw "rustfmt failed for $generationTarget" }
    if ($Check) {
        if (!(Test-Path -LiteralPath $OutputPath) -or [IO.File]::ReadAllText($generationTarget) -cne [IO.File]::ReadAllText($OutputPath)) { throw "generated Event catalog is stale: $OutputPath" }
        Write-Host "Verified $OutputPath ($($entries.Count) variants)"
    } else {
        Write-Host "Wrote $OutputPath ($($entries.Count) variants)"
    }
} finally {
    if ($Check) { Remove-Item -LiteralPath $generationTarget -Force }
}
