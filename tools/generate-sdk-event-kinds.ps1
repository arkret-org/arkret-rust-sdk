param(
    [string]$ArtifactsDir = (Join-Path $PSScriptRoot "..\..\arkret-spec\spec\v1\artifacts"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\crates\wire\src\generated\event_kinds.rs")
)

# Emits crates/wire/src/generated/event_kinds.rs from
# arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json.
#
# Outputs the strongly-typed `EventKind` enum: one PascalCase variant per
# active `ak.*` kind in the registry, plus an `Unknown(String)` catch-all that
# carries any other wire string verbatim for forward compatibility (an older
# build deserialising a newer ak.* kind keeps the bytes instead of failing the
# parse; the spec's "unknown standard kind is schema_violation" rule is enforced
# at the validation layer, not at deserialisation).

$registryPath = Join-Path $ArtifactsDir "registry\event-kind-registry.json"
if (!(Test-Path -LiteralPath $registryPath)) {
    throw "event-kind registry artifact not found: $registryPath"
}

$raw = Get-Content -LiteralPath $registryPath -Raw
$artifact = $raw | ConvertFrom-Json
$digest = (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($null -eq $artifact.event_kinds) {
    throw "event-kind-registry.json missing top-level 'event_kinds' array"
}

function ConvertTo-Variant {
    param([string]$Kind)
    $body = $Kind -replace '^ak\.', ''
    $segs = $body -split '[._]'
    ($segs | ForEach-Object {
        if ($_.Length -eq 0) { '' } else { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }
    }) -join ''
}

function ConvertTo-SimpleVariant {
    param([string]$Value)
    (($Value -split '[._]' | ForEach-Object {
        if ($_.Length -eq 0) { '' } else { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }
    }) -join '')
}

function ConvertTo-AssociatedName {
    param([string]$Kind)
    (($Kind -replace '^ak\.', '') -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
}

# Active kinds only, sorted by wire string in .NET Ordinal order so match arms
# and the variant list are deterministic and byte-ordered.
$kinds = @($artifact.event_kinds | Where-Object { $_.status -eq 'active' } | ForEach-Object { [string]$_.event_kind })
$arr = $kinds
[System.Array]::Sort($arr, [System.StringComparer]::Ordinal)

$entries = New-Object System.Collections.Generic.List[object]
$seenVariants = @{}
$rowByKind = @{}
foreach ($row in $artifact.event_kinds) {
    $rowByKind[[string]$row.event_kind] = $row
}
foreach ($k in $arr) {
    $variant = ConvertTo-Variant -Kind $k
    if ($seenVariants.ContainsKey($variant)) {
        throw "event-kind variant collision: '$variant' produced by both '$($seenVariants[$variant])' and '$k'"
    }
    $seenVariants[$variant] = $k
    $row = $rowByKind[$k]
    $entries.Add([PSCustomObject]@{
        Kind = $k
        Variant = $variant
        Category = [string]$row.category
        CategoryVariant = ConvertTo-SimpleVariant -Value ([string]$row.category)
        WireScope = [string]$row.wire_scope
        WireScopeVariant = switch ([string]$row.wire_scope) {
            'durable_event' { 'DurableEvent' }
            'actor_private_event' { 'ActorPrivateEvent' }
            'ephemeral_event' { 'EphemeralEvent' }
            default { throw "unsupported event wire scope: $($row.wire_scope)" }
        }
        ReducerInput = [bool]$row.reducer_input
        PayloadSchema = if ($null -eq $row.payload_schema) { $null } else { [string]$row.payload_schema }
        PayloadSchemaRef = if ($null -eq $row.payload_schema_ref) { $null } else { [string]$row.payload_schema_ref }
        CellFamily = if ($null -eq $row.cell_family) { $null } else { [string]$row.cell_family }
        CellSubjectRule = if ($null -eq $row.cell_subject) { $null } else { ($row.cell_subject | ConvertTo-Json -Compress -Depth 20) }
        Lattice = if ($null -eq $row.lattice) { $null } else { [string]$row.lattice }
        Bottom = if ($null -eq $row.bottom) { $null } else { [string]$row.bottom }
        Plane = if ($null -eq $row.plane) { $null } else { [string]$row.plane }
        Sealed = [bool]$row.sealed
    }) | Out-Null
}

$cellFamilyPlaneByFamily = @{}
foreach ($entry in $entries) {
    if ($null -eq $entry.CellFamily) {
        continue
    }
    if ($entry.Plane -ne "data" -and $entry.Plane -ne "control") {
        throw "event kind '$($entry.Kind)' with cell family '$($entry.CellFamily)' must declare plane=data|control"
    }
    if ($cellFamilyPlaneByFamily.ContainsKey($entry.CellFamily)) {
        $existingPlane = [string]$cellFamilyPlaneByFamily[$entry.CellFamily]
        if ($existingPlane -ne $entry.Plane) {
            throw "cell family '$($entry.CellFamily)' has conflicting planes '$existingPlane' and '$($entry.Plane)'"
        }
    } else {
        $cellFamilyPlaneByFamily[$entry.CellFamily] = $entry.Plane
    }
}
$cellFamilyPlanes = @($cellFamilyPlaneByFamily.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        Family = [string]$_.Key
        Plane = [string]$_.Value
        PlaneVariant = ConvertTo-SimpleVariant -Value ([string]$_.Value)
    }
} | Sort-Object Family)

$categories = @($entries | ForEach-Object { $_.Category } | Select-Object -Unique)
[System.Array]::Sort($categories, [System.StringComparer]::Ordinal)

$lines = New-Object System.Collections.Generic.List[string]
$add = { param($s) $lines.Add($s) | Out-Null }

& $add "//! Generated strongly-typed Arkret event-kind enum."
& $add "//!"
& $add "//! @generated by tools/generate-sdk-event-kinds.ps1 from"
& $add "//! arkret-spec/spec/v1/artifacts/registry/event-kind-registry.json; do not edit by hand."
& $add "//! Input version: $($artifact.version); sha256=$digest; active=$($entries.Count)."
& $add ""
& $add "use serde::{Deserialize, Deserializer, Serialize, Serializer};"
& $add ""
& $add "use crate::events::kinds::{EventProductClass, event_product_class, event_wire_scope};"
& $add ""
& $add '/// Count of standard `ak.*` event kinds the registry declares active.'
& $add "/// Excludes the [`EventKind::Unknown`] catch-all."
& $add "pub const EVENT_KIND_COUNT: usize = $($entries.Count);"
& $add ""
& $add "/// Raw category assigned by event-kind-registry.json."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventRegistryCategory {"
foreach ($category in $categories) {
    $categoryVariant = ConvertTo-SimpleVariant -Value $category
    & $add "    $categoryVariant,"
}
& $add "}"
& $add ""
& $add "/// Wire envelope scope assigned by the event registry."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventWireScope {"
& $add "    DurableEvent,"
& $add "    ActorPrivateEvent,"
& $add "    EphemeralEvent,"
& $add "    Custom,"
& $add "}"
& $add ""
& $add "/// Closed CBA plane assigned to a registered cell family."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum CbaEffectPlane {"
& $add "    Data,"
& $add "    Control,"
& $add "}"
& $add ""
& $add "impl CbaEffectPlane {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
& $add '            Self::Data => "data",'
& $add '            Self::Control => "control",'
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Registry-owned CBA plane for one cell family."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct CellFamilyPlaneDescriptor {"
& $add "    pub cell_family: &'static str,"
& $add "    pub plane: CbaEffectPlane,"
& $add "}"
& $add ""
& $add "/// Complete generated metadata for one active standard event kind."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct EventKindDescriptor {"
& $add "    pub kind: &'static str,"
& $add "    pub category: EventRegistryCategory,"
& $add "    pub wire_scope: EventWireScope,"
& $add "    pub reducer_input: bool,"
& $add "    pub payload_schema: Option<&'static str>,"
& $add "    pub payload_schema_ref: Option<&'static str>,"
& $add "    pub cell_family: Option<&'static str>,"
& $add "    /// JSON cell-subject rule; ``None`` means the envelope ``realm_id``."
& $add "    pub cell_subject_rule: Option<&'static str>,"
& $add "    pub lattice: Option<&'static str>,"
& $add "    pub bottom: Option<&'static str>,"
& $add "    pub plane: Option<&'static str>,"
& $add "    pub sealed: bool,"
& $add "}"
& $add ""
& $add '/// Strongly-typed Arkret event kind. One variant per active `ak.*` kind in'
& $add "/// ``event-kind-registry.json``, plus [`EventKind::Unknown`] which preserves"
& $add "/// any other wire string verbatim for forward compatibility."
& $add "///"
& $add "/// Serialises / deserialises as the bare wire string. Deserialising an"
& $add "/// unrecognised kind yields [`EventKind::Unknown`] rather than an error;"
& $add "/// rejecting unknown standard kinds is the validation layer's job."
& $add "///"
& $add "/// ``#[non_exhaustive]``: the registry gains kinds as the spec evolves and this"
& $add "/// enum is regenerated to match; downstream ``match`` expressions MUST carry a"
& $add "/// ``_`` arm with fail-closed semantics."
& $add "#[derive(Clone, Debug, PartialEq, Eq, Hash)]"
& $add "#[non_exhaustive]"
& $add "pub enum EventKind {"
foreach ($e in $entries) {
    & $add "    /// ``$($e.Kind)``"
    & $add "    $($e.Variant),"
}
& $add "    /// Forward-compatibility catch-all for any kind not in the registry at"
& $add "    /// build time. Carries the raw wire string."
& $add "    Unknown(String),"
& $add "}"
& $add ""
& $add "impl EventKind {"
& $add "    pub const ALL: &'static [Self] = &["
foreach ($e in $entries) {
    & $add "        Self::$($e.Variant),"
}
& $add "    ];"
& $add ""
foreach ($e in $entries) {
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "    pub const ${associatedName}: &'static str = `"$($e.Kind)`";"
}
& $add ""
& $add "    /// Canonical wire-form string for this kind."
& $add "    pub fn as_str(&self) -> &str {"
& $add "        match self {"
foreach ($e in $entries) {
    & $add "            Self::$($e.Variant) => `"$($e.Kind)`","
}
& $add "            Self::Unknown(raw) => raw.as_str(),"
& $add "        }"
& $add "    }"
& $add ""
& $add "    /// Parse a wire string into an [`EventKind`]. Unrecognised kinds become"
& $add "    /// [`EventKind::Unknown`] (forward compatible)."
& $add "    pub fn from_wire(value: &str) -> Self {"
& $add "        match value {"
foreach ($e in $entries) {
    & $add "            `"$($e.Kind)`" => Self::$($e.Variant),"
}
& $add "            _ => Self::Unknown(value.to_owned()),"
& $add "        }"
& $add "    }"
& $add ""
& $add "    /// Parse a wire string, returning `None` for any kind not declared in the"
& $add "    /// registry (vendor / unknown). Mirrors the previous wrapper semantics."
& $add "    pub fn try_new(value: &str) -> Option<Self> {"
& $add "        match Self::from_wire(value) {"
& $add "            Self::Unknown(_) => None,"
& $add "            known => Some(known),"
& $add "        }"
& $add "    }"
& $add ""
& $add '    /// `true` for any registry-declared kind; `false` for [`Self::Unknown`].'
& $add "    pub fn is_standard(&self) -> bool {"
& $add "        self.descriptor().is_some()"
& $add "    }"
& $add ""
& $add "    /// Registry metadata for a standard kind."
& $add "    pub fn descriptor(&self) -> Option<&'static EventKindDescriptor> {"
& $add "        EVENT_KIND_DESCRIPTORS"
& $add "            .iter()"
& $add "            .find(|descriptor| descriptor.kind == self.as_str())"
& $add "    }"
& $add ""
& $add "    /// Raw registry category, distinct from the product EventProductClass projection."
& $add "    pub fn registry_category(&self) -> Option<EventRegistryCategory> {"
& $add "        self.descriptor().map(|descriptor| descriptor.category)"
& $add "    }"
& $add ""
& $add "    /// Broad class for routing / indexing."
& $add "    pub fn product_class(&self) -> EventProductClass {"
& $add "        event_product_class(self)"
& $add "    }"
& $add ""
& $add "    /// Wire scope (durable / actor-private / ephemeral)."
& $add "    pub fn wire_scope(&self) -> EventWireScope {"
& $add "        self.descriptor()"
& $add "            .map(|descriptor| descriptor.wire_scope)"
& $add "            .unwrap_or_else(|| event_wire_scope(self.as_str()))"
& $add "    }"
& $add ""
& $add "    /// Whether this kind is a reducer-input durable event."
& $add "    pub fn is_reducer_input(&self) -> bool {"
& $add "        self.descriptor()"
& $add "            .is_some_and(|descriptor| descriptor.reducer_input)"
& $add "    }"
& $add "}"
& $add ""
& $add "impl std::fmt::Display for EventKind {"
& $add "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {"
& $add "        f.write_str(self.as_str())"
& $add "    }"
& $add "}"
& $add ""
& $add "impl AsRef<str> for EventKind {"
& $add "    fn as_ref(&self) -> &str {"
& $add "        self.as_str()"
& $add "    }"
& $add "}"
& $add ""
& $add "impl std::str::FromStr for EventKind {"
& $add "    type Err = std::convert::Infallible;"
& $add ""
& $add "    fn from_str(value: &str) -> Result<Self, Self::Err> {"
& $add "        Ok(Self::from_wire(value))"
& $add "    }"
& $add "}"
& $add ""
& $add "impl From<&str> for EventKind {"
& $add "    fn from(value: &str) -> Self {"
& $add "        Self::from_wire(value)"
& $add "    }"
& $add "}"
& $add ""
& $add "impl From<String> for EventKind {"
& $add "    fn from(value: String) -> Self {"
& $add "        Self::from_wire(&value)"
& $add "    }"
& $add "}"
& $add ""
& $add "impl From<&String> for EventKind {"
& $add "    fn from(value: &String) -> Self {"
& $add "        Self::from_wire(value)"
& $add "    }"
& $add "}"
& $add ""
& $add "impl PartialEq<str> for EventKind {"
& $add "    fn eq(&self, other: &str) -> bool {"
& $add "        self.as_str() == other"
& $add "    }"
& $add "}"
& $add ""
& $add "impl PartialEq<&str> for EventKind {"
& $add "    fn eq(&self, other: &&str) -> bool {"
& $add "        self.as_str() == *other"
& $add "    }"
& $add "}"
& $add ""
& $add "impl PartialEq<String> for EventKind {"
& $add "    fn eq(&self, other: &String) -> bool {"
& $add "        self.as_str() == other.as_str()"
& $add "    }"
& $add "}"
& $add ""
& $add "impl PartialEq<EventKind> for str {"
& $add "    fn eq(&self, other: &EventKind) -> bool {"
& $add "        self == other.as_str()"
& $add "    }"
& $add "}"
& $add ""
& $add "impl Serialize for EventKind {"
& $add "    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {"
& $add "        serializer.serialize_str(self.as_str())"
& $add "    }"
& $add "}"
& $add ""
& $add "impl<'de> Deserialize<'de> for EventKind {"
& $add "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {"
& $add "        let raw = String::deserialize(deserializer)?;"
& $add "        Ok(Self::from_wire(&raw))"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Active standard event-kind values from the registry."
& $add "pub const REGISTERED_EVENT_KINDS: &[EventKind] = &["
foreach ($e in $entries) {
    & $add "    EventKind::$($e.Variant),"
}
& $add "];"
& $add ""
& $add "pub const REGISTERED_EVENT_KIND_WIRE_VALUES: &[&str] = &["
foreach ($e in $entries) {
    & $add "    `"$($e.Kind)`","
}
& $add "];"
& $add ""
& $add "/// Return the registry-owned CBA plane for a cell family."
& $add "pub fn cba_cell_family_plane(cell_family: &str) -> Option<CbaEffectPlane> {"
& $add "    CELL_FAMILY_PLANE_DESCRIPTORS"
& $add "        .binary_search_by_key(&cell_family, |descriptor| descriptor.cell_family)"
& $add "        .ok()"
& $add "        .map(|index| CELL_FAMILY_PLANE_DESCRIPTORS[index].plane)"
& $add "}"
& $add ""
& $add "/// Unique registered cell families and their CBA planes, sorted by family."
& $add "pub const CELL_FAMILY_PLANE_DESCRIPTORS: &[CellFamilyPlaneDescriptor] = &["
foreach ($entry in $cellFamilyPlanes) {
    & $add "    CellFamilyPlaneDescriptor {"
    & $add "        cell_family: `"$($entry.Family)`","
    & $add "        plane: CbaEffectPlane::$($entry.PlaneVariant),"
    & $add "    },"
}
& $add "];"
& $add ""
& $add "/// Complete metadata rows for active standard event kinds."
& $add "pub const EVENT_KIND_DESCRIPTORS: &[EventKindDescriptor] = &["
foreach ($e in $entries) {
    $reducerInput = $e.ReducerInput.ToString().ToLowerInvariant()
    $payloadSchema = if ($null -eq $e.PayloadSchema) { "None" } else { "Some(`"$($e.PayloadSchema)`")" }
    $payloadSchemaRef = if ($null -eq $e.PayloadSchemaRef) { "None" } else { "Some(`"$($e.PayloadSchemaRef)`")" }
    $cellFamily = if ($null -eq $e.CellFamily) { "None" } else { "Some(`"$($e.CellFamily)`")" }
    $cellSubjectRule = if ($null -eq $e.CellSubjectRule) { "None" } else { "Some(r#`"$($e.CellSubjectRule)`"#)" }
    $lattice = if ($null -eq $e.Lattice) { "None" } else { "Some(`"$($e.Lattice)`")" }
    $bottom = if ($null -eq $e.Bottom) { "None" } else { "Some(`"$($e.Bottom)`")" }
    $plane = if ($null -eq $e.Plane) { "None" } else { "Some(`"$($e.Plane)`")" }
    $sealed = if ($e.Sealed) { "true" } else { "false" }
    & $add "    EventKindDescriptor {"
    & $add "        kind: `"$($e.Kind)`","
    & $add "        category: EventRegistryCategory::$($e.CategoryVariant),"
    & $add "        wire_scope: EventWireScope::$($e.WireScopeVariant),"
    & $add "        reducer_input: $reducerInput,"
    & $add "        payload_schema: $payloadSchema,"
    & $add "        payload_schema_ref: $payloadSchemaRef,"
    & $add "        cell_family: $cellFamily,"
    & $add "        cell_subject_rule: $cellSubjectRule,"
    & $add "        lattice: $lattice,"
    & $add "        bottom: $bottom,"
    & $add "        plane: $plane,"
    & $add "        sealed: $sealed,"
    & $add "    },"
}
& $add "];"
& $add ""
& $add "#[cfg(test)]"
& $add "mod tests {"
& $add "    use super::*;"
& $add ""
& $add "    #[test]"
& $add "    fn every_registered_cell_family_uses_its_generated_plane() {"
& $add "        for descriptor in EVENT_KIND_DESCRIPTORS {"
& $add "            let Some(cell_family) = descriptor.cell_family else {"
& $add "                continue;"
& $add "            };"
& $add "            assert_eq!("
& $add "                cba_cell_family_plane(cell_family).map(CbaEffectPlane::as_str),"
& $add "                descriptor.plane,"
& $add '                "cell family {cell_family} drifted from its event descriptor",'
& $add "            );"
& $add "        }"
& $add "    }"
& $add "}"

Set-Content -LiteralPath $OutputPath -Value ($lines -join [Environment]::NewLine) -NoNewline
& rustfmt +nightly --edition 2024 $OutputPath
if ($LASTEXITCODE -ne 0) { throw "rustfmt failed for $OutputPath" }
Write-Host "Wrote $OutputPath ($($entries.Count) variants)"
