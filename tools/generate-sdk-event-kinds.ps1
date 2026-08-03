param(
    [string]$ArtifactsDir = (Join-Path $PSScriptRoot "..\..\arkret-spec\spec\v1\artifacts"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\crates\wire\src\generated\event_kinds.rs")
)

. (Join-Path $PSScriptRoot 'utf8-byte-order.ps1')

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

# Active kinds only, sorted by their encoded UTF-8 bytes so match arms and the
# variant list are deterministic across PowerShell cultures and .NET runtimes.
$kinds = @($artifact.event_kinds | Where-Object { $_.status -eq 'active' } | ForEach-Object { [string]$_.event_kind })
$arr = Sort-Utf8ByteLexicographic -Values $kinds

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
        Admission = if ($null -eq $row.admission) { $null } else { [string]$row.admission }
        PayloadSchema = if ($null -eq $row.payload_schema) { $null } else { [string]$row.payload_schema }
        PayloadSchemaRef = if ($null -eq $row.payload_schema_ref) { $null } else { [string]$row.payload_schema_ref }
        CellFamily = if ($null -eq $row.cell_family) { $null } else { [string]$row.cell_family }
        CellSubjectRule = if ($null -eq $row.cell_subject) { $null } else { ($row.cell_subject | ConvertTo-Json -Compress -Depth 20) }
        ValueProjectionRule = if ($null -eq $row.value_projection) { $null } else { ($row.value_projection | ConvertTo-Json -Compress -Depth 20) }
        Lattice = if ($null -eq $row.lattice) { $null } else { [string]$row.lattice }
        Bottom = if ($null -eq $row.bottom) { $null } else { [string]$row.bottom }
        Plane = if ($null -eq $row.plane) { $null } else { [string]$row.plane }
        Sealed = [bool]$row.sealed
        CellWrites = @(
            if ($null -eq $row.cell_writes) { } else {
                foreach ($write in $row.cell_writes) {
                    [PSCustomObject]@{
                        CellFamily = if ($null -eq $write.cell_family) { $null } else { [string]$write.cell_family }
                        CellRefRule = if ($null -eq $write.cell_ref) { $null } else { ($write.cell_ref | ConvertTo-Json -Compress -Depth 40) }
                        CellSubjectRule = if ($null -eq $write.cell_subject) { $null } else { ($write.cell_subject | ConvertTo-Json -Compress -Depth 40) }
                        Lattice = if ($null -eq $write.lattice) { $null } else { [string]$write.lattice }
                        Bottom = if ($null -eq $write.bottom) { $null } else { [string]$write.bottom }
                        InitialValueRule = if ($null -eq $write.initial_value) { $null } else { ($write.initial_value | ConvertTo-Json -Compress -Depth 40) }
                        ValueProjectionRule = if ($null -eq $write.value_projection) { $null } else { ($write.value_projection | ConvertTo-Json -Compress -Depth 40) }
                        EffectProjectionRule = if ($null -eq $write.effect_projection) { $null } else { ($write.effect_projection | ConvertTo-Json -Compress -Depth 40) }
                        ConditionRule = if ($null -eq $write.condition) { $null } else { ($write.condition | ConvertTo-Json -Compress -Depth 40) }
                        DerivedMembersRule = if ($null -eq $write.derived_members) { $null } else { ($write.derived_members | ConvertTo-Json -Compress -Depth 40) }
                    }
                }
            }
        )
    }) | Out-Null
}

# Fold both the single-target shorthand and every cell_writes[] target into the
# family -> plane index. Multi-target kinds carry plane/sealed on the row, so a
# kind that outgrows the shorthand MUST NOT silently drop its families here.
$cellFamilyPlaneByFamily = @{}
foreach ($entry in $entries) {
    $families = New-Object System.Collections.Generic.List[string]
    if ($null -ne $entry.CellFamily) { $families.Add($entry.CellFamily) | Out-Null }
    foreach ($write in $entry.CellWrites) {
        $family = $write.CellFamily
        if ($null -eq $family) { continue }
        if (-not $families.Contains($family)) { $families.Add($family) | Out-Null }
    }
    if ($families.Count -eq 0) {
        continue
    }
    if ($entry.Plane -ne "data" -and $entry.Plane -ne "control") {
        throw "event kind '$($entry.Kind)' with cell families '$($families -join ', ')' must declare plane=data|control"
    }
    foreach ($family in $families) {
        if ($cellFamilyPlaneByFamily.ContainsKey($family)) {
            $existingPlane = [string]$cellFamilyPlaneByFamily[$family]
            if ($existingPlane -ne $entry.Plane) {
                throw "cell family '$family' has conflicting planes '$existingPlane' and '$($entry.Plane)'"
            }
        } else {
            $cellFamilyPlaneByFamily[$family] = $entry.Plane
        }
    }
}
# `cba_cell_family_plane` binary-searches this table, so it MUST be sorted in
# encoded UTF-8 byte order. Culture-aware sorting can reorder punctuation and
# silently break the lookup for families that land on the wrong side.
$cellFamilyNames = @($cellFamilyPlaneByFamily.Keys | ForEach-Object { [string]$_ })
$cellFamilyNames = Sort-Utf8ByteLexicographic -Values $cellFamilyNames
$cellFamilyPlanes = @($cellFamilyNames | ForEach-Object {
    $plane = [string]$cellFamilyPlaneByFamily[$_]
    $body = $_ -replace '^ak\.component\.', ''
    [PSCustomObject]@{
        Family = $_
        Variant = ConvertTo-SimpleVariant -Value $body
        AssociatedName = ($body -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
        Plane = $plane
        PlaneVariant = ConvertTo-SimpleVariant -Value $plane
    }
})

$categories = Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.Category })
$lattices = Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.CellWrites | ForEach-Object { if ($null -ne $_.Lattice) { $_.Lattice } } })
$bottomModes = Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.CellWrites | ForEach-Object { if ($null -ne $_.Bottom) { $_.Bottom } } })

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
& $add "/// Registered Arkret cell-family identifiers. Every registered"
& $add "/// ``ak.component.*`` literal the SDK ships is spelled exactly once here."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]"
& $add "#[repr(usize)]"
& $add "pub enum CellFamilyId {"
foreach ($entry in $cellFamilyPlanes) {
    & $add "    $($entry.Variant),"
}
& $add "}"
& $add ""
& $add "impl CellFamilyId {"
& $add "    pub const ALL: &'static [Self] = &["
foreach ($entry in $cellFamilyPlanes) {
    & $add "        Self::$($entry.Variant),"
}
& $add "    ];"
& $add ""
foreach ($entry in $cellFamilyPlanes) {
    & $add "    pub const $($entry.AssociatedName): &'static str = `"$($entry.Family)`";"
}
& $add ""
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($entry in $cellFamilyPlanes) {
    & $add "            Self::$($entry.Variant) => Self::$($entry.AssociatedName),"
}
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub fn from_wire(value: &str) -> Option<Self> {"
& $add "        match value {"
foreach ($entry in $cellFamilyPlanes) {
    & $add "            Self::$($entry.AssociatedName) => Some(Self::$($entry.Variant)),"
}
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "impl std::fmt::Display for CellFamilyId {"
& $add "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {"
& $add "        f.write_str(self.as_str())"
& $add "    }"
& $add "}"
& $add ""
& $add "impl Serialize for CellFamilyId {"
& $add "    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {"
& $add "        serializer.serialize_str(self.as_str())"
& $add "    }"
& $add "}"
& $add ""
& $add "impl<'de> Deserialize<'de> for CellFamilyId {"
& $add "    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {"
& $add "        let raw = String::deserialize(deserializer)?;"
& $add "        Self::from_wire(&raw).ok_or_else(|| {"
& $add '            serde::de::Error::custom(format!("unknown cell family: {raw}"))'
& $add "        })"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Closed lattice identifier used by registry-declared event cell writes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventCellLattice {"
foreach ($lattice in $lattices) {
    & $add "    $(ConvertTo-SimpleVariant -Value $lattice),"
}
& $add "}"
& $add ""
& $add "impl EventCellLattice {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($lattice in $lattices) {
    & $add "            Self::$(ConvertTo-SimpleVariant -Value $lattice) => `"$lattice`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Closed bottom-state behavior used by registry-declared event cell writes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventCellBottom {"
foreach ($bottom in $bottomModes) {
    & $add "    $(ConvertTo-SimpleVariant -Value $bottom),"
}
& $add "}"
& $add ""
& $add "impl EventCellBottom {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($bottom in $bottomModes) {
    & $add "            Self::$(ConvertTo-SimpleVariant -Value $bottom) => `"$bottom`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// One complete registry-declared cell write for an event kind. Complex"
& $add "/// projection and subject rules remain canonical JSON, but their ownership"
& $add "/// and presence are represented by this SDK type rather than downstream DTOs."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct EventCellWriteDescriptor {"
& $add "    pub cell_family: Option<CellFamilyId>,"
& $add "    pub cell_ref_rule: Option<&'static str>,"
& $add "    pub cell_subject_rule: Option<&'static str>,"
& $add "    pub lattice: Option<EventCellLattice>,"
& $add "    pub bottom: Option<EventCellBottom>,"
& $add "    pub initial_value_rule: Option<&'static str>,"
& $add "    pub value_projection_rule: Option<&'static str>,"
& $add "    pub effect_projection_rule: Option<&'static str>,"
& $add "    pub condition_rule: Option<&'static str>,"
& $add "    pub derived_members_rule: Option<&'static str>,"
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
& $add "    pub admission: Option<&'static str>,"
& $add "    pub payload_schema: Option<&'static str>,"
& $add "    pub payload_schema_ref: Option<&'static str>,"
& $add "    pub cell_writes: &'static [EventCellWriteDescriptor],"
& $add "    pub cell_family: Option<&'static str>,"
& $add "    /// JSON cell-subject rule; ``None`` means the envelope ``realm_id``."
& $add "    pub cell_subject_rule: Option<&'static str>,"
& $add "    /// JSON ``op.value`` projection rule for ordered_log appends; ``None`` means"
& $add "    /// the kind declares no registry-driven append value."
& $add "    pub value_projection_rule: Option<&'static str>,"
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
    & $add "        cell_family: CellFamilyId::$($entry.AssociatedName),"
    & $add "        plane: CbaEffectPlane::$($entry.PlaneVariant),"
    & $add "    },"
}
& $add "];"
& $add ""
& $add "/// Complete metadata rows for active standard event kinds."
& $add "pub const EVENT_KIND_DESCRIPTORS: &[EventKindDescriptor] = &["
foreach ($e in $entries) {
    $reducerInput = $e.ReducerInput.ToString().ToLowerInvariant()
    $admission = if ($null -eq $e.Admission) { "None" } else { "Some(`"$($e.Admission)`")" }
    $payloadSchema = if ($null -eq $e.PayloadSchema) { "None" } else { "Some(`"$($e.PayloadSchema)`")" }
    $payloadSchemaRef = if ($null -eq $e.PayloadSchemaRef) { "None" } else { "Some(`"$($e.PayloadSchemaRef)`")" }
    $cellFamily = if ($null -eq $e.CellFamily) {
        "None"
    } else {
        $cellFamilyBody = $e.CellFamily -replace '^ak\.component\.', ''
        $cellFamilyAssociatedName = ($cellFamilyBody -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
        "Some(CellFamilyId::$cellFamilyAssociatedName)"
    }
    $cellSubjectRule = if ($null -eq $e.CellSubjectRule) { "None" } else { "Some(r#`"$($e.CellSubjectRule)`"#)" }
    $valueProjectionRule = if ($null -eq $e.ValueProjectionRule) { "None" } else { "Some(r#`"$($e.ValueProjectionRule)`"#)" }
    $lattice = if ($null -eq $e.Lattice) { "None" } else { "Some(`"$($e.Lattice)`")" }
    $bottom = if ($null -eq $e.Bottom) { "None" } else { "Some(`"$($e.Bottom)`")" }
    $plane = if ($null -eq $e.Plane) { "None" } else { "Some(`"$($e.Plane)`")" }
    $sealed = if ($e.Sealed) { "true" } else { "false" }
    & $add "    EventKindDescriptor {"
    & $add "        kind: `"$($e.Kind)`","
    & $add "        category: EventRegistryCategory::$($e.CategoryVariant),"
    & $add "        wire_scope: EventWireScope::$($e.WireScopeVariant),"
    & $add "        reducer_input: $reducerInput,"
    & $add "        admission: $admission,"
    & $add "        payload_schema: $payloadSchema,"
    & $add "        payload_schema_ref: $payloadSchemaRef,"
    if ($e.CellWrites.Count -eq 0) {
        & $add "        cell_writes: &[],"
    } else {
        & $add "        cell_writes: &["
        foreach ($write in $e.CellWrites) {
            $cellWriteFamily = if ($null -eq $write.CellFamily) {
                "None"
            } else {
                $familyBody = $write.CellFamily -replace '^ak\.component\.', ''
                $familyVariant = ConvertTo-SimpleVariant -Value $familyBody
                "Some(CellFamilyId::$familyVariant)"
            }
            $cellWriteLattice = if ($null -eq $write.Lattice) { "None" } else { "Some(EventCellLattice::$(ConvertTo-SimpleVariant -Value $write.Lattice))" }
            $cellWriteBottom = if ($null -eq $write.Bottom) { "None" } else { "Some(EventCellBottom::$(ConvertTo-SimpleVariant -Value $write.Bottom))" }
            $cellRefRule = if ($null -eq $write.CellRefRule) { "None" } else { "Some(r#`"$($write.CellRefRule)`"#)" }
            $cellSubject = if ($null -eq $write.CellSubjectRule) { "None" } else { "Some(r#`"$($write.CellSubjectRule)`"#)" }
            $initialValue = if ($null -eq $write.InitialValueRule) { "None" } else { "Some(r#`"$($write.InitialValueRule)`"#)" }
            $valueProjection = if ($null -eq $write.ValueProjectionRule) { "None" } else { "Some(r#`"$($write.ValueProjectionRule)`"#)" }
            $effectProjection = if ($null -eq $write.EffectProjectionRule) { "None" } else { "Some(r#`"$($write.EffectProjectionRule)`"#)" }
            $condition = if ($null -eq $write.ConditionRule) { "None" } else { "Some(r#`"$($write.ConditionRule)`"#)" }
            $derivedMembers = if ($null -eq $write.DerivedMembersRule) { "None" } else { "Some(r#`"$($write.DerivedMembersRule)`"#)" }
            & $add "            EventCellWriteDescriptor {"
            & $add "                cell_family: $cellWriteFamily,"
            & $add "                cell_ref_rule: $cellRefRule,"
            & $add "                cell_subject_rule: $cellSubject,"
            & $add "                lattice: $cellWriteLattice,"
            & $add "                bottom: $cellWriteBottom,"
            & $add "                initial_value_rule: $initialValue,"
            & $add "                value_projection_rule: $valueProjection,"
            & $add "                effect_projection_rule: $effectProjection,"
            & $add "                condition_rule: $condition,"
            & $add "                derived_members_rule: $derivedMembers,"
            & $add "            },"
        }
        & $add "        ],"
    }
    & $add "        cell_family: $cellFamily,"
    & $add "        cell_subject_rule: $cellSubjectRule,"
    & $add "        value_projection_rule: $valueProjectionRule,"
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
& $add "            let mut families = descriptor.cell_writes.iter().filter_map(|write| write.cell_family.map(CellFamilyId::as_str)).collect::<Vec<_>>();"
& $add "            if let Some(cell_family) = descriptor.cell_family {"
& $add "                families.push(cell_family);"
& $add "            }"
& $add "            for cell_family in families {"
& $add "                assert_eq!("
& $add "                    cba_cell_family_plane(cell_family).map(CbaEffectPlane::as_str),"
& $add "                    descriptor.plane,"
& $add '                    "cell family {cell_family} drifted from its event descriptor",'
& $add "                );"
& $add "            }"
& $add "        }"
& $add "    }"
& $add ""
& $add "    #[test]"
& $add "    fn every_cell_family_round_trips_through_its_generated_id() {"
& $add "        for id in CellFamilyId::ALL {"
& $add "            assert_eq!(CellFamilyId::from_wire(id.as_str()), Some(*id));"
& $add "        }"
& $add "    }"
& $add "}"

Set-Content -LiteralPath $OutputPath -Value ($lines -join [Environment]::NewLine) -NoNewline
& rustfmt +nightly --edition 2024 $OutputPath
if ($LASTEXITCODE -ne 0) { throw "rustfmt failed for $OutputPath" }
Write-Host "Wrote $OutputPath ($($entries.Count) variants)"
