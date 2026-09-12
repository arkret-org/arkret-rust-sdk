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

function ConvertTo-RuleVariant {
    param([string]$Value)
    (($Value -split '[^A-Za-z0-9]+' | ForEach-Object {
        if ($_.Length -eq 0) { '' } else { $_.Substring(0, 1).ToUpper() + $_.Substring(1) }
    }) -join '')
}

function Add-RuleVocabulary {
    param($Value)
    if ($null -eq $Value) { return }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $Value.PSObject.Properties) {
            [void]$script:ruleKeys.Add([string]$property.Name)
            if ($property.Name -eq 'kind' -and $property.Value -is [string]) {
                [void]$script:ruleOperators.Add([string]$property.Value)
            }
            Add-RuleVocabulary -Value $property.Value
        }
        return
    }
    if ($Value -is [System.Array]) {
        foreach ($item in $Value) { Add-RuleVocabulary -Value $item }
    }
}

function ConvertTo-RuleExpression {
    param($Value, [bool]$IsOperator = $false)
    if ($null -eq $Value) { return 'EventCellRule::Null' }
    if ($IsOperator) {
        return "EventCellRule::Operator(EventCellRuleOperator::$(ConvertTo-RuleVariant -Value ([string]$Value)))"
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $fields = @($Value.PSObject.Properties | ForEach-Object {
            $key = ConvertTo-RuleVariant -Value ([string]$_.Name)
            $expression = ConvertTo-RuleExpression -Value $_.Value -IsOperator ($_.Name -eq 'kind')
            "EventCellRuleField { key: EventCellRuleKey::$key, value: $expression }"
        })
        return "EventCellRule::Object(&[$($fields -join ', ')])"
    }
    if ($Value -is [System.Array]) {
        $items = @($Value | ForEach-Object { ConvertTo-RuleExpression -Value $_ })
        return "EventCellRule::Array(&[$($items -join ', ')])"
    }
    if ($Value -is [bool]) {
        return "EventCellRule::Bool($($Value.ToString().ToLowerInvariant()))"
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64]) {
        return "EventCellRule::Integer($Value)"
    }
    if ($Value -is [uint64]) {
        if ($Value -gt [int64]::MaxValue) { throw "cell rule integer exceeds i64: $Value" }
        return "EventCellRule::Integer($Value)"
    }
    if ($Value -is [string]) {
        return "EventCellRule::String($($Value | ConvertTo-Json -Compress))"
    }
    throw "unsupported cell rule value type: $($Value.GetType().FullName)"
}

function ConvertTo-AssociatedName {
    param([string]$Kind)
    (($Kind -replace '^ak\.', '') -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
}

# Active kinds only, sorted by their encoded UTF-8 bytes so match arms and the
# variant list are deterministic across PowerShell cultures and .NET runtimes.
$kinds = @($artifact.event_kinds | Where-Object { $_.status -eq 'active' } | ForEach-Object { [string]$_.event_kind })
$arr = Sort-Utf8ByteLexicographic -Values $kinds

$ruleKeys = [System.Collections.Generic.HashSet[string]]::new()
$ruleOperators = [System.Collections.Generic.HashSet[string]]::new()
foreach ($row in $artifact.event_kinds) {
    Add-RuleVocabulary -Value $row.cell_subject
    Add-RuleVocabulary -Value $row.value_projection
    foreach ($write in $row.cell_writes) {
        Add-RuleVocabulary -Value $write.cell_ref
        Add-RuleVocabulary -Value $write.cell_subject
        Add-RuleVocabulary -Value $write.value_projection
        Add-RuleVocabulary -Value $write.for_each
        Add-RuleVocabulary -Value $write.effect_projection
        Add-RuleVocabulary -Value $write.condition
        Add-RuleVocabulary -Value $write.derived_members
    }
    # A `pre_state_requirements[].condition` is drawn from the same closed
    # payload-condition grammar as `cell_writes[].condition` and is rendered
    # into the same AST by tools/spec-codegen. Feeding it through the same
    # vocabulary keeps the two generators from disagreeing about which
    # operators and keys exist: an operator only a pre-state condition uses
    # would otherwise be emitted by spec-codegen but missing from this enum.
    foreach ($requirement in $row.pre_state_requirements) {
        Add-RuleVocabulary -Value $requirement.condition
    }
}
$sortedRuleKeys = Sort-Utf8ByteLexicographic -Values @($ruleKeys)
$sortedRuleOperators = Sort-Utf8ByteLexicographic -Values @($ruleOperators)

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
        PayloadSchemaRef = if ($null -eq $row.payload_schema_ref) { $null } else { [string]$row.payload_schema_ref }
        CellFamily = if ($null -eq $row.cell_family) { $null } else { [string]$row.cell_family }
        CellSubjectRule = $row.cell_subject
        ValueProjectionRule = $row.value_projection
        Plane = if ($null -eq $row.plane) { $null } else { [string]$row.plane }
        Sealed = [bool]$row.sealed
        CellWrites = @(
            if ($null -eq $row.cell_writes) { } else {
                foreach ($write in $row.cell_writes) {
                    [PSCustomObject]@{
                        CellFamily = if ($null -eq $write.cell_family) { $null } else { [string]$write.cell_family }
                        CellRefRule = $write.cell_ref
                        CellSubjectRule = $write.cell_subject
                        Execution = if ($null -eq $write.execution) { $null } else { [string]$write.execution }
                        StateModel = if ($null -eq $write.state_model) { $null } else { [string]$write.state_model }
                        ValueShape = if ($null -eq $write.value_shape) { $null } else { [string]$write.value_shape }
                        Bottom = if ($null -eq $write.bottom) { $null } else { [string]$write.bottom }
                        ValueProjectionRule = $write.value_projection
                        ForEachRule = $write.for_each
                        EffectProjectionRule = $write.effect_projection
                        ConditionRule = $write.condition
                        DerivedMembersRule = $write.derived_members
                    }
                }
            }
        )
    }) | Out-Null
}

foreach ($entry in $entries) {
    if ($entry.ReducerInput) {
        $executions = @($entry.CellWrites | ForEach-Object { $_.Execution } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        $entry.Plane = if ($executions -contains 'security') { 'control' } else { 'data' }
    } else {
        $entry.Plane = $null
    }
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
    foreach ($family in $families) {
        $write = @($entry.CellWrites | Where-Object { $_.CellFamily -eq $family })[0]
        $familyPlane = if ($write.Execution -eq 'security') { 'control' } else { 'data' }
        if ($cellFamilyPlaneByFamily.ContainsKey($family)) {
            $existingPlane = [string]$cellFamilyPlaneByFamily[$family]
            if ($existingPlane -ne $familyPlane) {
                throw "cell family '$family' has conflicting planes '$existingPlane' and '$familyPlane'"
            }
        } else {
            $cellFamilyPlaneByFamily[$family] = $familyPlane
        }
    }
}
# `cbs_cell_family_plane` binary-searches this table, so it MUST be sorted in
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
$stateModels = @("causal_register", "counter", "or_set", "ordered_log", "sequenced_state")
$executions = Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.CellWrites | ForEach-Object { if ($null -ne $_.Execution) { $_.Execution } } })
$valueShapes = Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.CellWrites | ForEach-Object { if ($null -ne $_.ValueShape) { $_.ValueShape } } })
$bottomModes = @(Sort-Utf8ByteLexicographic -Values @($entries | ForEach-Object { $_.CellWrites | ForEach-Object { if ($null -ne $_.Bottom) { $_.Bottom } } }))
foreach ($entry in $entries) {
    foreach ($write in $entry.CellWrites) {
        if ($write.StateModel -eq 'causal_register') {
            if ($write.Execution -ne 'data' -or $write.Bottom -ne 'expose') {
                throw "$($entry.Kind) causal_register write must be ordinary data with bottom=expose"
            }
        } elseif ($null -ne $write.Bottom) {
            throw "$($entry.Kind) $($write.StateModel) write must not declare bottom"
        }
    }
}
if ($bottomModes.Count -ne 1 -or $bottomModes[0] -ne 'expose') {
    throw "causal-register bottom policy vocabulary must be exactly ['expose']"
}

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
& $add "/// SHA-256 of the exact event-kind registry used to generate this module."
& $add "pub const EVENT_KIND_REGISTRY_SHA256: &str = `"$digest`";"
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
& $add "/// Closed CBS plane assigned to a registered cell family."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum CbsEffectPlane {"
& $add "    Data,"
& $add "    Control,"
& $add "}"
& $add ""
& $add "impl CbsEffectPlane {"
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
& $add "/// Closed state model used by registry-declared event cell writes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]"
& $add "#[serde(rename_all = `"snake_case`")]"
& $add "pub enum EventCellStateModel {"
foreach ($stateModel in $stateModels) {
    & $add "    $(ConvertTo-SimpleVariant -Value $stateModel),"
}
& $add "}"
& $add ""
& $add "impl EventCellStateModel {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($stateModel in $stateModels) {
    & $add "            Self::$(ConvertTo-SimpleVariant -Value $stateModel) => `"$stateModel`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]"
& $add "#[serde(rename_all = `"snake_case`")]"
& $add "pub enum EventCellExecution {"
foreach ($execution in $executions) { & $add "    $(ConvertTo-SimpleVariant -Value $execution)," }
& $add "}"
& $add ""
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]"
& $add "#[serde(rename_all = `"snake_case`")]"
& $add "pub enum EventCellValueShape {"
foreach ($valueShape in $valueShapes) { & $add "    $(ConvertTo-SimpleVariant -Value $valueShape)," }
& $add "}"
& $add ""
& $add "/// Closed bottom-state behavior used by registry-declared event cell writes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]"
& $add "#[serde(rename_all = `"snake_case`")]"
& $add "pub enum CausalRegisterBottomPolicy {"
foreach ($bottom in $bottomModes) {
    & $add "    $(ConvertTo-SimpleVariant -Value $bottom),"
}
& $add "}"
& $add ""
& $add "impl CausalRegisterBottomPolicy {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($bottom in $bottomModes) {
    & $add "            Self::$(ConvertTo-SimpleVariant -Value $bottom) => `"$bottom`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Closed property names used by registry-declared cell-rule AST nodes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventCellRuleKey {"
foreach ($key in $sortedRuleKeys) {
    & $add "    $(ConvertTo-RuleVariant -Value $key),"
}
& $add "}"
& $add ""
& $add "impl EventCellRuleKey {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($key in $sortedRuleKeys) {
    & $add "            Self::$(ConvertTo-RuleVariant -Value $key) => `"$key`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// Closed operators used by registry-declared cell-rule AST nodes."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]"
& $add "pub enum EventCellRuleOperator {"
foreach ($operator in $sortedRuleOperators) {
    & $add "    $(ConvertTo-RuleVariant -Value $operator),"
}
& $add "}"
& $add ""
& $add "impl EventCellRuleOperator {"
& $add "    pub const fn as_str(self) -> &'static str {"
& $add "        match self {"
foreach ($operator in $sortedRuleOperators) {
    & $add "            Self::$(ConvertTo-RuleVariant -Value $operator) => `"$operator`","
}
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// One named field in a closed cell-rule AST object."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct EventCellRuleField {"
& $add "    pub key: EventCellRuleKey,"
& $add "    pub value: EventCellRule,"
& $add "}"
& $add ""
& $add "/// Lossless, parse-free AST for registry-declared cell rules."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub enum EventCellRule {"
& $add "    Null,"
& $add "    Bool(bool),"
& $add "    Integer(i64),"
& $add "    String(&'static str),"
& $add "    Operator(EventCellRuleOperator),"
& $add "    Array(&'static [EventCellRule]),"
& $add "    Object(&'static [EventCellRuleField]),"
& $add "}"
& $add ""
& $add "impl EventCellRule {"
& $add "    pub const fn as_str(self) -> Option<&'static str> {"
& $add "        match self {"
& $add "            Self::String(value) => Some(value),"
& $add "            Self::Operator(value) => Some(value.as_str()),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub const fn as_bool(self) -> Option<bool> {"
& $add "        match self {"
& $add "            Self::Bool(value) => Some(value),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub const fn as_u64(self) -> Option<u64> {"
& $add "        match self {"
& $add "            Self::Integer(value) if value >= 0 => Some(value as u64),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub const fn as_array(self) -> Option<&'static [Self]> {"
& $add "        match self {"
& $add "            Self::Array(values) => Some(values),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub const fn as_object(self) -> Option<&'static [EventCellRuleField]> {"
& $add "        match self {"
& $add "            Self::Object(fields) => Some(fields),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub fn field(self, key: EventCellRuleKey) -> Option<Self> {"
& $add "        match self {"
& $add "            Self::Object(fields) => fields.iter().find(|field| field.key == key).map(|field| field.value),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub fn field_named(self, name: &str) -> Option<Self> {"
& $add "        match self {"
& $add "            Self::Object(fields) => fields.iter().find(|field| field.key.as_str() == name).map(|field| field.value),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub fn operator(self) -> Option<EventCellRuleOperator> {"
& $add "        match self.field(EventCellRuleKey::Kind) {"
& $add "            Some(Self::Operator(operator)) => Some(operator),"
& $add "            _ => None,"
& $add "        }"
& $add "    }"
& $add ""
& $add "    pub fn to_json_value(self) -> serde_json::Value {"
& $add "        match self {"
& $add "            Self::Null => serde_json::Value::Null,"
& $add "            Self::Bool(value) => serde_json::Value::Bool(value),"
& $add "            Self::Integer(value) => serde_json::Value::Number(value.into()),"
& $add "            Self::String(value) => serde_json::Value::String(value.to_owned()),"
& $add "            Self::Operator(value) => serde_json::Value::String(value.as_str().to_owned()),"
& $add "            Self::Array(values) => serde_json::Value::Array(values.iter().map(|value| value.to_json_value()).collect()),"
& $add "            Self::Object(fields) => serde_json::Value::Object(fields.iter().map(|field| (field.key.as_str().to_owned(), field.value.to_json_value())).collect()),"
& $add "        }"
& $add "    }"
& $add "}"
& $add ""
& $add "/// One complete registry-declared cell write for an event kind."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct EventCellWriteDescriptor {"
& $add "    pub cell_family: Option<CellFamilyId>,"
& $add "    pub cell_ref_rule: Option<EventCellRule>,"
& $add "    pub cell_subject_rule: Option<EventCellRule>,"
& $add "    pub execution: Option<EventCellExecution>,"
& $add "    pub state_model: Option<EventCellStateModel>,"
& $add "    pub value_shape: Option<EventCellValueShape>,"
& $add "    pub bottom: Option<CausalRegisterBottomPolicy>,"
& $add "    pub value_projection_rule: Option<EventCellRule>,"
& $add "    pub for_each_rule: Option<EventCellRule>,"
& $add "    pub effect_projection_rule: Option<EventCellRule>,"
& $add "    pub condition_rule: Option<EventCellRule>,"
& $add "    pub derived_members_rule: Option<EventCellRule>,"
& $add "}"
& $add ""
& $add "/// Registry-owned CBS plane for one cell family."
& $add "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
& $add "pub struct CellFamilyPlaneDescriptor {"
& $add "    pub cell_family: &'static str,"
& $add "    pub plane: CbsEffectPlane,"
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
& $add "    pub payload_schema_ref: Option<&'static str>,"
& $add "    pub cell_writes: &'static [EventCellWriteDescriptor],"
& $add "    pub cell_family: Option<&'static str>,"
& $add "    /// Cell-subject rule; ``None`` means the envelope ``realm_id``."
& $add "    pub cell_subject_rule: Option<EventCellRule>,"
& $add "    /// ``op.value`` projection rule for ordered_log appends; ``None`` means"
& $add "    /// the kind declares no registry-driven append value."
& $add "    pub value_projection_rule: Option<EventCellRule>,"
& $add "    plane: Option<CbsEffectPlane>,"
& $add "    pub sealed: bool,"
& $add "}"
& $add ""
& $add "/// Canonical wire strings for active standard Event kinds."
& $add "///"
& $add "/// Each registry wire literal is emitted exactly once in this module;"
& $add "/// typed code uses [`EventKind`] variants and string boundaries use these constants."
& $add "pub mod event_kind_str {"
foreach ($e in $entries) {
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "    pub const ${associatedName}: &'static str = `"$($e.Kind)`";"
}
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
& $add "    /// Canonical wire-form string for this kind."
& $add "    pub const fn as_str(&self) -> &str {"
& $add "        match self {"
foreach ($e in $entries) {
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "            Self::$($e.Variant) => event_kind_str::$associatedName,"
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
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "            event_kind_str::$associatedName => Self::$($e.Variant),"
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
& $add "            .binary_search_by_key(&self.as_str(), |descriptor| descriptor.kind)"
& $add "            .ok()"
& $add "            .map(|index| &EVENT_KIND_DESCRIPTORS[index])"
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
& $add ""
& $add "    /// Registry-declared CBS plane for reducer-input kinds."
& $add "    ///"
& $add "    /// Non-reducer and unknown kinds return ``None``. The generator rejects"
& $add "    /// any registered reducer-input kind without exactly one closed plane."
& $add "    pub fn cbs_plane(&self) -> Option<CbsEffectPlane> {"
& $add "        self.descriptor().and_then(|descriptor| descriptor.plane)"
& $add "    }"
& $add ""
& $add "    /// Whether the registry declares this reducer-input kind on the Data plane."
& $add "    pub fn is_data_plane(&self) -> bool {"
& $add "        self.cbs_plane() == Some(CbsEffectPlane::Data)"
& $add "    }"
& $add ""
& $add "    /// Whether the registry declares this reducer-input kind on the Control plane."
& $add "    pub fn is_control_plane(&self) -> bool {"
& $add "        self.cbs_plane() == Some(CbsEffectPlane::Control)"
& $add "    }"
& $add ""
& $add "    /// Whether any registered write for this kind targets sequenced safety state."
& $add "    pub fn has_security_writes(&self) -> bool {"
& $add "        self.descriptor().is_some_and(|descriptor| descriptor.cell_writes.iter().any(|write| write.execution == Some(EventCellExecution::Security)))"
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
& $add "/// Zero-sized markers for the active standard Event kinds."
& $add "///"
& $add "/// Payload bindings live in ``arkret-event-draft`` so this low-level wire"
& $add "/// crate does not depend on the higher-level payload model crates."
& $add "pub mod event_spec {"
& $add "    use super::{EventKind, event_kind_str};"
& $add ""
foreach ($e in $entries) {
    & $add "    /// Marker for ``$($e.Kind)``."
    & $add "    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]"
    & $add "    pub struct $($e.Variant);"
    & $add ""
    & $add "    impl $($e.Variant) {"
    & $add "        pub const KIND: EventKind = EventKind::$($e.Variant);"
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "        pub const KIND_STR: &'static str = event_kind_str::$associatedName;"
    & $add "    }"
    & $add ""
}
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
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    & $add "    event_kind_str::$associatedName,"
}
& $add "];"
& $add ""
& $add "/// Return the registry-owned CBS plane for a cell family."
& $add "pub fn cbs_cell_family_plane(cell_family: &str) -> Option<CbsEffectPlane> {"
& $add "    CELL_FAMILY_PLANE_DESCRIPTORS"
& $add "        .binary_search_by_key(&cell_family, |descriptor| descriptor.cell_family)"
& $add "        .ok()"
& $add "        .map(|index| CELL_FAMILY_PLANE_DESCRIPTORS[index].plane)"
& $add "}"
& $add ""
& $add "/// Unique registered cell families and their CBS planes, sorted by family."
& $add "pub const CELL_FAMILY_PLANE_DESCRIPTORS: &[CellFamilyPlaneDescriptor] = &["
foreach ($entry in $cellFamilyPlanes) {
    & $add "    CellFamilyPlaneDescriptor {"
    & $add "        cell_family: CellFamilyId::$($entry.AssociatedName),"
    & $add "        plane: CbsEffectPlane::$($entry.PlaneVariant),"
    & $add "    },"
}
& $add "];"
& $add ""
& $add "/// Complete metadata rows for active standard event kinds."
& $add "pub const EVENT_KIND_DESCRIPTORS: &[EventKindDescriptor] = &["
foreach ($e in $entries) {
    $associatedName = ConvertTo-AssociatedName -Kind $e.Kind
    $reducerInput = $e.ReducerInput.ToString().ToLowerInvariant()
    $admission = if ($null -eq $e.Admission) { "None" } else { "Some(`"$($e.Admission)`")" }
    $payloadSchemaRef = if ($null -eq $e.PayloadSchemaRef) { "None" } else { "Some(`"$($e.PayloadSchemaRef)`")" }
    $cellFamily = if ($null -eq $e.CellFamily) {
        "None"
    } else {
        $cellFamilyBody = $e.CellFamily -replace '^ak\.component\.', ''
        $cellFamilyAssociatedName = ($cellFamilyBody -replace '[^A-Za-z0-9]+', '_').ToUpperInvariant()
        "Some(CellFamilyId::$cellFamilyAssociatedName)"
    }
    $cellSubjectRule = if ($null -eq $e.CellSubjectRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $e.CellSubjectRule))" }
    $valueProjectionRule = if ($null -eq $e.ValueProjectionRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $e.ValueProjectionRule))" }
    $plane = if ($null -eq $e.Plane) {
        "None"
    } else {
        "Some(CbsEffectPlane::$(ConvertTo-SimpleVariant -Value $e.Plane))"
    }
    $sealed = if ($e.Sealed) { "true" } else { "false" }
    & $add "    EventKindDescriptor {"
    & $add "        kind: event_kind_str::$associatedName,"
    & $add "        category: EventRegistryCategory::$($e.CategoryVariant),"
    & $add "        wire_scope: EventWireScope::$($e.WireScopeVariant),"
    & $add "        reducer_input: $reducerInput,"
    & $add "        admission: $admission,"
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
            $cellWriteExecution = if ($null -eq $write.Execution) { "None" } else { "Some(EventCellExecution::$(ConvertTo-SimpleVariant -Value $write.Execution))" }
            $cellWriteStateModel = if ($null -eq $write.StateModel) { "None" } else { "Some(EventCellStateModel::$(ConvertTo-SimpleVariant -Value $write.StateModel))" }
            $cellWriteValueShape = if ($null -eq $write.ValueShape) { "None" } else { "Some(EventCellValueShape::$(ConvertTo-SimpleVariant -Value $write.ValueShape))" }
            $cellWriteBottom = if ($null -eq $write.Bottom) { "None" } else { "Some(CausalRegisterBottomPolicy::$(ConvertTo-SimpleVariant -Value $write.Bottom))" }
            $cellRefRule = if ($null -eq $write.CellRefRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.CellRefRule))" }
            $cellSubject = if ($null -eq $write.CellSubjectRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.CellSubjectRule))" }
            $valueProjection = if ($null -eq $write.ValueProjectionRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.ValueProjectionRule))" }
            $forEach = if ($null -eq $write.ForEachRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.ForEachRule))" }
            $effectProjection = if ($null -eq $write.EffectProjectionRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.EffectProjectionRule))" }
            $condition = if ($null -eq $write.ConditionRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.ConditionRule))" }
            $derivedMembers = if ($null -eq $write.DerivedMembersRule) { "None" } else { "Some($(ConvertTo-RuleExpression -Value $write.DerivedMembersRule))" }
            & $add "            EventCellWriteDescriptor {"
            & $add "                cell_family: $cellWriteFamily,"
            & $add "                cell_ref_rule: $cellRefRule,"
            & $add "                cell_subject_rule: $cellSubject,"
            & $add "                execution: $cellWriteExecution,"
            & $add "                state_model: $cellWriteStateModel,"
            & $add "                value_shape: $cellWriteValueShape,"
            & $add "                bottom: $cellWriteBottom,"
            & $add "                value_projection_rule: $valueProjection,"
            & $add "                for_each_rule: $forEach,"
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
& $add "    fn every_standard_kind_resolves_through_the_sorted_descriptor_table() {"
& $add "        assert!(EVENT_KIND_DESCRIPTORS.windows(2).all(|pair| pair[0].kind < pair[1].kind));"
& $add "        for kind in EventKind::ALL {"
& $add "            assert_eq!(kind.descriptor().map(|descriptor| descriptor.kind), Some(kind.as_str()));"
& $add "        }"
& $add "    }"
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
& $add "                    cbs_cell_family_plane(cell_family),"
& $add "                    descriptor.plane,"
& $add '                    "cell family {cell_family} drifted from its event descriptor",'
& $add "                );"
& $add "            }"
& $add "        }"
& $add "    }"
& $add ""
& $add "    #[test]"
& $add "    fn every_reducer_input_has_exactly_one_typed_plane() {"
& $add "        for kind in EventKind::ALL {"
& $add "            let descriptor = kind.descriptor().expect(`"registered kind`");"
& $add "            assert_eq!(kind.cbs_plane().is_some(), descriptor.reducer_input, `"{}`", kind.as_str());"
& $add "            assert_eq!(kind.is_data_plane(), kind.cbs_plane() == Some(CbsEffectPlane::Data));"
& $add "            assert_eq!(kind.is_control_plane(), kind.cbs_plane() == Some(CbsEffectPlane::Control));"
& $add "            assert!(!(kind.is_data_plane() && kind.is_control_plane()));"
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

$generatedSource = $lines -join [Environment]::NewLine
foreach ($entry in $entries) {
    $quotedKind = '"' + $entry.Kind + '"'
    $literalCount = [regex]::Matches(
        $generatedSource,
        [regex]::Escape($quotedKind)
    ).Count
    if ($literalCount -ne 1) {
        throw "generated Event kind literal $quotedKind must occur exactly once, found $literalCount"
    }
}

Set-Content -LiteralPath $OutputPath -Value $generatedSource -NoNewline
& rustfmt +nightly --edition 2024 $OutputPath
if ($LASTEXITCODE -ne 0) { throw "rustfmt failed for $OutputPath" }
Write-Host "Wrote $OutputPath ($($entries.Count) variants)"
