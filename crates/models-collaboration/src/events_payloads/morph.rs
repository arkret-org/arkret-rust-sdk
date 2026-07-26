//! Morph event payloads and schema-transition validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use arkret_wire::{Error, Hash, MorphId, Patch, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::internal_prelude::*;

/// Payload for `ak.morph.update`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphUpdatePayload {
    pub target_ref: MorphId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl MorphUpdatePayload {
    pub fn for_morph(morph_id: MorphId, patch: Patch) -> Result<Self> {
        validate_morph_update_patch(&patch)?;
        Ok(Self {
            target_ref: morph_id,
            patch,
            expected_state_digest: None,
        })
    }

    pub fn with_expected_state_digest(mut self, expected_state_digest: Hash) -> Self {
        self.expected_state_digest = Some(expected_state_digest);
        self
    }

    pub fn validate(&self) -> Result<()> {
        validate_morph_update_patch(&self.patch)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("morph update payload serialize: {err}")))
    }
}

fn validate_morph_update_patch(patch: &Patch) -> Result<()> {
    patch.validate()?;
    for (path, _) in patch.iter() {
        if matches!(path.as_str(), "morph_kind" | "stage" | "stage_changed_at") {
            return Err(Error::Protocol(
                "morph update patch targets create-locked or single-sourced field".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphCreatePayload {
    pub object: Morph,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_schema_migrate_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphSchemaMigratePayload {
    pub morph_id: MorphId,
    pub from_schema_refs: Vec<String>,
    pub to_schema_refs: Vec<String>,
    pub compatibility_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation_rules: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_evidence: Option<BTreeMap<String, Value>>,
}

impl MorphSchemaMigratePayload {
    pub fn validate_additive_schema_refs(
        &self,
        from_fields: &MorphSchemaFieldSet,
        to_fields: &MorphSchemaFieldSet,
    ) -> std::result::Result<(), MorphSchemaAdditiveViolation> {
        morph_schema_refs_additive_only(
            &self.from_schema_refs,
            &self.to_schema_refs,
            from_fields,
            to_fields,
        )
    }

    pub fn apply_transformation(
        &self,
        fields: &BTreeMap<String, Value>,
    ) -> std::result::Result<BTreeMap<String, Value>, MorphSchemaTransformationError> {
        if self.compatibility_class != "transformation" {
            return Err(MorphSchemaTransformationError::CompatibilityClass(
                self.compatibility_class.clone(),
            ));
        }
        let rules = self
            .transformation_rules
            .as_deref()
            .ok_or(MorphSchemaTransformationError::MissingRules)?;
        let mut output = fields.clone();
        for rule in rules {
            apply_transformation_rule(&mut output, rule)?;
        }
        Ok(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MorphSchemaTransformationError {
    CompatibilityClass(String),
    MissingRules,
    UnknownRule(String),
    InvalidRuleFields(String),
    MissingSourceField(String),
    TargetFieldExists(String),
    TypeMismatch(String),
}

impl fmt::Display for MorphSchemaTransformationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompatibilityClass(value) => {
                write!(
                    formatter,
                    "compatibility_class must be transformation, got {value}"
                )
            }
            Self::MissingRules => formatter.write_str("transformation_rules must be present"),
            Self::UnknownRule(value) => write!(formatter, "unknown transformation rule {value}"),
            Self::InvalidRuleFields(value) => {
                write!(formatter, "invalid fields for transformation rule {value}")
            }
            Self::MissingSourceField(value) => {
                write!(formatter, "transformation source field {value} is absent")
            }
            Self::TargetFieldExists(value) => {
                write!(
                    formatter,
                    "transformation target field {value} already exists"
                )
            }
            Self::TypeMismatch(value) => {
                write!(formatter, "transformation field {value} has the wrong type")
            }
        }
    }
}

impl std::error::Error for MorphSchemaTransformationError {}

fn apply_transformation_rule(
    fields: &mut BTreeMap<String, Value>,
    rule: &BTreeMap<String, Value>,
) -> std::result::Result<(), MorphSchemaTransformationError> {
    let rule_id = required_rule_string(rule, "rule", "unknown")?;
    match rule_id {
        "ak.transform.identity.v1" => {
            require_exact_rule_fields(rule, rule_id, &["rule"])?;
        }
        "ak.transform.rename.v1" => {
            require_exact_rule_fields(rule, rule_id, &["rule", "from", "to"])?;
            let from = required_rule_string(rule, "from", rule_id)?;
            let to = required_rule_string(rule, "to", rule_id)?;
            if fields.contains_key(to) {
                return Err(MorphSchemaTransformationError::TargetFieldExists(
                    to.to_owned(),
                ));
            }
            let value = fields.remove(from).ok_or_else(|| {
                MorphSchemaTransformationError::MissingSourceField(from.to_owned())
            })?;
            fields.insert(to.to_owned(), value);
        }
        "ak.transform.type_widen.v1" => {
            require_exact_rule_fields(rule, rule_id, &["rule", "field", "from_kind", "to_kind"])?;
            let field = required_rule_string(rule, "field", rule_id)?;
            let from_kind = required_rule_string(rule, "from_kind", rule_id)?;
            let to_kind = required_rule_string(rule, "to_kind", rule_id)?;
            if from_kind != "integer" || to_kind != "number" {
                return Err(MorphSchemaTransformationError::InvalidRuleFields(
                    rule_id.to_owned(),
                ));
            }
            let value = fields.get(field).ok_or_else(|| {
                MorphSchemaTransformationError::MissingSourceField(field.to_owned())
            })?;
            if !value
                .as_number()
                .is_some_and(|number| number.is_i64() || number.is_u64())
            {
                return Err(MorphSchemaTransformationError::TypeMismatch(
                    field.to_owned(),
                ));
            }
        }
        "ak.transform.default_backfill.v1" => {
            require_exact_rule_fields(rule, rule_id, &["rule", "to", "value"])?;
            let to = required_rule_string(rule, "to", rule_id)?;
            if !fields.contains_key(to) {
                fields.insert(to.to_owned(), rule["value"].clone());
            }
        }
        other => {
            return Err(MorphSchemaTransformationError::UnknownRule(
                other.to_owned(),
            ));
        }
    }
    Ok(())
}

fn required_rule_string<'a>(
    rule: &'a BTreeMap<String, Value>,
    field: &str,
    rule_id: &str,
) -> std::result::Result<&'a str, MorphSchemaTransformationError> {
    rule.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| MorphSchemaTransformationError::InvalidRuleFields(rule_id.to_owned()))
}

fn require_exact_rule_fields(
    rule: &BTreeMap<String, Value>,
    rule_id: &str,
    expected: &[&str],
) -> std::result::Result<(), MorphSchemaTransformationError> {
    let actual = rule.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(MorphSchemaTransformationError::InvalidRuleFields(
            rule_id.to_owned(),
        ));
    }
    Ok(())
}

pub type MorphSchemaFieldSet = BTreeMap<String, MorphSchemaFieldDescriptor>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphSchemaFieldDescriptor {
    pub value_kind: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub enum_values: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(default)]
    pub non_null_default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MorphSchemaAdditiveViolation {
    EmptyFromSchemaRefs,
    EmptyToSchemaRefs,
    DuplicateFromSchemaRef(String),
    DuplicateToSchemaRef(String),
    RemovedSchemaRef(String),
    RemovedField(String),
    NewRequiredField(String),
    FieldTypeChanged(String),
    FieldRequiredTightened(String),
    FieldNullableTightened(String),
    FieldEnumNarrowed(String),
    FieldMinimumRaised(String),
    FieldMaximumLowered(String),
    FieldMinLengthRaised(String),
    FieldMaxLengthLowered(String),
}

impl fmt::Display for MorphSchemaAdditiveViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFromSchemaRefs => f.write_str("from_schema_refs must not be empty"),
            Self::EmptyToSchemaRefs => f.write_str("to_schema_refs must not be empty"),
            Self::DuplicateFromSchemaRef(value) => {
                write!(f, "from_schema_refs contains duplicate {value}")
            }
            Self::DuplicateToSchemaRef(value) => {
                write!(f, "to_schema_refs contains duplicate {value}")
            }
            Self::RemovedSchemaRef(value) => write!(f, "to_schema_refs removed {value}"),
            Self::RemovedField(value) => write!(f, "to field set removed {value}"),
            Self::NewRequiredField(value) => write!(f, "new field {value} is required"),
            Self::FieldTypeChanged(value) => write!(f, "field {value} changed type"),
            Self::FieldRequiredTightened(value) => {
                write!(f, "field {value} changed optional to required")
            }
            Self::FieldNullableTightened(value) => {
                write!(f, "field {value} changed nullable to non-nullable")
            }
            Self::FieldEnumNarrowed(value) => write!(f, "field {value} narrowed enum values"),
            Self::FieldMinimumRaised(value) => write!(f, "field {value} raised minimum"),
            Self::FieldMaximumLowered(value) => write!(f, "field {value} lowered maximum"),
            Self::FieldMinLengthRaised(value) => write!(f, "field {value} raised min_length"),
            Self::FieldMaxLengthLowered(value) => write!(f, "field {value} lowered max_length"),
        }
    }
}

impl std::error::Error for MorphSchemaAdditiveViolation {}

pub fn morph_schema_refs_additive_only(
    from_schema_refs: &[String],
    to_schema_refs: &[String],
    from_fields: &MorphSchemaFieldSet,
    to_fields: &MorphSchemaFieldSet,
) -> std::result::Result<(), MorphSchemaAdditiveViolation> {
    let from_refs = collect_schema_refs(from_schema_refs, true)?;
    let to_refs = collect_schema_refs(to_schema_refs, false)?;
    for schema_ref in &from_refs {
        if !to_refs.contains(schema_ref) {
            return Err(MorphSchemaAdditiveViolation::RemovedSchemaRef(
                (*schema_ref).to_owned(),
            ));
        }
    }
    for (field_name, from_field) in from_fields {
        let Some(to_field) = to_fields.get(field_name) else {
            return Err(MorphSchemaAdditiveViolation::RemovedField(
                field_name.clone(),
            ));
        };
        validate_field_is_not_tightened(field_name, from_field, to_field)?;
    }
    for (field_name, to_field) in to_fields {
        if !from_fields.contains_key(field_name) && (to_field.required || to_field.non_null_default)
        {
            return Err(MorphSchemaAdditiveViolation::NewRequiredField(
                field_name.clone(),
            ));
        }
    }
    Ok(())
}

fn collect_schema_refs(
    refs: &[String],
    from_side: bool,
) -> std::result::Result<BTreeSet<&str>, MorphSchemaAdditiveViolation> {
    if refs.is_empty() {
        return Err(if from_side {
            MorphSchemaAdditiveViolation::EmptyFromSchemaRefs
        } else {
            MorphSchemaAdditiveViolation::EmptyToSchemaRefs
        });
    }
    let mut set = BTreeSet::new();
    for schema_ref in refs {
        if !set.insert(schema_ref.as_str()) {
            return Err(if from_side {
                MorphSchemaAdditiveViolation::DuplicateFromSchemaRef(schema_ref.clone())
            } else {
                MorphSchemaAdditiveViolation::DuplicateToSchemaRef(schema_ref.clone())
            });
        }
    }
    Ok(set)
}

fn validate_field_is_not_tightened(
    field_name: &str,
    from_field: &MorphSchemaFieldDescriptor,
    to_field: &MorphSchemaFieldDescriptor,
) -> std::result::Result<(), MorphSchemaAdditiveViolation> {
    if from_field.value_kind != to_field.value_kind {
        return Err(MorphSchemaAdditiveViolation::FieldTypeChanged(
            field_name.to_owned(),
        ));
    }
    if !from_field.required && to_field.required {
        return Err(MorphSchemaAdditiveViolation::FieldRequiredTightened(
            field_name.to_owned(),
        ));
    }
    if from_field.nullable && !to_field.nullable {
        return Err(MorphSchemaAdditiveViolation::FieldNullableTightened(
            field_name.to_owned(),
        ));
    }
    if !enum_values_are_not_narrowed(&from_field.enum_values, &to_field.enum_values) {
        return Err(MorphSchemaAdditiveViolation::FieldEnumNarrowed(
            field_name.to_owned(),
        ));
    }
    if lower_bound_raised(from_field.minimum, to_field.minimum) {
        return Err(MorphSchemaAdditiveViolation::FieldMinimumRaised(
            field_name.to_owned(),
        ));
    }
    if upper_bound_lowered(from_field.maximum, to_field.maximum) {
        return Err(MorphSchemaAdditiveViolation::FieldMaximumLowered(
            field_name.to_owned(),
        ));
    }
    if lower_bound_raised_u64(from_field.min_length, to_field.min_length) {
        return Err(MorphSchemaAdditiveViolation::FieldMinLengthRaised(
            field_name.to_owned(),
        ));
    }
    if upper_bound_lowered_u64(from_field.max_length, to_field.max_length) {
        return Err(MorphSchemaAdditiveViolation::FieldMaxLengthLowered(
            field_name.to_owned(),
        ));
    }
    Ok(())
}

fn enum_values_are_not_narrowed(
    from_values: &BTreeSet<String>,
    to_values: &BTreeSet<String>,
) -> bool {
    if from_values.is_empty() {
        to_values.is_empty()
    } else {
        from_values.is_subset(to_values)
    }
}

fn lower_bound_raised(from: Option<i64>, to: Option<i64>) -> bool {
    match (from, to) {
        (None, Some(_)) => true,
        (Some(from), Some(to)) => to > from,
        _ => false,
    }
}

fn upper_bound_lowered(from: Option<i64>, to: Option<i64>) -> bool {
    match (from, to) {
        (None, Some(_)) => true,
        (Some(from), Some(to)) => to < from,
        _ => false,
    }
}

fn lower_bound_raised_u64(from: Option<u64>, to: Option<u64>) -> bool {
    match (from, to) {
        (None, Some(_)) => true,
        (Some(from), Some(to)) => to > from,
        _ => false,
    }
}

fn upper_bound_lowered_u64(from: Option<u64>, to: Option<u64>) -> bool {
    match (from, to) {
        (None, Some(_)) => true,
        (Some(from), Some(to)) => to < from,
        _ => false,
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_stage_set_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphStageSetPayload {
    pub morph_id: MorphId,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stage: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value_kind: &str) -> MorphSchemaFieldDescriptor {
        MorphSchemaFieldDescriptor {
            value_kind: value_kind.to_owned(),
            ..Default::default()
        }
    }

    fn refs(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn morph_schema_refs_additive_accepts_superset_and_relaxed_field_constraints() {
        let from_refs = refs(&["ak.schema.risk.v1"]);
        let to_refs = refs(&["ak.schema.risk.v1", "ak.schema.risk.notes.v1"]);
        let mut from_fields = MorphSchemaFieldSet::new();
        let mut status = field("string");
        status.required = true;
        status.nullable = false;
        status.enum_values = ["open", "closed"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        status.minimum = Some(0);
        status.maximum = Some(10);
        from_fields.insert("fields.status".to_owned(), status);

        let mut to_fields = from_fields.clone();
        let relaxed = to_fields.get_mut("fields.status").unwrap();
        relaxed.required = false;
        relaxed.nullable = true;
        relaxed.enum_values.insert("review".to_owned());
        relaxed.minimum = Some(-1);
        relaxed.maximum = Some(20);
        to_fields.insert("fields.note".to_owned(), field("string"));

        morph_schema_refs_additive_only(&from_refs, &to_refs, &from_fields, &to_fields).unwrap();
    }

    #[test]
    fn morph_schema_refs_additive_rejects_removed_ref_and_field() {
        let from_refs = refs(&["ak.schema.risk.v1", "ak.schema.extra.v1"]);
        let to_refs = refs(&["ak.schema.risk.v1"]);
        let from_fields =
            MorphSchemaFieldSet::from([("fields.status".to_owned(), field("string"))]);
        let to_fields = MorphSchemaFieldSet::new();

        assert_eq!(
            morph_schema_refs_additive_only(&from_refs, &to_refs, &from_fields, &from_fields),
            Err(MorphSchemaAdditiveViolation::RemovedSchemaRef(
                "ak.schema.extra.v1".to_owned()
            ))
        );
        assert_eq!(
            morph_schema_refs_additive_only(
                &refs(&["ak.schema.risk.v1"]),
                &refs(&["ak.schema.risk.v1"]),
                &from_fields,
                &to_fields,
            ),
            Err(MorphSchemaAdditiveViolation::RemovedField(
                "fields.status".to_owned()
            ))
        );
    }

    #[test]
    fn morph_schema_refs_additive_rejects_new_required_or_tightened_fields() {
        let schema_refs = refs(&["ak.schema.risk.v1"]);
        let mut from_fields = MorphSchemaFieldSet::new();
        let mut from_status = field("string");
        from_status.enum_values = ["open", "closed"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        from_fields.insert("fields.status".to_owned(), from_status);

        let mut to_fields = from_fields.clone();
        let mut required_note = field("string");
        required_note.required = true;
        to_fields.insert("fields.note".to_owned(), required_note);
        assert_eq!(
            morph_schema_refs_additive_only(&schema_refs, &schema_refs, &from_fields, &to_fields),
            Err(MorphSchemaAdditiveViolation::NewRequiredField(
                "fields.note".to_owned()
            ))
        );

        let mut narrowed = from_fields.clone();
        narrowed
            .get_mut("fields.status")
            .unwrap()
            .enum_values
            .remove("closed");
        assert_eq!(
            morph_schema_refs_additive_only(&schema_refs, &schema_refs, &from_fields, &narrowed),
            Err(MorphSchemaAdditiveViolation::FieldEnumNarrowed(
                "fields.status".to_owned()
            ))
        );
    }
}
