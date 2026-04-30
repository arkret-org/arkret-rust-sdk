//! Schema registry and compatibility contracts.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{
    CAPABILITY_SCHEMA, CLIENT_SYNC_RESPONSE_SCHEMA, COMMIT_SCHEMA, CURSOR_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA, ENTITY_SCHEMA, EVENT_SCHEMA, Error, GeneratedSchemaValidator,
    OPERATION_SCHEMA, ProtocolSchemaRegistry, Result, SCHEMA_COMPATIBILITY_PROFILE,
    SchemaCompatibilityEntry, SchemaCompatibilityTable, VIEW_SCHEMA,
    schema_version_compatibility_table,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use contrix_core::{
    GeneratedSchemaField, GeneratedSchemaValueType, ProtocolSchemaRegistry as Registry,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogEntry {
    pub schema_id: String,
    pub current_version: String,
    pub compatible_since: String,
    pub migration_required: bool,
    pub generated_validator: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogReport {
    pub profile: String,
    pub entries: Vec<SchemaCatalogEntry>,
    pub missing_compatibility: Vec<String>,
}

impl SchemaCatalogReport {
    pub fn validate(&self) -> Result<()> {
        if self.profile != SCHEMA_COMPATIBILITY_PROFILE {
            return Err(Error::Protocol("schema catalog profile mismatch".to_owned()));
        }
        if !self.missing_compatibility.is_empty() {
            return Err(Error::Protocol(format!(
                "schemas missing compatibility entries: {:?}",
                self.missing_compatibility
            )));
        }
        Ok(())
    }
}

pub fn schema_catalog() -> SchemaCatalogReport {
    let registry = ProtocolSchemaRegistry::default();
    let compatibility = schema_version_compatibility_table();
    let compatibility_by_id = compatibility
        .entries
        .iter()
        .map(|entry| (entry.schema_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();
    let mut missing_compatibility = Vec::new();
    for schema_id in registry.schema_ids() {
        match compatibility_by_id.get(schema_id) {
            Some(entry) => entries.push(catalog_entry(&registry, entry)),
            None => missing_compatibility.push(schema_id.to_owned()),
        }
    }
    entries.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    SchemaCatalogReport { profile: compatibility.profile, entries, missing_compatibility }
}

fn catalog_entry(
    registry: &ProtocolSchemaRegistry,
    compatibility: &SchemaCompatibilityEntry,
) -> SchemaCatalogEntry {
    SchemaCatalogEntry {
        schema_id: compatibility.schema_id.clone(),
        current_version: compatibility.current_version.clone(),
        compatible_since: compatibility.compatible_since.clone(),
        migration_required: compatibility.migration_required,
        generated_validator: registry.generated_validator(&compatibility.schema_id).is_ok(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SchemaValidationVector {
    pub name: String,
    pub schema_id: String,
    pub input: Value,
    pub expected_valid: bool,
}

pub fn built_in_schema_vectors() -> Vec<SchemaValidationVector> {
    vec![
        SchemaValidationVector {
            name: "operation envelope minimal valid".to_owned(),
            schema_id: OPERATION_SCHEMA.to_owned(),
            input: json!({
                "operation_id": "cx:operation:01",
                "space_id": "cx:space:01",
                "actor_id": "did:web:alice.example",
                "kind": "cx.message.create",
                "causal": {},
                "content": {"body": "hello"}
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "operation envelope missing content".to_owned(),
            schema_id: OPERATION_SCHEMA.to_owned(),
            input: json!({
                "operation_id": "cx:operation:01",
                "space_id": "cx:space:01",
                "actor_id": "did:web:alice.example",
                "kind": "cx.message.create",
                "causal": {}
            }),
            expected_valid: false,
        },
        SchemaValidationVector {
            name: "event rejects untrusted security extension".to_owned(),
            schema_id: EVENT_SCHEMA.to_owned(),
            input: json!({
                "schema": "cx.schema.event.v1",
                "event_id": "cx:event:01",
                "space_id": "cx:space:01",
                "actor_id": "did:web:alice.example",
                "kind": "cx.message.text",
                "content": {},
                "x-security": {"override": true}
            }),
            expected_valid: false,
        },
    ]
}

pub fn validate_schema_vectors(vectors: &[SchemaValidationVector]) -> Result<()> {
    let registry = ProtocolSchemaRegistry::default();
    for vector in vectors {
        let valid = registry.validate_value(&vector.schema_id, &vector.input).is_ok();
        if valid != vector.expected_valid {
            return Err(Error::Protocol(format!(
                "schema vector '{}' expected valid={} got valid={valid}",
                vector.name, vector.expected_valid
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaBreakingChange {
    RemovedSchema,
    NewRequiredField,
    TypeNarrowed,
    AdditionalPropertiesClosed,
    SecurityExtensionTrustWidened,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEvolutionPlan {
    pub from_version: String,
    pub to_version: String,
    pub affected_schemas: Vec<String>,
    pub breaking_changes: BTreeSet<SchemaBreakingChange>,
}

impl SchemaEvolutionPlan {
    pub fn validate_release_candidate(&self) -> Result<()> {
        if self.from_version.trim().is_empty() || self.to_version.trim().is_empty() {
            return Err(Error::Protocol("schema evolution versions must be present".to_owned()));
        }
        if self.affected_schemas.is_empty() {
            return Err(Error::Protocol("schema evolution must name affected schemas".to_owned()));
        }
        if !self.breaking_changes.is_empty() {
            return Err(Error::Protocol(format!(
                "schema evolution contains breaking changes: {:?}",
                self.breaking_changes
            )));
        }
        Ok(())
    }
}

pub fn generated_validators() -> Result<BTreeMap<String, GeneratedSchemaValidator>> {
    let registry = ProtocolSchemaRegistry::default();
    registry
        .schema_ids()
        .map(|schema_id| Ok((schema_id.to_owned(), registry.generated_validator(schema_id)?)))
        .collect()
}

pub mod protocol {
    pub use contrix_core::{
        CAPABILITY_SCHEMA, CLIENT_SYNC_RESPONSE_SCHEMA, COMMIT_SCHEMA, CURSOR_SCHEMA,
        ENCRYPTED_PAYLOAD_SCHEMA, ENTITY_SCHEMA, EVENT_SCHEMA, GeneratedSchemaField,
        GeneratedSchemaValidator, GeneratedSchemaValueType, OPERATION_SCHEMA,
        ProtocolSchemaRegistry, SCHEMA_COMPATIBILITY_PROFILE, SchemaCompatibilityEntry,
        SchemaCompatibilityTable, VIEW_SCHEMA, schema_version_compatibility_table,
    };
}

pub const CORE_SCHEMA_IDS: &[&str] = &[
    CURSOR_SCHEMA,
    ENTITY_SCHEMA,
    VIEW_SCHEMA,
    EVENT_SCHEMA,
    OPERATION_SCHEMA,
    COMMIT_SCHEMA,
    CAPABILITY_SCHEMA,
    ENCRYPTED_PAYLOAD_SCHEMA,
    CLIENT_SYNC_RESPONSE_SCHEMA,
];

pub fn compatibility_table() -> SchemaCompatibilityTable {
    schema_version_compatibility_table()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_catalog_has_compatibility_for_all_registered_schemas() {
        let catalog = schema_catalog();
        catalog.validate().unwrap();
        assert!(catalog.entries.iter().any(|entry| entry.schema_id == OPERATION_SCHEMA));
    }

    #[test]
    fn schema_vectors_include_negative_security_extension_case() {
        validate_schema_vectors(&built_in_schema_vectors()).unwrap();
    }

    #[test]
    fn generated_validators_cover_core_schema_ids() {
        let validators = generated_validators().unwrap();
        for schema_id in CORE_SCHEMA_IDS {
            assert!(validators.contains_key(*schema_id), "{schema_id}");
        }
    }

    #[test]
    fn evolution_plan_rejects_breaking_release_candidate() {
        let mut breaking_changes = BTreeSet::new();
        breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
        let plan = SchemaEvolutionPlan {
            from_version: "0.1.0".to_owned(),
            to_version: "0.2.0".to_owned(),
            affected_schemas: vec![OPERATION_SCHEMA.to_owned()],
            breaking_changes,
        };
        assert!(matches!(plan.validate_release_candidate(), Err(Error::Protocol(_))));
    }
}
