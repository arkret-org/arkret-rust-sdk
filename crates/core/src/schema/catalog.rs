use super::*;

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
            name: "flow minimal valid".to_owned(),
            schema_id: FLOW_SCHEMA.to_owned(),
            input: json!({
                "schema": "cx.schema.flow.v1",
                "id": "cx:flow:01904100-0000-7000-8000-b30c13414158",
                "type": "flow",
                "space_id": "cx:space:01904100-0000-7000-8000-65c7feb295d7",
                "title": "Payment refactor",
                "tracks": {"synthesis": {}},
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-02T00:00:00Z"
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope minimal valid".to_owned(),
            schema_id: EVENT_SCHEMA.to_owned(),
            input: json!({
                "event_id": "cx:event:01904100-0000-7000-8000-a0086f45c575",
                "kind": "cx.message.create",
                "space_id": "cx:space:01904100-0000-7000-8000-65c7feb295d7",
                "actor_id": "did:web:alice.example",
                "actor_seq": 1,
                "created_at": "2026-05-02T00:00:00Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "refs": [],
                "payload": {"body": "hello"},
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope rejects untrusted security extension".to_owned(),
            schema_id: EVENT_SCHEMA.to_owned(),
            input: json!({
                "event_id": "cx:event:01904100-0000-7000-8000-a0086f45c575",
                "space_id": "cx:space:01904100-0000-7000-8000-65c7feb295d7",
                "actor_id": "did:web:alice.example",
                "actor_seq": 1,
                "kind": "cx.message.create",
                "created_at": "2026-05-02T00:00:00Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "refs": [],
                "payload": {},
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "payload_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }],
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
