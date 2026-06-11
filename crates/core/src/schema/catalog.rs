use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogEntry {
    pub schema_id: String,
    pub current_version: String,
    pub generated_validator: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogReport {
    pub profile: String,
    pub entries: Vec<SchemaCatalogEntry>,
}

impl SchemaCatalogReport {
    pub fn validate(&self) -> Result<()> {
        if self.profile != CORE_SCHEMA_PROFILE {
            return Err(Error::Protocol(
                "schema catalog profile mismatch".to_owned(),
            ));
        }
        let registry = ProtocolSchemaRegistry::default();
        let registered = registry.schema_ids().collect::<BTreeSet<_>>();
        let reported = self
            .entries
            .iter()
            .map(|entry| entry.schema_id.as_str())
            .collect();
        if registered != reported {
            return Err(Error::Protocol(
                "schema catalog does not match registry".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn schema_catalog() -> SchemaCatalogReport {
    let registry = ProtocolSchemaRegistry::default();
    let mut entries = Vec::new();
    for schema_id in registry.schema_ids() {
        entries.push(catalog_entry(&registry, schema_id));
    }
    entries.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    SchemaCatalogReport {
        profile: CORE_SCHEMA_PROFILE.to_owned(),
        entries,
    }
}

fn catalog_entry(registry: &ProtocolSchemaRegistry, schema_id: &str) -> SchemaCatalogEntry {
    SchemaCatalogEntry {
        schema_id: schema_id.to_owned(),
        current_version: "1".to_owned(),
        generated_validator: registry.generated_validator(schema_id).is_ok(),
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
                "schema": "ck.schema.flow.v1",
                "id": "ck:flow:01904100-0000-7000-8000-b30c13414158",
                "realm_id": "ck:realm:01904100-0000-7000-8000-65c7feb295d7",
                "metadata": {"title": "Payment refactor"},
                "stage": "draft",
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
                "event_id": "ck:event:01904100-0000-7000-8000-a0086f45c575",
                "kind": "ck.message.create",
                "space_id": "ck:space:01904100-0000-7000-8000-65c7feb295d7",
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
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
                "event_id": "ck:event:01904100-0000-7000-8000-a0086f45c575",
                "space_id": "ck:space:01904100-0000-7000-8000-65c7feb295d7",
                "actor_id": "did:web:alice.example",
                "actor_seq": 1,
                "kind": "ck.message.create",
                "created_at": "2026-05-02T00:00:00Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "refs": [],
                "payload": {},
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
        let valid = registry
            .validate_value(&vector.schema_id, &vector.input)
            .is_ok();
        if valid != vector.expected_valid {
            return Err(Error::Protocol(format!(
                "schema vector '{}' expected valid={} got valid={valid}",
                vector.name, vector.expected_valid
            )));
        }
    }
    Ok(())
}
