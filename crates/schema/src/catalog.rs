use arkret_wire::SchemaId;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCatalogEntry {
    pub schema_id: String,
    pub current_version: String,
    pub object_shape_summary: bool,
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
        object_shape_summary: registry.generated_object_shape(schema_id).is_ok(),
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
            name: "strand minimal valid".to_owned(),
            schema_id: SchemaId::STRAND_V1.to_owned(),
            input: json!({
                "schema": "ak.schema.strand.v1",
                "id": "ak:strand:AU3CMWGZ9fcGNNxRY0A7kmogpXARmmE24lLmsuUwxyVG",
                "realm_id": "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                "metadata": {"title": "Payment refactor"},
                "stage": "draft",
                "tracks": {"synthesis": {}},
                "created_by": "did:webvh:z6mkfixture:alice.example",
                "created_at": "2026-05-02T00:00:00.000Z"
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope minimal valid".to_owned(),
            schema_id: SchemaId::EVENT_V1.to_owned(),
            input: json!({
                "event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
                "kind": "ak.message.create",
                "space_id": "ak:space:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                "actor_id": "did:webvh:z6mkfixture:alice.example",
                "actor_seq": 1,
                "created_at": "2026-05-02T00:00:00.000Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "refs": [],
                "payload": {"body": "hello"},
                "proofs": [{
                    "kind": "detached_jws",
                    "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00.000Z",
                    "jws": "a..b"
                }]
            }),
            expected_valid: true,
        },
        SchemaValidationVector {
            name: "event envelope rejects untrusted security extension".to_owned(),
            schema_id: SchemaId::EVENT_V1.to_owned(),
            input: json!({
                "event_id": "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
                "space_id": "ak:space:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                "actor_id": "did:webvh:z6mkfixture:alice.example",
                "actor_seq": 1,
                "kind": "ak.message.create",
                "created_at": "2026-05-02T00:00:00.000Z",
                "hlc": "01970e589d21-0000-a13f9c2e",
                "prev_refs": [],
                "refs": [],
                "payload": {},
                "proofs": [{
                    "kind": "detached_jws",
                    "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00.000Z",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_reports_all_registered_schemas() {
        let catalog = schema_catalog();
        catalog.validate().unwrap();
        assert!(
            catalog
                .entries
                .iter()
                .any(|entry| entry.schema_id == SchemaId::EVENT_V1)
        );
    }

    #[test]
    fn vectors_include_negative_security_extension_case() {
        validate_schema_vectors(&built_in_schema_vectors()).unwrap();
    }
}
