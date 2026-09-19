//! Key-backup active-series event payloads and transition validation.

use arkret_wire::ActorId;

use crate::internal_prelude::*;

/// Counterpart for the closed current-generation device authorization binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedKeyBackupActiveSeriesAuthData {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
    device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesSourceCommitRef {
    pub realm_commit_id: RealmCommitId,
    pub device_generation_ref: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: ActorId,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub source_commit_ref: KeyBackupActiveSeriesSourceCommitRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub auth_data: KeyBackupActiveSeriesAuthData,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Authoring-only active-series record before a signature exists.
///
/// Its fields are private so this state can only be created through [`Self::new`],
/// and it intentionally does not implement `Deserialize`: unsigned records are
/// never wire or persistence inputs.
#[derive(Clone, Debug, Serialize)]
pub struct UnsignedKeyBackupActiveSeries {
    schema: String,
    actor_id: ActorId,
    backup_kind: BackupKind,
    active_series_id: BackupSeriesId,
    series_pointer_version: u64,
    previous_series_ids: Vec<BackupSeriesId>,
    source_commit_ref: KeyBackupActiveSeriesSourceCommitRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    auth_data: UnsignedKeyBackupActiveSeriesAuthData,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl UnsignedKeyBackupActiveSeries {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_id: ActorId,
        backup_kind: BackupKind,
        active_series_id: BackupSeriesId,
        series_pointer_version: u64,
        previous_series_ids: Vec<BackupSeriesId>,
        realm_commit_id: RealmCommitId,
        issued_at: DateTime<Utc>,
        verification_method: DidUrl,
        trust_anchor: ControllerBackupTrustAnchor,
    ) -> Result<Self> {
        if series_pointer_version == 0 {
            return Err(WireError::Protocol(
                "active-series pointer version must be at least one".to_owned(),
            ));
        }
        if trust_anchor.generation_ref == 0 {
            return Err(WireError::Protocol(
                "active-series device generation must be positive".to_owned(),
            ));
        }
        if previous_series_ids
            .iter()
            .any(|series_id| series_id == &active_series_id)
        {
            return Err(WireError::Protocol(
                "active series cannot also be a previous series".to_owned(),
            ));
        }
        if previous_series_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != previous_series_ids.len()
        {
            return Err(WireError::Protocol(
                "previous active-series ids must be unique".to_owned(),
            ));
        }
        Ok(Self {
            schema: SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1.to_owned(),
            actor_id,
            backup_kind,
            active_series_id,
            series_pointer_version,
            previous_series_ids,
            source_commit_ref: KeyBackupActiveSeriesSourceCommitRef {
                realm_commit_id,
                device_generation_ref: trust_anchor.generation_ref,
            },
            issued_at,
            auth_data: UnsignedKeyBackupActiveSeriesAuthData {
                verification_method,
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                device_authorize_event_id: trust_anchor.authorize_event_id,
            },
            extra: BTreeMap::new(),
        })
    }

    /// Canonical bytes signed by active-series producers and verified by all
    /// receivers. The unsigned typestate serializes exactly like the signed
    /// wire record except that `auth_data.signature` does not exist yet.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(self)?)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<KeyBackupActiveSeries> {
        Ok(KeyBackupActiveSeries {
            schema: self.schema,
            actor_id: self.actor_id,
            backup_kind: self.backup_kind,
            active_series_id: self.active_series_id,
            series_pointer_version: self.series_pointer_version,
            previous_series_ids: self.previous_series_ids,
            source_commit_ref: self.source_commit_ref,
            issued_at: self.issued_at,
            auth_data: KeyBackupActiveSeriesAuthData {
                verification_method: self.auth_data.verification_method,
                signature_algorithm: self.auth_data.signature_algorithm,
                signature,
                device_authorize_event_id: self.auth_data.device_authorize_event_id,
            },
            extra: self.extra,
        })
    }
}

impl KeyBackupActiveSeries {
    /// Canonical bytes covered by `auth_data.signature`.
    ///
    /// The active-series schema excludes only the signature member itself
    /// from this transcript. Keeping that operation on the public model avoids
    /// every producer and verifier growing its own JSON-shape implementation.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        let unsigned = UnsignedKeyBackupActiveSeries {
            schema: self.schema.clone(),
            actor_id: self.actor_id.clone(),
            backup_kind: self.backup_kind,
            active_series_id: self.active_series_id.clone(),
            series_pointer_version: self.series_pointer_version,
            previous_series_ids: self.previous_series_ids.clone(),
            source_commit_ref: self.source_commit_ref.clone(),
            issued_at: self.issued_at,
            auth_data: UnsignedKeyBackupActiveSeriesAuthData {
                verification_method: self.auth_data.verification_method.clone(),
                signature_algorithm: self.auth_data.signature_algorithm,
                device_authorize_event_id: self.auth_data.device_authorize_event_id.clone(),
            },
            extra: self.extra.clone(),
        };
        unsigned.signing_payload_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesHead {
    pub actor_id: ActorId,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub record_digest: String,
}

/// Current authority-projected generation and accepted device authorization used
/// to sign one active-series selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerBackupTrustAnchor {
    pub authorize_event_id: EventId,
    pub generation_ref: u64,
}

impl ControllerBackupTrustAnchor {
    pub fn from_record(record: &KeyBackupActiveSeries) -> Self {
        Self {
            authorize_event_id: record.auth_data.device_authorize_event_id.clone(),
            generation_ref: record.source_commit_ref.device_generation_ref,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControllerBackupTrustAnchorError {
    #[error("controller_backup_trust_anchor_device_unknown")]
    DeviceUnknown,
    #[error("controller_backup_trust_anchor_device_not_current")]
    DeviceNotCurrent,
}

pub fn resolve_controller_backup_trust_anchor(
    outcome: &arkret_models_crypto::keys::KeysQueryOutcome,
    account_id: &AccountId,
    device_id: &DeviceId,
) -> std::result::Result<ControllerBackupTrustAnchor, ControllerBackupTrustAnchorError> {
    let record = outcome
        .devices_for(account_id)
        .and_then(|devices| devices.get(device_id))
        .ok_or(ControllerBackupTrustAnchorError::DeviceUnknown)?;
    let generation_state = outcome.generation_for(account_id);
    // The row is already positioned by `account_id` and the `device_id` map key
    // its own Station matched against the verified origin attestation, so the
    // self projection carries no identity of its own to re-check.
    record
        .validate_projection()
        .map_err(|_| ControllerBackupTrustAnchorError::DeviceNotCurrent)?;
    if !record.is_usable_in_generation(generation_state) {
        return Err(ControllerBackupTrustAnchorError::DeviceNotCurrent);
    }
    Ok(ControllerBackupTrustAnchor {
        authorize_event_id: record.device_projection.device_authorize_event_id.clone(),
        generation_ref: generation_state
            .expect("usable record has generation state")
            .current_device_generation_ref,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyBackupActiveSeriesTransitionError {
    #[error("key_backup_active_series_schema_mismatch")]
    SchemaMismatch,
    #[error("key_backup_active_series_active_in_previous")]
    ActiveInPrevious,
    #[error("key_backup_active_series_previous_series_duplicate")]
    PreviousSeriesDuplicate,
    #[error("key_backup_active_series_actor_or_class_mismatch")]
    ActorOrClassMismatch,
    #[error("key_backup_active_series_pointer_version_rollback")]
    PointerVersionRollback,
    #[error("key_backup_active_series_pointer_version_gap")]
    PointerVersionGap,
    #[error("key_backup_active_series_pointer_version_fork")]
    PointerVersionFork,
}

impl KeyBackupActiveSeriesTransitionError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::SchemaMismatch => "key_backup_active_series_schema_mismatch",
            Self::ActiveInPrevious => "key_backup_active_series_active_in_previous",
            Self::PreviousSeriesDuplicate => "key_backup_active_series_previous_series_duplicate",
            Self::ActorOrClassMismatch => "key_backup_active_series_actor_or_class_mismatch",
            Self::PointerVersionRollback => "key_backup_active_series_pointer_version_rollback",
            Self::PointerVersionGap => "key_backup_active_series_pointer_version_gap",
            Self::PointerVersionFork => "key_backup_active_series_pointer_version_fork",
        }
    }
}

pub fn validate_key_backup_active_series_transition(
    current: Option<&KeyBackupActiveSeriesHead>,
    record: &KeyBackupActiveSeries,
) -> std::result::Result<KeyBackupActiveSeriesHead, KeyBackupActiveSeriesTransitionError> {
    validate_key_backup_active_series_record(record)?;
    let next = key_backup_active_series_head(record)?;
    let Some(current) = current else {
        return if record.series_pointer_version == 1 {
            Ok(next)
        } else {
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap)
        };
    };
    if current.actor_id != record.actor_id || current.backup_kind != record.backup_kind {
        return Err(KeyBackupActiveSeriesTransitionError::ActorOrClassMismatch);
    }
    if record.series_pointer_version == current.series_pointer_version {
        return if current.record_digest == next.record_digest {
            Ok(current.clone())
        } else {
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionFork)
        };
    }
    let expected = current.series_pointer_version.saturating_add(1);
    if record.series_pointer_version < expected {
        return Err(KeyBackupActiveSeriesTransitionError::PointerVersionRollback);
    }
    if record.series_pointer_version > expected {
        return Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap);
    }
    Ok(next)
}

/// Validate one active-series record independently of the prior projection.
pub fn validate_key_backup_active_series_record(
    record: &KeyBackupActiveSeries,
) -> std::result::Result<(), KeyBackupActiveSeriesTransitionError> {
    if record.schema != SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1
        || record
            .extra
            .keys()
            .any(|key| !valid_active_series_extension_key(key))
    {
        return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
    }
    if record
        .previous_series_ids
        .iter()
        .any(|series_id| series_id == &record.active_series_id)
    {
        return Err(KeyBackupActiveSeriesTransitionError::ActiveInPrevious);
    }
    let previous = record
        .previous_series_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if previous.len() != record.previous_series_ids.len() {
        return Err(KeyBackupActiveSeriesTransitionError::PreviousSeriesDuplicate);
    }
    Ok(())
}

pub fn key_backup_active_series_head(
    record: &KeyBackupActiveSeries,
) -> std::result::Result<KeyBackupActiveSeriesHead, KeyBackupActiveSeriesTransitionError> {
    let record_digest = canonical::canonical_sha256(record)
        .map_err(|_| KeyBackupActiveSeriesTransitionError::SchemaMismatch)?;
    Ok(KeyBackupActiveSeriesHead {
        actor_id: record.actor_id.clone(),
        backup_kind: record.backup_kind,
        active_series_id: record.active_series_id.clone(),
        series_pointer_version: record.series_pointer_version,
        previous_series_ids: record.previous_series_ids.clone(),
        record_digest,
    })
}

fn valid_active_series_extension_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("x_") else {
        return false;
    };
    if rest.is_empty() || rest.len() > 64 {
        return false;
    }
    let mut chars = rest.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|candidate| {
            candidate.is_ascii_lowercase() || candidate.is_ascii_digit() || candidate == '_'
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use arkret_schema::ProtocolSchemaRegistry;
    use arkret_schema_conformance::schema_registry_from_spec_artifacts;
    use chrono::TimeZone;
    use serde_json::{Value, json};

    use super::*;

    fn record() -> KeyBackupActiveSeries {
        UnsignedKeyBackupActiveSeries::new(
            ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkaccount").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
            )),
            BackupKind::SecretStorage,
            BackupSeriesId::new("ak:backup_series:01997c77-7ac0-7000-8000-000000000001").unwrap(),
            1,
            Vec::new(),
            RealmCommitId::from_digest([7; 32]),
            Utc.with_ymd_and_hms(2026, 9, 20, 0, 0, 0).unwrap(),
            DidUrl::new("did:web:account.example#device-1").unwrap(),
            ControllerBackupTrustAnchor {
                authorize_event_id: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [8; 32],
                ),
                generation_ref: 3,
            },
        )
        .unwrap()
        .attach_signature(Base64UrlString::new("AQ").unwrap())
        .unwrap()
    }

    fn schema_registry() -> (ProtocolSchemaRegistry, String) {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("the arkret-spec artifacts checkout must be reachable for conformance");
        let mut registry = schema_registry_from_spec_artifacts(&artifacts)
            .expect("the spec artifacts must produce a schema registry");
        let path = artifacts
            .join("schemas")
            .join("key-backup-active-series.schema.json");
        let schema: Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
        )
        .expect("active-series schema must be valid JSON");
        registry
            .register_reference_document(schema.clone())
            .expect("active-series schema declares an absolute $id");
        let schema_id = "test:key-backup-active-series".to_owned();
        registry
            .register_fragment(schema_id.clone(), schema, "#")
            .expect("active-series schema root must register");
        (registry, schema_id)
    }

    #[test]
    fn active_series_uses_the_closed_source_commit_ref_shape() {
        let record = record();
        let value = serde_json::to_value(&record).unwrap();
        assert!(value.get("source_ref").is_none());
        assert_eq!(
            value["source_commit_ref"],
            json!({
                "realm_commit_id": record.source_commit_ref.realm_commit_id,
                "device_generation_ref": 3,
            })
        );

        let (registry, schema_id) = schema_registry();
        registry
            .validate_value(&schema_id, &value)
            .expect("SDK active-series record must match the live schema");
        let round_trip: KeyBackupActiveSeries = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(round_trip).unwrap(), value);
    }

    #[test]
    fn signing_payload_binds_source_commit_ref_and_excludes_only_signature() {
        let record = record();
        let unsigned: Value =
            arkret_canonical::from_canonical_json_slice(&record.signing_payload_bytes().unwrap())
                .unwrap();
        assert_eq!(
            unsigned["source_commit_ref"]["realm_commit_id"],
            record.source_commit_ref.realm_commit_id.as_str()
        );
        assert_eq!(unsigned["source_commit_ref"]["device_generation_ref"], 3);
        assert!(unsigned.get("source_ref").is_none());
        assert!(unsigned["auth_data"].get("signature").is_none());
    }

    #[test]
    fn old_source_ref_and_full_committed_ref_shapes_are_rejected() {
        let value = serde_json::to_value(record()).unwrap();

        let mut old_top_level = value.clone();
        let source_commit_ref = old_top_level
            .as_object_mut()
            .unwrap()
            .remove("source_commit_ref")
            .unwrap();
        old_top_level
            .as_object_mut()
            .unwrap()
            .insert("source_ref".to_owned(), source_commit_ref);
        assert!(serde_json::from_value::<KeyBackupActiveSeries>(old_top_level.clone()).is_err());

        let mut old_nested = value.clone();
        old_nested["source_commit_ref"] = json!({
            "commit_ref": {
                "event_id": "ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2",
                "commit_id": RealmCommitId::from_digest([7; 32]),
                "stream_ref": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                },
                "stream_position": 1
            },
            "device_generation_ref": 3
        });
        assert!(serde_json::from_value::<KeyBackupActiveSeries>(old_nested.clone()).is_err());

        let (registry, schema_id) = schema_registry();
        assert!(registry.validate_value(&schema_id, &old_top_level).is_err());
        assert!(registry.validate_value(&schema_id, &old_nested).is_err());
    }
}
