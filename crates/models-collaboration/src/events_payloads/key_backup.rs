//! Key-backup active-series event payloads and transition validation.

use arkret_models_crypto::KeyBackupSourceCommitRef;
use arkret_wire::ActorId;

use crate::internal_prelude::*;

/// Counterpart for the closed current-generation device authorization binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesSignatureProof {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub device_authorize_event_id: Option<EventId>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedKeyBackupActiveSeriesAuthData {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
    device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: ActorId,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub source_commit_ref: Option<KeyBackupSourceCommitRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub effective_scope: Option<ScopeRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub manager_ref: Option<CommittedEventRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub recovery_ref: Option<CommittedEventRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub recipient_ref: Option<CommittedEventRef>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub signature_proof: KeyBackupActiveSeriesSignatureProof,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub custodian_actor_id: Option<ActorId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub custody_authorization_ref: Option<EventId>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Serialize for KeyBackupActiveSeries {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        KeyBackupActiveSeries::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeries {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let record = KeyBackupActiveSeries::deserialize(deserializer)?;
        validate_key_backup_active_series_record(&record).map_err(serde::de::Error::custom)?;
        Ok(record)
    }
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
    source_commit_ref: KeyBackupSourceCommitRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    signature_proof: UnsignedKeyBackupActiveSeriesAuthData,
    #[serde(skip_serializing_if = "Option::is_none")]
    custodian_actor_id: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custody_authorization_ref: Option<EventId>,
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
            source_commit_ref: KeyBackupSourceCommitRef {
                realm_commit_id,
                device_generation_ref: trust_anchor.generation_ref,
            },
            issued_at,
            signature_proof: UnsignedKeyBackupActiveSeriesAuthData {
                verification_method,
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                device_authorize_event_id: trust_anchor.authorize_event_id,
            },
            custodian_actor_id: None,
            custody_authorization_ref: None,
            extra: BTreeMap::new(),
        })
    }

    /// Bind a controller-signed Agent series selection to accepted immutable custody.
    /// Native provision, policy, Station and current-device verification remains mandatory.
    pub fn with_agent_custody(
        mut self,
        custodian: ActorId,
        authorization: EventId,
    ) -> Result<Self> {
        let subject = self.actor_id.as_account_id();
        let controller = custodian.as_account_id();
        if subject.is_none()
            || controller.is_none()
            || subject == controller
            || subject.map(|a| &a.station_id) != controller.map(|a| &a.station_id)
        {
            return Err(WireError::Protocol(
                "Agent custody requires distinct same-Station Account actors".into(),
            ));
        }
        self.custodian_actor_id = Some(custodian);
        self.custody_authorization_ref = Some(authorization);
        Ok(self)
    }

    /// Canonical bytes signed by active-series producers and verified by all
    /// receivers. The unsigned typestate serializes exactly like the signed
    /// wire record except that `signature_proof.signature` does not exist yet.
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
            source_commit_ref: Some(self.source_commit_ref),
            effective_scope: None,
            manager_ref: None,
            recovery_ref: None,
            recipient_ref: None,
            issued_at: self.issued_at,
            signature_proof: KeyBackupActiveSeriesSignatureProof {
                verification_method: self.signature_proof.verification_method,
                signature_algorithm: self.signature_proof.signature_algorithm,
                signature,
                device_authorize_event_id: Some(self.signature_proof.device_authorize_event_id),
            },
            custodian_actor_id: self.custodian_actor_id,
            custody_authorization_ref: self.custody_authorization_ref,
            extra: self.extra,
        })
    }
}

impl KeyBackupActiveSeries {
    /// Canonical bytes covered by `signature_proof.signature`.
    ///
    /// The active-series schema excludes only the signature member itself
    /// from this transcript. Keeping that operation on the public model avoids
    /// every producer and verifier growing its own JSON-shape implementation.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        validate_key_backup_active_series_record(self)
            .map_err(|e| WireError::Protocol(e.to_string()))?;
        let mut value = serde_json::to_value(self)?;
        value
            .get_mut("signature_proof")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| WireError::Protocol("missing active series proof".into()))?
            .remove("signature");
        Ok(canonical::canonical_json_bytes(&value)?)
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
    pub effective_scope: Option<ScopeRef>,
}

/// Current authority-projected generation and accepted device authorization used
/// to sign one active-series selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerBackupTrustAnchor {
    pub authorize_event_id: EventId,
    pub generation_ref: u64,
}

impl ControllerBackupTrustAnchor {
    pub fn from_record(record: &KeyBackupActiveSeries) -> Result<Self> {
        validate_key_backup_active_series_record(record)
            .map_err(|e| WireError::Protocol(e.to_string()))?;
        Ok(Self {
            authorize_event_id: record
                .signature_proof
                .device_authorize_event_id
                .clone()
                .ok_or_else(|| {
                    WireError::Protocol(
                        "native Service series has no Controller Device trust anchor".into(),
                    )
                })?,
            generation_ref: record
                .source_commit_ref
                .as_ref()
                .ok_or_else(|| {
                    WireError::Protocol("native Service series has no PCR generation".into())
                })?
                .device_generation_ref,
        })
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
    outcome: &arkret_models_crypto::keys::KeysQueryResponseBody,
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
    if current.actor_id != record.actor_id
        || current.backup_kind != record.backup_kind
        || current.effective_scope != record.effective_scope
    {
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
    match &record.actor_id {
        ActorId::Realm { realm_actor_id } => {
            let scope = record
                .effective_scope
                .as_ref()
                .ok_or(KeyBackupActiveSeriesTransitionError::SchemaMismatch)?;
            arkret_models_crypto::validate_realm_actor_backup_scope(realm_actor_id, scope)
                .map_err(|_| KeyBackupActiveSeriesTransitionError::ActorOrClassMismatch)?;
            if record.source_commit_ref.is_some()
                || record.signature_proof.device_authorize_event_id.is_some()
                || record.custodian_actor_id.is_some()
                || record.custody_authorization_ref.is_some()
                || record.manager_ref.is_none()
                || record.recovery_ref.is_none()
                || record.recipient_ref.is_none()
            {
                return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
            }
        }
        _ => {
            if record
                .source_commit_ref
                .as_ref()
                .is_none_or(|source| source.device_generation_ref == 0)
                || record.signature_proof.device_authorize_event_id.is_none()
                || record.effective_scope.is_some()
                || record.manager_ref.is_some()
                || record.recovery_ref.is_some()
                || record.recipient_ref.is_some()
            {
                return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
            }
        }
    }
    if record.series_pointer_version == 0
        || record.signature_proof.signature_algorithm != KeyBackupSignatureAlgorithm::Ed25519
    {
        return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
    }
    if record.custodian_actor_id.is_some() != record.custody_authorization_ref.is_some() {
        return Err(KeyBackupActiveSeriesTransitionError::SchemaMismatch);
    }
    if let Some(custodian) = &record.custodian_actor_id {
        let subject = record.actor_id.as_account_id();
        let controller = custodian.as_account_id();
        if subject.is_none()
            || controller.is_none()
            || subject == controller
            || subject.map(|a| &a.station_id) != controller.map(|a| &a.station_id)
        {
            return Err(KeyBackupActiveSeriesTransitionError::ActorOrClassMismatch);
        }
    }
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
        effective_scope: record.effective_scope.clone(),
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

/// Local unsigned manager-Service series selection. This is not a Device
/// authorization or an accepted current projection.
#[derive(Clone, Debug)]
pub struct UnsignedRealmActorKeyBackupActiveSeries {
    actor_id: RealmActorId,
    effective_scope: ScopeRef,
    active_series_id: BackupSeriesId,
    series_pointer_version: u64,
    previous_series_ids: Vec<BackupSeriesId>,
    manager_ref: CommittedEventRef,
    recovery_ref: CommittedEventRef,
    recipient_ref: CommittedEventRef,
    issued_at: DateTime<Utc>,
    verification_method: DidUrl,
}

impl UnsignedRealmActorKeyBackupActiveSeries {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_id: RealmActorId,
        effective_scope: ScopeRef,
        active_series_id: BackupSeriesId,
        series_pointer_version: u64,
        previous_series_ids: Vec<BackupSeriesId>,
        manager_ref: CommittedEventRef,
        recovery_ref: CommittedEventRef,
        recipient_ref: CommittedEventRef,
        issued_at: DateTime<Utc>,
        verification_method: DidUrl,
    ) -> Result<Self> {
        arkret_models_crypto::validate_realm_actor_backup_scope(&actor_id, &effective_scope)?;
        if series_pointer_version == 0
            || previous_series_ids.contains(&active_series_id)
            || previous_series_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != previous_series_ids.len()
        {
            return Err(WireError::Protocol(
                "invalid native active series selection".into(),
            ));
        }
        Ok(Self {
            actor_id,
            effective_scope,
            active_series_id,
            series_pointer_version,
            previous_series_ids,
            manager_ref,
            recovery_ref,
            recipient_ref,
            issued_at,
            verification_method,
        })
    }

    fn unsigned(&self) -> Value {
        serde_json::json!({
            "schema": SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
            "actor_id": ActorId::Realm { realm_actor_id: self.actor_id.clone() },
            "backup_kind": BackupKind::SecretStorage,
            "active_series_id": self.active_series_id,
            "series_pointer_version": self.series_pointer_version,
            "previous_series_ids": self.previous_series_ids,
            "effective_scope": self.effective_scope,
            "manager_ref": self.manager_ref, "recovery_ref": self.recovery_ref,
            "recipient_ref": self.recipient_ref,
            "issued_at": arkret_canonical::format_timestamp_canonical(self.issued_at),
            "signature_proof": {"verification_method": self.verification_method, "signature_algorithm": "Ed25519"}
        })
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(&self.unsigned())?)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<KeyBackupActiveSeries> {
        if arkret_canonical::base64url_decode(signature.as_str())?.len() != 64 {
            return Err(WireError::Protocol(
                "native series requires an actual Ed25519 signature".into(),
            ));
        }
        let mut value = self.unsigned();
        value["signature_proof"]["signature"] = serde_json::to_value(signature)?;
        let record: KeyBackupActiveSeries = serde_json::from_value(value)?;
        validate_key_backup_active_series_record(&record)
            .map_err(|e| WireError::Protocol(e.to_string()))?;
        Ok(record)
    }
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
                "realm_commit_id": record.source_commit_ref.as_ref().unwrap().realm_commit_id,
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
            record
                .source_commit_ref
                .as_ref()
                .unwrap()
                .realm_commit_id
                .as_str()
        );
        assert_eq!(unsigned["source_commit_ref"]["device_generation_ref"], 3);
        assert!(unsigned.get("source_ref").is_none());
        assert!(unsigned["signature_proof"].get("signature").is_none());
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

        let mut old_nested = value;
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
