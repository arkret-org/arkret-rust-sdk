//! Key-backup active-series event payloads and transition validation.

use arkret_wire::DidCoreId;

use crate::internal_prelude::*;

/// Top-level application fields declared by `auth_data.signed_fields`.
///
/// The signature transcript also binds every `auth_data` member except the
/// signature itself. Those members are signature-envelope metadata rather
/// than application fields, so they are intentionally not repeated here.
pub const KEY_BACKUP_ACTIVE_SERIES_SIGNED_FIELDS: [&str; 8] = [
    "schema",
    "actor_id",
    "backup_kind",
    "active_series_id",
    "series_pointer_version",
    "previous_series_ids",
    "frontier_ref",
    "issued_at",
];

/// A real active-series signature. The unsigned state has no value of this
/// type, and the historical `"pending"` sentinel is rejected at every typed
/// construction and deserialization boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct KeyBackupActiveSeriesSignature(Base64UrlString);

impl KeyBackupActiveSeriesSignature {
    pub fn new(signature: Base64UrlString) -> Result<Self> {
        if signature.as_str() == "pending" {
            return Err(Error::Protocol(
                "active-series signature cannot be the pending sentinel".to_owned(),
            ));
        }
        Ok(Self(signature))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeriesSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let signature = Base64UrlString::deserialize(deserializer)?;
        Self::new(signature).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for the closed current-generation device authorization binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: KeyBackupActiveSeriesSignature,
    pub signed_fields: Vec<String>,
    pub device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedKeyBackupActiveSeriesAuthData {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
    signed_fields: Vec<String>,
    device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesFrontierRef {
    pub frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SealId>,
    pub device_generation_ref: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: DidCoreId,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub frontier_ref: KeyBackupActiveSeriesFrontierRef,
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
    actor_id: DidCoreId,
    backup_kind: BackupKind,
    active_series_id: BackupSeriesId,
    series_pointer_version: u64,
    previous_series_ids: Vec<BackupSeriesId>,
    frontier_ref: KeyBackupActiveSeriesFrontierRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
    auth_data: UnsignedKeyBackupActiveSeriesAuthData,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl UnsignedKeyBackupActiveSeries {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_id: DidCoreId,
        backup_kind: BackupKind,
        active_series_id: BackupSeriesId,
        series_pointer_version: u64,
        previous_series_ids: Vec<BackupSeriesId>,
        frontier_digest: Hash,
        seal_ref: Option<SealId>,
        issued_at: DateTime<Utc>,
        verification_method: DidUrl,
        trust_anchor: ControllerBackupTrustAnchor,
    ) -> Result<Self> {
        if series_pointer_version == 0 {
            return Err(Error::Protocol(
                "active-series pointer version must be at least one".to_owned(),
            ));
        }
        if trust_anchor.generation_ref == 0 {
            return Err(Error::Protocol(
                "active-series device generation must be positive".to_owned(),
            ));
        }
        if previous_series_ids
            .iter()
            .any(|series_id| series_id == &active_series_id)
        {
            return Err(Error::Protocol(
                "active series cannot also be a previous series".to_owned(),
            ));
        }
        if previous_series_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != previous_series_ids.len()
        {
            return Err(Error::Protocol(
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
            frontier_ref: KeyBackupActiveSeriesFrontierRef {
                frontier_digest,
                seal_ref,
                device_generation_ref: trust_anchor.generation_ref,
            },
            issued_at,
            auth_data: UnsignedKeyBackupActiveSeriesAuthData {
                verification_method,
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                signed_fields: KEY_BACKUP_ACTIVE_SERIES_SIGNED_FIELDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
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
            frontier_ref: self.frontier_ref,
            issued_at: self.issued_at,
            auth_data: KeyBackupActiveSeriesAuthData {
                verification_method: self.auth_data.verification_method,
                signature_algorithm: self.auth_data.signature_algorithm,
                signature: KeyBackupActiveSeriesSignature::new(signature)?,
                signed_fields: self.auth_data.signed_fields,
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
            frontier_ref: self.frontier_ref.clone(),
            issued_at: self.issued_at,
            auth_data: UnsignedKeyBackupActiveSeriesAuthData {
                verification_method: self.auth_data.verification_method.clone(),
                signature_algorithm: self.auth_data.signature_algorithm,
                signed_fields: self.auth_data.signed_fields.clone(),
                device_authorize_event_id: self.auth_data.device_authorize_event_id.clone(),
            },
            extra: self.extra.clone(),
        };
        unsigned.signing_payload_bytes()
    }

    /// Canonical CAS cell selected by `(actor_id, backup_kind)`.
    pub fn cell_ref(&self) -> Result<CellRef> {
        let subject = composite_subject(&[self.actor_id.as_str(), self.backup_kind.as_str()])?;
        Ok(CellRef::new(format!(
            "ak:cell:{}:{subject}",
            CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesHead {
    pub actor_id: DidCoreId,
    pub backup_kind: BackupKind,
    pub active_series_id: BackupSeriesId,
    pub series_pointer_version: u64,
    pub previous_series_ids: Vec<BackupSeriesId>,
    pub record_digest: String,
}

/// Current reducer-managed generation and accepted device authorization used
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
            generation_ref: record.frontier_ref.device_generation_ref,
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
    principal: &DidCoreId,
    device_id: &DeviceId,
) -> std::result::Result<ControllerBackupTrustAnchor, ControllerBackupTrustAnchorError> {
    let record = outcome
        .device_keys
        .get(&principal.clone())
        .and_then(|devices| devices.get(device_id))
        .ok_or(ControllerBackupTrustAnchorError::DeviceUnknown)?;
    let generation_state = outcome.device_generations.get(&principal.clone());
    if !record.is_usable_in_generation(generation_state) {
        return Err(ControllerBackupTrustAnchorError::DeviceNotCurrent);
    }
    Ok(ControllerBackupTrustAnchor {
        authorize_event_id: record.device_authorize_event_id.clone(),
        generation_ref: generation_state
            .expect("usable record has generation state")
            .current_device_generation_ref,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyBackupActiveSeriesTransitionError {
    #[error("key_backup_active_series_schema_mismatch")]
    SchemaMismatch,
    #[error("key_backup_active_series_signed_fields_duplicate")]
    SignedFieldsDuplicate,
    #[error("key_backup_active_series_signed_fields_incomplete")]
    SignedFieldsIncomplete,
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
            Self::SignedFieldsDuplicate => "key_backup_active_series_signed_fields_duplicate",
            Self::SignedFieldsIncomplete => "key_backup_active_series_signed_fields_incomplete",
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

/// Validate one active-series record independently of its predecessor. This is
/// shared by admission, authority, and reducer paths so `signed_fields`
/// duplicate/incomplete semantics cannot diverge between verifiers.
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
    let signed_fields = record
        .auth_data
        .signed_fields
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if signed_fields.len() != record.auth_data.signed_fields.len() {
        return Err(KeyBackupActiveSeriesTransitionError::SignedFieldsDuplicate);
    }
    if KEY_BACKUP_ACTIVE_SERIES_SIGNED_FIELDS
        .iter()
        .any(|required| {
            !signed_fields
                .iter()
                .any(|candidate| candidate.as_str() == *required)
        })
    {
        return Err(KeyBackupActiveSeriesTransitionError::SignedFieldsIncomplete);
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
    use super::*;

    fn unsigned_fixture() -> UnsignedKeyBackupActiveSeries {
        UnsignedKeyBackupActiveSeries::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            BackupKind::MlsHistory,
            BackupSeriesId::new("ak:backup_series:019a6760-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            1,
            vec![],
            Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            Some(SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap()),
            DateTime::parse_from_rfc3339("2026-08-08T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            DidUrl::new("did:web:alice.example#device-1".to_owned()).unwrap(),
            ControllerBackupTrustAnchor {
                authorize_event_id: EventId::new(
                    "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e".to_owned(),
                )
                .unwrap(),
                generation_ref: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn active_series_signing_transcript_kat_is_stable_across_typestates() {
        const EXPECTED: &str = concat!(
            r#"{"active_series_id":"ak:backup_series:019a6760-0000-7000-8000-000000000001","actor_id":"ak:did_core:web:alice.example","auth_data":{"device_authorize_event_id":"ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e","signature_algorithm":"Ed25519","signed_fields":["schema","actor_id","backup_kind","active_series_id","series_pointer_version","previous_series_ids","frontier_ref","issued_at"],"verification_method":"did:web:alice.example#device-1"},"backup_kind":"mls_history","frontier_ref":{"device_generation_ref":1,"frontier_digest":"sha256:"#,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            r#"","seal_ref":"ak:seal:sha256:"#,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            r#""},"issued_at":"2026-08-08T00:00:00.000Z","previous_series_ids":[],"schema":"ak.schema.key_backup_active_series.v1","series_pointer_version":1}"#,
        );
        let unsigned = unsigned_fixture();
        assert_eq!(
            unsigned.signing_payload_bytes().unwrap(),
            EXPECTED.as_bytes()
        );

        let signed = unsigned
            .attach_signature(Base64UrlString::new("AQ".to_owned()).unwrap())
            .unwrap();
        assert_eq!(signed.signing_payload_bytes().unwrap(), EXPECTED.as_bytes());
    }

    #[test]
    fn signed_active_series_rejects_the_historical_pending_sentinel() {
        let unsigned = unsigned_fixture();
        assert!(
            unsigned
                .attach_signature(Base64UrlString::new("pending".to_owned()).unwrap())
                .is_err()
        );

        let signed = unsigned_fixture()
            .attach_signature(Base64UrlString::new("AQ".to_owned()).unwrap())
            .unwrap();
        let mut value = serde_json::to_value(signed).unwrap();
        value["auth_data"]["signature"] = Value::String("pending".to_owned());
        assert!(serde_json::from_value::<KeyBackupActiveSeries>(value).is_err());
    }

    #[test]
    fn signed_fields_duplicate_and_incomplete_reasons_are_stable() {
        let mut duplicate = unsigned_fixture()
            .attach_signature(Base64UrlString::new("AQ".to_owned()).unwrap())
            .unwrap();
        duplicate.auth_data.signed_fields.push("schema".to_owned());
        assert_eq!(
            validate_key_backup_active_series_transition(None, &duplicate),
            Err(KeyBackupActiveSeriesTransitionError::SignedFieldsDuplicate)
        );

        let mut incomplete = unsigned_fixture()
            .attach_signature(Base64UrlString::new("AQ".to_owned()).unwrap())
            .unwrap();
        incomplete
            .auth_data
            .signed_fields
            .retain(|field| field != "issued_at");
        assert_eq!(
            validate_key_backup_active_series_transition(None, &incomplete),
            Err(KeyBackupActiveSeriesTransitionError::SignedFieldsIncomplete)
        );
    }
}
