//! Key-backup active-series event payloads and transition validation.

use crate::internal_prelude::*;

/// Counterpart for the closed current-generation device authorization binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
    pub device_authorize_event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupActiveSeriesFrontierRef {
    pub frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SealId>,
    pub device_generation_ref: NonEmptyString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupActiveSeries {
    pub schema: String,
    pub actor_id: Did,
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

impl KeyBackupActiveSeries {
    /// Canonical bytes covered by `auth_data.signature`.
    ///
    /// The active-series schema excludes only the signature member itself
    /// from this transcript. Keeping that operation on the public model avoids
    /// every producer and verifier growing its own JSON-shape implementation.
    pub fn signature_payload_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .get_mut("auth_data")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                Error::Protocol("active-series auth_data must serialize as an object".to_owned())
            })?
            .remove("signature");
        Ok(canonical::canonical_json_bytes(&unsigned)?)
    }

    /// Canonical CAS cell selected by `(actor_id, backup_kind)`.
    pub fn cell_ref(&self) -> Result<CellRef> {
        let subject = composite_subject(&[self.actor_id.as_str(), self.backup_kind.as_str()])?;
        Ok(CellRef::new(format!(
            "ak:cell:{}:{subject}",
            CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
        ))?)
    }

    /// Whole-value CAS guard required before replacing this accepted record.
    ///
    /// The registered projector copies this `head_eq` value into the next
    /// `cas_register` op's predecessor. Omitting it would author a concurrent
    /// initial head and force the security-barrier cell into Bottom.
    pub fn replacement_precondition(&self) -> Result<Precondition> {
        Ok(Precondition {
            cell: self.cell_ref()?,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(serde_json::to_value(self)?),
                values: None,
                predicate_id: None,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesHead {
    pub actor_id: Did,
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
    pub generation_ref: NonEmptyString,
}

impl ControllerBackupTrustAnchor {
    pub fn frontier_ref_member(&self) -> (&'static str, Value) {
        (
            "device_generation_ref",
            Value::String(self.generation_ref.to_string()),
        )
    }

    pub fn auth_data_member(&self) -> (&'static str, Value) {
        (
            "device_authorize_event_id",
            Value::String(self.authorize_event_id.to_string()),
        )
    }

    pub fn from_record(record: &KeyBackupActiveSeries) -> Self {
        Self {
            authorize_event_id: record.auth_data.device_authorize_event_id.clone(),
            generation_ref: record.frontier_ref.device_generation_ref.clone(),
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
    principal: &Did,
    device_id: &DeviceId,
) -> std::result::Result<ControllerBackupTrustAnchor, ControllerBackupTrustAnchorError> {
    let record = outcome
        .device_keys
        .get(principal)
        .and_then(|devices| devices.get(device_id))
        .ok_or(ControllerBackupTrustAnchorError::DeviceUnknown)?;
    let generation_state = outcome.device_generations.get(principal);
    if !record.is_usable_in_generation(generation_state) {
        return Err(ControllerBackupTrustAnchorError::DeviceNotCurrent);
    }
    Ok(ControllerBackupTrustAnchor {
        authorize_event_id: record
            .device_authorize_event_id
            .clone()
            .ok_or(ControllerBackupTrustAnchorError::DeviceNotCurrent)?,
        generation_ref: generation_state
            .expect("usable record has generation state")
            .current_device_generation_ref
            .clone(),
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

pub fn validate_key_backup_active_series_transition(
    current: Option<&KeyBackupActiveSeriesHead>,
    record: &KeyBackupActiveSeries,
) -> std::result::Result<KeyBackupActiveSeriesHead, KeyBackupActiveSeriesTransitionError> {
    const REQUIRED_SIGNED_FIELDS: &[&str] = &[
        "schema",
        "actor_id",
        "backup_kind",
        "active_series_id",
        "series_pointer_version",
        "previous_series_ids",
        "frontier_ref",
        "issued_at",
    ];
    if record.schema != "ak.schema.key_backup_active_series.v1"
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
    if REQUIRED_SIGNED_FIELDS.iter().any(|required| {
        !signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == *required)
    }) {
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

pub type KeyBackupActiveSeriesPayload = KeyBackupActiveSeries;
