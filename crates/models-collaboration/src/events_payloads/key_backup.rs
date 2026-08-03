//! Key-backup active-series event payloads and transition validation.

use std::num::NonZeroU64;

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/key_backup_active_series_payload`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: KeyBackupSignatureAlgorithm,
    pub signature: Base64UrlString,
    pub signed_fields: Vec<String>,
    pub trust_binding: KeyBackupActiveSeriesTrustBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBackupActiveSeriesFrontierRef {
    pub frontier_digest: Hash,
    pub seal_ref: Option<SealId>,
    pub generation: KeyBackupActiveSeriesFrontierGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBackupActiveSeriesTrustBinding {
    SskGeneration(NonZeroU64),
    DeviceAuthorizeEventId(EventId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBackupActiveSeriesFrontierGeneration {
    SskGeneration(NonZeroU64),
    DeviceGenerationRef(NonEmptyString),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBackupActiveSeriesAuthDataWire {
    verification_method: DidUrl,
    signature_algorithm: KeyBackupSignatureAlgorithm,
    signature: Base64UrlString,
    signed_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authorize_event_id: Option<EventId>,
}

impl Serialize for KeyBackupActiveSeriesAuthData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, device_authorize_event_id) = match &self.trust_binding {
            KeyBackupActiveSeriesTrustBinding::SskGeneration(generation) => {
                (Some(*generation), None)
            }
            KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id) => {
                (None, Some(event_id.clone()))
            }
        };
        KeyBackupActiveSeriesAuthDataWire {
            verification_method: self.verification_method.clone(),
            signature_algorithm: self.signature_algorithm,
            signature: self.signature.clone(),
            signed_fields: self.signed_fields.clone(),
            ssk_generation,
            device_authorize_event_id,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeriesAuthData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyBackupActiveSeriesAuthDataWire::deserialize(deserializer)?;
        let trust_binding = match (wire.ssk_generation, wire.device_authorize_event_id) {
            (Some(generation), None) => {
                KeyBackupActiveSeriesTrustBinding::SskGeneration(generation)
            }
            (None, Some(event_id)) => {
                KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id)
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "active-series auth_data must contain exactly one trust binding",
                ));
            }
        };
        Ok(Self {
            verification_method: wire.verification_method,
            signature_algorithm: wire.signature_algorithm,
            signature: wire.signature,
            signed_fields: wire.signed_fields,
            trust_binding,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBackupActiveSeriesFrontierRefWire {
    frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssk_generation: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_generation_ref: Option<NonEmptyString>,
}

impl Serialize for KeyBackupActiveSeriesFrontierRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (ssk_generation, device_generation_ref) = match &self.generation {
            KeyBackupActiveSeriesFrontierGeneration::SskGeneration(generation) => {
                (Some(*generation), None)
            }
            KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation) => {
                (None, Some(generation.clone()))
            }
        };
        KeyBackupActiveSeriesFrontierRefWire {
            frontier_digest: self.frontier_digest.clone(),
            seal_ref: self.seal_ref.clone(),
            ssk_generation,
            device_generation_ref,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyBackupActiveSeriesFrontierRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KeyBackupActiveSeriesFrontierRefWire::deserialize(deserializer)?;
        let generation = match (wire.ssk_generation, wire.device_generation_ref) {
            (Some(generation), None) => {
                KeyBackupActiveSeriesFrontierGeneration::SskGeneration(generation)
            }
            (None, Some(generation)) => {
                KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation)
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "active-series frontier_ref must contain exactly one generation binding",
                ));
            }
        };
        Ok(Self {
            frontier_digest: wire.frontier_digest,
            seal_ref: wire.seal_ref,
            generation,
        })
    }
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
                Error::Protocol(
                    "active-series auth_data must serialize as an object".to_owned(),
                )
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

/// The single controller trust anchor an active-series record is bound to.
///
/// The anchor shows up in *two* places in the payload — `frontier_ref` carries
/// the generation, `auth_data` carries what signed for it — and the receiver
/// rejects a record where the halves disagree
/// ([`KeyBackupActiveSeriesTransitionError::GenerationBindingMismatch`]).
/// Authoring them separately is what makes that reachable, and hand-writing the
/// generation number additionally produces envelopes that are internally
/// consistent but stale against the current authority, which the receiver
/// rejects later as `backup_frontier_stale`.
///
/// So callers hold one of these instead of three loose fields, and derive both
/// halves from it. The value itself comes from
/// [`resolve_controller_backup_trust_anchor`], which reads the accepted
/// keys/query projection — there is no constructor that takes a bare number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerBackupTrustAnchor {
    /// A model: the principal's accepted cross-signing generation.
    CrossSigningGeneration(NonZeroU64),
    /// B model: the reducer-managed device generation, anchored to the accepted
    /// `ak.device.authorize` Event that produced it.
    DeviceGeneration {
        authorize_event_id: EventId,
        generation_ref: NonEmptyString,
    },
}

impl ControllerBackupTrustAnchor {
    /// The `frontier_ref` half.
    pub fn frontier_generation(&self) -> KeyBackupActiveSeriesFrontierGeneration {
        match self {
            Self::CrossSigningGeneration(generation) => {
                KeyBackupActiveSeriesFrontierGeneration::SskGeneration(*generation)
            }
            Self::DeviceGeneration { generation_ref, .. } => {
                KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation_ref.clone())
            }
        }
    }

    /// The `auth_data` half.
    pub fn trust_binding(&self) -> KeyBackupActiveSeriesTrustBinding {
        match self {
            Self::CrossSigningGeneration(generation) => {
                KeyBackupActiveSeriesTrustBinding::SskGeneration(*generation)
            }
            Self::DeviceGeneration {
                authorize_event_id, ..
            } => KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(
                authorize_event_id.clone(),
            ),
        }
    }

    /// The `(member name, value)` this anchor contributes to `frontier_ref`,
    /// for callers that assemble the payload as JSON before signing it.
    pub fn frontier_ref_member(&self) -> (&'static str, Value) {
        match self {
            Self::CrossSigningGeneration(generation) => {
                ("ssk_generation", Value::from(generation.get()))
            }
            Self::DeviceGeneration { generation_ref, .. } => (
                "device_generation_ref",
                Value::String(generation_ref.to_string()),
            ),
        }
    }

    /// The `(member name, value)` this anchor contributes to `auth_data`.
    pub fn auth_data_member(&self) -> (&'static str, Value) {
        match self {
            Self::CrossSigningGeneration(generation) => {
                ("ssk_generation", Value::from(generation.get()))
            }
            Self::DeviceGeneration {
                authorize_event_id, ..
            } => (
                "device_authorize_event_id",
                Value::String(authorize_event_id.to_string()),
            ),
        }
    }

    /// Read the anchor back out of an accepted record, refusing a record whose
    /// two halves describe different trust models.
    pub fn from_record(
        record: &KeyBackupActiveSeries,
    ) -> std::result::Result<Self, ControllerBackupTrustAnchorError> {
        match (
            &record.frontier_ref.generation,
            &record.auth_data.trust_binding,
        ) {
            (
                KeyBackupActiveSeriesFrontierGeneration::SskGeneration(frontier),
                KeyBackupActiveSeriesTrustBinding::SskGeneration(auth),
            ) if frontier == auth => Ok(Self::CrossSigningGeneration(*frontier)),
            (
                KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(generation_ref),
                KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(authorize_event_id),
            ) => Ok(Self::DeviceGeneration {
                authorize_event_id: authorize_event_id.clone(),
                generation_ref: generation_ref.clone(),
            }),
            _ => Err(ControllerBackupTrustAnchorError::GenerationBindingMismatch),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControllerBackupTrustAnchorError {
    #[error("controller_backup_trust_anchor_device_unknown")]
    DeviceUnknown,
    /// The device presents A-model and B-model trust material at once, or
    /// neither. `QueryDeviceRecord::is_usable_in_generation` fails these closed
    /// for the same reason: there is no defined ordering between the two.
    #[error("controller_backup_trust_anchor_mixed_trust_model")]
    MixedTrustModel,
    #[error("controller_backup_trust_anchor_cross_signing_state_missing")]
    CrossSigningStateMissing,
    /// The device's binding cites a generation the principal has since rotated
    /// past. Signing against it would produce a `backup_frontier_stale`
    /// rejection at the receiver.
    #[error("controller_backup_trust_anchor_cross_signing_generation_changed")]
    CrossSigningGenerationChanged,
    #[error("controller_backup_trust_anchor_generation_binding_mismatch")]
    GenerationBindingMismatch,
}

/// Derive the controller trust anchor from the accepted keys/query projection.
///
/// This is the only way to obtain a [`ControllerBackupTrustAnchor`]: the
/// generation is read from the authority's current state rather than supplied
/// by the caller, so an active-series record cannot be signed against a
/// generation the principal has already rotated past.
///
/// Mixed or incomplete trust material fails closed. The A-model branch
/// additionally re-checks the device's `cross_signing_binding` against the
/// principal's current accepted `ak.cross_signing.publish` generation, because
/// a binding that survived a rotation is exactly the stale-anchor case.
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
        return Err(ControllerBackupTrustAnchorError::MixedTrustModel);
    }

    match (
        record.cross_signing_binding.as_ref(),
        generation_state,
        record.authorized_generation_ref.as_ref(),
        record.device_authorize_event_id.as_ref(),
    ) {
        (Some(binding), None, None, None) => {
            let publish = outcome
                .cross_signing
                .get(principal)
                .ok_or(ControllerBackupTrustAnchorError::CrossSigningStateMissing)?;
            if publish.generation.get() != binding.ssk_generation {
                return Err(ControllerBackupTrustAnchorError::CrossSigningGenerationChanged);
            }
            let generation = NonZeroU64::new(binding.ssk_generation)
                .ok_or(ControllerBackupTrustAnchorError::CrossSigningGenerationChanged)?;
            Ok(ControllerBackupTrustAnchor::CrossSigningGeneration(
                generation,
            ))
        }
        (None, Some(state), Some(_), Some(authorize_event_id)) => {
            Ok(ControllerBackupTrustAnchor::DeviceGeneration {
                authorize_event_id: authorize_event_id.clone(),
                generation_ref: state.current_device_generation_ref.clone(),
            })
        }
        _ => Err(ControllerBackupTrustAnchorError::MixedTrustModel),
    }
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
    #[error("key_backup_active_series_generation_binding_mismatch")]
    GenerationBindingMismatch,
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
    let generation_matches = matches!(
        (&record.auth_data.trust_binding, &record.frontier_ref.generation),
        (
            KeyBackupActiveSeriesTrustBinding::SskGeneration(auth),
            KeyBackupActiveSeriesFrontierGeneration::SskGeneration(frontier)
        ) if auth == frontier
    ) || matches!(
        (
            &record.auth_data.trust_binding,
            &record.frontier_ref.generation
        ),
        (
            KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(_),
            KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(_)
        )
    );
    if !generation_matches {
        return Err(KeyBackupActiveSeriesTransitionError::GenerationBindingMismatch);
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

#[cfg(test)]
mod key_backup_active_series_tests {
    use serde_json::json;

    use super::*;

    fn record(version: u64) -> KeyBackupActiveSeries {
        serde_json::from_value(json!({
            "schema": "ak.schema.key_backup_active_series.v1",
            "actor_id": "did:web:alice.example",
            "backup_kind": "mls_history",
            "active_series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            "series_pointer_version": version,
            "previous_series_ids": [],
            "frontier_ref": {
                "frontier_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "seal_ref": "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "ssk_generation": 2
            },
            "issued_at": "2026-07-18T00:00:00.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "signed_fields": [
                    "schema", "actor_id", "backup_kind", "active_series_id",
                    "series_pointer_version", "previous_series_ids", "frontier_ref", "issued_at"
                ],
                "ssk_generation": 2
            }
        }))
        .unwrap()
    }

    #[test]
    fn public_authoring_helpers_bind_signature_and_cas_predecessor() {
        let first = record(1);
        let first_bytes = first.signature_payload_bytes().unwrap();
        let mut changed_signature = first.clone();
        changed_signature.auth_data.signature = Base64UrlString::new("ZGlmZmVyZW50").unwrap();
        assert_eq!(
            first_bytes,
            changed_signature.signature_payload_bytes().unwrap(),
            "the signature member itself is excluded from the transcript"
        );

        let precondition = first.replacement_precondition().unwrap();
        assert_eq!(precondition.predicate.op, PredicateOp::HeadEq);
        assert_eq!(
            precondition.predicate.value,
            Some(serde_json::to_value(&first).unwrap())
        );
        let subject = composite_subject(&[first.actor_id.as_str(), first.backup_kind.as_str()])
            .unwrap();
        assert_eq!(
            precondition.cell.as_str(),
            format!(
                "ak:cell:{}:{subject}",
                CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
            )
        );
    }

    fn cross_signing_publish(generation: u64) -> arkret_models_identity::CrossSigningPublish {
        // The type refuses an SSK and USK that share a public key, so the two
        // subordinate keys are distinct here.
        let subordinate = |fragment: &str, public_key: &str| {
            json!({
                "kid": format!("did:web:alice.example#{fragment}"),
                "alg": "Ed25519",
                "public_key": public_key,
                "key_format": "multibase",
                "binding": {
                    "verification_method": "did:web:alice.example#ak_principal_signing_v1",
                    "alg": "Ed25519",
                    "signature": "c2lnbmF0dXJl"
                }
            })
        };
        serde_json::from_value(json!({
            "principal_id": "did:web:alice.example",
            "trust_domain": "ak:trust_domain:alice.example",
            "principal_signing_key": {
                "kid": "did:web:alice.example#ak_principal_signing_v1",
                "alg": "Ed25519",
                "public_key": "z6MkfixturePrincipalSigningKeyForTests001",
                "key_format": "multibase"
            },
            "self_signing_key": subordinate(
                "ak_self_signing_v1",
                "z6MkfixtureSelfSigningKeyValueForTests0001"
            ),
            "user_signing_key": subordinate(
                "ak_user_signing_v1",
                "z6MkfixtureUserSigningKeyValueForTests0002"
            ),
            "generation": generation,
            "expected_previous_generation": generation - 1,
            "issued_at": "2026-07-18T00:00:00.000Z"
        }))
        .expect("cross-signing publish fixture")
    }

    fn cross_signing_device(ssk_generation: u64) -> arkret_models_crypto::keys::QueryDeviceRecord {
        arkret_models_crypto::keys::QueryDeviceRecord {
            device_status: Some(arkret_models_crypto::keys::DeviceStatus::Active),
            cross_signing_binding: Some(
                serde_json::from_value(json!({
                    "verification_method": "did:web:alice.example#ak_self_signing_v1",
                    "ssk_generation": ssk_generation,
                    "signature": "c2lnbmF0dXJl"
                }))
                .expect("cross-signing binding fixture"),
            ),
            ..Default::default()
        }
    }

    fn device_generation_device() -> arkret_models_crypto::keys::QueryDeviceRecord {
        arkret_models_crypto::keys::QueryDeviceRecord {
            device_status: Some(arkret_models_crypto::keys::DeviceStatus::Active),
            enrollment_authority_binding: Some(
                serde_json::from_value(json!({
                    "kind": "service_attested",
                    "authority_did": "did:web:authority.example",
                    "authorization_ref": "ak:event:01964137-0000-7000-8000-0000000000a1"
                }))
                .expect("enrollment authority binding fixture"),
            ),
            device_authorize_event_id: Some(
                EventId::new("ak:event:01964137-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
            ),
            authorized_generation_ref: Some(
                NonEmptyString::new("did-version-7".to_owned()).unwrap(),
            ),
            ..Default::default()
        }
    }

    fn keys_query(
        device: arkret_models_crypto::keys::QueryDeviceRecord,
        publish: Option<arkret_models_identity::CrossSigningPublish>,
        generation_state: Option<arkret_models_crypto::keys::DeviceGenerationState>,
    ) -> arkret_models_crypto::keys::KeysQueryOutcome {
        let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
        let device_id =
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000011".to_owned()).unwrap();
        arkret_models_crypto::keys::KeysQueryOutcome {
            device_keys: BTreeMap::from([(actor.clone(), BTreeMap::from([(device_id, device)]))]),
            failures: Vec::new(),
            cross_signing: publish
                .map(|publish| BTreeMap::from([(actor.clone(), publish)]))
                .unwrap_or_default(),
            device_generations: generation_state
                .map(|state| BTreeMap::from([(actor, state)]))
                .unwrap_or_default(),
        }
    }

    fn test_actor() -> Did {
        Did::new("did:web:alice.example".to_owned()).unwrap()
    }

    fn test_device() -> DeviceId {
        DeviceId::new("ak:device:01964137-0000-7000-8000-000000000011".to_owned()).unwrap()
    }

    #[test]
    fn trust_anchor_halves_always_agree() {
        // The receiver rejects a record whose `frontier_ref` and `auth_data`
        // describe different trust models. Deriving both from one anchor makes
        // that unreachable, for either model.
        for anchor in [
            ControllerBackupTrustAnchor::CrossSigningGeneration(NonZeroU64::new(2).unwrap()),
            ControllerBackupTrustAnchor::DeviceGeneration {
                authorize_event_id: EventId::new(
                    "ak:event:01964137-0000-7000-8000-0000000000a1".to_owned(),
                )
                .unwrap(),
                generation_ref: NonEmptyString::new("did-version-7".to_owned()).unwrap(),
            },
        ] {
            let mut value = serde_json::to_value(record(1)).unwrap();
            let frontier = value["frontier_ref"].as_object_mut().unwrap();
            frontier.remove("ssk_generation");
            frontier.remove("device_generation_ref");
            let (member, member_value) = anchor.frontier_ref_member();
            frontier.insert(member.to_owned(), member_value);
            let auth = value["auth_data"].as_object_mut().unwrap();
            auth.remove("ssk_generation");
            auth.remove("device_authorize_event_id");
            let (member, member_value) = anchor.auth_data_member();
            auth.insert(member.to_owned(), member_value);

            let rebuilt: KeyBackupActiveSeries = serde_json::from_value(value).unwrap();
            assert_eq!(
                rebuilt.frontier_ref.generation,
                anchor.frontier_generation()
            );
            assert_eq!(rebuilt.auth_data.trust_binding, anchor.trust_binding());
            validate_key_backup_active_series_transition(None, &rebuilt)
                .expect("an anchor-built record must satisfy the generation binding check");
            assert_eq!(
                ControllerBackupTrustAnchor::from_record(&rebuilt).unwrap(),
                anchor
            );
        }
    }

    #[test]
    fn from_record_rejects_a_mixed_trust_model() {
        let mut value = serde_json::to_value(record(1)).unwrap();
        value["auth_data"]
            .as_object_mut()
            .unwrap()
            .remove("ssk_generation");
        value["auth_data"]["device_authorize_event_id"] =
            json!("ak:event:01964137-0000-7000-8000-0000000000a1");
        let mixed: KeyBackupActiveSeries = serde_json::from_value(value).unwrap();
        assert_eq!(
            ControllerBackupTrustAnchor::from_record(&mixed),
            Err(ControllerBackupTrustAnchorError::GenerationBindingMismatch)
        );
    }

    #[test]
    fn resolve_reads_the_generation_from_the_authority() {
        let outcome = keys_query(
            cross_signing_device(2),
            Some(cross_signing_publish(2)),
            None,
        );
        assert_eq!(
            resolve_controller_backup_trust_anchor(&outcome, &test_actor(), &test_device()),
            Ok(ControllerBackupTrustAnchor::CrossSigningGeneration(
                NonZeroU64::new(2).unwrap()
            ))
        );

        let outcome = keys_query(
            device_generation_device(),
            None,
            Some(arkret_models_crypto::keys::DeviceGenerationState {
                current_device_generation_ref: NonEmptyString::new("did-version-7".to_owned())
                    .unwrap(),
                device_generation_status:
                    arkret_models_crypto::keys::DeviceGenerationStatus::Active,
            }),
        );
        assert_eq!(
            resolve_controller_backup_trust_anchor(&outcome, &test_actor(), &test_device()),
            Ok(ControllerBackupTrustAnchor::DeviceGeneration {
                authorize_event_id: EventId::new(
                    "ak:event:01964137-0000-7000-8000-0000000000a1".to_owned()
                )
                .unwrap(),
                generation_ref: NonEmptyString::new("did-version-7".to_owned()).unwrap(),
            })
        );
    }

    #[test]
    fn resolve_refuses_a_generation_the_principal_rotated_past() {
        // The device binding still cites generation 2 while the principal has
        // published generation 3. Signing an active-series record against 2 is
        // what the receiver later rejects as `backup_frontier_stale`, so the
        // anchor must refuse to exist.
        let outcome = keys_query(
            cross_signing_device(2),
            Some(cross_signing_publish(3)),
            None,
        );
        assert_eq!(
            resolve_controller_backup_trust_anchor(&outcome, &test_actor(), &test_device()),
            Err(ControllerBackupTrustAnchorError::CrossSigningGenerationChanged)
        );
    }

    #[test]
    fn resolve_fails_closed_on_unknown_and_mixed_devices() {
        let empty = arkret_models_crypto::keys::KeysQueryOutcome {
            device_keys: BTreeMap::new(),
            failures: Vec::new(),
            cross_signing: BTreeMap::new(),
            device_generations: BTreeMap::new(),
        };
        assert_eq!(
            resolve_controller_backup_trust_anchor(&empty, &test_actor(), &test_device()),
            Err(ControllerBackupTrustAnchorError::DeviceUnknown)
        );

        // A-model binding presented alongside a B-model generation fence.
        let mut mixed = cross_signing_device(2);
        mixed.authorized_generation_ref =
            Some(NonEmptyString::new("did-version-7".to_owned()).unwrap());
        let outcome = keys_query(
            mixed,
            Some(cross_signing_publish(2)),
            Some(arkret_models_crypto::keys::DeviceGenerationState {
                current_device_generation_ref: NonEmptyString::new("did-version-7".to_owned())
                    .unwrap(),
                device_generation_status:
                    arkret_models_crypto::keys::DeviceGenerationStatus::Active,
            }),
        );
        assert_eq!(
            resolve_controller_backup_trust_anchor(&outcome, &test_actor(), &test_device()),
            Err(ControllerBackupTrustAnchorError::MixedTrustModel)
        );
    }

    #[test]
    fn a_and_b_generation_models_round_trip_exclusively() {
        let a = record(1);
        assert!(matches!(
            a.auth_data.trust_binding,
            KeyBackupActiveSeriesTrustBinding::SskGeneration(_)
        ));
        let mut b = serde_json::to_value(&a).unwrap();
        b["auth_data"]
            .as_object_mut()
            .unwrap()
            .remove("ssk_generation");
        b["auth_data"]["device_authorize_event_id"] =
            json!("ak:event:01964137-0000-7000-8000-000000000009");
        b["frontier_ref"]
            .as_object_mut()
            .unwrap()
            .remove("ssk_generation");
        b["frontier_ref"]["device_generation_ref"] = json!("3-generation");
        let b_value = b.clone();
        let b_record: KeyBackupActiveSeries = serde_json::from_value(b).unwrap();
        assert_eq!(serde_json::to_value(b_record).unwrap(), b_value);

        let mut mixed = b_value;
        mixed["auth_data"]["ssk_generation"] = json!(2);
        assert!(serde_json::from_value::<KeyBackupActiveSeries>(mixed).is_err());
    }

    #[test]
    fn pointer_versions_are_contiguous_and_fail_closed() {
        let first = record(1);
        let head = validate_key_backup_active_series_transition(None, &first).unwrap();
        let second = record(2);
        let second_head =
            validate_key_backup_active_series_transition(Some(&head), &second).unwrap();
        assert_eq!(second_head.series_pointer_version, 2);
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &record(1)),
            Ok(head.clone())
        );
        let mut fork = record(1);
        fork.issued_at = "2026-07-18T00:00:01.000Z".parse().unwrap();
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &fork),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionFork)
        );
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&head), &record(3)),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionGap)
        );
        assert_eq!(
            validate_key_backup_active_series_transition(Some(&second_head), &record(1)),
            Err(KeyBackupActiveSeriesTransitionError::PointerVersionRollback)
        );
    }
}
