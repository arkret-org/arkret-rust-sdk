//! Key claim and distribution DTO counterparts for `keys-operations.schema.json`.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use arkret_wire::{
    AccountId, DeviceId, DidKey, EventId, Hash, NonEmptyString, ProtocolSignature, ReasonCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::artifacts_keys::{
    AccountDeviceAlgorithmEntry, AccountDeviceKeyEntry, AlgorithmCounts, AlgorithmKeyRecords,
    KeyOperationSignature, QueryAccountDeviceSelector,
};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysUploadRequestBody {
    pub device_id: DeviceId,
    pub device_signature: KeyOperationSignature,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: AlgorithmKeyRecords,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: AlgorithmKeyRecords,
}

/// Canonical unsigned projection for `keys/upload`.
///
/// Both key maps are always serialized, including as `{}`, because the
/// signature transcript in `device-lifecycle.md` §8.1 fixes that exact shape.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysUploadUnsignedRequest {
    pub device_id: DeviceId,
    pub one_time_keys: AlgorithmKeyRecords,
    pub fallback_keys: AlgorithmKeyRecords,
}

impl KeysUploadRequestBody {
    #[must_use]
    pub fn unsigned(&self) -> KeysUploadUnsignedRequest {
        KeysUploadUnsignedRequest {
            device_id: self.device_id.clone(),
            one_time_keys: self.one_time_keys.clone(),
            fallback_keys: self.fallback_keys.clone(),
        }
    }
}

impl KeysUploadUnsignedRequest {
    #[must_use]
    pub fn into_signed(self, device_signature: KeyOperationSignature) -> KeysUploadRequestBody {
        KeysUploadRequestBody {
            device_id: self.device_id,
            device_signature,
            one_time_keys: self.one_time_keys,
            fallback_keys: self.fallback_keys,
        }
    }
}

pub const KEYS_UPLOAD_SIGNATURE_DOMAIN: &str = "ak.keys-upload-v1\n";

/// Build the one SDK-owned `keys/upload` signing transcript.
pub fn keys_upload_signing_input(
    unsigned: &KeysUploadUnsignedRequest,
) -> arkret_canonical::Result<Vec<u8>> {
    let canonical = arkret_canonical::canonical_json_bytes(unsigned)?;
    let mut input = Vec::with_capacity(KEYS_UPLOAD_SIGNATURE_DOMAIN.len() + canonical.len());
    input.extend_from_slice(KEYS_UPLOAD_SIGNATURE_DOMAIN.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysUploadOutcome {
    pub one_time_key_counts: AlgorithmCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: AlgorithmKeyRecords,
}

/// At most 16 accounts per directory read, local and cross-Station alike
/// (`device-lifecycle.md` §8). An over-limit request fails whole; it is never
/// truncated.
pub const MAX_KEYS_QUERY_ACCOUNTS: usize = 16;
/// At most 32 devices per selected account.
pub const MAX_KEYS_QUERY_DEVICES_PER_ACCOUNT: usize = 32;
/// Canonical byte budget of either direction of both keys query operations.
pub const KEYS_QUERY_MAX_BYTES: usize = 65_536;

fn validate_device_key_selectors(
    selectors: &[QueryAccountDeviceSelector],
) -> arkret_wire::Result<()> {
    if selectors.is_empty() || selectors.len() > MAX_KEYS_QUERY_ACCOUNTS {
        return Err(arkret_wire::WireError::Protocol(
            "keys query selects 1..16 accounts and is never truncated".to_owned(),
        ));
    }
    arkret_wire::validate_identity_entries(selectors)
}

fn validate_keys_query_bytes(value: &impl Serialize, request: bool) -> arkret_wire::Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > KEYS_QUERY_MAX_BYTES {
        return Err(arkret_wire::WireError::ProtocolCode {
            code: if request {
                arkret_wire::ErrorCode::PayloadTooLarge
            } else {
                arkret_wire::ErrorCode::LimitExceeded
            },
            message: "keys query exceeds its canonical byte budget".to_owned(),
        });
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysQueryRequestBody {
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_keys: Vec<QueryAccountDeviceSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<u64>)))]
    pub timeout_ms: Option<NonZeroU64>,
}

impl KeysQueryRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_device_key_selectors(&self.device_keys)?;
        validate_keys_query_bytes(self, true)
    }
}

/// Directory status of a `(principal_id, device_id)` pair at query time.
///
/// `active` = a `ak.device.authorize` is in effect and the device is not
/// revoked; `revoked` = a `ak.device.revoke` is in effect. Servers MUST omit
/// [`QueryDeviceRecord::device_signing_key_did`] for any non-active device.
/// Shared device lifecycle status. Individual wire surfaces narrow the allowed
/// variants in their own schema; for example, a keys-query attestation pins
/// `keys-operations.schema.json#/$defs/device_projection_attestation_core/properties/device_status`
/// to `active`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

impl DeviceStatus {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGenerationState {
    pub current_device_generation_ref: u64,
}

/// Exact original device grant window, independent of current-query cache TTL.
/// `keys-operations.schema.json#/$defs/device_projection_attestation_core/properties/
/// authorization_window`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizationWindow {
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Origin Station assertion that one exact device projection is the
/// account's current accepted one.
///
/// This is the whole verification closure of the cross-principal `keys/query`
/// surface. It replaces replaying the PCR genesis and authorization history:
/// that material is account-internal governance,
/// a relationship-gated third party has no business holding it, and the schema
/// never carried it in the first place, so the old closure was unexecutable on
/// the wire. Mirrors
/// `keys-operations.schema.json#/$defs/device_projection_attestation_core`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProjectionAttestationCore {
    /// Complete account identity. The proof controller MUST be its Station.
    pub account_id: AccountId,
    pub device_id: DeviceId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    /// Constant `active`: this surface attests usable devices only.
    pub device_status: DeviceStatus,
    pub authorization_window: DeviceAuthorizationWindow,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProjectionAttestation {
    pub attestation: DeviceProjectionAttestationCore,
    pub proof: ProtocolSignature,
}

/// Proof context of [`DeviceProjectionAttestation`]. It is its own registered
/// context and deliberately not the resolution attestation's: a signature made
/// about an account's public resolution projection must never be
/// reinterpretable as a statement about one of its devices.
pub const DEVICE_PROJECTION_ATTESTATION_CONTEXT: &str =
    arkret_wire::ProofContextId::DEVICE_PROJECTION_ATTESTATION_PROOF_V1;

impl DeviceProjectionAttestation {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let core = &self.attestation;
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(
            &serde_json::json!({"attestation": core}),
        )?)?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": DEVICE_PROJECTION_ATTESTATION_CONTEXT,
            "payload_digest": payload_digest,
            "account_id": core.account_id,
            "device_id": core.device_id,
            "device_signing_key_did": core.device_signing_key_did,
            "hpke_key": core.hpke_key,
            "device_authorize_event_id": core.device_authorize_event_id,
            "authorized_generation_ref": core.authorized_generation_ref,
            "device_status": core.device_status,
            "attested_at": arkret_canonical::format_timestamp_canonical(core.attested_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(core.expires_at),
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEventAuthorization {
    pub event_id: EventId,
    pub verification_method: arkret_wire::DidUrl,
    pub destination_service_id: arkret_wire::DidCoreId,
    pub forward_body_digest: Hash,
    pub authorization_ref: arkret_wire::CommittedEventRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: arkret_wire::CurrentRevision,
    pub governance_generation: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDeviceProjectionAttestationCore {
    /// Complete account identity. The proof controller MUST be its Station.
    pub account_id: AccountId,
    pub device_id: DeviceId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    /// Constant `active`: this surface attests usable devices only.
    pub device_status: DeviceStatus,
    pub authorization_window: DeviceAuthorizationWindow,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub event_authorization: HumanEventAuthorization,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardDeviceProjectionAttestation {
    pub attestation: ForwardDeviceProjectionAttestationCore,
    pub proof: ProtocolSignature,
}

impl ForwardDeviceProjectionAttestation {
    pub fn proof_signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let core = &self.attestation;
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(
            &serde_json::json!({"attestation": core}),
        )?)?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": DEVICE_PROJECTION_ATTESTATION_CONTEXT,
            "payload_digest": payload_digest,
            "account_id": core.account_id,
            "device_id": core.device_id,
            "device_signing_key_did": core.device_signing_key_did,
            "hpke_key": core.hpke_key,
            "device_authorize_event_id": core.device_authorize_event_id,
            "authorized_generation_ref": core.authorized_generation_ref,
            "device_status": core.device_status,
            "attested_at": arkret_canonical::format_timestamp_canonical(core.attested_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(core.expires_at),
            "verification_method": self.proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
    }
}

/// Restricted device projection a client receives from its *own* authenticated
/// Station on the self `keys/query` surface.
///
/// The values are the ones the returning Station read out of the origin
/// Station's verified [`DeviceProjectionAttestation`]. The row therefore
/// carries no origin proof and no wrapper whose only job was to verify that
/// proof, and a client MUST NOT treat this projection as portable evidence
/// about the origin. `account_id` and `device_id` are deliberately absent:
/// they are the enclosing [`QueryAccountDeviceEntry::account_id`] and the
/// `device_keys` map key, and the returning Station MUST have checked that the
/// verified attestation named exactly that pair before projecting the row.
/// Mirrors `keys-operations.schema.json#/$defs/verified_device_projection`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDeviceProjection {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub device_signing_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub device_authorize_event_id: EventId,
    pub authorized_generation_ref: u64,
    /// Constant `active`: this surface projects usable devices only.
    pub device_status: DeviceStatus,
    /// Origin observation instant, forwarded verbatim.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub attested_at: DateTime<Utc>,
    /// Fresh current-query cache deadline, forwarded verbatim. The returning
    /// Station MUST NOT extend it.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authorization_window: DeviceAuthorizationWindow,
}

/// Per-`(account_id, device_id)` entry in [`KeysQueryOutcome::device_keys`],
/// the client-facing self surface.
///
/// Every field is required. A device whose generation is fenced or conflicted,
/// or which is revoked, is not degraded into a partial row: it is omitted from
/// `device_keys` or reported through the non-enumerating `failures` shape, so
/// an incomplete row can never be mistaken for a usable one. `account_id` and
/// `device_id` are the map keys, not row fields. This is deliberately a
/// different type from [`PeerQueryDeviceRecord`]: the client's Station already
/// verified the origin attestation, so the client gets the restricted
/// projection and never the origin proof. Mirrors
/// `keys-operations.schema.json#/$defs/query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceRecord {
    /// Content-addressed retained device evidence and its Station attester
    /// closure. It keeps pointing at that complete immutable evidence object:
    /// it is neither recomputed from this pruned projection nor an additional
    /// device-authority claim.
    pub signer_evidence_ref: arkret_wire::SignerEvidenceRef,
    /// Prekey bundle keyed by algorithm name. The demo projection carries the
    /// opaque uploaded key payload here; each value matches the schema
    /// `key_record` once real prekey records are published.
    #[serde(default)]
    pub algorithms: AlgorithmKeyRecords,
    /// Canonical (UTF-8 bytewise sorted, deduplicated) algorithm ids used to
    /// select entries from the sibling prekey-bundle map.
    pub trust_algorithms: Vec<NonEmptyString>,
    /// Values the client's own Station read out of the verified origin
    /// attestation. Not portable evidence.
    pub device_projection: VerifiedDeviceProjection,
}

impl QueryDeviceRecord {
    /// Return whether this device is usable in the reducer's current accepted
    /// generation.
    ///
    /// This is the generation half of the §8.2 gate only. The proof half was
    /// already discharged by the client's own Station before this row existed;
    /// the client has no origin proof here and MUST NOT try to reconstruct one.
    pub fn is_usable_in_generation(&self, generation: Option<&DeviceGenerationState>) -> bool {
        if self.device_projection.device_status != DeviceStatus::Active {
            return false;
        }
        match generation {
            Some(state) => {
                self.device_projection.authorized_generation_ref
                    == state.current_device_generation_ref
            }
            None => false,
        }
    }

    /// Row-local invariants of a self-surface projection.
    ///
    /// There is no `(account_id, device_id)` to cross-check here — those live
    /// only in the enclosing entry and map key — and deliberately no path from
    /// this pruned projection back to `signer_evidence_ref` or to an origin
    /// attestation.
    pub fn validate_projection(&self) -> arkret_wire::Result<()> {
        self.signer_evidence_ref.content_digest()?;
        if self.device_projection.device_status != DeviceStatus::Active {
            return Err(arkret_wire::WireError::Protocol(
                "verified device projection does not project a usable device".to_owned(),
            ));
        }
        if self.device_projection.attested_at >= self.device_projection.expires_at {
            return Err(arkret_wire::WireError::Protocol(
                "verified device projection is not a positive validity window".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Per-`(account_id, device_id)` entry in
/// [`PeerKeysQueryOutcome::device_keys`], the Station-to-Station surface.
///
/// Every returned row is complete and attested: the origin Station signs the
/// exact projection, so the requesting Station can verify the row itself. A
/// Station MUST NOT turn an unverified peer row into a client result by
/// dropping its proof. Mirrors
/// `keys-operations.schema.json#/$defs/peer_query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryDeviceRecord {
    /// Content-addressed retained device evidence and its Station attester
    /// closure. Its embedded attestation equals this row's attestation byte for
    /// byte; the ref is not an additional device-authority claim.
    pub signer_evidence_ref: arkret_wire::SignerEvidenceRef,
    #[serde(default)]
    pub algorithms: AlgorithmKeyRecords,
    pub trust_algorithms: Vec<NonEmptyString>,
    /// Origin Station signature over this exact row.
    pub device_projection_attestation: DeviceProjectionAttestation,
}

impl PeerQueryDeviceRecord {
    /// Return whether this device is usable in the reducer's current accepted
    /// generation.
    ///
    /// This is the generation half of the §8.2 gate only. A caller MUST also
    /// verify the attestation proof before treating the attested keys as usable;
    /// `arkret-signatures` owns that half because it needs the serving Station's DID Document.
    pub fn is_usable_in_generation(&self, generation: Option<&DeviceGenerationState>) -> bool {
        let attested = &self.device_projection_attestation.attestation;
        if attested.device_status != DeviceStatus::Active {
            return false;
        }
        match generation {
            Some(state) => {
                attested.authorized_generation_ref == state.current_device_generation_ref
            }
            None => false,
        }
    }

    /// Bind the attestation to the `(account_id, device_id)` map keys it travels under.
    ///
    /// This does not verify the detached proof; it rejects a swapped or edited
    /// row before a caller spends a signature check on it.
    pub fn validate_attestation_binding(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> arkret_wire::Result<()> {
        self.signer_evidence_ref.content_digest()?;
        let core = &self.device_projection_attestation.attestation;
        if &core.account_id != account_id || &core.device_id != device_id {
            return Err(arkret_wire::WireError::Protocol(
                "device projection attestation addresses a different (account, device)".to_owned(),
            ));
        }
        if core.device_status != DeviceStatus::Active {
            return Err(arkret_wire::WireError::Protocol(
                "device projection attestation does not attest a usable device".to_owned(),
            ));
        }
        if core.attested_at >= core.expires_at {
            return Err(arkret_wire::WireError::Protocol(
                "device projection attestation is not a positive validity window".to_owned(),
            ));
        }
        Ok(())
    }

    /// Project the verified peer row onto the restricted client-facing shape.
    ///
    /// The caller MUST have verified `device_projection_attestation` against
    /// the origin Station's DID Document first; this only prunes what the
    /// client is allowed to see.
    pub fn project_verified_row(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> arkret_wire::Result<QueryDeviceRecord> {
        self.validate_attestation_binding(account_id, device_id)?;
        let core = &self.device_projection_attestation.attestation;
        Ok(QueryDeviceRecord {
            signer_evidence_ref: self.signer_evidence_ref.clone(),
            algorithms: self.algorithms.clone(),
            trust_algorithms: self.trust_algorithms.clone(),
            device_projection: VerifiedDeviceProjection {
                device_signing_key_did: core.device_signing_key_did.clone(),
                hpke_key: core.hpke_key.clone(),
                device_authorize_event_id: core.device_authorize_event_id.clone(),
                authorized_generation_ref: core.authorized_generation_ref,
                device_status: core.device_status,
                attested_at: core.attested_at,
                expires_at: core.expires_at,
                authorization_window: core.authorization_window.clone(),
            },
        })
    }
}

/// Closed non-enumerating reason space of the device directory read surfaces.
///
/// `device_result_unavailable` covers absent, invisible, unrelated, revoked,
/// fenced and policy-denied targets with one indistinguishable value.
/// `device_directory_unavailable` states only that the requester's own Station
/// could not obtain or verify a current attested projection this time; it never
/// depends on target state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryFailureReason {
    DeviceResultUnavailable,
    DeviceDirectoryUnavailable,
}

/// Closed failure row of `self/keys/query` and `peer/keys/query`.
///
/// A missing row and an empty `device_keys` map are *not* substitutes for this
/// value: a caller that cannot fetch the directory must be able to tell that
/// apart from a target that has no usable device.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub reason_code: QueryFailureReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<u64>)))]
    pub retry_after_ms: Option<NonZeroU64>,
}

impl QueryFailure {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.retry_after_ms.is_some()
            && self.reason_code != QueryFailureReason::DeviceDirectoryUnavailable
        {
            return Err(arkret_wire::WireError::Protocol(
                "a target-private device query failure must not carry retry_after_ms".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_query_failures(failures: &[QueryFailure]) -> arkret_wire::Result<()> {
    if failures.len() > 512 {
        return Err(arkret_wire::WireError::Protocol(
            "device query failures exceed the registered bound".to_owned(),
        ));
    }
    failures.iter().try_for_each(QueryFailure::validate)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysQueryOutcome {
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_keys: Vec<QueryAccountDeviceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<QueryFailure>,
    /// Reducer-managed B-model device generation fence by complete account.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_generations: Vec<AccountDeviceGenerationEntry>,
}

/// `keys-operations.schema.json#/$defs/query_device_keys`.
pub type QueryDeviceKeys = BTreeMap<DeviceId, QueryDeviceRecord>;

/// `keys-operations.schema.json#/$defs/peer_query_device_keys`.
pub type PeerQueryDeviceKeys = BTreeMap<DeviceId, PeerQueryDeviceRecord>;

/// One self-surface device-key result group per exact `AccountId`. Item of
/// `keys-operations.schema.json#/$defs/query_account_device_entries/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAccountDeviceEntry {
    pub account_id: AccountId,
    pub device_keys: QueryDeviceKeys,
}

impl arkret_wire::CanonicalIdentityEntry for QueryAccountDeviceEntry {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
    fn validate_entry(&self) -> arkret_wire::Result<()> {
        for record in self.device_keys.values() {
            record.validate_projection()?;
        }
        Ok(())
    }
}

/// One Station-to-Station device-key result group per exact `AccountId`. Item
/// of `keys-operations.schema.json#/$defs/peer_query_account_device_entries/items`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerQueryAccountDeviceEntry {
    pub account_id: AccountId,
    pub device_keys: PeerQueryDeviceKeys,
}

impl arkret_wire::CanonicalIdentityEntry for PeerQueryAccountDeviceEntry {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
    fn validate_entry(&self) -> arkret_wire::Result<()> {
        for (device_id, record) in &self.device_keys {
            record.validate_attestation_binding(&self.account_id, device_id)?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceGenerationEntry {
    pub account_id: AccountId,
    pub generation_state: DeviceGenerationState,
}

impl arkret_wire::CanonicalIdentityEntry for AccountDeviceGenerationEntry {
    type Identity = AccountId;
    fn identity(&self) -> &AccountId {
        &self.account_id
    }
}

impl KeysQueryOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_query_failures(&self.failures)?;
        validate_keys_query_bytes(self, false)
    }

    pub fn devices_for(&self, account_id: &AccountId) -> Option<&QueryDeviceKeys> {
        self.device_keys
            .iter()
            .find(|entry| &entry.account_id == account_id)
            .map(|entry| &entry.device_keys)
    }

    pub fn generation_for(&self, account_id: &AccountId) -> Option<&DeviceGenerationState> {
        self.device_generations
            .iter()
            .find(|entry| &entry.account_id == account_id)
            .map(|entry| &entry.generation_state)
    }
}

/// Declared use of the requested directory rows. The destination authorizes
/// each purpose independently and never clears the broadest one once.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKeysQueryPurpose {
    E2eeMessageEncryption,
    MlsGroupAdmission,
    CallMedia,
}

/// Closed relationship the requesting Station asserts. The destination
/// re-derives it from its own accepted state; the assertion never authorizes by
/// itself. The `contact` branch deliberately carries no `realm_id` because a
/// legitimate Contact needs no shared Realm.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerKeysRelationshipBasis {
    RealmMembership {
        realm_id: arkret_wire::RealmId,
    },
    /// Declared as an empty struct variant so `deny_unknown_fields` actually
    /// applies: a unit variant of an internally tagged enum silently accepts a
    /// smuggled `realm_id`, which is exactly the shape the closed contact branch
    /// forbids.
    Contact {},
}

/// Body of `ak.peer.keys.read.lookup.v1` (`POST /_arkret/peer/keys/query`).
///
/// This is the only registered carrier for a cross-Station `keys/query` target:
/// the client asks its own Station, which authenticates itself with its own
/// RFC 9421 service signature. No client SessionGrant, DPoP or local bearer is
/// ever forwarded, and the client never connects to the origin Station itself.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeysQueryRequestBody {
    pub request_id: arkret_wire::RequestId,
    pub requester_account_id: AccountId,
    pub purpose: PeerKeysQueryPurpose,
    pub relationship_basis: PeerKeysRelationshipBasis,
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_keys: Vec<QueryAccountDeviceSelector>,
}

impl PeerKeysQueryRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.requester_account_id.validate()?;
        validate_device_key_selectors(&self.device_keys)?;
        for selector in &self.device_keys {
            selector.account_id.validate()?;
        }
        validate_keys_query_bytes(self, true)
    }

    /// Every selected target belongs to one destination Station, which the
    /// caller MUST have authenticated as `Destination-Service-ID`.
    pub fn destination_station_id(&self) -> arkret_wire::Result<&arkret_wire::DidCoreId> {
        let first = self
            .device_keys
            .first()
            .map(|selector| &selector.account_id.station_id)
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol(
                    "peer keys query selects no destination account".to_owned(),
                )
            })?;
        if self
            .device_keys
            .iter()
            .any(|selector| &selector.account_id.station_id != first)
        {
            return Err(arkret_wire::WireError::Protocol(
                "peer keys query targets more than one destination Station".to_owned(),
            ));
        }
        Ok(first)
    }
}

/// Success body of `ak.peer.keys.read.lookup.v1`.
///
/// The destination adds no response signature layer: every row carries the
/// origin's own `device_projection_attestation`, which the requesting Station
/// verifies before handing the client a restricted typed result.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerKeysQueryOutcome {
    pub request_id: arkret_wire::RequestId,
    pub requester_account_id: AccountId,
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_keys: Vec<PeerQueryAccountDeviceEntry>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_generations: Vec<AccountDeviceGenerationEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<QueryFailure>,
}

impl PeerKeysQueryOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_query_failures(&self.failures)?;
        validate_keys_query_bytes(self, false)
    }

    /// Reject a response that answers a different request or requester before
    /// any row is installed.
    pub fn validate_for_request(
        &self,
        request: &PeerKeysQueryRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.requester_account_id != request.requester_account_id
        {
            return Err(arkret_wire::WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::StateMismatch,
                message: "peer keys query result answers a different request or requester"
                    .to_owned(),
            });
        }
        let selected: std::collections::BTreeSet<_> = request
            .device_keys
            .iter()
            .map(|selector| &selector.account_id)
            .collect();
        if self
            .device_keys
            .iter()
            .any(|entry| !selected.contains(&entry.account_id))
            || self
                .device_generations
                .iter()
                .any(|entry| !selected.contains(&entry.account_id))
        {
            return Err(arkret_wire::WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::StateMismatch,
                message: "peer keys query result carries an unselected account".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysClaimRequestBody {
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub one_time_keys: Vec<AccountDeviceAlgorithmEntry>,
}

/// Per-target failure returned by the keys *claim* operations only.
///
/// The directory read surfaces (`self/keys/query`, `peer/keys/query`) use the
/// closed [`QueryFailure`] instead: an open `reason_code` there would leak
/// target state and let a caller distinguish an absent account from a revoked
/// one.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysOperationFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<NonEmptyString>,
    pub reason_code: ReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<u64>)))]
    pub retry_after_ms: Option<NonZeroU64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysClaimOutcome {
    #[serde(
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub one_time_keys: Vec<AccountDeviceKeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<KeysOperationFailure>,
}

#[cfg(test)]
mod device_generation_tests {
    use arkret_wire::Base64UrlString;
    use serde_json::json;

    use super::*;

    #[test]
    fn keys_upload_transcript_is_sdk_owned_and_keeps_empty_maps() {
        let unsigned = KeysUploadUnsignedRequest {
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            one_time_keys: BTreeMap::new(),
            fallback_keys: BTreeMap::new(),
        };

        assert_eq!(
            String::from_utf8(keys_upload_signing_input(&unsigned).unwrap()).unwrap(),
            concat!(
                "ak.keys-upload-v1\n",
                "{\"device_id\":\"ak:device:0196419b-0000-7000-8000-000000000001\",",
                "\"fallback_keys\":{},\"one_time_keys\":{}}"
            )
        );

        let signed = unsigned.into_signed(KeyOperationSignature {
            kid: NonEmptyString::new("did:web:alice.example#device").unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            sig: Base64UrlString::new("c2ln").unwrap(),
        });
        assert_eq!(
            signed
                .device_signature
                .signature_algorithm
                .unwrap()
                .as_str(),
            "Ed25519"
        );
    }

    const DEVICE_SIGNING_KEY: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x";
    const DEVICE_AUTHORIZE_EVENT: &str = "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e";
    const PRINCIPAL_ID: &str = "ak:did_core:webvh:z6mkfixture";
    const STATION_ID: &str = "ak:did_core:webvh:z6mkfixtureps";
    const DEVICE_ID: &str = "ak:device:0196419b-0000-7000-8000-000000000001";

    fn peer_row(generation: u64) -> serde_json::Value {
        let trust_algorithm = arkret_wire::generated::HPKE_SUITES[2].canonical_id;
        json!({
            "signer_evidence_ref": format!("ak:signer_evidence:sha256:{}", "a".repeat(64)),
            "algorithms": {},
            "trust_algorithms": [trust_algorithm],
            "device_projection_attestation": {
                "attestation": {
                    "account_id": {"principal_id": PRINCIPAL_ID, "station_id": STATION_ID},
                    "device_id": DEVICE_ID,
                    "device_signing_key_did": DEVICE_SIGNING_KEY,
                    "hpke_key": "hpke-1",
                    "device_authorize_event_id": DEVICE_AUTHORIZE_EVENT,
                    "authorized_generation_ref": generation,
                    "authorization_window": {"not_before": "2026-08-01T00:00:00.000Z", "expires_at": null},
                    "device_status": "active",
                    "attested_at": "2026-08-15T00:00:00.000Z",
                    "expires_at": "2026-08-15T00:10:00.000Z"
                },
                "proof": {
                    "verification_method": "did:webvh:z6mkfixtureps:ps.example#signing-1",
                    "created_at": "2026-08-15T00:00:00.000Z",
                    "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
                }
            }
        })
    }

    fn self_row(generation: u64) -> serde_json::Value {
        let trust_algorithm = arkret_wire::generated::HPKE_SUITES[2].canonical_id;
        json!({
            "signer_evidence_ref": format!("ak:signer_evidence:sha256:{}", "a".repeat(64)),
            "algorithms": {},
            "trust_algorithms": [trust_algorithm],
            "device_projection": {
                "device_signing_key_did": DEVICE_SIGNING_KEY,
                "hpke_key": "hpke-1",
                "device_authorize_event_id": DEVICE_AUTHORIZE_EVENT,
                "authorized_generation_ref": generation,
                "device_status": "active",
                "attested_at": "2026-08-15T00:00:00.000Z",
                "expires_at": "2026-08-15T00:10:00.000Z",
                "authorization_window": {"not_before": "2026-08-01T00:00:00.000Z", "expires_at": null}
            }
        })
    }

    #[test]
    fn device_generation_must_be_current_and_fully_anchored() {
        let generation = DeviceGenerationState {
            current_device_generation_ref: 7,
        };
        let record: QueryDeviceRecord = serde_json::from_value(self_row(7)).unwrap();
        assert!(record.is_usable_in_generation(Some(&generation)));
        assert!(!record.is_usable_in_generation(None));

        let stale: QueryDeviceRecord = serde_json::from_value(self_row(6)).unwrap();
        assert!(!stale.is_usable_in_generation(Some(&generation)));

        let peer: PeerQueryDeviceRecord = serde_json::from_value(peer_row(7)).unwrap();
        assert!(peer.is_usable_in_generation(Some(&generation)));
    }

    #[test]
    fn a_device_row_requires_its_own_projection_member() {
        let mut without_attestation = peer_row(7);
        without_attestation
            .as_object_mut()
            .unwrap()
            .remove("device_projection_attestation");
        assert!(serde_json::from_value::<PeerQueryDeviceRecord>(without_attestation).is_err());

        let mut without_projection = self_row(7);
        without_projection
            .as_object_mut()
            .unwrap()
            .remove("device_projection");
        assert!(serde_json::from_value::<QueryDeviceRecord>(without_projection).is_err());
    }

    /// The two surfaces are different types on purpose. A client row can never
    /// smuggle in an origin proof, and a peer row can never be read as a client
    /// row by dropping one.
    #[test]
    fn self_and_peer_rows_are_not_interchangeable() {
        assert!(serde_json::from_value::<QueryDeviceRecord>(peer_row(7)).is_err());
        assert!(serde_json::from_value::<PeerQueryDeviceRecord>(self_row(7)).is_err());

        let mut smuggled = self_row(7);
        smuggled["device_projection_attestation"] =
            peer_row(7)["device_projection_attestation"].clone();
        assert!(
            serde_json::from_value::<QueryDeviceRecord>(smuggled).is_err(),
            "the self row is closed: it carries no origin attestation"
        );

        // The projection itself names no (account, device): it is positioned by
        // the enclosing entry and map key, so it cannot be replayed as a
        // free-standing statement about some other device.
        let projection = self_row(7)["device_projection"].clone();
        assert!(projection.get("account_id").is_none());
        assert!(projection.get("device_id").is_none());
    }

    /// A self row exposes no material from which a caller could assemble an
    /// `AccountDeviceSignerEvidence`, which requires a complete signed
    /// `DeviceProjectionAttestation`.
    #[test]
    fn a_self_row_offers_no_signed_evidence_to_reconstruct() {
        let record: QueryDeviceRecord = serde_json::from_value(self_row(7)).unwrap();
        record.validate_projection().unwrap();
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec![
                "algorithms",
                "device_projection",
                "signer_evidence_ref",
                "trust_algorithms"
            ]
        );
        assert!(value.get("device_projection_attestation").is_none());
        assert!(value["device_projection"].get("proof").is_none());
    }

    #[test]
    fn attestation_binding_rejects_a_swapped_or_edited_row() {
        let principal = AccountId::new(
            arkret_wire::DidCoreId::new(PRINCIPAL_ID).unwrap(),
            arkret_wire::DidCoreId::new(STATION_ID).unwrap(),
        );
        let device = DeviceId::new(DEVICE_ID).unwrap();
        let record: PeerQueryDeviceRecord = serde_json::from_value(peer_row(7)).unwrap();
        record
            .validate_attestation_binding(&principal, &device)
            .expect("attestation covers this row");

        let other_device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap();
        assert!(
            record
                .validate_attestation_binding(&principal, &other_device)
                .is_err()
        );
        assert!(
            record
                .project_verified_row(&principal, &other_device)
                .is_err()
        );

        let projected = record.project_verified_row(&principal, &device).unwrap();
        assert_eq!(projected.device_projection.authorized_generation_ref, 7);

        let mut edited: PeerQueryDeviceRecord = serde_json::from_value(peer_row(7)).unwrap();
        edited.device_projection_attestation.attestation.device_id = other_device;
        assert!(
            edited
                .validate_attestation_binding(&principal, &device)
                .is_err(),
            "an attestation moved under another row key must be rejected"
        );
    }

    /// The transcript is context-separated from the resolution attestation, so
    /// a signature about an account can never be replayed as a statement about
    /// one of its devices.
    #[test]
    fn attestation_transcript_carries_its_own_context() {
        let record: PeerQueryDeviceRecord = serde_json::from_value(peer_row(7)).unwrap();
        let bytes = record
            .device_projection_attestation
            .proof_signing_bytes()
            .unwrap();
        let transcript = String::from_utf8(bytes).unwrap();
        assert!(
            transcript.contains(DEVICE_PROJECTION_ATTESTATION_CONTEXT),
            "{transcript}"
        );
        assert!(transcript.contains(DEVICE_ID), "{transcript}");
    }

    fn account(station: &str) -> AccountId {
        AccountId::new(
            arkret_wire::DidCoreId::new(PRINCIPAL_ID).unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        )
    }

    #[test]
    fn account_selectors_preserve_same_principal_at_distinct_stations() {
        let a = account("ak:did_core:web:a.example");
        let b = account("ak:did_core:web:b.example");
        let body = json!({"device_keys": [
            {"account_id": a, "device_ids": [DEVICE_ID]},
            {"account_id": b, "device_ids": [DEVICE_ID]}
        ]});
        let parsed: KeysQueryRequestBody = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(parsed.device_keys.len(), 2);
        assert_eq!(serde_json::to_value(parsed).unwrap(), body);
        let mut reversed = body;
        reversed["device_keys"].as_array_mut().unwrap().reverse();
        assert!(serde_json::from_value::<KeysQueryRequestBody>(reversed).is_err());
    }

    #[test]
    fn account_collections_reject_duplicate_identities_with_different_values() {
        let id = account(STATION_ID);
        let query = json!({"device_keys": [
            {"account_id": id, "device_ids": [DEVICE_ID]},
            {"account_id": id, "device_ids": ["ak:device:0196419b-0000-7000-8000-000000000002"]}
        ]});
        assert!(serde_json::from_value::<KeysQueryRequestBody>(query).is_err());
        let duplicate = json!({"device_keys": [], "device_generations": [
            {"account_id": id, "generation_state": {"current_device_generation_ref": 1}},
            {"account_id": id, "generation_state": {"current_device_generation_ref": 2}}
        ]});
        assert!(serde_json::from_value::<KeysQueryOutcome>(duplicate).is_err());
        for ids in [json!([]), json!([DEVICE_ID, DEVICE_ID])] {
            assert!(
                serde_json::from_value::<KeysQueryRequestBody>(json!({
                    "device_keys": [{"account_id": id, "device_ids": ids}]
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn self_outcome_addresses_rows_by_entry_account_only() {
        let own = account(STATION_ID);
        let other = account("ak:did_core:web:other.example");
        let value = json!({"device_keys": [{
            "account_id": own, "device_keys": {DEVICE_ID: self_row(7)}
        }]});
        let outcome: KeysQueryOutcome = serde_json::from_value(value).unwrap();
        assert!(outcome.devices_for(&own).is_some());
        assert!(outcome.devices_for(&other).is_none());
    }

    /// The peer surface still binds every signed row to its entry account, so a
    /// row moved under another Station's account is rejected on deserialization.
    #[test]
    fn peer_outcome_rejects_cross_station_attestation_row_swaps() {
        let own = account(STATION_ID);
        let other = account("ak:did_core:web:other.example");
        let mut value = json!({
            "request_id": "ak:request:01970000-0000-7000-8000-000000000061",
            "requester_account_id": own,
            "device_keys": [{"account_id": own, "device_keys": {DEVICE_ID: peer_row(7)}}]
        });
        serde_json::from_value::<PeerKeysQueryOutcome>(value.clone()).unwrap();
        value["device_keys"][0]["account_id"] = serde_json::to_value(other).unwrap();
        assert!(serde_json::from_value::<PeerKeysQueryOutcome>(value).is_err());
    }

    #[test]
    fn attestation_transcript_uses_one_complete_account_id() {
        let record: PeerQueryDeviceRecord = serde_json::from_value(peer_row(7)).unwrap();
        let bytes = record
            .device_projection_attestation
            .proof_signing_bytes()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["account_id"],
            serde_json::to_value(account(STATION_ID)).unwrap()
        );
        assert!(value.get("principal_id").is_none());
        assert!(value.get("station_id").is_none());
    }
}

#[cfg(test)]
mod peer_keys_query_tests {
    use arkret_wire::{DidCoreId, RealmId, RequestId};

    use super::*;
    use crate::artifacts_keys::QueryAccountDeviceSelector;

    fn account(principal: &str, station: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    fn device(index: u32) -> DeviceId {
        DeviceId::new(format!("ak:device:0196419b-0000-7000-8000-{index:012}")).unwrap()
    }

    fn selector(account_id: AccountId, devices: usize) -> QueryAccountDeviceSelector {
        QueryAccountDeviceSelector {
            account_id,
            device_ids: (0..devices).map(|index| device(index as u32 + 1)).collect(),
        }
    }

    fn request() -> PeerKeysQueryRequestBody {
        PeerKeysQueryRequestBody {
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000061").unwrap(),
            requester_account_id: account(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:home.example",
            ),
            purpose: PeerKeysQueryPurpose::E2eeMessageEncryption,
            relationship_basis: PeerKeysRelationshipBasis::Contact {},
            device_keys: vec![selector(
                account(
                    "ak:did_core:web:bob.example",
                    "ak:did_core:web:remote.example",
                ),
                2,
            )],
        }
    }

    #[test]
    fn peer_request_pins_one_destination_station() {
        let request = request();
        request.validate().unwrap();
        assert_eq!(
            request.destination_station_id().unwrap().as_str(),
            "ak:did_core:web:remote.example"
        );

        let mut split = request;
        split.device_keys.push(selector(
            account(
                "ak:did_core:web:carol.example",
                "ak:did_core:web:other.example",
            ),
            1,
        ));
        split.device_keys.sort_by_key(|entry| {
            arkret_canonical::canonical_json_bytes(&entry.account_id).unwrap()
        });
        assert!(split.destination_station_id().is_err());
    }

    #[test]
    fn contact_basis_carries_no_realm_and_realm_basis_does() {
        let contact = serde_json::to_value(PeerKeysRelationshipBasis::Contact {}).unwrap();
        assert_eq!(contact, serde_json::json!({"kind": "contact"}));
        let realm = serde_json::to_value(PeerKeysRelationshipBasis::RealmMembership {
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
        })
        .unwrap();
        assert_eq!(realm["kind"], "realm_membership");
        assert!(realm.get("realm_id").is_some());
        // A contact branch that smuggles a realm_id is not a valid wire shape.
        assert!(
            serde_json::from_value::<PeerKeysRelationshipBasis>(serde_json::json!({
                "kind": "contact",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
            }))
            .is_err()
        );
    }

    #[test]
    fn selector_bounds_fail_whole_rather_than_truncate() {
        let mut too_many_accounts = request();
        too_many_accounts.device_keys = (0..17)
            .map(|index| {
                selector(
                    account(
                        &format!("ak:did_core:web:p{index:02}.example"),
                        "ak:did_core:web:remote.example",
                    ),
                    1,
                )
            })
            .collect();
        too_many_accounts.device_keys.sort_by_key(|entry| {
            arkret_canonical::canonical_json_bytes(&entry.account_id).unwrap()
        });
        assert!(too_many_accounts.validate().is_err());

        let mut empty = request();
        empty.device_keys.clear();
        assert!(empty.validate().is_err());

        let mut too_many_devices = request();
        too_many_devices.device_keys = vec![selector(
            account(
                "ak:did_core:web:bob.example",
                "ak:did_core:web:remote.example",
            ),
            33,
        )];
        assert!(too_many_devices.validate().is_err());

        let local = KeysQueryRequestBody {
            device_keys: vec![selector(
                account(
                    "ak:did_core:web:bob.example",
                    "ak:did_core:web:home.example",
                ),
                32,
            )],
            timeout_ms: None,
        };
        local.validate().unwrap();
    }

    #[test]
    fn directory_failures_are_a_closed_two_value_reason_space() {
        let unavailable = QueryFailure {
            account_id: None,
            device_id: None,
            reason_code: QueryFailureReason::DeviceDirectoryUnavailable,
            retry_after_ms: Some(NonZeroU64::new(500).unwrap()),
        };
        unavailable.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&unavailable).unwrap()["reason_code"],
            "device_directory_unavailable"
        );

        // A target-private failure must not leak timing through retry_after_ms.
        let private = QueryFailure {
            retry_after_ms: Some(NonZeroU64::new(500).unwrap()),
            reason_code: QueryFailureReason::DeviceResultUnavailable,
            ..unavailable
        };
        assert!(private.validate().is_err());

        // The free-form claim reason space is no longer reachable from a
        // directory read.
        assert!(
            serde_json::from_value::<QueryFailure>(serde_json::json!({
                "reason_code": "device_unknown"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<QueryFailure>(serde_json::json!({
                "reason_code": "device_result_unavailable",
                "algorithm": "ed25519"
            }))
            .is_err()
        );
    }

    #[test]
    fn peer_outcome_must_answer_the_exact_request_and_selected_accounts() {
        let request = request();
        let outcome = PeerKeysQueryOutcome {
            request_id: request.request_id.clone(),
            requester_account_id: request.requester_account_id.clone(),
            device_keys: Vec::new(),
            device_generations: Vec::new(),
            failures: vec![QueryFailure {
                account_id: None,
                device_id: None,
                reason_code: QueryFailureReason::DeviceResultUnavailable,
                retry_after_ms: None,
            }],
        };
        outcome.validate_for_request(&request).unwrap();

        let mut other_request = outcome.clone();
        other_request.request_id =
            RequestId::new("ak:request:01970000-0000-7000-8000-000000000062").unwrap();
        assert!(other_request.validate_for_request(&request).is_err());

        let mut other_requester = outcome;
        other_requester.requester_account_id = account(
            "ak:did_core:web:mallory.example",
            "ak:did_core:web:home.example",
        );
        assert!(other_requester.validate_for_request(&request).is_err());
    }

    #[test]
    fn peer_outcome_rejects_an_unselected_account_row() {
        let request = request();
        let outcome = PeerKeysQueryOutcome {
            request_id: request.request_id.clone(),
            requester_account_id: request.requester_account_id.clone(),
            device_keys: Vec::new(),
            device_generations: vec![AccountDeviceGenerationEntry {
                account_id: account(
                    "ak:did_core:web:carol.example",
                    "ak:did_core:web:remote.example",
                ),
                generation_state: DeviceGenerationState {
                    current_device_generation_ref: 1,
                },
            }],
            failures: Vec::new(),
        };
        assert!(outcome.validate_for_request(&request).is_err());
    }
}

impl ForwardDeviceProjectionAttestationCore {
    pub fn validate_event_authorization(&self) -> arkret_wire::Result<()> {
        let source = &self.event_authorization;
        if !source.forward_body_digest.as_str().starts_with("sha256:")
            || source.authorization_ref.event_id != self.device_authorize_event_id
            || !matches!(
                &source.authorization_ref.stream_ref,
                arkret_wire::CommitStreamRef::Realm { .. }
            )
            || source.authorization_ref.stream_position > source.revision.stream_position
            || (source.authorization_ref.commit_id == source.revision.commit_id
                && source.authorization_ref.stream_position != source.revision.stream_position)
        {
            return Err(arkret_wire::WireError::Protocol("forward device attestation does not bind an exact covering original authorization source".into()));
        }
        Ok(())
    }
}
