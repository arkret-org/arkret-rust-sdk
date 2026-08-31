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

/// Directory status of a `(principal_id, device_id)` pair at query time.
///
/// `active` = a `ak.device.authorize` is in effect and the device is not
/// revoked; `revoked` = a `ak.device.revoke` is in effect. Servers MUST omit
/// [`QueryDeviceRecord::device_signing_key_did`] for any non-active device.
/// Mirrors `keys-operations.schema.json#/$defs/device_status`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceGenerationStatus {
    Active,
    Conflicted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGenerationState {
    pub current_device_generation_ref: u64,
    pub device_generation_status: DeviceGenerationStatus,
}

/// Origin Station assertion that one exact device projection is the
/// account's current accepted one.
///
/// This is the whole verification closure of the cross-principal `keys/query`
/// surface. It replaced the PCR genesis receipt / authorization chain / accepted
/// Seal the prose used to demand: that material is account-internal governance,
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
        let payload_digest = Hash::new(arkret_canonical::canonical_sha256(core)?)?;
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

/// Per-`(principal_id, device_id)` entry in [`KeysQueryOutcome::device_keys`].
///
/// Every field is required. A device whose generation is fenced or conflicted,
/// or which is revoked, is not degraded into a partial row: it is omitted from
/// `device_keys` or reported through the non-enumerating `failures` shape, so
/// an incomplete row can never be mistaken for a usable one. `principal_id` and
/// `device_id` are the map keys, not row fields. Mirrors
/// `keys-operations.schema.json#/$defs/query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceRecord {
    /// Prekey bundle keyed by algorithm name. The demo projection carries the
    /// opaque uploaded key payload here; each value matches the schema
    /// `key_record` once real prekey records are published.
    #[serde(default)]
    pub algorithms: AlgorithmKeyRecords,
    /// Canonical (UTF-8 bytewise sorted, deduplicated) algorithm ids used to
    /// select entries from the sibling prekey-bundle map. Device identity,
    /// signing/HPKE material and generation live only in the attestation.
    pub trust_algorithms: Vec<NonEmptyString>,
    /// Origin Station signature over this exact row.
    pub device_projection_attestation: DeviceProjectionAttestation,
}

impl QueryDeviceRecord {
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
                state.device_generation_status == DeviceGenerationStatus::Active
                    && attested.authorized_generation_ref == state.current_device_generation_ref
            }
            None => false,
        }
    }

    /// Bind the attestation to the `(principal_id, device_id)` map keys it travels under.
    ///
    /// This does not verify the detached proof; it rejects a swapped or edited
    /// row before a caller spends a signature check on it.
    pub fn validate_attestation_binding(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> arkret_wire::Result<()> {
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
    pub failures: Vec<KeysOperationFailure>,
    /// Reducer-managed B-model device generation fence by complete account.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "arkret_wire::deserialize_identity_entries",
        serialize_with = "arkret_wire::serialize_identity_entries"
    )]
    pub device_generations: Vec<AccountDeviceGenerationEntry>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAccountDeviceEntry {
    pub account_id: AccountId,
    pub device_keys: BTreeMap<DeviceId, QueryDeviceRecord>,
}

impl arkret_wire::CanonicalIdentityEntry for QueryAccountDeviceEntry {
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
    pub fn devices_for(
        &self,
        account_id: &AccountId,
    ) -> Option<&BTreeMap<DeviceId, QueryDeviceRecord>> {
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

/// Per-target failure returned by keys query and claim operations.
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

    fn attested_row(generation: u64) -> serde_json::Value {
        let trust_algorithm = arkret_wire::generated::HPKE_SUITES[2].canonical_id;
        json!({
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
                    "device_status": "active",
                    "attested_at": "2026-08-15T00:00:00.000Z",
                    "expires_at": "2026-08-15T00:10:00.000Z"
                },
                "proof": {
                    "verification_method": "did:webvh:z6mkfixtureps:ps.example#signing-1",
                    "created_at": "2026-08-15T00:00:00.000Z",
                    "jws": "c2ln"
                }
            }
        })
    }

    #[test]
    fn device_generation_must_be_current_and_fully_anchored() {
        let generation = DeviceGenerationState {
            current_device_generation_ref: 7,
            device_generation_status: DeviceGenerationStatus::Active,
        };
        let record: QueryDeviceRecord = serde_json::from_value(attested_row(7)).unwrap();
        assert!(record.is_usable_in_generation(Some(&generation)));
        assert!(!record.is_usable_in_generation(None));

        let stale: QueryDeviceRecord = serde_json::from_value(attested_row(6)).unwrap();
        assert!(!stale.is_usable_in_generation(Some(&generation)));
    }

    #[test]
    fn a_device_row_requires_its_projection_attestation() {
        let mut without_attestation = attested_row(7);
        without_attestation
            .as_object_mut()
            .unwrap()
            .remove("device_projection_attestation");
        assert!(serde_json::from_value::<QueryDeviceRecord>(without_attestation).is_err());
    }

    #[test]
    fn attestation_binding_rejects_a_swapped_or_edited_row() {
        let principal = AccountId::new(
            arkret_wire::DidCoreId::new(PRINCIPAL_ID).unwrap(),
            arkret_wire::DidCoreId::new(STATION_ID).unwrap(),
        );
        let device = DeviceId::new(DEVICE_ID).unwrap();
        let record: QueryDeviceRecord = serde_json::from_value(attested_row(7)).unwrap();
        record
            .validate_attestation_binding(&principal, &device)
            .expect("attestation covers this row");

        let other_device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap();
        assert!(
            record
                .validate_attestation_binding(&principal, &other_device)
                .is_err()
        );

        let mut edited: QueryDeviceRecord = serde_json::from_value(attested_row(7)).unwrap();
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
        let record: QueryDeviceRecord = serde_json::from_value(attested_row(7)).unwrap();
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
    fn account_collections_reject_legacy_maps_and_duplicate_identities_with_different_values() {
        let id = account(STATION_ID);
        let query = json!({"device_keys": [
            {"account_id": id, "device_ids": [DEVICE_ID]},
            {"account_id": id, "device_ids": ["ak:device:0196419b-0000-7000-8000-000000000002"]}
        ]});
        assert!(serde_json::from_value::<KeysQueryRequestBody>(query).is_err());
        assert!(
            serde_json::from_value::<KeysQueryRequestBody>(json!({
                "device_keys": {PRINCIPAL_ID: [DEVICE_ID]}
            }))
            .is_err()
        );
        let duplicate = json!({"device_keys": [], "device_generations": [
            {"account_id": id, "generation_state": {"current_device_generation_ref": 1, "device_generation_status": "active"}},
            {"account_id": id, "generation_state": {"current_device_generation_ref": 2, "device_generation_status": "active"}}
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
    fn query_outcome_rejects_cross_station_attestation_row_swaps() {
        let own = account(STATION_ID);
        let other = account("ak:did_core:web:other.example");
        let mut value = json!({"device_keys": [{
            "account_id": own, "device_keys": {DEVICE_ID: attested_row(7)}
        }]});
        let outcome: KeysQueryOutcome = serde_json::from_value(value.clone()).unwrap();
        assert!(outcome.devices_for(&own).is_some());
        assert!(outcome.devices_for(&other).is_none());
        value["device_keys"][0]["account_id"] = serde_json::to_value(other).unwrap();
        assert!(serde_json::from_value::<KeysQueryOutcome>(value).is_err());
    }

    #[test]
    fn attestation_transcript_uses_one_complete_account_id() {
        let record: QueryDeviceRecord = serde_json::from_value(attested_row(7)).unwrap();
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
        let mut legacy = attested_row(7);
        let core = legacy["device_projection_attestation"]["attestation"]
            .as_object_mut()
            .unwrap();
        core.remove("account_id");
        core.insert("principal_id".to_owned(), json!(PRINCIPAL_ID));
        core.insert("station_id".to_owned(), json!(STATION_ID));
        assert!(serde_json::from_value::<QueryDeviceRecord>(legacy).is_err());
    }
}
