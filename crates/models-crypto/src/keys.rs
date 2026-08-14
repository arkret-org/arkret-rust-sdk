//! Key claim and distribution DTO counterparts for `keys-operations.schema.json`.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use arkret_wire::{DeviceId, DidCoreId, DidKey, EventId, NonEmptyString, ReasonCode};
use serde::{Deserialize, Serialize};

use crate::artifacts_keys::{
    AlgorithmCounts, AlgorithmKeyRecords, KeyOperationSignature, PrincipalDeviceAlgorithmMap,
    PrincipalDeviceKeyRecords, QueryDeviceMap,
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
    pub device_keys: QueryDeviceMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<u64>)))]
    pub timeout_ms: Option<NonZeroU64>,
}

/// Directory status of a `(principal_id, device_id)` pair at query time.
///
/// `active` = a `ak.device.authorize` is in effect and the device is not
/// revoked; `revoked` = a `ak.device.revoke` is in effect. Servers MUST omit
/// [`QueryDeviceRecord::device_signing_key`] for any non-active device.
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

/// Per-`(principal_id, device_id)` entry in [`KeysQueryOutcome::device_keys`].
///
/// The prekey bundle is carried under `algorithms` (algorithm name →
/// `key_record`); the device signing-key directory facet
/// (`device_signing_key` / `device_status`) sits at the same level as the
/// algorithm dimension, not repeated per algorithm. The directory facet is
/// populated only for verified, non-revoked devices. Mirrors
/// `keys-operations.schema.json#/$defs/query_device_record`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceRecord {
    /// Prekey bundle keyed by algorithm name. The demo projection carries the
    /// opaque uploaded key payload here; each value matches the schema
    /// `key_record` once real prekey records are published.
    #[serde(default)]
    pub algorithms: AlgorithmKeyRecords,
    /// Authoritative device verify key as an Ed25519 `did:key`
    /// (multibase base58btc, multicodec ed25519-pub). Present only for
    /// verified, non-revoked devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<String>)))]
    pub device_signing_key: Option<DidKey>,
    /// Device HPKE sealing public key echoed verbatim from the authoritative
    /// `ak.device.authorize.payload.hpke_key` (`device-lifecycle.md` §8.2).
    /// Present only for verified, non-revoked devices; services MUST NOT
    /// substitute this value in projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_key: Option<NonEmptyString>,
    /// Canonical (UTF-8 bytewise sorted, deduplicated) algorithm ids echoed
    /// verbatim from `ak.device.authorize.payload.algorithms`; together with
    /// `device_signing_key` and `hpke_key` this is the material the §5.2
    /// `ak-device-trust-bind-v1` transcript covers. Distinct from the sibling
    /// `algorithms` prekey-bundle map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_algorithms: Option<Vec<NonEmptyString>>,
    /// Directory status of the device at query time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_status: Option<DeviceStatus>,
    /// Accepted `ak.device.authorize` event id that anchored the device-set
    /// projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    /// Reducer-managed B-model generation that authorized this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_generation_ref: Option<u64>,
}

impl QueryDeviceRecord {
    /// Return whether this device is usable in the reducer's current accepted
    /// generation.
    pub fn is_usable_in_generation(&self, generation: Option<&DeviceGenerationState>) -> bool {
        if self.device_status != Some(DeviceStatus::Active) {
            return false;
        }
        match (generation, self.authorized_generation_ref.as_ref()) {
            (Some(state), Some(device_generation)) => {
                state.device_generation_status == DeviceGenerationStatus::Active
                    && device_generation == &state.current_device_generation_ref
                    && self.device_authorize_event_id.is_some()
            }
            _ => false,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysQueryOutcome {
    pub device_keys: BTreeMap<DidCoreId, BTreeMap<DeviceId, QueryDeviceRecord>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<KeysOperationFailure>,
    /// Reducer-managed B-model device generation fence by principal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_generations: BTreeMap<DidCoreId, DeviceGenerationState>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysClaimRequestBody {
    pub one_time_keys: PrincipalDeviceAlgorithmMap,
}

/// Per-target failure returned by keys query and claim operations.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysOperationFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<DidCoreId>,
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
    pub one_time_keys: PrincipalDeviceKeyRecords,
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

    #[test]
    fn device_generation_must_be_current_and_fully_anchored() {
        let generation = DeviceGenerationState {
            current_device_generation_ref: 7,
            device_generation_status: DeviceGenerationStatus::Active,
        };
        let mut record: QueryDeviceRecord = serde_json::from_value(json!({
            "device_status": "active",
            "device_authorize_event_id": "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            "authorized_generation_ref": 7
        }))
        .unwrap();
        assert!(record.is_usable_in_generation(Some(&generation)));
        assert!(!record.is_usable_in_generation(None));

        record.device_authorize_event_id = None;
        assert!(!record.is_usable_in_generation(Some(&generation)));
        record.device_authorize_event_id =
            Some(EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e").unwrap());
        record.authorized_generation_ref = Some(6);
        assert!(!record.is_usable_in_generation(Some(&generation)));
    }
}
