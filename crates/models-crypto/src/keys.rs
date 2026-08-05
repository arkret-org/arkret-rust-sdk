//! Key claim and distribution DTO counterparts for `keys-operations.schema.json`.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use arkret_models_identity::artifacts_device_identity::{
    CrossSigningPublish, DeviceEnrollmentAuthorityBinding,
};
use arkret_wire::{
    Base64UrlString, DeviceId, Did, DidKey, DidUrl, EventId, NonEmptyString, ReasonCode,
};
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
    pub current_device_generation_ref: NonEmptyString,
    pub device_generation_status: DeviceGenerationStatus,
}

/// Per-device cross-signing binding echoed from
/// `ak.device.authorize.payload.cross_signing_binding`
/// (`crypto-media/device-lifecycle.md` §5.2). The accepted-generation SSK signs
/// `"ak.device-trust-bind-v1\n" + canonical_json({principal_id, device_id,
/// device_public_key, hpke_key, algorithms, ssk_generation})`. Absent for
/// service-attested devices. Mirrors
/// `keys-operations.schema.json#/$defs/cross_signing_binding`.
///
/// Shape-identical to `arkret_crypto::DeviceTrustBinding` (the SDK chain
/// verifier's input type), but defined here in `core` because `core` cannot
/// depend on `crypto`; `alg` is optional per schema.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceCrossSigningBinding {
    /// DID URL of the self-signing key (SSK) that produced the binding
    /// signature, e.g. `did:webvh:...#ak_self_signing_v1`.
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<NonEmptyString>,
    /// `cross_signing.publish` generation under which the SSK signed this
    /// device binding; compared to the principal's accepted generation per
    /// §5.2.1.
    pub ssk_generation: u64,
    pub signature: Base64UrlString,
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
    /// Cross-signing trust material: the device's authoritative
    /// `cross_signing_binding` echoed verbatim, so the client can
    /// independently verify the device-key ← SSK link (`device-lifecycle.md`
    /// §8.3). Absent for service-attested devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<QueryDeviceCrossSigningBinding>,
    /// Service-attested trust material for managed-DID devices
    /// (`device-lifecycle.md` §5.4), echoed from the accepted
    /// `ak.device.authorize` payload. Present only for a verified, non-revoked
    /// device authorized by the designated enrollment authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    /// Accepted `ak.device.authorize` event id that anchored the device-set
    /// projection. For service-attested devices this pairs with
    /// [`Self::enrollment_authority_binding`] and is the hot-path trust anchor
    /// clients carry forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorize_event_id: Option<EventId>,
    /// Reducer-managed B-model generation that authorized this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_generation_ref: Option<NonEmptyString>,
}

impl QueryDeviceRecord {
    /// Return whether this device is usable under exactly one accepted trust
    /// model. A-model devices require only a cross-signing binding. B-model
    /// devices require the current generation, enrollment-authority binding,
    /// and accepted authorize-event anchor. Mixed A/B projections fail closed.
    pub fn is_usable_in_generation(&self, generation: Option<&DeviceGenerationState>) -> bool {
        if self.device_status != Some(DeviceStatus::Active) {
            return false;
        }
        match (generation, self.authorized_generation_ref.as_ref()) {
            (None, None) => {
                self.cross_signing_binding.is_some() && self.enrollment_authority_binding.is_none()
            }
            (Some(state), Some(device_generation)) => {
                state.device_generation_status == DeviceGenerationStatus::Active
                    && device_generation == &state.current_device_generation_ref
                    && self.enrollment_authority_binding.is_some()
                    && self.device_authorize_event_id.is_some()
                    && self.cross_signing_binding.is_none()
            }
            _ => false,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysQueryOutcome {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, QueryDeviceRecord>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<KeysOperationFailure>,
    /// Tier-2: per-principal current accepted-generation
    /// `ak.cross_signing.publish` payload (`device-lifecycle.md` §5.1), letting
    /// the client anchor the SSK to the DID control set before trusting any
    /// `cross_signing_binding` (§8.3). Reuses the schema-counterpart type
    /// [`CrossSigningPublish`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = std::collections::BTreeMap<String, serde_json::Value>))
    )]
    pub cross_signing: BTreeMap<Did, CrossSigningPublish>,
    /// Reducer-managed B-model device generation fence by principal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_generations: BTreeMap<Did, DeviceGenerationState>,
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
    pub principal_id: Option<Did>,
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
    fn device_generation_trust_models_are_exclusive_and_fully_anchored() {
        let cross_signing_binding = json!({
            "verification_method": "did:webvh:z6mkfixture:alice.example#ssk",
            "ssk_generation": 1,
            "signature": "c2ln"
        });
        let enrollment_authority_binding = json!({
            "kind": "service_attested",
            "authority_did": "did:webvh:z6mkauthority:auth.example",
            "authorization_ref": "did:webvh:z6mkfixture:alice.example#enrollment-authority"
        });

        let mut a_model: QueryDeviceRecord = serde_json::from_value(json!({
            "device_status": "active",
            "cross_signing_binding": cross_signing_binding
        }))
        .unwrap();
        assert!(a_model.is_usable_in_generation(None));
        a_model.enrollment_authority_binding =
            Some(serde_json::from_value(enrollment_authority_binding.clone()).unwrap());
        assert!(!a_model.is_usable_in_generation(None));

        let generation = DeviceGenerationState {
            current_device_generation_ref: NonEmptyString::new("did-version-7").unwrap(),
            device_generation_status: DeviceGenerationStatus::Active,
        };
        let mut b_model: QueryDeviceRecord = serde_json::from_value(json!({
            "device_status": "active",
            "enrollment_authority_binding": enrollment_authority_binding,
            "device_authorize_event_id": "ak:event:01904100-0000-8000-8000-a11ce0000001",
            "authorized_generation_ref": "did-version-7"
        }))
        .unwrap();
        assert!(b_model.is_usable_in_generation(Some(&generation)));

        b_model.device_authorize_event_id = None;
        assert!(!b_model.is_usable_in_generation(Some(&generation)));
        b_model.device_authorize_event_id =
            Some(EventId::new("ak:event:01904100-0000-8000-8000-a11ce0000001").unwrap());
        b_model.cross_signing_binding = a_model.cross_signing_binding;
        assert!(!b_model.is_usable_in_generation(Some(&generation)));
    }
}
