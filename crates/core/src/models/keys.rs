use std::num::NonZeroU64;

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysUploadRequestBody {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: AlgorithmKeyRecords,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: AlgorithmKeyRecords,
    pub device_signature: KeyOperationSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysUploadOutcome {
    pub one_time_key_counts: AlgorithmCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: AlgorithmKeyRecords,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysQueryRequestBody {
    pub device_keys: QueryDeviceMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = u64)))]
    pub timeout_ms: Option<NonZeroU64>,
}

/// Directory status of a `(principal_id, device_id)` pair at query time.
///
/// `active` = a `ak.device.authorize` is in effect and the device is not
/// revoked; `revoked` = a `ak.device.revoke` is in effect. Servers MUST omit
/// [`QueryDeviceRecord::device_signing_key`] for any non-active device.
/// Mirrors `keys-operations.schema.json#/$defs/device_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceGenerationStatus {
    Active,
    Conflicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceCrossSigningBinding {
    /// DID URL of the self-signing key (SSK) that produced the binding
    /// signature, e.g. `did:webvh:...#ak_self_signing_v1`.
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<NonEmptyString>,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub cross_signing: BTreeMap<Did, CrossSigningPublish>,
    /// Reducer-managed B-model device generation fence by principal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_generations: BTreeMap<Did, DeviceGenerationState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysClaimRequestBody {
    pub one_time_keys: PrincipalDeviceAlgorithmMap,
}

/// Per-target failure returned by keys query and claim operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysOperationFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<NonEmptyString>,
    pub reason_code: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = u64)))]
    pub retry_after_ms: Option<NonZeroU64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeysClaimOutcome {
    pub one_time_keys: PrincipalDeviceKeyRecords,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<KeysOperationFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendRequestBody {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceMessageTarget {
    pub message_id: DeviceMessageId,
    pub kind: ProtocolKind,
    pub content: BTreeMap<String, Value>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesGetOutcome {
    pub messages: Vec<DeviceMessageEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub limited: bool,
    #[serde(default)]
    pub lost: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesAckRequestBody {
    pub ack_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesAckOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned_count: Option<u64>,
}

#[cfg(test)]
mod device_message_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn device_message_target_rejects_non_object_content_and_invalid_kind() {
        let valid = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(valid).is_ok());

        let missing_message_id = json!({
            "kind": "ak.key.verification.request",
            "content": {"transaction_id": "txn"},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(missing_message_id).is_err());

        let invalid_kind = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "key.verification.request",
            "content": {},
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(invalid_kind).is_err());

        let scalar_content = json!({
            "message_id": "ak:device_message:01904100-0000-7000-8000-000000000001",
            "kind": "ak.key.verification.request",
            "content": "legacy payload",
            "expires_at": "2026-07-15T01:00:00Z"
        });
        assert!(serde_json::from_value::<DeviceMessageTarget>(scalar_content).is_err());
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
            "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce0000001",
            "authorized_generation_ref": "did-version-7"
        }))
        .unwrap();
        assert!(b_model.is_usable_in_generation(Some(&generation)));

        b_model.device_authorize_event_id = None;
        assert!(!b_model.is_usable_in_generation(Some(&generation)));
        b_model.device_authorize_event_id =
            Some(EventId::new("ak:event:01904100-0000-7000-8000-a11ce0000001").unwrap());
        b_model.cross_signing_binding = a_model.cross_signing_binding;
        assert!(!b_model.is_usable_in_generation(Some(&generation)));
    }
}
