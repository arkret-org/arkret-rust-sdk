use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadRequestBody {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
    pub device_signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadOutcome {
    pub one_time_key_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryRequestBody {
    pub device_keys: BTreeMap<Did, Vec<DeviceId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Directory status of a `(principal_id, device_id)` pair at query time.
///
/// `active` = a `ck.device.authorize` is in effect and the device is not
/// revoked; `revoked` = a `ck.device.revoke` is in effect. Servers MUST omit
/// [`QueryDeviceRecord::device_signing_key`] for any non-active device.
/// Mirrors `keys-operations.schema.json#/$defs/device_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// Tier-2 per-device cross-signing binding echoed from
/// `ck.device.authorize.payload.cross_signing_binding`
/// (`crypto-media/device-lifecycle.md` §5.2). The accepted-generation SSK signs
/// `"ck-device-trust-bind-v1\n" + canonical_json({principal_id, device_id,
/// device_public_key, ssk_generation})`. Absent for inception bootstrap devices
/// (§5.0.1). Mirrors `keys-operations.schema.json#/$defs/cross_signing_binding`.
///
/// Shape-identical to `cokret_crypto::DeviceTrustBinding` (the SDK chain
/// verifier's input type), but defined here in `core` because `core` cannot
/// depend on `crypto`; `alg` is optional per schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct QueryDeviceCrossSigningBinding {
    /// DID URL of the self-signing key (SSK) that produced the binding
    /// signature, e.g. `did:webvh:...#ck_self_signing_v1`.
    pub verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// `cross_signing.publish` generation under which the SSK signed this
    /// device binding; compared to the principal's accepted generation per
    /// §5.2.1.
    pub ssk_generation: u64,
    pub signature: String,
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
pub struct QueryDeviceRecord {
    /// Prekey bundle keyed by algorithm name. The demo projection carries the
    /// opaque uploaded key payload here; each value matches the schema
    /// `key_record` once real prekey records are published.
    #[serde(default)]
    pub algorithms: BTreeMap<String, Value>,
    /// Authoritative device verify key as an Ed25519 `did:key`
    /// (multibase base58btc, multicodec ed25519-pub). Present only for
    /// verified, non-revoked devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signing_key: Option<String>,
    /// Directory status of the device at query time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_status: Option<DeviceStatus>,
    /// Tier-2: the device's authoritative `cross_signing_binding` echoed
    /// verbatim, so the client can independently verify the
    /// device-key ← SSK link (`device-lifecycle.md` §8.3). Absent for
    /// inception bootstrap devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<QueryDeviceCrossSigningBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryOutcome {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, QueryDeviceRecord>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Value>,
    /// Tier-2: per-principal current accepted-generation
    /// `ck.cross_signing.publish` payload (`device-lifecycle.md` §5.1), letting
    /// the client anchor the SSK to the DID control set before trusting any
    /// `cross_signing_binding` (§8.3). Reuses the schema-counterpart type
    /// [`CrossSigningPublish`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cross_signing: BTreeMap<Did, CrossSigningPublish>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimRequestBody {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimOutcome {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesPutRequestBody {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, DeviceMessageTarget>>,
}

pub type DeviceMessagesSendRequestBody = DeviceMessagesPutRequestBody;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessageTarget {
    pub kind: String,
    pub content: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessageEnvelope {
    pub kind: String,
    pub sender_principal_id: Did,
    pub sender_device_id: DeviceId,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesPutOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

pub type DeviceMessagesSendOutcome = DeviceMessagesPutOutcome;

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
