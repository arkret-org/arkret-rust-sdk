//! Device identity schema artifact counterparts.
//!
//! [`IdentityReceipt`] and the cross-signing reset proof shapes migrated
//! to `arkret-models-identity` (re-exported below); the shapes kept here
//! await migration alongside their sibling artifact counterparts.

pub use arkret_models_identity::artifacts_device_identity::*;

use super::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json#/properties/handover_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStaleHandoverProof {
    pub frontier: Vec<EventId>,
    pub recipient_service_id: Did,
    pub actor_id: Did,
    pub witness: NonEmptyJsonObject,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStale {
    pub new_recipient_service_id: Did,
    pub handover_frontier: Vec<EventId>,
    pub handover_proof: DeliveryBindingStaleHandoverProof,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json#/$defs/event_id_list`.
pub type EventIdList = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/key_verification_content`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContentNewDevicePubkey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<NonEmptyString>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContent {
    pub transaction_id: TransactionId,
    pub from_device: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<ProtocolKindList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ProtocolKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<KeyVerificationPurpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<KeyVerificationPairingCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_device_pubkey: Option<KeyVerificationContentNewDevicePubkey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_signature: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_audience: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_agreement_protocols: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_authentication_codes: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_authentication_string: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<BTreeMap<String, NonEmptyString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<BTreeMap<String, NonEmptyString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_keys: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<KeyVerificationCancellationCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<KeyVerificationCancellationReason>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationPurpose {
    DeviceKeyVerification,
    SamePrincipalDeviceAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationCancellationCode {
    UserCancelled,
    Timeout,
    UnknownTransaction,
    UnexpectedMessage,
    UnsupportedMethod,
    UnsupportedAlgorithm,
    MismatchedCommitment,
    MismatchedMac,
    DeviceRevoked,
    UntrustedDevice,
    PolicyDenied,
    AcceptedByOtherDevice,
    CrossSigningReset,
}

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/string_list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StringList(Vec<NonEmptyString>);

impl StringList {
    pub fn new(values: Vec<NonEmptyString>) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::Protocol("string list must not be empty".to_owned()));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(Error::Protocol(
                "string list values must be unique".to_owned(),
            ));
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[NonEmptyString] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<NonEmptyString> {
        self.0
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<NonEmptyString>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

/// Non-empty unique list of Arkret protocol kinds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProtocolKindList(Vec<ProtocolKind>);

impl ProtocolKindList {
    pub fn new(values: Vec<ProtocolKind>) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::Protocol(
                "protocol kind list must not be empty".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(Error::Protocol(
                "protocol kind list values must be unique".to_owned(),
            ));
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[ProtocolKind] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<ProtocolKind> {
        self.0
    }
}

impl<'de> Deserialize<'de> for ProtocolKindList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<ProtocolKind>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

macro_rules! bounded_key_verification_string {
    ($name:ident, $maximum:expr, $error:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub struct $name(NonEmptyString);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = NonEmptyString::new(value)
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?;
                if value.chars().count() > $maximum {
                    return Err(Error::Protocol($error.to_owned()));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_key_verification_string!(
    KeyVerificationPairingCode,
    128,
    "key verification pairing code exceeds 128 characters"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct KeyVerificationCancellationReason(String);

impl KeyVerificationCancellationReason {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.chars().count() > 256 {
            return Err(Error::Protocol(
                "key verification cancellation reason exceeds 256 characters".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyVerificationCancellationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-active-series.schema.json#/$defs/frontier_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierRef {
    pub frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<Hash>,
    pub ssk_generation: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn key_verification_content_enforces_schema_string_constraints() {
        let valid = json!({
            "transaction_id": "ak:transaction:01904100-0000-7000-8000-000000000001",
            "from_device": "ak:device:01904100-0000-7000-8000-000000000001",
            "methods": ["ak.key.verification.sas_v1"],
            "pairing_code": "482 913",
            "new_device_pubkey": {
                "kid": "ak:device:01904100-0000-7000-8000-000000000002",
                "alg": "EdDSA",
                "public_key": "z6MkDevice",
                "vendor_hint": true
            },
            "mac": {"ed25519:key": "c2ln"},
            "device_metadata": {"display_name": "Laptop"},
            "vendor_extension": {"opaque": true}
        });
        assert!(serde_json::from_value::<KeyVerificationContent>(valid.clone()).is_ok());

        let mut empty_methods = valid.clone();
        empty_methods["methods"] = json!([]);
        assert!(serde_json::from_value::<KeyVerificationContent>(empty_methods).is_err());

        let mut duplicate_methods = valid.clone();
        duplicate_methods["methods"] =
            json!(["ak.key.verification.sas_v1", "ak.key.verification.sas_v1"]);
        assert!(serde_json::from_value::<KeyVerificationContent>(duplicate_methods).is_err());

        let mut invalid_method = valid.clone();
        invalid_method["methods"] = json!(["legacy.verification"]);
        assert!(serde_json::from_value::<KeyVerificationContent>(invalid_method).is_err());

        let mut empty_mac = valid.clone();
        empty_mac["mac"] = json!({"ed25519:key": ""});
        assert!(serde_json::from_value::<KeyVerificationContent>(empty_mac).is_err());

        let mut long_pairing_code = valid.clone();
        long_pairing_code["pairing_code"] = json!("x".repeat(129));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_pairing_code).is_err());

        let mut long_reason = valid;
        long_reason["reason"] = json!("x".repeat(257));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_reason).is_err());
    }
}
