//! Device-authorization, cross-signing, and identity-binding payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

pub const DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON: &str = "device_authorize_binding_one_of";

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/cross_signing_publish_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSigningPublishPayload {
    pub principal_id: Did,
    pub trust_domain: String,
    pub principal_signing_key: BTreeMap<String, Value>,
    pub self_signing_key: BTreeMap<String, Value>,
    pub user_signing_key: BTreeMap<String, Value>,
    pub expected_previous_generation: u64,
    pub generation: u64,
    pub issued_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_authorize_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBootstrapBinding {
    pub kind: String,
    pub did_method_evidence_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub principal_id: Did,
    pub device_id: String,
    pub device_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_algorithm: Option<String>,
    pub authorized_by: DeviceOrPrincipalRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_signing_binding: Option<DeviceCrossSigningBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_binding: Option<DeviceBootstrapBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_session_id: Option<RecoverySessionId>,
}

impl DeviceAuthorizePayload {
    pub fn authorization_binding_count(&self) -> usize {
        self.cross_signing_binding.is_some() as usize
            + self.bootstrap_binding.is_some() as usize
            + self.enrollment_authority_binding.is_some() as usize
    }

    pub fn validate_authorization_binding_one_of(&self) -> std::result::Result<(), &'static str> {
        if self.authorization_binding_count() == 1 {
            Ok(())
        } else {
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// device_enrollment_authority_binding`.
///
/// Delegated-authority binding for a `service_attested` `ck.device.authorize`
/// (managed-DID / account-authority onboarding). The cryptographic signer is the
/// envelope proof (`verification_method` maps to `executed_by`); this object
/// records the trust root. See `zh/crypto-media/device-lifecycle.md` §5.4.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnrollmentAuthorityBinding {
    /// MUST be `"service_attested"`.
    pub kind: String,
    /// DID of the enrollment authority that attested this device (equals the
    /// envelope `executed_by`); designated by the principal DID document.
    pub authority_did: Did,
    /// Reference to the delegation designating `authority_did` (DID-document
    /// service delegation, materialized grant, or delegation event id); equals
    /// the envelope `authorization_ref`.
    pub authorization_ref: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_cross_signing_binding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCrossSigningBinding {
    pub verification_method: Value,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_or_principal_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceOrPrincipalRef {
    DeviceId(String),
    Did(Did),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokePayload {
    pub principal_id: Did,
    pub device_id: String,
    pub revoked_by: DeviceOrPrincipalRef,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationBoundPayload {
    pub pair_key: Value,
    pub participants_unordered: Vec<Did>,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub contact_refs: ContactEventRefs,
    pub member_event_refs: Value,
    pub main_strand_create_ref: EventRef,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_binding_ref: Option<EventRef>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/encrypted_metadata`.
pub type EncryptedMetadata = EncryptedEnvelope;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/erasure_receipt_payload`.
pub type ErasureReceiptPayload = ErasureReceipt;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn base_device_authorize_payload() -> DeviceAuthorizePayload {
        DeviceAuthorizePayload {
            principal_id: Did::new("did:web:alice.example").unwrap(),
            device_id: "ck:device:01904100-0000-7000-8000-a11ce0000001".to_owned(),
            device_public_key: "z6MkDeviceKey".to_owned(),
            device_key_algorithm: None,
            authorized_by: DeviceOrPrincipalRef::Did(Did::new("did:web:alice.example").unwrap()),
            scopes: None,
            not_before: "2026-05-30T00:00:00Z".parse().unwrap(),
            expires_at: None,
            device_signature: None,
            proof: None,
            cross_signing_binding: None,
            bootstrap_binding: None,
            enrollment_authority_binding: None,
            recovery_session_id: None,
        }
    }

    fn cross_signing_binding() -> DeviceCrossSigningBinding {
        DeviceCrossSigningBinding {
            verification_method: json!("did:web:alice.example#ssk"),
            alg: "EdDSA".to_owned(),
            ssk_generation: 1,
            signature: "c2ln".to_owned(),
        }
    }

    #[test]
    fn device_authorize_requires_exactly_one_authorization_binding() {
        let mut payload = base_device_authorize_payload();
        assert_eq!(
            payload.validate_authorization_binding_one_of(),
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );

        payload.cross_signing_binding = Some(cross_signing_binding());
        assert!(payload.validate_authorization_binding_one_of().is_ok());

        payload.bootstrap_binding = Some(DeviceBootstrapBinding {
            kind: "inception_key".to_owned(),
            did_method_evidence_ref: "did:web:alice.example#inception".to_owned(),
        });
        assert_eq!(
            payload.validate_authorization_binding_one_of(),
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );

        payload.cross_signing_binding = None;
        assert!(payload.validate_authorization_binding_one_of().is_ok());
    }
}
