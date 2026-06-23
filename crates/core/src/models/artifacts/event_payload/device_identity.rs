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

    /// Validate the provenance anchor for a `service_attested`
    /// `ck.device.authorize` payload.
    ///
    /// The payload binding is not authority by itself: the accepted Event
    /// envelope must name the same service DID as `executed_by`, carry the same
    /// `authorization_ref`, and point at the DID-document delegation used for
    /// the enrollment authority signature.
    pub fn validate_service_attested_provenance(
        &self,
        executed_by: Option<&Did>,
        authorization_ref: Option<&str>,
        accepted_at: DateTime<Utc>,
    ) -> Result<()> {
        self.validate_authorization_binding_one_of()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let binding = self.enrollment_authority_binding.as_ref().ok_or_else(|| {
            Error::Protocol(
                "service_attested device authorize requires enrollment_authority_binding"
                    .to_owned(),
            )
        })?;
        binding.validate_against_event_anchor(executed_by, authorization_ref, accepted_at)
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
#[derive(Clone, Debug, Serialize)]
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

impl<'de> Deserialize<'de> for DeviceEnrollmentAuthorityBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            authority_did: Did,
            #[serde(
                default,
                alias = "version_time",
                alias = "versionTime",
                rename = "authority_version_time"
            )]
            _authority_version_time: Option<DateTime<Utc>>,
            authorization_ref: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            kind: wire.kind,
            authority_did: wire.authority_did,
            authorization_ref: wire.authorization_ref,
        })
    }
}

impl DeviceEnrollmentAuthorityBinding {
    pub const KIND_SERVICE_ATTESTED: &'static str = "service_attested";

    pub fn validate_against_event_anchor(
        &self,
        executed_by: Option<&Did>,
        authorization_ref: Option<&str>,
        _accepted_at: DateTime<Utc>,
    ) -> Result<()> {
        if self.kind != Self::KIND_SERVICE_ATTESTED {
            return Err(Error::Protocol(
                "device enrollment authority binding kind must be service_attested".to_owned(),
            ));
        }
        match executed_by {
            Some(did) if did == &self.authority_did => {}
            Some(_) => {
                return Err(Error::Protocol(
                    "service_attested executed_by does not match authority_did".to_owned(),
                ));
            }
            None => {
                return Err(Error::Protocol(
                    "service_attested device authorize requires executed_by".to_owned(),
                ));
            }
        }
        match authorization_ref {
            Some(value) if value == self.authorization_ref => {}
            Some(_) => {
                return Err(Error::Protocol(
                    "service_attested authorization_ref mismatch".to_owned(),
                ));
            }
            None => {
                return Err(Error::Protocol(
                    "service_attested device authorize requires authorization_ref".to_owned(),
                ));
            }
        }
        Ok(())
    }
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
    DeviceId(DeviceId),
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
    pub pair_key: String,
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

    #[test]
    fn device_authorize_accepts_service_attested_did_key_authority() {
        let payload = json!({
            "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
            "device_id": "ck:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
            "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
            "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
            "not_before": "2026-06-22T14:45:51Z",
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
                "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
            }
        });
        let payload: DeviceAuthorizePayload = serde_json::from_value(payload).unwrap();
        assert!(payload.validate_authorization_binding_one_of().is_ok());
        assert!(
            payload
                .validate_service_attested_provenance(
                    Some(&Did::new(
                        "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw".to_owned()
                    )
                    .unwrap()),
                    Some("did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"),
                    "2026-06-22T14:45:52Z".parse().unwrap(),
                )
                .is_ok()
        );
    }

    #[test]
    fn service_attested_accepts_optional_version_time_alias() {
        let binding: DeviceEnrollmentAuthorityBinding = serde_json::from_value(json!({
            "kind": "service_attested",
            "authority_did": "did:web:authority.example",
            "versionTime": "2026-06-22T14:45:51Z",
            "authorization_ref": "did:web:alice.example#enrollment-authority"
        }))
        .unwrap();
        assert_eq!(
            binding.authorization_ref,
            "did:web:alice.example#enrollment-authority"
        );
    }

    #[test]
    fn device_or_principal_ref_rejects_unknown_string() {
        assert!(
            serde_json::from_value::<DeviceOrPrincipalRef>(json!("neither-a-device-id-nor-a-did"))
                .is_err()
        );
    }

    #[test]
    fn device_or_principal_ref_accepts_device_id_and_did_key() {
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "ck:device:01904100-0000-7000-8000-000000000001"
        ))
        .unwrap();
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw"
        ))
        .unwrap();
    }
}
