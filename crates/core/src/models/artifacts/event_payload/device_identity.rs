//! Device-authorization, cross-signing, and identity-binding payloads.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::*;

pub const DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON: &str = "device_authorize_binding_one_of";

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_authorize_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBootstrapBinding {
    pub kind: DeviceBootstrapBindingKind,
    pub did_method_evidence_ref: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceBootstrapBindingKind {
    InceptionSelfAuthorized,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorizePayload {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub device_public_key: NonEmptyString,
    /// Device HPKE public key used for secret/key envelope sealing. Covered by
    /// `cross_signing_binding` (§5.2) or the enrollment-authority Event proof
    /// (§5.4); services MUST NOT substitute this value in projection.
    pub hpke_key: NonEmptyString,
    /// Canonical sorted (UTF-8 bytewise) unique algorithm ids supported by
    /// this device. Enters the device trust binding transcript together with
    /// `device_public_key` and `hpke_key`.
    pub algorithms: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_algorithm: Option<NonEmptyString>,
    pub authorized_by: DeviceOrPrincipalRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<NonEmptyString>>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAuthorizePayloadWire {
    principal_id: Did,
    device_id: DeviceId,
    device_public_key: NonEmptyString,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    #[serde(default)]
    device_key_algorithm: Option<NonEmptyString>,
    authorized_by: DeviceOrPrincipalRef,
    #[serde(default)]
    scopes: Option<Vec<NonEmptyString>>,
    not_before: DateTime<Utc>,
    #[serde(default)]
    expires_at: Option<NullableTimestamp>,
    #[serde(default)]
    device_signature: Option<SignatureMaterial>,
    #[serde(default)]
    proof: Option<SignatureMaterial>,
    #[serde(default)]
    cross_signing_binding: Option<DeviceCrossSigningBinding>,
    #[serde(default)]
    bootstrap_binding: Option<DeviceBootstrapBinding>,
    #[serde(default)]
    enrollment_authority_binding: Option<DeviceEnrollmentAuthorityBinding>,
    #[serde(default)]
    recovery_session_id: Option<RecoverySessionId>,
}

impl<'de> Deserialize<'de> for DeviceAuthorizePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceAuthorizePayloadWire::deserialize(deserializer)?;
        let payload = Self {
            principal_id: wire.principal_id,
            device_id: wire.device_id,
            device_public_key: wire.device_public_key,
            hpke_key: wire.hpke_key,
            algorithms: wire.algorithms,
            device_key_algorithm: wire.device_key_algorithm,
            authorized_by: wire.authorized_by,
            scopes: wire.scopes,
            not_before: wire.not_before,
            expires_at: wire.expires_at,
            device_signature: wire.device_signature,
            proof: wire.proof,
            cross_signing_binding: wire.cross_signing_binding,
            bootstrap_binding: wire.bootstrap_binding,
            enrollment_authority_binding: wire.enrollment_authority_binding,
            recovery_session_id: wire.recovery_session_id,
        };
        payload
            .validate_wire_constraints()
            .map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl DeviceAuthorizePayload {
    /// Enforce the `device-lifecycle.md` §5.2 canonical-form MUST on
    /// `algorithms`: non-empty, UTF-8 bytewise ascending, no duplicates. The
    /// producer MUST write the same canonical array that enters the
    /// `ak-device-trust-bind-v1` signing input.
    pub fn validate_canonical_algorithms(&self) -> std::result::Result<(), &'static str> {
        if self.algorithms.is_empty() {
            return Err("device_authorize_algorithms_empty");
        }
        if self
            .algorithms
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err("device_authorize_algorithms_not_canonical");
        }
        Ok(())
    }

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

    pub fn validate_wire_constraints(&self) -> std::result::Result<(), &'static str> {
        self.validate_authorization_binding_one_of()?;
        self.validate_canonical_algorithms()?;
        if self.device_signature.is_none()
            && self.proof.is_none()
            && self.enrollment_authority_binding.is_none()
        {
            return Err("device_authorize_signature_or_authority_required");
        }
        if let Some(scopes) = &self.scopes
            && (scopes.is_empty() || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len())
        {
            return Err("device_authorize_scopes_must_be_non_empty_and_unique");
        }
        Ok(())
    }

    /// Canonical signing input for
    /// `ak.device.authorize.payload.device_signature`.
    ///
    /// The signature proves possession of the private key corresponding to
    /// `device_public_key`; it is deliberately separate from the SSK-signed
    /// `cross_signing_binding`.
    pub fn device_possession_signature_input(&self) -> Result<Vec<u8>> {
        self.validate_authorization_binding_one_of()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        self.validate_canonical_algorithms()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let device_key_algorithm = self.device_key_algorithm.as_deref().ok_or_else(|| {
            Error::Protocol("device_authorize_device_key_algorithm_required".to_owned())
        })?;
        if !matches!(device_key_algorithm, "EdDSA" | "Ed25519") {
            return Err(Error::Protocol(
                "device_authorize_device_key_algorithm_unsupported".to_owned(),
            ));
        }
        let (authorization_binding_kind, cross_signing_generation) =
            if let Some(binding) = &self.cross_signing_binding {
                ("cross_signing", Some(binding.ssk_generation))
            } else if self.bootstrap_binding.is_some() {
                ("bootstrap", None)
            } else if self.enrollment_authority_binding.is_some() {
                ("enrollment_authority", None)
            } else {
                return Err(Error::Protocol(
                    DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON.to_owned(),
                ));
            };
        let authorized_by = match &self.authorized_by {
            DeviceOrPrincipalRef::DeviceId(device_id) => device_id.as_str(),
            DeviceOrPrincipalRef::Did(did) => did.as_str(),
        };
        let mut scopes = self.scopes.clone();
        if let Some(scopes) = &mut scopes {
            scopes.sort_unstable();
            scopes.dedup();
        }
        let expires_at = self.expires_at.as_ref().and_then(|value| value.as_ref());
        let recovery_session_id = self.recovery_session_id.as_ref().map(|id| id.as_str());
        let body = serde_json::json!({
            "principal_id": self.principal_id.as_str(),
            "device_id": self.device_id.as_str(),
            "device_public_key": self.device_public_key.as_str(),
            "hpke_key": self.hpke_key.as_str(),
            "algorithms": &self.algorithms,
            "device_key_algorithm": device_key_algorithm,
            "authorized_by": authorized_by,
            "not_before": self.not_before,
            "expires_at": expires_at,
            "scopes": scopes,
            "recovery_session_id": recovery_session_id,
            "authorization_binding_kind": authorization_binding_kind,
            "cross_signing_generation": cross_signing_generation,
        });
        let mut out = binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX.to_vec();
        out.extend_from_slice(&canonical::canonical_json_bytes(&body)?);
        Ok(out)
    }

    /// Validate the provenance anchor for a `service_attested`
    /// `ak.device.authorize` payload.
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
/// Delegated-authority binding for a `service_attested` `ak.device.authorize`
/// (managed-DID / account-authority onboarding). The cryptographic signer is the
/// envelope proof (`verification_method` maps to `executed_by`); this object
/// records the trust root. See `zh/crypto-media/device-lifecycle.md` §5.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceEnrollmentAuthorityBinding {
    /// MUST be `"service_attested"`.
    pub kind: DeviceEnrollmentAuthorityBindingKind,
    /// DID of the enrollment authority that attested this device (equals the
    /// envelope `executed_by`); designated by the principal DID document.
    pub authority_did: Did,
    /// Reference to the delegation designating `authority_did` (DID-document
    /// service delegation, materialized grant, or delegation event id); equals
    /// the envelope `authorization_ref`.
    pub authorization_ref: NonEmptyString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceEnrollmentAuthorityBindingKind {
    ServiceAttested,
}

impl DeviceEnrollmentAuthorityBinding {
    pub fn validate_against_event_anchor(
        &self,
        executed_by: Option<&Did>,
        authorization_ref: Option<&str>,
        _accepted_at: DateTime<Utc>,
    ) -> Result<()> {
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
            Some(value) if value == self.authorization_ref.as_str() => {}
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
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub ssk_generation: NonZeroU64,
    pub signature: Base64UrlString,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListUpdatePayload {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<Vec<DeviceId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_list_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceListUpdatePayloadWire {
    principal_id: Did,
    #[serde(default)]
    changed: Option<Vec<DeviceId>>,
    #[serde(default)]
    left: Option<Vec<DeviceId>>,
    #[serde(default)]
    device_list_digest: Option<Hash>,
    #[serde(default)]
    stream_id: Option<NonEmptyString>,
    #[serde(default)]
    updated_at: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for DeviceListUpdatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DeviceListUpdatePayloadWire::deserialize(deserializer)?;
        if wire.changed.is_none() && wire.left.is_none() && wire.device_list_digest.is_none() {
            return Err(serde::de::Error::custom(
                "device list update requires changed, left, or device_list_digest",
            ));
        }
        for (name, devices) in [("changed", &wire.changed), ("left", &wire.left)] {
            if let Some(devices) = devices
                && (devices.is_empty()
                    || devices.iter().collect::<BTreeSet<_>>().len() != devices.len())
            {
                return Err(serde::de::Error::custom(format!(
                    "device list update {name} must be non-empty and unique"
                )));
            }
        }
        Ok(Self {
            principal_id: wire.principal_id,
            changed: wire.changed,
            left: wire.left,
            device_list_digest: wire.device_list_digest,
            stream_id: wire.stream_id,
            updated_at: wire.updated_at,
        })
    }
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
    pub device_id: DeviceId,
    pub revoked_by: DeviceOrPrincipalRef,
    pub revoked_at: DateTime<Utc>,
    pub reason: DeviceRevocationReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignatureMaterial>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceRevocationReason(String);

impl DeviceRevocationReason {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, &'static str> {
        let value = value.into();
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return Err("device revocation reason must not be empty");
        };
        if value.len() > 64
            || !first.is_ascii_lowercase()
            || !characters.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err("device revocation reason must match ^[a-z][a-z0-9_]{0,63}$");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceRevocationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceRevocationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
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
    pub member_event_refs: ContactEventRefs,
    pub main_strand_create_ref: EventRef,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_binding_ref: Option<EventRef>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn device_authorize_value() -> serde_json::Value {
        json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "device_public_key": "z6MkDeviceKey",
            "hpke_key": "z6LSHpkeKey",
            "algorithms": [
                "ak.hpke_x25519_aead_chacha20poly1305.v1",
                "ak.mls.v1"
            ],
            "device_signature": "c2ln",
            "authorized_by": "did:webvh:z6mkfixture:alice.example",
            "not_before": "2026-05-30T00:00:00Z",
            "bootstrap_binding": {
                "kind": "inception_self_authorized",
                "did_method_evidence_ref": "did:webvh:z6mkfixture:alice.example#inception"
            }
        })
    }

    fn base_device_authorize_payload() -> DeviceAuthorizePayload {
        DeviceAuthorizePayload {
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001").unwrap(),
            device_public_key: NonEmptyString::new("z6MkDeviceKey").unwrap(),
            hpke_key: NonEmptyString::new("z6LSHpkeKey").unwrap(),
            algorithms: vec![
                NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
                NonEmptyString::new("ak.mls.v1").unwrap(),
            ],
            device_key_algorithm: None,
            authorized_by: DeviceOrPrincipalRef::Did(
                Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            ),
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
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#ssk").unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            ssk_generation: NonZeroU64::new(1).unwrap(),
            signature: Base64UrlString::new("c2ln").unwrap(),
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
            kind: DeviceBootstrapBindingKind::InceptionSelfAuthorized,
            did_method_evidence_ref: NonEmptyString::new(
                "did:webvh:z6mkfixture:alice.example#inception",
            )
            .unwrap(),
        });
        assert_eq!(
            payload.validate_authorization_binding_one_of(),
            Err(DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );

        payload.cross_signing_binding = None;
        assert!(payload.validate_authorization_binding_one_of().is_ok());
    }

    #[test]
    fn device_authorize_possession_input_binds_device_and_recovery_context() {
        let mut payload = base_device_authorize_payload();
        payload.device_key_algorithm = Some(NonEmptyString::new("EdDSA").unwrap());
        payload.cross_signing_binding = Some(cross_signing_binding());
        payload.scopes = Some(vec![
            NonEmptyString::new("write").unwrap(),
            NonEmptyString::new("read").unwrap(),
            NonEmptyString::new("read").unwrap(),
        ]);
        payload.recovery_session_id = Some(
            RecoverySessionId::new("ak:recovery_session:01904100-0000-7000-8000-000000000042")
                .unwrap(),
        );

        let input = String::from_utf8(payload.device_possession_signature_input().unwrap())
            .expect("canonical input is utf8");

        assert!(
            input
                .as_bytes()
                .starts_with(binding_contexts::DEVICE_AUTHORIZE_POSSESSION_PREFIX)
        );
        assert!(input.contains("\"authorization_binding_kind\":\"cross_signing\""));
        assert!(input.contains("\"cross_signing_generation\":1"));
        assert!(input.contains(
            "\"recovery_session_id\":\"ak:recovery_session:01904100-0000-7000-8000-000000000042\""
        ));
        assert!(input.contains("\"scopes\":[\"read\",\"write\"]"));
    }

    #[test]
    fn device_authorize_possession_input_requires_declared_device_alg() {
        let mut payload = base_device_authorize_payload();
        payload.cross_signing_binding = Some(cross_signing_binding());

        assert!(matches!(
            payload.device_possession_signature_input(),
            Err(Error::Protocol(reason))
                if reason == "device_authorize_device_key_algorithm_required"
        ));
    }

    #[test]
    fn device_authorize_deserialization_enforces_conditionals_and_canonical_lists() {
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(device_authorize_value()).is_ok());

        let mut missing_proof = device_authorize_value();
        missing_proof
            .as_object_mut()
            .unwrap()
            .remove("device_signature");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(missing_proof).is_err());

        let mut conflicting_binding = device_authorize_value();
        conflicting_binding["enrollment_authority_binding"] = json!({
            "kind": "service_attested",
            "authority_did": "did:webvh:z6mkfixture:authority.example",
            "authorization_ref": "did:webvh:z6mkfixture:alice.example#enrollment-authority"
        });
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(conflicting_binding).is_err());

        let mut unsorted_algorithms = device_authorize_value();
        unsorted_algorithms["algorithms"] = json!(["ak.mls.v1", "ak.hpke.v1"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(unsorted_algorithms).is_err());

        let mut duplicate_scopes = device_authorize_value();
        duplicate_scopes["scopes"] = json!(["read", "read"]);
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(duplicate_scopes).is_err());
    }

    #[test]
    fn device_authorize_rejects_wrong_consts_and_scalar_shapes() {
        let mut wrong_bootstrap_kind = device_authorize_value();
        wrong_bootstrap_kind["bootstrap_binding"]["kind"] = json!("inception_key");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(wrong_bootstrap_kind).is_err());

        let mut empty_key = device_authorize_value();
        empty_key["device_public_key"] = json!("");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(empty_key).is_err());

        let mut invalid_device = device_authorize_value();
        invalid_device["device_id"] = json!("device-1");
        assert!(serde_json::from_value::<DeviceAuthorizePayload>(invalid_device).is_err());
    }

    #[test]
    fn device_authorize_accepts_service_attested_did_key_authority() {
        let payload = json!({
            "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
            "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
            "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
            "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
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
    fn service_attested_rejects_legacy_version_time_alias() {
        let binding = serde_json::from_value::<DeviceEnrollmentAuthorityBinding>(json!({
            "kind": "service_attested",
            "authority_did": "did:webvh:z6mkfixture:authority.example",
            "versionTime": "2026-06-22T14:45:51Z",
            "authorization_ref": "did:webvh:z6mkfixture:alice.example#enrollment-authority"
        }));
        assert!(binding.is_err());
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
            "ak:device:01904100-0000-7000-8000-000000000001"
        ))
        .unwrap();
        serde_json::from_value::<DeviceOrPrincipalRef>(json!(
            "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw"
        ))
        .unwrap();
    }

    #[test]
    fn device_list_update_enforces_any_of_and_set_constraints() {
        let principal_id = "did:webvh:z6mkfixture:alice.example";
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "changed": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "left": [
                    "ak:device:01904100-0000-7000-8000-000000000001",
                    "ak:device:01904100-0000-7000-8000-000000000001"
                ]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DeviceListUpdatePayload>(json!({
                "principal_id": principal_id,
                "device_list_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }))
            .is_ok()
        );
    }

    #[test]
    fn device_revocation_reason_enforces_schema_slug() {
        assert!(DeviceRevocationReason::new("device_lost").is_ok());
        assert!(DeviceRevocationReason::new("").is_err());
        assert!(DeviceRevocationReason::new("DeviceLost").is_err());
        assert!(DeviceRevocationReason::new("device-lost").is_err());
        assert!(DeviceRevocationReason::new(format!("a{}", "b".repeat(64))).is_err());
    }
}
