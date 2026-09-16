//! SessionGrant issuance and rotation branches that carry no accepted-device
//! possession proof (`service-operation-dtos.schema.json`).
//!
//! `ak.gate.account.command.issue_session_grant` admits a closed
//! `HumanSessionGrantRequest | RecoverySessionGrantRequest |
//! AgentSessionGrantRequest` union, and its rotation admits a closed
//! `HumanSessionGrantRefreshRequest | AgentSessionGrantRefreshRequest` union.
//! The human branches live in [`crate::session_grants`]; this module owns the
//! fresh-device recovery issuance branch and the Agent runtime-key rotation
//! branch, which revalidates current runtime-key authorization through its own
//! validator instead of a device possession proof.

use arkret_models_identity::SessionGrantCredentialClass;
use arkret_wire::{
    Base64UrlString, DeviceId, DidCoreId, DidUrl, Hash, RequestId, Result, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical intent label shared by every SessionGrant rotation digest.
pub const AGENT_SESSION_REFRESH_OPERATION: &str = "refresh_session_grant";

/// Longest validity window an Agent runtime-key refresh proof may claim.
pub const AGENT_SESSION_REFRESH_PROOF_MAX_LIFETIME_SECONDS: i64 = 300;

/// Fresh-device existing-principal recovery issuance.
///
/// Authorization is the Bound AccountHandoff plus a matching per-request DPoP
/// proof. The Account Authority binds this request to its account/principal
/// mapping and does not consume the handoff on success, so the candidate
/// device is deliberately not required to hold an accepted-device
/// authorization yet.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/RecoverySessionGrantRequest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySessionGrantRequest {
    pub credential_class: SessionGrantCredentialClass,
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience_id: DidCoreId,
}

impl RecoverySessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        if self.credential_class != SessionGrantCredentialClass::RecoverySession {
            return Err(WireError::Protocol(
                "recovery session grant request requires credential_class=recovery_session"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// DPoP-bound Agent SessionGrant rotation.
///
/// The predecessor is presented as `Authorization: DPoP` plus a matching DPoP
/// proof; this body carries no client-generated challenge and no polymorphic
/// proof kind.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/AgentSessionGrantRefreshRequest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionGrantRefreshRequest {
    /// Near-expiry Agent DPoP-bound SessionGrant.
    pub grant_jwt: String,
    /// When present, it must equal the predecessor grant audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_id: Option<DidCoreId>,
    pub device_id: DeviceId,
    pub agent_session_refresh_proof: AgentSessionRefreshProof,
}

impl AgentSessionGrantRefreshRequest {
    pub fn validate(&self) -> Result<()> {
        if self.grant_jwt.trim().is_empty() {
            return Err(WireError::Protocol(
                "agent session refresh grant_jwt must not be empty".to_owned(),
            ));
        }
        self.agent_session_refresh_proof.validate()?;
        if self
            .audience_id
            .as_ref()
            .is_some_and(|audience_id| audience_id != &self.agent_session_refresh_proof.audience_id)
        {
            return Err(WireError::Protocol(
                "agent session refresh proof audience_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Const-valued context of [`AgentSessionRefreshProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSessionRefreshProofContext {
    #[serde(rename = "ak.agent_session_refresh_proof.v1")]
    V1,
}

/// Current Agent runtime-key proof for SessionGrant rotation.
// Field declaration order is byte-for-byte the properties order of
// service-operation-dtos.schema.json#/$defs/AgentSessionRefreshProof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionRefreshProof {
    pub context: AgentSessionRefreshProofContext,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    /// Must be after `issued_at` and no more than
    /// [`AGENT_SESSION_REFRESH_PROOF_MAX_LIFETIME_SECONDS`] later.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: Base64UrlString,
}

impl AgentSessionRefreshProof {
    pub fn validate(&self) -> Result<()> {
        validate_agent_session_refresh_window(self.issued_at, self.expires_at)?;
        let signature_bytes = arkret_wire::base64url::base64url_decode(self.signature.as_str())
            .map_err(|_| {
                WireError::Protocol("agent refresh proof signature is invalid".to_owned())
            })?;
        if signature_bytes.len() != 64 {
            return Err(WireError::Protocol(
                "agent refresh proof signature must encode 64 Ed25519 bytes".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = canonical::unsigned_value(self, &["signature"])?;
        canonical::canonical_json_bytes(&value).map_err(Into::into)
    }
}

/// The same proof before its Ed25519 signature is attached.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UnsignedAgentSessionRefreshProof {
    pub context: AgentSessionRefreshProofContext,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedAgentSessionRefreshProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        validate_agent_session_refresh_window(self.issued_at, self.expires_at)?;
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn attach_signature(self, signature: Base64UrlString) -> Result<AgentSessionRefreshProof> {
        self.canonical_signing_bytes()?;
        let proof = AgentSessionRefreshProof {
            context: self.context,
            request_canonical_digest: self.request_canonical_digest,
            audience_id: self.audience_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_method: self.verification_method,
            signature,
        };
        proof.validate()?;
        Ok(proof)
    }
}

fn validate_agent_session_refresh_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    if expires_at <= issued_at
        || (expires_at - issued_at).num_seconds() > AGENT_SESSION_REFRESH_PROOF_MAX_LIFETIME_SECONDS
    {
        return Err(WireError::Protocol(format!(
            "agent refresh proof validity window must be positive and at most {AGENT_SESSION_REFRESH_PROOF_MAX_LIFETIME_SECONDS} seconds"
        )));
    }
    Ok(())
}

#[derive(Serialize)]
struct AgentSessionRefreshRequestDigestInput<'a> {
    operation: &'static str,
    grant_jwt_digest: String,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    audience_id: &'a DidCoreId,
    verification_method: &'a DidUrl,
}

/// Stable canonical intent an Agent runtime key signs when it rotates a grant.
///
/// The predecessor JWT is hashed rather than carried, so the digest never
/// re-exposes the credential it replaces.
pub fn agent_session_refresh_request_digest(
    grant_jwt: &str,
    principal_id: &DidCoreId,
    device_id: &DeviceId,
    audience_id: &DidCoreId,
    verification_method: &DidUrl,
) -> Result<Hash> {
    Ok(Hash::new(canonical::canonical_sha256(
        &AgentSessionRefreshRequestDigestInput {
            operation: AGENT_SESSION_REFRESH_OPERATION,
            grant_jwt_digest: canonical::sha256_digest(grant_jwt.as_bytes()),
            principal_id,
            device_id,
            audience_id,
            verification_method,
        },
    )?)?)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const REQUEST: &str = "ak:request:01970000-0000-7000-8000-000000000021";
    const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const PRINCIPAL: &str = "ak:did_core:web:alice.example";
    const AUDIENCE: &str = "ak:did_core:web:station.example";
    const VERIFICATION_METHOD: &str = "did:web:agent.example#key-1";

    fn signature() -> String {
        "A".repeat(86)
    }

    fn refresh_proof_value() -> Value {
        json!({
            "context": "ak.agent_session_refresh_proof.v1",
            "request_canonical_digest": format!("sha256:{}", "1".repeat(64)),
            "audience_id": AUDIENCE,
            "issued_at": "2026-08-15T00:00:00.000Z",
            "expires_at": "2026-08-15T00:04:00.000Z",
            "verification_method": VERIFICATION_METHOD,
            "signature": signature()
        })
    }

    fn agent_refresh_value() -> Value {
        json!({
            "grant_jwt": "header.body.signature",
            "audience_id": AUDIENCE,
            "device_id": DEVICE,
            "agent_session_refresh_proof": refresh_proof_value()
        })
    }

    fn recovery_value() -> Value {
        json!({
            "credential_class": "recovery_session",
            "request_id": REQUEST,
            "principal_id": PRINCIPAL,
            "device_id": DEVICE,
            "audience_id": AUDIENCE
        })
    }

    fn assert_rejects_each_omitted_required_member<T>(value: Value, required: &[&str])
    where
        T: for<'de> Deserialize<'de>,
    {
        for member in required {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(*member);
            assert!(
                serde_json::from_value::<T>(missing).is_err(),
                "{member} must be required"
            );
        }
    }

    fn assert_rejects_unknown_member<T>(value: Value)
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut unknown = value;
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unregistered_member".to_owned(), json!(1));
        assert!(serde_json::from_value::<T>(unknown).is_err());
    }

    #[test]
    fn recovery_request_round_trips_and_is_closed() {
        let decoded: RecoverySessionGrantRequest =
            serde_json::from_value(recovery_value()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), recovery_value());
        decoded.validate().unwrap();

        assert_rejects_unknown_member::<RecoverySessionGrantRequest>(recovery_value());
        assert_rejects_each_omitted_required_member::<RecoverySessionGrantRequest>(
            recovery_value(),
            &[
                "credential_class",
                "request_id",
                "principal_id",
                "device_id",
                "audience_id",
            ],
        );
    }

    #[test]
    fn recovery_request_pins_its_credential_class() {
        let mut standard = recovery_value();
        standard
            .as_object_mut()
            .unwrap()
            .insert("credential_class".to_owned(), json!("standard"));
        let decoded: RecoverySessionGrantRequest = serde_json::from_value(standard).unwrap();
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn agent_refresh_request_round_trips_and_is_closed() {
        let decoded: AgentSessionGrantRefreshRequest =
            serde_json::from_value(agent_refresh_value()).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            agent_refresh_value()
        );
        decoded.validate().unwrap();

        assert_rejects_unknown_member::<AgentSessionGrantRefreshRequest>(agent_refresh_value());
        assert_rejects_each_omitted_required_member::<AgentSessionGrantRefreshRequest>(
            agent_refresh_value(),
            &["grant_jwt", "device_id", "agent_session_refresh_proof"],
        );
    }

    #[test]
    fn agent_refresh_request_omits_the_optional_audience() {
        let mut without_audience = agent_refresh_value();
        without_audience
            .as_object_mut()
            .unwrap()
            .remove("audience_id");
        let decoded: AgentSessionGrantRefreshRequest =
            serde_json::from_value(without_audience.clone()).unwrap();
        assert!(decoded.audience_id.is_none());
        assert_eq!(serde_json::to_value(&decoded).unwrap(), without_audience);
        decoded.validate().unwrap();
    }

    #[test]
    fn agent_refresh_request_binds_the_audience_to_its_proof() {
        let mut mismatched = agent_refresh_value();
        mismatched
            .as_object_mut()
            .unwrap()
            .insert("audience_id".to_owned(), json!(PRINCIPAL));
        let decoded: AgentSessionGrantRefreshRequest = serde_json::from_value(mismatched).unwrap();
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn refresh_proof_round_trips_and_is_closed() {
        let decoded: AgentSessionRefreshProof =
            serde_json::from_value(refresh_proof_value()).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            refresh_proof_value()
        );
        decoded.validate().unwrap();

        assert_rejects_unknown_member::<AgentSessionRefreshProof>(refresh_proof_value());
        assert_rejects_each_omitted_required_member::<AgentSessionRefreshProof>(
            refresh_proof_value(),
            &[
                "context",
                "request_canonical_digest",
                "audience_id",
                "issued_at",
                "expires_at",
                "verification_method",
                "signature",
            ],
        );
    }

    #[test]
    fn refresh_proof_bounds_its_validity_window() {
        let mut too_long = refresh_proof_value();
        too_long
            .as_object_mut()
            .unwrap()
            .insert("expires_at".to_owned(), json!("2026-08-15T00:06:00.000Z"));
        let decoded: AgentSessionRefreshProof = serde_json::from_value(too_long).unwrap();
        assert!(decoded.validate().is_err());

        let mut inverted = refresh_proof_value();
        inverted
            .as_object_mut()
            .unwrap()
            .insert("expires_at".to_owned(), json!("2026-08-14T23:59:00.000Z"));
        let decoded: AgentSessionRefreshProof = serde_json::from_value(inverted).unwrap();
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn refresh_proof_context_is_closed() {
        let mut other_context = refresh_proof_value();
        other_context
            .as_object_mut()
            .unwrap()
            .insert("context".to_owned(), json!("ak.agent_session_proof.v1"));
        assert!(serde_json::from_value::<AgentSessionRefreshProof>(other_context).is_err());
    }

    #[test]
    fn unsigned_proof_signs_over_every_member_but_the_signature() {
        let unsigned = UnsignedAgentSessionRefreshProof {
            context: AgentSessionRefreshProofContext::V1,
            request_canonical_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            audience_id: DidCoreId::new(AUDIENCE).unwrap(),
            issued_at: "2026-08-15T00:00:00Z".parse().unwrap(),
            expires_at: "2026-08-15T00:04:00Z".parse().unwrap(),
            verification_method: DidUrl::new(VERIFICATION_METHOD).unwrap(),
        };
        let signing_bytes = unsigned.canonical_signing_bytes().unwrap();
        let proof = unsigned
            .attach_signature(Base64UrlString::new(signature()).unwrap())
            .unwrap();
        assert_eq!(proof.canonical_signing_bytes().unwrap(), signing_bytes);
        assert_eq!(serde_json::to_value(&proof).unwrap(), refresh_proof_value());
    }

    #[test]
    fn refresh_request_digest_hashes_the_predecessor_grant() {
        let principal_id = DidCoreId::new(PRINCIPAL).unwrap();
        let device_id = DeviceId::new(DEVICE).unwrap();
        let audience_id = DidCoreId::new(AUDIENCE).unwrap();
        let verification_method = DidUrl::new(VERIFICATION_METHOD).unwrap();
        let first = agent_session_refresh_request_digest(
            "header.body.signature",
            &principal_id,
            &device_id,
            &audience_id,
            &verification_method,
        )
        .unwrap();
        let second = agent_session_refresh_request_digest(
            "header.body.other",
            &principal_id,
            &device_id,
            &audience_id,
            &verification_method,
        )
        .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            first,
            agent_session_refresh_request_digest(
                "header.body.signature",
                &principal_id,
                &device_id,
                &audience_id,
                &verification_method,
            )
            .unwrap()
        );
    }
}
