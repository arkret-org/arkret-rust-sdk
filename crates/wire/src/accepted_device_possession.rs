//! Accepted-device possession proofs shared by session issue/refresh and the
//! origin device-authorization gate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlString, DeviceId, DidCoreId, DidUrl, Hash, RequestId, Result, SessionGrantId,
    WireError, canonical,
};

pub const ACCEPTED_DEVICE_POSSESSION_PROOF_CONTEXT: &str =
    "ak.session-grant-accepted-device-possession-proof-v1";
pub const MAX_ACCEPTED_DEVICE_POSSESSION_PROOF_LIFETIME_SECONDS: i64 = 300;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptedDevicePossessionProofContext {
    #[serde(rename = "ak.session-grant-accepted-device-possession-proof-v1")]
    V1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptedDeviceIssuePossessionPurpose {
    #[serde(rename = "session_grant_issue")]
    SessionGrantIssue,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptedDeviceRefreshPossessionPurpose {
    #[serde(rename = "session_grant_refresh")]
    SessionGrantRefresh,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedDeviceIssuePossessionProof {
    pub context: AcceptedDevicePossessionProofContext,
    pub purpose: AcceptedDeviceIssuePossessionPurpose,
    pub request_id: RequestId,
    pub account_subject: Hash,
    pub account_handoff_grant_digest: Hash,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: Base64UrlString,
}

impl AcceptedDeviceIssuePossessionProof {
    pub fn validate(&self) -> Result<()> {
        AcceptedDevicePossessionProof::Issue(self.clone()).validate()
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        AcceptedDevicePossessionProof::Issue(self.clone()).canonical_signing_bytes()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UnsignedAcceptedDeviceIssuePossessionProof {
    pub context: AcceptedDevicePossessionProofContext,
    pub purpose: AcceptedDeviceIssuePossessionPurpose,
    pub request_id: RequestId,
    pub account_subject: Hash,
    pub account_handoff_grant_digest: Hash,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedAcceptedDeviceIssuePossessionProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        validate_unsigned_common(&self.holder_jkt, self.issued_at, self.expires_at)?;
        accepted_device_possession_signing_bytes(self)
    }

    pub fn attach_signature(
        self,
        signature: Base64UrlString,
    ) -> Result<AcceptedDeviceIssuePossessionProof> {
        let proof = AcceptedDeviceIssuePossessionProof {
            context: self.context,
            purpose: self.purpose,
            request_id: self.request_id,
            account_subject: self.account_subject,
            account_handoff_grant_digest: self.account_handoff_grant_digest,
            principal_id: self.principal_id,
            device_id: self.device_id,
            audience: self.audience,
            holder_jkt: self.holder_jkt,
            session_intent_digest: self.session_intent_digest,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_method: self.verification_method,
            signature,
        };
        proof.validate()?;
        Ok(proof)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedDeviceRefreshPossessionProof {
    pub context: AcceptedDevicePossessionProofContext,
    pub purpose: AcceptedDeviceRefreshPossessionPurpose,
    pub predecessor_session_grant_id: SessionGrantId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: Base64UrlString,
}

impl AcceptedDeviceRefreshPossessionProof {
    pub fn validate(&self) -> Result<()> {
        AcceptedDevicePossessionProof::Refresh(self.clone()).validate()
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        AcceptedDevicePossessionProof::Refresh(self.clone()).canonical_signing_bytes()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UnsignedAcceptedDeviceRefreshPossessionProof {
    pub context: AcceptedDevicePossessionProofContext,
    pub purpose: AcceptedDeviceRefreshPossessionPurpose,
    pub predecessor_session_grant_id: SessionGrantId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub audience: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedAcceptedDeviceRefreshPossessionProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        validate_unsigned_common(&self.holder_jkt, self.issued_at, self.expires_at)?;
        accepted_device_possession_signing_bytes(self)
    }

    pub fn attach_signature(
        self,
        signature: Base64UrlString,
    ) -> Result<AcceptedDeviceRefreshPossessionProof> {
        let proof = AcceptedDeviceRefreshPossessionProof {
            context: self.context,
            purpose: self.purpose,
            predecessor_session_grant_id: self.predecessor_session_grant_id,
            principal_id: self.principal_id,
            device_id: self.device_id,
            audience: self.audience,
            holder_jkt: self.holder_jkt,
            session_intent_digest: self.session_intent_digest,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_method: self.verification_method,
            signature,
        };
        proof.validate()?;
        Ok(proof)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AcceptedDevicePossessionProof {
    Issue(AcceptedDeviceIssuePossessionProof),
    Refresh(AcceptedDeviceRefreshPossessionProof),
}

impl AcceptedDevicePossessionProof {
    pub fn principal_id(&self) -> &DidCoreId {
        match self {
            Self::Issue(proof) => &proof.principal_id,
            Self::Refresh(proof) => &proof.principal_id,
        }
    }

    pub fn device_id(&self) -> &DeviceId {
        match self {
            Self::Issue(proof) => &proof.device_id,
            Self::Refresh(proof) => &proof.device_id,
        }
    }

    pub fn session_intent_digest(&self) -> &Hash {
        match self {
            Self::Issue(proof) => &proof.session_intent_digest,
            Self::Refresh(proof) => &proof.session_intent_digest,
        }
    }

    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::Issue(proof) => &proof.verification_method,
            Self::Refresh(proof) => &proof.verification_method,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Issue(proof) => validate_common(
                &proof.holder_jkt,
                proof.issued_at,
                proof.expires_at,
                &proof.signature,
            ),
            Self::Refresh(proof) => validate_common(
                &proof.holder_jkt,
                proof.issued_at,
                proof.expires_at,
                &proof.signature,
            ),
        }
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("accepted-device proof serializes as an object")
            .remove("signature");
        accepted_device_possession_signing_bytes(&value)
    }

    pub fn proof_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(canonical::canonical_sha256(self)?)?)
    }
}

fn accepted_device_possession_signing_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let canonical_json = canonical::canonical_json_bytes(value)?;
    let mut bytes = Vec::with_capacity(
        ACCEPTED_DEVICE_POSSESSION_PROOF_CONTEXT.len() + 1 + canonical_json.len(),
    );
    bytes.extend_from_slice(ACCEPTED_DEVICE_POSSESSION_PROOF_CONTEXT.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&canonical_json);
    Ok(bytes)
}

fn validate_common(
    holder_jkt: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    signature: &Base64UrlString,
) -> Result<()> {
    validate_unsigned_common(holder_jkt, issued_at, expires_at)?;
    let signature_bytes = crate::base64url::base64url_decode(signature.as_str()).map_err(|_| {
        WireError::Protocol("accepted-device proof signature is invalid".to_owned())
    })?;
    if signature_bytes.len() != 64 {
        return Err(WireError::Protocol(
            "accepted-device proof signature must encode 64 Ed25519 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_unsigned_common(
    holder_jkt: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    if holder_jkt.len() != 43
        || !holder_jkt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WireError::Protocol(
            "accepted-device proof holder_jkt must be a base64url SHA-256 thumbprint".to_owned(),
        ));
    }
    if expires_at <= issued_at
        || (expires_at - issued_at).num_seconds()
            > MAX_ACCEPTED_DEVICE_POSSESSION_PROOF_LIFETIME_SECONDS
    {
        return Err(WireError::Protocol(
            "accepted-device proof validity window must be positive and at most 300 seconds"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedDevicePossessionVerification {
    pub proof_digest: Hash,
    pub verification_method: DidUrl,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + second, 0).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn unsigned_issue() -> UnsignedAcceptedDeviceIssuePossessionProof {
        UnsignedAcceptedDeviceIssuePossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000021").unwrap(),
            account_subject: hash('a'),
            account_handoff_grant_digest: hash('b'),
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            audience: DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            holder_jkt: "A".repeat(43),
            session_intent_digest: hash('c'),
            issued_at: at(0),
            expires_at: at(300),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
        }
    }

    fn signature() -> Base64UrlString {
        Base64UrlString::new(crate::base64url::base64url_encode([7u8; 64])).unwrap()
    }

    #[test]
    fn unsigned_issue_authoring_matches_the_final_proof_transcript() {
        let unsigned = unsigned_issue();
        let signing_bytes = unsigned.canonical_signing_bytes().unwrap();
        let proof = unsigned.attach_signature(signature()).unwrap();

        assert_eq!(signing_bytes, proof.canonical_signing_bytes().unwrap());
        assert!(
            signing_bytes
                .starts_with(format!("{ACCEPTED_DEVICE_POSSESSION_PROOF_CONTEXT}\n").as_bytes())
        );
        proof.validate().unwrap();
    }

    #[test]
    fn unsigned_refresh_authoring_matches_the_final_proof_transcript() {
        let issue = unsigned_issue();
        let unsigned = UnsignedAcceptedDeviceRefreshPossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
            predecessor_session_grant_id: SessionGrantId::new(
                "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            )
            .unwrap(),
            principal_id: issue.principal_id,
            device_id: issue.device_id,
            audience: issue.audience,
            holder_jkt: issue.holder_jkt,
            session_intent_digest: issue.session_intent_digest,
            issued_at: issue.issued_at,
            expires_at: issue.expires_at,
            verification_method: issue.verification_method,
        };
        let signing_bytes = unsigned.canonical_signing_bytes().unwrap();
        let proof = unsigned.attach_signature(signature()).unwrap();

        assert_eq!(signing_bytes, proof.canonical_signing_bytes().unwrap());
        proof.validate().unwrap();
    }

    #[test]
    fn unsigned_authoring_rejects_an_invalid_transcript_before_signing() {
        let mut unsigned = unsigned_issue();
        unsigned.expires_at = unsigned.issued_at;
        assert!(unsigned.canonical_signing_bytes().is_err());
    }
}
