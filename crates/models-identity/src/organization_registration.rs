use std::collections::BTreeSet;

use arkret_wire::{Did, Error, Hash, Proof, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const ORGANIZATION_REGISTRATION_PREPARE_PATH: &str =
    "/_arkret/root/identity/organization-registrations:prepare";
pub const ORGANIZATION_REGISTRATION_ENSURE_PATH: &str =
    "/_arkret/root/identity/organization-registrations:ensure";
pub const ORGANIZATION_REGISTRATION_GET_PATH: &str =
    "/_arkret/root/identity/organization-registrations";
pub const ORGANIZATION_REGISTRATION_REFRESH_PATH: &str =
    "/_arkret/root/identity/organization-registrations:refresh";
pub const ORGANIZATION_REGISTRATION_REVOKE_PATH: &str =
    "/_arkret/root/identity/organization-registrations:revoke";
pub const ORGANIZATION_REGISTRATION_CONTROL_PURPOSE: &str =
    "ak.organization-registration-control-proof-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRegistrationScope {
    OrganizationProfileManage,
    OrganizationRealmEndorse,
    OrganizationServiceDelegate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrganizationControlProofKind {
    ResolvedVerificationMethod,
    GovernanceQuorum,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationControlProof {
    pub proof_kind: OrganizationControlProofKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_threshold: Option<u64>,
    pub proofs: Vec<Proof>,
}

impl OrganizationControlProof {
    pub fn validate(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "organization control proof requires at least one proof".to_owned(),
            ));
        }
        let unique_methods = self
            .proofs
            .iter()
            .map(|proof| proof.verification_method.as_str())
            .collect::<BTreeSet<_>>();
        if unique_methods.len() != self.proofs.len() {
            return Err(Error::Protocol(
                "organization control proofs must use distinct verification methods".to_owned(),
            ));
        }
        match (self.proof_kind, self.quorum_threshold) {
            (OrganizationControlProofKind::ResolvedVerificationMethod, None)
                if self.proofs.len() == 1 =>
            {
                Ok(())
            }
            (OrganizationControlProofKind::ResolvedVerificationMethod, None) => Err(
                Error::Protocol("resolved control proof must contain exactly one proof".to_owned()),
            ),
            (OrganizationControlProofKind::GovernanceQuorum, Some(threshold))
                if threshold >= 2 && unique_methods.len() >= threshold as usize =>
            {
                Ok(())
            }
            (OrganizationControlProofKind::GovernanceQuorum, Some(_)) => Err(Error::Protocol(
                "governance control proof does not meet quorum_threshold".to_owned(),
            )),
            (OrganizationControlProofKind::GovernanceQuorum, None) => Err(Error::Protocol(
                "governance control proof requires quorum_threshold".to_owned(),
            )),
            (OrganizationControlProofKind::ResolvedVerificationMethod, Some(_)) => Err(
                Error::Protocol("resolved control proof forbids quorum_threshold".to_owned()),
            ),
        }
    }
}

fn validate_scopes(scopes: &[OrganizationRegistrationScope]) -> Result<()> {
    if scopes.is_empty() || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len() {
        return Err(Error::Protocol(
            "organization registration scopes must be non-empty and unique".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationChallengeRequestBody {
    pub organization_id: Did,
    pub local_admin_subject: Did,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
}

impl OrganizationRegistrationChallengeRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_scopes(&self.requested_scopes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationChallenge {
    pub challenge_id: String,
    pub organization_id: Did,
    pub purpose: String,
    pub nonce: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: String,
    pub local_admin_subject: Did,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

impl OrganizationRegistrationChallenge {
    pub fn validate_for(
        &self,
        request: &OrganizationRegistrationChallengeRequestBody,
    ) -> Result<()> {
        self.validate_for_at(request, Utc::now())
    }

    /// Validate the challenge and its request bindings at a caller-supplied
    /// instant. This deterministic form is useful for replay-resistant
    /// consumers and tests.
    pub fn validate_for_at(
        &self,
        request: &OrganizationRegistrationChallengeRequestBody,
        now: DateTime<Utc>,
    ) -> Result<()> {
        request.validate()?;
        if self.organization_id != request.organization_id
            || self.local_admin_subject != request.local_admin_subject
            || self.requested_scopes != request.requested_scopes
            || self.purpose != ORGANIZATION_REGISTRATION_CONTROL_PURPOSE
        {
            return Err(Error::Protocol(
                "organization registration challenge binding mismatch".to_owned(),
            ));
        }
        if !self
            .challenge_id
            .strip_prefix("ak:organization-registration-challenge:")
            .is_some_and(is_lower_hex_sha256)
            || self.nonce.len() < 22
            || self.nonce.len() > 128
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || self.trust_domain.is_empty()
        {
            return Err(Error::Protocol(
                "organization registration challenge contains an invalid id or binding".to_owned(),
            ));
        }
        let origin = url::Url::parse(&self.origin)
            .map_err(|_| Error::Protocol("organization challenge origin is invalid".to_owned()))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !self.origin.ends_with('/')
            || self.expires_at <= self.created_at
            || self.expires_at <= now
            || self.expires_at - self.created_at > chrono::Duration::seconds(300)
        {
            return Err(Error::Protocol(
                "organization registration challenge has invalid origin or lifetime".to_owned(),
            ));
        }
        validate_scopes(&self.requested_scopes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrganizationHandleAttestationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationHandleAttestation {
    pub subject: Did,
    pub handle: String,
    pub issuer: Did,
    pub audience: String,
    pub status: OrganizationHandleAttestationStatus,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationEnsureRequestBody {
    pub organization_id: Did,
    pub challenge_id: String,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof: OrganizationControlProof,
    pub local_admin_subject: Did,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_attestation: Option<OrganizationHandleAttestation>,
}

impl OrganizationRegistrationEnsureRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate()?;
        validate_scopes(&self.requested_scopes)?;
        if self.version_id.is_empty()
            || !self
                .challenge_id
                .strip_prefix("ak:organization-registration-challenge:")
                .is_some_and(is_lower_hex_sha256)
        {
            return Err(Error::Protocol(
                "organization registration ensure has an invalid challenge or version".to_owned(),
            ));
        }
        if let Some(attestation) = &self.handle_attestation
            && (attestation.subject != self.organization_id
                || attestation.handle.is_empty()
                || attestation.audience.is_empty())
        {
            return Err(Error::Protocol(
                "organization handle attestation binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationRefreshRequestBody {
    pub organization_id: Did,
    pub challenge_id: String,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof: OrganizationControlProof,
}

impl OrganizationRegistrationRefreshRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate()?;
        if self.version_id.is_empty()
            || !self
                .challenge_id
                .strip_prefix("ak:organization-registration-challenge:")
                .is_some_and(is_lower_hex_sha256)
        {
            return Err(Error::Protocol(
                "organization registration refresh has an invalid challenge or version".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRegistrationRevokeReason {
    OrganizationRegistrationSuperseded,
    OrganizationRegistrationWithdrawn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationRevokeRequestBody {
    pub organization_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<OrganizationRegistrationRevokeReason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRegistrationStatus {
    Active,
    Stale,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationReceipt {
    pub registration_receipt_id: String,
    pub organization_id: Did,
    pub registration_generation: u64,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof_kind: OrganizationControlProofKind,
    pub control_key_digest: Hash,
    pub local_admin_subject: Did,
    pub delegated_scopes: Vec<OrganizationRegistrationScope>,
    pub status: OrganizationRegistrationStatus,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub issuer_service_id: Did,
    pub proof: Proof,
}

impl OrganizationRegistrationReceipt {
    pub fn expected_receipt_id(&self) -> Result<String> {
        let mut claims = serde_json::to_value(self)?;
        let object = claims.as_object_mut().ok_or_else(|| {
            Error::Protocol("organization registration receipt must be an object".to_owned())
        })?;
        object.remove("registration_receipt_id");
        object.remove("proof");
        let digest = arkret_canonical::canonical::canonical_sha256(&claims)?;
        Ok(format!(
            "ak:organization-registration-receipt:{}",
            digest.strip_prefix("sha256:").unwrap_or(&digest)
        ))
    }

    pub fn validate(&self) -> Result<()> {
        validate_scopes(&self.delegated_scopes)?;
        if self.registration_generation == 0
            || self.version_id.is_empty()
            || self.expires_at <= self.issued_at
            || self.registration_receipt_id != self.expected_receipt_id()?
            || self.issuer_service_id.method() != "webvh"
            || !self
                .proof
                .verification_method
                .starts_with(&format!("{}#", self.issuer_service_id))
        {
            return Err(Error::Protocol(
                "organization registration receipt binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationOutcome {
    pub organization_id: Did,
    pub registration_generation: u64,
    pub version_id: String,
    pub registration_receipt: OrganizationRegistrationReceipt,
    pub created: bool,
}

impl OrganizationRegistrationOutcome {
    pub fn validate(&self) -> Result<()> {
        self.registration_receipt.validate()?;
        if self.organization_id != self.registration_receipt.organization_id
            || self.registration_generation != self.registration_receipt.registration_generation
            || self.version_id != self.registration_receipt.version_id
        {
            return Err(Error::Protocol(
                "organization registration outcome and receipt do not match".to_owned(),
            ));
        }
        Ok(())
    }
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).expect("valid DID")
    }

    fn challenge_request() -> OrganizationRegistrationChallengeRequestBody {
        OrganizationRegistrationChallengeRequestBody {
            organization_id: did("did:webvh:zOrg:org.example"),
            local_admin_subject: did("did:webvh:zAdmin:admin.example"),
            requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
        }
    }

    #[test]
    fn challenge_rejects_expiry_and_excessive_lifetime() {
        let request = challenge_request();
        let now = DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let base = OrganizationRegistrationChallenge {
            challenge_id: format!("ak:organization-registration-challenge:{}", "a".repeat(64)),
            organization_id: request.organization_id.clone(),
            purpose: ORGANIZATION_REGISTRATION_CONTROL_PURPOSE.to_owned(),
            nonce: "0123456789abcdefghijkl".to_owned(),
            audience: did("did:webvh:zService:service.example"),
            origin: "https://service.example/".to_owned(),
            trust_domain: "example".to_owned(),
            local_admin_subject: request.local_admin_subject.clone(),
            requested_scopes: request.requested_scopes.clone(),
            created_at: now - chrono::Duration::seconds(60),
            expires_at: now,
        };
        assert!(base.validate_for_at(&request, now).is_err());
        let mut too_long = base;
        too_long.created_at = now;
        too_long.expires_at = now + chrono::Duration::seconds(301);
        assert!(too_long.validate_for_at(&request, now).is_err());
    }

    #[test]
    fn request_rejects_duplicate_scopes_and_unknown_fields() {
        let mut request = challenge_request();
        request
            .requested_scopes
            .push(OrganizationRegistrationScope::OrganizationProfileManage);
        assert!(request.validate().is_err());
        assert!(
            serde_json::from_value::<OrganizationRegistrationChallengeRequestBody>(
                serde_json::json!({
                    "organization_id": "did:webvh:zOrg:org.example",
                    "local_admin_subject": "did:webvh:zAdmin:admin.example",
                    "requested_scopes": ["organization_profile_manage"],
                    "unexpected": true
                })
            )
            .is_err()
        );
    }
}
