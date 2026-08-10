use std::collections::BTreeSet;

use arkret_wire::{
    DidCoreId, DidFullId, Error, Hash, PayloadProof, ProofContextId, Result,
    project_full_id_to_core_id,
};
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
    pub proofs: Vec<PayloadProof>,
}

impl OrganizationControlProof {
    pub fn validate(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "organization control proof requires at least one proof".to_owned(),
            ));
        }
        for proof in &self.proofs {
            proof.validate_production()?;
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

    /// Validate the digest carried by every detached proof against the exact
    /// beneficiary-bound control transcript required by identity-did §8.4.
    ///
    /// Signature verification remains the resolver's responsibility because
    /// it requires the DID document pinned by `version_id` and
    /// `log_head_digest`.
    pub fn validate_transcript_bindings(
        &self,
        challenge_id: &str,
        organization_id: &DidCoreId,
        full_id: &DidFullId,
        local_admin_subject: &DidCoreId,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<()> {
        self.validate()?;
        for proof in &self.proofs {
            let transcript = serde_json::json!({
                "context": ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
                "challenge_id": challenge_id,
                "organization_id": organization_id,
                "full_id": full_id,
                "local_admin_subject": local_admin_subject,
                "version_id": version_id,
                "log_head_digest": log_head_digest,
                "verification_method": proof.verification_method,
                "created_at": proof.created_at,
            });
            let expected = Hash::new(arkret_canonical::canonical::canonical_sha256(&transcript)?)?;
            if proof.payload_digest != expected {
                return Err(Error::Protocol(
                    "organization control proof payload_digest does not match its bound transcript"
                        .to_owned(),
                ));
            }
        }
        Ok(())
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
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub local_admin_subject: DidCoreId,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
}

impl OrganizationRegistrationChallengeRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_scopes(&self.requested_scopes)?;
        if project_full_id_to_core_id(&self.full_id)?.as_str() != self.organization_id.as_str() {
            return Err(Error::Protocol(
                "organization registration full_id does not project to organization_id".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationChallenge {
    pub challenge_id: String,
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub purpose: String,
    pub nonce: String,
    pub audience: DidCoreId,
    pub origin: String,
    pub trust_domain: String,
    pub local_admin_subject: DidCoreId,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
            || self.full_id != request.full_id
            || self.local_admin_subject != request.local_admin_subject
            || self.requested_scopes != request.requested_scopes
            || self.purpose != ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1
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
            || project_full_id_to_core_id(&self.full_id)?.as_str() != self.organization_id.as_str()
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
    pub subject: DidCoreId,
    pub handle: String,
    pub issuer: DidCoreId,
    pub audience: String,
    pub status: OrganizationHandleAttestationStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationEnsureRequestBody {
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub challenge_id: String,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof: OrganizationControlProof,
    pub local_admin_subject: DidCoreId,
    pub requested_scopes: Vec<OrganizationRegistrationScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_attestation: Option<OrganizationHandleAttestation>,
}

impl OrganizationRegistrationEnsureRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate()?;
        validate_scopes(&self.requested_scopes)?;
        if self.version_id.is_empty()
            || project_full_id_to_core_id(&self.full_id)?.as_str() != self.organization_id.as_str()
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

    pub fn validate_for_challenge_at(
        &self,
        challenge: &OrganizationRegistrationChallenge,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        let challenge_request = OrganizationRegistrationChallengeRequestBody {
            organization_id: self.organization_id.clone(),
            full_id: self.full_id.clone(),
            local_admin_subject: self.local_admin_subject.clone(),
            requested_scopes: self.requested_scopes.clone(),
        };
        challenge.validate_for_at(&challenge_request, now)?;
        if self.challenge_id != challenge.challenge_id {
            return Err(Error::Protocol(
                "organization registration ensure challenge_id mismatch".to_owned(),
            ));
        }
        self.control_proof.validate_transcript_bindings(
            &self.challenge_id,
            &self.organization_id,
            &self.full_id,
            &self.local_admin_subject,
            &self.version_id,
            &self.log_head_digest,
        )?;
        if self.control_proof.proofs.iter().any(|proof| {
            proof.created_at < challenge.created_at || proof.created_at >= challenge.expires_at
        }) {
            return Err(Error::Protocol(
                "organization control proof was not created during the challenge lifetime"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            self,
        )?)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct OrganizationRegistrationRefreshRequestBody {
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub challenge_id: String,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof: OrganizationControlProof,
}

impl OrganizationRegistrationRefreshRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate()?;
        if self.version_id.is_empty()
            || project_full_id_to_core_id(&self.full_id)?.as_str() != self.organization_id.as_str()
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

    pub fn validate_for_challenge_at(
        &self,
        challenge: &OrganizationRegistrationChallenge,
        current_local_admin_subject: &DidCoreId,
        current_scopes: &[OrganizationRegistrationScope],
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        let challenge_request = OrganizationRegistrationChallengeRequestBody {
            organization_id: self.organization_id.clone(),
            full_id: self.full_id.clone(),
            local_admin_subject: current_local_admin_subject.clone(),
            requested_scopes: current_scopes.to_vec(),
        };
        challenge.validate_for_at(&challenge_request, now)?;
        if self.challenge_id != challenge.challenge_id {
            return Err(Error::Protocol(
                "organization registration refresh challenge_id mismatch".to_owned(),
            ));
        }
        self.control_proof.validate_transcript_bindings(
            &self.challenge_id,
            &self.organization_id,
            &self.full_id,
            current_local_admin_subject,
            &self.version_id,
            &self.log_head_digest,
        )?;
        if self.control_proof.proofs.iter().any(|proof| {
            proof.created_at < challenge.created_at || proof.created_at >= challenge.expires_at
        }) {
            return Err(Error::Protocol(
                "organization control proof was not created during the challenge lifetime"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            self,
        )?)?)
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
    pub organization_id: DidCoreId,
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
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub registration_generation: u64,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub control_proof_kind: OrganizationControlProofKind,
    pub control_key_digest: Hash,
    pub local_admin_subject: DidCoreId,
    pub delegated_scopes: Vec<OrganizationRegistrationScope>,
    pub status: OrganizationRegistrationStatus,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub issuer_service_id: DidCoreId,
    pub proof: PayloadProof,
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

    pub fn expected_payload_digest(&self) -> Result<Hash> {
        let mut document = serde_json::to_value(self)?;
        let object = document.as_object_mut().ok_or_else(|| {
            Error::Protocol("organization registration receipt must be an object".to_owned())
        })?;
        object.remove("proof");
        Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
            &document,
        )?)?)
    }

    /// Return the exact detached-JWS payload for the receipt proof. Consumers
    /// still need signing-time DID resolution to verify the signature.
    pub fn proof_signing_bytes(&self) -> Result<Vec<u8>> {
        let binding = serde_json::json!({
            "context": ProofContextId::ORGANIZATION_REGISTRATION_RECEIPT_PROOF_V1,
            "payload_digest": self.proof.payload_digest,
            "issuer_service_id": self.issuer_service_id,
            "registration_receipt_id": self.registration_receipt_id,
            "organization_id": self.organization_id,
            "full_id": self.full_id,
            "verification_method": self.proof.verification_method,
            "created_at": self.proof.created_at,
            "domain": self.proof.domain,
            "audience": self.proof.audience,
        });
        let object = binding.as_object().expect("JSON object");
        let mut compact = object.clone();
        if self.proof.domain.is_none() {
            compact.remove("domain");
        }
        if self.proof.audience.is_none() {
            compact.remove("audience");
        }
        Ok(arkret_canonical::canonical::canonical_json_bytes(&compact)?)
    }

    pub fn validate(&self) -> Result<()> {
        validate_scopes(&self.delegated_scopes)?;
        self.proof.validate_production()?;
        if self.registration_generation == 0
            || self.version_id.is_empty()
            || project_full_id_to_core_id(&self.full_id)?.as_str() != self.organization_id.as_str()
            || self.expires_at <= self.issued_at
            || self.registration_receipt_id != self.expected_receipt_id()?
            || self.proof.payload_digest != self.expected_payload_digest()?
            || self.proof.created_at != self.issued_at
            || project_verification_method_to_core(&self.proof.verification_method)?
                != self.issuer_service_id
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
    pub organization_id: DidCoreId,
    pub full_id: DidFullId,
    pub registration_generation: u64,
    pub version_id: String,
    pub registration_receipt: OrganizationRegistrationReceipt,
    pub created: bool,
}

impl OrganizationRegistrationOutcome {
    pub fn validate(&self) -> Result<()> {
        self.registration_receipt.validate()?;
        if self.organization_id != self.registration_receipt.organization_id
            || self.full_id != self.registration_receipt.full_id
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

/// Return the stored outcome only for the one replay shape permitted by the
/// single-use challenge contract: the submitted canonical request digest is
/// byte-identical to the digest committed with the successful outcome.
pub fn organization_registration_replay_outcome(
    successful_request_digest: &Hash,
    submitted_request_digest: &Hash,
    successful_outcome: &OrganizationRegistrationOutcome,
) -> Result<OrganizationRegistrationOutcome> {
    if successful_request_digest != submitted_request_digest {
        return Err(Error::Protocol(
            "organization registration challenge was consumed by a different request".to_owned(),
        ));
    }
    let mut replay = successful_outcome.clone();
    replay.created = false;
    replay.validate()?;
    Ok(replay)
}

/// Enforce the current-generation pointer and lifecycle state before a receipt
/// is used for a high-risk authorization decision.
pub fn validate_organization_registration_authorization_at(
    receipt: &OrganizationRegistrationReceipt,
    current_generation: u64,
    current_status: OrganizationRegistrationStatus,
    now: DateTime<Utc>,
) -> Result<()> {
    receipt.validate()?;
    if receipt.registration_generation != current_generation
        || current_status == OrganizationRegistrationStatus::Revoked
    {
        return Err(Error::Protocol(
            "organization registration receipt is revoked or superseded".to_owned(),
        ));
    }
    if current_status == OrganizationRegistrationStatus::Stale
        || receipt.status != OrganizationRegistrationStatus::Active
        || receipt.expires_at <= now
    {
        return Err(Error::Protocol(
            "organization registration receipt is stale".to_owned(),
        ));
    }
    Ok(())
}

/// Compute the generation for a non-replay ensure transition. Generation zero
/// is never emitted; a revoked or superseded generation remains immutable.
pub fn next_organization_registration_generation(current_generation: Option<u64>) -> Result<u64> {
    match current_generation {
        None => Ok(1),
        Some(0) => Err(Error::Protocol(
            "organization registration generation must start at one".to_owned(),
        )),
        Some(generation) => generation.checked_add(1).ok_or_else(|| {
            Error::Protocol("organization registration generation overflow".to_owned())
        }),
    }
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn project_verification_method_to_core(
    verification_method: &arkret_wire::DidUrl,
) -> Result<DidCoreId> {
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            Error::Protocol(
                "organization receipt verification_method requires a fragment".to_owned(),
            )
        })?;
    project_full_id_to_core_id(&DidFullId::new(controller.to_owned())?).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidUrl;

    use super::*;

    fn full(value: &str) -> DidFullId {
        DidFullId::new(value.to_owned()).expect("valid full DID")
    }

    fn core(value: &str) -> DidCoreId {
        project_full_id_to_core_id(&full(value)).expect("registered method adapter")
    }

    fn service(value: &str) -> DidCoreId {
        project_full_id_to_core_id(&full(value)).expect("registered method adapter")
    }

    fn challenge_request() -> OrganizationRegistrationChallengeRequestBody {
        OrganizationRegistrationChallengeRequestBody {
            organization_id: core("did:webvh:zOrg:org.example"),
            full_id: full("did:webvh:zOrg:org.example"),
            local_admin_subject: core("did:webvh:zAdmin:admin.example"),
            requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
        }
    }

    fn payload_proof(created_at: DateTime<Utc>, verification_method: &DidUrl) -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..fixture".to_owned(),
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
            full_id: request.full_id.clone(),
            purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
            nonce: "0123456789abcdefghijkl".to_owned(),
            audience: service("did:webvh:zService:service.example"),
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
                    "organization_id": "ak:did_core:webvh:zOrg",
                    "full_id": "did:webvh:zOrg:org.example",
                    "local_admin_subject": "ak:did_core:webvh:zAdmin",
                    "requested_scopes": ["organization_profile_manage"],
                    "unexpected": true
                })
            )
            .is_err()
        );
    }

    #[test]
    fn ensure_binds_control_proof_to_challenge_and_beneficiary() {
        let request = challenge_request();
        let created_at = DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let challenge = OrganizationRegistrationChallenge {
            challenge_id: format!("ak:organization-registration-challenge:{}", "a".repeat(64)),
            organization_id: request.organization_id.clone(),
            full_id: request.full_id.clone(),
            purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
            nonce: "0123456789abcdefghijkl".to_owned(),
            audience: service("did:webvh:zService:service.example"),
            origin: "https://service.example/".to_owned(),
            trust_domain: "example".to_owned(),
            local_admin_subject: request.local_admin_subject.clone(),
            requested_scopes: request.requested_scopes.clone(),
            created_at,
            expires_at: created_at + chrono::Duration::seconds(300),
        };
        let version_id = "3-zQmPinnedVersion".to_owned();
        let log_head_digest = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let verification_method =
            DidUrl::new(format!("{}#org-control-key-1", request.full_id)).unwrap();
        let transcript = serde_json::json!({
            "context": ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
            "challenge_id": challenge.challenge_id,
            "organization_id": request.organization_id,
            "full_id": request.full_id,
            "local_admin_subject": request.local_admin_subject,
            "version_id": version_id,
            "log_head_digest": log_head_digest,
            "verification_method": verification_method,
            "created_at": created_at,
        });
        let mut proof = payload_proof(created_at, &verification_method);
        proof.payload_digest =
            Hash::new(arkret_canonical::canonical::canonical_sha256(&transcript).unwrap()).unwrap();
        let ensure = OrganizationRegistrationEnsureRequestBody {
            organization_id: request.organization_id.clone(),
            full_id: request.full_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            version_id,
            log_head_digest,
            control_proof: OrganizationControlProof {
                proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
                quorum_threshold: None,
                proofs: vec![proof],
            },
            local_admin_subject: request.local_admin_subject.clone(),
            requested_scopes: request.requested_scopes,
            handle_attestation: None,
        };
        assert!(
            ensure
                .validate_for_challenge_at(&challenge, created_at + chrono::Duration::seconds(1))
                .is_ok()
        );

        let mut transferred = ensure;
        transferred.local_admin_subject = core("did:webvh:zAttacker:attacker.example");
        assert!(
            transferred
                .validate_for_challenge_at(&challenge, created_at + chrono::Duration::seconds(1))
                .is_err()
        );
    }

    #[test]
    fn receipt_digest_layers_are_non_recursive_and_verified() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let issuer_full = full("did:webvh:zService:service.example");
        let issuer = service(issuer_full.as_str());
        let mut receipt = OrganizationRegistrationReceipt {
            registration_receipt_id: "ak:organization-registration-receipt:placeholder".to_owned(),
            organization_id: core("did:webvh:zOrg:org.example"),
            full_id: full("did:webvh:zOrg:org.example"),
            registration_generation: 1,
            version_id: "3-zQmPinnedVersion".to_owned(),
            log_head_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            control_proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
            control_key_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            local_admin_subject: core("did:webvh:zAdmin:admin.example"),
            delegated_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
            status: OrganizationRegistrationStatus::Active,
            issued_at,
            expires_at: issued_at + chrono::Duration::days(30),
            issuer_service_id: issuer,
            proof: payload_proof(
                issued_at,
                &DidUrl::new(format!("{issuer_full}#notary-key")).unwrap(),
            ),
        };
        receipt.registration_receipt_id = receipt.expected_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        assert!(receipt.validate().is_ok());
        assert!(!receipt.proof_signing_bytes().unwrap().is_empty());

        receipt.proof.created_at += chrono::Duration::seconds(1);
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn challenge_replay_requires_the_committed_request_digest() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let issuer_full = full("did:webvh:zService:service.example");
        let issuer = service(issuer_full.as_str());
        let mut receipt = OrganizationRegistrationReceipt {
            registration_receipt_id: "ak:organization-registration-receipt:placeholder".to_owned(),
            organization_id: core("did:webvh:zOrg:org.example"),
            full_id: full("did:webvh:zOrg:org.example"),
            registration_generation: 1,
            version_id: "3-zQmPinnedVersion".to_owned(),
            log_head_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            control_proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
            control_key_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            local_admin_subject: core("did:webvh:zAdmin:admin.example"),
            delegated_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
            status: OrganizationRegistrationStatus::Active,
            issued_at,
            expires_at: issued_at + chrono::Duration::days(30),
            issuer_service_id: issuer,
            proof: payload_proof(
                issued_at,
                &DidUrl::new(format!("{issuer_full}#notary-key")).unwrap(),
            ),
        };
        receipt.registration_receipt_id = receipt.expected_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        let outcome = OrganizationRegistrationOutcome {
            organization_id: receipt.organization_id.clone(),
            full_id: receipt.full_id.clone(),
            registration_generation: 1,
            version_id: receipt.version_id.clone(),
            registration_receipt: receipt,
            created: true,
        };
        let committed = Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap();
        let different = Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap();
        let replay =
            organization_registration_replay_outcome(&committed, &committed, &outcome).unwrap();
        assert!(!replay.created);
        assert!(
            organization_registration_replay_outcome(&committed, &different, &outcome).is_err()
        );
    }

    #[test]
    fn high_risk_authorization_checks_current_generation_and_status() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let issuer_full = full("did:webvh:zService:service.example");
        let issuer = service(issuer_full.as_str());
        let mut receipt = OrganizationRegistrationReceipt {
            registration_receipt_id: "ak:organization-registration-receipt:placeholder".to_owned(),
            organization_id: core("did:webvh:zOrg:org.example"),
            full_id: full("did:webvh:zOrg:org.example"),
            registration_generation: 1,
            version_id: "3-zQmPinnedVersion".to_owned(),
            log_head_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            control_proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
            control_key_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            local_admin_subject: core("did:webvh:zAdmin:admin.example"),
            delegated_scopes: vec![OrganizationRegistrationScope::OrganizationRealmEndorse],
            status: OrganizationRegistrationStatus::Active,
            issued_at,
            expires_at: issued_at + chrono::Duration::days(30),
            issuer_service_id: issuer,
            proof: payload_proof(
                issued_at,
                &DidUrl::new(format!("{issuer_full}#notary-key")).unwrap(),
            ),
        };
        receipt.registration_receipt_id = receipt.expected_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        let now = issued_at + chrono::Duration::days(1);
        assert!(
            validate_organization_registration_authorization_at(
                &receipt,
                1,
                OrganizationRegistrationStatus::Active,
                now,
            )
            .is_ok()
        );
        assert!(
            validate_organization_registration_authorization_at(
                &receipt,
                2,
                OrganizationRegistrationStatus::Active,
                now,
            )
            .is_err()
        );
        assert!(
            validate_organization_registration_authorization_at(
                &receipt,
                1,
                OrganizationRegistrationStatus::Stale,
                now,
            )
            .is_err()
        );
        assert_eq!(next_organization_registration_generation(None).unwrap(), 1);
        assert_eq!(
            next_organization_registration_generation(Some(1)).unwrap(),
            2
        );
    }

    #[test]
    fn embedded_organization_registration_fixture_has_19_typed_schema_cases() {
        let fixture = arkret_schema::embedded_json_artifact(
            "fixtures/organization-registration-fixture.json",
        )
        .unwrap();
        assert_eq!(
            fixture
                .pointer("/runner/kind")
                .and_then(serde_json::Value::as_str),
            Some("json_schema_and_semantic_cases")
        );
        let cases = fixture["schema_validation_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 19);
        for case in cases {
            let instance = case["instance"].clone();
            let schema_ref = case["schema_ref"].as_str().unwrap();
            let schema_only_valid = case["schema_only_valid"].as_bool() == Some(true);
            let accepted = match schema_ref.rsplit('/').next().unwrap() {
                "OrganizationRegistrationChallenge" => {
                    serde_json::from_value::<OrganizationRegistrationChallenge>(instance).is_ok()
                }
                "OrganizationRegistrationChallengeRequestBody" => {
                    serde_json::from_value::<OrganizationRegistrationChallengeRequestBody>(instance)
                        .is_ok()
                }
                "OrganizationRegistrationEnsureRequestBody" => serde_json::from_value::<
                    OrganizationRegistrationEnsureRequestBody,
                >(instance)
                .and_then(|body| {
                    if schema_only_valid {
                        Ok(())
                    } else {
                        body.validate()
                            .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                    }
                })
                .is_ok(),
                "OrganizationRegistrationRefreshRequestBody" => serde_json::from_value::<
                    OrganizationRegistrationRefreshRequestBody,
                >(instance)
                .and_then(|body| {
                    if schema_only_valid {
                        Ok(())
                    } else {
                        body.validate()
                            .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                    }
                })
                .is_ok(),
                "OrganizationControlProof" => {
                    serde_json::from_value::<OrganizationControlProof>(instance)
                        .and_then(|proof| {
                            if schema_only_valid {
                                Ok(())
                            } else {
                                proof.validate().map_err(|error| {
                                    serde_json::Error::io(std::io::Error::other(error))
                                })
                            }
                        })
                        .is_ok()
                }
                "OrganizationRegistrationReceipt" => {
                    // Fixture receipt ids, payload digests and JWS values are
                    // explicit structural placeholders. Cryptographic and
                    // lifecycle semantics are exercised by the focused tests
                    // above rather than being silently treated as valid.
                    serde_json::from_value::<OrganizationRegistrationReceipt>(instance).is_ok()
                }
                "OrganizationRegistrationOutcome" => {
                    serde_json::from_value::<OrganizationRegistrationOutcome>(instance).is_ok()
                }
                other => panic!("unhandled organization registration fixture schema: {other}"),
            };
            assert_eq!(
                accepted,
                case["expect_valid"].as_bool().unwrap(),
                "typed schema drift in fixture case {}",
                case["name"]
            );
        }
    }
}
