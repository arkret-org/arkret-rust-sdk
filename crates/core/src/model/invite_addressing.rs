//! Invite addressing and private delivery wire helpers.
//!
//! These types mirror the active v1 schemas:
//! `principal-locator.schema.json`, `invite-delivery-request.schema.json`,
//! and `invite-receive-policy.schema.json`.

use super::*;

pub const PRINCIPAL_LOCATOR_SCHEMA: &str = "ck.schema.principal_locator.v1";
pub const INVITE_DELIVERY_REQUEST_SCHEMA: &str = "ck.schema.invite_delivery_request.v1";
pub const INVITE_RECEIVE_POLICY_SCHEMA: &str = "ck.schema.invite_receive_policy.v1";
pub const INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER: &str = "principal_server";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteAddress {
    pub subject_id: Did,
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

impl InviteAddress {
    pub fn principal_server(subject_id: Did, recipient_service_did: Did) -> Self {
        Self { subject_id, recipient_service_did, recipient_service_type: None }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_address.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryTarget {
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
}

impl InviteDeliveryTarget {
    pub fn principal_server(recipient_service_did: Did) -> Self {
        Self { recipient_service_did, recipient_service_type: None }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_delivery_target.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocator {
    pub schema: String,
    pub subject_id: Did,
    pub recipient_service_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub locator_ref_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub proofs: Vec<PrincipalLocatorProof>,
}

impl PrincipalLocator {
    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != PRINCIPAL_LOCATOR_SCHEMA {
            return Err(Error::Protocol("principal_locator.schema mismatch".to_owned()));
        }
        if let Some(service_type) = &self.recipient_service_type
            && service_type != INVITE_RECIPIENT_SERVICE_TYPE_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "principal_locator.recipient_service_type MUST be principal_server".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "principal_locator.expires_at MUST be after issued_at".to_owned(),
            ));
        }
        if !self.proofs.iter().any(|proof| {
            proof.proof_purpose == PrincipalLocatorProofPurpose::RecipientServiceAcceptance
        }) {
            return Err(Error::Protocol(
                "principal_locator.proofs MUST include recipient_service_acceptance".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocatorDisplayHint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalLocatorProofPurpose {
    SubjectLocatorAuthorization,
    RecipientServiceAcceptance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocatorProof {
    pub proof_purpose: PrincipalLocatorProofPurpose,
    pub proof: DetachedPayloadProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DetachedPayloadProof {
    pub kind: String,
    pub verification_method: String,
    pub alg: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntroductionEvidence {
    LocatorRef { principal_locator: PrincipalLocator },
    SharedRealm { realm_id: RealmId, inviter_member_ref: EventId, invitee_member_ref: EventId },
    SamePrincipalServer,
    ExplicitAddress,
}

impl IntroductionEvidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocatorRef { .. } => "locator_ref",
            Self::SharedRealm { .. } => "shared_realm",
            Self::SamePrincipalServer => "same_principal_server",
            Self::ExplicitAddress => "explicit_address",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequest {
    pub schema: String,
    pub invite_event: Value,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}

impl InviteDeliveryRequest {
    pub fn new(
        invite_event: Value,
        invite_address: InviteAddress,
        introduction_evidence: IntroductionEvidence,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            schema: INVITE_DELIVERY_REQUEST_SCHEMA.to_owned(),
            invite_event,
            invite_address,
            introduction_evidence,
            idempotency_key: idempotency_key.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != INVITE_DELIVERY_REQUEST_SCHEMA {
            return Err(Error::Protocol("invite_delivery_request.schema mismatch".to_owned()));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(Error::Protocol(
                "invite_delivery_request.idempotency_key MUST NOT be empty".to_owned(),
            ));
        }
        self.invite_address.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InviteDeliveryOutcomeStatus {
    Accepted,
    Duplicate,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryOutcome {
    pub status: InviteDeliveryOutcomeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InviteReceiveAction {
    Drop,
    Quarantine,
    Notify,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum UnknownInviteAction {
    Drop,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteReceivePolicy {
    pub schema: String,
    pub subject_id: Did,
    pub allowed_introduction_kinds: Vec<String>,
    pub explicit_address_behavior: InviteReceiveAction,
    pub unknown_invites: UnknownInviteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_principal_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_principal_services: Vec<Did>,
}
