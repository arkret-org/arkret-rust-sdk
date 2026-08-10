//! Invite addressing and private delivery wire helpers.
//!
//! These types mirror the active v1 schemas:
//! `principal-locator.schema.json`, `invite-delivery-request.schema.json`,
//! and `invite-receive-policy.schema.json`.

use arkret_models_identity::handle::Handle;
use arkret_models_identity::{RouteAssistance, ServiceResolutionCarrier};
use arkret_wire::event_envelope::Event;
use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use arkret_wire::{
    BlobRef, CoreId, Did, Error, EventId, Hash, InviteLocatorId, InviteReceiveAction, RealmId,
    Result, SchemaId, ServiceId, UnknownInviteAction,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::handle_claim::HandleClaim;
use crate::governance::member_delivery_binding_candidate::MemberDeliveryBindingCandidate;

pub const INVITE_RECIPIENT_SERVICE_KIND_PRINCIPAL_SERVER: &str = "principal_server";
pub const INVITE_LOCATOR_RESOLVE_PATH: &str = "_arkret/open/invite-locators/resolve";
pub const INVITE_LOCATOR_ISSUE_PATH: &str = "_arkret/self/invite-locators";
pub const INVITE_LOCATOR_ROTATE_PATH: &str = "_arkret/self/invite-locators/rotate";
pub const INVITE_LOCATOR_REVOKE_PATH: &str = "_arkret/self/invite-locators/revoke";
pub const INVITE_LOCATOR_DEFAULT_TTL_SECONDS: u32 = 900;
pub const INVITE_LOCATOR_MIN_TTL_SECONDS: u32 = 60;
pub const INVITE_LOCATOR_MAX_TTL_SECONDS: u32 = 3600;

fn validate_locator_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn deserialize_non_null_optional<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteLocatorResolveRequestBody {
    pub locator_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalLocatorResolveRequestBody {
    pub locator_token: String,
}

impl InviteLocatorResolveRequestBody {
    pub fn new(locator_token: impl Into<String>) -> Self {
        Self {
            locator_token: locator_token.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if !validate_locator_token_shape(self.locator_token.trim()) {
            return Err(Error::Protocol(
                "invite locator token must be base64url and carry at least 128-bit entropy"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteLocatorIssueRequestBody {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_seconds: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub one_time_use: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
}

impl InviteLocatorIssueRequestBody {
    pub fn effective_ttl_seconds(&self) -> u32 {
        self.ttl_seconds
            .unwrap_or(INVITE_LOCATOR_DEFAULT_TTL_SECONDS)
    }

    pub fn validate_minimal(&self) -> Result<()> {
        let ttl = self.effective_ttl_seconds();
        if !(INVITE_LOCATOR_MIN_TTL_SECONDS..=INVITE_LOCATOR_MAX_TTL_SECONDS).contains(&ttl) {
            return Err(Error::Protocol(
                "invite locator ttl_seconds must be between 60 and 3600".to_owned(),
            ));
        }
        if let Some(display_hint) = &self.display_hint {
            display_hint.validate_minimal()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteLocatorRotateRequestBody {
    pub locator_id: InviteLocatorId,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_seconds: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub one_time_use: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_nullable",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_hint: Option<Option<PrincipalLocatorDisplayHint>>,
}

impl InviteLocatorRotateRequestBody {
    pub fn validate_minimal(&self) -> Result<()> {
        if let Some(ttl) = self.ttl_seconds
            && !(INVITE_LOCATOR_MIN_TTL_SECONDS..=INVITE_LOCATOR_MAX_TTL_SECONDS).contains(&ttl)
        {
            return Err(Error::Protocol(
                "invite locator ttl_seconds must be between 60 and 3600".to_owned(),
            ));
        }
        if let Some(Some(display_hint)) = &self.display_hint {
            display_hint.validate_minimal()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteLocatorRevokeRequestBody {
    pub locator_id: InviteLocatorId,
}

impl InviteLocatorRevokeRequestBody {
    pub fn validate_minimal(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteLocatorStatus {
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteLocatorIssueOutcome {
    pub locator_id: InviteLocatorId,
    pub locator_token: String,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub one_time_use: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteLocatorRevokeOutcome {
    pub locator_id: InviteLocatorId,
    pub status: InviteLocatorStatus,
    #[serde(with = "canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteAddress {
    pub subject_id: CoreId,
    pub recipient_service_id: ServiceId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_kind: Option<String>,
}

impl InviteAddress {
    pub fn principal_server(
        subject_id: CoreId,
        recipient_service_id: ServiceId,
        service_resolution: ServiceResolutionCarrier,
    ) -> Self {
        Self {
            subject_id,
            recipient_service_id,
            service_resolution,
            route_assistance: None,
            recipient_service_kind: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_service_resolution_carrier(&self.recipient_service_id, &self.service_resolution)?;
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
        }
        if let Some(service_kind) = &self.recipient_service_kind
            && service_kind != INVITE_RECIPIENT_SERVICE_KIND_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_address.recipient_service_kind MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryTarget {
    pub recipient_service_id: ServiceId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_kind: Option<String>,
}

impl InviteDeliveryTarget {
    pub fn principal_server(
        recipient_service_id: ServiceId,
        service_resolution: ServiceResolutionCarrier,
    ) -> Self {
        Self {
            recipient_service_id,
            service_resolution,
            recipient_service_kind: None,
        }
    }

    pub fn from_invite_address(address: &InviteAddress) -> Self {
        Self {
            recipient_service_id: address.recipient_service_id.clone(),
            service_resolution: address.service_resolution.clone(),
            recipient_service_kind: address.recipient_service_kind.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_service_resolution_carrier(&self.recipient_service_id, &self.service_resolution)?;
        if let Some(service_kind) = &self.recipient_service_kind
            && service_kind != INVITE_RECIPIENT_SERVICE_KIND_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "invite_delivery_target.recipient_service_kind MUST be principal_server".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalLocator {
    pub schema: String,
    pub subject_id: CoreId,
    pub recipient_service_id: ServiceId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_kind: Option<String>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub locator_ref_digest: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub proofs: Vec<PrincipalLocatorProof>,
}

impl PrincipalLocator {
    pub const SCHEMA: &'static str = SchemaId::PRINCIPAL_LOCATOR_V1;
    pub fn invite_address(&self) -> InviteAddress {
        InviteAddress {
            subject_id: self.subject_id.clone(),
            recipient_service_id: self.recipient_service_id.clone(),
            service_resolution: self.service_resolution.clone(),
            route_assistance: self.route_assistance.clone(),
            recipient_service_kind: self.recipient_service_kind.clone(),
        }
    }

    pub fn invite_delivery_target(&self) -> InviteDeliveryTarget {
        InviteDeliveryTarget {
            recipient_service_id: self.recipient_service_id.clone(),
            service_resolution: self.service_resolution.clone(),
            recipient_service_kind: self.recipient_service_kind.clone(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::PRINCIPAL_LOCATOR_V1 {
            return Err(Error::Protocol(
                "principal_locator.schema mismatch".to_owned(),
            ));
        }
        validate_service_resolution_carrier(&self.recipient_service_id, &self.service_resolution)?;
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
        }
        if let Some(service_kind) = &self.recipient_service_kind
            && service_kind != INVITE_RECIPIENT_SERVICE_KIND_PRINCIPAL_SERVER
        {
            return Err(Error::Protocol(
                "principal_locator.recipient_service_kind MUST be principal_server".to_owned(),
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

fn validate_service_resolution_carrier(
    expected_service_id: &ServiceId,
    carrier: &ServiceResolutionCarrier,
) -> Result<()> {
    if let ServiceResolutionCarrier::Inline { inline } = carrier
        && &inline.record.service_id != expected_service_id
    {
        return Err(Error::Protocol(
            "service_resolution inline record does not match recipient_service_id".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalLocatorDisplayHint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

impl PrincipalLocatorDisplayHint {
    pub fn validate_minimal(&self) -> Result<()> {
        if self
            .display_name_hint
            .as_ref()
            .is_some_and(|value| value.chars().count() > 128)
        {
            return Err(Error::Protocol(
                "invite locator display_name_hint must not exceed 128 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum PrincipalLocatorProofPurpose {
    SubjectLocatorAuthorization,
    RecipientServiceAcceptance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalLocatorProof {
    pub proof_purpose: PrincipalLocatorProofPurpose,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub proof: DetachedPayloadProof,
}

pub use arkret_models_identity::proof::DetachedPayloadProof;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntroductionEvidence {
    LocatorRef {
        principal_locator: PrincipalLocator,
    },
    ConsentGrant {
        consent_grant_ref: EventId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_id: Option<String>,
    },
    SharedRealm {
        realm_id: RealmId,
        inviter_member_ref: EventId,
        invitee_member_ref: EventId,
    },
    HandleClaim {
        handle: Handle,
        handle_claim: Box<HandleClaim>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member_delivery_binding_candidate: Option<Box<MemberDeliveryBindingCandidate>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolved_by: Option<Did>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "optional_canonical_timestamp"
        )]
        resolved_at: Option<DateTime<Utc>>,
    },
    SamePrincipalServer,
    ExplicitAddress,
}

impl IntroductionEvidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocatorRef { .. } => "locator_ref",
            Self::ConsentGrant { .. } => "consent_grant",
            Self::SharedRealm { .. } => "shared_realm",
            Self::HandleClaim { .. } => "handle_claim",
            Self::SamePrincipalServer => "same_principal_server",
            Self::ExplicitAddress => "explicit_address",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequestBodyBody {
    pub schema: String,
    pub invite_event: Event,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}

impl InviteDeliveryRequestBodyBody {
    pub fn new(
        invite_event: Event,
        invite_address: InviteAddress,
        introduction_evidence: IntroductionEvidence,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            schema: SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
            invite_event,
            invite_address,
            introduction_evidence,
            idempotency_key: idempotency_key.into(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::INVITE_DELIVERY_REQUEST_V1 {
            return Err(Error::Protocol(
                "invite_delivery_request.schema mismatch".to_owned(),
            ));
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
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteDeliveryOutcomeStatus {
    Accepted,
    Duplicate,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteDeliveryOutcome {
    pub status: InviteDeliveryOutcomeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed_outcome: Option<DisclosedOutcome>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_canonical_timestamp"
    )]
    pub received_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DisclosedOutcome {
    Delivered,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteReceivePolicy {
    pub schema: String,
    pub subject_id: Did,
    pub holder_allowed_introduction_kinds: Vec<String>,
    pub explicit_address_behavior: InviteReceiveAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_behavior: Option<InviteReceiveAction>,
    pub unknown_invites: UnknownInviteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_handle_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_handle_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_handle_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_directory_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_principal_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_principal_services: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_subjects: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<DisclosurePolicy>,
}

impl InviteReceivePolicy {
    pub const SCHEMA: &'static str = SchemaId::INVITE_RECEIVE_POLICY_V1;
    /// Build the fail-closed default from `invite-addressing.md` §5.
    ///
    /// The subject is already a validated DID so callers cannot silently
    /// substitute a placeholder principal when identity parsing fails.
    #[must_use]
    pub fn spec_default(subject_id: Did) -> Self {
        Self {
            schema: SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned(),
            subject_id,
            holder_allowed_introduction_kinds: vec![
                "locator_ref".to_owned(),
                "consent_grant".to_owned(),
                "shared_realm".to_owned(),
            ],
            explicit_address_behavior: InviteReceiveAction::Quarantine,
            handle_claim_behavior: Some(InviteReceiveAction::Quarantine),
            unknown_invites: UnknownInviteAction::Drop,
            allowed_handle_domains: Vec::new(),
            denied_handle_domains: Vec::new(),
            trusted_handle_issuers: Vec::new(),
            trusted_directory_services: Vec::new(),
            trusted_realm_ids: Vec::new(),
            trusted_principal_services: Vec::new(),
            denied_principal_services: Vec::new(),
            denied_subjects: Vec::new(),
            disclosure: Some(DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                discovery_trust: Some(DisclosureLevel::Opaque),
                low_trust: Some(DisclosureLevel::Opaque),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DisclosureLevel {
    Opaque,
    Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DisclosurePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_trust: Option<DisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_trust: Option<DisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_trust: Option<DisclosureLevel>,
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::handle::HandleBindingState;
    use arkret_wire::{DidUrl, PayloadProof, ReceivePolicyConstraints, ReceivePolicySurface};

    use super::*;

    #[test]
    fn invite_receive_policy_spec_default_is_fail_closed() {
        let subject_id = Did::new("did:web:alice.example").unwrap();
        let policy = InviteReceivePolicy::spec_default(subject_id.clone());

        assert_eq!(policy.schema, SchemaId::INVITE_RECEIVE_POLICY_V1);
        assert_eq!(policy.subject_id, subject_id);
        assert_eq!(
            policy.holder_allowed_introduction_kinds,
            ["locator_ref", "consent_grant", "shared_realm"]
        );
        assert_eq!(policy.unknown_invites, UnknownInviteAction::Drop);
        assert_eq!(
            policy.explicit_address_behavior,
            InviteReceiveAction::Quarantine
        );
        assert_eq!(
            policy.handle_claim_behavior,
            Some(InviteReceiveAction::Quarantine)
        );
        assert_eq!(
            policy.disclosure,
            Some(DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                discovery_trust: Some(DisclosureLevel::Opaque),
                low_trust: Some(DisclosureLevel::Opaque),
            })
        );
    }

    fn test_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-07T10:00:00.123Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn invite_locator_resolve_body_validates_body_only_token_shape() {
        let token = "a".repeat(22);
        let body = InviteLocatorResolveRequestBody::new(token);
        body.validate_minimal()
            .expect("valid base64url token shape");
        assert!(
            InviteLocatorResolveRequestBody::new("short")
                .validate_minimal()
                .is_err()
        );
        assert!(
            InviteLocatorResolveRequestBody::new("aaaaaaaaaaaaaaaaaaaaa+")
                .validate_minimal()
                .is_err()
        );
    }

    #[test]
    fn invite_locator_management_bodies_enforce_ttl_and_typed_id() {
        assert!(
            InviteLocatorIssueRequestBody::default()
                .validate_minimal()
                .is_ok()
        );
        assert!(
            InviteLocatorIssueRequestBody {
                ttl_seconds: Some(59),
                ..Default::default()
            }
            .validate_minimal()
            .is_err()
        );
        let rotate = InviteLocatorRotateRequestBody {
            locator_id: InviteLocatorId::new(
                "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            )
            .unwrap(),
            ttl_seconds: Some(900),
            one_time_use: Some(true),
            display_hint: None,
        };
        rotate
            .validate_minimal()
            .expect("valid locator rotate body");
        assert!(
            serde_json::from_value::<InviteLocatorRevokeRequestBody>(serde_json::json!({
                "locator_id": "wrong"
            }))
            .is_err()
        );
    }

    #[test]
    fn invite_locator_rotate_distinguishes_omitted_preserved_and_explicitly_cleared_hint() {
        let omitted: InviteLocatorRotateRequestBody = serde_json::from_value(serde_json::json!({
            "locator_id": "ak:invite_locator:0196419b-0000-7000-8000-000000000000"
        }))
        .unwrap();
        assert_eq!(omitted.display_hint, None);

        let cleared: InviteLocatorRotateRequestBody = serde_json::from_value(serde_json::json!({
            "locator_id": "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
            "display_hint": null
        }))
        .unwrap();
        assert_eq!(cleared.display_hint, Some(None));

        assert!(
            serde_json::from_value::<InviteLocatorRotateRequestBody>(serde_json::json!({
                "locator_id": "ak:invite_locator:0196419b-0000-7000-8000-000000000000",
                "ttl_seconds": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<InviteLocatorIssueRequestBody>(serde_json::json!({
                "display_hint": null
            }))
            .is_err()
        );
    }

    #[test]
    fn principal_locator_serializes_canonical_timestamps() {
        let issued_at = test_time();
        let expires_at = issued_at + chrono::Duration::minutes(15);
        let recipient_full_id =
            arkret_wire::FullId::new("did:webvh:z6mkfixturepsbob:ps.bob.example").unwrap();
        let locator = PrincipalLocator {
            schema: SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
            subject_id: arkret_wire::project_full_id_to_core_id(
                &arkret_wire::FullId::new("did:webvh:z6mkfixturebob:bob.example").unwrap(),
            )
            .unwrap(),
            recipient_service_id: ServiceId::from(
                arkret_wire::project_full_id_to_core_id(&recipient_full_id).unwrap(),
            ),
            service_resolution: ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url:
                    "https://ps.bob.example/_arkret/open/service-resolution/current".to_owned(),
                pinned_record_digest: None,
            },
            route_assistance: None,
            recipient_service_kind: None,
            issued_at,
            expires_at,
            locator_ref_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            delivery_modes: Vec::new(),
            display_hint: None,
            proofs: vec![PrincipalLocatorProof {
                proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
                proof: DetachedPayloadProof {
                    kind: "detached_jws".to_owned(),
                    verification_method: DidUrl::new(format!("{recipient_full_id}#server-key-1"))
                        .unwrap(),
                    payload_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
                    created_at: issued_at,
                    domain: None,
                    audience: None,
                    jws: "header..sig".to_owned(),
                },
            }],
        };

        let value = serde_json::to_value(&locator).expect("serialize locator");
        assert_eq!(value["issued_at"], "2026-06-07T10:00:00.123Z");
        assert_eq!(value["expires_at"], "2026-06-07T10:15:00.123Z");
        assert_eq!(
            value["proofs"][0]["proof"]["created_at"],
            "2026-06-07T10:00:00.123Z"
        );
        assert!(serde_json::from_value::<PrincipalLocator>(value).is_ok());
    }

    #[test]
    fn invite_delivery_outcome_serializes_canonical_received_at() {
        let outcome = InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Accepted,
            disclosed_outcome: None,
            received_at: Some(test_time()),
            retry_after_ms: None,
        };
        let value = serde_json::to_value(outcome).expect("serialize outcome");
        assert_eq!(value["received_at"], "2026-06-07T10:00:00.123Z");
        assert!(value.get("disclosed_outcome").is_none());
    }

    #[test]
    fn introduction_evidence_consent_grant_roundtrips_wire_kind() {
        let evidence = IntroductionEvidence::ConsentGrant {
            consent_grant_ref: EventId::new(
                "ak:event:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR",
            )
            .unwrap(),
            consent_id: None,
        };
        assert_eq!(evidence.kind(), "consent_grant");
        let value = serde_json::to_value(&evidence).expect("serialize consent_grant evidence");
        assert_eq!(value["kind"], "consent_grant");
        assert!(value.get("consent_id").is_none());
        let parsed: IntroductionEvidence =
            serde_json::from_value(value).expect("deserialize consent_grant evidence");
        assert_eq!(parsed, evidence);
    }

    #[test]
    fn invite_delivery_outcome_serializes_disclosed_outcome() {
        let outcome = InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Accepted,
            disclosed_outcome: Some(DisclosedOutcome::Delivered),
            received_at: None,
            retry_after_ms: None,
        };
        let value = serde_json::to_value(outcome).expect("serialize outcome");
        assert_eq!(value["disclosed_outcome"], "delivered");
        assert!(
            serde_json::from_value::<InviteDeliveryOutcome>(serde_json::json!({
                "status": "deferred",
                "disclosed_outcome": "quarantined"
            }))
            .is_err(),
            "holder-private quarantine state must not be representable on the wire"
        );
    }

    #[test]
    fn invite_receive_policy_skips_empty_disclosure_fields() {
        let policy = InviteReceivePolicy {
            schema: SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned(),
            subject_id: Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            holder_allowed_introduction_kinds: vec!["consent_grant".to_owned()],
            explicit_address_behavior: InviteReceiveAction::Quarantine,
            handle_claim_behavior: None,
            unknown_invites: UnknownInviteAction::Drop,
            allowed_handle_domains: Vec::new(),
            denied_handle_domains: Vec::new(),
            trusted_handle_issuers: Vec::new(),
            trusted_directory_services: Vec::new(),
            trusted_realm_ids: Vec::new(),
            trusted_principal_services: Vec::new(),
            denied_principal_services: Vec::new(),
            denied_subjects: Vec::new(),
            disclosure: None,
        };
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert!(value.get("denied_subjects").is_none());
        assert!(value.get("disclosure").is_none());

        let policy = InviteReceivePolicy {
            denied_subjects: vec![Did::new("did:webvh:z6mkfixture:mallory.example").unwrap()],
            disclosure: Some(DisclosurePolicy {
                high_trust: Some(DisclosureLevel::Outcome),
                discovery_trust: Some(DisclosureLevel::Opaque),
                low_trust: Some(DisclosureLevel::Opaque),
            }),
            ..policy
        };
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert_eq!(value["disclosure"]["high_trust"], "outcome");
        assert_eq!(value["disclosure"]["discovery_trust"], "opaque");
        assert_eq!(value["disclosure"]["low_trust"], "opaque");
        assert!(serde_json::from_value::<InviteReceivePolicy>(value).is_ok());
    }

    #[test]
    fn introduction_evidence_handle_claim_roundtrips_wire_kind() {
        let handle = Handle::parse("alice:example.com").unwrap();
        let expires_at = test_time() + chrono::Duration::hours(1);
        let resolved_at = DateTime::parse_from_rfc3339("2026-06-07T10:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let claim = HandleClaim {
            handle: Some(handle.clone()),
            subject: Some(Did::new("did:webvh:z6mkfixture:alice.example").unwrap()),
            binding_state: Some(HandleBindingState::Verified),
            expires_at: Some(expires_at),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
                created_at: resolved_at.to_owned(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "header..sig".to_owned(),
            }],
            ..Default::default()
        };
        let evidence = IntroductionEvidence::HandleClaim {
            handle,
            handle_claim: Box::new(claim),
            member_delivery_binding_candidate: None,
            resolved_by: Some(Did::new("did:webvh:z6mkfixture:directory.example").unwrap()),
            resolved_at: Some(resolved_at),
        };
        assert_eq!(evidence.kind(), "handle_claim");
        let value = serde_json::to_value(&evidence).expect("serialize handle_claim evidence");
        assert_eq!(value["kind"], "handle_claim");
        assert_eq!(value["resolved_at"], "2026-06-07T10:00:00.000Z");
        let parsed: IntroductionEvidence =
            serde_json::from_value(value).expect("deserialize handle_claim evidence");
        assert_eq!(parsed, evidence);
    }

    #[test]
    fn receive_policy_constraints_preserve_omitted_vs_empty_caps() {
        let constraints = ReceivePolicyConstraints {
            policy_version: Some("default".to_owned()),
            applies_to: Some(vec![ReceivePolicySurface::InviteDelivery]),
            deployment_allowed_introduction_kinds: Some(Vec::new()),
            deployment_denied_introduction_kinds: vec!["explicit_address".to_owned()],
            handle_claim_max_behavior: Some(InviteReceiveAction::Quarantine),
            explicit_address_max_behavior: None,
            unknown_invites_max_behavior: Some(UnknownInviteAction::Drop),
            allowed_handle_domains: None,
            trusted_handle_issuers: None,
            trusted_directory_services: None,
            trusted_principal_services: None,
            denied_principal_services: None,
            accepted_subject_did_methods: Some(Vec::new()),
        };
        let value = serde_json::to_value(&constraints).expect("serialize constraints");
        assert_eq!(value["applies_to"], serde_json::json!(["invite_delivery"]));
        assert_eq!(
            value["deployment_allowed_introduction_kinds"],
            serde_json::json!([])
        );
        assert!(value.get("allowed_handle_domains").is_none());
        assert_eq!(value["accepted_subject_did_methods"], serde_json::json!([]));
        assert!(serde_json::from_value::<ReceivePolicyConstraints>(value).is_ok());
    }
}
