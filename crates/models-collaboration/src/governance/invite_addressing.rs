//! Invite addressing and private delivery wire helpers.
//!
//! These types mirror the active v1 schemas:
//! `principal-locator.schema.json`, `invite-delivery-request.schema.json`,
//! and `invite-receive-policy.schema.json`.

use arkret_models_identity::handle::Handle;
use arkret_models_identity::{HandleClaim, RouteAssistance, ServiceResolutionCarrier};
use arkret_wire::event_envelope::Event;
use arkret_wire::serde_helpers::{canonical_timestamp, optional_canonical_timestamp};
use arkret_wire::{
    AccountId, ActorId, BlobRef, DidCoreId, EventId, Hash, InviteId, InviteLocatorId,
    InviteReceiveAction, RealmId, Result, SchemaId, UnknownInviteAction, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use super::holder_quarantine::*;
use crate::serde_absence::{deserialize_non_null_optional, deserialize_present_nullable};

pub const INVITE_RECIPIENT_SERVICE_KIND_STATION: &str = "station";
pub const INVITE_LOCATOR_RESOLVE_PATH: &str = "_arkret/open/invite-locators/resolve";
pub const INVITE_LOCATOR_ISSUE_PATH: &str = "_arkret/self/invite-locators";
pub const INVITE_LOCATOR_ROTATE_PATH: &str = "_arkret/self/invite-locators/rotate";
pub const INVITE_LOCATOR_DEFAULT_TTL_SECONDS: u32 = 900;
pub const INVITE_LOCATOR_MIN_TTL_SECONDS: u32 = 60;
pub const INVITE_LOCATOR_MAX_TTL_SECONDS: u32 = 3600;

fn validate_locator_token_shape(value: &str) -> bool {
    (22..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteLocatorResolveRequestBody {
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
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
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
    pub account_id: AccountId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
}

impl InviteAddress {
    pub fn station(
        subject_id: DidCoreId,
        recipient_id: DidCoreId,
        service_resolution: ServiceResolutionCarrier,
    ) -> Self {
        Self {
            account_id: AccountId::new(subject_id, recipient_id),
            service_resolution,
            route_assistance: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_service_resolution_carrier(&self.account_id.station_id, &self.service_resolution)?;
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct PrincipalLocator {
    pub schema: String,
    pub account_id: AccountId,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_assistance: Option<RouteAssistance>,
    #[serde(with = "canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub locator_ref_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub proofs: Vec<PrincipalLocatorProof>,
}

impl PrincipalLocator {
    pub const SCHEMA: &'static str = SchemaId::PRINCIPAL_LOCATOR_V1;

    pub fn payload_digest(&self) -> Result<Hash> {
        let unsigned = arkret_canonical::unsigned_value(self, &["proofs"])?;
        Hash::new(arkret_canonical::canonical_sha256(&unsigned)?).map_err(Into::into)
    }

    /// The registered locator transcript. Proof purpose selects the permitted
    /// controller; it does not replace the context-separated signed binding.
    pub fn proof_signing_bytes(&self, proof: &DetachedPayloadProof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.payload_digest != payload_digest {
            return Err(WireError::Protocol(
                "principal locator proof payload digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::json!({
            "context": arkret_wire::ProofContextId::PRINCIPAL_LOCATOR_PROOF_V1,
            "payload_digest": payload_digest,
            "account_id": self.account_id,
            "verification_method": proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(proof.created_at),
        });
        if let Some(domain) = &proof.domain {
            binding["domain"] = serde_json::json!(domain);
        }
        if let Some(audience) = &proof.audience {
            binding["audience"] = serde_json::to_value(audience)?;
        }
        Ok(arkret_canonical::canonical_json_bytes(&binding)?)
    }

    pub fn invite_address(&self) -> InviteAddress {
        InviteAddress {
            account_id: self.account_id.clone(),
            service_resolution: self.service_resolution.clone(),
            route_assistance: self.route_assistance.clone(),
        }
    }

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::PRINCIPAL_LOCATOR_V1 {
            return Err(WireError::Protocol(
                "principal_locator.schema mismatch".to_owned(),
            ));
        }
        validate_service_resolution_carrier(&self.account_id.station_id, &self.service_resolution)?;
        if let Some(route_assistance) = &self.route_assistance {
            route_assistance.validate_shape()?;
        }
        if self.expires_at <= self.issued_at {
            return Err(WireError::Protocol(
                "principal_locator.expires_at MUST be after issued_at".to_owned(),
            ));
        }
        if !self.proofs.iter().any(|proof| {
            proof.proof_purpose == PrincipalLocatorProofPurpose::RecipientServiceAcceptance
        }) {
            return Err(WireError::Protocol(
                "principal_locator.proofs MUST include recipient_service_acceptance".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_service_resolution_carrier(
    expected_service_id: &DidCoreId,
    carrier: &ServiceResolutionCarrier,
) -> Result<()> {
    if let ServiceResolutionCarrier::Inline { inline } = carrier
        && &inline.service_id != expected_service_id
    {
        return Err(WireError::Protocol(
            "service_resolution inline record does not match recipient_id".to_owned(),
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
            return Err(WireError::Protocol(
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
#[allow(clippy::large_enum_variant)]
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
        resolved_by: Option<DidCoreId>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "optional_canonical_timestamp"
        )]
        resolved_at: Option<DateTime<Utc>>,
    },
    ExplicitAddress,
}

impl IntroductionEvidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocatorRef { .. } => "locator_ref",
            Self::ConsentGrant { .. } => "consent_grant",
            Self::SharedRealm { .. } => "shared_realm",
            Self::HandleClaim { .. } => "handle_claim",
            Self::ExplicitAddress => "explicit_address",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequestBody {
    pub schema: String,
    pub invite_event: Event,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfInviteDispatchRequestBody {
    pub schema: String,
    pub invite_event_id: EventId,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}

impl SelfInviteDispatchRequestBody {
    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::INVITE_DELIVERY_REQUEST_V1 {
            return Err(WireError::Protocol(
                "invite_delivery_request.schema mismatch".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() || self.idempotency_key.len() > 256 {
            return Err(WireError::Protocol(
                "invite_delivery_request.idempotency_key MUST be 1..=256 bytes".to_owned(),
            ));
        }
        self.invite_address.validate()
    }
}

impl InviteDeliveryRequestBody {
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
            return Err(WireError::Protocol(
                "invite_delivery_request.schema mismatch".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(WireError::Protocol(
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

/// Strong cell value for the `ak.account.invite_delivery` account-data key
/// ([`arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY`]), whose wire
/// schema is `spec/v1/artifacts/schemas/invite-delivery.schema.json`
/// (`ak.schema.invite_delivery.v1`).
///
/// Actor-private plaintext carrier for delivered directed-invite credentials
/// on the notify branch (invite-addressing.md section 7), written by the
/// recipient Station through the delivery path. `invite_token` is a
/// server-issued private locator that MUST NOT enter the Invite object or
/// Realm history. The cell is a bounded CAS register: at most
/// [`InviteDelivery::MAX_ENTRIES`] entries, at most one entry per
/// `invite_id` (a redelivery replaces the previous entry), expired entries
/// are purged on the next write and overflow evicts the oldest entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteDelivery {
    /// `ak.schema.invite_delivery.v1`.
    pub schema: String,
    /// Instant of the accepted CAS write that produced this value.
    #[serde(with = "canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    /// Delivered invite credentials, oldest first.
    pub delivery_entries: Vec<InviteDeliveryEntry>,
}

impl InviteDelivery {
    pub const SCHEMA: &'static str = SchemaId::INVITE_DELIVERY_V1;
    /// Registered `maxItems` bound on `entries`; overflow evicts the oldest.
    pub const MAX_ENTRIES: usize = 200;
    /// Schema bounds on `invite_token` (`minLength: 1`, `maxLength: 512`),
    /// defined once in `arkret-wire` because the same credential rides three
    /// other carriers.
    pub const INVITE_TOKEN_MAX_LENGTH: usize = arkret_wire::INVITE_TOKEN_MAX_CHARS;

    /// Constructor that pins the canonical schema discriminator.
    pub fn new(updated_at: DateTime<Utc>, entries: Vec<InviteDeliveryEntry>) -> Self {
        Self {
            schema: SchemaId::INVITE_DELIVERY_V1.to_owned(),
            updated_at,
            delivery_entries: entries,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::INVITE_DELIVERY_V1 {
            return Err(WireError::Protocol(
                "invite_delivery.schema mismatch".to_owned(),
            ));
        }
        if self.delivery_entries.len() > Self::MAX_ENTRIES {
            return Err(WireError::Protocol(format!(
                "invite_delivery.delivery_entries exceeds {} entries",
                Self::MAX_ENTRIES
            )));
        }
        for (index, entry) in self.delivery_entries.iter().enumerate() {
            entry.validate()?;
            if self.delivery_entries[..index]
                .iter()
                .any(|prior| prior.invite_id == entry.invite_id)
            {
                return Err(WireError::Protocol(
                    "invite_delivery.delivery_entries must carry at most one entry per invite_id"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// One delivered directed-invite credential inside [`InviteDelivery`]
/// (`invite-delivery.schema.json#/$defs/delivery_entry`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteDeliveryEntry {
    /// Invite ID derived from the accepted `ak.invite.create` Event; the
    /// deduplication key of the register.
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    /// Complete inviter account copied from the accepted Invite Event and
    /// bound by the delivery verification chain.
    pub inviter_account_id: AccountId,
    /// Opaque server-issued private invite locator token. Clients MUST treat
    /// it as opaque and MUST NOT persist it outside this cell or equivalent
    /// holder-private state.
    pub invite_token: String,
    /// Instant the recipient Station accepted this delivery.
    #[serde(with = "canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    /// Expiry of the underlying invite credential; a stale entry MUST NOT be
    /// used to accept the invite.
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl InviteDeliveryEntry {
    pub fn validate(&self) -> Result<()> {
        arkret_wire::validate_invite_token("invite_delivery entry", &self.invite_token)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteReceivePolicy {
    pub schema: String,
    pub account_id: AccountId,
    pub holder_allowed_introduction_kinds: Vec<String>,
    pub explicit_address_behavior: InviteReceiveAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_behavior: Option<InviteReceiveAction>,
    pub unknown_invites: UnknownInviteAction,
    /// Holder-selected consent gate profile (`consent-model.md` §6.1). Omitted
    /// on the wire means `default`; the canonical serialization omits the
    /// default so existing policies keep their bytes.
    #[serde(
        default,
        skip_serializing_if = "arkret_wire::ConsentProfile::is_default"
    )]
    pub consent_profile: arkret_wire::ConsentProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_source_quota: Option<arkret_wire::NewSourceQuotaOverride>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_handle_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_handle_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_handle_issuer_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_directory_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_realm_ids: Vec<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_source_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_source_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_actor_ids: Vec<ActorId>,
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
    pub fn spec_default(account_id: AccountId) -> Self {
        Self {
            schema: SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned(),
            account_id,
            holder_allowed_introduction_kinds: vec![
                "locator_ref".to_owned(),
                "consent_grant".to_owned(),
                "shared_realm".to_owned(),
            ],
            explicit_address_behavior: InviteReceiveAction::Quarantine,
            handle_claim_behavior: Some(InviteReceiveAction::Quarantine),
            unknown_invites: UnknownInviteAction::Drop,
            consent_profile: arkret_wire::ConsentProfile::Default,
            new_source_quota: None,
            allowed_handle_domains: Vec::new(),
            denied_handle_domains: Vec::new(),
            trusted_handle_issuer_ids: Vec::new(),
            trusted_directory_ids: Vec::new(),
            trusted_realm_ids: Vec::new(),
            trusted_source_ids: Vec::new(),
            denied_source_ids: Vec::new(),
            denied_actor_ids: Vec::new(),
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
    use arkret_models_identity::{
        HandleClaimCore, HandleClaimStatus, HandleClaimVariant, HandleVisibility,
    };
    use arkret_wire::{
        Did, DidUrl, PayloadProof, PayloadProofPurpose, ReceivePolicyConstraints,
        ReceivePolicySurface,
    };

    use super::*;

    #[test]
    fn invite_receive_policy_spec_default_is_fail_closed() {
        let subject_id = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap();
        let policy = InviteReceivePolicy::spec_default(AccountId::new(
            subject_id.clone(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));

        assert_eq!(policy.schema, SchemaId::INVITE_RECEIVE_POLICY_V1);
        assert_eq!(policy.account_id.principal_id, subject_id);
        let value = serde_json::to_value(&policy).unwrap();
        assert!(value.get("subject_id").is_none());
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
        let recipient_id = DidCoreId::new("ak:did_core:webvh:z6mkfixturepsbob").unwrap();
        let recipient_did = Did::new("did:webvh:z6mkfixturepsbob:ps.bob.example").unwrap();
        let locator = PrincipalLocator {
            schema: SchemaId::PRINCIPAL_LOCATOR_V1.to_owned(),
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
                recipient_id,
            ),
            service_resolution: ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: "https://ps.bob.example/_arkret/open/service-resolution/current"
                    .to_owned(),
            },
            route_assistance: None,
            issued_at,
            expires_at,
            locator_ref_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            display_hint: None,
            proofs: vec![PrincipalLocatorProof {
                proof_purpose: PrincipalLocatorProofPurpose::RecipientServiceAcceptance,
                proof: DetachedPayloadProof {
                    kind: "detached_jws".to_owned(),
                    verification_method: DidUrl::new(format!("{recipient_did}#server-key-1"))
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
        let digest = locator.payload_digest().unwrap();
        let mut unsigned = locator.clone();
        unsigned.proofs.clear();
        assert_eq!(unsigned.payload_digest().unwrap(), digest);
        let mut proof = locator.proofs[0].proof.clone();
        proof.payload_digest = digest;
        let binding: serde_json::Value =
            serde_json::from_slice(&locator.proof_signing_bytes(&proof).unwrap()).unwrap();
        assert_eq!(
            binding["account_id"],
            serde_json::to_value(&locator.account_id).unwrap()
        );
        assert!(binding.get("subject_id").is_none());
        assert!(binding.get("recipient_id").is_none());
        unsigned.account_id.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert_ne!(unsigned.payload_digest().unwrap(), proof.payload_digest);
        assert!(unsigned.proof_signing_bytes(&proof).is_err());
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
    fn invite_receive_policy_consent_profile_defaults_and_roundtrips() {
        // consent-model.md §6.1: the profile carrier is
        // `invite_receive_policy.consent_profile`; omitted means `default` and
        // the default is not serialized so existing policy bytes are stable.
        let policy = InviteReceivePolicy::spec_default(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        assert_eq!(policy.consent_profile, arkret_wire::ConsentProfile::Default);
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert!(value.get("consent_profile").is_none());

        let mut explicit = value.clone();
        explicit["consent_profile"] = serde_json::json!("require_explicit_consent");
        let parsed: InviteReceivePolicy =
            serde_json::from_value(explicit).expect("registered profile parses");
        assert_eq!(
            parsed.consent_profile,
            arkret_wire::ConsentProfile::RequireExplicitConsent
        );
        assert!(parsed.consent_profile.requires_explicit_consent());
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["consent_profile"],
            "require_explicit_consent"
        );

        let mut unregistered = value;
        unregistered["consent_profile"] = serde_json::json!("strict");
        assert!(serde_json::from_value::<InviteReceivePolicy>(unregistered).is_err());
    }

    #[test]
    fn invite_receive_policy_skips_empty_disclosure_fields() {
        let policy = InviteReceivePolicy {
            schema: SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned(),
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            holder_allowed_introduction_kinds: vec!["consent_grant".to_owned()],
            explicit_address_behavior: InviteReceiveAction::Quarantine,
            handle_claim_behavior: None,
            unknown_invites: UnknownInviteAction::Drop,
            consent_profile: arkret_wire::ConsentProfile::Default,
            new_source_quota: None,
            allowed_handle_domains: Vec::new(),
            denied_handle_domains: Vec::new(),
            trusted_handle_issuer_ids: Vec::new(),
            trusted_directory_ids: Vec::new(),
            trusted_realm_ids: Vec::new(),
            trusted_source_ids: Vec::new(),
            denied_source_ids: Vec::new(),
            denied_actor_ids: Vec::new(),
            disclosure: None,
        };
        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert!(value.get("denied_actor_ids").is_none());
        assert!(value.get("disclosure").is_none());

        let policy = InviteReceivePolicy {
            denied_actor_ids: vec![ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ))],
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
        let core_proof = PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1").unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            created_at: resolved_at,
            domain: Some("ak.handle_claim_proof.v1".to_owned()),
            audience: None,
            proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
            jws: "header..sig".to_owned(),
        };
        let claim = HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            claim: HandleClaimCore {
                schema: HandleClaimCore::SCHEMA.to_owned(),
                handle: handle.clone(),
                handle_aliases: Vec::new(),
                subject_account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                    DidCoreId::new("ak:did_core:webvh:z6mkfixtureserver").unwrap(),
                ),
                issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
                claim: HandleClaimVariant::HandleBinding,
                visibility: HandleVisibility::Public,
                audience: None,
                issued_at: resolved_at,
                expires_at: Some(expires_at),
                source_refs: Vec::new(),
                proofs: [
                    core_proof.clone(),
                    PayloadProof {
                        proof_purpose: Some(PayloadProofPurpose::HolderAcceptance),
                        ..core_proof
                    },
                ],
            },
            status: HandleClaimStatus::Verified,
            as_of: resolved_at,
            verifier_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureissuer").unwrap(),
            verified_at: Some(resolved_at),
            revocation: None,
            fresh_until: resolved_at + chrono::Duration::minutes(5),
            status_proof: PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
                created_at: resolved_at,
                domain: Some("ak.handle_claim_status.v1".to_owned()),
                audience: None,
                proof_purpose: Some(PayloadProofPurpose::StatusAttestation),
                jws: "header..sig".to_owned(),
            },
        };
        let evidence = IntroductionEvidence::HandleClaim {
            handle,
            handle_claim: Box::new(claim),
            resolved_by: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
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
            new_source_quota: None,
            disclosure_max: None,
            allowed_handle_domains: None,
            trusted_handle_issuer_ids: None,
            trusted_directory_ids: None,
            trusted_source_ids: None,
            denied_source_ids: None,
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

    fn invite_delivery_entry_fixture() -> InviteDeliveryEntry {
        InviteDeliveryEntry {
            invite_id: InviteId::new("ak:invite:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD")
                .unwrap(),
            realm_id: RealmId::new("ak:realm:ARkAfriCBkEJNgK9UxfUciMBt-L3mtRcFLO8ICOBW_9K")
                .unwrap(),
            inviter_account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
            ),
            invite_token: "srv-01HYZ8Z000000000000000".to_owned(),
            received_at: DateTime::parse_from_rfc3339("2026-08-20T01:02:03Z")
                .unwrap()
                .with_timezone(&Utc),
            expires_at: DateTime::parse_from_rfc3339("2026-08-27T01:02:03Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn invite_delivery_cell_round_trips_and_passes_spec_schema() {
        let updated_at = DateTime::parse_from_rfc3339("2026-08-20T01:02:04Z")
            .unwrap()
            .with_timezone(&Utc);
        let cell = InviteDelivery::new(updated_at, vec![invite_delivery_entry_fixture()]);
        cell.validate().unwrap();
        assert_eq!(cell.schema, SchemaId::INVITE_DELIVERY_V1);

        let value = serde_json::to_value(&cell).expect("serialize invite_delivery cell");
        let parsed: InviteDelivery =
            serde_json::from_value(value.clone()).expect("deserialize invite_delivery cell");
        assert_eq!(parsed, cell);

        // SDK output is accepted by the spec schema, with and without entries.
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec artifact registry available (live co-checkout or embedded)");
        registry
            .validate_value(SchemaId::INVITE_DELIVERY_V1, &value)
            .unwrap();
        let empty = InviteDelivery::new(updated_at, Vec::new());
        registry
            .validate_value(
                SchemaId::INVITE_DELIVERY_V1,
                &serde_json::to_value(&empty).unwrap(),
            )
            .unwrap();

        // The closed schema rejects unknown additive keys.
        let mut leaky = value;
        leaky["unexpected"] = serde_json::json!(true);
        assert!(
            registry
                .validate_value(SchemaId::INVITE_DELIVERY_V1, &leaky)
                .is_err()
        );
    }

    #[test]
    fn invite_delivery_cell_enforces_bounds() {
        let updated_at = DateTime::parse_from_rfc3339("2026-08-20T01:02:04Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut oversized = InviteDelivery::new(updated_at, Vec::new());
        oversized.delivery_entries = (0..=InviteDelivery::MAX_ENTRIES)
            .map(|_| invite_delivery_entry_fixture())
            .collect();
        assert!(oversized.validate().is_err());

        let mut duplicated = InviteDelivery::new(
            updated_at,
            vec![invite_delivery_entry_fixture(), {
                let mut second = invite_delivery_entry_fixture();
                second.invite_token = "srv-other-token".to_owned();
                second
            }],
        );
        assert!(duplicated.validate().is_err());
        duplicated.delivery_entries[1].invite_id =
            InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap();
        duplicated.validate().unwrap();

        let mut empty_token =
            InviteDelivery::new(updated_at, vec![invite_delivery_entry_fixture()]);
        empty_token.delivery_entries[0].invite_token = String::new();
        assert!(empty_token.validate().is_err());
        let mut long_token = InviteDelivery::new(updated_at, vec![invite_delivery_entry_fixture()]);
        long_token.delivery_entries[0].invite_token =
            "t".repeat(InviteDelivery::INVITE_TOKEN_MAX_LENGTH + 1);
        assert!(long_token.validate().is_err());
    }
}
