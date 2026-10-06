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
    AccountId, ActorId, BlobRef, CommitStreamRef, DidCoreId, EventId, Hash, InviteId,
    InviteLocatorId, InviteReceiveAction, RealmCommit, RealmId, Result, SchemaId,
    UnknownInviteAction, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use super::holder_quarantine::*;
use super::realm_join_intake::{RealmJoinCandidate, validate_authority_locator_hints};
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

/// Private service-to-service invite delivery request
/// (`invite-delivery-request.schema.json`).
///
/// The current Realm governance Station emits it after committing the invite
/// Event. `invite_commit` is the Realm-stream authority commit of exactly that
/// Event; `authority_locator_hints` are untrusted discovery hints only. Field
/// declaration order is the schema `properties` order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequestBody {
    pub schema: String,
    pub invite_event: Event,
    pub invite_commit: RealmCommit,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub producer_signer_fact: Option<crate::authority_commit::HumanHistoricalSignerFact>,
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
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
        invite_commit: RealmCommit,
        producer_signer_fact: Option<crate::authority_commit::HumanHistoricalSignerFact>,
        authority_locator_hints: Vec<RealmJoinCandidate>,
        invite_address: InviteAddress,
        introduction_evidence: IntroductionEvidence,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        let request = Self {
            schema: SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
            invite_event,
            invite_commit,
            producer_signer_fact,
            authority_locator_hints,
            invite_address,
            introduction_evidence,
            idempotency_key: idempotency_key.into(),
        };
        request.validate_for_submission()?;
        Ok(request)
    }

    /// Validate a new ordinary notification, separately from exact legacy original decoding.
    /// This does not verify the Event signature or authenticate governance authority.
    pub fn validate_for_submission(&self) -> Result<()> {
        self.validate_minimal()?;
        if self.invite_event.kind != arkret_wire::EventKind::InviteCreate {
            return Err(WireError::Protocol(
                "invite delivery requires the original Invite create Event".into(),
            ));
        }
        let suite = arkret_canonical::canonical::digest_suite(
            self.invite_event.event_id.digest_suite_code().as_str(),
        )?;
        crate::authority_commit::validate_new_human_admission_fact(
            &self.invite_event,
            self.producer_signer_fact.as_ref(),
            suite,
        )
    }

    /// Wire-local checks that need no key material: the schema discriminator,
    /// the idempotency key bounds, the Realm-stream `invite_commit` addressing
    /// exactly `invite_event`, the locator-hint array contract, and the invite
    /// address carrier. Signature, governance authority and producer proof
    /// verification remain the receiver's responsibility.
    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != SchemaId::INVITE_DELIVERY_REQUEST_V1 {
            return Err(WireError::Protocol(
                "invite_delivery_request.schema mismatch".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty() || self.idempotency_key.chars().count() > 256 {
            return Err(WireError::Protocol(
                "invite_delivery_request.idempotency_key MUST be 1..=256 characters".to_owned(),
            ));
        }
        self.invite_commit.validate_shape()?;
        match (
            &self.invite_commit.producer_signer_fact_digest,
            &self.producer_signer_fact,
        ) {
            (Some(_), Some(fact)) => {
                // Only closed shape belongs to this stage. Exact fact/Commit
                // digest and producer proof binding are signature checks at
                // the receiver, with signature_invalid on failure.
                fact.key.validate()?;
            }
            (None, None) => {}
            _ => {
                return Err(WireError::Protocol(
                    "invite signer fact and original Commit digest must be present together".into(),
                ));
            }
        }
        if self.invite_commit.event_ref != self.invite_event.event_id {
            return Err(WireError::Protocol(
                "invite_delivery_request.invite_commit.event_ref MUST equal invite_event.event_id"
                    .to_owned(),
            ));
        }
        if !matches!(
            &self.invite_commit.stream_ref,
            CommitStreamRef::Realm { realm_id } if *realm_id == self.invite_event.realm_id
        ) {
            return Err(WireError::Protocol(
                "invite_delivery_request.invite_commit MUST be on the invite Event's Realm stream"
                    .to_owned(),
            ));
        }
        validate_authority_locator_hints(&self.authority_locator_hints)?;
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
/// Actor-private plaintext carrier for delivered directed invites on the
/// notify branch (invite-addressing.md section 7), written by the recipient
/// Station through the delivery path. It carries invite references and
/// untrusted locator hints but no bearer credential. The cell is a bounded CAS register: at most
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
    /// Delivered directed invites, oldest first.
    pub delivery_entries: Vec<InviteDeliveryEntry>,
}

impl InviteDelivery {
    pub const SCHEMA: &'static str = SchemaId::INVITE_DELIVERY_V1;
    /// Registered `maxItems` bound on `entries`; overflow evicts the oldest.
    pub const MAX_ENTRIES: usize = 200;

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

/// One delivered directed invite inside [`InviteDelivery`]
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
    /// One to eight untrusted locator cores, strictly sorted by `service_id`
    /// UTF-8 bytes. Realm scope and freshness come only from this entry; the
    /// invitee still fetches and verifies a nonce-bound RealmAuthorityBundle
    /// through its own Station before any preview, join preparation or
    /// bootstrap request.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
    /// Instant the recipient Station accepted this delivery.
    #[serde(with = "canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    /// Expiry copied from the accepted invite; a stale entry MUST NOT be used
    /// to accept the invite.
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl InviteDeliveryEntry {
    pub fn validate(&self) -> Result<()> {
        validate_authority_locator_hints(&self.authority_locator_hints)
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
