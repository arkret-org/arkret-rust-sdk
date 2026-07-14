//! Preview-policy, profile-realm-override, reaction, read-receipt, realm, relation,
//! signature-material, space, state, and view payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{HistoryKeySource, RealmKeyWithheldReasonCode};
use crate::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/preview_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueHistory {
    pub range: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_member_events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValueToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_target_digest: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayloadValue {
    pub mode: String,
    pub audiences: Vec<String>,
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PreviewPolicyPayloadValueHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<PreviewPolicyPayloadValueToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyPayload {
    pub value: PreviewPolicyPayloadValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRealmOverridePayload {
    pub target_ref: String,
    pub target_realm_id: RealmId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// reaction_encrypted_payload_plaintext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionEncryptedPayloadPlaintext {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_add_event_ids: Option<Vec<EventRef>>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionPayload {
    pub target_ref: ObjectRef,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptPolicyPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_overrides_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_child_privacy_tightening_against_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_public_receipts_on_world_readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_forced_public_world_readable_receipts: Option<bool>,
}

// `realm_archive_payload` now has a strong type:
// `models::operation_payloads::RealmArchivePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: Realm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

// `realm_destroy_payload` now has a strong type:
// `models::operation_payloads::RealmDestroyPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_disappearing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDisappearingPolicyPayload {
    pub enabled: bool,
    pub max_ttl_ms: u64,
    pub allowed_triggers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_grace_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_realms: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

impl RealmFreezePayload {
    pub fn new(frozen: bool) -> Self {
        Self {
            frozen,
            reason: None,
            effective_at: None,
            freeze_expires_at: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        if !reason.trim().is_empty() {
            self.reason = Some(reason);
        }
        self
    }

    pub fn with_freeze_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.freeze_expires_at = Some(expires_at);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm freeze payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_inheritance_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayloadInherits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_bundles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_defaults: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayload {
    pub source_realm_id: RealmId,
    pub inherits: RealmInheritancePolicyPayloadInherits,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InheritancePolicyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `relationship` discriminator for [`RealmOrganizationPayload`]
/// (event-payload.schema.json `#/$defs/realm_organization_payload`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationRelationship {
    Owner,
    Governance,
    Sponsor,
    DirectoryCertifier,
}

/// `status` discriminator for [`RealmOrganizationPayload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationStatus {
    Active,
    Revoked,
}

/// `control_scopes[]` item enum for [`RealmOrganizationPayload`]. A scope is an
/// endorsement boundary only; actual Realm control still requires the matching
/// Realm policy / notary / capability / service-binding event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationControlScope {
    OfficialBadge,
    RealmAdmin,
    NotaryControl,
    PolicyServer,
    DeliveryBindingPolicy,
    DurabilityPolicy,
    ModerationPolicy,
    RetentionPolicy,
    DirectoryListing,
    PlaintextVisibleService,
}

/// `authorization.issuer_role` enum for [`RealmOrganizationAuthorization`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationIssuerRole {
    OrganizationDid,
    GovernanceService,
    AccountAuthority,
    ThresholdQuorum,
}

impl RealmOrganizationIssuerRole {
    /// Roles whose statement MUST carry a `delegation_ref` resolving to a live
    /// organization DID delegation (governance_service / account_authority).
    pub fn requires_delegation_ref(self) -> bool {
        matches!(self, Self::GovernanceService | Self::AccountAuthority)
    }
}

/// Counterpart for the inner `authorization` object of
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// This is the organization-side authorization proof, independent of the
/// Realm-side `ak.realm.admin` authorization required to write the event into
/// Realm history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationAuthorization {
    /// Organization DID or delegated service DID that issued this statement.
    pub issuer: Did,
    pub issuer_role: RealmOrganizationIssuerRole,
    /// DID URL of a concrete verification method (bare DIDs are not valid).
    pub verification_method: DidUrl,
    /// REQUIRED when `issuer_role` is `governance_service` or
    /// `account_authority`; MUST resolve to a live organization DID delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<ObjectRef>,
    /// Optional human admin / service principal that initiated the decision.
    /// Does not become the organization principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    pub signed_at: DateTime<Utc>,
    /// Signature, threshold transcript, or governance-service attestation over
    /// the canonical organization statement.
    pub proof: SignatureMaterial,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// Organization-side endorsement or revocation for a Realm relationship. The
/// reducer cell subject is `(organization_id, relationship)` — `statement_id`
/// is audit identity, not the cell subject. Field order mirrors the spec schema
/// `properties` ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationPayload {
    /// Stable id of this organization statement (audit identity).
    pub statement_id: String,
    /// Realm the statement is bound to; MUST equal the enclosing
    /// `Event.realm_id`.
    pub realm_id: RealmId,
    /// Organization principal DID that endorses / governs / sponsors /
    /// certifies / revokes the Realm relationship.
    pub organization_id: Did,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    /// Machine-readable scopes covered by the organization's consent
    /// (non-empty, unique).
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Nullable expiry — `Some(None)` and absence both mean "no expiry".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    /// REQUIRED when `status == revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    /// Optional digest of the Realm control frontier the organization evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier_digest: Option<Hash>,
    /// Optional DID-document delegation URL / policy object / governance
    /// decision / attestation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_policy_ref: Option<ObjectRef>,
    pub authorization: RealmOrganizationAuthorization,
}

impl RealmOrganizationPayload {
    /// `true` when the statement asserts the relationship (not a revocation).
    pub fn is_active_status(&self) -> bool {
        matches!(self.status, RealmOrganizationStatus::Active)
    }

    /// `true` when the statement revokes the relationship.
    pub fn is_revoked_status(&self) -> bool {
        matches!(self.status, RealmOrganizationStatus::Revoked)
    }

    /// `true` when `not_before` is set and lies strictly after `now` (the
    /// statement is not yet within its validity window).
    pub fn is_not_yet_valid(&self, now: DateTime<Utc>) -> bool {
        self.not_before.is_some_and(|nbf| now < nbf)
    }

    /// `true` when `expires_at` is set and lies at or before `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    /// `true` when the statement is an `active` relationship currently inside
    /// its validity window (`not_before <= now < expires_at`).
    pub fn is_effective_active(&self, now: DateTime<Utc>) -> bool {
        self.is_active_status() && !self.is_not_yet_valid(now) && !self.is_expired(now)
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyScope {
    pub effective_scope: EffectiveScope,
    pub policy_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_scope`.
///
/// Request-flavoured scope: unlike [`RealmKeyScope`] (used by the durable
/// share), `policy_digest` is an OPTIONAL requester hint (the key source MUST
/// recompute effective policy) and `from_epoch` / `to_epoch` are REQUIRED (the
/// requester always names the epoch range it wants).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestScope {
    pub effective_scope: EffectiveScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Hash>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_content`.
///
/// Ephemeral `ak.realm_key.request` body: a device asks a provider to seal the
/// retained `history_secret[from..to]` for a Realm to its HPKE public key so it
/// can decrypt pre-join content. The sealed material rides back inside a
/// `ak.realm_key.share` `ciphertext`.
///
/// `requested_source_class` reuses the authoritative
/// [`crate::models::HistoryKeySource`] (defined in `history_visibility.rs`).
/// The direct request/share path is not allowed to request the
/// [`HistoryKeySource::KeyBackup`] class — backup-derived history keys are out
/// of scope here; [`RealmKeyRequestPayload::validate`] rejects it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestPayload {
    pub key_scope: RealmKeyRequestScope,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub recipient_hpke_public_key: NonEmptyString,
    pub requested_source_class: HistoryKeySource,
    pub target_source_ref: RealmKeySourceRef,
    pub target_principal_id: Did,
    pub created_at: DateTime<Utc>,
}

impl RealmKeyRequestPayload {
    /// Reject empty load-bearing fields and the out-of-scope `key_backup`
    /// source class before the request is shipped.
    pub fn validate(&self) -> Result<()> {
        if self.requested_source_class == HistoryKeySource::KeyBackup {
            return Err(Error::Protocol(
                "ak.realm_key.request.requested_source_class must not be key_backup".to_owned(),
            ));
        }
        if self.recipient_hpke_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.realm_key.request.recipient_hpke_public_key must not be blank".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmKeySourceRef {
    Device(DeviceId),
    Service(Did),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmKeyShareResult {
    Shared,
    Withheld,
    Rejected,
    Expired,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyShareAuditPayload {
    pub share_event_ref: EventId,
    pub result: RealmKeyShareResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<Hash>,
    pub recorded_at: DateTime<Utc>,
}

/// Discriminator for `realm_key_share_payload.share_class`
/// (event-payload.schema.json, device-lifecycle.md §13). `member_device` is the
/// ordinary per-member history delivery path (carries `recipient_device_id`);
/// `realm_recovery_key` is the Realm `durability_policy` RRK durability seal
/// (carries `recipient_verification_method` + `recovery_recipient_id`, never a
/// device id) — see encryption-and-audit.md §2.10.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmKeyShareClass {
    MemberDevice,
    RealmRecoveryKey,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeySharePayload {
    pub share_class: RealmKeyShareClass,
    pub recipient_principal_id: Did,
    /// Present only for `share_class=member_device`; forbidden for
    /// `realm_recovery_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    /// Present only for `share_class=realm_recovery_key`: the RRK
    /// `verification_method` (identity-did.md §8.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_verification_method: Option<DidUrl>,
    /// Present only for `share_class=realm_recovery_key`: the
    /// `durability_policy.recovery_recipients[].recipient_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_recipient_id: Option<NonEmptyString>,
    pub sender_device_id: DeviceId,
    /// Accepted policy/grant/source authorization event reference covering this
    /// delivery at the Event CBA basis. The receiver verifies it before
    /// installing any history secret material.
    pub source_authorization_ref: EventId,
    pub sender_device_signature: SignatureMaterial,
    pub key_scope: RealmKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_key_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RealmKeySharePayload {
    /// Canonical bytes the sender device MUST sign and place in
    /// `sender_device_signature` (device-lifecycle.md §13). Covers
    /// `sender_device_id`, source authorization ref, recipient principal/device,
    /// `key_scope`,
    /// `ciphertext` / `encrypted_key_ref`, `aad_digest` and `created_at` —
    /// everything except the signature field itself. Signer and verifier MUST
    /// reconstruct it byte-identically; the to-device receiver verifies this
    /// independently of the durable Event-envelope signature.
    pub fn sender_signing_input(&self) -> Vec<u8> {
        let covered = serde_json::json!({
            "purpose": "ak.realm_key.share.sender_device_signature.v1",
            "share_class": self.share_class,
            "sender_device_id": self.sender_device_id,
            "source_authorization_ref": self.source_authorization_ref,
            "recipient_principal_id": self.recipient_principal_id,
            "recipient_device_id": self.recipient_device_id,
            "recipient_verification_method": self.recipient_verification_method,
            "recovery_recipient_id": self.recovery_recipient_id,
            "key_scope": self.key_scope,
            "ciphertext": self.ciphertext,
            "encrypted_key_ref": self.encrypted_key_ref,
            "aad_digest": self.aad_digest,
            "created_at": self.created_at,
        });
        canonical::canonical_json_bytes(&covered).unwrap_or_default()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyWithheldPayload {
    pub recipient_principal_id: Did,
    pub recipient_device_id: String,
    pub sender_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_scope: Option<RealmKeyScope>,
    pub withheld_reason_code: RealmKeyWithheldReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_ids: Vec<Did>,
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_retention_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leakage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_rotation_cadence_ms: Option<u64>,
}

// `realm_tombstone_payload` now has a strong type:
// `models::operation_payloads::RealmTombstonePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

// `relation_create_payload` now has a strong type:
// `models::operation_payloads::RelationCreatePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/signature_material`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignatureMaterial {
    NonEmptyString(NonEmptyString),
    Variant1(BTreeMap<String, Value>),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceCreatePayload {
    pub object: Space,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceParentPayload {
    pub space_id: SpaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    pub expected_parent_space_id: Option<SpaceId>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacePatchPayload {
    pub space_id: SpaceId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Patch>,
}

#[cfg(test)]
mod realm_key_request_tests {
    use serde_json::json;

    use super::*;

    fn request_scope() -> RealmKeyRequestScope {
        RealmKeyRequestScope {
            effective_scope: EffectiveScope::Realm {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            },
            policy_digest: None,
            membership_frontier_digest: None,
            from_epoch: 0,
            to_epoch: 4,
            history_visibility: None,
        }
    }

    fn request(source: HistoryKeySource) -> RealmKeyRequestPayload {
        RealmKeyRequestPayload {
            key_scope: request_scope(),
            recipient_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000A".to_owned(),
            )
            .unwrap(),
            recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000b")
                .unwrap(),
            recipient_hpke_public_key: NonEmptyString::new("cHVia2V5").unwrap(),
            requested_source_class: source,
            target_source_ref: RealmKeySourceRef::Device(
                DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c").unwrap(),
            ),
            target_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000D".to_owned(),
            )
            .unwrap(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn realm_key_request_round_trips_and_field_order_is_stable() {
        let payload = request(HistoryKeySource::VerifiedMemberDevice);
        payload.validate().unwrap();
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value["requested_source_class"],
            json!("verified_member_device")
        );
        let parsed: RealmKeyRequestPayload = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.recipient_device_id, payload.recipient_device_id);
        assert_eq!(parsed.target_source_ref, payload.target_source_ref);
    }

    #[test]
    fn realm_key_request_rejects_key_backup_and_empty_fields() {
        assert!(request(HistoryKeySource::KeyBackup).validate().is_err());

        let mut bad = request(HistoryKeySource::OwnDevice);
        bad.recipient_hpke_public_key = NonEmptyString::new("   ").unwrap();
        assert!(bad.validate().is_err());
    }
}

#[cfg(test)]
mod realm_organization_tests {
    use serde_json::json;

    use super::*;

    fn active_value() -> Value {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000010",
            "organization_id": "did:webvh:example.test:orgs:01J0000000000000000000000A",
            "relationship": "owner",
            "status": "active",
            "control_scopes": ["official_badge", "realm_admin"],
            "issued_at": "2026-06-25T00:00:00Z",
            "authorization": {
                "issuer": "did:webvh:example.test:orgs:01J0000000000000000000000A",
                "issuer_role": "organization_did",
                "verification_method": "did:webvh:example.test:orgs:01J0000000000000000000000A#k1",
                "signed_at": "2026-06-25T00:00:00Z",
                "proof": "c2ln"
            }
        })
    }

    #[test]
    fn active_payload_round_trips_and_enum_renames_match_spec() {
        let value = active_value();
        let payload: RealmOrganizationPayload = serde_json::from_value(value).unwrap();
        assert!(payload.is_active_status());
        assert_eq!(payload.relationship, RealmOrganizationRelationship::Owner);
        assert_eq!(
            payload.control_scopes,
            vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin
            ]
        );
        let reserialized = serde_json::to_value(&payload).unwrap();
        assert_eq!(reserialized["status"], json!("active"));
        assert_eq!(reserialized["relationship"], json!("owner"));
        assert_eq!(
            reserialized["authorization"]["issuer_role"],
            json!("organization_did")
        );
        // Optional/absent fields must not be emitted.
        assert!(reserialized.get("expires_at").is_none());
        assert!(reserialized.get("revokes_statement_id").is_none());
    }

    #[test]
    fn validity_window_helpers() {
        let now = DateTime::parse_from_rfc3339("2026-06-25T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut payload: RealmOrganizationPayload = serde_json::from_value(active_value()).unwrap();
        assert!(payload.is_effective_active(now));

        payload.not_before = Some(
            DateTime::parse_from_rfc3339("2026-06-26T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(payload.is_not_yet_valid(now));
        assert!(!payload.is_effective_active(now));

        payload.not_before = None;
        payload.expires_at = Some(
            DateTime::parse_from_rfc3339("2026-06-25T06:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(payload.is_expired(now));
        assert!(!payload.is_effective_active(now));
    }

    #[test]
    fn issuer_role_delegation_requirement() {
        assert!(RealmOrganizationIssuerRole::GovernanceService.requires_delegation_ref());
        assert!(RealmOrganizationIssuerRole::AccountAuthority.requires_delegation_ref());
        assert!(!RealmOrganizationIssuerRole::OrganizationDid.requires_delegation_ref());
        assert!(!RealmOrganizationIssuerRole::ThresholdQuorum.requires_delegation_ref());
    }

    #[test]
    fn legacy_organization_ref_shape_fails_to_deserialize() {
        // The pre-migration singleton shape `{ "organization_ref": ... }` must
        // not deserialize into the relationship-statement strong type.
        let legacy = json!({ "organization_ref": "did:webvh:z6mkfixture:org.example" });
        assert!(serde_json::from_value::<RealmOrganizationPayload>(legacy).is_err());
    }
}
