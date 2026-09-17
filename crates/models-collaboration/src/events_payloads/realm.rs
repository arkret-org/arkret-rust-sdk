//! Realm lifecycle, policy, and organization event payloads.

use std::collections::BTreeSet;

use arkret_models_identity::primary_handle::HandleIssuerPolicyEntry;
use arkret_wire::{ActorId, DidCoreId, DomainSeparationId};

use crate::events_payloads::join_policy::JoinPolicyPayload;
use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::internal_prelude::*;
use crate::objects::media::MediaBackendKind;
use crate::serde_absence::deserialize_non_null_optional;

/// `ak.realm.governance_station.change` payload. The accepted change Event is
/// committed in the Realm stream before the dual-signed authority handoff is
/// usable by any other stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmGovernanceStationChangePayload {
    pub expected_governance_generation: u64,
    pub expected_realm_stream_commit_id: RealmCommitId,
    pub new_governance_station_id: DidCoreId,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/inheritance_policy_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InheritancePolicyStatus {
    Active,
    Tombstoned,
}

/// Patch carried by `ak.realm.owner.transfer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferPatch {
    pub controller_actor_id: ActorId,
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/realm_owner_transfer_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOwnerTransferPayload {
    pub realm_id: RealmId,
    pub expected_state_digest: Hash,
    pub patch: RealmOwnerTransferPatch,
    pub successor_acceptance: SignatureMaterial,
}

impl RealmOwnerTransferPayload {
    pub fn successor_controller_epoch(current: u64) -> Result<u64> {
        const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
        current
            .checked_add(1)
            .filter(|successor| *successor <= JSON_SAFE_INTEGER_MAX)
            .ok_or_else(|| WireError::Protocol("Realm controller_epoch is exhausted".to_owned()))
    }
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/realm_authority_reset_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAuthorityResetPayload {
    pub realm_id: RealmId,
    pub expected_state_digest: Hash,
}

impl RealmAuthorityResetPayload {
    pub fn successor_authority_generation(current: u64) -> Result<u64> {
        const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
        current
            .checked_add(1)
            .filter(|successor| *successor <= JSON_SAFE_INTEGER_MAX)
            .ok_or_else(|| {
                WireError::Protocol("Realm authority_generation is exhausted".to_owned())
            })
    }
}

/// `account_deactivation.member_action` of [`RealmPolicyBundlePayload`].
///
/// The single authority for this closed enum and its outcome semantics is
/// `identity/account-lifecycle.md` §7.1. Absent component means
/// `leave_self_initiated`; an unrecognized value fails closed to
/// `retain_membership` rather than to the default, which is why the enum is
/// closed and a parse failure is not resolved by substituting the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeactivationMemberAction {
    LeaveSelfInitiated,
    RetainMembership,
    LeaveAll,
}

/// `account_deactivation` component of [`RealmPolicyBundlePayload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmAccountDeactivationPolicy {
    pub member_action: AccountDeactivationMemberAction,
}

/// `preauth` component of [`RealmPolicyBundlePayload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPreauthPolicy {
    /// When true, every invite into this Realm MUST pass the holder consent
    /// admission gate in `identity/consent-model.md` §6.1 before the invite
    /// Event is submitted. It MUST NOT be read as permission for a
    /// cross-Realm authority-commit condition.
    pub consent_required: bool,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_policy_bundle_payload`.
///
/// Payload of `ak.realm.policy_bundle`: the payload **is** this flat closed
/// object, not a `state_payload` wrapper. Every revision restates the complete
/// enabled component set. The governance Station commits each replacement as
/// one Realm-stream Event and projections use the latest committed revision.
///
/// The closed property set is exactly the Realm policy components that have
/// **no** independent facet Event kind. Components that own their own kind and
/// cell (`ak.realm.join_rule`, `ak.realm.history_access`,
/// `ak.realm.read_receipt_policy`, `ak.realm.media_service`, …) are written by
/// those events and reach the accepted policy projection through their own
/// typed current result; echoing them here would create a second, drifting
/// truth.
///
/// `policy_revision` is strictly monotonic: the governance Station rejects a
/// rollback or a gap, so a later revision always supersedes an earlier one even
/// when the restated component set repeats a value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/realm_policy_bundle_payload`.
pub struct RealmPolicyBundlePayload {
    pub policy_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    /// Whether a media service listed in `plaintext_visible_services` may
    /// decrypt call media. Absent means `false`. One of three conditions that
    /// MUST all hold (`crypto-media/media-service-binding.md` §8.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_service_decrypts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_policy: Option<JoinPolicyPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_issuer_policies: Option<Vec<HandleIssuerPolicyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_deactivation: Option<RealmAccountDeactivationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preauth: Option<RealmPreauthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_third_party_invite_verification_ids: Option<Vec<DidCoreId>>,
}

impl RealmPolicyBundlePayload {
    /// A bundle revision carrying one component set.
    ///
    /// Every component starts absent, and absent means **disabled**: the cell
    /// is sequenced state, so a revision restates the complete enabled set and
    /// anything not written here is cleared. Authors building the next revision
    /// start from the currently accepted bundle
    /// ([`Self::restate`]) rather than from this constructor.
    pub fn new(policy_revision: u64) -> Self {
        Self {
            policy_revision,
            federation_policy: None,
            media_service_decrypts: None,
            join_policy: None,
            handle_issuer_policies: None,
            agent_participation: None,
            account_deactivation: None,
            preauth: None,
            allowed_third_party_invite_verification_ids: None,
        }
    }

    /// The next revision of an accepted bundle, carrying every component
    /// forward.
    ///
    /// This is the only safe way to author a follow-up revision. Because
    /// `ak.component.realm.policy_bundle.v1` is sequenced state, a revision
    /// that writes only the components it means to change **clears** the rest.
    pub fn restate(&self, policy_revision: u64) -> Self {
        Self {
            policy_revision,
            ..self.clone()
        }
    }

    pub fn media_service_decrypts(&self) -> bool {
        self.media_service_decrypts.unwrap_or(false)
    }

    /// `minProperties: 2` — a revision that enables nothing is a
    /// `schema_violation`, because restating "the complete enabled component
    /// set" as the empty set would silently disable every component.
    pub fn validate(&self) -> Result<()> {
        if self.policy_revision == 0 {
            return Err(WireError::Protocol(
                "realm_policy_bundle_payload.policy_revision must be >= 1 (schema_violation)"
                    .to_owned(),
            ));
        }
        if self.declared_component_count() == 0 {
            return Err(WireError::Protocol(
                "realm_policy_bundle_payload must declare at least one component beside \
                 policy_revision (schema_violation)"
                    .to_owned(),
            ));
        }
        if let Some(service_ids) = &self.allowed_third_party_invite_verification_ids {
            if service_ids.len() > 256 {
                return Err(WireError::Protocol(
                    "realm policy third-party invite verification allowset exceeds 256 services"
                        .to_owned(),
                ));
            }
            if service_ids.iter().collect::<BTreeSet<_>>().len() != service_ids.len() {
                return Err(WireError::Protocol(
                    "realm policy third-party invite verification allowset must be unique"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Components declared beside `policy_revision`.
    ///
    /// Derived from the serialized object rather than from a hand-maintained
    /// chain of `is_none()` tests: a new component added to the struct is
    /// counted automatically, so `minProperties` cannot go stale the way it
    /// did when the payload carried five of the fifteen components.
    fn declared_component_count(&self) -> usize {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_object().map(|object| object.len()))
            .map_or(0, |len| len.saturating_sub(1))
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|err| {
            WireError::Protocol(format!("realm policy bundle payload serialize: {err}"))
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: RealmGenesis,
}

impl RealmCreatePayload {
    pub fn new(object: RealmGenesis) -> Self {
        Self { object }
    }

    pub fn to_value(&self) -> Result<Value> {
        self.object.validate()?;
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm create payload serialize: {err}")))
    }
}

/// Closed Realm identity branch selected by the genesis payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmPurpose {
    Collaboration,
    DirectConversation,
    PrincipalControl,
    AgentControl,
    AppletManagedControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FoundingDeviceKeyAlgorithm {
    Ed25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundingDeviceKeyPurpose {
    EventSigningAndMlsIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FoundingDeviceHpkeKeyAlgorithm {
    X25519,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The descriptor carries the keys themselves, never their digests.
///
/// Review 2026-09-02-1955 deleted `device_key_digest` and `hpke_key_digest`:
/// both are pure functions of members that stay on the wire, so a second copy
/// could only ever disagree with the key it claims to commit to. The receipt
/// side (`pcr_genesis_scope`) still carries them because it carries no raw key;
/// it recomputes them from this descriptor with [`Self::device_key_digest`] and
/// [`Self::hpke_key_digest`].
pub struct FoundingDeviceDescriptor {
    pub descriptor_version: u8,
    pub device_id: DeviceId,
    pub device_public_key_did: NonEmptyString,
    pub device_key_algorithm: FoundingDeviceKeyAlgorithm,
    pub device_key_purpose: FoundingDeviceKeyPurpose,
    pub hpke_key: NonEmptyString,
    pub hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm,
    pub algorithms: Vec<NonEmptyString>,
    pub founding_authorize_payload_digest: Hash,
}

impl FoundingDeviceDescriptor {
    /// `SHA-256(UTF-8(canonical multikey))` over the bare `z6Mk…` string.
    ///
    /// Fixed at SHA-256 by the receipt schema, never the Realm digest suite.
    pub fn device_key_digest(&self) -> Result<Hash> {
        let multikey = self
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| {
                WireError::Protocol(
                    "founding device_public_key_did is not a did:key URI".to_owned(),
                )
            })?;
        Hash::new(canonical::sha256_digest(multikey.as_bytes())).map_err(Into::into)
    }

    /// `SHA-256(UTF-8(canonical multikey))` over `hpke_key` exactly as carried.
    pub fn hpke_key_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(self.hpke_key.as_bytes())).map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.descriptor_version != 1
            || !self.device_public_key_did.as_str().starts_with("did:key:z")
            || self.algorithms.is_empty()
            || self
                .algorithms
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(WireError::Protocol(
                "schema_violation: invalid founding device descriptor".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Minimal immutable identity and authority root carried by `ak.realm.create`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmGenesis {
    pub schema: String,
    pub purpose: RealmPurpose,
    pub genesis_salt: GenesisSalt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub founding_device_descriptor: Option<FoundingDeviceDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_resolution: Option<arkret_models_identity::ResolutionCommitment>,
    pub trust_domain: TrustDomainId,
    pub security_class: SecurityClass,
    pub governance_station_id: DidCoreId,
    pub initial_join_rule: JoinRule,
    pub initial_history_access: HistoryAccess,
    pub initial_discoverability: Discoverability,
}

impl RealmGenesis {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose: RealmPurpose,
        genesis_salt: GenesisSalt,
        trust_domain: TrustDomainId,
        security_class: SecurityClass,
        governance_station_id: DidCoreId,
        initial_join_rule: JoinRule,
        initial_history_access: HistoryAccess,
        initial_discoverability: Discoverability,
        founding_device_descriptor: Option<FoundingDeviceDescriptor>,
        initial_resolution: Option<arkret_models_identity::ResolutionCommitment>,
    ) -> Result<Self> {
        let value = Self {
            schema: SchemaId::REALM_GENESIS_V1.to_owned(),
            purpose,
            genesis_salt,
            founding_device_descriptor,
            initial_resolution,
            trust_domain,
            security_class,
            governance_station_id,
            initial_join_rule,
            initial_history_access,
            initial_discoverability,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        let identity_control = matches!(
            self.purpose,
            RealmPurpose::PrincipalControl
                | RealmPurpose::AgentControl
                | RealmPurpose::AppletManagedControl
        );
        if self.schema != SchemaId::REALM_GENESIS_V1
            || identity_control != self.initial_resolution.is_some()
            || (self.purpose == RealmPurpose::PrincipalControl)
                != self.founding_device_descriptor.is_some()
        {
            return Err(WireError::Protocol(
                "schema_violation: invalid Realm genesis identity branch".to_owned(),
            ));
        }
        if let Some(descriptor) = &self.founding_device_descriptor {
            descriptor.validate()?;
        }
        if let Some(resolution) = &self.initial_resolution
            && (resolution.method_history_head.is_empty()
                || resolution.version_id.is_empty()
                || project_did_to_core_id(&resolution.did).is_err())
        {
            return Err(WireError::Protocol(
                "schema_violation: invalid initial identity resolution".to_owned(),
            ));
        }
        Ok(())
    }
}
/// Complete value of the Realm display-profile singleton cell.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmProfile {
    pub schema: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

impl RealmProfile {
    pub fn new(title: impl Into<String>) -> Result<Self> {
        let title = title.into();
        if title.is_empty() {
            return Err(WireError::Protocol(
                "realm profile title must not be empty (schema_violation)".to_owned(),
            ));
        }
        Ok(Self {
            schema: SchemaId::REALM_PROFILE_V1.to_owned(),
            title,
            summary: None,
            avatar_blob_ref: None,
        })
    }

    pub fn to_value(&self) -> Result<Value> {
        if self.schema != SchemaId::REALM_PROFILE_V1 || self.title.is_empty() {
            return Err(WireError::Protocol(
                "schema_violation: invalid Realm profile".to_owned(),
            ));
        }
        serde_json::to_value(self)
            .map_err(|error| WireError::Protocol(format!("Realm profile serialize: {error}")))
    }
}

// `realm_destroy_payload` uses `models::operation_payloads::RealmDestroyPayload`.

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RealmFreezePayload {
    pub fn new() -> Self {
        Self { reason: None }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        if !reason.trim().is_empty() {
            self.reason = Some(reason);
        }
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| WireError::Protocol(format!("realm freeze payload serialize: {err}")))
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationRelationship {
    Owner,
    Governance,
    Sponsor,
    DirectoryCertifier,
}

/// `status` discriminator for [`RealmOrganizationPayload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationStatus {
    Active,
    Revoked,
}

/// `control_scopes[]` item enum for [`RealmOrganizationPayload`]. A scope is an
/// endorsement boundary only; actual Realm control still requires the matching
/// Realm policy, governance-Station authority, capability or service-binding
/// Event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationControlScope {
    OfficialBadge,
    RealmAdmin,
    RealmAuthority,
    ModerationPolicy,
    RetentionPolicy,
    DirectoryListing,
    PlaintextVisibleService,
}

/// `authorization.issuer_role` enum for [`RealmOrganizationAuthorization`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationIssuerRole {
    Organization,
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
    pub issuer_id: DidCoreId,
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
    pub executed_by: Option<DidCoreId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
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
    pub organization_id: DidCoreId,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    /// Machine-readable scopes covered by the organization's consent
    /// (non-empty, unique).
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    /// Nullable expiry — `Some(None)` and absence both mean "no expiry".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    /// REQUIRED when `status == revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    /// Optional authority commit the organization evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_commit_ref: Option<RealmCommitId>,
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

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_ids: Vec<DidCoreId>,
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

// `realm_tombstone_payload` uses `models::operation_payloads::RealmTombstonePayload`.

// `relation_create_payload` uses `models::operation_payloads::RelationCreatePayload`.

/// Transcript discriminator for the bytes an organization-side proof signs over.
pub const ORGANIZATION_STATEMENT_TRANSCRIPT_KIND: &str =
    DomainSeparationId::REALM_ORGANIZATION_STATEMENT_V1;

/// Canonical transcript the organization-side proof signs over. Every statement
/// field except `authorization.proof` (the signature itself) and the redundant
/// `signed_at` is included, so a verifier can rebuild the exact bytes from the
/// wire statement. Optional fields are omitted when absent so the bytes are
/// stable.
#[derive(Debug, Serialize)]
struct OrganizationStatementTranscript<'a> {
    kind: &'a str,
    statement_id: &'a str,
    realm_id: &'a RealmId,
    organization_id: &'a DidCoreId,
    relationship: &'a RealmOrganizationRelationship,
    status: &'a RealmOrganizationStatus,
    control_scopes: &'a [RealmOrganizationControlScope],
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revokes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_commit_ref: Option<&'a RealmCommitId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_policy_ref: Option<&'a ObjectRef>,
    issuer: &'a DidCoreId,
    issuer_role: &'a RealmOrganizationIssuerRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_ref: Option<&'a ObjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: Option<&'a DidCoreId>,
}

/// Canonical bytes the organization-side `authorization.proof` signs over.
///
/// Both the issuing side (coauth) and the verifying side (soland) MUST derive
/// the signing input from this one function so the bytes are byte-identical.
/// The transcript binds every semantic field of the statement except the proof
/// itself, so a detached signature over these bytes authenticates the whole
/// statement. The signing key MUST be a verification method in the
/// `organization_id` DID document (`authorization.verification_method`); the
/// verifier resolves that document and checks the signature.
pub fn realm_organization_statement_signing_bytes(
    payload: &RealmOrganizationPayload,
) -> Result<Vec<u8>> {
    let authorization = &payload.authorization;
    let transcript = OrganizationStatementTranscript {
        kind: ORGANIZATION_STATEMENT_TRANSCRIPT_KIND,
        statement_id: &payload.statement_id,
        realm_id: &payload.realm_id,
        organization_id: &payload.organization_id,
        relationship: &payload.relationship,
        status: &payload.status,
        control_scopes: &payload.control_scopes,
        issued_at: payload.issued_at,
        not_before: payload.not_before,
        expires_at: payload.expires_at,
        supersedes_statement_id: payload.supersedes_statement_id.as_ref(),
        revokes_statement_id: payload.revokes_statement_id.as_ref(),
        realm_commit_ref: payload.realm_commit_ref.as_ref(),
        organization_policy_ref: payload.organization_policy_ref.as_ref(),
        issuer: &authorization.issuer_id,
        issuer_role: &authorization.issuer_role,
        delegation_ref: authorization.delegation_ref.as_ref(),
        executed_by: authorization.executed_by.as_ref(),
    };
    Ok(canonical::canonical_json_bytes(&transcript)?)
}

/// Deployment roles supported by one Realm media service.
///
/// Mirrors the closed `modes[]` enum of
/// `event-payload.schema.json#/$defs/realm_media_service_payload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmMediaServiceMode {
    Turn,
    Sfu,
    Mcu,
}

/// Call topologies a Realm media service may default to or allow.
///
/// Mirrors the closed `default_call_mode` / `allowed_call_modes[]` enum of
/// `event-payload.schema.json#/$defs/realm_media_service_payload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmMediaCallMode {
    P2p,
    Sfu,
    Mcu,
}

/// One backend focus of the Realm media service descriptor.
///
/// `focus_kind` is the closed backend registry ([`MediaBackendKind`]); an
/// unknown label fails to deserialize instead of surviving as a catch-all, so a
/// receiver fails closed with
/// [`ReasonCode::UNKNOWN_FOCUS_TYPE`](arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE)
/// rather than handing `backend_token` to an arbitrary SDK. `token_endpoint`
/// and `connect_url` are required because a focus a client can neither exchange
/// a token at nor connect to is not a usable focus. See
/// `crypto-media/media-service-binding.md` section 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/media_service_focus`.
pub struct MediaServiceFocus {
    pub focus_id: NonEmptyString,
    pub focus_kind: MediaBackendKind,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub region: Option<NonEmptyString>,
    pub token_endpoint: String,
    pub connect_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<NonEmptyString>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub health_endpoint: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub cascade_group: Option<NonEmptyString>,
}

impl MediaServiceFocus {
    /// Enforces the profile constraints the derived `Deserialize` cannot carry:
    /// the `non_typed_identifier_floor` on `focus_id` and the URL scheme
    /// patterns on the three endpoint fields.
    pub fn validate(&self) -> Result<()> {
        if self.focus_id.as_str().starts_with("ak:") {
            return media_schema_violation("media service focus_id must not use the ak: namespace");
        }
        if !is_url_with_scheme(&self.token_endpoint, "https://") {
            return media_schema_violation("media service token_endpoint must be an https URL");
        }
        if !is_url_with_allowed_schemes(&self.connect_url, &["https://", "wss://"]) {
            return media_schema_violation("media service connect_url must be an https or wss URL");
        }
        if self
            .health_endpoint
            .as_deref()
            .is_some_and(|url| !is_url_with_scheme(url, "https://"))
        {
            return media_schema_violation("media service health_endpoint must be an https URL");
        }
        if contains_duplicate(&self.capabilities) {
            return media_schema_violation("media service focus capabilities must be unique");
        }
        Ok(())
    }
}

/// Closed media service descriptor carried under
/// [`RealmMediaServicePayload::value`].
///
/// The descriptor is the trust root for media token issuance, so it is closed
/// on purpose: issuer configuration (signing key ids, audiences, TTLs, backend
/// credentials) is deployment configuration of the service named by
/// `foci[].token_endpoint` and MUST NOT be carried here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/realm_media_service_payload` `value`.
pub struct RealmMediaServiceValue {
    pub service_id: DidCoreId,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub modes: Option<Vec<RealmMediaServiceMode>>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub ice_config_endpoint: Option<String>,
    pub foci: Vec<MediaServiceFocus>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_call_mode: Option<RealmMediaCallMode>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_call_modes: Option<Vec<RealmMediaCallMode>>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub recording_supported: Option<bool>,
}

impl RealmMediaServiceValue {
    /// A descriptor with a single flat endpoint, or with no foci at all, fails
    /// closed with [`ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED`]; the realtime
    /// path MUST NOT normalize or infer one.
    pub fn validate(&self) -> Result<()> {
        if self
            .modes
            .as_ref()
            .is_some_and(|modes| modes.is_empty() || contains_duplicate(modes))
        {
            return media_schema_violation("media service modes must be non-empty and unique");
        }
        if self
            .ice_config_endpoint
            .as_deref()
            .is_some_and(|url| !is_url_with_scheme(url, "https://"))
        {
            return media_schema_violation(
                "media service ice_config_endpoint must be an https URL",
            );
        }
        if self.foci.is_empty() || contains_duplicate(&self.foci) {
            return Err(WireError::Protocol(format!(
                "{}: media service foci must be non-empty and unique",
                ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED
            )));
        }
        for focus in &self.foci {
            focus.validate()?;
        }
        if self
            .allowed_call_modes
            .as_ref()
            .is_some_and(|modes| modes.is_empty() || contains_duplicate(modes))
        {
            return media_schema_violation(
                "media service allowed_call_modes must be non-empty and unique",
            );
        }
        Ok(())
    }
}

/// `ak.realm.media_service` payload.
///
/// The descriptor lives under `payload.value` and is never flattened onto
/// `payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/realm_media_service_payload`.
pub struct RealmMediaServicePayload {
    pub value: RealmMediaServiceValue,
}

impl RealmMediaServicePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

fn media_schema_violation<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(format!("schema_violation: {message}")))
}

fn contains_duplicate<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn is_url_with_allowed_schemes(value: &str, schemes: &[&str]) -> bool {
    schemes
        .iter()
        .any(|scheme| is_url_with_scheme(value, scheme))
}

fn is_url_with_scheme(value: &str, scheme: &str) -> bool {
    value
        .strip_prefix(scheme)
        .is_some_and(|rest| !rest.is_empty() && !rest.chars().any(char::is_whitespace))
}

#[cfg(test)]
mod media_service_tests {
    use super::*;

    fn focus_json() -> Value {
        serde_json::json!({
            "focus_id": "focus-eu-1",
            "focus_kind": "livekit",
            "region": "eu-west",
            "token_endpoint": "https://media.example/token",
            "connect_url": "wss://media.example/rtc",
            "capabilities": ["simulcast", "svc"],
            "health_endpoint": "https://media.example/health",
            "cascade_group": "eu"
        })
    }

    #[test]
    fn media_service_focus_round_trips_every_property() {
        let json = focus_json();
        let focus: MediaServiceFocus = serde_json::from_value(json.clone()).unwrap();
        focus.validate().unwrap();
        assert_eq!(focus.focus_kind, MediaBackendKind::Livekit);
        assert_eq!(serde_json::to_value(&focus).unwrap(), json);
    }

    #[test]
    fn media_service_focus_omits_absent_optional_members() {
        let focus: MediaServiceFocus = serde_json::from_value(serde_json::json!({
            "focus_id": "focus-1",
            "focus_kind": "arkret_native",
            "token_endpoint": "https://media.example/token",
            "connect_url": "https://media.example/rtc"
        }))
        .unwrap();
        focus.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&focus).unwrap(),
            serde_json::json!({
                "focus_id": "focus-1",
                "focus_kind": "arkret_native",
                "token_endpoint": "https://media.example/token",
                "connect_url": "https://media.example/rtc"
            })
        );
    }

    #[test]
    fn media_service_focus_rejects_unknown_member() {
        let mut json = focus_json();
        json["sfu_endpoint"] = serde_json::json!("https://media.example/sfu");
        serde_json::from_value::<MediaServiceFocus>(json).unwrap_err();
    }

    #[test]
    fn media_service_focus_rejects_missing_required_member() {
        for required in ["focus_id", "focus_kind", "token_endpoint", "connect_url"] {
            let mut json = focus_json();
            json.as_object_mut().unwrap().remove(required);
            serde_json::from_value::<MediaServiceFocus>(json)
                .expect_err("required member omission must be rejected");
        }
    }

    #[test]
    fn media_service_focus_kind_registry_is_closed() {
        for known in [
            "livekit",
            "mediasoup",
            "janus",
            "arkret_native",
            "moq_relay",
        ] {
            let mut json = focus_json();
            json["focus_kind"] = serde_json::json!(known);
            serde_json::from_value::<MediaServiceFocus>(json).unwrap();
        }
        let mut json = focus_json();
        json["focus_kind"] = serde_json::json!("whip");
        serde_json::from_value::<MediaServiceFocus>(json)
            .expect_err("unknown focus_kind must fail closed");
    }

    #[test]
    fn media_service_focus_validate_rejects_bad_profiles() {
        let mut json = focus_json();
        json["focus_id"] = serde_json::json!("ak:focus");
        serde_json::from_value::<MediaServiceFocus>(json)
            .unwrap()
            .validate()
            .unwrap_err();

        let mut json = focus_json();
        json["token_endpoint"] = serde_json::json!("http://media.example/token");
        serde_json::from_value::<MediaServiceFocus>(json)
            .unwrap()
            .validate()
            .unwrap_err();

        let mut json = focus_json();
        json["connect_url"] = serde_json::json!("ws://media.example/rtc");
        serde_json::from_value::<MediaServiceFocus>(json)
            .unwrap()
            .validate()
            .unwrap_err();
    }

    #[test]
    fn realm_media_service_payload_round_trips_and_requires_foci() {
        let json = serde_json::json!({
            "value": {
                "service_id": "ak:did_core:web:media.example",
                "modes": ["sfu"],
                "ice_config_endpoint": "https://media.example/ice",
                "foci": [focus_json()],
                "default_call_mode": "sfu",
                "allowed_call_modes": ["p2p", "sfu"],
                "recording_supported": false
            }
        });
        let payload: RealmMediaServicePayload = serde_json::from_value(json.clone()).unwrap();
        payload.validate().unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), json);

        let mut empty = json;
        empty["value"]["foci"] = serde_json::json!([]);
        let payload: RealmMediaServicePayload = serde_json::from_value(empty).unwrap();
        let message = payload.validate().unwrap_err().to_string();
        assert!(message.contains(ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED));
    }
}
