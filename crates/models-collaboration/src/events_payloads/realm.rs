//! Realm lifecycle, policy, and organization event payloads.

use std::collections::BTreeSet;

use arkret_models_identity::primary_handle::HandleIssuerPolicyEntry;
use arkret_wire::{ActorId, DidCoreId, DomainSeparationId};

use crate::events_payloads::join_policy::JoinPolicyPayload;
use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::internal_prelude::*;

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
    pub controller_id: ActorId,
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
    pub destructive_confirmation: String,
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

/// `mls_send_pause` value of [`RealmPolicyBundlePayload`].
///
/// A closed one-value enum rather than a `bool`: `advisory` downgrades the MLS
/// send pause from MUST to SHOULD and is only accepted when the Realm declares
/// `ak.profile.e2ee_relaxed.v1`; omitting the field in a later revision reverts
/// to the strict default, which has no token of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsSendPause {
    Advisory,
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
    /// Control Move is submitted. It MUST NOT be read as permission for a
    /// cross-Realm CBA precondition.
    pub consent_required: bool,
}

/// Absolute ceiling on `relaxed_window_max_ms`
/// (`crypto-media/encryption-and-audit.md` §2.4.1).
///
/// Deliberately **not** enforced by the wire type: the schema leaves the field
/// unbounded above so an over-ceiling value reaches the reducer and surfaces as
/// `relaxed_window_exceeds_ceiling`. A type that clamped or rejected here would
/// turn that into `schema_violation`, or worse, into a silent truncation.
pub const RELAXED_WINDOW_MAX_MS_CEILING: u64 = 300_000;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_policy_bundle_payload`.
///
/// Payload of `ak.realm.policy_bundle`: the payload **is** this flat closed
/// object, not a `state_payload` wrapper. Every revision restates the complete
/// enabled component set, because the bundle is written wholesale into the
/// `ak.component.realm.policy_bundle.v1` `cas_register` cell and the Realm
/// object's derived policy fields re-derive from the latest accepted bundle.
///
/// The closed property set is exactly the Realm policy components that have
/// **no** independent facet Event kind. Components that own their own kind and
/// cell (`ak.realm.join_rule`, `ak.realm.history_access`,
/// `ak.realm.read_receipt_policy`, `ak.realm.media_service`, …) are written by
/// those events and already reach `policy_root` through the
/// `ak.component.realm.*policy*` leaf filter; echoing them here would create a
/// second, drifting truth.
///
/// `content_scheme` and `durability_policy` are **not** members: both are
/// frozen by the accepted MLS group Genesis and are read from that exact group
/// state (`models/realm-and-space.md` sections 2.3 and 2.3.1). The closed
/// schema omits them, so a bundle that restated either value would create a
/// second, mutable truth for a create-locked field.
///
/// `policy_revision` is strictly monotonic and is what gives this cell family a
/// generation dimension inside its value — `cas_register` supersession binds by
/// value, so a family that can otherwise repeat a value needs one
/// (`event-auth-state-resolution.md` §9.3.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `event-payload.schema.json#/$defs/realm_policy_bundle_payload`.
pub struct RealmPolicyBundlePayload {
    pub policy_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_encryption_floor: Option<EncryptionFloor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_send_pause: Option<MlsSendPause>,
    /// Declared `ak.profile.e2ee_relaxed.v1` removed-member decryption window.
    /// Absent means the spec default of 30000 ms.
    ///
    /// A value above [`RELAXED_WINDOW_MAX_MS_CEILING`] is representable on
    /// purpose: the reducer and every receiver reject it with
    /// `relaxed_window_exceeds_ceiling`, and MUST NOT silently clamp it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relaxed_window_max_ms: Option<u64>,
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
    pub availability_policy: Option<RealmAvailabilityPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_policy: Option<RealmAuditPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_witness_freshness_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_intake_sla_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_decision_window_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_absolute_deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_proposal_defers: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_compaction_max_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_authority_lifetime_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom_escalation_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_lattices: Option<Vec<CellLatticeDeclaration>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preauth: Option<RealmPreauthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_third_party_invite_verification_ids: Option<Vec<DidCoreId>>,
}

impl RealmPolicyBundlePayload {
    /// A bundle revision carrying one component set.
    ///
    /// Every component starts absent, and absent means **disabled**: the cell
    /// is a `cas_register`, so a revision restates the complete enabled set and
    /// anything not written here is cleared. Authors building the next revision
    /// start from the currently accepted bundle
    /// ([`Self::restate`]) rather than from this constructor.
    pub fn new(policy_revision: u64) -> Self {
        Self {
            policy_revision,
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            federation_policy: None,
            mls_send_pause: None,
            relaxed_window_max_ms: None,
            media_service_decrypts: None,
            join_policy: None,
            handle_issuer_policies: None,
            agent_participation: None,
            account_deactivation: None,
            availability_policy: None,
            audit_policy: None,
            revocation_freshness_window_ms: None,
            recovery_witness_freshness_window_ms: None,
            proposal_intake_sla_ms: None,
            proposal_decision_window_ms: None,
            proposal_absolute_deadline_ms: None,
            max_proposal_defers: None,
            seal_compaction_max_interval_ms: None,
            max_authority_lifetime_ms: None,
            bottom_escalation_after_ms: None,
            cell_lattices: None,
            preauth: None,
            allowed_third_party_invite_verification_ids: None,
        }
    }

    /// The next revision of an accepted bundle, carrying every component
    /// forward.
    ///
    /// This is the only safe way to author a follow-up revision. Because
    /// `ak.component.realm.policy_bundle.v1` is a `cas_register`, a revision
    /// that writes only the components it means to change **clears** the rest.
    pub fn restate(&self, policy_revision: u64) -> Self {
        Self {
            policy_revision,
            ..self.clone()
        }
    }

    /// Whether `relaxed_window_max_ms` is above the absolute ceiling.
    ///
    /// Callers reject with `relaxed_window_exceeds_ceiling`; they MUST NOT
    /// truncate to the ceiling and continue.
    pub fn relaxed_window_exceeds_ceiling(&self) -> bool {
        self.relaxed_window_max_ms
            .is_some_and(|value| value > RELAXED_WINDOW_MAX_MS_CEILING)
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
        self.control_proposal_decision_policy()?;
        Ok(())
    }

    /// Resolve the Control Proposal timing policy carried by this complete
    /// policy-bundle revision, applying the protocol defaults for omitted
    /// fields.
    pub fn control_proposal_decision_policy(&self) -> Result<ControlProposalDecisionPolicy> {
        let defaults = ControlProposalDecisionPolicy::default();
        let duration_ms =
            |value: Option<u64>, fallback: chrono::Duration| -> Result<chrono::Duration> {
                let millis = value.unwrap_or_else(|| fallback.num_milliseconds() as u64);
                let millis = i64::try_from(millis).map_err(|_| {
                    WireError::Protocol(
                    "Realm proposal decision duration exceeds i64 milliseconds (schema_violation)"
                        .to_owned(),
                )
                })?;
                Ok(chrono::Duration::milliseconds(millis))
            };
        let policy = ControlProposalDecisionPolicy {
            proposal_intake_sla: duration_ms(
                self.proposal_intake_sla_ms,
                defaults.proposal_intake_sla,
            )?,
            decision_window: duration_ms(
                self.proposal_decision_window_ms,
                defaults.decision_window,
            )?,
            absolute_horizon: duration_ms(
                self.proposal_absolute_deadline_ms,
                defaults.absolute_horizon,
            )?,
            max_defers: self.max_proposal_defers.unwrap_or(defaults.max_defers),
        };
        policy.validate()?;
        Ok(policy)
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

/// Minimal immutable identity and security interpretation root carried by
/// `ak.realm.create`.
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
    pub schema_refs: Vec<String>,
    pub reducer_profile: String,
    pub digest_algorithm: canonical::DigestSuite,
    pub security_class: SecurityClass,
    pub encryption_profile: EncryptionProfile,
    pub notary: NotaryValue,
}

impl RealmGenesis {
    #[allow(clippy::too_many_arguments)]
    pub fn event_derived(
        purpose: RealmPurpose,
        genesis_salt: GenesisSalt,
        trust_domain: TrustDomainId,
        schema_refs: Vec<String>,
        reducer_profile: impl Into<String>,
        digest_algorithm: canonical::DigestSuite,
        security_class: SecurityClass,
        encryption_profile: EncryptionProfile,
        notary: NotaryValue,
    ) -> Result<Self> {
        let value = Self {
            schema: SchemaId::REALM_GENESIS_V1.to_owned(),
            purpose,
            genesis_salt,
            founding_device_descriptor: None,
            initial_resolution: None,
            trust_domain,
            schema_refs,
            reducer_profile: reducer_profile.into(),
            digest_algorithm,
            security_class,
            encryption_profile,
            notary,
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn principal_control(
        genesis_salt: GenesisSalt,
        founding_device_descriptor: Option<FoundingDeviceDescriptor>,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        trust_domain: TrustDomainId,
        schema_refs: Vec<String>,
        reducer_profile: impl Into<String>,
        digest_algorithm: canonical::DigestSuite,
        security_class: SecurityClass,
        encryption_profile: EncryptionProfile,
        notary: NotaryValue,
    ) -> Result<Self> {
        let value = Self {
            schema: SchemaId::REALM_GENESIS_V1.to_owned(),
            purpose: RealmPurpose::PrincipalControl,
            genesis_salt,
            founding_device_descriptor,
            initial_resolution: Some(initial_resolution),
            trust_domain,
            schema_refs,
            reducer_profile: reducer_profile.into(),
            digest_algorithm,
            security_class,
            encryption_profile,
            notary,
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn agent_control(
        genesis_salt: GenesisSalt,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        trust_domain: TrustDomainId,
        schema_refs: Vec<String>,
        reducer_profile: impl Into<String>,
        digest_algorithm: canonical::DigestSuite,
        security_class: SecurityClass,
        encryption_profile: EncryptionProfile,
        notary: NotaryValue,
    ) -> Result<Self> {
        let value = Self {
            schema: SchemaId::REALM_GENESIS_V1.to_owned(),
            purpose: RealmPurpose::AgentControl,
            genesis_salt,
            founding_device_descriptor: None,
            initial_resolution: Some(initial_resolution),
            trust_domain,
            schema_refs,
            reducer_profile: reducer_profile.into(),
            digest_algorithm,
            security_class,
            encryption_profile,
            notary,
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn applet_managed_control(
        genesis_salt: GenesisSalt,
        initial_resolution: arkret_models_identity::ResolutionCommitment,
        trust_domain: TrustDomainId,
        schema_refs: Vec<String>,
        reducer_profile: impl Into<String>,
        digest_algorithm: canonical::DigestSuite,
        security_class: SecurityClass,
        encryption_profile: EncryptionProfile,
        notary: NotaryValue,
    ) -> Result<Self> {
        let value = Self {
            schema: SchemaId::REALM_GENESIS_V1.to_owned(),
            purpose: RealmPurpose::AppletManagedControl,
            genesis_salt,
            founding_device_descriptor: None,
            initial_resolution: Some(initial_resolution),
            trust_domain,
            schema_refs,
            reducer_profile: reducer_profile.into(),
            digest_algorithm,
            security_class,
            encryption_profile,
            notary,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::REALM_GENESIS_V1
            || self.schema_refs.is_empty()
            || self.reducer_profile.is_empty()
            || (!matches!(self.purpose, RealmPurpose::PrincipalControl)
                && self.founding_device_descriptor.is_some())
            || (self.purpose == RealmPurpose::PrincipalControl && self.initial_resolution.is_none())
            || (!matches!(
                self.purpose,
                RealmPurpose::PrincipalControl
                    | RealmPurpose::AgentControl
                    | RealmPurpose::AppletManagedControl
            ) && self.initial_resolution.is_some())
            || (matches!(
                self.purpose,
                RealmPurpose::AgentControl | RealmPurpose::AppletManagedControl
            ) && self.founding_device_descriptor.is_some())
            || (matches!(
                self.purpose,
                RealmPurpose::PrincipalControl
                    | RealmPurpose::AgentControl
                    | RealmPurpose::AppletManagedControl
            ) != self.initial_resolution.is_some())
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
        self.notary.validate()?;
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

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_notary_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmNotaryPayload {
    pub realm_id: RealmId,
    pub notary: NotaryValue,
}

impl RealmNotaryPayload {
    pub fn validate(&self) -> Result<()> {
        self.notary.validate()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// realm_digest_suite_transition_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDigestSuiteTransitionPayload {
    pub from_digest_algorithm: canonical::DigestSuite,
    pub to_digest_algorithm: canonical::DigestSuite,
    pub transition_snapshot_ref: SnapshotId,
    pub snapshot_commitment: Hash,
}

impl RealmDigestSuiteTransitionPayload {
    pub fn validate(&self) -> Result<()> {
        if self.from_digest_algorithm == self.to_digest_algorithm {
            return Err(WireError::Protocol(
                "realm digest suite transition must change digest_algorithm (schema_violation)"
                    .to_owned(),
            ));
        }
        if matches!(
            (&self.from_digest_algorithm, &self.to_digest_algorithm),
            (
                canonical::DigestSuite::Blake3,
                canonical::DigestSuite::Sha256
            )
        ) {
            return Err(WireError::Protocol(
                "realm digest suite transition must not downgrade hash strength (schema_violation)"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

// `realm_destroy_payload` uses `models::operation_payloads::RealmDestroyPayload`.

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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

#[cfg(test)]
mod inheritance_policy_status_tests {
    use super::InheritancePolicyStatus;

    #[test]
    fn status_is_the_closed_schema_enum() {
        assert_eq!(
            serde_json::to_value(InheritancePolicyStatus::Active).unwrap(),
            "active"
        );
        assert!(serde_json::from_str::<InheritancePolicyStatus>(r#""retired""#).is_err());
    }
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
/// Realm policy / notary / capability / service-binding event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationControlScope {
    OfficialBadge,
    RealmAdmin,
    NotaryControl,
    DurabilityPolicy,
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
    realm_frontier_digest: Option<&'a Hash>,
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
        realm_frontier_digest: payload.realm_frontier_digest.as_ref(),
        organization_policy_ref: payload.organization_policy_ref.as_ref(),
        issuer: &authorization.issuer_id,
        issuer_role: &authorization.issuer_role,
        delegation_ref: authorization.delegation_ref.as_ref(),
        executed_by: authorization.executed_by.as_ref(),
    };
    Ok(canonical::canonical_json_bytes(&transcript)?)
}
#[cfg(test)]
mod realm_control_payload_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_notary_payload_is_closed_and_validated() {
        let value = json!({
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "notary": {
                "kind": "single_signer",
                "signer": {
                    "actor_id": {
                        "kind": "service",
                        "service_id": "ak:did_core:web:notary.example"
                    },
                    "verification_method": "did:web:notary.example#key-1",
                    "key_kind": "ed25519_raw32",
                    "jose_algorithm": "Ed25519",
                    "frozen_public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "frozen_public_key_digest": "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
                }
            }
        });
        let payload: RealmNotaryPayload = serde_json::from_value(value.clone()).unwrap();
        payload.validate().unwrap();

        let mut unknown = value;
        unknown["notary"]["endpoint"] = json!("https://notary.example");
        assert!(serde_json::from_value::<RealmNotaryPayload>(unknown).is_err());
    }

    #[test]
    fn digest_suite_transition_rejects_noop_and_downgrade() {
        let value = json!({
            "from_digest_algorithm": "sha256",
            "to_digest_algorithm": "blake3",
            "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000002",
            "snapshot_commitment": format!("sha256:{}", "a".repeat(64))
        });
        let payload: RealmDigestSuiteTransitionPayload =
            serde_json::from_value(value.clone()).unwrap();
        payload.validate().unwrap();

        let mut noop = value.clone();
        noop["to_digest_algorithm"] = json!("sha256");
        let noop: RealmDigestSuiteTransitionPayload = serde_json::from_value(noop).unwrap();
        assert!(noop.validate().is_err());

        let mut downgrade = value;
        downgrade["from_digest_algorithm"] = json!("blake3");
        downgrade["to_digest_algorithm"] = json!("sha256");
        let downgrade: RealmDigestSuiteTransitionPayload =
            serde_json::from_value(downgrade).unwrap();
        assert!(downgrade.validate().is_err());
    }
}
#[cfg(test)]
mod realm_organization_tests {
    use serde_json::json;

    use super::*;

    fn active_value() -> Value {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "organization_id": "ak:did_core:webvh:example.test",
            "relationship": "owner",
            "status": "active",
            "control_scopes": ["official_badge", "realm_admin"],
            "issued_at": "2026-06-25T00:00:00.000Z",
            "authorization": {
                "issuer_id": "ak:did_core:webvh:example.test",
                "issuer_role": "organization",
                "verification_method": "did:webvh:example.test:orgs:01J0000000000000000000000A#k1",
                "signed_at": "2026-06-25T00:00:00.000Z",
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
            json!("organization")
        );
        // Optional/absent fields must not be emitted.
        assert!(reserialized.get("expires_at").is_none());
        assert!(reserialized.get("revokes_statement_id").is_none());
    }

    #[test]
    fn validity_window_helpers() {
        let now = DateTime::parse_from_rfc3339("2026-06-25T12:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut payload: RealmOrganizationPayload = serde_json::from_value(active_value()).unwrap();
        assert!(payload.is_effective_active(now));

        payload.not_before = Some(
            DateTime::parse_from_rfc3339("2026-06-26T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(payload.is_not_yet_valid(now));
        assert!(!payload.is_effective_active(now));

        payload.not_before = None;
        payload.expires_at = Some(
            DateTime::parse_from_rfc3339("2026-06-25T06:00:00.000Z")
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
        assert!(!RealmOrganizationIssuerRole::Organization.requires_delegation_ref());
        assert!(!RealmOrganizationIssuerRole::ThresholdQuorum.requires_delegation_ref());
    }
}

#[cfg(test)]
mod realm_policy_bundle_tests {
    use super::*;

    fn declared_bundle() -> RealmPolicyBundlePayload {
        let mut bundle = RealmPolicyBundlePayload::new(3);
        bundle.media_service_decrypts = Some(true);
        bundle
    }

    #[test]
    fn restating_a_revision_carries_every_component_forward() {
        // The cas_register hazard: a next revision that only writes what it
        // changes clears everything else. `restate` is the safe author path.
        let accepted = declared_bundle();
        let next = accepted.restate(4);
        assert_eq!(next.policy_revision, 4);
        assert!(next.media_service_decrypts());
    }

    #[test]
    fn an_over_ceiling_relaxed_window_survives_the_type_and_is_flagged() {
        // 300001 MUST reach the reducer as relaxed_window_exceeds_ceiling, so
        // the type neither rejects nor clamps it.
        let mut bundle = RealmPolicyBundlePayload::new(2);
        bundle.relaxed_window_max_ms = Some(RELAXED_WINDOW_MAX_MS_CEILING + 1);
        bundle
            .validate()
            .expect("an over-ceiling window is not a schema_violation");
        assert_eq!(
            bundle.relaxed_window_max_ms,
            Some(RELAXED_WINDOW_MAX_MS_CEILING + 1),
            "the value must not be truncated to the ceiling"
        );
        assert!(bundle.relaxed_window_exceeds_ceiling());

        let mut at_ceiling = RealmPolicyBundlePayload::new(2);
        at_ceiling.relaxed_window_max_ms = Some(RELAXED_WINDOW_MAX_MS_CEILING);
        assert!(!at_ceiling.relaxed_window_exceeds_ceiling());
    }

    #[test]
    fn a_revision_that_enables_nothing_is_a_schema_violation() {
        assert!(RealmPolicyBundlePayload::new(1).validate().is_err());
        assert!(RealmPolicyBundlePayload::new(0).validate().is_err());
        // The min-properties count is derived from the serialized object, so a
        // component added later is counted without editing `validate`.
        let mut only_preauth = RealmPolicyBundlePayload::new(1);
        only_preauth.preauth = Some(RealmPreauthPolicy {
            consent_required: true,
        });
        only_preauth.validate().unwrap();
    }

    #[test]
    fn governance_timing_fields_have_one_typed_policy_bundle_carrier() {
        let mut bundle = RealmPolicyBundlePayload::new(1);
        bundle.proposal_intake_sla_ms = Some(5_000);
        bundle.proposal_decision_window_ms = Some(30_000);
        bundle.proposal_absolute_deadline_ms = Some(90_000);
        bundle.max_proposal_defers = Some(2);
        bundle.revocation_freshness_window_ms = Some(60_000);
        bundle.max_authority_lifetime_ms = Some(120_000);
        let value = bundle.to_value().unwrap();
        assert_eq!(value["proposal_decision_window_ms"], Value::from(30_000));
        assert_eq!(value["max_authority_lifetime_ms"], Value::from(120_000));

        bundle.proposal_decision_window_ms = Some(90_000);
        bundle.proposal_absolute_deadline_ms = Some(90_000);
        bundle.max_proposal_defers = Some(1);
        assert!(bundle.validate().is_err());
    }
}
