//! Personal-Agent lifecycle wire models and the requested-scope commitment
//! digest, relocated from `arkret-core`. These bind agent-key payloads
//! (`events_payloads::agent`), grant / key-state artifacts
//! (`governance::agent_artifacts`), capability grants
//! (`governance::grant_constraint`), and the managed-frontier reference
//! (`arkret-models-crypto`), all reachable within the collaboration layering
//! edge. `arkret-core` re-exports them for path stability.

use std::collections::BTreeSet;

use arkret_wire::serde_helpers::{
    deserialize_canonical_timestamp, deserialize_canonical_timestamp_millis,
    deserialize_optional_canonical_timestamp, serialize_canonical_timestamp,
    serialize_canonical_timestamp_millis, serialize_optional_canonical_timestamp,
};

use crate::events_payloads::agent::{
    AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyScope, AgentSidecarExposureAck,
};
use crate::governance::agent_artifacts::{AgentKeyAuthorizationState, GrantSnapshot, PublicKey};
use crate::http_bodies::{AccountDevicePairOutcome, AccountDevicePairRequestBody};
use crate::internal_prelude::*;

pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_SCHEMA: &str =
    "ak.schema.agent_requested_scope_disclosure.v1";

/// Controller-signed, verifier-bound private disclosure of an Agent's
/// immutable requested-scope ceiling.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRequestedScopeDisclosure {
    pub schema: String,
    pub request_id: RequestId,
    pub agent_id: Did,
    pub controller_id: Did,
    pub requested_scope: AgentKeyScope,
    pub requested_scope_digest: Hash,
    pub verifier_did: Did,
    pub audience: NonEmptyString,
    pub challenge: NonEmptyString,
    #[serde(
        serialize_with = "serialize_canonical_timestamp_millis",
        deserialize_with = "deserialize_canonical_timestamp_millis"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp_millis",
        deserialize_with = "deserialize_canonical_timestamp_millis"
    )]
    pub expires_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

impl AgentRequestedScopeDisclosure {
    pub fn canonical_bytes_without_proofs(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AgentRequestedScopeDisclosure serializes as an object")
            .remove("proofs");
        Ok(canonical::canonical_json_bytes(&value)?)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(
            &self.canonical_bytes_without_proofs()?,
        ))
        .map_err(|reason| Error::Protocol(reason.to_string()))
    }

    pub fn canonical_proof_binding_bytes(&self, proof: &Proof) -> Result<Vec<u8>> {
        let payload_digest = self.payload_digest()?;
        if proof.event_digest != payload_digest {
            return Err(Error::Protocol(
                "agent requested-scope disclosure proof digest mismatch".to_owned(),
            ));
        }
        Ok(canonical::canonical_json_bytes(&serde_json::json!({
            "context": "ak.agent-requested-scope-disclosure-proof-v1",
            "payload_digest": payload_digest,
            "agent_id": self.agent_id,
            "controller_id": self.controller_id,
            "verifier_did": self.verifier_did,
            "audience": self.audience,
            "challenge": self.challenge,
            "verification_method": proof.verification_method,
            "created_at": proof.created_at,
        }))?)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != AGENT_REQUESTED_SCOPE_DISCLOSURE_SCHEMA {
            return Err(Error::Protocol(
                "agent requested-scope disclosure schema is invalid".to_owned(),
            ));
        }
        if self.challenge.as_str().len() < 16 {
            return Err(Error::Protocol(
                "agent requested-scope disclosure challenge must contain at least 16 bytes"
                    .to_owned(),
            ));
        }
        let lifetime = self.expires_at.signed_duration_since(self.issued_at);
        if lifetime <= chrono::Duration::zero() || lifetime > chrono::Duration::seconds(300) {
            return Err(Error::Protocol(
                "agent requested-scope disclosure lifetime must be within 1..=300 seconds"
                    .to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "agent requested-scope disclosure requires a controller proof".to_owned(),
            ));
        }
        let payload_digest = self.payload_digest()?;
        if self
            .proofs
            .iter()
            .any(|proof| proof.event_digest != payload_digest)
        {
            return Err(Error::Protocol(
                "agent requested-scope disclosure proof digest mismatch".to_owned(),
            ));
        }
        let expected = agent_requested_scope_digest(
            &self.agent_id,
            &self.controller_id,
            &self.requested_scope,
        )?;
        if self.requested_scope_digest != expected {
            return Err(Error::Protocol(
                "agent requested-scope disclosure digest does not match its scope".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: NonEmptyString,
    pub agent_id: Did,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    pub proof_of_possession: NonEmptyJsonObject,
    pub requested_scope_disclosure: AgentRequestedScopeDisclosure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    pub authorize_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentKeyPairOutcome {
    pub ok: bool,
    pub authorized_event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalRequestBody {
    pub pairing_code: NonEmptyString,
    pub pairing_request_id: NonEmptyString,
    pub agent_id: Did,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    pub proof_of_possession: NonEmptyJsonObject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalOutcome {
    pub ok: bool,
    pub approval_request_id: String,
    pub status: AgentStatus,
}

/// Runtime-side poll for the controller decision on a previously submitted
/// runtime key request. The `pairing_request_id` + `pairing_code` +
/// `agent_id` triple is the query credential; a record miss and a
/// mismatch are indistinguishable (both not_found). Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusRequestBody {
    pub pairing_request_id: String,
    pub pairing_code: String,
    pub agent_id: Did,
}

/// Controller-decision status for an agent runtime key pairing request.
/// Once approved, `authorized_event_ref` plus the authorized key binding
/// fields are present; the runtime MUST compare
/// `authorized_public_key_digest` against its own key and treat a mismatch
/// as paired-by-another-runtime. Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusOutcome {
    pub ok: bool,
    pub status: AgentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_verification_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_public_key_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum AgentProvisionRequestBody {
    Prepare {
        #[serde(skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        slug: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        avatar_blob_ref: Option<BlobRef>,
        requested_scope: AgentKeyScope,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_ttl_ms: Option<u64>,
    },
    Commit {
        agent_id: Did,
        principal_control_realm_id: RealmId,
        #[serde(skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        slug: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        avatar_blob_ref: Option<BlobRef>,
        requested_scope: AgentKeyScope,
        provision_events: Box<AgentProvisionEvents>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_ttl_ms: Option<u64>,
    },
}

/// Closed controller-signed Event pair committed by personal-Agent
/// provisioning. The server validates semantic cross-bindings and admits both
/// envelopes through the ordinary Event pipeline; it never authors a proof on
/// the controller's behalf.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionEvents {
    pub accountability_grant: Event,
    pub selector_claim: Event,
}

// NOTE: `AgentKeyScope` is the spec object `{actions, resources, constraints?}`
// defined in `models/artifacts/event_payload/agent.rs`
// (`event-payload.schema.json#/$defs/agent_key_scope`, `$ref`'d by
// `agent-operations.schema.json#/$defs/agent_provision_request_body.requested_scope`).
// The former SDK-local `account/realm/applet/limited` enum was off-spec and
// has been removed.

/// Re-open pairing on any non-terminal agent. The service issues a fresh
/// one-time pairing handle and every previously issued handle becomes
/// permanently unresolvable. `pending_runtime_key` / `pairing_expired`
/// re-open bootstrap pairing; `active` / `paused` perform runtime
/// replacement re-pairing (existing keys stay valid until the new pairing
/// completes, then are atomically superseded by the single accepted
/// authorization Event).
/// `deactivated` rejects. Mirrors
/// `agent-operations.schema.json#/$defs/agent_renew_pairing_request_body`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentPcrRecoveryStatus {
    Pending,
    Ready,
    Stale,
}

/// Recovery coverage for a managed Agent Principal Control Realm. The tagged
/// representation preserves the schema invariant that only ready/stale states
/// carry an accepted backup reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPcrRecoveryState {
    Pending,
    Ready {
        backup_id: BackupId,
        series_id: BackupSeriesId,
        series_seq: u64,
        managed_frontier_ref: ManagedFrontierRef,
    },
    Stale {
        backup_id: BackupId,
        series_id: BackupSeriesId,
        series_seq: u64,
        managed_frontier_ref: ManagedFrontierRef,
    },
}

impl AgentPcrRecoveryState {
    pub const fn status(&self) -> AgentPcrRecoveryStatus {
        match self {
            Self::Pending => AgentPcrRecoveryStatus::Pending,
            Self::Ready { .. } => AgentPcrRecoveryStatus::Ready,
            Self::Stale { .. } => AgentPcrRecoveryStatus::Stale,
        }
    }

    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Provisioning is the raw allocation stage, so its recovery projection is
/// constrained to pending and carries no backup reference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionPcrRecovery {
    pub status: AgentProvisionPcrRecoveryStatus,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentProvisionPcrRecoveryStatus {
    #[default]
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentPairingMode {
    Bootstrap,
    Replacement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentProvisionOutcome {
    AwaitingControllerEvents {
        agent_id: Did,
        principal_control_realm_id: RealmId,
        controller_realm_id: RealmId,
        controller_authorization_ref: String,
        requested_scope_digest: Hash,
    },
    Complete {
        #[serde(flatten)]
        outcome: AgentProvisionComplete,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionComplete {
    pub agent_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub requested_scope_digest: Hash,
    pub pcr_recovery: AgentProvisionPcrRecovery,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp_millis",
        deserialize_with = "deserialize_canonical_timestamp_millis"
    )]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingOutcome {
    pub agent_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub requested_scope_digest: Hash,
    pub pcr_recovery: AgentPcrRecoveryState,
    pub pairing_mode: AgentPairingMode,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp_millis",
        deserialize_with = "deserialize_canonical_timestamp_millis"
    )]
    pub expires_at: DateTime<Utc>,
}

/// One-time bootstrap material handed to a personal agent runtime after
/// provisioning. Mirrors `agent-operations.schema.json#/$defs/agent_pairing_bootstrap`
/// and AKP-0008 §4.4: a short-lived, revocable pairing input only. It is not a
/// session grant, capability grant or long-term secret, and it deliberately
/// carries no scope payload (the authoritative ceiling lives in
/// `ak.agent.key.authorize` and the effective-permission intersection).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: Did,
    pub agent_id: Did,
    pub pairing_request_id: String,
    pub pairing_code: String,
    #[serde(
        serialize_with = "serialize_canonical_timestamp_millis",
        deserialize_with = "deserialize_canonical_timestamp_millis"
    )]
    pub pairing_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentPairingResolveRequestBody {
    pub pairing_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    PendingRuntimeKey,
    Active,
    PairingExpired,
    Paused,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProjection {
    pub agent_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub status: AgentStatus,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

impl AgentLifecycleState {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deactivated => "deactivated",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleOutcome {
    pub ok: bool,
    pub status: AgentLifecycleState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentList {
    #[serde(default)]
    pub agents: Vec<AgentProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<cursor::Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentView {
    pub agent: AgentProjection,
    pub status: AgentStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_state: Option<KeyState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentPauseRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Closed Agent-PCR lifecycle Event authored by the Agent principal and
    /// executed/signed by its controller delegation.
    pub lifecycle_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentResumeRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidecar_exposure_ack: Option<AgentSidecarExposureAck>,
    /// Closed Agent-PCR lifecycle Event authored by the Agent principal and
    /// executed/signed by its controller delegation.
    pub lifecycle_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentDeactivateRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantAttachRequestBody {
    pub grant: CapabilityGrant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantAttachOutcome {
    pub ok: bool,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantDetachOutcome {
    pub ok: bool,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub revoked_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarStrandContextRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarRelationContextRef {
    pub realm_id: RealmId,
    pub relation_id: RelationId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum AgentSidecarContextRef {
    Strand(AgentSidecarStrandContextRef),
    Relation(AgentSidecarRelationContextRef),
}

impl AgentSidecarContextRef {
    pub fn strand(realm_id: RealmId, strand_id: StrandId) -> Self {
        Self::Strand(AgentSidecarStrandContextRef {
            realm_id,
            strand_id,
        })
    }

    pub fn relation(realm_id: RealmId, relation_id: RelationId) -> Self {
        Self::Relation(AgentSidecarRelationContextRef {
            realm_id,
            relation_id,
        })
    }

    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Strand(value) => &value.realm_id,
            Self::Relation(value) => &value.realm_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarEnsureRequestBody {
    pub controller_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addressed_agent_ids: Vec<Did>,
    pub context_ref: AgentSidecarContextRef,
}

impl AgentSidecarEnsureRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self
            .addressed_agent_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.addressed_agent_ids.len()
            || self
                .addressed_agent_ids
                .iter()
                .any(|agent_id| agent_id == &self.controller_id)
        {
            return Err(Error::Protocol(
                "addressed Sidecar Agents must be unique and exclude the controller".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarAccessReadiness {
    Opening,
    AccessReconciliationPending,
    KeyMaterialPending,
    EpochUpdateRequired,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PendingSidecarAccessReconciliationStage {
    BackingScopeMembership,
    MlsWelcome,
    MlsRemove,
    EpochRotation,
    DeviceKeyMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PendingSidecarAccessReconciliationItem {
    pub agent_id: Did,
    pub stage: PendingSidecarAccessReconciliationStage,
    pub reason: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarEnsureOutcome {
    pub ok: bool,
    pub sidecar_id: SidecarId,
    pub private_strand_id: StrandId,
    pub private_relation_id: RelationId,
    pub access_readiness: AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<PendingSidecarAccessReconciliationItem>,
}

impl AgentSidecarEnsureOutcome {
    pub fn validate(&self) -> Result<()> {
        if !self.ok {
            return Err(Error::Protocol(
                "successful Sidecar ensure outcome requires ok=true".to_owned(),
            ));
        }
        if self.access_readiness == AgentSidecarAccessReadiness::Ready
            && !self.pending_access_reconciliations.is_empty()
        {
            return Err(Error::Protocol(
                "ready Sidecar ensure outcome cannot have pending reconciliation".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum AgentSidecarSchema {
    #[serde(rename = "ak.schema.agent_sidecar.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum AgentSidecarEncryptionProfile {
    #[serde(rename = "mls_rfc9420")]
    MlsRfc9420,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarState {
    Active,
    Suspended,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecar {
    pub id: SidecarId,
    pub schema: AgentSidecarSchema,
    pub realm_id: RealmId,
    pub controller_id: Did,
    pub backing_circle_id: CircleId,
    pub encryption_profile: AgentSidecarEncryptionProfile,
    pub state: AgentSidecarState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl AgentSidecar {
    pub fn validate(&self) -> Result<()> {
        if self.state != AgentSidecarState::Active && self.state_changed_at.is_none() {
            return Err(Error::Protocol(
                "non-active Sidecar requires state_changed_at".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarView {
    pub sidecar: AgentSidecar,
    pub desired_agent_ids: Vec<Did>,
    pub effective_agent_ids: Vec<Did>,
    pub access_readiness: AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<PendingSidecarAccessReconciliationItem>,
}

impl AgentSidecarView {
    pub fn validate(&self) -> Result<()> {
        self.sidecar.validate()?;
        let desired = self.desired_agent_ids.iter().collect::<BTreeSet<_>>();
        if desired.len() != self.desired_agent_ids.len()
            || self
                .effective_agent_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.effective_agent_ids.len()
            || self
                .effective_agent_ids
                .iter()
                .any(|agent_id| !desired.contains(agent_id))
        {
            return Err(Error::Protocol(
                "sidecar effective access must be a unique subset of desired access".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarList {
    pub items: Vec<AgentSidecarView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<NonEmptyString>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarDisplayMode {
    #[default]
    ContextMerged,
    SidecarOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarTrackMergePolicy {
    TimelineInterleave,
    SharedBasePrivateOverlay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarProjectionProvenance {
    Shared,
    Private,
    PrivateEcho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum AgentSidecarViewStateSchema {
    #[serde(rename = "ak.schema.agent_sidecar_view_state.v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarViewState {
    pub schema: AgentSidecarViewStateSchema,
    pub controller_id: Did,
    pub sidecar_id: SidecarId,
    pub context_ref: AgentSidecarStrandContextRef,
    pub display_mode: AgentSidecarDisplayMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapsed: Option<bool>,
    pub updated_hlc: Hlc,
    pub origin_device_id: DeviceId,
}

impl AgentSidecarViewState {
    pub fn account_data_type(&self) -> String {
        format!(
            "ak.agent.sidecar_view_state.v1:{}:{}:{}",
            self.controller_id, self.context_ref.realm_id, self.context_ref.strand_id
        )
    }

    pub fn validate_account_data_type(&self, data_type: &str) -> Result<()> {
        if data_type == self.account_data_type() {
            Ok(())
        } else {
            Err(Error::Protocol(
                "Sidecar view-state account-data key does not match plaintext".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentSidecarExchangeId(String);

impl AgentSidecarExchangeId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if (22..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~=-".contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(Error::Protocol("invalid Sidecar exchange id".to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentSidecarExchangeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for AgentSidecarExchangeId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentSidecarExchangeId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "salvo-oapi")]
impl salvo::oapi::ToSchema for AgentSidecarExchangeId {
    fn to_schema(
        _components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        salvo::oapi::Object::new()
            .schema_type(salvo::oapi::BasicType::String)
            .pattern(r"^[A-Za-z0-9._~=-]{22,128}$")
            .into()
    }
}

#[cfg(feature = "salvo-oapi")]
impl salvo::oapi::ComposeSchema for AgentSidecarExchangeId {
    fn compose(
        components: &mut salvo::oapi::Components,
        _generics: Vec<salvo::oapi::RefOr<salvo::oapi::Schema>>,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        <Self as salvo::oapi::ToSchema>::to_schema(components)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarSourceTrackRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: String,
}

impl AgentSidecarSourceTrackRef {
    pub fn validate(&self) -> Result<()> {
        let value = self.track_name.as_bytes();
        if value.is_empty()
            || value.len() > 64
            || !value[0].is_ascii_lowercase()
            || value
                .iter()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'))
        {
            return Err(Error::Protocol("invalid Sidecar Track name".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeOrigin {
    SourceTrackRouted,
    SidecarNative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeStatus {
    Pending,
    Delivered,
    Responding,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub enum AgentSidecarExchangeProjectionSchema {
    #[serde(rename = "ak.schema.agent_sidecar_exchange_projection.v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeProjection {
    pub schema: AgentSidecarExchangeProjectionSchema,
    pub controller_id: Did,
    pub sidecar_id: SidecarId,
    pub private_strand_id: StrandId,
    pub exchange_id: AgentSidecarExchangeId,
    pub origin: AgentSidecarExchangeOrigin,
    pub source_track_ref: AgentSidecarSourceTrackRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_frontier_anchor: Option<EventId>,
    pub source_hlc: Hlc,
    pub client_order_key: NonEmptyString,
    pub addressed_agent_ids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participating_agent_ids: Vec<Did>,
    pub private_request_event_id: EventId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_facing_response_event_ids: Vec<EventId>,
    pub status: AgentSidecarExchangeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<NonEmptyString>,
    pub updated_hlc: Hlc,
}

impl AgentSidecarExchangeProjection {
    pub fn account_data_type(&self) -> String {
        format!(
            "ak.agent.sidecar_projection.v1:{}:{}:{}:{}",
            self.controller_id,
            self.source_track_ref.realm_id,
            self.source_track_ref.strand_id,
            self.exchange_id
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.source_track_ref.validate()?;
        let order_key = self.client_order_key.as_str().as_bytes();
        if order_key.len() > 128
            || order_key
                .iter()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"._~=-".contains(byte)))
        {
            return Err(Error::Protocol(
                "invalid Sidecar client order key".to_owned(),
            ));
        }
        if self.origin != AgentSidecarExchangeOrigin::SourceTrackRouted {
            return Err(Error::Protocol(
                "sidecar-native Events must not create source echo projections".to_owned(),
            ));
        }
        if self.status == AgentSidecarExchangeStatus::Failed && self.failure_code.is_none() {
            return Err(Error::Protocol(
                "failed Sidecar exchange projection requires failure_code".to_owned(),
            ));
        }
        if let Some(failure_code) = &self.failure_code {
            let value = failure_code.as_str().as_bytes();
            if value.len() > 64
                || !value[0].is_ascii_lowercase()
                || value.iter().any(|byte| {
                    !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
                })
            {
                return Err(Error::Protocol("invalid Sidecar failure code".to_owned()));
            }
        }
        if self.status == AgentSidecarExchangeStatus::Complete
            && self.user_facing_response_event_ids.is_empty()
        {
            return Err(Error::Protocol(
                "complete Sidecar exchange projection requires a user-facing response".to_owned(),
            ));
        }
        for values in [&self.addressed_agent_ids, &self.participating_agent_ids] {
            if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
                return Err(Error::Protocol(
                    "Sidecar Agent id arrays must be unique".to_owned(),
                ));
            }
        }
        if self
            .user_facing_response_event_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.user_facing_response_event_ids.len()
        {
            return Err(Error::Protocol(
                "Sidecar response Event ids must be unique".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_account_data_type(&self, data_type: &str) -> Result<()> {
        if data_type == self.account_data_type() {
            Ok(())
        } else {
            Err(Error::Protocol(
                "Sidecar exchange account-data key does not match plaintext".to_owned(),
            ))
        }
    }
}

#[derive(Serialize)]
struct AgentRequestedScopeCommitment<'a> {
    agent_id: &'a str,
    controller_id: &'a str,
    kind: &'static str,
    requested_scope: &'a AgentKeyScope,
}

/// Compute the immutable provision ceiling commitment fixed in the accepted
/// Agent DID `ArkretPrincipalControlRealm` service entry.
pub fn agent_requested_scope_digest(
    agent_id: &Did,
    controller_id: &Did,
    requested_scope: &AgentKeyScope,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentRequestedScopeCommitment {
            agent_id: agent_id.as_str(),
            controller_id: controller_id.as_str(),
            kind: "ak.agent.requested_scope_commitment.v1",
            requested_scope,
        },
    )?)
    .map_err(Error::from)
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentOperations {
    AccountDevicePairRequestBody(AccountDevicePairRequestBody),
    AccountDevicePairOutcome(AccountDevicePairOutcome),
    AgentKeyPairRequestBody(Box<AgentKeyPairRequestBody>),
    AgentKeyPairOutcome(AgentKeyPairOutcome),
    AgentRuntimeApprovalRequestBody(AgentRuntimeApprovalRequestBody),
    AgentRuntimeApprovalOutcome(AgentRuntimeApprovalOutcome),
    AgentProvisionRequestBody(Box<AgentProvisionRequestBody>),
    AgentProvisionOutcome(AgentProvisionOutcome),
    AgentRenewPairingRequestBody(AgentRenewPairingRequestBody),
    AgentRenewPairingOutcome(AgentRenewPairingOutcome),
    AgentPairingBootstrap(AgentPairingBootstrap),
    AgentList(AgentList),
    AgentView(Box<AgentView>),
    AgentPauseRequestBody(AgentPauseRequestBody),
    AgentLifecycleState(AgentLifecycleOutcome),
    AgentResumeRequestBody(AgentResumeRequestBody),
    AgentDeactivateRequestBody(AgentDeactivateRequestBody),
    AgentGrantAttachRequestBody(AgentGrantAttachRequestBody),
    AgentGrantAttachOutcome(AgentGrantAttachOutcome),
    AgentGrantDetachOutcome(AgentGrantDetachOutcome),
    AgentSidecarEnsureRequestBody(AgentSidecarEnsureRequestBody),
    AgentSidecarEnsureOutcome(AgentSidecarEnsureOutcome),
    AgentSidecarView(Box<AgentSidecarView>),
    AgentSidecarList(AgentSidecarList),
}

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/key_state`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct KeyState {
    pub agent_id: Did,
    pub controller_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub status: AgentStatus,
    pub pcr_recovery: AgentPcrRecoveryState,
    /// Immutable global Agent ceiling captured by provisioning.
    pub requested_scope: AgentKeyScope,
    /// Digest of the immutable ceiling committed by the accepted Agent DID.
    pub requested_scope_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_request_id: Option<String>,
    /// Branch of the current unconsumed, unexpired pairing handle. Present
    /// exactly when `pairing_request_id` and `pairing_expires_at` are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_mode: Option<AgentPairingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_runtime_key_request: Option<BTreeMap<String, Value>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp",
        deserialize_with = "deserialize_optional_canonical_timestamp"
    )]
    pub approval_requested_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_authorizations: Vec<AgentKeyAuthorizationState>,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Timelike};

    use super::*;

    fn runtime_approval_request(runtime_attestation: Value) -> Value {
        serde_json::json!({
            "pairing_code": "12345678",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
            "public_key": {
                "kty": "OKP",
                "kid": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
                "alg": "Ed25519",
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "proof_of_possession": { "signature": "c2ln" },
            "runtime_attestation": runtime_attestation
        })
    }

    #[test]
    fn runtime_attestation_is_closed_to_the_v1_self_asserted_shape() {
        let accepted: AgentRuntimeApprovalRequestBody =
            serde_json::from_value(runtime_approval_request(serde_json::json!({
                "kind": "self_asserted",
                "software": "arkret-agent"
            })))
            .expect("registered self_asserted attestation accepts");
        assert!(accepted.runtime_attestation.is_some());

        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "tee" })
            ))
            .is_err(),
            "unknown attestation kinds must fail closed"
        );
        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "self_asserted", "unregistered": true })
            ))
            .is_err(),
            "unregistered attestation fields must fail closed"
        );
    }

    #[test]
    fn sidecar_ensure_request_uses_strand_level_context_ref_shape() {
        let request = AgentSidecarEnsureRequestBody {
            controller_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice").unwrap(),
            addressed_agent_ids: vec![Did::new("did:webvh:z6mkfixture:agent.example").unwrap()],
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031").unwrap(),
            ),
        };
        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("realm_id").is_none());
        assert!(value.get("agent_id").is_none());
        assert_eq!(
            value["controller_id"],
            "did:webvh:z6mkfixture:example.com:users:alice"
        );
        assert_eq!(
            value["addressed_agent_ids"][0],
            "did:webvh:z6mkfixture:agent.example"
        );
        assert_eq!(
            value["context_ref"]["realm_id"],
            "ak:realm:01964137-0000-7000-8000-000000000030"
        );
        assert_eq!(
            value["context_ref"]["strand_id"],
            "ak:strand:01964137-0000-7000-8000-000000000031"
        );

        for forbidden in ["track_name", "message_id"] {
            let mut invalid = value.clone();
            invalid["context_ref"][forbidden] = serde_json::json!("discussion");
            assert!(
                serde_json::from_value::<AgentSidecarEnsureRequestBody>(invalid).is_err(),
                "{forbidden} must not participate in Sidecar context identity"
            );
        }
    }

    #[test]
    fn sidecar_timestamps_are_canonical_at_the_wire_boundary() {
        let timestamp = Utc
            .with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
            .unwrap()
            .with_nanosecond(987_654_321)
            .unwrap();
        let sidecar = AgentSidecar {
            id: SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000021").unwrap(),
            schema: AgentSidecarSchema::V1,
            realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000020").unwrap(),
            controller_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice").unwrap(),
            backing_circle_id: CircleId::new("ak:circle:01964137-0000-7000-8000-000000000022")
                .unwrap(),
            encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
            state: AgentSidecarState::Active,
            state_changed_at: Some(timestamp),
            created_at: timestamp,
            updated_at: Some(timestamp),
        };

        let value = serde_json::to_value(&sidecar).unwrap();
        for field in ["state_changed_at", "created_at", "updated_at"] {
            assert_eq!(value[field], "2026-07-20T12:34:56Z", "{field}");
            canonical::validate_timestamp_canonical(value[field].as_str().unwrap()).unwrap();
        }

        let mut non_canonical = value;
        non_canonical["created_at"] = serde_json::json!("2026-07-20T12:34:56.987654Z");
        assert!(serde_json::from_value::<AgentSidecar>(non_canonical).is_err());
    }

    #[test]
    fn sidecar_exchange_projection_is_per_exchange_and_fail_closed() {
        let projection = AgentSidecarExchangeProjection {
            schema: AgentSidecarExchangeProjectionSchema::V1,
            controller_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice").unwrap(),
            sidecar_id: SidecarId::new(
                "ak:sidecar:01964137-0000-7000-8000-000000000032".to_owned(),
            )
            .unwrap(),
            private_strand_id: StrandId::new(
                "ak:strand:01964137-0000-7000-8000-000000000033".to_owned(),
            )
            .unwrap(),
            exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap(),
            origin: AgentSidecarExchangeOrigin::SourceTrackRouted,
            source_track_ref: AgentSidecarSourceTrackRef {
                realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030".to_owned())
                    .unwrap(),
                strand_id: StrandId::new(
                    "ak:strand:01964137-0000-7000-8000-000000000031".to_owned(),
                )
                .unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_frontier_anchor: None,
            source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![],
            participating_agent_ids: vec![],
            private_request_event_id: EventId::new(
                "ak:event:01964137-0000-7000-8000-000000000034".to_owned(),
            )
            .unwrap(),
            user_facing_response_event_ids: vec![],
            status: AgentSidecarExchangeStatus::Pending,
            failure_code: None,
            updated_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        };
        projection.validate().unwrap();
        assert_eq!(
            projection.account_data_type(),
            "ak.agent.sidecar_projection.v1:did:webvh:z6mkfixture:example.com:users:alice:ak:realm:01964137-0000-7000-8000-000000000030:ak:strand:01964137-0000-7000-8000-000000000031:Abcdefghijklmnopqrstuv"
        );

        let mut native = projection.clone();
        native.origin = AgentSidecarExchangeOrigin::SidecarNative;
        assert!(native.validate().is_err());

        let mut unknown = serde_json::to_value(&projection).unwrap();
        unknown["private_circle_id"] =
            serde_json::json!("ak:circle:01964137-0000-7000-8000-000000000035");
        assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(unknown).is_err());
    }

    #[test]
    fn requested_scope_commitment_is_domain_separated_and_stable() {
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let controller_id = Did::new("did:webvh:z6mkcontroller:controller.example").unwrap();
        let requested_scope: AgentKeyScope = serde_json::from_value(serde_json::json!({
            "actions": [
                "ak.event.read",
                "ak.self.events.stream.subscribe"
            ],
            "resources": [
                {
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }
            ]
        }))
        .unwrap();
        let digest =
            agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope).unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:fc25a74d604984484de924bf889d612ba574d4bb4970620c70dc603adf22a042"
        );
    }
}
