//! `cx.profile.agent_workspace.v1` — Agent Workspace integration helpers.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`
//!
//! This module provides:
//!
//! - Wire types for `cx.schema.agent_task.v1` and the two new content blocks
//!   (`cx.content.mention_redirect`, `cx.content.import_attestation`).
//! - Three orthogonal FSM enums (`ExecutionState` / `TransparencyState` /
//!   `SourceAuthorityState`) plus the runtime gate invariant.
//! - Reservation / recovery / cleanup Move-draft helpers using the empty
//!   sentinel pattern (`head_eq: "__unset__"`).
//! - import_attestation signing helpers (JCS canonical signing input + SHA-256
//!   content hash + domain-separated export-policy signature).
//!
//! All wire shapes use `serde_json::Value` for content blocks to avoid
//! coupling to a typed Content Block hierarchy that the SDK does not have.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use crate::AgentTaskId;
use crate::Did;

// ---------------------------------------------------------------------------
// Sentinel
// ---------------------------------------------------------------------------

/// Empty sentinel literal for reservation cells.
///
/// Reservation cell schemas declare `initial_value="__unset__"` so that
/// `head_eq: "__unset__"` predicate enforces singleton semantics under
/// cas-register's `basis != settled and basis != null → ⊥` rule. See
/// `agent-workspace-profile.md §6.1`.
pub const RESERVATION_SENTINEL: &str = "__unset__";

/// Default reservation TTL in seconds (10 minutes).
pub const DEFAULT_RESERVATION_TTL_SECONDS: u64 = 600;

// ---------------------------------------------------------------------------
// FSM cells
// ---------------------------------------------------------------------------

/// `execution_state` cell. Single-source-of-truth for task lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    /// Phase 1 written; awaiting source stub accepted (Phase 3 reconcile).
    PendingSourceStub,
    /// Phase 3 reconciled; agent runtime MAY execute (subject to gate).
    Active,
    /// Controller marked complete.
    Completed,
    /// Phase 2 source stub rejected.
    CancelledStubRejected,
    /// TTL housekeeping cleanup after orphan reservation.
    CancelledOrphan,
    /// Controller explicit cancel.
    CancelledByController,
}

/// `transparency` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyState {
    Ok,
    /// Source stub was redacted; agent paused awaiting controller decision.
    Lost,
    /// Controller acknowledged loss and chose to continue.
    ReconfirmedAfterLoss,
}

/// `source_authority` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthorityState {
    Ok,
    /// Source-side capability grant was revoked or agent was removed.
    Revoked,
    /// Controller chose to continue using already-imported content.
    ReconfirmedAfterRevoke,
}

impl ExecutionState {
    /// Returns true if the FSM transition is legal per the spec table.
    /// See `agent-workspace-profile.md §7.4 (Cell 1)`.
    pub fn legal_transition(from: ExecutionState, to: ExecutionState) -> bool {
        use ExecutionState::*;
        matches!(
            (from, to),
            (PendingSourceStub, Active)
                | (PendingSourceStub, CancelledStubRejected)
                | (PendingSourceStub, CancelledOrphan)
                | (PendingSourceStub, CancelledByController)
                | (Active, Completed)
                | (Active, CancelledByController)
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecutionState::Completed
                | ExecutionState::CancelledStubRejected
                | ExecutionState::CancelledOrphan
                | ExecutionState::CancelledByController
        )
    }
}

impl TransparencyState {
    pub fn legal_transition(from: TransparencyState, to: TransparencyState) -> bool {
        use TransparencyState::*;
        matches!((from, to), (Ok, Lost) | (Lost, ReconfirmedAfterLoss))
    }
}

impl SourceAuthorityState {
    pub fn legal_transition(from: SourceAuthorityState, to: SourceAuthorityState) -> bool {
        use SourceAuthorityState::*;
        matches!((from, to), (Ok, Revoked) | (Revoked, ReconfirmedAfterRevoke))
    }
}

/// Agent runtime execution gate.
///
/// Agent MAY execute iff all three cells are in allowed states. See
/// `agent-workspace-profile.md §7.3`.
pub fn agent_runtime_may_execute(
    execution: ExecutionState,
    transparency: TransparencyState,
    source_authority: SourceAuthorityState,
) -> bool {
    execution == ExecutionState::Active
        && matches!(transparency, TransparencyState::Ok | TransparencyState::ReconfirmedAfterLoss)
        && matches!(
            source_authority,
            SourceAuthorityState::Ok | SourceAuthorityState::ReconfirmedAfterRevoke
        )
}

// ---------------------------------------------------------------------------
// Object schema
// ---------------------------------------------------------------------------

/// `cx.schema.agent_task.v1` object. State lives in three FSM cells, NOT
/// in object fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String, // cx:agent_task:<uuid>
    #[serde(default = "default_schema_id")]
    pub schema: String,
    pub space_id: String, // cx:space:<mirror>
    pub flow_id: String,  // cx:flow:<mirror>
    pub target_agent_id: Did,
    pub instruction: Value, // Content Block
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_anchor: Option<ContextAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_stub_event_ref: Option<String>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

fn default_schema_id() -> String {
    "cx.schema.agent_task.v1".to_owned()
}

/// Source-Space frontier binding carried on agent_task created via
/// mention_redirect routing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContextAnchor {
    pub source_space_id: String,
    pub source_flow_id: String,
    pub source_anchor_ref: String,    // cx:anchor:...
    pub source_frontier_hash: String, // sha256:...
    pub trigger_redirect_pair_id: String,
}

// ---------------------------------------------------------------------------
// Content blocks
// ---------------------------------------------------------------------------

/// `cx.content.mention_redirect` content block. Source-Space stub.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MentionRedirectContent {
    #[serde(default = "mention_redirect_kind")]
    pub kind: String,
    /// Plain-text fallback / disclosure summary. Visible to all source
    /// Flow members. Client UI MUST display "visible to all members" notice.
    pub body: String,
    pub target_actor_id: Did,
    /// Reference to an active grant in the source Space whose
    /// `attached_authority.controller == sender_principal` and
    /// `subject == target_actor_id`.
    pub authority_grant_ref: String, // cx:grant:<uuidv7>
    /// Opaque sender-generated UUIDv7 correlating source stub with mirror
    /// agent_task. Does NOT leak mirror IDs.
    pub redirect_pair_id: String,
}

fn mention_redirect_kind() -> String {
    "cx.content.mention_redirect".to_owned()
}

/// `cx.content.import_attestation` content block.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImportAttestationContent {
    #[serde(default = "import_attestation_kind")]
    pub kind: String,
    pub body: String,
    pub claimed_origin: ClaimedOrigin,
    pub importer: Importer,
    /// Importer's signature over JCS-canonical signing input.
    /// Proves importer's CLAIM, not original author's plaintext.
    pub import_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_proofs: Option<OptionalProofs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_export_policy_attestation: Option<SourceExportPolicyAttestation>,
    pub content: Value, // re-encrypted Content Block
}

fn import_attestation_kind() -> String {
    "cx.content.import_attestation".to_owned()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimedOrigin {
    pub space_id: String,
    pub flow_id: String,
    pub message_id: String,
    pub actor_id: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Importer {
    pub actor_id: Did,
    pub imported_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OptionalProofs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_author_proof_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_frontier_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceExportPolicyAttestation {
    pub authority_did: Did,
    pub source_space_id: String,
    pub policy_hash: String,
    pub policy_decision: PolicyDecision,
    pub importer_actor_id: Did,
    pub import_destination_space_id: String,
    pub content_hash: String, // sha256:...
    pub source_frontier_ref: String,
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    RequireAttestationGranted,
}

// ---------------------------------------------------------------------------
// Capability grant attached_authority
// ---------------------------------------------------------------------------

/// `attached_authority` extension on `cx.schema.capability.v1`.
/// REQUIRED when grant subject is an agent DID with
/// `agent_authority.acting_mode == "delegated_assistant"`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "evidence_kind", rename_all = "snake_case")]
pub enum AttachedAuthority {
    AnchoredEventRef {
        authority_event_ref: String,  // cx:event:...
        authority_event_hash: String, // sha256:...
        #[serde(default, skip_serializing_if = "Option::is_none")]
        anchor_inclusion_proof: Option<Value>,
    },
    StateWitness {
        witness_issuer: Did,
        witness_signature: String,
        agent_id: Did,
        controller: Did,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        responsible_actor: Option<Did>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        acting_mode: Option<String>,
        valid_until: DateTime<Utc>,
    },
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentTaskCreatePayload {
    pub task_id: String,
    pub target_agent_id: Did,
    pub instruction: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_anchor: Option<ContextAnchor>,
    // NOTE: reservation_ttl_seconds was removed in Rev 12; reservation
    // TTL lives on cx.agent_workspace.reservation.set events. See
    // ReservationSetPayload below.
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationCellNamespace {
    MirrorSpaceBySource,
    MirrorFlowBySource,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationSetPayload {
    pub cell_namespace: ReservationCellNamespace,
    pub cell_namespace_subject: String,
    pub reservation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationRecoverPayload {
    pub cell_namespace: ReservationCellNamespace,
    pub cell_namespace_subject: String,
    pub conflict_heads: Vec<String>,
    pub winner: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationCleanupPayload {
    pub cell_namespace: ReservationCellNamespace,
    pub cell_namespace_subject: String,
    pub stale_reservation_id: String,
    pub ttl_evidence: TtlEvidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentTaskTransitionPayload {
    pub task_id: String,
    /// Cell key like `agent_task.<task_id>.execution_state`.
    pub cell: String,
    #[serde(default = "transition_op")]
    pub op: String,
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    // NOTE: ttl_evidence was removed in Rev 12; orphan cleanup lives on
    // cx.agent_workspace.reservation.cleanup events. See
    // ReservationCleanupPayload above.
}

fn transition_op() -> String {
    "transition".to_owned()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TtlEvidence {
    pub reservation_anchor_ref: String,
    pub reservation_anchor_index: u64,
    pub current_anchor_ref: String,
    pub current_anchor_index: u64,
    pub ttl_anchor_distance: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentTaskCancelPayload {
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Critical extension descriptor
// ---------------------------------------------------------------------------

/// Build the `requirements.critical_extensions[]` entry for a mention_redirect
/// event. Receivers not declaring `cx.feature.mention_redirect.v1` MUST reject
/// the entire event (preserves privacy invariant).
pub fn mention_redirect_critical_extension() -> Value {
    json!({
        "id": "cx.feature.mention_redirect.v1",
        "scope": "payload",
        "fail_closed": true,
        "schema_ref": "cx.schema.content.mention_redirect.v1"
    })
}

// ---------------------------------------------------------------------------
// Cell key helpers
// ---------------------------------------------------------------------------

pub fn execution_state_cell_key(task_id: &str) -> String {
    format!("agent_task.{}.execution_state", task_id)
}

pub fn transparency_cell_key(task_id: &str) -> String {
    format!("agent_task.{}.transparency", task_id)
}

pub fn source_authority_cell_key(task_id: &str) -> String {
    format!("agent_task.{}.source_authority", task_id)
}

pub fn mirror_space_by_source_cell_key(source_space_id: &str) -> String {
    format!("mirror_space_by_source:{}", source_space_id)
}

pub fn mirror_flow_by_source_cell_key(source_flow_id: &str) -> String {
    format!("mirror_flow_by_source:{}", source_flow_id)
}

// ---------------------------------------------------------------------------
// Reservation Move draft
// ---------------------------------------------------------------------------

/// A minimal Move-draft descriptor for the reservation `set` op. Real
/// Move construction happens via the higher-level Move builder; this struct
/// captures the data agent_workspace flows need.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationMoveDraft {
    pub cell_key: String,
    /// Always `RESERVATION_SENTINEL`.
    pub predicate_head_eq: String,
    /// Pre-allocated UUIDv7 (cx:space:<...> or cx:flow:<...>).
    pub effect_value: String,
    pub reservation_ttl_seconds: u64,
}

/// Build a level-1 (workspace root → mirror Space) reservation draft.
pub fn compute_mirror_space_reservation(
    source_space_id: &str,
    pre_allocated_mirror_space_id: &str,
) -> ReservationMoveDraft {
    ReservationMoveDraft {
        cell_key: mirror_space_by_source_cell_key(source_space_id),
        predicate_head_eq: RESERVATION_SENTINEL.to_owned(),
        effect_value: pre_allocated_mirror_space_id.to_owned(),
        reservation_ttl_seconds: DEFAULT_RESERVATION_TTL_SECONDS,
    }
}

/// Build a level-2 (mirror Space → mirror Flow) reservation draft.
pub fn compute_mirror_flow_reservation(
    source_flow_id: &str,
    pre_allocated_mirror_flow_id: &str,
) -> ReservationMoveDraft {
    ReservationMoveDraft {
        cell_key: mirror_flow_by_source_cell_key(source_flow_id),
        predicate_head_eq: RESERVATION_SENTINEL.to_owned(),
        effect_value: pre_allocated_mirror_flow_id.to_owned(),
        reservation_ttl_seconds: DEFAULT_RESERVATION_TTL_SECONDS,
    }
}

// ---------------------------------------------------------------------------
// Recovery Move draft
// ---------------------------------------------------------------------------

/// Recovery draft for resolving cell ⊥. Conforms to
/// `event-auth-state-resolution.md §8`: `head_in [conflict_heads]` predicate
/// + lex-min winner + state_witness + inclusion_proof + recovery_capability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecoveryMoveDraft {
    pub cell_key: String,
    /// Predicate `head_in` candidates.
    pub predicate_head_in: Vec<String>,
    /// Effect value = lex-min(predicate_head_in).
    pub effect_value: String,
    pub recovery_capability_grant_ref: String, // cx:grant:<recover_capability>
    pub pre_conflict_state_witness_ref: String,
    pub snapshot_inclusion_proof_ref: String,
}

/// Pick lex-min winner from a non-empty list of conflicting cell heads.
fn lex_min_winner(candidates: &[String]) -> Option<String> {
    candidates.iter().min().cloned()
}

/// Construct a recovery Move draft.
///
/// Returns `None` if `conflict_heads` is empty.
pub fn compute_recovery_move(
    cell_key: impl Into<String>,
    conflict_heads: &[String],
    recovery_capability_grant_ref: impl Into<String>,
    pre_conflict_state_witness_ref: impl Into<String>,
    snapshot_inclusion_proof_ref: impl Into<String>,
) -> Option<RecoveryMoveDraft> {
    let winner = lex_min_winner(conflict_heads)?;
    Some(RecoveryMoveDraft {
        cell_key: cell_key.into(),
        predicate_head_in: conflict_heads.to_vec(),
        effect_value: winner,
        recovery_capability_grant_ref: recovery_capability_grant_ref.into(),
        pre_conflict_state_witness_ref: pre_conflict_state_witness_ref.into(),
        snapshot_inclusion_proof_ref: snapshot_inclusion_proof_ref.into(),
    })
}

// ---------------------------------------------------------------------------
// Orphan cleanup Move draft
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CleanupMoveDraft {
    pub cell_key: String,
    /// `head_eq` on the stale reservation_id.
    pub predicate_head_eq: String,
    /// Always `RESERVATION_SENTINEL` (reset).
    pub effect_value: String,
    pub cleanup_capability_grant_ref: String,
    pub ttl_evidence: TtlEvidence,
}

/// Build a cleanup Move draft. The reducer verifies
/// `current_anchor_index >= reservation_anchor_index + ttl_anchor_distance`.
pub fn compute_orphan_cleanup_move(
    cell_key: impl Into<String>,
    stale_reservation_id: impl Into<String>,
    cleanup_capability_grant_ref: impl Into<String>,
    ttl_evidence: TtlEvidence,
) -> CleanupMoveDraft {
    CleanupMoveDraft {
        cell_key: cell_key.into(),
        predicate_head_eq: stale_reservation_id.into(),
        effect_value: RESERVATION_SENTINEL.to_owned(),
        cleanup_capability_grant_ref: cleanup_capability_grant_ref.into(),
        ttl_evidence,
    }
}

// ---------------------------------------------------------------------------
// import_attestation canonical signing input + content_hash
// ---------------------------------------------------------------------------

/// Compute SHA-256 over JCS-canonicalized Content Block, prefixed `sha256:`.
///
/// Per `agent-workspace-profile.md §10.3` content_hash algorithm.
pub fn compute_content_hash(content: &Value) -> crate::Result<String> {
    let canonical = crate::canonical::canonical_json_bytes(content)?;
    Ok(crate::canonical::sha256_digest(&canonical))
}

/// Build the canonical signing input for import_attestation's
/// `import_signature`.
///
/// Includes domain separator + schema_id to prevent replay across attestation
/// types.
pub fn import_attestation_signing_input(
    claimed_origin: &ClaimedOrigin,
    content_hash: &str,
    importer: &Importer,
) -> crate::Result<Vec<u8>> {
    let envelope = json!({
        "schema_id": "cx.schema.content.import_attestation.v1",
        "domain": "cx.domain.import_attestation.v1",
        "body": {
            "claimed_origin": claimed_origin,
            "content_hash": content_hash,
            "importer": importer
        }
    });
    crate::canonical::canonical_json_bytes(&envelope)
}

/// Build the canonical signing input for source_export_policy_attestation's
/// `signature`. Excludes the `signature` field itself (avoids circular
/// signing). Includes domain separator.
pub fn export_policy_signing_input(att: &SourceExportPolicyAttestation) -> crate::Result<Vec<u8>> {
    let body = json!({
        "authority_did": att.authority_did,
        "source_space_id": att.source_space_id,
        "policy_hash": att.policy_hash,
        "policy_decision": att.policy_decision,
        "importer_actor_id": att.importer_actor_id,
        "import_destination_space_id": att.import_destination_space_id,
        "content_hash": att.content_hash,
        "source_frontier_ref": att.source_frontier_ref,
        "issued_at": att.issued_at,
        "valid_until": att.valid_until
    });
    let envelope = json!({
        "schema_id": "cx.schema.content.source_export_policy_attestation.v1",
        "domain": "cx.domain.export_policy_attestation.v1",
        "body": body
    });
    crate::canonical::canonical_json_bytes(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    #[test]
    fn execution_state_legal_transitions() {
        use ExecutionState::*;
        assert!(ExecutionState::legal_transition(PendingSourceStub, Active));
        assert!(ExecutionState::legal_transition(PendingSourceStub, CancelledStubRejected));
        assert!(ExecutionState::legal_transition(PendingSourceStub, CancelledOrphan));
        assert!(ExecutionState::legal_transition(PendingSourceStub, CancelledByController));
        assert!(ExecutionState::legal_transition(Active, Completed));
        assert!(ExecutionState::legal_transition(Active, CancelledByController));
    }

    #[test]
    fn execution_state_illegal_transitions() {
        use ExecutionState::*;
        assert!(!ExecutionState::legal_transition(Completed, Active));
        assert!(!ExecutionState::legal_transition(CancelledByController, Active));
        assert!(!ExecutionState::legal_transition(Active, PendingSourceStub));
        assert!(!ExecutionState::legal_transition(CancelledOrphan, CancelledByController));
    }

    #[test]
    fn execution_state_terminals() {
        use ExecutionState::*;
        assert!(Completed.is_terminal());
        assert!(CancelledStubRejected.is_terminal());
        assert!(CancelledOrphan.is_terminal());
        assert!(CancelledByController.is_terminal());
        assert!(!PendingSourceStub.is_terminal());
        assert!(!Active.is_terminal());
    }

    #[test]
    fn transparency_legal_transitions() {
        use TransparencyState::*;
        assert!(TransparencyState::legal_transition(Ok, Lost));
        assert!(TransparencyState::legal_transition(Lost, ReconfirmedAfterLoss));
    }

    #[test]
    fn transparency_illegal_transitions_unreachable_edges_removed() {
        use TransparencyState::*;
        // Rev 7: reconfirmed_after_loss → lost is unreachable (Message
        // redaction is terminal), so legal_transition MUST return false.
        assert!(!TransparencyState::legal_transition(ReconfirmedAfterLoss, Lost));
        assert!(!TransparencyState::legal_transition(Lost, Ok));
        assert!(!TransparencyState::legal_transition(Ok, ReconfirmedAfterLoss));
    }

    #[test]
    fn source_authority_legal_transitions() {
        use SourceAuthorityState::*;
        assert!(SourceAuthorityState::legal_transition(Ok, Revoked));
        assert!(SourceAuthorityState::legal_transition(Revoked, ReconfirmedAfterRevoke));
    }

    #[test]
    fn source_authority_illegal_transitions_unreachable_edges_removed() {
        use SourceAuthorityState::*;
        // Rev 7: reconfirmed_after_revoke → ok and → revoked are unreachable
        // (authority_grant_ref binds original grant_id; re-grant is a new
        // grant that doesn't affect existing tasks).
        assert!(!SourceAuthorityState::legal_transition(ReconfirmedAfterRevoke, Ok));
        assert!(!SourceAuthorityState::legal_transition(ReconfirmedAfterRevoke, Revoked));
        assert!(!SourceAuthorityState::legal_transition(Revoked, Ok));
    }

    #[test]
    fn runtime_gate_invariant() {
        use ExecutionState::*;
        use SourceAuthorityState as S;
        use TransparencyState as T;
        // Happy path
        assert!(agent_runtime_may_execute(Active, T::Ok, S::Ok));
        assert!(agent_runtime_may_execute(Active, T::ReconfirmedAfterLoss, S::Ok));
        assert!(agent_runtime_may_execute(Active, T::Ok, S::ReconfirmedAfterRevoke));
        // Blocked paths
        assert!(!agent_runtime_may_execute(PendingSourceStub, T::Ok, S::Ok));
        assert!(!agent_runtime_may_execute(Active, T::Lost, S::Ok));
        assert!(!agent_runtime_may_execute(Active, T::Ok, S::Revoked));
        assert!(!agent_runtime_may_execute(Completed, T::Ok, S::Ok));
    }

    #[test]
    fn cell_key_helpers() {
        assert_eq!(
            execution_state_cell_key("cx:agent_task:abc"),
            "agent_task.cx:agent_task:abc.execution_state"
        );
        assert_eq!(
            mirror_space_by_source_cell_key("cx:space:src"),
            "mirror_space_by_source:cx:space:src"
        );
    }

    #[test]
    fn reservation_uses_sentinel_predicate() {
        let draft = compute_mirror_space_reservation("cx:space:src", "cx:space:reserved-mirror");
        assert_eq!(draft.predicate_head_eq, RESERVATION_SENTINEL);
        assert_eq!(draft.effect_value, "cx:space:reserved-mirror");
        assert_eq!(draft.reservation_ttl_seconds, DEFAULT_RESERVATION_TTL_SECONDS);
    }

    #[test]
    fn recovery_picks_lex_min_winner() {
        let heads = vec!["cx:space:b".to_owned(), "cx:space:a".to_owned(), "cx:space:c".to_owned()];
        let recovery = compute_recovery_move(
            "mirror_space_by_source:src",
            &heads,
            "cx:grant:recover",
            "cx:witness:1",
            "cx:proof:1",
        )
        .expect("non-empty");
        assert_eq!(recovery.effect_value, "cx:space:a");
        assert_eq!(recovery.predicate_head_in.len(), 3);
    }

    #[test]
    fn recovery_empty_returns_none() {
        let recovery = compute_recovery_move(
            "mirror_space_by_source:src",
            &[],
            "cx:grant:recover",
            "cx:witness:1",
            "cx:proof:1",
        );
        assert!(recovery.is_none());
    }

    #[test]
    fn orphan_cleanup_resets_to_sentinel() {
        let ttl = TtlEvidence {
            reservation_anchor_ref: "cx:anchor:r".to_owned(),
            reservation_anchor_index: 100,
            current_anchor_ref: "cx:anchor:c".to_owned(),
            current_anchor_index: 200,
            ttl_anchor_distance: 50,
        };
        let cleanup = compute_orphan_cleanup_move(
            "mirror_space_by_source:src",
            "cx:space:stale",
            "cx:grant:cleanup",
            ttl,
        );
        assert_eq!(cleanup.predicate_head_eq, "cx:space:stale");
        assert_eq!(cleanup.effect_value, RESERVATION_SENTINEL);
    }

    #[test]
    fn content_hash_canonical() {
        let content = json!({
            "kind": "cx.content.text",
            "body": "hello"
        });
        let h = compute_content_hash(&content).expect("hash");
        assert!(h.starts_with("sha256:"));
        // Order-invariance: rearrange keys, same hash.
        let content2 = json!({
            "body": "hello",
            "kind": "cx.content.text"
        });
        let h2 = compute_content_hash(&content2).expect("hash");
        assert_eq!(h, h2);
    }

    #[test]
    fn import_attestation_signing_input_includes_domain_separator() {
        let claimed_origin = ClaimedOrigin {
            space_id: "cx:space:src".to_owned(),
            flow_id: "cx:flow:src".to_owned(),
            message_id: "cx:message:src".to_owned(),
            actor_id: did("did:web:bob.example"),
            created_at: Utc.with_ymd_and_hms(2026, 5, 17, 9, 55, 0).unwrap(),
        };
        let importer = Importer {
            actor_id: did("did:web:alice-agent.example"),
            imported_at: Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 1).unwrap(),
        };
        let input = import_attestation_signing_input(&claimed_origin, "sha256:abc", &importer)
            .expect("input");
        let as_str = String::from_utf8(input).expect("utf8");
        assert!(as_str.contains("cx.domain.import_attestation.v1"));
        assert!(as_str.contains("cx.schema.content.import_attestation.v1"));
        assert!(!as_str.contains("signature\":"));
    }

    #[test]
    fn export_policy_signing_input_excludes_signature() {
        let att = SourceExportPolicyAttestation {
            authority_did: did("did:web:admin.example"),
            source_space_id: "cx:space:src".to_owned(),
            policy_hash: "sha256:p".to_owned(),
            policy_decision: PolicyDecision::Allow,
            importer_actor_id: did("did:web:agent.example"),
            import_destination_space_id: "cx:space:mirror".to_owned(),
            content_hash: "sha256:c".to_owned(),
            source_frontier_ref:
                "cx:anchor:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            issued_at: Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 17, 11, 0, 0).unwrap(),
            signature: "should-not-appear".to_owned(),
        };
        let input = export_policy_signing_input(&att).expect("input");
        let as_str = String::from_utf8(input).expect("utf8");
        assert!(as_str.contains("cx.domain.export_policy_attestation.v1"));
        assert!(!as_str.contains("should-not-appear"));
    }

    #[test]
    fn critical_extension_descriptor_uses_payload_scope() {
        let ext = mention_redirect_critical_extension();
        assert_eq!(ext["scope"], "payload");
        assert_eq!(ext["fail_closed"], true);
        assert_eq!(ext["id"], "cx.feature.mention_redirect.v1");
    }

    #[test]
    fn agent_task_serde_roundtrip() {
        let task = AgentTask {
            id: "cx:agent_task:01964200-0000-7000-8000-000000000000".to_owned(),
            schema: default_schema_id(),
            space_id: "cx:space:mirror".to_owned(),
            flow_id: "cx:flow:mirror".to_owned(),
            target_agent_id: did("did:web:agent.example"),
            instruction: json!({ "kind": "cx.content.text", "body": "do X" }),
            encrypted_payload: None,
            context_anchor: Some(ContextAnchor {
                source_space_id: "cx:space:src".to_owned(),
                source_flow_id: "cx:flow:src".to_owned(),
                source_anchor_ref:
                    "cx:anchor:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                source_frontier_hash: "sha256:f".to_owned(),
                trigger_redirect_pair_id: "01964200-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
            }),
            source_stub_event_ref: None,
            created_by: did("did:web:alice.example"),
            created_at: Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap(),
        };
        let json_str = serde_json::to_string(&task).expect("serialize");
        let back: AgentTask = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(task, back);
    }

    #[test]
    fn attached_authority_variants() {
        let aa = AttachedAuthority::AnchoredEventRef {
            authority_event_ref: "cx:event:1".to_owned(),
            authority_event_hash: "sha256:h".to_owned(),
            anchor_inclusion_proof: None,
        };
        let s = serde_json::to_value(&aa).expect("serialize");
        assert_eq!(s["evidence_kind"], "anchored_event_ref");
    }

    #[test]
    fn attached_authority_roundtrip_in_capability_grant() {
        // Verify the new attached_authority field on CapabilityGrant
        // round-trips through serde JSON (proves the spec PR 1.2 schema
        // change lands cleanly on the SDK side). See agent-workspace
        // -profile.md §5 + capability-grant.schema.json.
        use crate::authz::{CapabilityGrant, ResourceSelector};

        let grant = CapabilityGrant {
            id: "cx:grant:01964200-0000-7000-8000-bbbbbbbbbbbb".to_owned(),
            space_id: None,
            issuer: did("did:web:alice.example"),
            subject: did("did:web:alice-agent.example"),
            actions: vec!["cx.message.create".to_owned()],
            resources: vec![ResourceSelector::Space {
                space_id: "cx:space:01904100-0000-7000-8000-1a412919cd4b".to_owned(),
            }],
            constraints: vec![],
            delegable: false,
            parent_grant_id: None,
            valid_from: None,
            valid_until: None,
            revoked_by: None,
            revoked_at: None,
            attached_authority: Some(AttachedAuthority::AnchoredEventRef {
                authority_event_ref: "cx:event:01964200-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                authority_event_hash: "sha256:abc".to_owned(),
                anchor_inclusion_proof: None,
            }),
        };
        let s = serde_json::to_value(&grant).expect("serialize");
        assert_eq!(s["attached_authority"]["evidence_kind"], "anchored_event_ref");
        let back: CapabilityGrant = serde_json::from_value(s).expect("deserialize");
        assert!(back.attached_authority.is_some());

        // Grants without attached_authority should serialize without the
        // field (skip_serializing_if = "Option::is_none").
        let mut without = grant.clone();
        without.attached_authority = None;
        let s2 = serde_json::to_value(&without).expect("serialize");
        assert!(s2.get("attached_authority").is_none());
    }
}
