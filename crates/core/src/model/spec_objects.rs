//! Spec object types that did not have a Rust mirror until now.
//!
//! Each struct here mirrors a JSON schema in
//! `cokret-spec/spec/v1/artifacts/schemas/`:
//!
//! - `agent.schema.json` → [`AgentProtocolEnvelope`] + [`AgentAuditBinding`]
//! - `applet.schema.json` → [`AppletProtocolEnvelope`] + [`AppletErrorContext`]
//! - `moderation-queue-item.schema.json` → [`ModerationQueueItem`]
//!   + [`ModerationQueueStatus`] + [`ModerationQueuePriority`]
//!   + [`ModerationQueueVisibility`] + [`ModerationEvidencePolicy`]
//!
//! ### Sibling moderation-appeal types
//!
//! `moderation-appeal.schema.json` is already implemented in
//! [`super::ModerationAppealPayload`], [`super::AppealVerdict`] etc.
//! Those names are NOT redefined here. New downstream code MUST consume
//! the existing typed versions; they use richer typed-ID fields
//! (`TypedAppealId` / `EventId`) than a raw-string rewrite would.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Did;

// ---------------------------------------------------------------------------
// Agent protocol envelope (agent.schema.json)
// ---------------------------------------------------------------------------

/// Lifecycle state shared by `ck.agent.protocol_session.status` events
/// (and `ck.applet.protocol_session.status` — see [`AppletProtocolEnvelope`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSessionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Wire shape for the `ck.agent.*` event family
/// (`agent.schema.json`). Mirrors the applet envelope but terminates
/// in a `*.result` event carrying [`AgentAuditBinding`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProtocolEnvelope {
    /// Stable agent runtime identifier. Spec v1: this is a DID;
    /// `ck:agent:*` is not a registered typed-id kind.
    pub agent_id: Did,
    /// HTTPS endpoint advertised by `ck.agent.endpoint` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    /// Per-invocation correlation id used by `protocol_session.start /
    /// .status / .result` to pair request/response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lifecycle state for `ck.agent.protocol_session.status` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ProtocolSessionStatus>,
    /// Caller-supplied parameters for `protocol_session.start`. Opaque
    /// to soland — agent runtimes interpret per agent manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Terminal payload for `ck.agent.protocol_session.result`.
    /// Free-form; agents document the shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Runtime-side detail surface (intermediate progress, bridge
    /// identifier, error context, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
    /// Signed audit binding emitted with the terminal `*.result`
    /// event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_binding: Option<AgentAuditBinding>,
}

/// Signed audit binding emitted with the terminal
/// `ck.agent.protocol_session.result` event so callers can prove the
/// agent runtime executed under a specific capability grant.
///
/// This is the **wire envelope** that gets serialised onto the
/// `audit_binding` field of [`AgentProtocolEnvelope`]. Verification and
/// signing of these bindings lives in
/// `cokret_sdk::agent_binding` (Ed25519 implementation).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentAuditBinding {
    /// Grant reference. Wire form: `ck:grant:<uuidv7>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

// ---------------------------------------------------------------------------
// Applet protocol envelope (applet.schema.json)
// ---------------------------------------------------------------------------

/// Wire shape for the `ck.applet.*` event family
/// (`applet.schema.json`): registration, discovery,
/// `protocol_session.start`, `.status`, and `bridge_error`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletProtocolEnvelope {
    /// Stable applet identifier. Either a DID or the registered
    /// typed-id form `ck:applet:<uuidv7>`. Arbitrary opaque strings
    /// are NOT valid wire identifiers — bridge-specific aliases
    /// belong in `namespace` / `external_ref` extension fields.
    pub applet_id: String,
    /// DID of the service that hosts the applet runtime (used by
    /// registration / discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    /// Per-invocation correlation id used by `protocol_session.start /
    /// .status` to pair request/response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lifecycle state for `ck.applet.protocol_session.status` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ProtocolSessionStatus>,
    /// Caller-supplied parameters for `protocol_session.start`. Opaque
    /// to soland — bridge implementations interpret per applet manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Bridge-side detail surface (echo response payload, error
    /// context, bridge identifier, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
    /// Bridge-error context for `ck.applet.bridge_error` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AppletErrorContext>,
    /// Applet manifest snapshot at registration time (capability
    /// requirements, supported intents, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
}

/// Bridge-error context for `ck.applet.bridge_error` events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletErrorContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Moderation queue item (moderation-queue-item.schema.json)
// ---------------------------------------------------------------------------

/// Lifecycle status shared by `ModerationReport` and `ModerationQueueItem`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueStatus {
    Submitted,
    Triaged,
    Reviewing,
    Actioned,
    Dismissed,
    Appealed,
    Closed,
}

/// Priority bucket for queue routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueuePriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Visibility class describing what evidence form the queue carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModerationQueueVisibility {
    MetadataOnly,
    EncryptedEvidence,
    PlaintextEvidence,
    FrankingProofOnly,
}

/// Evidence-handling policy embedded in a queue item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationEvidencePolicy {
    pub plaintext_allowed: bool,
    pub requires_franking_proof_verification: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<bool>,
}

/// Moderation queue container (`ck.component.moderation_queue.v1` cell
/// body). Mirrors `moderation-queue-item.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationQueueItem {
    /// `ck:moderation_queue_item:<uuidv7>`.
    pub id: String,
    /// The full report this queue entry represents. Stored as
    /// [`serde_json::Value`] so callers can choose to deserialise into
    /// the existing `ModerationReport` struct without forcing a
    /// circular dependency between this module and `profiles.rs`.
    pub report: Value,
    pub status: ModerationQueueStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<ModerationQueuePriority>,
    pub visibility: ModerationQueueVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assigned_to: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_policy: Option<ModerationEvidencePolicy>,
    /// `ck:event:<uuidv7>` references to audit events recording queue
    /// actions (decisions, redirects, dismissals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn agent_envelope_round_trips_minimal() {
        let env = AgentProtocolEnvelope {
            agent_id: Did::new("did:web:agent.example.com".to_owned()).unwrap(),
            endpoint_url: None,
            session_id: None,
            status: None,
            params: None,
            result: None,
            detail: None,
            audit_binding: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        assert_eq!(json_text, r#"{"agent_id":"did:web:agent.example.com"}"#);
        let parsed: AgentProtocolEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn agent_envelope_status_round_trips() {
        let env = AgentProtocolEnvelope {
            agent_id: Did::new("did:web:agent.example.com".to_owned()).unwrap(),
            endpoint_url: None,
            session_id: Some("session-1".to_owned()),
            status: Some(ProtocolSessionStatus::Running),
            params: Some(json!({"input": "hello"})),
            result: None,
            detail: None,
            audit_binding: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        assert!(json_text.contains(r#""status":"running""#));
        let parsed: AgentProtocolEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn applet_envelope_round_trips() {
        let env = AppletProtocolEnvelope {
            applet_id: "ck:applet:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            service_did: Some(Did::new("did:web:bridge.example.com".to_owned()).unwrap()),
            session_id: Some("sess-1".to_owned()),
            status: Some(ProtocolSessionStatus::Completed),
            params: None,
            detail: Some(json!({"bridge": "matrix"})),
            error: None,
            manifest: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        let parsed: AppletProtocolEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn queue_item_round_trips() {
        let item = ModerationQueueItem {
            id: "ck:moderation_queue_item:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            report: json!({"realm_id": "ck:realm:...", "reason": "spam"}),
            status: ModerationQueueStatus::Submitted,
            priority: Some(ModerationQueuePriority::Normal),
            visibility: ModerationQueueVisibility::MetadataOnly,
            assigned_to: vec![],
            evidence_policy: Some(ModerationEvidencePolicy {
                plaintext_allowed: false,
                requires_franking_proof_verification: true,
                retention_expires_at: None,
                legal_hold: None,
            }),
            audit_refs: vec![],
            created_at: Utc::now(),
            updated_at: None,
        };
        let json_text = serde_json::to_string(&item).unwrap();
        assert!(json_text.contains(r#""status":"submitted""#));
        assert!(json_text.contains(r#""visibility":"metadata_only""#));
        let parsed: ModerationQueueItem = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, item);
    }
}
