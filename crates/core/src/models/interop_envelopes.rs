//! Agent and applet interop envelope models.

use super::*;

// ---------------------------------------------------------------------------
// Agent interop envelope (agent.schema.json)
// ---------------------------------------------------------------------------

/// Lifecycle state shared by `ck.agent.interop_session.status` events
/// (and `ck.applet.interop_session.status` — see [`AppletInteropEnvelope`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InteropSessionStatus {
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
pub struct AgentInteropEnvelope {
    /// Stable agent runtime identifier. Spec v1: this is a DID;
    /// `ck:agent:*` is not a registered typed-id kind.
    pub agent_id: Did,
    /// HTTPS endpoint advertised by `ck.agent.endpoint` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    /// Per-invocation correlation id used by `interop_session.start /
    /// .status / .result` to pair request/response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lifecycle state for `ck.agent.interop_session.status` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InteropSessionStatus>,
    /// Caller-supplied parameters for `interop_session.start`. Opaque
    /// to soland — agent runtimes interpret per agent manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Terminal payload for `ck.agent.interop_session.result`.
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
/// `ck.agent.interop_session.result` event so callers can prove the
/// agent runtime executed under a specific capability grant.
///
/// This is the **wire envelope** that gets serialised onto the
/// `audit_binding` field of [`AgentInteropEnvelope`]. Verification and
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
// Applet interop envelope (applet.schema.json)
// ---------------------------------------------------------------------------

/// Wire shape for the `ck.applet.*` event family
/// (`applet.schema.json`): registration, discovery,
/// `interop_session.start`, `.status`, and `bridge_error`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletInteropEnvelope {
    /// Stable applet identifier. Either a DID or the registered
    /// typed-id form `ck:applet:<uuidv7>`. Arbitrary opaque strings
    /// are NOT valid wire identifiers — bridge-specific aliases
    /// belong in `namespace` / `external_ref` extension fields.
    pub applet_id: String,
    /// DID of the service that hosts the applet runtime (used by
    /// registration / discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<Did>,
    /// Per-invocation correlation id used by `interop_session.start /
    /// .status` to pair request/response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lifecycle state for `ck.applet.interop_session.status` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InteropSessionStatus>,
    /// Caller-supplied parameters for `interop_session.start`. Opaque
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn agent_envelope_round_trips_minimal() {
        let env = AgentInteropEnvelope {
            agent_id: Did::new("did:webvh:z6mkfixture:agent.example.com".to_owned()).unwrap(),
            endpoint_url: None,
            session_id: None,
            status: None,
            params: None,
            result: None,
            detail: None,
            audit_binding: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        assert_eq!(json_text, r#"{"agent_id":"did:webvh:z6mkfixture:agent.example.com"}"#);
        let parsed: AgentInteropEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn agent_envelope_status_round_trips() {
        let env = AgentInteropEnvelope {
            agent_id: Did::new("did:webvh:z6mkfixture:agent.example.com".to_owned()).unwrap(),
            endpoint_url: None,
            session_id: Some("session-1".to_owned()),
            status: Some(InteropSessionStatus::Running),
            params: Some(json!({"input": "hello"})),
            result: None,
            detail: None,
            audit_binding: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        assert!(json_text.contains(r#""status":"running""#));
        let parsed: AgentInteropEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn applet_envelope_round_trips() {
        let env = AppletInteropEnvelope {
            applet_id: "ck:applet:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            service_did: Some(Did::new("did:webvh:z6mkfixture:bridge.example.com".to_owned()).unwrap()),
            session_id: Some("sess-1".to_owned()),
            status: Some(InteropSessionStatus::Completed),
            params: None,
            detail: Some(json!({"bridge": "matrix"})),
            error: None,
            manifest: None,
        };
        let json_text = serde_json::to_string(&env).unwrap();
        let parsed: AppletInteropEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }
}
