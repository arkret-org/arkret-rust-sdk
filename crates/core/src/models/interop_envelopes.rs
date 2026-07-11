//! Applet interop envelope models.

use super::*;

// ---------------------------------------------------------------------------
// Applet interop shared types
// ---------------------------------------------------------------------------

/// Lifecycle state for `ak.applet.interop_session.status` events.
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

// ---------------------------------------------------------------------------
// Applet interop envelope (applet.schema.json)
// ---------------------------------------------------------------------------

/// Wire shape for the `ak.applet.*` event family
/// (`applet.schema.json`): registration, discovery,
/// `interop_session.start`, `.status`, and `bridge_error`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletInteropEnvelope {
    /// Stable applet identifier. Either a DID or the registered
    /// typed-id form `ak:applet:<uuidv7>`. Arbitrary opaque strings
    /// are NOT valid wire identifiers — bridge-specific aliases
    /// belong in `namespace` / `external_ref` extension fields.
    pub applet_id: String,
    /// DID of the service that hosts the applet runtime (used by
    /// registration / discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    /// Per-invocation correlation id used by `interop_session.start /
    /// .status` to pair request/response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lifecycle state for `ak.applet.interop_session.status` events.
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
    /// Bridge-error context for `ak.applet.bridge_error` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AppletErrorContext>,
    /// Applet manifest snapshot at registration time (capability
    /// requirements, supported intents, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
}

/// Bridge-error context for `ak.applet.bridge_error` events.
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
    fn applet_envelope_round_trips() {
        let env = AppletInteropEnvelope {
            applet_id: "ak:applet:01970e58-9d21-7000-8000-aaaaaaaaaaaa".to_owned(),
            service_id: Some(
                Did::new("did:webvh:z6mkfixture:bridge.example.com".to_owned()).unwrap(),
            ),
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
