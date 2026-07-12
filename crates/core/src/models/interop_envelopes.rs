//! Applet protocol object models.

use super::*;

// ---------------------------------------------------------------------------
// Applet protocol object (applet.schema.json)
// ---------------------------------------------------------------------------

/// Wire shape for the registered `ak.applet.*` protocol object fields.
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
            error: None,
            manifest: Some(json!({"name": "bridge"})),
        };
        let json_text = serde_json::to_string(&env).unwrap();
        let parsed: AppletInteropEnvelope = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, env);
    }
}
