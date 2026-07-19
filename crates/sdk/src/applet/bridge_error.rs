use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, Event, Hlc, RealmId, Result};

// ─── S-11 / S-13: ak.applet.bridge_error builder ──────────────────────────

/// Who MAY see a `ak.applet.bridge_error` Event. Spec `applet-schema.md`
/// §7 makes `visibility_scope` a **required** enum; clients MUST restrict
/// display accordingly and MUST NOT leak bridge-internal detail to
/// unrelated members. Serializes as snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorVisibility {
    /// Realm administrators only.
    RealmAdmins,
    /// The Applet controller only.
    AppletController,
    /// All Realm members.
    RealmMembers,
}

/// Closed `error_class` enum for `ak.applet.bridge_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorClass {
    ExternalNetwork,
    Auth,
    Schema,
    RateLimit,
    Policy,
}

/// Build a `ak.applet.bridge_error` Event per spec `applet-schema.md` §7
/// (authoritative `applet_bridge_error_payload`).
///
/// External Applets MUST emit this Event rather than silently dropping
/// upstream-network failures. The payload MUST bind `realm_id`,
/// `failed_transaction_ref`, `retriable` and `visibility_scope`; missing
/// any required field is rejected as `schema_violation`. The builder
/// takes all required fields up front so a bridge error can never be
/// built without them.
///
/// S-13 (2026-06-04): replaces the prior `severity` / `target_ref` shape
/// — the spec landed `error_class` / `retriable` / `visibility_scope` /
/// `failed_transaction_ref` instead.
#[derive(Clone, Debug)]
pub struct AppletBridgeErrorBuilder {
    realm_id: RealmId,
    applet_id: String,
    actor_id: Did,
    failed_transaction_ref: String,
    error_class: AppletBridgeErrorClass,
    error_code: String,
    retriable: bool,
    visibility_scope: AppletBridgeErrorVisibility,
    message: Option<String>,
    external_ref: Option<Value>,
    retry_after_ms: Option<u64>,
}

impl AppletBridgeErrorBuilder {
    /// `applet_id` is the typed `ak:applet:<uuidv7>` (or DID); `actor_id`
    /// is the bot / system DID emitting the error. `failed_transaction_ref`
    /// points at the failed transaction / source Event (e.g. a push
    /// `event_id`) and MUST NOT inline unauthorized external plaintext.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm_id: RealmId,
        applet_id: impl Into<String>,
        actor_id: Did,
        failed_transaction_ref: impl Into<String>,
        error_class: AppletBridgeErrorClass,
        error_code: impl Into<String>,
        retriable: bool,
        visibility_scope: AppletBridgeErrorVisibility,
    ) -> Self {
        Self {
            realm_id,
            applet_id: applet_id.into(),
            actor_id,
            failed_transaction_ref: failed_transaction_ref.into(),
            error_class,
            error_code: error_code.into(),
            retriable,
            visibility_scope,
            message: None,
            external_ref: None,
            retry_after_ms: None,
        }
    }

    /// Human-readable summary. MUST NOT leak unauthorized external
    /// plaintext.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// External network reference (protocol / network id). MUST NOT
    /// contain unauthorized external plaintext.
    pub fn with_external_ref(mut self, external_ref: Value) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    /// Suggested retry delay; only meaningful when `retriable == true`.
    pub fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    pub fn build(self, actor_seq: u64, hlc: Hlc) -> Result<Event> {
        let mut content = serde_json::Map::new();
        content.insert(
            "applet_id".to_owned(),
            Value::String(self.applet_id.clone()),
        );
        content.insert(
            "realm_id".to_owned(),
            Value::String(self.realm_id.as_str().to_owned()),
        );
        content.insert(
            "failed_transaction_ref".to_owned(),
            Value::String(self.failed_transaction_ref.clone()),
        );
        content.insert(
            "error_class".to_owned(),
            serde_json::to_value(self.error_class).expect("error_class is a closed enum"),
        );
        content.insert(
            "error_code".to_owned(),
            Value::String(self.error_code.clone()),
        );
        content.insert("retriable".to_owned(), Value::Bool(self.retriable));
        content.insert(
            "visibility_scope".to_owned(),
            serde_json::to_value(self.visibility_scope).expect("visibility_scope is a closed enum"),
        );
        if let Some(message) = &self.message {
            content.insert("message".to_owned(), Value::String(message.clone()));
        }
        if let Some(external_ref) = &self.external_ref {
            content.insert("external_ref".to_owned(), external_ref.clone());
        }
        if self.retriable
            && let Some(retry_after_ms) = self.retry_after_ms
        {
            content.insert("retry_after_ms".to_owned(), Value::from(retry_after_ms));
        }
        Ok(Event::new(
            "ak.applet.bridge_error",
            self.realm_id,
            self.actor_id,
            actor_seq,
            hlc,
            Value::Object(content),
        )?)
    }
}
