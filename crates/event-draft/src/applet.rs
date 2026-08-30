//! Applet-originated Event materialization.

use std::collections::BTreeMap;

use arkret_identifiers::AppletId;
use arkret_models_integration::{
    AppletBridgeErrorClass, AppletBridgeErrorPayload, AppletBridgeVisibilityScope,
};
use arkret_wire::{ActorId, NonEmptyString, RealmId, ScopeRef};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{EventDraftError, EventIntent, Result, TypedEventDraft};

/// Draft builder for the canonical `ak.applet.bridge_error` Event payload.
#[derive(Clone, Debug)]
pub struct AppletBridgeErrorBuilder {
    realm_id: RealmId,
    applet_id: AppletId,
    actor_id: ActorId,
    failed_transaction_ref: String,
    error_class: AppletBridgeErrorClass,
    error_code: String,
    retriable: bool,
    visibility_scope: AppletBridgeVisibilityScope,
    message: Option<String>,
    external_ref: Option<Value>,
    retry_after_ms: Option<u64>,
}

impl AppletBridgeErrorBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm_id: RealmId,
        applet_id: AppletId,
        actor_id: ActorId,
        failed_transaction_ref: impl Into<String>,
        error_class: AppletBridgeErrorClass,
        error_code: impl Into<String>,
        retriable: bool,
        visibility_scope: AppletBridgeVisibilityScope,
    ) -> Self {
        Self {
            realm_id,
            applet_id,
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

    pub fn with_external_ref(mut self, external_ref: Value) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    pub fn build(self, created_at: DateTime<Utc>) -> Result<EventIntent> {
        let external_ref = self
            .external_ref
            .map(|value| match value {
                Value::Object(entries) => Ok(entries.into_iter().collect::<BTreeMap<_, _>>()),
                _ => Err(EventDraftError::Protocol(
                    "applet bridge external_ref must be an object".to_owned(),
                )),
            })
            .transpose()?;
        let payload = AppletBridgeErrorPayload {
            applet_id: self.applet_id,
            realm_id: self.realm_id.clone(),
            failed_transaction_ref: self.failed_transaction_ref,
            error_class: self.error_class,
            error_code: NonEmptyString::new(self.error_code)
                .map_err(|reason| EventDraftError::Protocol(reason.to_owned()))?,
            retriable: self.retriable,
            visibility_scope: self.visibility_scope,
            external_ref,
            message: self.message,
            retry_after_ms: self.retriable.then_some(self.retry_after_ms).flatten(),
        };
        TypedEventDraft::<arkret_wire::event_spec::AppletBridgeError>::new(
            ScopeRef::Realm {
                realm_id: self.realm_id,
            },
            self.actor_id,
            payload,
        )?
        .into_intent(created_at)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AppletId, DidCoreId, EventKind};
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
    }

    #[test]
    fn bridge_error_builder_emits_canonical_typed_payload() {
        let event = AppletBridgeErrorBuilder::new(
            realm(),
            AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
            ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture:bot.example").unwrap()),
            "ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s",
            AppletBridgeErrorClass::ExternalNetwork,
            "external_rate_limited",
            true,
            AppletBridgeVisibilityScope::RealmAdmins,
        )
        .with_external_ref(json!({"slack_response_code": 429}))
        .with_retry_after_ms(1000)
        .build("2026-05-26T10:30:00.000Z".parse().unwrap())
        .unwrap();

        assert_eq!(event.kind(), &EventKind::AppletBridgeError);
        assert_eq!(event.payload()["realm_id"], realm().as_str());
        assert_eq!(event.payload()["error_class"], "external_network");
        assert_eq!(event.payload()["visibility_scope"], "realm_admins");
        assert_eq!(event.payload()["retry_after_ms"], 1000);
        assert_eq!(event.payload()["external_ref"]["slack_response_code"], 429);
    }

    #[test]
    fn bridge_error_builder_rejects_non_object_external_ref() {
        let result = AppletBridgeErrorBuilder::new(
            realm(),
            AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
            ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture:bot.example").unwrap()),
            "ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s",
            AppletBridgeErrorClass::Schema,
            "invalid_external_ref",
            false,
            AppletBridgeVisibilityScope::AppletController,
        )
        .with_external_ref(json!(["not", "an", "object"]))
        .build("2026-05-26T10:30:00.000Z".parse().unwrap());

        assert!(matches!(result, Err(EventDraftError::Protocol(_))));
    }
}
