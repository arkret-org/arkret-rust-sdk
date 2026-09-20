//! Kind-erased producer intent for one Event.
//!
//! Authority ordering is deliberately absent. A producer creates and signs an
//! Event; the current governance Station later places that immutable Event in
//! exactly one Realm, Circle, or Sidecar commit stream.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_wire::{
    ActorId, AppletId, AuthoredEvent, AuthorizationRef, EventId, EventKind, RealmId, ScopeRef,
    SemanticRef,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;

/// Complete producer-selected Event content before its content-derived id is
/// finalized.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventIntent {
    kind: EventKind,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    created_at: DateTime<Utc>,
    payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    semantic_refs: Vec<SemanticRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executed_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_ref: Option<AuthorizationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_ref: Option<BTreeMap<String, Value>>,
}

impl EventIntent {
    pub(crate) fn new(
        kind: EventKind,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        created_at: DateTime<Utc>,
        payload: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            kind,
            scope_ref,
            actor_id,
            created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
            payload,
            semantic_refs: Vec::new(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
        }
    }

    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    pub fn scope_ref(&self) -> &ScopeRef {
        &self.scope_ref
    }

    pub fn realm_id_opt(&self) -> Option<&RealmId> {
        self.scope_ref.realm_id_opt()
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn payload(&self) -> &BTreeMap<String, Value> {
        &self.payload
    }

    pub fn semantic_refs(&self) -> &[SemanticRef] {
        &self.semantic_refs
    }

    pub fn executed_by(&self) -> Option<&ActorId> {
        self.executed_by.as_ref()
    }

    pub fn authorization_ref(&self) -> Option<&AuthorizationRef> {
        self.authorization_ref.as_ref()
    }

    pub fn applet_id(&self) -> Option<&AppletId> {
        self.applet_id.as_ref()
    }

    pub fn typed_payload<K: crate::EventSpec>(&self) -> Result<K::Payload> {
        if self.kind != K::KIND {
            return Err(crate::EventDraftError::Protocol(format!(
                "intent kind {} does not match requested payload {}",
                self.kind.as_str(),
                K::KIND_STR
            )));
        }
        serde_json::from_value(Value::Object(self.payload.clone().into_iter().collect())).map_err(
            |error| {
                crate::EventDraftError::Protocol(format!(
                    "{} payload invalid: {error}",
                    K::KIND_STR
                ))
            },
        )
    }

    pub fn with_scope_ref(mut self, scope_ref: ScopeRef) -> Result<Self> {
        if self.scope_ref == ScopeRef::RealmGenesis {
            return Err(crate::EventDraftError::Protocol(format!(
                "{} is a Realm genesis and cannot be narrowed to another scope",
                self.kind.as_str()
            )));
        }
        self.scope_ref = scope_ref;
        Ok(self)
    }

    pub fn with_created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = arkret_canonical::normalize_timestamp_canonical(created_at);
        self
    }

    pub fn with_semantic_refs(mut self, semantic_refs: Vec<SemanticRef>) -> Self {
        self.semantic_refs = semantic_refs;
        self
    }

    pub fn with_semantic_ref(mut self, event_ref: SemanticRef) -> Self {
        self.semantic_refs.push(event_ref);
        self
    }

    pub fn with_optional_executed_by(mut self, executed_by: Option<ActorId>) -> Self {
        self.executed_by = executed_by;
        self
    }

    pub fn with_optional_authorization_ref(
        mut self,
        authorization_ref: Option<AuthorizationRef>,
    ) -> Self {
        self.authorization_ref = authorization_ref;
        self
    }

    pub fn with_optional_applet_id(mut self, applet_id: Option<AppletId>) -> Self {
        self.applet_id = applet_id;
        self
    }

    pub fn with_optional_external_ref(
        mut self,
        external_ref: Option<BTreeMap<String, Value>>,
    ) -> Self {
        self.external_ref = external_ref;
        self
    }

    pub fn with_executed_by(mut self, executed_by: ActorId) -> Self {
        self.executed_by = Some(executed_by);
        self
    }

    pub fn with_authorization_ref(mut self, authorization_ref: AuthorizationRef) -> Self {
        self.authorization_ref = Some(authorization_ref);
        self
    }

    pub fn with_applet_id(mut self, applet_id: AppletId) -> Self {
        self.applet_id = Some(applet_id);
        self
    }

    pub fn with_external_ref(mut self, external_ref: BTreeMap<String, Value>) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    /// Finalize the producer Event. Stream position and predecessor are added
    /// only to the Station-authored `RealmCommit`, never to this Event.
    pub fn author_with_digest_suite(self, digest_suite: DigestSuite) -> Result<AuthoredEvent> {
        Ok(AuthoredEvent::finalize_with_digest_suite(
            self.into_unauthored_envelope(),
            digest_suite,
        )?)
    }

    fn into_unauthored_envelope(self) -> arkret_wire::Event {
        let placeholder = EventId::from_digest(DigestSuite::Sha256, [0; 32]);
        let realm_id = self
            .scope_ref
            .realm_id_opt()
            .cloned()
            .unwrap_or_else(|| RealmId::from_event_id(&placeholder));
        arkret_wire::Event {
            event_id: placeholder,
            kind: self.kind,
            realm_id,
            scope_ref: self.scope_ref,
            actor_id: self.actor_id,
            executed_by: self.executed_by,
            authorization_ref: self.authorization_ref,
            applet_id: self.applet_id,
            external_ref: self.external_ref,
            created_at: self.created_at,
            semantic_refs: self.semantic_refs,
            payload: self.payload,
            producer_proof: None,
        }
    }

    /// Recover producer-selected content from an Event without importing any
    /// Station ordering metadata.
    pub fn from_authored(event: &arkret_wire::Event) -> Self {
        Self {
            kind: event.kind.clone(),
            scope_ref: event.scope_ref.clone(),
            actor_id: event.actor_id.clone(),
            created_at: event.created_at,
            payload: event.payload.clone(),
            semantic_refs: event.semantic_refs.clone(),
            executed_by: event.executed_by.clone(),
            authorization_ref: event.authorization_ref.clone(),
            applet_id: event.applet_id.clone(),
            external_ref: event.external_ref.clone(),
        }
    }

    pub fn matches_authored_event(&self, event: &arkret_wire::Event) -> bool {
        self.kind == event.kind
            && self.scope_ref == event.scope_ref
            && self.actor_id == event.actor_id
            && self.created_at == event.created_at
            && self.payload == event.payload
            && self.semantic_refs == event.semantic_refs
            && self.executed_by == event.executed_by
            && self.authorization_ref == event.authorization_ref
            && self.applet_id == event.applet_id
            && self.external_ref == event.external_ref
    }
}
