//! Typed producer-side Event drafting boundaries.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use arkret_canonical::DigestSuite;
use arkret_wire::{
    ActorId, AppletId, AuthoredEvent, AuthorizationRef, EventKind, EventRef, ExtensionManifest,
    RegistryContentRef, ScopeRef,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{EventDraftError, EventIntent, EventSpec, Result};

/// A standard Event draft whose kind and payload type are one type-level fact.
pub struct TypedEventDraft<K: EventSpec> {
    scope_ref: ScopeRef,
    actor_id: ActorId,
    payload: K::Payload,
    refs: Vec<EventRef>,
    executed_by: Option<ActorId>,
    authorization_ref: Option<AuthorizationRef>,
    applet_id: Option<AppletId>,
    external_ref: Option<BTreeMap<String, Value>>,
    marker: PhantomData<K>,
}

impl<K: EventSpec> TypedEventDraft<K> {
    pub fn new(scope_ref: ScopeRef, actor_id: ActorId, payload: K::Payload) -> Result<Self> {
        K::validate_payload(&payload).map_err(|error| {
            EventDraftError::Protocol(format!("{} payload invalid: {error}", K::KIND_STR))
        })?;
        Ok(Self {
            scope_ref,
            actor_id,
            payload,
            refs: Vec::new(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            marker: PhantomData,
        })
    }

    pub fn with_refs(mut self, refs: Vec<EventRef>) -> Self {
        self.refs = refs;
        self
    }

    pub fn with_ref(mut self, event_ref: EventRef) -> Self {
        self.refs.push(event_ref);
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

    /// Erase the marker only after its payload has been validated. Authority
    /// stream position is intentionally not part of this producer draft.
    pub fn into_intent(self, created_at: DateTime<Utc>) -> Result<EventIntent> {
        let payload = serde_json::to_value(self.payload)?;
        let Value::Object(payload) = payload else {
            return Err(EventDraftError::Protocol(format!(
                "{} payload must serialize as a JSON object",
                K::KIND_STR
            )));
        };
        Ok(EventIntent::new(
            K::KIND,
            self.scope_ref,
            self.actor_id,
            created_at,
            payload.into_iter().collect(),
        )
        .with_refs(self.refs)
        .with_optional_executed_by(self.executed_by)
        .with_optional_authorization_ref(self.authorization_ref)
        .with_optional_applet_id(self.applet_id)
        .with_optional_external_ref(self.external_ref))
    }

    pub fn author_with_digest_suite(
        self,
        created_at: DateTime<Utc>,
        digest_suite: DigestSuite,
    ) -> Result<AuthoredEvent> {
        self.into_intent(created_at)?
            .author_with_digest_suite(digest_suite)
    }
}

/// Runtime validator used by extension authoring after manifest loading.
pub trait ExtensionPayloadValidator {
    fn validate_payload(
        &self,
        schema_ref: &RegistryContentRef,
        payload: &Value,
    ) -> arkret_wire::Result<()>;
}

/// Producer coordinates needed to finalize a validated extension Event.
#[derive(Clone, Debug)]
pub struct EventAuthoringContext {
    pub scope_ref: ScopeRef,
    pub actor_id: ActorId,
    pub created_at: DateTime<Utc>,
    pub digest_suite: DigestSuite,
}

impl<F> ExtensionPayloadValidator for F
where
    F: Fn(&RegistryContentRef, &Value) -> arkret_wire::Result<()>,
{
    fn validate_payload(
        &self,
        schema_ref: &RegistryContentRef,
        payload: &Value,
    ) -> arkret_wire::Result<()> {
        self(schema_ref, payload)
    }
}

/// Extension payload proven against one digest-pinned schema declared by its
/// loaded manifest. Standard kinds are rejected at this boundary.
pub struct ValidatedExtensionPayload {
    kind: EventKind,
    payload: BTreeMap<String, Value>,
    schema_ref: RegistryContentRef,
    manifest_id: String,
}

impl ValidatedExtensionPayload {
    pub fn validate(
        kind: EventKind,
        payload: Value,
        manifest: &ExtensionManifest,
        schema_ref: &RegistryContentRef,
        validator: &impl ExtensionPayloadValidator,
    ) -> Result<Self> {
        if !matches!(kind, EventKind::Unknown(_)) {
            return Err(EventDraftError::Protocol(
                "extension authoring rejects registered standard Event kinds".to_owned(),
            ));
        }
        let namespace_prefix = format!("{}.", manifest.namespace.trim_end_matches('.'));
        if !kind.as_str().starts_with(&namespace_prefix) {
            return Err(EventDraftError::Protocol(format!(
                "extension Event kind '{}' is outside manifest namespace '{}'",
                kind.as_str(),
                manifest.namespace
            )));
        }
        if !manifest.payload_schema_refs.contains(schema_ref) {
            return Err(EventDraftError::Protocol(format!(
                "extension manifest '{}' does not declare payload schema '{}'",
                manifest.manifest_id, schema_ref.registry_id
            )));
        }
        let Value::Object(payload) = payload else {
            return Err(EventDraftError::Protocol(
                "extension Event payload must be a JSON object".to_owned(),
            ));
        };
        validator.validate_payload(schema_ref, &Value::Object(payload.clone()))?;
        Ok(Self {
            kind,
            payload: payload.into_iter().collect(),
            schema_ref: schema_ref.clone(),
            manifest_id: manifest.manifest_id.clone(),
        })
    }

    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    pub fn schema_ref(&self) -> &RegistryContentRef {
        &self.schema_ref
    }

    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub fn author(self, context: EventAuthoringContext) -> Result<AuthoredEvent> {
        EventIntent::new(
            self.kind,
            context.scope_ref,
            context.actor_id,
            context.created_at,
            self.payload,
        )
        .author_with_digest_suite(context.digest_suite)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::DeviceReanchorPayload;
    use arkret_wire::{
        AccountId, ConfidentialityClass, DidCoreId, ExtensionManifest, Hash,
        ManifestResourceLimits, ProtocolLayerKind, RealmId, RegistryContentRef, event_spec,
    };
    use serde_json::json;

    use super::*;
    use crate::EventPayloadExt;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn schema_ref(name: &str, byte: char) -> RegistryContentRef {
        RegistryContentRef {
            registry_id: name.to_owned(),
            digest: hash(byte),
            retrieval_url: None,
        }
    }

    fn extension_manifest(schema_ref: RegistryContentRef) -> ExtensionManifest {
        ExtensionManifest {
            manifest_id: "ak.manifest.example.v1".to_owned(),
            extension_id: "ak.extension.example.v1".to_owned(),
            namespace: "ak.example".to_owned(),
            protocol_layer_kind: ProtocolLayerKind::Extension,
            manifest_digest: hash('a'),
            publisher_id: DidCoreId::new("ak:did_core:web:publisher.example").unwrap(),
            published_at: "2026-08-09T00:00:00Z".parse().unwrap(),
            dependency_refs: Vec::new(),
            payload_schema_refs: vec![schema_ref],
            reducer_contract_refs: Vec::new(),
            required_actions: Vec::new(),
            confidentiality_class: ConfidentialityClass::PlaintextAllowed,
            transport_rail_ids: Vec::new(),
            recovery_profile_ref: None,
            federation_profile_ref: None,
            conformance_vector_refs: Vec::new(),
            resource_limits: ManifestResourceLimits::default(),
            proofs: Vec::new(),
        }
    }

    #[test]
    fn device_reanchor_typed_draft_authors_the_registered_event() {
        let payload: DeviceReanchorPayload = serde_json::from_value(json!({
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkholder",
                "station_id": "ak:did_core:web:station.example"
            },
            "recovery_authority_kind": "pcr_policy",
            "recovery_policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "recovery_policy_version": 3,
            "recovery_session_id": "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c",
            "previous_device_generation": 7,
            "new_device_generation": 8,
            "replacement_authorize_payload_digest": format!("sha256:{}", "a".repeat(64))
        }))
        .unwrap();
        let principal = DidCoreId::new("ak:did_core:webvh:z6mkholder").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();

        let event = TypedEventDraft::<event_spec::DeviceReanchor>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            ActorId::account(AccountId::new(principal, station)),
            payload.clone(),
        )
        .unwrap()
        .author_with_digest_suite("2026-09-19T00:00:00Z".parse().unwrap(), DigestSuite::Sha256)
        .unwrap();

        assert_eq!(event.event().kind, event_spec::DeviceReanchor::KIND);
        assert_eq!(event.event().realm_id, realm_id);
        assert_eq!(
            event
                .event()
                .typed_payload::<event_spec::DeviceReanchor>()
                .unwrap(),
            payload
        );
    }

    #[test]
    fn extension_authoring_requires_namespace_declared_schema_and_validator() {
        let reference = schema_ref("ak.schema.example.note.v1", 'b');
        let manifest = extension_manifest(reference.clone());
        let validator = |_: &RegistryContentRef, payload: &Value| {
            payload
                .get("text")
                .and_then(Value::as_str)
                .map(|_| ())
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol("example note requires text".to_owned())
                })
        };

        let validated = ValidatedExtensionPayload::validate(
            EventKind::from_wire("ak.example.note"),
            json!({"text": "hello"}),
            &manifest,
            &reference,
            &validator,
        )
        .unwrap();
        assert_eq!(validated.kind().as_str(), "ak.example.note");
    }
}
