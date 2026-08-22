//! Typed authoring boundaries for standard and extension Events.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use arkret_canonical::DigestSuite;
use arkret_wire::{
    AppletId, AuthContext, AuthoredEvent, AuthorizationRef, CriticalExtension, DidCoreId, EventId,
    EventKind, EventRef, EventRequirements, ExtensionManifest, FeatureRef, Hash, Hlc, Precondition,
    ProfileRef, RegistryContentRef, ScopeRef, SealBasis, SealId,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{EventDraftError, EventIntent, EventSpec, Result};

/// A standard Event draft whose kind and payload type are one type-level fact.
///
/// `K` is explicit because multiple standard kinds intentionally share one
/// payload type. There is no method that accepts or overrides a runtime kind.
///
/// A marker cannot be paired with another marker's payload:
///
/// ```compile_fail
/// # use arkret_event_draft::TypedEventDraft;
/// # use arkret_models_collaboration::events_payloads::{MessageCreatePayload, RealmCreatePayload};
/// # use arkret_wire::{DidCoreId, ScopeRef, event_spec};
/// # fn mismatch(scope: ScopeRef, actor: DidCoreId, ps: DidCoreId, payload: MessageCreatePayload) {
/// let _ = TypedEventDraft::<event_spec::RealmCreate>::new(scope, actor, ps, payload);
/// # }
/// ```
pub struct TypedEventDraft<K: EventSpec> {
    scope_ref: ScopeRef,
    actor_id: DidCoreId,
    principal_server_id: DidCoreId,
    payload: K::Payload,
    prev_refs: Vec<EventId>,
    refs: Vec<EventRef>,
    causal_refs: Vec<Hash>,
    preconditions: Vec<Precondition>,
    seal_ref: Option<SealId>,
    auth_context: Option<AuthContext>,
    seal_basis: Option<SealBasis>,
    requirements: EventRequirements,
    executed_by: Option<DidCoreId>,
    authorization_ref: Option<AuthorizationRef>,
    applet_id: Option<AppletId>,
    external_ref: Option<BTreeMap<String, Value>>,
    marker: PhantomData<K>,
}

impl<K: EventSpec> TypedEventDraft<K> {
    pub fn new(
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        principal_server_id: DidCoreId,
        payload: K::Payload,
    ) -> Result<Self> {
        K::validate_payload(&payload).map_err(|error| {
            EventDraftError::Protocol(format!("{} payload invalid: {error}", K::KIND_STR))
        })?;
        Ok(Self {
            scope_ref,
            actor_id,
            principal_server_id,
            payload,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            marker: PhantomData,
        })
    }

    pub fn with_prev_refs(mut self, prev_refs: Vec<EventId>) -> Self {
        self.prev_refs = prev_refs;
        self
    }

    pub fn with_refs(mut self, refs: Vec<EventRef>) -> Self {
        self.refs = refs;
        self
    }

    pub fn with_ref(mut self, event_ref: EventRef) -> Self {
        self.refs.push(event_ref);
        self
    }

    pub fn with_causal_refs(mut self, causal_refs: Vec<Hash>) -> Self {
        self.causal_refs = causal_refs;
        self
    }

    pub fn with_preconditions(mut self, preconditions: Vec<Precondition>) -> Self {
        self.preconditions = preconditions;
        self
    }

    pub fn with_seal_ref(mut self, seal_ref: SealId) -> Self {
        self.seal_ref = Some(seal_ref);
        self
    }

    pub fn with_auth_context(mut self, auth_context: AuthContext) -> Self {
        self.auth_context = Some(auth_context);
        self
    }

    pub fn with_seal_basis(mut self, seal_basis: SealBasis) -> Self {
        self.seal_basis = Some(seal_basis);
        self
    }

    pub fn with_requirements(mut self, requirements: EventRequirements) -> Self {
        self.requirements = requirements;
        self
    }

    pub fn with_schema_profile_ref(mut self, profile_ref: ProfileRef) -> Self {
        self.requirements.schema_profile_refs.push(profile_ref);
        self
    }

    pub fn with_required_feature(mut self, feature_ref: FeatureRef) -> Self {
        self.requirements.required_features.push(feature_ref);
        self
    }

    pub fn with_critical_extension(mut self, extension: CriticalExtension) -> Self {
        self.requirements.critical_extensions.push(extension);
        self
    }

    pub fn with_executed_by(mut self, executed_by: DidCoreId) -> Self {
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

    /// Erase `K` into a kind-agnostic [`EventIntent`] after proving the
    /// marker's payload pairing.
    ///
    /// This is how a heterogeneous command bus or durable queue holds drafts of
    /// many kinds without authoring first: [`EventIntent`] carries every
    /// producer decision and no derived identity.
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
            self.principal_server_id,
            created_at,
            payload.into_iter().collect(),
        )
        .with_prev_refs(self.prev_refs)
        .with_refs(self.refs)
        .with_causal_refs(self.causal_refs)
        .with_preconditions(self.preconditions)
        .with_requirements(self.requirements)
        .with_optional_seal_ref(self.seal_ref)
        .with_optional_auth_context(self.auth_context)
        .with_optional_seal_basis(self.seal_basis)
        .with_optional_executed_by(self.executed_by)
        .with_optional_authorization_ref(self.authorization_ref)
        .with_optional_applet_id(self.applet_id)
        .with_optional_external_ref(self.external_ref))
    }

    /// Author under the Realm's declared content digest suite. Callers must
    /// obtain this suite from accepted Realm state; it is used for both the
    /// placeholder-derived genesis Realm id and the final content-bound Event
    /// id.
    pub fn author_with_digest_suite(
        self,
        actor_seq: u64,
        hlc: Hlc,
        created_at: DateTime<Utc>,
        digest_suite: DigestSuite,
    ) -> Result<AuthoredEvent> {
        self.into_intent(created_at)?
            .author_with_digest_suite(actor_seq, hlc, digest_suite)
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
        let payload_value = Value::Object(payload.clone());
        validator.validate_payload(schema_ref, &payload_value)?;
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

    pub fn author(
        self,
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        principal_server_id: DidCoreId,
        actor_seq: u64,
        hlc: Hlc,
        created_at: DateTime<Utc>,
        digest_suite: DigestSuite,
    ) -> Result<AuthoredEvent> {
        EventIntent::new(
            self.kind,
            scope_ref,
            actor_id,
            principal_server_id,
            created_at,
            self.payload,
        )
        .author_with_digest_suite(actor_seq, hlc, digest_suite)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        ConfidentialityClass, ExtensionManifest, Hash, ManifestResourceLimits, ProtocolLayerKind,
        RegistryContentRef,
    };
    use serde_json::json;

    use super::*;

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
    fn extension_authoring_requires_namespace_declared_schema_and_validator() {
        let reference = schema_ref("ak.schema.example.note.v1", 'b');
        let manifest = extension_manifest(reference.clone());
        let validator = |_: &RegistryContentRef, payload: &Value| {
            if payload.get("text").and_then(Value::as_str).is_some() {
                Ok(())
            } else {
                Err(arkret_wire::WireError::Protocol(
                    "example note requires text".to_owned(),
                ))
            }
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

        assert!(
            ValidatedExtensionPayload::validate(
                EventKind::MessageCreate,
                json!({"text": "hello"}),
                &manifest,
                &reference,
                &validator,
            )
            .is_err()
        );
        assert!(
            ValidatedExtensionPayload::validate(
                EventKind::from_wire("ak.exampleevil.note"),
                json!({"text": "hello"}),
                &manifest,
                &reference,
                &validator,
            )
            .is_err()
        );
        assert!(
            ValidatedExtensionPayload::validate(
                EventKind::from_wire("ak.example.note"),
                json!({}),
                &manifest,
                &reference,
                &validator,
            )
            .is_err()
        );
        assert!(
            ValidatedExtensionPayload::validate(
                EventKind::from_wire("ak.example.note"),
                json!({"text": "hello"}),
                &manifest,
                &schema_ref("ak.schema.other.v1", 'c'),
                &validator,
            )
            .is_err()
        );
    }
}
