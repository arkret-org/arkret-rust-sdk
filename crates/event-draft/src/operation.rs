//! SDK-local operation drafts and the registry-backed envelope builder.

use arkret_models_collaboration::sync_frames::account_sync::DeviceMessageTarget;
use arkret_models_crypto::mls_envelopes::{
    MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
use arkret_wire::{
    Audience, AuthorizationRef, CriticalExtension, DeviceMessageId, DidCoreId, Event, EventId,
    EventKind, EventRef, EventRequirements, FeatureRef, GrantId, Hash, Hlc, OperationId,
    OperationKind, Precondition, ProfileRef, Proof, ProofBindingRequirements, RealmId, ScopeRef,
    SealBasis, SealId, SignatureBindingPayload, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::registry::EventDraftKindRegistry;
use crate::typed_event_draft::author_erased_event;
use crate::{EventDraftError, EventSpec, Result, TypedDeviceMessageTarget, device_message_spec};

/// Envelope facts consumed while projecting one accepted Event.
///
/// These values are never merged into the signed payload. Keeping them beside
/// the payload prevents projection code from probing aliases such as
/// `sender`/`actor_id` or maintaining enrich/strip field lists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionContext {
    pub sender: DidCoreId,
    pub actor_seq: u64,
    pub event_id: EventId,
    pub preconditions: Vec<Precondition>,
    pub accepted_event_id: EventId,
    pub canonical_event_digest: Hash,
    pub envelope_causal_refs: Vec<Hash>,
    pub seal_ref: Option<SealId>,
    pub seal_basis: Option<SealBasis>,
    pub hlc: Option<Hlc>,
    pub executed_by: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<AuthorizationRef>,
    pub accepted_scope_ref: ScopeRef,
}

/// Erased heterogeneous reducer input projected from an accepted Event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectedEventOperation {
    pub schema: String,
    pub operation_id: OperationId,
    pub record_kind: String,
    pub operation_kind: OperationKind,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub event_kind: EventKind,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub context: ProjectionContext,
}

impl ProjectedEventOperation {
    pub const SCHEMA: &'static str = "ak.local.projected_event_operation.v1";

    /// Project one already accepted Event without rewriting its signed payload.
    pub fn from_accepted_event(
        operation_id: OperationId,
        operation_kind: OperationKind,
        object_id: Option<String>,
        event: &Event,
    ) -> Result<Self> {
        Ok(Self {
            schema: Self::SCHEMA.to_owned(),
            operation_id,
            record_kind: "operation".to_owned(),
            operation_kind,
            realm_id: event.realm_id.clone(),
            object_id,
            event_kind: event.kind.clone(),
            payload: Value::Object(event.payload.clone().into_iter().collect()),
            refs: event.refs.clone(),
            idempotency_key: None,
            created_at: event.created_at,
            context: ProjectionContext {
                sender: event.actor_id.clone(),
                actor_seq: event.actor_seq,
                event_id: event.event_id.clone(),
                preconditions: event.preconditions.clone(),
                accepted_event_id: event.event_id.clone(),
                canonical_event_digest: Hash::new(event.event_digest()?)?,
                envelope_causal_refs: event.causal_refs.clone(),
                seal_ref: event.seal_ref.clone(),
                seal_basis: event.seal_basis.clone(),
                hlc: event.hlc.clone(),
                executed_by: event.executed_by.clone(),
                authorization_ref: event.authorization_ref.clone(),
                accepted_scope_ref: event.scope_ref.clone(),
            },
        })
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(self)?)
    }

    pub fn validate_payload_object(&self) -> Result<()> {
        if self.payload.is_object() {
            Ok(())
        } else {
            Err(EventDraftError::Protocol(
                "operation payload must be a JSON object".to_owned(),
            ))
        }
    }

    /// Borrow-independent minimal input for the registry effect projector.
    /// This never fabricates a signed Event from an incomplete projection DTO.
    pub fn projection_input(&self) -> Result<arkret_wire::ProjectedEventInput> {
        let Value::Object(payload) = self.payload.clone() else {
            return Err(EventDraftError::Protocol(
                "operation payload must be a JSON object".to_owned(),
            ));
        };
        Ok(arkret_wire::ProjectedEventInput {
            kind: self.event_kind.clone(),
            event_id: self.context.event_id.clone(),
            actor_id: self.context.sender.clone(),
            authorization_ref: self.context.authorization_ref.clone(),
            actor_seq: self.context.actor_seq,
            realm_id: self.realm_id.clone(),
            created_at: self.created_at,
            payload: payload.into_iter().collect(),
            refs: self.refs.clone(),
            preconditions: self.context.preconditions.clone(),
            seal_ref: self.context.seal_ref.clone(),
            seal_basis: self.context.seal_basis.clone(),
        })
    }

    /// Decode the signed payload only when this projection carries the marker's
    /// exact Event kind.
    pub fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
        if self.event_kind != K::KIND {
            return Err(arkret_wire::WireError::PayloadKindMismatch {
                expected: K::KIND_STR,
                actual: self.event_kind.as_str().to_owned(),
            }
            .into());
        }
        let payload = serde_json::from_value(self.payload.clone()).map_err(|source| {
            arkret_wire::WireError::PayloadInvalid {
                kind: K::KIND_STR,
                reason: source.to_string(),
            }
        })?;
        K::validate_payload(&payload).map_err(|error| arkret_wire::WireError::PayloadInvalid {
            kind: K::KIND_STR,
            reason: error.to_string(),
        })?;
        Ok(payload)
    }
}

mod local_operation_sealed {
    pub trait Sealed {}
}

/// Type binding for the three non-Event MLS scheduler drafts.
pub trait LocalOperationSpec: local_operation_sealed::Sealed + 'static {
    const OBJECT_KIND: &'static str;
    type Payload: Clone + Serialize;
}

pub mod local_operation_spec {
    #[derive(Clone, Copy, Debug)]
    pub struct MlsProposal;
    #[derive(Clone, Copy, Debug)]
    pub struct MlsCommit;
    #[derive(Clone, Copy, Debug)]
    pub struct MlsWelcome;
}

macro_rules! local_operation_specs {
    ($($marker:ty => ($kind:literal, $payload:ty)),+ $(,)?) => {
        $(
            impl local_operation_sealed::Sealed for $marker {}
            impl LocalOperationSpec for $marker {
                const OBJECT_KIND: &'static str = $kind;
                type Payload = $payload;
            }
        )+
    };
}

local_operation_specs! {
    local_operation_spec::MlsProposal => ("mls_proposal", MlsProposalEnvelope),
    local_operation_spec::MlsCommit => ("mls_commit", MlsCommitEnvelope),
    local_operation_spec::MlsWelcome => ("mls_welcome", MlsWelcomeEnvelope),
}

/// A local scheduler draft. It is not an Event or reducer projection.
#[derive(Clone, Debug, Serialize)]
pub struct LocalOperationDraft<K: LocalOperationSpec> {
    pub schema: String,
    pub operation_id: OperationId,
    pub record_kind: String,
    pub operation_kind: OperationKind,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub object_kind: &'static str,
    pub payload: K::Payload,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl<K: LocalOperationSpec> LocalOperationDraft<K> {
    pub const SCHEMA: &'static str = "ak.local.operation_draft.v1";

    fn new(operation_id: OperationId, realm_id: RealmId, payload: K::Payload) -> Self {
        Self {
            schema: Self::SCHEMA.to_owned(),
            operation_id,
            record_kind: "operation".to_owned(),
            operation_kind: OperationKind::Create,
            realm_id,
            object_id: None,
            object_kind: K::OBJECT_KIND,
            payload,
            refs: Vec::new(),
            idempotency_key: None,
            created_at: Utc::now(),
        }
    }

    fn with_object_id(mut self, object_id: String) -> Self {
        self.object_id = Some(object_id);
        self
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(self)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationEnvelope {
    pub operation_id: OperationId,
    pub scope_ref: ScopeRef,
    pub actor_id: DidCoreId,
    pub(crate) kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub causal: CausalRef,
    pub(crate) payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEnvelope {
    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    pub fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
        if self.kind != K::KIND {
            return Err(arkret_wire::WireError::PayloadKindMismatch {
                expected: K::KIND_STR,
                actual: self.kind.as_str().to_owned(),
            }
            .into());
        }
        let payload = serde_json::from_value(self.payload.clone()).map_err(|source| {
            arkret_wire::WireError::PayloadInvalid {
                kind: K::KIND_STR,
                reason: source.to_string(),
            }
        })?;
        K::validate_payload(&payload).map_err(|error| arkret_wire::WireError::PayloadInvalid {
            kind: K::KIND_STR,
            reason: error.to_string(),
        })?;
        Ok(payload)
    }

    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(&self.digest_payload()?)?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(EventDraftError::Protocol(
                "operation envelope proofs must contain at least one proof".to_owned(),
            ));
        }
        if !self.payload.is_object() {
            return Err(EventDraftError::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this operation's digest.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.operation_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.event_digest != expected_hash {
                return Err(EventDraftError::Protocol(format!(
                    "operation proof event_digest '{}' does not match operation digest '{}'",
                    proof.event_digest, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn validate_proof_bindings_with_context(
        &self,
        domain: Option<String>,
        audience: Option<Audience>,
        requirements: ProofBindingRequirements,
    ) -> Result<()> {
        let expected_hash = Hash::new(self.operation_digest()?)?;
        for proof in &self.proofs {
            let expected = SignatureBindingPayload {
                payload_digest: expected_hash.clone(),
                actor_id: self.actor_id.clone(),
                verification_method: proof.verification_method.clone(),
                created_at: proof.created_at,
                domain: domain.clone(),
                audience: audience.clone(),
            };
            proof.validate_binding_with_requirements(&expected, requirements)?;
        }
        Ok(())
    }

    /// Materialize this SDK-local operation draft as a signed Event Envelope.
    ///
    /// Operation envelopes are not Arkret v1 wire facts. Callers must choose
    /// the event causal/auth references during conversion, then submit the
    /// returned [`Event`] to network, sync, federation or reducers.
    pub(crate) fn into_event_envelope(self, conversion: OperationEventConversion) -> Result<Event> {
        let Value::Object(payload) = self.payload else {
            return Err(EventDraftError::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
            ));
        };
        let mut event = author_erased_event(
            self.kind,
            self.scope_ref,
            self.actor_id,
            self.causal.actor_seq,
            self.causal.hlc,
            Utc::now(),
            arkret_canonical::DigestSuite::Sha256,
            payload.into_iter().collect(),
            conversion.prev_refs,
            conversion.refs,
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            EventRequirements {
                schema_profile_refs: conversion.schema_profile_refs,
                required_features: conversion.required_features,
                critical_extensions: conversion.critical_extensions,
            },
            None,
            None,
            None,
            None,
            None,
        )?;
        event.proofs = conversion.proofs;
        event.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(self.operation_id.to_string()),
        );
        if !self.causal.deps.is_empty() {
            event.unsigned.insert(
                "local_operation_dependencies".to_owned(),
                serde_json::to_value(self.causal.deps)?,
            );
        }
        if let Some(target_ref) = self.target_ref {
            event
                .unsigned
                .insert("local_target_ref".to_owned(), Value::String(target_ref));
        }
        Ok(event)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OperationEventConversion {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_profile_refs: Vec<ProfileRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<FeatureRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub critical_extensions: Vec<CriticalExtension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEventConversion {
    pub fn with_prev_ref(mut self, event_id: EventId) -> Self {
        self.prev_refs.push(event_id);
        self
    }

    pub fn with_authorized_by_ref(mut self, grant_id: GrantId) -> Self {
        self.refs.push(EventRef::authorized_by_grant(grant_id));
        self
    }

    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proofs.push(proof);
        self
    }
}

/// Registry-backed builder for [`OperationEnvelope`].
#[derive(Clone, Debug)]
pub struct OperationEnvelopeBuilder<K: EventSpec> {
    operation_id: OperationId,
    scope_ref: ScopeRef,
    actor_id: DidCoreId,
    target_ref: Option<String>,
    deps: Vec<OperationId>,
    hlc: Hlc,
    actor_seq: u64,
    payload: K::Payload,
    authz_ref: Option<GrantId>,
    proofs: Vec<Proof>,
}

impl<K: EventSpec> OperationEnvelopeBuilder<K> {
    /// Create a builder for one registered operation kind.
    pub fn new(
        operation_id: OperationId,
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        actor_seq: u64,
        hlc: Hlc,
        payload: K::Payload,
    ) -> Self {
        Self {
            operation_id,
            scope_ref,
            actor_id,
            target_ref: None,
            deps: Vec::new(),
            hlc,
            actor_seq,
            payload,
            authz_ref: None,
            proofs: Vec::new(),
        }
    }

    /// Set a target reference.
    pub fn with_target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Add a causal dependency.
    pub fn with_dependency(mut self, dependency: OperationId) -> Self {
        self.deps.push(dependency);
        self
    }

    /// Attach an authorization reference.
    pub fn with_authz_ref(mut self, authz_ref: GrantId) -> Self {
        self.authz_ref = Some(authz_ref);
        self
    }

    /// Attach a proof.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Build and validate the operation envelope against a registry.
    pub fn build(self, registry: &EventDraftKindRegistry) -> Result<OperationEnvelope> {
        K::validate_payload(&self.payload)?;
        let payload = serde_json::to_value(self.payload)?;
        let validation = registry.canonicalize(K::KIND.as_str())?;
        let envelope = OperationEnvelope {
            operation_id: self.operation_id,
            scope_ref: self.scope_ref,
            actor_id: self.actor_id,
            kind: EventKind::from_wire(&validation.canonical_kind),
            target_ref: self.target_ref,
            causal: CausalRef {
                deps: self.deps,
                hlc: self.hlc,
                actor_seq: self.actor_seq,
            },
            payload,
            authz_ref: self.authz_ref,
            proofs: self.proofs,
        };
        registry.validate_envelope(&envelope)?;
        Ok(envelope)
    }

    /// Validate the marker-bound payload and materialize its standard Event in
    /// one typed authoring chain. A deserialized raw [`OperationEnvelope`]
    /// cannot call this conversion.
    pub fn into_event_envelope(
        self,
        registry: &EventDraftKindRegistry,
        conversion: OperationEventConversion,
    ) -> Result<Event> {
        self.build(registry)?.into_event_envelope(conversion)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalRef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<OperationId>,
    pub hlc: Hlc,
    pub actor_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationSignature {
    pub key_id: String,
    pub signature_algorithm: String,
    pub sig: String,
}

/// Build typed local scheduler drafts from MLS transport envelopes.
///
/// The envelope wire shapes live in `arkret_models_crypto::mls_envelopes`;
/// this extension trait keeps the draft binding (envelope → repo
/// operation) on the event-draft side so the data crate never depends on
/// the drafting layer.
pub trait MlsEnvelopeOperationExt {
    type Spec: LocalOperationSpec;

    /// Build a repo operation that carries this MLS envelope.
    fn operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<LocalOperationDraft<Self::Spec>>;
}

impl MlsEnvelopeOperationExt for MlsProposalEnvelope {
    type Spec = local_operation_spec::MlsProposal;

    fn operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<LocalOperationDraft<Self::Spec>> {
        Ok(
            LocalOperationDraft::new(operation_id, realm_id, self.clone()).with_object_id(format!(
                "{}:{}:{}",
                self.group_id, self.epoch, self.proposal_type
            )),
        )
    }
}

impl MlsEnvelopeOperationExt for MlsCommitEnvelope {
    type Spec = local_operation_spec::MlsCommit;

    fn operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<LocalOperationDraft<Self::Spec>> {
        Ok(
            LocalOperationDraft::new(operation_id, realm_id, self.clone())
                .with_object_id(format!("{}:{}", self.group_id, self.epoch)),
        )
    }
}

impl MlsEnvelopeOperationExt for MlsWelcomeEnvelope {
    type Spec = local_operation_spec::MlsWelcome;

    fn operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<LocalOperationDraft<Self::Spec>> {
        Ok(
            LocalOperationDraft::new(operation_id, realm_id, self.clone()).with_object_id(format!(
                "{}:{}:{}:{}",
                self.group_id, self.epoch, self.recipient_principal_id, self.recipient_device_id
            )),
        )
    }
}

/// Project an MLS Welcome transport envelope into a `DeviceMessageTarget`.
///
/// A `Welcome` is delivered out-of-band to the invitee's device via the
/// to-device channel. The `DeviceMessageTarget` wire shape is owned by
/// `arkret-models-collaboration`, so this binding lives on the event-draft
/// side (which already depends on it) rather than in the OpenMLS-isolation
/// layer (`arkret-mls`), which must not reach the collaboration crate.
pub trait MlsWelcomeTargetExt {
    /// Build the `ak.mls.welcome.v1` to-device target that carries this
    /// Welcome to the recipient device.
    fn welcome_device_message_target(
        &self,
        message_id: DeviceMessageId,
        expires_at: DateTime<Utc>,
    ) -> Result<DeviceMessageTarget>;
}

impl MlsWelcomeTargetExt for MlsWelcomeEnvelope {
    fn welcome_device_message_target(
        &self,
        message_id: DeviceMessageId,
        expires_at: DateTime<Utc>,
    ) -> Result<DeviceMessageTarget> {
        TypedDeviceMessageTarget::<device_message_spec::MlsWelcome>::new(
            message_id,
            expires_at,
            self.clone(),
        )?
        .build()
    }
}
