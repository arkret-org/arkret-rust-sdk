//! SDK-local operation drafts and the registry-backed envelope builder.

use arkret_models_collaboration::sync_frames::account_sync::DeviceMessageTarget;
use arkret_models_crypto::mls_envelopes::{
    MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
use arkret_wire::{
    Audience, CriticalExtension, DeviceMessageId, Did, Event, EventId, EventRef, EventRequirements,
    FeatureRef, GrantId, Hash, Hlc, OperationId, OperationKind, ProfileRef, Proof,
    ProofBindingRequirements, ProtocolKind, RealmId, ScopeRef, SignatureBindingPayload, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::registry::EventDraftKindRegistry;
use crate::{EventDraftError, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub schema: String,
    pub operation_id: OperationId,
    pub record_kind: String,
    pub operation_kind: OperationKind,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub object_kind: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub canonical_event_digest: Option<String>,
}

impl Operation {
    /// SDK-local operation draft marker. Operation drafts are builder inputs only; they are not an
    /// Arkret wire schema and MUST be materialized as Event envelopes before submission.
    pub const SCHEMA: &'static str = "ak.local.operation_draft.v1";
    pub fn create(
        operation_id: OperationId,
        realm_id: RealmId,
        object_kind: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            schema: Operation::SCHEMA.to_owned(),
            operation_id,
            record_kind: "operation".to_owned(),
            operation_kind: OperationKind::Create,
            realm_id,
            object_id: None,
            object_kind: object_kind.into(),
            payload,
            refs: Vec::new(),
            idempotency_key: None,
            created_at: Utc::now(),
            canonical_event_digest: None,
        }
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(self)?)
    }

    /// Canonical acting-principal accessor for operation payloads.
    ///
    /// Resolves the actor DID from the payload object by probing the alias
    /// fields in this fixed priority order:
    /// `actor_id` → `sender` → `actor` → `member` → `subject` →
    /// `created_by` → `updated_by`. An alias only wins when its value is a
    /// string that parses as a syntactically valid DID ([`Did::new`]);
    /// non-string or malformed values are skipped and the next alias is
    /// tried. Returns `None` when no alias yields a valid DID.
    ///
    /// This is the single-source replacement for the three hand-written
    /// payload-actor extraction copies in soland; downstream crates MUST
    /// call this accessor instead of re-implementing the alias order.
    pub fn actor(&self) -> Option<Did> {
        const ACTOR_ALIASES: [&str; 7] = [
            "actor_id",
            "sender",
            "actor",
            "member",
            "subject",
            "created_by",
            "updated_by",
        ];
        let object = self.payload.as_object()?;
        for alias in ACTOR_ALIASES {
            if let Some(candidate) = object.get(alias).and_then(Value::as_str)
                && let Ok(did) = Did::new(candidate)
            {
                return Some(did);
            }
        }
        None
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationEnvelope {
    pub operation_id: OperationId,
    pub scope_ref: ScopeRef,
    pub actor_id: Did,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub causal: CausalRef,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEnvelope {
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
    pub fn into_event_envelope(self, conversion: OperationEventConversion) -> Result<Event> {
        let mut event = Event::new(
            self.kind.clone(),
            self.scope_ref,
            self.actor_id,
            self.causal.actor_seq,
            self.causal.hlc,
            self.payload,
        )?;
        event.prev_refs = conversion.prev_refs;
        event.refs = conversion.refs;
        event.requirements = EventRequirements {
            schema_profile_refs: conversion.schema_profile_refs,
            required_features: conversion.required_features,
            critical_extensions: conversion.critical_extensions,
        };
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
pub struct OperationEnvelopeBuilder {
    operation_id: OperationId,
    scope_ref: ScopeRef,
    actor_id: Did,
    kind: String,
    target_ref: Option<String>,
    deps: Vec<OperationId>,
    hlc: Hlc,
    actor_seq: u64,
    payload: Value,
    authz_ref: Option<GrantId>,
    proofs: Vec<Proof>,
}

impl OperationEnvelopeBuilder {
    /// Create a builder for one registered operation kind.
    pub fn new(
        operation_id: OperationId,
        scope_ref: ScopeRef,
        actor_id: Did,
        kind: impl Into<String>,
        actor_seq: u64,
        hlc: Hlc,
    ) -> Self {
        Self {
            operation_id,
            scope_ref,
            actor_id,
            kind: kind.into(),
            target_ref: None,
            deps: Vec::new(),
            hlc,
            actor_seq,
            payload: Value::Object(Default::default()),
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

    /// Replace the payload object.
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// Insert one payload field.
    pub fn with_payload_field(mut self, field: impl Into<String>, value: Value) -> Self {
        if !self.payload.is_object() {
            self.payload = Value::Object(Default::default());
        }
        if let Value::Object(payload) = &mut self.payload {
            payload.insert(field.into(), value);
        }
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
        let validation = registry.canonicalize(&self.kind)?;
        let envelope = OperationEnvelope {
            operation_id: self.operation_id,
            scope_ref: self.scope_ref,
            actor_id: self.actor_id,
            kind: validation.canonical_kind,
            target_ref: self.target_ref,
            causal: CausalRef {
                deps: self.deps,
                hlc: self.hlc,
                actor_seq: self.actor_seq,
            },
            payload: self.payload,
            authz_ref: self.authz_ref,
            proofs: self.proofs,
        };
        registry.validate_envelope(&envelope)?;
        Ok(envelope)
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

/// Build repo [`Operation`] drafts from MLS transport envelopes.
///
/// The envelope wire shapes live in `arkret_models_crypto::mls_envelopes`;
/// this extension trait keeps the draft binding (envelope → repo
/// operation) on the event-draft side so the data crate never depends on
/// the drafting layer.
pub trait MlsEnvelopeOperationExt {
    /// Build a repo operation that carries this MLS envelope.
    fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation>;
}

impl MlsEnvelopeOperationExt for MlsProposalEnvelope {
    fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_proposal",
            serde_json::to_value(self)?,
        );
        operation.object_id = Some(format!(
            "{}:{}:{}",
            self.group_id, self.epoch, self.proposal_type
        ));
        Ok(operation)
    }
}

impl MlsEnvelopeOperationExt for MlsCommitEnvelope {
    fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_commit",
            serde_json::to_value(self)?,
        );
        operation.object_id = Some(format!("{}:{}", self.group_id, self.epoch));
        Ok(operation)
    }
}

impl MlsEnvelopeOperationExt for MlsWelcomeEnvelope {
    fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_welcome",
            serde_json::to_value(self)?,
        );
        operation.object_id = Some(format!(
            "{}:{}:{}:{}",
            self.group_id, self.epoch, self.recipient_principal_id, self.recipient_device_id
        ));
        Ok(operation)
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
        Ok(DeviceMessageTarget {
            message_id,
            kind: ProtocolKind::new("ak.mls.welcome.v1")
                .map_err(|error| EventDraftError::Protocol(error.to_owned()))?,
            content: serde_json::from_value(json!({
                "group_id": self.group_id,
                "epoch": self.epoch,
                "recipient_principal_id": self.recipient_principal_id,
                "recipient_device_id": self.recipient_device_id,
                "welcome": self.welcome,
                "welcome_hash": self.welcome_hash,
                "ratchet_tree": self.ratchet_tree,
            }))?,
            expires_at,
        })
    }
}

#[cfg(test)]
mod actor_accessor_tests {
    use serde_json::json;

    use super::*;

    fn operation_with_payload(payload: Value) -> Operation {
        Operation::create(
            OperationId::new("ak:operation:01904100-0000-7000-8000-000000000001").unwrap(),
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            "message",
            payload,
        )
    }

    #[test]
    fn actor_resolves_aliases_in_priority_order() {
        let operation = operation_with_payload(json!({
            "sender": "did:webvh:QmScid:bob.example",
            "actor_id": "did:webvh:QmScid:alice.example",
        }));
        assert_eq!(
            operation.actor().unwrap().as_str(),
            "did:webvh:QmScid:alice.example",
        );
    }

    #[test]
    fn actor_skips_aliases_that_are_not_valid_dids() {
        let operation = operation_with_payload(json!({
            "actor_id": "not-a-did",
            "sender": 42,
            "member": "did:webvh:QmScid:carol.example",
        }));
        assert_eq!(
            operation.actor().unwrap().as_str(),
            "did:webvh:QmScid:carol.example",
        );
    }

    #[test]
    fn actor_returns_none_without_any_alias() {
        let operation = operation_with_payload(json!({"body": "hello"}));
        assert!(operation.actor().is_none());
        let non_object = operation_with_payload(json!("string payload"));
        assert!(non_object.actor().is_none());
    }
}
