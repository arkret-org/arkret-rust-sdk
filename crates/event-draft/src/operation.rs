//! SDK-local reducer projections and MLS scheduler drafts.
//!
//! Producer Events are authored directly through [`crate::TypedEventDraft`].
//! There is no second signed operation envelope and no producer-side causal
//! chain; ordering belongs exclusively to Station-authored RealmCommit streams.

use arkret_models_crypto::mls_envelopes::{
    MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
use arkret_wire::{
    ActorId, AuthorizationRef, DeviceId, Did, Event, EventId, EventKind, Hash, OperationId,
    OperationKind, RealmId, ScopeRef, SemanticRef, canonical, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EventDraftError, EventSpec, Result};

/// Accepted Event facts retained beside a local reducer projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionContext {
    pub sender: ActorId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_device_id: Option<DeviceId>,
    pub event_id: EventId,
    pub accepted_event_id: EventId,
    pub canonical_event_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<AuthorizationRef>,
    pub accepted_scope_ref: ScopeRef,
    /// Verified accepting Commit facts, supplied by the local receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_ref: Option<arkret_wire::CommittedEventRef>,
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
    pub semantic_refs: Vec<SemanticRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub context: ProjectionContext,
}

impl ProjectedEventOperation {
    pub const SCHEMA: &'static str = "org.arkret.sdk.projected_event_operation.v1";

    pub fn from_accepted_event(
        operation_id: OperationId,
        operation_kind: OperationKind,
        object_id: Option<String>,
        event: &Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        arkret_wire::forbidden_wire::validate_event_payload_forbidden_fields(
            &event.kind,
            &payload,
        )?;
        Ok(Self {
            schema: Self::SCHEMA.to_owned(),
            operation_id,
            record_kind: "operation".to_owned(),
            operation_kind,
            realm_id: event.realm_id.clone(),
            object_id,
            event_kind: event.kind.clone(),
            payload,
            semantic_refs: event.semantic_refs.clone(),
            idempotency_key: None,
            created_at: event.created_at,
            context: ProjectionContext {
                sender: event.actor_id.clone(),
                producer_device_id: producer_device_id(event),
                event_id: event.event_id.clone(),
                accepted_event_id: event.event_id.clone(),
                canonical_event_digest: Hash::new(
                    event.event_digest_with_digest_suite(digest_suite)?,
                )?,
                executed_by: event.executed_by.clone(),
                authorization_ref: event.authorization_ref.clone(),
                accepted_scope_ref: event.scope_ref.clone(),
                committed_ref: None,
            },
        })
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(self)?)
    }

    /// Attach receiver-verified Commit coordinates without changing the Event.
    pub fn with_committed_ref(mut self, reference: arkret_wire::CommittedEventRef) -> Result<Self> {
        let stream = arkret_wire::CommitStreamRef::from_scope(
            &self.context.accepted_scope_ref,
            Some(self.realm_id.clone()),
        )?;
        if reference.event_id != self.context.accepted_event_id
            || reference.stream_ref != stream
            || reference.stream_ref.realm_id() != &self.realm_id
        {
            return Err(EventDraftError::Protocol(
                "accepting Commit does not cover the projected Event scope".to_owned(),
            ));
        }
        self.context.committed_ref = Some(reference);
        Ok(self)
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
            realm_id: self.realm_id.clone(),
            created_at: self.created_at,
            payload: payload.into_iter().collect(),
            semantic_refs: self.semantic_refs.clone(),
        })
    }

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

fn producer_device_id(event: &Event) -> Option<DeviceId> {
    let producer_proof = event.producer_proof.as_ref()?;
    let (controller, fragment) = producer_proof
        .verification_method
        .as_str()
        .split_once('#')?;
    let controller = Did::new(controller.to_owned()).ok()?;
    let signer_id = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    if &project_did_to_core_id(&controller).ok()? != signer_id.signing_principal_id() {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

mod local_operation_sealed {
    pub trait Sealed {}
}

/// Type binding for local MLS scheduler records. They are never Events and do
/// not participate in RealmCommit stream ordering.
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
    pub semantic_refs: Vec<SemanticRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl<K: LocalOperationSpec> LocalOperationDraft<K> {
    pub const SCHEMA: &'static str = "org.arkret.sdk.operation_draft.v1";

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
            semantic_refs: Vec::new(),
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

pub trait MlsEnvelopeOperationExt {
    type Spec: LocalOperationSpec;

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
        let endpoint = match &self.recipient {
            arkret_models_crypto::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => format!("device:{principal_id}:{device_id}"),
            arkret_models_crypto::MlsEndpointIdentity::AgentRuntime {
                agent_id,
                verification_method,
                agent_key_authorize_event_id,
            } => format!("agent:{agent_id}:{verification_method}:{agent_key_authorize_event_id}"),
            arkret_models_crypto::MlsEndpointIdentity::MinimalMetadataPairwise {
                pairwise_actor_id,
                verification_method,
            } => format!("pairwise:{pairwise_actor_id}:{verification_method}"),
        };
        Ok(
            LocalOperationDraft::new(operation_id, realm_id, self.clone())
                .with_object_id(format!("{}:{}:{endpoint}", self.group_id, self.epoch)),
        )
    }
}

#[cfg(test)]
mod committed_projection_tests {
    use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
    use arkret_wire::{
        AccountId, CircleId, CommitStreamRef, CommittedEventRef, DidCoreId, RealmCommitId,
        StrandId, event_spec,
    };
    use chrono::TimeZone;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap()
    }

    fn circle_scope() -> ScopeRef {
        ScopeRef::Circle {
            realm_id: realm(),
            circle_id: CircleId::new("ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu")
                .unwrap(),
        }
    }

    fn authored_projection(scope: ScopeRef, body: &str) -> (Event, ProjectedEventOperation) {
        let principal = DidCoreId::new("ak:did_core:web:projection-author.example").unwrap();
        let payload = MessageCreatePayload::with_content(
            StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
            "discussion",
            ContentBlock::text(body),
        );
        let authored = crate::TypedEventDraft::<event_spec::MessageCreate>::new(
            scope,
            ActorId::account(AccountId::new(principal.clone(), principal)),
            payload,
        )
        .unwrap()
        .author_with_digest_suite(
            Utc.with_ymd_and_hms(2026, 9, 28, 0, 0, 0).single().unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let event = authored.event().clone();
        let operation = ProjectedEventOperation::from_accepted_event(
            OperationId::new("ak:operation:018cc7fa-7c00-7000-8000-000000000001").unwrap(),
            OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        (event, operation)
    }

    fn accepting_ref(event: &Event) -> CommittedEventRef {
        CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                event.event_id.as_str().as_bytes(),
            )),
            stream_ref: CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .unwrap(),
            stream_position: 7,
        }
    }

    #[test]
    fn matching_realm_and_circle_commit_context_preserves_canonical_event_facts() {
        for scope in [ScopeRef::Realm { realm_id: realm() }, circle_scope()] {
            let (event, operation) = authored_projection(scope, "accepted message");
            let preimage =
                arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
            let input = operation.projection_input().unwrap();
            let payload = operation.payload.clone();
            let digest = operation.context.canonical_event_digest.clone();
            let reference = accepting_ref(&event);
            let attached = operation.with_committed_ref(reference.clone()).unwrap();
            assert_eq!(attached.context.committed_ref, Some(reference));
            assert_eq!(attached.context.event_id, event.event_id);
            assert_eq!(attached.context.accepted_event_id, event.event_id);
            assert_eq!(attached.context.canonical_event_digest, digest);
            assert_eq!(attached.payload, payload);
            assert_eq!(attached.projection_input().unwrap(), input);
            assert_eq!(
                arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap(),
                preimage
            );
        }
    }

    #[test]
    fn commit_context_rejects_scope_and_realm_mismatch() {
        let (event, operation) =
            authored_projection(ScopeRef::Realm { realm_id: realm() }, "realm message");
        let mismatches = [
            CommitStreamRef::from_scope(&circle_scope(), None).unwrap(),
            CommitStreamRef::Realm {
                realm_id: RealmId::new("ak:realm:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
                    .unwrap(),
            },
        ];
        for stream_ref in mismatches {
            let mut reference = accepting_ref(&event);
            reference.stream_ref = stream_ref;
            assert!(matches!(
                operation.clone().with_committed_ref(reference),
                Err(EventDraftError::Protocol(_))
            ));
        }
        let (circle_event, circle_operation) =
            authored_projection(circle_scope(), "circle message");
        let mut reference = accepting_ref(&circle_event);
        reference.stream_ref = CommitStreamRef::Realm { realm_id: realm() };
        assert!(matches!(
            circle_operation.with_committed_ref(reference),
            Err(EventDraftError::Protocol(_))
        ));
    }

    #[test]
    fn commit_context_rejects_another_content_bound_event_in_the_same_stream() {
        let scope = ScopeRef::Realm { realm_id: realm() };
        let (event, operation) = authored_projection(scope.clone(), "original message");
        let (other, _) = authored_projection(scope, "different message");
        assert_ne!(event.event_id, other.event_id);
        let mut reference = accepting_ref(&event);
        reference.event_id = other.event_id;
        assert!(matches!(
            operation.with_committed_ref(reference),
            Err(EventDraftError::Protocol(_))
        ));
    }
}
