//! Closed preparation of one ordinary Message; encryption precedes the request.
use arkret_canonical::DigestSuite;
use arkret_canonical::serde_helpers::canonical_timestamp;
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{
    AccountId, ActorId, AuthContext, AuthoredEvent, AuthorizationRef, Base64UrlString,
    EncryptedPayloadScheme, Event, EventId, EventKind, EventRef, Hash, Hlc, RealmId, RequestId,
    Result, ScopeRef, SealId, StrandId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::PreparedEventDraft;
use crate::event_sync::RealmActorFrontierView;
use crate::events_payloads::message::{ContentBlock, MessageCreatePayload, MessageTrackName};
use crate::objects::strand::MessageMetadata;

pub const MESSAGE_PREPARE_TTL_SECONDS: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessageEncryptionContext {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub effective_scope: ScopeRef,
    pub sender_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum MessageAuthoringContent {
    Plaintext {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        content: ContentBlock,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<serde_json::Value>)))]
        metadata: Option<MessageMetadata>,
    },
    Mls {
        encrypted_content: EncryptedEnvelope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encrypted_metadata: Option<EncryptedEnvelope>,
        encryption_context: MessageEncryptionContext,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessageAuthoringIntent {
    pub strand_id: StrandId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub track_name: MessageTrackName,
    pub content: MessageAuthoringContent,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<String>,
}

impl MessageAuthoringIntent {
    pub fn payload(&self) -> MessageCreatePayload {
        let mut payload = MessageCreatePayload {
            strand_id: self.strand_id.clone(),
            track_name: "discussion".to_owned(),
            content: None,
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: self.blob_refs.clone(),
            reply_to_id: self.reply_to_id.clone(),
            agent_context: None,
            mimi_provenance: None,
        };
        match &self.content {
            MessageAuthoringContent::Plaintext { content, metadata } => {
                payload.content = Some(content.clone());
                payload.metadata = metadata.clone();
            }
            MessageAuthoringContent::Mls {
                encrypted_content,
                encrypted_metadata,
                ..
            } => {
                payload.encrypted_content = Some(encrypted_content.clone());
                payload.encrypted_metadata = encrypted_metadata.clone();
            }
        }
        payload
    }

    pub fn validate(&self) -> Result<()> {
        if let MessageAuthoringContent::Mls {
            encrypted_content,
            encrypted_metadata,
            encryption_context: c,
        } = &self.content
        {
            for envelope in std::iter::once(encrypted_content).chain(encrypted_metadata.iter()) {
                envelope.reconstruct_pre_encryption_header(
                    c.scheme.clone(),
                    c.effective_scope.clone(),
                    "ak.message.create",
                    &c.sender_domain,
                    None,
                )?;
            }
            if encrypted_metadata.as_ref().is_some_and(|m| {
                m.encryption_context.group_state_ref()
                    != encrypted_content.encryption_context.group_state_ref()
                    || m.encryption_context.epoch() != encrypted_content.encryption_context.epoch()
            }) {
                return Err(invalid(
                    "message and metadata must use the same frozen group state",
                ));
            }
        }
        let payload = self.payload().to_value()?;
        if let Some(content) = payload.get("content") {
            crate::events_payloads::message::validate_content_block(content)
                .map_err(|error| invalid(error.message()))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessagePrepareRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub intent: MessageAuthoringIntent,
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
}

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

impl MessagePrepareRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.intent.validate()?;
        if arkret_canonical::canonical_json_bytes(self)?.len() > 1_048_576 {
            return Err(invalid(
                "message preparation request exceeds canonical byte limit",
            ));
        }
        Ok(())
    }
    pub fn request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.created_at + chrono::Duration::seconds(MESSAGE_PREPARE_TTL_SECONDS)
    }
    pub fn validate_time(&self, now: DateTime<Utc>) -> Result<()> {
        if self.created_at > now || now >= self.expires_at() {
            return Err(invalid("authoring_request_expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessagePrepareOutcome {
    pub request_digest: Hash,
    pub draft: PreparedEventDraft,
    pub accepted_actor_frontier: RealmActorFrontierView,
    #[serde(with = "canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl MessagePrepareOutcome {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        request: &MessagePrepareRequestBody,
        frontier: RealmActorFrontierView,
        scope_ref: ScopeRef,
        seal_ref: SealId,
        auth_context: AuthContext,
        authorization_ref: Option<AuthorizationRef>,
        direct_binding: Option<EventId>,
        suite: DigestSuite,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        request.validate()?;
        request.validate_time(now)?;
        frontier.validate()?;
        let mut event = Event {
            event_id: EventId::from_digest(suite, [0; 32]),
            kind: EventKind::MessageCreate,
            realm_id: request.realm_id.clone(),
            scope_ref,
            actor_id: ActorId::account(request.account_id.clone()),
            actor_seq: frontier.next_actor_seq,
            created_at: request.created_at,
            hlc: request.hlc.clone(),
            prev_refs: frontier.frontier_event_ids.clone(),
            seal_ref: Some(seal_ref),
            auth_context: Some(auth_context),
            authorization_ref,
            executed_by: None,
            applet_id: None,
            external_ref: None,
            seal_basis: None,
            refs: direct_binding
                .map(|id| EventRef::new(id.to_string(), "direct_conversation_binding"))
                .into_iter()
                .collect(),
            causal_refs: vec![],
            preconditions: vec![],
            payload: serde_json::from_value(serde_json::to_value(request.intent.payload())?)?,
            unsigned: Default::default(),
            proofs: vec![],
            requirements: Default::default(),
        };
        event.refresh_content_bound_identity_with_digest_suite(suite)?;
        let outcome = Self {
            request_digest: request.request_digest()?,
            draft: PreparedEventDraft {
                unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(
                    arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?,
                ))
                .map_err(invalid)?,
                event_digest: Hash::new(event.event_digest_with_digest_suite(suite)?)?,
            },
            accepted_actor_frontier: frontier,
            observed_at: now,
            expires_at: request.expires_at(),
        };
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    pub fn validate_for_request(
        &self,
        request: &MessagePrepareRequestBody,
    ) -> Result<AuthoredEvent> {
        self.validate_request_digest(request, &request.request_digest()?)
    }

    /// Bind all canonical request members, including explicitly carried empty
    /// optional collections which a typed serialization may omit.
    pub fn validate_for_canonical_request(&self, bytes: &[u8]) -> Result<AuthoredEvent> {
        let request: MessagePrepareRequestBody =
            arkret_canonical::from_canonical_json_slice(bytes)?;
        self.validate_request_digest(
            &request,
            &Hash::new(arkret_canonical::sha256_digest(bytes))?,
        )
    }

    fn validate_request_digest(
        &self,
        request: &MessagePrepareRequestBody,
        digest: &Hash,
    ) -> Result<AuthoredEvent> {
        request.validate()?;
        self.accepted_actor_frontier.validate()?;
        request.validate_time(self.observed_at)?;
        let authored = self.draft.unsigned_event_for_kind("ak.message.create")?;
        let e = authored.event();
        let f = &self.accepted_actor_frontier;
        if &self.request_digest != digest
            || self.expires_at != request.expires_at()
            || e.realm_id != request.realm_id
            || e.actor_id != ActorId::account(request.account_id.clone())
            || e.created_at != request.created_at
            || e.hlc != request.hlc
            || serde_json::to_value(&e.payload)? != serde_json::to_value(request.intent.payload())?
            || f.realm_id != e.realm_id
            || f.actor_id != e.actor_id
            || e.actor_seq != f.next_actor_seq
            || e.prev_refs != f.frontier_event_ids
            || e.actor_seq > 9_007_199_254_740_991
            || e.seal_ref.is_none()
            || e.auth_context.is_none()
            || e.seal_basis.is_some()
            || !valid_message_refs(e)
            || !e.causal_refs.is_empty()
            || !e.preconditions.is_empty()
            || e.executed_by.is_some()
            || e.applet_id.is_some()
            || e.external_ref.is_some()
            || !e.requirements.is_empty()
            || !e.proofs.is_empty()
            || e.authorization_ref.as_ref().is_some_and(|r| {
                !matches!(
                    r.as_str(),
                    arkret_wire::REALM_AUTHORITY_ROOT_CELL
                        | arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1
                )
            })
        {
            return Err(invalid(
                "prepared message does not preserve exact closed intent",
            ));
        }
        if let MessageAuthoringContent::Mls {
            encryption_context, ..
        } = &request.intent.content
        {
            if e.scope_ref != encryption_context.effective_scope {
                return Err(invalid("prepared message changed frozen encryption scope"));
            }
        }
        Ok(authored)
    }

    /// Compare Station choices with independently known target, signer and
    /// actor history before exposing the Event to the producer signer.
    pub fn verify_for_signing(
        &self,
        request: &MessagePrepareRequestBody,
        scope: &ScopeRef,
        signer: &AuthContext,
        direct_binding: Option<&EventId>,
        known: Option<&RealmActorFrontierView>,
        now: DateTime<Utc>,
    ) -> Result<AuthoredEvent> {
        request.validate_time(now)?;
        let event = self.validate_for_request(request)?;
        if &event.event().scope_ref != scope
            || event.event().auth_context.as_ref() != Some(signer)
            || event.event().refs.first().map(|r| r.id.as_str())
                != direct_binding.map(EventId::as_str)
        {
            return Err(invalid(
                "prepared message target or signer context differs from local intent",
            ));
        }
        if let Some(known) = known {
            known.validate()?;
            let prepared = &self.accepted_actor_frontier;
            if known.realm_id != prepared.realm_id
                || known.actor_id != prepared.actor_id
                || known.next_actor_seq > prepared.next_actor_seq
                || (known.next_actor_seq == prepared.next_actor_seq
                    && known
                        .frontier_event_ids
                        .iter()
                        .any(|id| !prepared.frontier_event_ids.contains(id)))
            {
                return Err(invalid(
                    "prepared message contradicts locally known actor frontier",
                ));
            }
        }
        Ok(event)
    }
}

fn valid_message_refs(event: &Event) -> bool {
    let direct = event.authorization_ref.as_ref().is_some_and(|r| {
        r.as_str() == arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1
    });
    if direct {
        matches!(event.refs.as_slice(), [r] if r.role == "direct_conversation_binding"
            && r.critical && r.proof.is_none() && EventId::new(r.id.clone()).is_ok())
    } else {
        event.refs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> MessagePrepareRequestBody {
        MessagePrepareRequestBody {
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000031").unwrap(),
            account_id: AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ),
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            intent: MessageAuthoringIntent {
                strand_id: StrandId::new("ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
                track_name: MessageTrackName::Discussion,
                content: MessageAuthoringContent::Plaintext {
                    content: ContentBlock::text("hello"),
                    metadata: None,
                },
                blob_refs: vec![],
                reply_to_id: None,
            },
            created_at: "2026-09-12T00:00:00.000Z".parse().unwrap(),
            hlc: None,
        }
    }
    fn auth() -> AuthContext {
        AuthContext {
            key_id: arkret_wire::OpaqueLocalId::new("device:01970000-0000-7000-8000-000000000031")
                .unwrap(),
            key_epoch: 0,
            credential_epoch: None,
        }
    }
    fn prepare(
        request: &MessagePrepareRequestBody,
        seq: u64,
        ids: Vec<EventId>,
    ) -> MessagePrepareOutcome {
        let frontier = RealmActorFrontierView::new(
            request.realm_id.clone(),
            ActorId::account(request.account_id.clone()),
            seq,
            ids,
            DigestSuite::Sha256,
        )
        .unwrap();
        MessagePrepareOutcome::prepare(
            request,
            frontier,
            ScopeRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap(),
            auth(),
            None,
            None,
            DigestSuite::Sha256,
            request.created_at,
        )
        .unwrap()
    }
    #[test]
    fn direct_message_requires_exact_locally_known_binding() {
        let request = request();
        let binding = EventId::from_digest(DigestSuite::Sha256, [7; 32]);
        let frontier = RealmActorFrontierView::new(
            request.realm_id.clone(),
            ActorId::account(request.account_id.clone()),
            0,
            vec![],
            DigestSuite::Sha256,
        )
        .unwrap();
        let scope = ScopeRef::Realm {
            realm_id: request.realm_id.clone(),
        };
        let make = |id| {
            MessagePrepareOutcome::prepare(
                &request,
                frontier.clone(),
                scope.clone(),
                SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap(),
                auth(),
                Some(
                    AuthorizationRef::new(
                        arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_PARTICIPANT_V1,
                    )
                    .unwrap(),
                ),
                id,
                DigestSuite::Sha256,
                request.created_at,
            )
        };
        assert!(make(None).is_err());
        let outcome = make(Some(binding.clone())).unwrap();
        outcome
            .verify_for_signing(
                &request,
                &scope,
                &auth(),
                Some(&binding),
                None,
                request.created_at,
            )
            .unwrap();
        assert!(
            outcome
                .verify_for_signing(&request, &scope, &auth(), None, None, request.created_at)
                .is_err()
        );
        let other = EventId::from_digest(DigestSuite::Sha256, [8; 32]);
        assert!(
            outcome
                .verify_for_signing(
                    &request,
                    &scope,
                    &auth(),
                    Some(&other),
                    None,
                    request.created_at
                )
                .is_err()
        );
    }
    #[test]
    fn exact_intent_and_expiry_are_checked_before_signing() {
        let request = request();
        let outcome = prepare(&request, 0, vec![]);
        let scope = ScopeRef::Realm {
            realm_id: request.realm_id.clone(),
        };
        outcome
            .verify_for_signing(&request, &scope, &auth(), None, None, request.created_at)
            .unwrap();
        assert!(
            outcome
                .verify_for_signing(&request, &scope, &auth(), None, None, request.expires_at())
                .is_err()
        );
        let mut changed = request.clone();
        changed.intent.reply_to_id =
            Some("ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".into());
        assert!(outcome.validate_for_request(&changed).is_err());
        changed = request.clone();
        changed.created_at += chrono::Duration::milliseconds(1);
        assert!(outcome.validate_for_request(&changed).is_err());
        let mut wrong_key = auth();
        wrong_key.key_epoch += 1;
        assert!(
            outcome
                .verify_for_signing(&request, &scope, &wrong_key, None, None, request.created_at)
                .is_err()
        );
    }
    #[test]
    fn rejoin_frontier_preserves_known_siblings_and_allows_additional_sibling() {
        let request = request();
        let a = EventId::from_digest(DigestSuite::Sha256, [1; 32]);
        let b = EventId::from_digest(DigestSuite::Sha256, [2; 32]);
        let mut ids = vec![a.clone(), b];
        ids.sort();
        let outcome = prepare(&request, 8, ids);
        let known = RealmActorFrontierView::new(
            request.realm_id.clone(),
            ActorId::account(request.account_id.clone()),
            8,
            vec![a],
            DigestSuite::Sha256,
        )
        .unwrap();
        let scope = ScopeRef::Realm {
            realm_id: request.realm_id.clone(),
        };
        outcome
            .verify_for_signing(
                &request,
                &scope,
                &auth(),
                None,
                Some(&known),
                request.created_at,
            )
            .unwrap();
        let reset = prepare(&request, 0, vec![]);
        assert!(
            reset
                .verify_for_signing(
                    &request,
                    &scope,
                    &auth(),
                    None,
                    Some(&known),
                    request.created_at
                )
                .is_err()
        );
    }
    #[test]
    fn changing_unsigned_bytes_or_intent_is_detected_without_signing() {
        let request = request();
        let mut outcome = prepare(&request, 0, vec![]);
        let mut event = outcome.draft.unsigned_event().unwrap().event().clone();
        event.payload.insert(
            "reply_to_id".into(),
            serde_json::json!("ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
        );
        event
            .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        outcome.draft.unsigned_event_bytes =
            Base64UrlString::new(arkret_canonical::base64url_encode(
                arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap(),
            ))
            .unwrap();
        assert!(outcome.validate_for_request(&request).is_err());
        outcome.draft.event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        assert!(outcome.validate_for_request(&request).is_err());
    }
    #[test]
    fn closed_request_cannot_smuggle_an_event_or_plaintext_into_mls() {
        let request = request();
        let mut value = serde_json::to_value(&request).unwrap();
        value["seal_ref"] =
            serde_json::json!("ak:seal:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
        assert!(serde_json::from_value::<MessagePrepareRequestBody>(value).is_err());
        let content = serde_json::json!({"kind":"mls","content":{"kind":"text","body":"secret"}});
        assert!(serde_json::from_value::<MessageAuthoringContent>(content).is_err());
    }

    #[test]
    fn raw_request_digest_preserves_explicit_empty_collections() {
        let request = request();
        let mut outcome = prepare(&request, 0, vec![]);
        let mut value = serde_json::to_value(&request).unwrap();
        value["intent"]["blob_refs"] = serde_json::json!([]);
        let canonical = arkret_canonical::canonical_json_bytes(&value).unwrap();
        assert!(outcome.validate_for_canonical_request(&canonical).is_err());
        outcome.request_digest = Hash::new(arkret_canonical::sha256_digest(&canonical)).unwrap();
        outcome.validate_for_canonical_request(&canonical).unwrap();
        assert!(outcome.validate_for_request(&request).is_err());
    }

    #[test]
    fn encrypted_prepare_preserves_ciphertext_and_frozen_context_on_retry() {
        let mut request = request();
        request.intent.content = MessageAuthoringContent::Mls {
            encrypted_content: EncryptedEnvelope {version:"1.0".into(), content_type:"application/vnd.arkret.message+json".into(),
                encryption_context: arkret_models_crypto::encrypted_envelope::EncryptedEnvelopeEncryptionContext::exporter(4, EventId::from_digest(DigestSuite::Sha256,[7;32]), 31), ciphertext:"YWJj".into()},
            encrypted_metadata: None,
            encryption_context: MessageEncryptionContext {scheme:EncryptedPayloadScheme::MlsExporterAeadV1,
                effective_scope:ScopeRef::Realm {realm_id:request.realm_id.clone()}, sender_domain:"device:sender".into()},
        };
        let outcome = prepare(&request, 0, vec![]);
        let before = arkret_canonical::canonical_json_bytes(&request).unwrap();
        outcome.validate_for_request(&request).unwrap();
        outcome.validate_for_request(&request).unwrap();
        assert_eq!(
            before,
            arkret_canonical::canonical_json_bytes(&request).unwrap()
        );
        if let MessageAuthoringContent::Mls {
            encrypted_content, ..
        } = &mut request.intent.content
        {
            encrypted_content.ciphertext = "ZGVm".into();
        }
        assert!(outcome.validate_for_request(&request).is_err());
    }
}
