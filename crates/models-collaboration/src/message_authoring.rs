//! Message authoring and authority submission DTOs.

use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::{
    AccountId, EncryptedPayloadScheme, EventCommitSubmission, EventKind, Hash, RealmId, RequestId,
    Result, ScopeRef, StrandId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::message::{ContentBlock, MessageCreatePayload, MessageTrackName};
use crate::objects::strand::MessageMetadata;
use crate::prepared_event_draft::PreparedEventDraft;

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
            track_name: match self.track_name {
                MessageTrackName::Discussion => "discussion".to_owned(),
            },
            content: None,
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            blob_refs: self.blob_refs.clone(),
            reply_to_id: self.reply_to_id.clone(),
            agent_context: None,
            mimi_provenance: None,
            poll_response_heads: Vec::new(),
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
}

/// A producer-authored Message Event submitted to the governance Station.
/// The response is `AuthoritySubmitOutcome`; no actor checkpoint is returned or
/// signed because producer Events no longer form a causal predecessor graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageSubmitRequestBody {
    pub submission: EventCommitSubmission,
}

impl MessageSubmitRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.submission.event.kind != EventKind::MessageCreate {
            return Err(WireError::Protocol(
                "message submission requires ak.message.create".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Optional thin-client request for a governance Station to prepare one
/// unsigned `ak.message.create` Event. Full clients may author locally; this
/// carrier grants no authority and reserves no stream position.
// Field declaration order is byte-for-byte the properties order of
// message-authoring.schema.json#/$defs/message_prepare_request_body.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessagePrepareRequestBody {
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub intent: MessageAuthoringIntent,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl MessagePrepareRequestBody {
    /// `x-arkret-max-canonical-bytes` on the schema node.
    pub const MAX_CANONICAL_BYTES: usize = 1_048_576;

    pub fn validate(&self) -> Result<()> {
        let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(self)?;
        if canonical_bytes.len() > Self::MAX_CANONICAL_BYTES {
            return Err(WireError::Protocol(
                "message prepare request exceeds its canonical byte ceiling".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical-hash idempotency key bound by the prepare outcome.
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(arkret_canonical::canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

/// Counterpart for
/// `message-authoring.schema.json#/$defs/message_prepare_outcome`.
///
/// The prepare phase hands back one service-prepared unsigned Event plus the
/// exact request digest it answers; the producer signs that draft and submits
/// it through [`MessageSubmitRequestBody`]. The outcome carries no
/// reservation, predecessor or ordering member: a producer Event has no causal
/// predecessor, and finality is the authority-signed RealmCommit.
// Field declaration order is byte-for-byte the properties order of
// message-authoring.schema.json#/$defs/message_prepare_outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MessagePrepareOutcome {
    pub request_digest: Hash,
    pub draft: PreparedEventDraft,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl MessagePrepareOutcome {
    /// `x-arkret-max-canonical-bytes` on the schema node.
    pub const MAX_CANONICAL_BYTES: usize = 2_097_152;

    /// The draft is the only thing the producer signs, so it must really be an
    /// `ak.message.create` draft whose digest matches its own bytes, and the
    /// validity window must still be open.
    pub fn validate(&self) -> Result<()> {
        self.draft
            .unsigned_event_for_kind(arkret_wire::event_kind_str::MESSAGE_CREATE)?;
        if self.expires_at <= self.observed_at {
            return Err(WireError::Protocol(
                "message prepare outcome expires_at must be after observed_at".to_owned(),
            ));
        }
        let canonical_bytes = arkret_canonical::canonical::canonical_json_bytes(self)?;
        if canonical_bytes.len() > Self::MAX_CANONICAL_BYTES {
            return Err(WireError::Protocol(
                "message prepare outcome exceeds its canonical byte ceiling".to_owned(),
            ));
        }
        Ok(())
    }

    /// The prepared draft's own Event id, so a caller never re-derives one
    /// from the unsigned bytes by hand.
    pub fn draft_event_id(&self) -> Result<arkret_wire::EventId> {
        self.draft.event_id()
    }

    /// Verify that a Station-prepared draft answers the exact frozen request.
    ///
    /// This comparison is deliberately client-side: prepare is not an
    /// authority decision, and a client must never sign a Station-rewritten
    /// message body or encryption scope.
    pub fn validate_against_request(&self, request: &MessagePrepareRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_digest != request.canonical_request_digest()? {
            return Err(WireError::Protocol(
                "message prepare outcome does not bind the exact request".to_owned(),
            ));
        }
        let expected_expires_at = request
            .created_at
            .checked_add_signed(chrono::Duration::seconds(300))
            .ok_or_else(|| {
                WireError::Protocol("message prepare request timestamp overflows expiry".to_owned())
            })?;
        if self.expires_at != expected_expires_at {
            return Err(WireError::Protocol(
                "message prepare outcome expiry must equal created_at plus 300 seconds".to_owned(),
            ));
        }

        let authored = self
            .draft
            .unsigned_event_for_kind(arkret_wire::event_kind_str::MESSAGE_CREATE)?;
        let event = authored.event();
        if event.actor_id.as_account_id() != Some(&request.account_id)
            || event.realm_id != request.realm_id
            || event.created_at != request.created_at
        {
            return Err(WireError::Protocol(
                "message prepare draft rewrites the frozen author, Realm, or timestamp".to_owned(),
            ));
        }
        if let MessageAuthoringContent::Mls {
            encryption_context, ..
        } = &request.intent.content
            && event.scope_ref != encryption_context.effective_scope
        {
            return Err(WireError::Protocol(
                "message prepare draft rewrites the frozen encryption scope".to_owned(),
            ));
        }
        if serde_json::to_value(&event.payload)? != serde_json::to_value(request.intent.payload())?
        {
            return Err(WireError::Protocol(
                "message prepare draft rewrites the frozen message payload".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod message_prepare_tests {
    use arkret_wire::{
        AccountId, ActorId, Base64UrlString, DidCoreId, Hash, RealmId, test_support,
    };
    use chrono::TimeZone;
    use serde_json::{Value, json};

    use super::*;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn author() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkauthor").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        ))
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5")
                .unwrap(),
        }
    }

    /// Build a real prepared draft, so the outcome is exercised against the
    /// same digest round trip a service-produced draft goes through rather
    /// than against opaque stub bytes.
    fn draft_for(kind: &str) -> PreparedEventDraft {
        let event = test_support::raw_event_for_actor_at(
            kind,
            scope(),
            author(),
            json!({ "body": "hello" }),
            Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        let bytes =
            arkret_canonical::canonical::canonical_json_bytes(&event.digest_payload().unwrap())
                .unwrap();
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        PreparedEventDraft {
            unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(&bytes))
                .unwrap(),
            event_digest,
        }
    }

    fn outcome_value(draft: &PreparedEventDraft) -> Value {
        json!({
            "request_digest": DIGEST,
            "draft": {
                "unsigned_event_bytes": draft.unsigned_event_bytes.as_str(),
                "event_digest": draft.event_digest.as_str()
            },
            "observed_at": "2026-09-16T00:00:00.000Z",
            "expires_at": "2026-09-16T00:05:00.000Z"
        })
    }

    fn request_value() -> Value {
        json!({
            "request_id": "ak:request:019b6a40-0000-7000-8000-000000000001",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkauthor",
                "station_id": "ak:did_core:webvh:z6mkstation"
            },
            "realm_id": "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            "intent": {
                "strand_id": "ak:strand:AUOjN8M8xm-W1G1Ve9UR6sHKJh7JPG7bM8ZDnzcGJ2Vh",
                "track_name": "discussion",
                "content": {
                    "kind": "plaintext",
                    "content": {
                        "kind": "ak.content.text",
                        "body": "hello",
                        "format": "plain"
                    }
                }
            },
            "created_at": "2026-09-16T00:00:00.000Z"
        })
    }

    fn draft_for_request(request: &MessagePrepareRequestBody) -> PreparedEventDraft {
        let payload = serde_json::to_value(request.intent.payload()).unwrap();
        let event = test_support::raw_event_for_actor_at(
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            ScopeRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            ActorId::account(request.account_id.clone()),
            payload,
            request.created_at,
        )
        .unwrap();
        let bytes =
            arkret_canonical::canonical::canonical_json_bytes(&event.digest_payload().unwrap())
                .unwrap();
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        PreparedEventDraft {
            unsigned_event_bytes: Base64UrlString::new(arkret_canonical::base64url_encode(&bytes))
                .unwrap(),
            event_digest,
        }
    }

    fn outcome_for_request(request: &MessagePrepareRequestBody) -> MessagePrepareOutcome {
        MessagePrepareOutcome {
            request_digest: request.canonical_request_digest().unwrap(),
            draft: draft_for_request(request),
            observed_at: request.created_at,
            expires_at: request.created_at + chrono::Duration::seconds(300),
        }
    }

    #[test]
    fn request_round_trips_in_schema_property_order() {
        let value = request_value();
        let request: MessagePrepareRequestBody = serde_json::from_value(value.clone()).unwrap();
        request.validate().unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), value);
        assert!(request.canonical_request_digest().is_ok());
    }

    #[test]
    fn every_request_member_is_required_and_no_other_is_accepted() {
        for member in [
            "request_id",
            "account_id",
            "realm_id",
            "intent",
            "created_at",
        ] {
            let mut missing = request_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<MessagePrepareRequestBody>(missing).is_err(),
                "{member} must be required"
            );
        }
        let mut extended = request_value();
        extended
            .as_object_mut()
            .unwrap()
            .insert("reservation_handle".to_owned(), json!("x"));
        assert!(serde_json::from_value::<MessagePrepareRequestBody>(extended).is_err());
    }

    #[test]
    fn outcome_must_bind_the_exact_frozen_request_and_draft() {
        let request: MessagePrepareRequestBody = serde_json::from_value(request_value()).unwrap();
        outcome_for_request(&request)
            .validate_against_request(&request)
            .unwrap();

        let mut changed_value = request_value();
        changed_value["intent"]["content"]["content"]["body"] = json!("rewritten");
        let changed: MessagePrepareRequestBody = serde_json::from_value(changed_value).unwrap();

        let digest_mismatch = outcome_for_request(&request);
        assert!(digest_mismatch.validate_against_request(&changed).is_err());

        let mut rewritten_draft = outcome_for_request(&request);
        rewritten_draft.draft = draft_for_request(&changed);
        assert!(rewritten_draft.validate_against_request(&request).is_err());

        let mut wrong_expiry = outcome_for_request(&request);
        wrong_expiry.expires_at += chrono::Duration::seconds(1);
        assert!(wrong_expiry.validate_against_request(&request).is_err());
    }

    #[test]
    fn outcome_round_trips_in_schema_property_order() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        let value = outcome_value(&draft);
        let outcome: MessagePrepareOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(outcome.request_digest.as_str(), DIGEST);
        outcome.validate().unwrap();
        assert_eq!(serde_json::to_value(&outcome).unwrap(), value);
    }

    #[test]
    fn every_member_is_required_and_no_other_is_accepted() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        for member in ["request_digest", "draft", "observed_at", "expires_at"] {
            let mut missing = outcome_value(&draft);
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<MessagePrepareOutcome>(missing).is_err(),
                "{member} must be required"
            );
        }
        for absent in ["reservation_handle", "prev_refs", "actor_seq"] {
            let mut extended = outcome_value(&draft);
            extended
                .as_object_mut()
                .unwrap()
                .insert(absent.to_owned(), json!("x"));
            assert!(
                serde_json::from_value::<MessagePrepareOutcome>(extended).is_err(),
                "{absent} must not be accepted"
            );
        }
    }

    #[test]
    fn the_draft_must_be_a_message_create_draft() {
        let draft = draft_for(arkret_wire::event_kind_str::REACTION_ADD);
        let outcome: MessagePrepareOutcome = serde_json::from_value(outcome_value(&draft)).unwrap();
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn a_draft_whose_digest_does_not_match_its_bytes_is_refused() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        let mut tampered = outcome_value(&draft);
        tampered["draft"]
            .as_object_mut()
            .unwrap()
            .insert("event_digest".to_owned(), json!(DIGEST));
        let outcome: MessagePrepareOutcome = serde_json::from_value(tampered).unwrap();
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn an_already_closed_validity_window_is_refused() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        let mut closed = outcome_value(&draft);
        closed
            .as_object_mut()
            .unwrap()
            .insert("expires_at".to_owned(), json!("2026-09-16T00:00:00.000Z"));
        let outcome: MessagePrepareOutcome = serde_json::from_value(closed).unwrap();
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn timestamps_must_be_canonical() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        let mut loose = outcome_value(&draft);
        loose
            .as_object_mut()
            .unwrap()
            .insert("observed_at".to_owned(), json!("2026-09-16T00:00:00Z"));
        assert!(serde_json::from_value::<MessagePrepareOutcome>(loose).is_err());
    }

    #[test]
    fn the_prepared_draft_exposes_its_own_event_id() {
        let draft = draft_for(arkret_wire::event_kind_str::MESSAGE_CREATE);
        let outcome: MessagePrepareOutcome = serde_json::from_value(outcome_value(&draft)).unwrap();
        assert_eq!(outcome.draft_event_id().unwrap(), draft.event_id().unwrap());
    }
}
