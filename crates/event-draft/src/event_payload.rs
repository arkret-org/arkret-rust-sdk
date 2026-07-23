//! Typed read-only projections over the payload-agnostic wire [`Event`].

use arkret_models_collaboration::events_payloads::capability_circle_consent_contact::{
    ContainerMoveItemPayload, ContainerRebalancePayload,
};
use arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload;
use arkret_models_collaboration::events_payloads::list_message_mimi_mls::{
    MessageRedactPayload, MessageRevisePayload,
};
use arkret_models_collaboration::events_payloads::moderation_morph_misc::MorphCreatePayload;
use arkret_models_collaboration::events_payloads::morph_message::{
    MessageCreatePayload, MorphUpdatePayload,
};
use arkret_models_collaboration::events_payloads::object_create::StrandPatchPayload;
use arkret_models_collaboration::events_payloads::preview_realm_reaction::{
    ReactionPayload, RealmDigestSuiteTransitionPayload, RealmNotaryPayload,
};
use arkret_models_collaboration::events_payloads::strand_history_join::StrandCreatePayload;
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_wire::Event;
use arkret_wire::events::kinds::EventKind;

use crate::{EventDraftError, Result};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum MessageEventPayload {
    Create(MessageCreatePayload),
    Revise(MessageRevisePayload),
    Redact(MessageRedactPayload),
    ReactionAdd(ReactionPayload),
    ReactionRemove(ReactionPayload),
}

macro_rules! event_payload_accessors {
    ($($name:ident => ($ty:ty, $kind:path)),+ $(,)?) => {
        /// Strongly typed, read-only payload projections for a wire [`Event`].
        pub trait EventPayloadExt {
            $(fn $name(&self) -> Result<$ty>;)+
            fn as_message_event_payload(&self) -> Result<MessageEventPayload>;
        }

        impl EventPayloadExt for Event {
            $(
                fn $name(&self) -> Result<$ty> {
                    Ok(self.typed_payload::<$ty>($kind)?)
                }
            )+

            fn as_message_event_payload(&self) -> Result<MessageEventPayload> {
                match self.kind.as_str() {
                    EventKind::MESSAGE_CREATE => Ok(MessageEventPayload::Create(self.as_message_create()?)),
                    EventKind::MESSAGE_REVISE => Ok(MessageEventPayload::Revise(self.as_message_revise()?)),
                    EventKind::MESSAGE_REDACT => Ok(MessageEventPayload::Redact(self.as_message_redact()?)),
                    EventKind::REACTION_ADD => Ok(MessageEventPayload::ReactionAdd(self.as_reaction_add()?)),
                    EventKind::REACTION_REMOVE => Ok(MessageEventPayload::ReactionRemove(self.as_reaction_remove()?)),
                    _ => Err(EventDraftError::Protocol(format!(
                        "event is not a message timeline payload: {}",
                        self.kind.as_str()
                    ))),
                }
            }
        }
    };
}

event_payload_accessors! {
    as_message_create => (MessageCreatePayload, EventKind::MESSAGE_CREATE),
    as_message_revise => (MessageRevisePayload, EventKind::MESSAGE_REVISE),
    as_message_redact => (MessageRedactPayload, EventKind::MESSAGE_REDACT),
    as_reaction_add => (ReactionPayload, EventKind::REACTION_ADD),
    as_reaction_remove => (ReactionPayload, EventKind::REACTION_REMOVE),
    as_strand_create => (StrandCreatePayload, EventKind::STRAND_CREATE),
    as_strand_update => (StrandPatchPayload, EventKind::STRAND_UPDATE),
    as_member_state => (MembershipPayload, EventKind::MEMBER_STATE),
    as_device_reanchor => (DeviceReanchorPayload, EventKind::DEVICE_REANCHOR),
    as_morph_create => (MorphCreatePayload, EventKind::MORPH_CREATE),
    as_morph_update => (MorphUpdatePayload, EventKind::MORPH_UPDATE),
    as_container_move_item => (ContainerMoveItemPayload, EventKind::CONTAINER_MOVE_ITEM),
    as_container_rebalance => (ContainerRebalancePayload, EventKind::CONTAINER_REBALANCE),
    as_realm_notary => (RealmNotaryPayload, EventKind::REALM_NOTARY),
    as_realm_digest_suite_transition => (RealmDigestSuiteTransitionPayload, EventKind::REALM_DIGEST_SUITE_TRANSITION),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{Did, EventId, EventRequirements, Hlc, RealmId};
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: EventId::new("ak:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: EventKind::MESSAGE_CREATE.into(),
            realm_id: realm(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: serde_json::from_value(json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }))
            .unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            causal_refs: Vec::new(),
            conflict_keys_digest: None,
            proofs: Vec::new(),
        }
    }

    #[test]
    fn payload_accessor_parses_plain_message_payload() {
        let event = base_event();
        let payload = event.as_message_create().unwrap();

        assert_eq!(
            payload.strand_id.as_str(),
            "ak:strand:01904100-0000-7000-8000-6c663fa0205f"
        );
        assert_eq!(payload.track_name, "discussion");
        assert_eq!(
            payload
                .content
                .as_ref()
                .map(|content| content.body.as_str()),
            Some("hello")
        );
        assert!(payload.encrypted_content.is_none());
    }

    #[test]
    fn message_event_payload_classifies_message_and_reaction_kinds() {
        let mut revise = base_event();
        revise.kind = EventKind::MESSAGE_REVISE.into();
        revise.payload = serde_json::from_value(json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
            "content": {"kind": "ak.content.text", "body": "hello revised"},
            "reason": "typo"
        }))
        .unwrap();
        assert!(matches!(
            revise.as_message_event_payload().unwrap(),
            MessageEventPayload::Revise(_)
        ));

        let mut reaction = base_event();
        reaction.kind = EventKind::REACTION_ADD.into();
        reaction.payload = serde_json::from_value(json!({
            "target_ref": "ak:event:01904100-0000-7000-8000-000000000099",
            "key": "+1"
        }))
        .unwrap();

        match reaction.as_message_event_payload().unwrap() {
            MessageEventPayload::ReactionAdd(payload) => assert_eq!(payload.key, "+1"),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn payload_accessor_parses_encrypted_message_payload() {
        let mut event = base_event();
        event.payload = serde_json::from_value(json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
            "track_name": "discussion",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "AA",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "b3BhcXVl",
                "aad_visibility_event_id": "hidden",
                "aad": {
                    "realm_id": "ak:realm:01904100-0000-7000-8000-6c663fa0205f",
                    "event_kind": "ak.message.create"
                },
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "ak:event:01904100-0000-7000-8000-000000000004"
                },
                "payload_digest": format!("sha256:{}", "a".repeat(64)),
                "aad_digest": format!("sha256:{}", "b".repeat(64))
            }
        }))
        .unwrap();

        let payload = event.payload_as::<MessageCreatePayload>().unwrap();
        assert!(payload.content.is_none());
        assert_eq!(
            payload
                .encrypted_content
                .as_ref()
                .map(|content| content.ciphertext.as_str()),
            Some("b3BhcXVl")
        );
    }

    #[test]
    fn typed_payload_rejects_kind_mismatch() {
        let error = base_event()
            .typed_payload::<MessageCreatePayload>(EventKind::STRAND_CREATE)
            .unwrap_err();

        assert!(error.to_string().contains("kind mismatch"), "{error}");
    }

    #[test]
    fn payload_accessor_rejects_missing_required_field() {
        let mut event = base_event();
        event.payload = serde_json::from_value(json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }))
        .unwrap();

        assert!(event.payload_as::<MessageCreatePayload>().is_err());
    }

    #[test]
    fn payload_accessor_does_not_change_digest_input() {
        let event = base_event();
        let digest = event.event_digest().unwrap();

        let _payload = event.as_message_create().unwrap();

        assert_eq!(event.event_digest().unwrap(), digest);
        assert_eq!(event.payload["content"]["body"], "hello");
    }
}
