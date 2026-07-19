//! Kind-specific payload accessors and schema validation for the Event
//! Envelope.
//!
//! [`Event`] itself is a payload-agnostic, kind-routed container owned by
//! `arkret-wire`. This module layers the strongly-typed, lazily-parsed
//! payload projections (which depend on the payload model types) and the
//! schema-registry-backed submit gate (which depends on `arkret-schema`)
//! on top of it via [`EventPayloadExt`]. Accessors are pure read
//! projections: they never change the canonical payload bytes or the
//! event digest input.

use super::*;
use crate::events::kinds::EventKind;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageEventPayload {
    Create(MessageCreatePayload),
    Revise(MessageRevisePayload),
    Redact(MessageRedactPayload),
    ReactionAdd(ReactionPayload),
    ReactionRemove(ReactionPayload),
}

macro_rules! event_payload_accessors {
    ($(
        $(#[$meta:meta])*
        $name:ident => ($ty:ty, $kind:path)
    ),+ $(,)?) => {
        /// Strongly-typed payload projections and the full submit gate for
        /// the payload-agnostic [`Event`] envelope.
        pub trait EventPayloadExt {
            $(
                $(#[$meta])*
                fn $name(&self) -> Result<$ty>;
            )+

            /// Classify and parse the message-timeline payload subset.
            fn as_message_event_payload(&self) -> Result<MessageEventPayload>;

            /// Validate the serialized envelope against the registered
            /// `event-envelope` schema artifact.
            fn validate_wire_schema(&self) -> Result<()>;

            /// Full submit gate: the wire-structural checks
            /// ([`Event::validate_for_submit_structural`]) plus
            /// schema-registry validation. Use this — not the structural
            /// variant alone — as the submit gate.
            fn validate_for_submit(&self) -> Result<()>;
        }

        impl EventPayloadExt for Event {
            $(
                fn $name(&self) -> Result<$ty> {
                    Ok(self.typed_payload::<$ty>($kind)?)
                }
            )+

            fn as_message_event_payload(&self) -> Result<MessageEventPayload> {
                match self.kind.as_str() {
                    EventKind::MESSAGE_CREATE => {
                        Ok(MessageEventPayload::Create(self.as_message_create()?))
                    }
                    EventKind::MESSAGE_REVISE => {
                        Ok(MessageEventPayload::Revise(self.as_message_revise()?))
                    }
                    EventKind::MESSAGE_REDACT => {
                        Ok(MessageEventPayload::Redact(self.as_message_redact()?))
                    }
                    EventKind::REACTION_ADD => {
                        Ok(MessageEventPayload::ReactionAdd(self.as_reaction_add()?))
                    }
                    EventKind::REACTION_REMOVE => Ok(MessageEventPayload::ReactionRemove(
                        self.as_reaction_remove()?,
                    )),
                    _ => Err(Error::Protocol(format!(
                        "event is not a message timeline payload: {}",
                        self.kind.as_str()
                    ))),
                }
            }

            fn validate_wire_schema(&self) -> Result<()> {
                let value = serde_json::to_value(self)?;
                let registry = crate::schema::schema_registry_from_default_spec_artifacts()?
                    .unwrap_or_else(crate::schema::ProtocolSchemaRegistry::default);
                Ok(registry.validate_value(EVENT_SCHEMA, &value)?)
            }

            fn validate_for_submit(&self) -> Result<()> {
                self.validate_for_submit_structural()?;
                self.validate_wire_schema()
            }
        }
    };
}

event_payload_accessors! {
    /// Parse a `ak.message.create` payload.
    as_message_create => (MessageCreatePayload, EventKind::MESSAGE_CREATE),
    /// Parse a `ak.message.revise` payload.
    as_message_revise => (MessageRevisePayload, EventKind::MESSAGE_REVISE),
    /// Parse a `ak.message.redact` payload.
    as_message_redact => (MessageRedactPayload, EventKind::MESSAGE_REDACT),
    /// Parse a `ak.reaction.add` payload.
    as_reaction_add => (ReactionPayload, EventKind::REACTION_ADD),
    /// Parse a `ak.reaction.remove` payload.
    as_reaction_remove => (ReactionPayload, EventKind::REACTION_REMOVE),
    /// Parse a `ak.strand.create` payload.
    as_strand_create => (StrandCreatePayload, EventKind::STRAND_CREATE),
    /// Parse a `ak.strand.update` payload.
    as_strand_update => (StrandPatchPayload, EventKind::STRAND_UPDATE),
    /// Parse a `ak.member.state` payload.
    as_member_state => (MembershipPayload, EventKind::MEMBER_STATE),
    /// Parse a `ak.device.reanchor` payload.
    as_device_reanchor => (DeviceReanchorPayload, EventKind::DEVICE_REANCHOR),
    /// Parse a `ak.morph.create` payload.
    as_morph_create => (MorphCreatePayload, EventKind::MORPH_CREATE),
    /// Parse a `ak.morph.update` payload.
    as_morph_update => (MorphUpdatePayload, EventKind::MORPH_UPDATE),
    /// Parse a `ak.container.move_item` payload.
    as_container_move_item => (ContainerMoveItemPayload, EventKind::CONTAINER_MOVE_ITEM),
    /// Parse a `ak.container.rebalance` payload.
    as_container_rebalance => (ContainerRebalancePayload, EventKind::CONTAINER_REBALANCE),
    /// Parse a `ak.realm.notary` payload.
    as_realm_notary => (RealmNotaryPayload, EventKind::REALM_NOTARY),
    /// Parse a `ak.realm.digest_suite_transition` payload.
    as_realm_digest_suite_transition => (RealmDigestSuiteTransitionPayload, EventKind::REALM_DIGEST_SUITE_TRANSITION),
}

#[cfg(test)]
mod event_payload_accessor_tests {
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
            kind: "ak.message.create".into(),
            realm_id: realm(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
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
            "content": {
                "kind": "ak.content.text",
                "body": "hello revised"
            },
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

        let payload = reaction.as_message_event_payload().unwrap();
        match payload {
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
        let event = base_event();
        let error = event
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
