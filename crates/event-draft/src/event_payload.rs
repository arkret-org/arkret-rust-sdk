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
