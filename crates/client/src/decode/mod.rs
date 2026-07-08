use cokret_core::Event;
use cokret_core::events::kinds;

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedMessage {
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedNotification {
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedInbound {
    Message(DecodedMessage),
    Notification(DecodedNotification),
    Event(Event),
}

#[derive(Clone, Debug, Default)]
pub struct InboundDecoder;

impl InboundDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_event(&self, event: Event) -> DecodedInbound {
        match event.kind.as_str() {
            kinds::MESSAGE_CREATE | kinds::MESSAGE_REVISE | kinds::MESSAGE_REDACT => {
                DecodedInbound::Message(DecodedMessage { event })
            }
            "ck.notification.create" | "ck.notification.dismiss" => {
                DecodedInbound::Notification(DecodedNotification { event })
            }
            _ => DecodedInbound::Event(event),
        }
    }
}
