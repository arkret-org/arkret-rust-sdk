use serde::{Deserialize, Serialize};

use crate::{Event, MessageEventPayload, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedMessage {
    pub event: Event,
    pub payload: MessageEventPayload,
}

#[derive(Clone, Debug)]
pub enum DecodedInbound {
    Message(DecodedMessage),
    Event(Event),
}

#[derive(Clone, Debug, Default)]
pub struct InboundDecoder;

impl InboundDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_event(&self, event: Event) -> DecodedInbound {
        match self.try_decode_event(event.clone()) {
            Ok(decoded) => decoded,
            Err(_) => DecodedInbound::Event(event),
        }
    }

    pub fn try_decode_event(&self, event: Event) -> Result<DecodedInbound> {
        match event.kind.as_str() {
            crate::events::EventKind::MESSAGE_CREATE
            | crate::events::EventKind::MESSAGE_REVISE
            | crate::events::EventKind::MESSAGE_REDACT
            | crate::events::EventKind::REACTION_ADD
            | crate::events::EventKind::REACTION_REMOVE => {
                let payload = event.as_message_event_payload()?;
                Ok(DecodedInbound::Message(DecodedMessage { event, payload }))
            }
            _ => Ok(DecodedInbound::Event(event)),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::{Did, Hlc, RealmId};

    fn event(kind: &str, payload: Value) -> Event {
        Event::new(
            kind,
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn decoder_parses_message_create_payload() {
        let inbound = InboundDecoder::new()
            .try_decode_event(event(
                crate::events::EventKind::MESSAGE_CREATE,
                json!({
                    "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                    "track_name": "discussion",
                    "content": {"kind": "ak.content.text", "body": "hello"}
                }),
            ))
            .unwrap();

        match inbound {
            DecodedInbound::Message(message) => match message.payload {
                MessageEventPayload::Create(payload) => {
                    assert_eq!(payload.track_name, "discussion")
                }
                other => panic!("unexpected payload: {other:?}"),
            },
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decoder_rejects_invalid_standard_message_payload() {
        let result = InboundDecoder::new().try_decode_event(event(
            crate::events::EventKind::MESSAGE_CREATE,
            json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
        ));

        assert!(result.is_err());
    }
}
