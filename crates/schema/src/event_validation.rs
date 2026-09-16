//! Typed validation for payload-agnostic wire events.

use arkret_wire::Event;

use crate::{Result, SchemaError};

/// Validate an Event envelope against the SDK's closed typed wire contract.
pub fn validate_event_wire_schema(event: &Event) -> Result<()> {
    let value = serde_json::to_value(event)
        .map_err(|error| SchemaError::Protocol(format!("event serialization failed: {error}")))?;
    serde_json::from_value::<Event>(value)
        .map(|_| ())
        .map_err(|error| SchemaError::Protocol(format!("event wire contract failed: {error}")))
}

/// Run the complete Event submit gate: structural checks followed by schema validation.
pub fn validate_event_for_submit(event: &Event) -> Result<()> {
    event
        .validate_for_submit_structural()
        .map_err(|error| SchemaError::Protocol(error.to_string()))?;
    validate_event_wire_schema(event)
}

/// Typed wire validation layered on top of the wire [`Event`].
pub trait EventSchemaExt {
    fn validate_wire_schema(&self) -> Result<()>;
    fn validate_for_submit(&self) -> Result<()>;
}

impl EventSchemaExt for Event {
    fn validate_wire_schema(&self) -> Result<()> {
        validate_event_wire_schema(self)
    }

    fn validate_for_submit(&self) -> Result<()> {
        validate_event_for_submit(self)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    fn event() -> Event {
        arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
        )
        .unwrap()
    }

    #[test]
    fn extension_trait_and_free_function_share_the_typed_wire_gate() {
        let event = event();

        validate_event_wire_schema(&event).unwrap();
        event.validate_wire_schema().unwrap();
    }

    #[test]
    fn submit_gate_requires_exactly_one_producer_proof() {
        let error = event().validate_for_submit().unwrap_err().to_string();
        assert!(error.contains("exactly one producer proof"));
    }
}
