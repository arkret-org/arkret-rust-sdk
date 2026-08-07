//! Registry-backed validation for payload-agnostic wire events.

use arkret_wire::{Event, SchemaId};

use crate::{
    ProtocolSchemaRegistry, Result, SchemaError, schema_registry_from_default_spec_artifacts,
};

/// Validate an Event envelope against the registered `event-envelope` schema.
pub fn validate_event_wire_schema(event: &Event) -> Result<()> {
    let value = serde_json::to_value(event)
        .map_err(|error| SchemaError::Protocol(format!("event serialization failed: {error}")))?;
    let registry = schema_registry_from_default_spec_artifacts()?
        .unwrap_or_else(ProtocolSchemaRegistry::default);
    registry.validate_value(SchemaId::EVENT_V1, &value)
}

/// Run the complete Event submit gate: structural checks followed by schema validation.
pub fn validate_event_for_submit(event: &Event) -> Result<()> {
    event
        .validate_for_submit_structural()
        .map_err(|error| SchemaError::Protocol(error.to_string()))?;
    validate_event_wire_schema(event)
}

/// Registry-backed schema validation layered on top of the wire [`Event`].
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
    use arkret_wire::{Did, EnvelopeActorKind, Hlc, RealmId, ReasonCode, ScopeRef};
    use serde_json::json;

    use super::*;

    fn event() -> Event {
        Event::new(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
        )
        .unwrap()
    }

    #[test]
    fn extension_trait_and_free_function_share_the_schema_gate() {
        let event = event();

        let direct = validate_event_wire_schema(&event).unwrap_err().to_string();
        let extension = event.validate_wire_schema().unwrap_err().to_string();

        assert_eq!(extension, direct);
    }

    #[test]
    fn submit_gate_runs_structural_validation_before_schema_validation() {
        // `actor_kind` is the reducer-stamped envelope field. A producer that
        // supplies one is rejected structurally, before the payload ever
        // reaches the registered schema.
        let mut event = event();
        event.actor_kind = Some(EnvelopeActorKind::Native);

        let error = event.validate_for_submit().unwrap_err().to_string();

        assert!(error.contains(ReasonCode::ACTOR_KIND_REDUCER_MANAGED));
    }
}
