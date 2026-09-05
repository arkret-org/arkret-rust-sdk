//! Raw Event fixtures for conformance and deliberately invalid test inputs.
//!
//! Production authoring must use `arkret_event_draft::TypedEventDraft` or the
//! validated extension boundary. Keeping these helpers out of `impl Event`
//! makes the standard raw constructor unavailable as an ordinary API.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::{AccountId, ActorId, DidCoreId, Event, EventId, Hash, Hlc, Result, ScopeRef};

/// The detached compact JWS a fixture carries when its case is the envelope
/// shape and not that anything verified.
///
/// `event-envelope.schema.json` pins `proof.jws` to
/// `^[A-Za-z0-9_-]+\.(?:[A-Za-z0-9_-]+)?\.[A-Za-z0-9_-]+$`, so a placeholder
/// still owes the base64url protected header, the empty detached payload
/// segment, and the signature segment. Single-token placeholders such as
/// `"sig"` are wire-invalid and are rejected by `ProducerEventProof::validate`.
///
/// The signature segment is `payload_digest` itself, so the value is a function
/// of the bytes it claims to cover: a fixture cannot pin a constant that
/// survives an edit to those bytes, and no Ed25519 verifier can accept it.
/// A fixture whose case *is* that a signature verified must sign with a real
/// key. `arkret_test_kit::proof::StructuralOnlyPayloadSigner` emits this same
/// value through the `PayloadSigner` boundary and reports it as
/// `ProofFidelity::StructuralOnly`.
#[doc(hidden)]
#[must_use]
pub fn structural_only_detached_jws(payload_digest: &Hash) -> String {
    let digest_hex = payload_digest
        .as_str()
        .rsplit(':')
        .next()
        .unwrap_or_default();
    format!("eyJhbGciOiJFZDI1NTE5In0..{digest_hex}")
}

/// Envelope metadata embedded in raw projection fixture payloads.
///
/// Serde owns the split so fixture callers do not hand-edit an Event digest
/// preimage or maintain another list of excluded Event members.
#[derive(Deserialize)]
struct RawProjectionFixtureEnvelope {
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(flatten)]
    payload: serde_json::Map<String, Value>,
}

#[doc(hidden)]
pub struct RawProjectionFixtureParts {
    pub actor_id: Option<DidCoreId>,
    pub event_id: Option<EventId>,
    pub payload: Value,
}

/// Decode the test-only projection fixture overlay into explicit envelope
/// metadata and a clean Event payload object.
#[doc(hidden)]
pub fn split_raw_projection_fixture_payload(payload: Value) -> Result<RawProjectionFixtureParts> {
    let fixture: RawProjectionFixtureEnvelope =
        serde_json::from_value(payload).map_err(|error| {
            crate::WireError::Protocol(format!("invalid raw projection fixture: {error}"))
        })?;
    let actor_id = fixture.sender.map(DidCoreId::new).transpose()?;
    let event_id = fixture.event_id.map(EventId::new).transpose()?;
    Ok(RawProjectionFixtureParts {
        actor_id,
        event_id,
        payload: Value::Object(fixture.payload),
    })
}

#[doc(hidden)]
pub fn raw_event(
    kind: impl Into<String>,
    scope_ref: ScopeRef,
    actor_id: DidCoreId,
    station_id: DidCoreId,
    actor_seq: u64,
    hlc: Hlc,
    payload: Value,
) -> Result<Event> {
    Event::new(
        kind,
        scope_ref,
        ActorId::account(AccountId::new(actor_id, station_id)),
        actor_seq,
        hlc,
        payload,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn raw_event_at(
    kind: impl Into<String>,
    scope_ref: ScopeRef,
    actor_id: DidCoreId,
    station_id: DidCoreId,
    actor_seq: u64,
    hlc: Hlc,
    payload: Value,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    Event::new_at(
        kind,
        scope_ref,
        ActorId::account(AccountId::new(actor_id, station_id)),
        actor_seq,
        hlc,
        payload,
        created_at,
    )
}

/// Build a deterministic raw fixture Event from its complete ActorId.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn raw_event_for_actor_at(
    kind: impl Into<String>,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    actor_seq: u64,
    hlc: Hlc,
    payload: Value,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    Event::new_at(
        kind, scope_ref, actor_id, actor_seq, hlc, payload, created_at,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::split_raw_projection_fixture_payload;

    #[test]
    fn raw_projection_sender_rejects_a_did_instead_of_falling_back() {
        let error = split_raw_projection_fixture_payload(json!({
            "sender": "did:web:alice.example",
            "membership": "join"
        }))
        .err()
        .expect("a DID is not a stable Event actor id");

        assert!(
            error.to_string().contains("did:web:alice.example"),
            "{error}"
        );
    }

    #[test]
    fn raw_projection_sender_accepts_a_core_id_and_removes_the_overlay() {
        let parts = split_raw_projection_fixture_payload(json!({
            "sender": "ak:did_core:web:alice.example",
            "membership": "join"
        }))
        .expect("a stable core actor id is valid");

        assert_eq!(
            parts.actor_id.as_ref().map(|actor| actor.as_str()),
            Some("ak:did_core:web:alice.example")
        );
        assert_eq!(parts.payload, json!({"membership": "join"}));
    }

    #[test]
    fn raw_projection_event_id_rejects_an_invalid_overlay() {
        let error = split_raw_projection_fixture_payload(json!({
            "event_id": "event-not-typed",
            "membership": "join"
        }))
        .err()
        .expect("an invalid Event id must not fall back to a derived fixture id");

        assert!(error.to_string().contains("event-not-typed"), "{error}");
    }
}
