//! Public Reaction coordinates bind independently of AEAD and native admission.

use arkret_canonical::{DigestSuite, base64url_encode};
use arkret_models_collaboration::events_payloads::ReactionPayload;
use arkret_models_crypto::encrypted_envelope::{
    EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EncryptedEnvelopeRoutingContext,
};
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::{EventId, MessageId};

fn payload() -> ReactionPayload {
    // The formal KAT supplies valid envelope metadata. This test does not
    // claim that a modified KAT ciphertext is a native accepted Reaction.
    let fixture = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let mut envelope: EncryptedEnvelope =
        serde_json::from_value(fixture["kat"]["envelope"].clone()).unwrap();
    let event = EventId::from_digest(DigestSuite::Sha256, [7; 32]);
    let key = base64url_encode([7; 32]);
    let EncryptedEnvelopeEncryptionContext::EpochContent {
        routing_context, ..
    } = &mut envelope.encryption_context;
    *routing_context = Some(EncryptedEnvelopeRoutingContext {
        target_ref: event.clone(),
        routing_tag: key.clone(),
    });
    ReactionPayload {
        target_ref: MessageId::from_event_id(&event).to_string(),
        key,
        annotation: None,
        encrypted_payload: Some(envelope),
    }
}

fn rejects_typed_and_wire(payload: ReactionPayload) {
    assert!(payload.validate().is_err());
    let wire = serde_json::to_value(payload).unwrap();
    assert!(serde_json::from_value::<ReactionPayload>(wire).is_err());
}

#[test]
fn encrypted_reaction_binds_the_key_and_retypes_its_message_create_event() {
    let payload = payload();
    payload.validate().unwrap();
    let envelope = payload.encrypted_payload.as_ref().unwrap();
    let routing = envelope.encryption_context.routing_context().unwrap();
    assert_ne!(payload.target_ref.as_str(), routing.target_ref.as_str());
    assert_eq!(
        MessageId::new(payload.target_ref.as_str())
            .unwrap()
            .event_id(),
        routing.target_ref
    );
    let wire = serde_json::to_value(&payload).unwrap();
    let decoded: ReactionPayload = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
}

#[test]
fn encrypted_reaction_rejects_a_different_individually_valid_outer_key() {
    let mut payload = payload();
    payload.key = base64url_encode([8; 32]);
    rejects_typed_and_wire(payload);
}

#[test]
fn encrypted_reaction_rejects_a_different_individually_valid_message_target() {
    let mut payload = payload();
    let event = EventId::from_digest(DigestSuite::Sha256, [8; 32]);
    payload.target_ref = MessageId::from_event_id(&event).to_string();
    rejects_typed_and_wire(payload);
}

#[test]
fn encrypted_reaction_requires_the_route_and_valid_envelope_metadata() {
    let mut missing_route = payload();
    let EncryptedEnvelopeEncryptionContext::EpochContent {
        routing_context, ..
    } = &mut missing_route
        .encrypted_payload
        .as_mut()
        .unwrap()
        .encryption_context;
    *routing_context = None;
    rejects_typed_and_wire(missing_route);

    let mut malformed = payload();
    malformed
        .encrypted_payload
        .as_mut()
        .unwrap()
        .ciphertext
        .clear();
    rejects_typed_and_wire(malformed);
}

#[test]
fn plaintext_reaction_does_not_require_encrypted_routing_metadata() {
    let mut payload = payload();
    payload.encrypted_payload = None;
    payload.key = "like".to_owned();
    payload.annotation = Some("plain annotation".to_owned());
    payload.validate().unwrap();
    let wire = serde_json::to_value(payload).unwrap();
    serde_json::from_value::<ReactionPayload>(wire).unwrap();
}

#[test]
fn reaction_annotation_rejects_explicit_null_instead_of_normalizing_to_absence() {
    let mut wire = serde_json::to_value(payload()).unwrap();
    wire["annotation"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ReactionPayload>(wire).is_err());
}

#[test]
fn reaction_encrypted_payload_rejects_explicit_null_instead_of_becoming_plaintext() {
    let mut wire = serde_json::to_value(payload()).unwrap();
    wire["encrypted_payload"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ReactionPayload>(wire).is_err());
}
