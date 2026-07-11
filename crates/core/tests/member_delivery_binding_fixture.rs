//! Executable consumer for the spec fixture
//! `fixtures/membership-delivery-binding-fixture.json`
//! (`ak.member.state{join}.delivery_binding` closure vectors).
//!
//! The SDK-implementable subset exercises the typed
//! [`arkret_core::MemberDeliveryBinding`] model: wire-shape parsing and the
//! `binding_source`-conditional `validate()` rules. Vectors whose
//! expectations are server-reducer semantics stay owned by the soland
//! reducer suite and are consumed here at the metadata level only:
//!
//! * `ak.vector.membership.delivery_binding.handover.v1` — federation frontier-driven route
//!   resolution (`delivery_binding_stale` / `delivery_binding_handed_over` responses, fail-closed
//!   after leave).
//! * The policy-evaluation half of `policy_mismatch.v1` — evaluating
//!   `delivery_binding_policy.allow_binding_sources` / `allowed_recipient_services` against a
//!   landing `ak.member.state` needs the Realm policy reducer; the SDK asserts the binding is
//!   structurally valid (the rejection is policy-level, not schema-level) plus the promised reason
//!   code registration.
//! * `unroutable.v1` delivery-side effects (skipping notifications / sync / push / to-device /
//!   key-packages) — server delivery pipeline conduct.
//!
//! Known wire-shape divergence (reported, not papered over in the model):
//! the payload-schema `event_ref` (`event-payload.schema.json#/$defs/
//! event_ref`) is a bare `ak:event:...` string, while the SDK
//! `MemberDeliveryBinding.service_acceptance_ref` is the envelope-style
//! `EventRef {id, role}` object. `binding_from_fixture` adapts the string
//! form explicitly so the divergence stays visible in exactly one place.

use arkret_core::schema::{embedded_error_code_identifiers, embedded_json_artifact};
use arkret_core::{BindingSource, DeliveryStatus, MemberDeliveryBinding};
use serde_json::{Value, json};

const FIXTURE_PATH: &str = "fixtures/membership-delivery-binding-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded membership delivery binding fixture")
}

fn vector(fixture: &Value, vector_id: &str) -> Value {
    fixture["vectors"]
        .as_array()
        .expect("fixture vectors must be an array")
        .iter()
        .find(|vector| vector["vector_id"].as_str() == Some(vector_id))
        .unwrap_or_else(|| panic!("fixture vector {vector_id} missing"))
        .clone()
}

/// Deserialize a fixture `delivery_binding` object into the typed model,
/// adapting the payload-schema string `service_acceptance_ref` into the
/// SDK's `EventRef {id, role}` object form (see module docs).
fn binding_from_fixture(raw: &Value) -> MemberDeliveryBinding {
    let mut raw = raw.clone();
    if let Some(reference) = raw
        .get("service_acceptance_ref")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        raw["service_acceptance_ref"] = json!({
            "id": reference,
            "role": "service_acceptance",
        });
    }
    serde_json::from_value(raw).expect("fixture delivery_binding must deserialize")
}

fn registered_identifiers() -> std::collections::BTreeSet<String> {
    embedded_error_code_identifiers().expect("embedded error-code registry must load")
}

#[test]
fn fixture_vector_manifest_is_pinned() {
    // Guard: extend this test module when the spec adds or renames vectors.
    let fixture = fixture();
    let ids: Vec<&str> = fixture["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|vector| vector["vector_id"].as_str().expect("vector_id"))
        .collect();
    assert_eq!(
        ids,
        vec![
            "ak.vector.membership.delivery_binding.explicit.v1",
            "ak.vector.membership.delivery_binding.did_document_default.v1",
            "ak.vector.membership.delivery_binding.unroutable.v1",
            "ak.vector.membership.delivery_binding.handover.v1",
            "ak.vector.membership.delivery_binding.policy_mismatch.v1",
        ],
        "membership delivery binding fixture manifest drifted — update the SDK consumers"
    );
}

#[test]
fn explicit_binding_parses_and_validates_to_expected_route() {
    let vector = vector(
        &fixture(),
        "ak.vector.membership.delivery_binding.explicit.v1",
    );
    let payload = &vector["input"]["payload"];
    assert_eq!(payload["delivery_status"].as_str(), Some("routable"));

    let binding = binding_from_fixture(&payload["delivery_binding"]);
    binding
        .validate()
        .expect("explicit binding with service_acceptance_ref must validate");
    assert_eq!(binding.binding_source, BindingSource::Explicit);

    assert_eq!(vector["expected"]["outcome"].as_str(), Some("accepted"));
    let expected_route = vector["expected"]["delivery_route"]
        .as_str()
        .expect("expected delivery_route");
    assert_eq!(
        binding.recipient_service_id.as_str(),
        expected_route,
        "accepted binding must route to recipient_service_id"
    );
}

#[test]
fn did_document_default_binding_requires_digest() {
    let vector = vector(
        &fixture(),
        "ak.vector.membership.delivery_binding.did_document_default.v1",
    );
    let raw_binding = &vector["input"]["payload"]["delivery_binding"];

    // Positive half: digest present -> validates and routes as expected.
    let binding = binding_from_fixture(raw_binding);
    binding
        .validate()
        .expect("did_document_default binding with digest must validate");
    assert_eq!(binding.binding_source, BindingSource::DidDocumentDefault);
    assert_eq!(
        Some(binding.recipient_service_id.as_str()),
        vector["expected"]["delivery_route"].as_str(),
    );
    assert_eq!(
        binding.did_document_digest.as_ref().map(|d| d.as_str()),
        vector["given_state"]["did_document_service"]["canonical_digest"].as_str(),
        "binding digest must pin the DID Document digest materialized at join time"
    );

    // Negative half derived from the vector's own expectation
    // (`missing_did_document_digest_reason_code = schema_violation`):
    // dropping the digest must fail the conditional-required rule.
    let mut stripped = binding.clone();
    stripped.did_document_digest = None;
    stripped
        .validate()
        .expect_err("did_document_default binding without digest must fail closed");
    let reason = vector["expected"]["missing_did_document_digest_reason_code"]
        .as_str()
        .expect("missing_did_document_digest_reason_code");
    assert!(
        registered_identifiers().contains(reason),
        "reason code {reason} not registered"
    );
}

#[test]
fn unroutable_membership_carries_no_binding_and_no_route() {
    let vector = vector(
        &fixture(),
        "ak.vector.membership.delivery_binding.unroutable.v1",
    );
    let payload = &vector["input"]["payload"];

    let status: DeliveryStatus = serde_json::from_value(payload["delivery_status"].clone())
        .expect("delivery_status must deserialize into the typed enum");
    assert_eq!(status, DeliveryStatus::Unroutable);
    assert!(
        payload.get("delivery_binding").is_none(),
        "unroutable membership must not carry a delivery_binding"
    );
    assert!(
        vector["expected"]["delivery_route"].is_null(),
        "unroutable membership resolves to no delivery route"
    );
    let reason = vector["expected"]["policy_disallow_reason_code"]
        .as_str()
        .expect("policy_disallow_reason_code");
    assert!(
        registered_identifiers().contains(reason),
        "reason code {reason} not registered"
    );
}

#[test]
fn policy_mismatch_binding_is_structurally_valid_but_policy_rejected() {
    // The SDK half: the binding itself is schema/shape-valid — the promised
    // rejection is Realm policy evaluation, which is soland-reducer residual.
    let vector = vector(
        &fixture(),
        "ak.vector.membership.delivery_binding.policy_mismatch.v1",
    );
    let binding = binding_from_fixture(&vector["input"]["payload"]["delivery_binding"]);
    binding
        .validate()
        .expect("policy_mismatch binding is structurally valid; rejection is policy-level");
    assert_eq!(binding.binding_source, BindingSource::Explicit);

    assert_eq!(vector["expected"]["outcome"].as_str(), Some("rejected"));
    let reason = vector["expected"]["reason_code"]
        .as_str()
        .expect("reason_code");
    assert!(
        registered_identifiers().contains(reason),
        "reason code {reason} not registered"
    );
    // The mismatch the reducer must reject: the offered recipient service is
    // outside the policy allow-list and the binding source is not allowed.
    let policy = &vector["given_state"]["delivery_binding_policy"];
    let allowed_services: Vec<&str> = policy["allowed_recipient_services"]
        .as_array()
        .expect("allowed_recipient_services")
        .iter()
        .map(|service| service.as_str().expect("service DID"))
        .collect();
    assert!(
        !allowed_services.contains(&binding.recipient_service_id.as_str()),
        "fixture premise: recipient service must be outside the policy allow-list"
    );
}

#[test]
fn handover_vector_reason_codes_are_registered() {
    // The handover vector is federation-runtime reducer semantics (frontier
    // comparisons, stale/handed-over responses, fail-closed after leave) —
    // soland residual. Consume it here by pinning that every reason code it
    // promises is a registered identifier.
    let vector = vector(
        &fixture(),
        "ak.vector.membership.delivery_binding.handover.v1",
    );
    let identifiers = registered_identifiers();
    let mut checked = 0usize;
    for step in vector["sequence"].as_array().expect("handover sequence") {
        if let Some(reason) = step["expected_response"]["reason_code"].as_str() {
            assert!(
                identifiers.contains(reason),
                "handover reason code {reason} not registered"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 2,
        "handover vector must promise the stale + handed-over reason codes"
    );
    assert_eq!(
        vector["expected"]["routing_authority"].as_str(),
        Some("effective_member_cell.delivery_binding"),
        "the effective member cell stays the only routing authority"
    );
}
