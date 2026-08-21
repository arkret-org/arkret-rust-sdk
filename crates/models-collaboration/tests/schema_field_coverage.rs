//! Machine gate: a hand-written request/response DTO's field set MUST equal the
//! property set its spec `$defs` entry declares.
//!
//! Why this exists: `EventsQueryPostRequestBody` once shipped without
//! `include_completeness` while both the schema and the GET query binding
//! declared it, so the typed POST body could not express a request the GET
//! client could. The schema release gate stayed green throughout, because
//! nothing compared the two field sets — the spec's claim that the GET and POST
//! forms are `binding_variant_of` each other lived only in prose.
//!
//! The comparison is exact in both directions:
//!
//! - a schema property the DTO cannot carry is a missing capability;
//! - a DTO field the schema does not declare is a field no peer will accept.
//!
//! Adding a DTO to the gate means one `assert_dto_matches_schema` call with a
//! fully-populated instance. The instance MUST set every optional field, since
//! `skip_serializing_if` hides `None` from the serialized form; deserializing
//! the fixture (rather than constructing it field by field) also proves the DTO
//! accepts every declared property on the wire.

use std::collections::BTreeSet;

use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
use arkret_models_collaboration::http_bodies::{
    EventView, RedactedEventView, ReferenceLockedEventStub,
};
use arkret_wire::EventKind;
use serde::Serialize;
use serde_json::{Value, json};

/// Spec artifact holding the service operation request/response DTOs.
const SERVICE_OPERATION_DTOS: &str = "schemas/service-operation-dtos.schema.json";

/// Field names declared by `<artifact>#/$defs/<definition>/properties`.
fn schema_property_names(artifact: &str, definition: &str) -> BTreeSet<String> {
    let schema = arkret_schema::embedded_json_artifact(artifact)
        .unwrap_or_else(|error| panic!("embedded artifact {artifact} failed to load: {error}"));
    let properties = schema
        .get("$defs")
        .and_then(|defs| defs.get(definition))
        .and_then(|definition| definition.get("properties"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| panic!("{artifact}#/$defs/{definition}/properties is missing"));
    properties.keys().cloned().collect()
}

/// Field names a fully-populated instance actually serializes.
fn serialized_field_names<T: Serialize>(fully_populated: &T) -> BTreeSet<String> {
    serde_json::to_value(fully_populated)
        .expect("DTO serializes")
        .as_object()
        .expect("DTO serializes to a JSON object")
        .keys()
        .cloned()
        .collect()
}

/// Assert the DTO carries exactly the fields its schema definition declares.
fn assert_dto_matches_schema<T: Serialize>(artifact: &str, definition: &str, fully_populated: &T) {
    let declared = schema_property_names(artifact, definition);
    let carried = serialized_field_names(fully_populated);

    let missing: Vec<&String> = declared.difference(&carried).collect();
    assert!(
        missing.is_empty(),
        "{definition} cannot carry schema-declared field(s) {missing:?}; \
         either the DTO is behind the schema or the fixture forgot to populate them"
    );
    let undeclared: Vec<&String> = carried.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "{definition} serializes field(s) {undeclared:?} that {artifact} does not declare; \
         no conforming peer will accept them"
    );
}

/// `$defs/Cursor` is `^ak:cursor:[A-Za-z0-9_-]+$` — an opaque token the client
/// carries verbatim. Any syntactically valid value serves here.
fn sample_cursor() -> Value {
    json!("ak:cursor:c2FtcGxlLWhhbmRsZQ")
}

#[test]
fn events_query_post_request_body_matches_its_schema_definition() {
    let fully_populated: EventsQueryPostRequestBody = serde_json::from_value(json!({
        "realms": ["ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"],
        "actors": ["ak:did_core:web:alice.example"],
        "before": sample_cursor(),
        "after": sample_cursor(),
        "order": "descending",
        "limit": 50,
        "filters": { "kind": "ak.message.create" },
        "include_completeness": true
    }))
    .expect("every schema-declared field is accepted by the typed POST body");

    assert_dto_matches_schema(
        SERVICE_OPERATION_DTOS,
        "EventsQueryPostRequestBody",
        &fully_populated,
    );
}

#[test]
fn event_read_projection_rows_match_their_schema_definitions() {
    let redacted: RedactedEventView = serde_json::from_value(json!({
        "view_kind": "redacted_event_view",
        "event_id": "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq",
        "kind": EventKind::MessageCreate.as_str(),
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "created_at": "2026-08-09T00:00:00.000Z",
        "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "payload_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "redaction_reason": "policy_hidden",
        "hidden_fields": ["payload.body"],
        "inclusion_proof": {"root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        "reducer_input": false
    }))
    .expect("every RedactedEventView field is accepted");
    assert_dto_matches_schema(SERVICE_OPERATION_DTOS, "RedactedEventView", &redacted);

    let locked: ReferenceLockedEventStub = serde_json::from_value(json!({
        "view_kind": "reference_locked_event_stub",
        "status": "locked",
        "event_id": "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq",
        "kind": EventKind::MessageCreate.as_str(),
        "realm_id": "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs",
        "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reason_code": "reference_locked",
        "inclusion_proof": {"root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        "reducer_input": false
    }))
    .expect("every ReferenceLockedEventStub field is accepted");
    assert_dto_matches_schema(SERVICE_OPERATION_DTOS, "ReferenceLockedEventStub", &locked);

    let event_view: EventView = serde_json::from_value(json!({
        "event": locked,
        "visibility": {"history_access": "since_join"},
        "receipts": [{"receipt": "visible"}]
    }))
    .expect("every EventView field is accepted");
    assert_dto_matches_schema(SERVICE_OPERATION_DTOS, "EventView", &event_view);
}

/// Guard the guard: a DTO behind its schema must fail the comparison rather
/// than pass silently. Without this, a bug in `schema_property_names` (an
/// artifact rename, a `$defs` restructure) would turn the gate into a no-op
/// that reports success for every DTO.
#[test]
fn the_gate_detects_a_dto_missing_a_declared_field() {
    #[derive(Serialize)]
    struct BehindTheSchema {
        realms: Vec<String>,
    }

    let declared = schema_property_names(SERVICE_OPERATION_DTOS, "EventsQueryPostRequestBody");
    let carried = serialized_field_names(&BehindTheSchema {
        realms: vec!["ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned()],
    });
    let missing: Vec<&String> = declared.difference(&carried).collect();
    assert!(
        missing.contains(&&"include_completeness".to_owned()),
        "the coverage comparison must notice a dropped field, got {missing:?}"
    );
}

/// Spec artifact holding the Event payload `$defs`.
const EVENT_PAYLOAD: &str = "schemas/event-payload.schema.json";

/// `ak.realm.policy_bundle` is a `cas_register`: a revision restates the
/// complete enabled component set, so a payload type that is behind the schema
/// does not merely fail to express a component — it **clears** it on every
/// write. The set comparison is therefore a correctness gate, not tidiness.
///
/// The 2026-08-01 ruling is exactly this failure: the payload carried five of
/// the fifteen declared components, so `join_policy`, `audit_policy`,
/// `aad_visibility` and the rest were unwritable and any bundle authored
/// through the SDK wiped them.
#[test]
fn realm_policy_bundle_payload_matches_its_schema_definition() {
    let fully_populated: arkret_models_collaboration::events_payloads::RealmPolicyBundlePayload =
        serde_json::from_value(json!({
            "policy_revision": 4,
            "content_scheme": "mls_exporter_aead_v1",
            "content_encryption_floor": "e2ee_required",
            "metadata_encryption_floor": "e2ee_required",
            "federation_policy": "restricted",
            "aad_visibility": { "event_id_kind": "routing_digest" },
            "durability_policy": { "mode": "none" },
            "mls_send_pause": "advisory",
            "relaxed_window_max_ms": 60000,
            "media_service_decrypts": true,
            "join_policy": {
                "gates": [{ "gate_id": "open", "kind": "allow_all" }],
                "combinator": "all"
            },
            "agent_participation": {
                "native_agent": {
                    "reply_message": true,
                    "reaction_add": false,
                    "reaction_remove": false,
                    "accept_third_party_mention": false,
                    "act_on_behalf": false
                }
            },
            "account_deactivation": { "member_action": "leave_all" },
            "availability_policy": {
                "min_holders": 1,
                "holder_roles": ["joined_member_principal_server"],
                "applies_to": ["seal_include"]
            },
            "audit_policy": {
                "range_completeness_witnesses": ["ak:did_core:web:witness.example"],
                "witnessed_min_attestations": 1,
                "witness_independence": "distinct_did"
            },
            "revocation_freshness_window_ms": 60000,
            "recovery_witness_freshness_window_ms": 60000,
            "proposal_intake_sla_ms": 60000,
            "proposal_decision_window_ms": 30000,
            "proposal_absolute_deadline_ms": 90000,
            "max_proposal_defers": 2,
            "seal_compaction_max_interval_ms": 300000,
            "max_authority_lifetime_ms": 86400000,
            "bottom_escalation_after_ms": 60000,
            "cell_lattices": [{
                "cell_family": arkret_wire::CellFamilyId::STRAND_TRACKS_V1,
                "lattice": "cas_register",
                "bottom": "reject"
            }],
            "preauth": { "consent_required": true },
            "allowed_third_party_invite_verification_service_ids": [
                "ak:did_core:web:verification.example"
            ]
        }))
        .expect("every schema-declared component is accepted by the typed bundle payload");

    assert_dto_matches_schema(
        EVENT_PAYLOAD,
        "realm_policy_bundle_payload",
        &fully_populated,
    );
}

/// Field names declared by a standalone schema artifact's top-level
/// `properties`.
fn root_property_names(artifact: &str) -> BTreeSet<String> {
    let schema = arkret_schema::embedded_json_artifact(artifact)
        .unwrap_or_else(|error| panic!("embedded artifact {artifact} failed to load: {error}"));
    schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| panic!("{artifact}#/properties is missing"))
        .keys()
        .cloned()
        .collect()
}

fn assert_profile_matches_schema<T: Serialize>(artifact: &str, fully_populated: &T) {
    let declared = root_property_names(artifact);
    let carried = serialized_field_names(fully_populated);
    assert_eq!(
        declared, carried,
        "{artifact} and its typed profile disagree on the closed field set"
    );
}

/// Every registered Signal plaintext profile carries exactly its closed
/// schema's fields — in particular both members of the §1.1 common minimum,
/// `kind` and `payload_sequence`.
///
/// The 2026-08-01 ruling removed the durable-object leftovers from
/// `ak.receipt.read` and added `payload_sequence` to `ak.call.signal`; this is
/// what keeps a profile from drifting back into hand-topped-up fields.
#[test]
fn signal_plaintext_profiles_match_their_closed_schemas() {
    use arkret_models_collaboration::signal_plaintext::{
        PresencePlaintext, ReadReceipt, TypingPlaintext,
    };

    let receipt: ReadReceipt = serde_json::from_value(json!({
        "kind": "ak.receipt.read",
        "payload_sequence": 9,
        "actor_id": "ak:did_core:web:alice.example",
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "read_scope": {"kind": "realm"}
    }))
    .expect("read receipt accepts every declared field");
    assert_profile_matches_schema("schemas/read-receipt.schema.json", &receipt);

    let presence: PresencePlaintext = serde_json::from_value(json!({
        "kind": "ak.presence",
        "payload_sequence": 2,
        "actor_id": "ak:did_core:web:alice.example",
        "state": "online",
        "status_message": "back in ten",
        "last_active_at": "2026-08-01T00:00:00.000Z",
        "ttl_ms": 30000
    }))
    .expect("presence accepts every declared field");
    assert_profile_matches_schema("schemas/signal-presence.schema.json", &presence);

    let typing: TypingPlaintext = serde_json::from_value(json!({
        "kind": "ak.typing",
        "payload_sequence": 3,
        "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        "track_name": "discussion",
        "typing": true,
        "ttl_ms": 5000
    }))
    .expect("typing accepts every declared field");
    assert_profile_matches_schema("schemas/signal-typing.schema.json", &typing);

    let call: arkret_models_collaboration::call_signal::CallSignalPlaintext =
        serde_json::from_value(json!({
            "kind": "ak.call.signal",
            "payload_sequence": 4,
            "call_id": "ak:call:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            "signal_kind": "candidate",
            "seq": 1,
            "data": {
                "candidates": [{
                    "candidate": "candidate:1 1 UDP 2122260223 192.0.2.1 54400 typ host"
                }]
            }
        }))
        .expect("call signal accepts every declared field");
    assert_profile_matches_schema("schemas/call-signal-plaintext.schema.json", &call);
}
