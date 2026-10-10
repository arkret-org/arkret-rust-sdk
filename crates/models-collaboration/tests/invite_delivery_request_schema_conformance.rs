//! The private invite delivery body stays member-for-member isomorphic to
//! `invite-delivery-request.schema.json`, including the governance
//! `invite_commit` and the untrusted `authority_locator_hints` array.

use std::path::PathBuf;
use std::{fmt, fs};

use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody;
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};

const SCHEMA_FILE: &str = "invite-delivery-request.schema.json";

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_text() -> String {
    let path = artifacts_dir().join("schemas").join(SCHEMA_FILE);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn schema_accepts(value: &Value) -> bool {
    let mut registry: ProtocolSchemaRegistry = schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry");
    let schema: Value = serde_json::from_str(&schema_text()).expect("schema must be valid JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    registry.register("test:invite-delivery-request", schema);
    registry
        .validate_value("test:invite-delivery-request", value)
        .is_ok()
}

/// Object member names in document order; `serde_json::Value` would sort them.
struct OrderedKeys(Vec<String>);

impl<'de> Deserialize<'de> for OrderedKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeysVisitor;
        impl<'de> Visitor<'de> for KeysVisitor {
            type Value = OrderedKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OrderedKeys, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    map.next_value::<IgnoredAny>()?;
                    keys.push(key);
                }
                Ok(OrderedKeys(keys))
            }
        }
        deserializer.deserialize_map(KeysVisitor)
    }
}

#[derive(Deserialize)]
struct PublishedTopLevel {
    properties: OrderedKeys,
    required: Vec<String>,
}

fn published_top_level() -> PublishedTopLevel {
    serde_json::from_str(&schema_text()).expect("schema top level must parse")
}

/// The spec's approval KAT Event: a real canonical envelope, used here only
/// for the delivery body's shape.
fn invite_event() -> Value {
    let path = artifacts_dir()
        .join("fixtures")
        .join("approval-signature-kat-fixture.json");
    let fixture: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    fixture["event_id_invariance"]["submission_with_evidence"]["event"].clone()
}

fn invite_commit_for(event: &Value) -> Value {
    json!({
        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        "realm_id": event["realm_id"],
        "stream_ref": {"kind": "realm", "realm_id": event["realm_id"]},
        "stream_position": 0,
        "previous_commit_ref": null,
        "event_ref": event["event_id"],
        "governance_generation": 0,
        "authority_ref": event["event_id"],
        "committed_at": "2026-09-20T00:00:00.000Z",
        "signature": {
            "context": "ak.realm_commit_signature.v1",
            "signature_algorithm": "Ed25519",
            "verification_method": "did:web:station.example#authority",
            "signed_digest": format!("sha256:{}", "4".repeat(64)),
            "created_at": "2026-09-20T00:00:00.000Z",
            "sig": "A".repeat(86)
        }
    })
}

fn hint(service_id: &str, source: &str) -> Value {
    json!({"service_kind": "station", "service_id": service_id, "source": source})
}

fn delivery_body() -> Value {
    let event = invite_event();
    let commit = invite_commit_for(&event);
    json!({
        "schema": "ak.schema.invite_delivery_request.v1",
        "invite_event": event,
        "invite_commit": commit,
        "authority_locator_hints": [
            hint("ak:did_core:web:a.example", "invite"),
            {
                "service_kind": "station",
                "service_id": "ak:did_core:web:b.example",
                "endpoint_url": "https://b.example/_arkret",
                "source": "invite"
            }
        ],
        "invite_address": {
            "account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:station-b.example"
            },
            "service_resolution": {
                "resolution_url": "https://station-b.example/.well-known/did.json"
            }
        },
        "introduction_evidence": {"kind": "explicit_address"},
        "idempotency_key": "invite-delivery-0001"
    })
}

fn sdk_parse(value: &Value) -> Result<InviteDeliveryRequestBody, serde_json::Error> {
    serde_json::from_value(value.clone())
}

fn sdk_accepts(value: &Value) -> bool {
    sdk_parse(value).is_ok_and(|body| body.validate_minimal().is_ok())
}

#[test]
fn delivery_body_matches_the_published_schema_member_for_member() {
    let value = delivery_body();
    assert!(schema_accepts(&value), "schema rejected the canonical body");

    let body = sdk_parse(&value).expect("SDK accepts the canonical body");
    body.validate_minimal()
        .expect("canonical body passes wire-local checks");
    assert_eq!(serde_json::to_value(&body).unwrap(), value);

    let published = published_top_level();
    let serialized: OrderedKeys =
        serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
    assert_eq!(
        serialized.0,
        published
            .properties
            .0
            .iter()
            .filter(|name| name.as_str() != "producer_signer_fact")
            .cloned()
            .collect::<Vec<_>>(),
        "SDK member order must be the schema properties order"
    );
    assert_eq!(
        published.required, serialized.0,
        "the exact legacy original omits only the optional new signer fact"
    );
}

#[test]
fn every_required_member_is_required_by_schema_and_sdk() {
    for member in published_top_level().required {
        let mut value = delivery_body();
        value.as_object_mut().unwrap().remove(&member);
        assert!(
            !schema_accepts(&value),
            "schema accepted body without {member}"
        );
        assert!(
            sdk_parse(&value).is_err(),
            "SDK accepted body without {member}"
        );
    }
}

#[test]
fn unknown_members_are_refused_by_schema_and_sdk() {
    let mut value = delivery_body();
    value["authority_bundle"] = json!({});
    assert!(!schema_accepts(&value));
    assert!(sdk_parse(&value).is_err());
}

#[test]
fn invite_commit_must_address_the_invite_event_on_its_realm_stream() {
    let mut other_event = delivery_body();
    other_event["invite_commit"]["event_ref"] =
        json!("ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRC");
    other_event["invite_commit"]["authority_ref"] =
        other_event["invite_commit"]["event_ref"].clone();
    assert!(sdk_parse(&other_event).is_ok());
    assert!(!sdk_accepts(&other_event), "commit for another Event");

    let mut circle_stream = delivery_body();
    circle_stream["invite_commit"]["stream_ref"] = json!({
        "kind": "circle",
        "realm_id": circle_stream["invite_event"]["realm_id"],
        "circle_id": "ak:circle:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB"
    });
    assert!(sdk_parse(&circle_stream).is_ok());
    assert!(!sdk_accepts(&circle_stream), "commit on a Circle stream");
}

#[test]
fn authority_locator_hints_follow_the_closed_array_contract() {
    let with_hints = |hints: Value| {
        let mut value = delivery_body();
        value["authority_locator_hints"] = hints;
        value
    };

    let empty = with_hints(json!([]));
    assert!(!schema_accepts(&empty));
    assert!(!sdk_accepts(&empty));

    let nine = with_hints(Value::Array(
        (0..9)
            .map(|index| hint(&format!("ak:did_core:web:s{index}.example"), "invite"))
            .collect(),
    ));
    assert!(!schema_accepts(&nine));
    assert!(!sdk_accepts(&nine));

    let a = hint("ak:did_core:web:a.example", "invite");
    let b = hint("ak:did_core:web:b.example", "directory");

    let exact_duplicate = with_hints(json!([a, a]));
    assert!(!schema_accepts(&exact_duplicate));
    assert!(!sdk_accepts(&exact_duplicate));

    let conflicting = with_hints(json!([a, hint("ak:did_core:web:a.example", "cache")]));
    assert!(!sdk_accepts(&conflicting));

    let reversed = with_hints(json!([b, a]));
    assert!(!sdk_accepts(&reversed));

    let mut insecure = a.clone();
    insecure["endpoint_url"] = json!("http://a.example/_arkret");
    let insecure = with_hints(json!([insecure]));
    assert!(!schema_accepts(&insecure));
    assert!(!sdk_accepts(&insecure));

    let mut retired = a.clone();
    retired["realm_id"] = json!("ak:realm:ATh7OWLLpUdTVYsKdp6rkClScUpjYJlF1Y3byjeyHS8J");
    let retired = with_hints(json!([retired]));
    assert!(!schema_accepts(&retired));
    assert!(sdk_parse(&retired).is_err());

    let sorted = with_hints(json!([a, b]));
    assert!(schema_accepts(&sorted));
    assert!(sdk_accepts(&sorted));
}

#[test]
fn idempotency_key_is_bounded_like_the_schema() {
    let mut longest = delivery_body();
    longest["idempotency_key"] = json!("k".repeat(256));
    assert!(schema_accepts(&longest));
    assert!(sdk_accepts(&longest));

    let mut too_long = delivery_body();
    too_long["idempotency_key"] = json!("k".repeat(257));
    assert!(!schema_accepts(&too_long));
    assert!(!sdk_accepts(&too_long));

    let mut empty = delivery_body();
    empty["idempotency_key"] = json!("");
    assert!(!schema_accepts(&empty));
    assert!(!sdk_accepts(&empty));
}

#[test]
fn invite_fact_presence_and_closed_source_match_the_original_commit_schema() {
    use arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact;
    use arkret_models_identity::ResolvedSignerKey;
    use arkret_wire::{CommittedEventRef, CurrentRevision, RealmCommitId};
    let mut body = sdk_parse(&delivery_body()).unwrap();
    // This schema case uses an actual device-produced Invite, not the principal-key approval KAT.
    use ed25519_dalek::{Signer as _, SigningKey};
    let device =
        arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
    let controller = body
        .invite_event
        .producer_proof
        .as_ref()
        .unwrap()
        .verification_method
        .as_str()
        .split_once('#')
        .unwrap()
        .0
        .to_owned();
    let signing = SigningKey::from_bytes(&[7; 32]);
    let raw = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.invite.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: body.invite_event.realm_id.clone(),
        },
        body.invite_event.actor_id.clone(),
        crate_payload(&body),
        body.invite_event.created_at,
    )
    .unwrap();
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        raw,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let mut proof = arkret_wire::ProducerEventProof {
        kind: "detached_jws".into(),
        verification_method: arkret_wire::DidUrl::new(format!("{controller}#{device}")).unwrap(),
        event_digest: arkret_wire::Hash::new(
            authored
                .event()
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        created_at: authored.event().created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = proof
        .canonical_binding_bytes(&authored.event().actor_id)
        .unwrap();
    let header = arkret_canonical::base64url_encode(br#"{"alg":"Ed25519"}"#);
    let input = format!("{header}.{}", arkret_canonical::base64url_encode(&binding));
    let signature = signing.sign(input.as_bytes());
    signing
        .verifying_key()
        .verify_strict(input.as_bytes(), &signature)
        .unwrap();
    proof.jws = format!(
        "{header}..{}",
        arkret_canonical::base64url_encode(signature.to_bytes())
    );
    authored.attach_proof(proof);
    body.invite_event = authored.into_event();
    body.invite_commit.event_ref = body.invite_event.event_id.clone();
    let producer = body.invite_event.human_device_producer().unwrap().unwrap();
    let fact = HumanHistoricalSignerFact {
        event_id: body.invite_event.event_id.clone(),
        actor: body.invite_event.actual_signer().clone(),
        device_id: producer.device_id,
        verification_method: body
            .invite_event
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
        key: ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                signing.verifying_key().as_bytes(),
            ))
            .unwrap(),
            authorization_ref: CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [8; 32],
                ),
                commit_id: RealmCommitId::from_digest([9; 32]),
                stream_ref: body.invite_commit.stream_ref.clone(),
                stream_position: 2,
            },
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([10; 32]),
                stream_position: 3,
            },
            governance_generation: 4,
        },
        accepted_at: body.invite_commit.committed_at,
    };
    body.invite_commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    let unsigned = arkret_canonical::canonical::unsigned_value(
        &body.invite_commit,
        &["commit_id", "signature"],
    )
    .unwrap();
    body.invite_commit.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&unsigned).unwrap(),
    ));
    body.producer_signer_fact = Some(fact);
    body.validate_minimal().unwrap();
    let mut mismatched = body.clone();
    mismatched
        .producer_signer_fact
        .as_mut()
        .unwrap()
        .accepted_at += chrono::Duration::seconds(1);
    mismatched.validate_minimal().unwrap();
    assert!(
        mismatched
            .producer_signer_fact
            .as_ref()
            .unwrap()
            .validate_commit_binding(
                &arkret_wire::CommittedEventFullView {
                    event: mismatched.invite_event.clone(),
                    commit: mismatched.invite_commit.clone(),
                },
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err(),
        "closed shape cannot replace exact cryptographic admission binding"
    );
    let value = serde_json::to_value(&body).unwrap();
    assert!(schema_accepts(&value));
    let serialized: OrderedKeys =
        serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
    assert_eq!(serialized.0, published_top_level().properties.0);
    let mut missing = value.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("producer_signer_fact");
    assert!(!schema_accepts(&missing));
    assert!(!sdk_accepts(&missing));
    let mut extra = value.clone();
    extra["invite_commit"]
        .as_object_mut()
        .unwrap()
        .remove("producer_signer_fact_digest");
    assert!(!schema_accepts(&extra));
    assert!(!sdk_accepts(&extra));
    let mut null = value.clone();
    null["producer_signer_fact"] = Value::Null;
    assert!(!schema_accepts(&null));
    assert!(sdk_parse(&null).is_err());
    let mut null_digest = value.clone();
    null_digest["invite_commit"]["producer_signer_fact_digest"] = Value::Null;
    assert!(!schema_accepts(&null_digest));
    assert!(sdk_parse(&null_digest).is_err());
    let mut target = value;
    target["producer_signer_fact"]["target"] = json!({});
    assert!(!schema_accepts(&target));
    assert!(sdk_parse(&target).is_err());
}

fn crate_payload(body: &InviteDeliveryRequestBody) -> Value {
    arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
        body.invite_address.account_id.clone(),
        arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&body.introduction_evidence).unwrap(),
        )
        .unwrap(),
        body.invite_event.created_at + chrono::Duration::hours(1),
    )
    .to_value()
    .unwrap()
}
