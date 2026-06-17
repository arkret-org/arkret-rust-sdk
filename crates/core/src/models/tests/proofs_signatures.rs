use std::collections::BTreeMap;

use chrono::Utc;
use serde_json::json;

use super::super::*;
use super::test_realm_id;

fn valid_proof() -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        event_digest: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        domain: None,
        audience: None,
        jws: "header.payload.signature".to_owned(),
    }
}

#[test]
fn hlc_sorts_by_structured_parts() {
    let mut hlcs = [
        "01970e589d21-0004-bbbbbbbb",
        "01970e589d20-0009-ffffffff",
        "01970e589d21-0003-ffffffff",
        "01970e589d21-0004-a13f9c2e",
    ]
    .map(|value| Hlc::new(value).unwrap());
    hlcs.sort();
    let actual = hlcs.map(|value| value.to_string());
    assert_eq!(
        actual,
        [
            "01970e589d20-0009-ffffffff",
            "01970e589d21-0003-ffffffff",
            "01970e589d21-0004-a13f9c2e",
            "01970e589d21-0004-bbbbbbbb",
        ]
    );
}

#[test]
fn relation_requires_exact_wire_endpoints() {
    let relation = Relation {
        schema: RELATION_SCHEMA.to_owned(),
        id: RelationId::new("ck:relation:01904100-0000-7000-8000-7b3bf7d6e46b").unwrap(),
        realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: RelationKind::Mentions,
        from_ref: "ck:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned(),
        to_ref: "did:web:alice.example".to_owned(),
        rank: None,
        fields: BTreeMap::new(),
        state: None,
        state_changed_at: None,
        created_by: Did::new("did:web:alice.example").unwrap(),
        created_at: Utc::now(),
        updated_by: None,
        updated_at: None,
    };
    relation.validate_endpoints().unwrap();
}

#[test]
fn query_request_uses_protocol_filters_array() {
    let request = ViewQuery {
        realm_ids: vec![RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
        object_types: vec!["morph".to_owned()],
        morph_types: vec!["task".to_owned()],
        facets: vec![Facet::Stateful, Facet::Rankable],
        seal_ref: None,
        filters: vec![Filter::Predicate(FieldFilter {
            field: "fields.status".to_owned(),
            op: FilterOp::Eq,
            value: Some(json!("todo")),
        })],
        relation: None,
        context: None,
        order_by: vec![],
        projection: vec![],
        cursor: None,
        limit: Some(50),
        consistency: None,
    };

    let value = serde_json::to_value(request).unwrap();
    assert!(value.get("realm_ids").unwrap().is_array());
    assert!(value.get("filters").unwrap().is_array());
    assert_eq!(value["facets"], json!(["stateful", "rankable"]));
    assert!(value.get("renderer").is_none());
    assert!(value.get("sync_token").is_none());
}

#[test]
fn facets_accept_name_lists_and_config_maps() {
    let names: Facets =
        serde_json::from_value(json!(["stateful", "rankable", "renderable"])).unwrap();
    assert!(names.contains(&Facet::Stateful));
    assert_eq!(names.facet_names().len(), 3);

    let configs: Facets = serde_json::from_value(json!({
        "rankable": {"rank_field": "fields.rank"},
        "renderable": {"renderers": ["card"]}
    }))
    .unwrap();
    assert!(configs.contains(&Facet::Rankable));
    assert_eq!(
        serde_json::to_value(configs).unwrap()["renderable"]["renderers"][0],
        "card"
    );
}

#[test]
fn view_supports_renderer_and_facet_config_facades() {
    let request = ViewQuery {
        realm_ids: vec![RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
        object_types: Vec::new(),
        morph_types: Vec::new(),
        facets: vec![Facet::Stateful, Facet::Rankable],
        seal_ref: None,
        filters: Vec::new(),
        relation: None,
        context: None,
        order_by: Vec::new(),
        projection: Vec::new(),
        cursor: None,
        limit: None,
        consistency: None,
    };
    let view = View {
        schema: VIEW_SCHEMA.to_owned(),
        id: ViewId::new("ck:view:01904100-0000-7000-8000-848727f328fe").unwrap(),
        realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        kind: ViewKind::Collection,
        visibility: None,
        renderer: Some(ViewRenderer::Board),
        title: Some("Board".to_owned()),
        query: request,
        visible_fields: Vec::new(),
        layout: None,
        collection: Some(CollectionViewConfig {
            item_facets: vec![Facet::Stateful, Facet::Rankable],
            item_render: Some("card".to_owned()),
            ..Default::default()
        }),
        time_window: None,
        timeline: None,
        graph: None,
        document: None,
        dashboard: None,
        sort: Vec::new(),
        created_by: Did::new("did:web:alice.example").unwrap(),
        created_at: Utc::now(),
    };

    let value = serde_json::to_value(view).unwrap();
    assert_eq!(value["renderer"], "board");
    assert_eq!(
        value["collection"]["item_facets"],
        json!(["stateful", "rankable"])
    );
}

#[test]
fn operation_serializes_protocol_field_names() {
    let mut operation = Operation::create(
        OperationId::new("ck:operation:01904100-0000-7000-8000-d408d6a2241c").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "morph",
        json!({"id":"ck:morph:01904100-0000-7000-8000-c12dc98b2948"}),
    );
    operation.object_id = Some("ck:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned());

    let value = serde_json::to_value(operation).unwrap();

    assert_eq!(value["type"], "operation");
    assert_eq!(value["operation_type"], "create");
    assert_eq!(
        value["object_id"],
        "ck:morph:01904100-0000-7000-8000-c12dc98b2948"
    );
    assert_eq!(value["object_type"], "morph");
    assert!(value.get("target_object_id").is_none());
    assert_eq!(value["schema"], OPERATION_SCHEMA);
}

// SyncOutcome carries `cursor` / `realms` / `left_realms` /
// `notifications`. Realm ids and product Space ids are validated by their
// typed-id constructors and exercised by the typed-ID tests above.

#[test]
fn proof_validate_rejects_alg_none() {
    let mut proof = valid_proof();
    proof.alg = "none".to_owned();
    assert!(proof.validate().is_err());
    assert!(proof.validate().unwrap_err().to_string().contains("'none'"));
}

#[test]
fn proof_validate_rejects_none_case_insensitive() {
    let mut proof = valid_proof();
    proof.alg = "NONE".to_owned();
    assert!(proof.validate().is_err());
}

#[test]
fn proof_validate_rejects_empty_fields() {
    let mut proof = valid_proof();
    proof.alg = "".to_owned();
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.verification_method = "".to_owned();
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.jws = "".to_owned();
    assert!(proof.validate().is_err());

    let mut proof = valid_proof();
    proof.kind = "".to_owned();
    assert!(proof.validate().is_err());
}

#[test]
fn proof_validate_accepts_valid_proof() {
    assert!(valid_proof().validate().is_ok());
}

#[test]
fn proof_validate_production_rejects_dev_kinds() {
    for kind in &["dev", "test", "mock", "stub", "dummy"] {
        let mut proof = valid_proof();
        proof.kind = kind.to_string();
        assert!(
            proof.validate_production().is_err(),
            "should reject kind: {kind}"
        );
    }
}

#[test]
fn proof_validate_production_rejects_unsupported_algorithms() {
    let mut proof = valid_proof();
    proof.alg = "HS256".to_owned();
    assert!(proof.validate_production().is_err());

    let mut proof = valid_proof();
    proof.alg = "RSASSA-PKCS1-v1_5".to_owned();
    assert!(proof.validate_production().is_err());
}

#[test]
fn proof_validate_production_accepts_known_algorithms() {
    // The accepted set MUST equal the signature-alg-registry active rows
    // (encoding.md §6.1): EdDSA / ES256 / ML-DSA-65.
    for alg in &["EdDSA", "ES256", "ML-DSA-65"] {
        let mut proof = valid_proof();
        proof.alg = alg.to_string();
        assert!(
            proof.validate_production().is_ok(),
            "should accept algorithm: {alg}"
        );
    }
}

#[test]
fn proof_validate_production_rejects_unregistered_algorithms() {
    // ES256K / RS256 / PS256 are NOT in the signature-alg-registry active set
    // and MUST be rejected — admitting them widens the SDK's security gate
    // beyond the protocol-accepted algorithms (encoding.md §6.1).
    for alg in &["ES256K", "RS256", "PS256"] {
        let mut proof = valid_proof();
        proof.alg = alg.to_string();
        assert!(
            proof.validate_production().is_err(),
            "should reject unregistered algorithm: {alg}"
        );
    }
}

#[test]
fn proof_validate_binding_matches_expected_fields() {
    let proof = valid_proof();
    let expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    assert!(proof.validate_binding(&expected).is_ok());
}

#[test]
fn proof_validate_binding_rejects_mismatched_verification_method() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.verification_method = "did:web:bob.example#key-1".to_owned();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_payload_digest() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.payload_digest =
        Hash::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_domain() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.domain = Some("other.example".to_owned());
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_mismatched_audience() {
    let mut proof = valid_proof();
    proof.audience = Some(Audience::Single("svc-a".to_owned()));
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.audience = Some(Audience::Single("svc-b".to_owned()));
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn proof_validate_binding_rejects_excessive_time_drift() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.created_at = "2026-04-26T01:00:00Z".parse().unwrap();
    assert!(proof.validate_binding(&expected).is_err());
}

#[test]
fn event_validate_proof_bindings_checks_digest_match() {
    let event = Event::new(
        "ck.message.create",
        test_realm_id(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event.event_digest().unwrap();
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        event_digest: Hash::new(digest).unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "sig".to_owned(),
    };

    let mut signed_event = event;
    signed_event.proofs = vec![proof];
    assert!(signed_event.validate_proof_bindings().is_ok());
}

#[test]
fn event_validate_proof_bindings_rejects_mismatched_digest() {
    let event = Event::new(
        "ck.message.create",
        test_realm_id(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let bad_proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        event_digest: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "sig".to_owned(),
    };

    let mut signed_event = event;
    signed_event.proofs = vec![bad_proof];
    assert!(signed_event.validate_proof_bindings().is_err());
}

#[test]
fn event_digest_includes_profile_refs_features_and_critical_extensions() {
    let mut event = Event::new(
        "ck.message.create",
        test_realm_id(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();
    let base_digest = event.event_digest().unwrap();

    event
        .requirements
        .schema_profile_refs
        .push("ck.schema.core_event.v1".to_owned());
    event.requirements.reducer_profile_ref = Some("ck.reducer.core_event.v1".to_owned());
    event
        .requirements
        .required_features
        .push("ck.feature.event_extensions.v1".to_owned());
    event
        .requirements
        .critical_extensions
        .push(CriticalExtension {
            id: "ck.feature.policy_gate.v1".to_owned(),
            scope: "authz".to_owned(),
            schema_ref: Some("ck.schema.policy.v1".to_owned()),
            fail_closed: true,
        });

    assert_ne!(base_digest, event.event_digest().unwrap());
    let value = serde_json::to_value(&event).unwrap();
    assert!(value.get("schema_profile_refs").is_none());
    assert_eq!(
        value["requirements"]["schema"][0],
        "ck.schema.core_event.v1"
    );
    assert_eq!(value["requirements"]["reducer"], "ck.reducer.core_event.v1");
    assert_eq!(
        value["requirements"]["features"][0],
        "ck.feature.event_extensions.v1"
    );

    event.requirements.critical_extensions[0].fail_closed = false;
    assert!(event.validate_for_submit().is_err());
}

#[test]
fn operation_draft_explicitly_materializes_event_envelope_without_signed_operation_id() {
    let operation = OperationEnvelopeBuilder::new(
        OperationId::new("ck:operation:01904100-0000-7000-8000-9c5aa474063f").unwrap(),
        test_realm_id(),
        Did::new("did:web:alice.example").unwrap(),
        OP_MESSAGE_CREATE,
        7,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
    )
    .with_content(json!({
        "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
        "track_name": "discussion",
        "content": {"kind": "ck.content.text", "body": "hello"}
    }))
    .build(&OperationKindRegistry::default())
    .unwrap();

    let event = operation
        .into_event_envelope(OperationEventConversion::default())
        .unwrap();
    assert_eq!(event.kind, OP_MESSAGE_CREATE);
    assert_eq!(event.actor_seq, 7);
    assert_eq!(
        event.content,
        json!({
            "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
            "track_name": "discussion",
            "content": {"kind": "ck.content.text", "body": "hello"}
        })
    );
    assert_eq!(
        event.unsigned["local_operation_idempotency_alias"],
        json!("ck:operation:01904100-0000-7000-8000-9c5aa474063f")
    );
    assert!(
        !event
            .digest_payload()
            .unwrap()
            .to_string()
            .contains("local_operation_id")
    );
}
