use super::*;
use serde_json::json;

#[test]
fn did_validation_rejects_handles() {
    assert!(Did::new("did:web:alice.example").is_ok());
    assert!(Did::new("alice.example").is_err());
}

#[test]
fn did_uuid_validation_checks_uuid_layout() {
    let did = Did::new("did:uuid:550e8400-e29b-41d4-a716-446655440000").unwrap();
    assert_eq!(did.method(), "uuid");
    assert!(did.is_uuid());
    assert!(Did::new("did:uuid:19dbd742-a001-834d-91b6-b01c2e3b76d9").unwrap().is_uuid());

    assert!(Did::new("did:uuid:550e8400-e29b-11d4-a716-446655440000").is_err());
    assert!(Did::new("did:uuid:550e8400-e29b-41d4-c716-446655440000").is_err());
    assert!(Did::new("did:uuid:550E8400-e29b-41d4-a716-446655440000").is_err());
    assert!(Did::new("did:uuid:00000000-0000-4000-8000-000000000000").is_ok());
    assert!(Did::new("did:uuid:00000000-0000-0000-0000-000000000000").is_err());
}

#[test]
fn did_uuid_generation_sets_version_and_variant_bits() {
    let did = Did::uuid_v4_from_bytes([0xff; 16]).unwrap();
    assert_eq!(did.as_str(), "did:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff");
    assert!(did.is_uuid());

    let generated = Did::new_uuid_v4().unwrap();
    assert!(generated.is_uuid());
}

#[test]
fn device_id_accepts_protocol_device_forms() {
    assert!(DeviceId::new("dev_alice_1").is_ok());
    assert!(DeviceId::new("cx:device:01904100-0000-7000-8000-8b3ad8ecac70").is_ok());
    assert!(DeviceId::new("device-1").is_err());
}

#[test]
fn server_description_checks_protocol_version() {
    let desc = ServerDescription {
        service_did: Did::new("did:web:svc.example").unwrap(),
        service_type: "principal_server".to_owned(),
        protocol_version: "1.0".to_owned(),
        supported_profiles: vec![],
        supported_features: vec![],
        supported_operations: vec![],
        supported_bindings: vec![],
        supported_reducer_profiles: vec![],
        supported_schema_profiles: vec![],
        auth_metadata: Value::Null,
        limits: Value::Null,
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };
    assert!(desc.supports_contrix_v1());
}

#[test]
fn event_new_sets_required_event_id() {
    let event = Event::new(
        "cx.message.create",
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    assert!(event.event_id.as_str().starts_with("cx:event:"));
}

#[test]
fn event_digest_uses_canonical_payload_without_proofs_or_unsigned() {
    let event = Event {
        event_id: EventId::new("cx:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
        kind: "cx.message.create".to_owned(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        actor_id: Did::new("did:web:alice.example").unwrap(),
        actor_seq: 1,
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        prev_refs: Vec::new(),
        refs: Vec::new(),
        schema_profile_refs: Vec::new(),
        reducer_profile_ref: None,
        required_features: Vec::new(),
        critical_extensions: Vec::new(),
        redacts: None,
        content: json!({ "body": "hello" }),
        unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
        proofs: Vec::new(),
    };

    assert_eq!(
        event.event_digest().unwrap(),
        "sha256:c807c361145a6a97b16bd0915e096b32a3ec0c837aec5199a7ff92b3cc404901"
    );
}

#[test]
fn operation_envelope_uses_spec_fields_and_digest_ignores_proofs() {
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#device-1".to_owned(),
        payload_hash: Hash::new(
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )
        .unwrap(),
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        domain: None,
        audience: None,
        jws: "sig-a".to_owned(),
    };
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("cx:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        actor_id: Did::new("did:web:alice.example").unwrap(),
        kind: "cx.message.create".to_owned(),
        target_ref: Some("cx:thread:general".to_owned()),
        causal: CausalRef {
            deps: vec![
                OperationId::new("cx:operation:01904100-0000-7000-8000-5f8278b99124").unwrap(),
            ],
            hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            actor_seq: 7,
        },
        content: json!({"body": "hello"}),
        authz_ref: None,
        proofs: vec![proof.clone()],
    };
    let mut different_proof = envelope.clone();
    different_proof.proofs = vec![Proof { jws: "sig-b".to_owned(), ..proof }];

    assert_eq!(envelope.operation_digest().unwrap(), different_proof.operation_digest().unwrap());
    envelope.validate_for_submit().unwrap();

    let encoded = serde_json::to_value(&envelope).unwrap();
    assert_eq!(encoded["actor_id"], "did:web:alice.example");
    assert_eq!(encoded["kind"], "cx.message.create");
    assert_eq!(encoded["content"]["body"], "hello");
    assert!(encoded.get("actor").is_none());
    assert!(encoded.get("type").is_none());
    assert!(encoded.get("body").is_none());
    assert!(encoded.get("signature").is_none());
}

#[test]
fn operation_kind_registry_accepts_only_canonical_kinds() {
    let registry = OperationKindRegistry::default();

    let canonical = registry.canonicalize(OP_MESSAGE_CREATE).unwrap();
    assert_eq!(canonical.canonical_kind, OP_MESSAGE_CREATE);

    assert!(registry.canonicalize("message_create").is_err());
    assert!(registry.canonicalize("cx.task.move").is_err());
    assert!(registry.canonicalize("cx.relation.move").is_err());
    assert!(registry.kinds().count() >= BUILT_IN_OPERATION_KINDS.len());
}

#[test]
fn operation_kind_registry_rejects_removed_flow_alias_kinds() {
    let registry = OperationKindRegistry::default();
    for kind in [
        "cx.subject.create",
        "cx.subject.update",
        "cx.subject.archive",
        "cx.subject.restore",
        "cx.subject.link_surface",
        "cx.subject.unlink_surface",
        "cx.subject.set_primary_surface",
    ] {
        assert!(
            registry.canonicalize(kind).is_err(),
            "removed kind should not be canonical: {kind}"
        );
    }
}

#[test]
fn operation_kind_registry_drives_envelope_semantics() {
    let registry = OperationKindRegistry::default();
    let envelope = OperationEnvelope {
        operation_id: OperationId::new("cx:operation:01904100-0000-7000-8000-0198d483044c")
            .unwrap(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        actor_id: Did::new("did:web:alice.example").unwrap(),
        kind: OP_MESSAGE_CREATE.to_owned(),
        target_ref: None,
        causal: CausalRef {
            deps: Vec::new(),
            hlc: Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
            actor_seq: 1,
        },
        content: json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
            "track": "discussion",
            "content": {"kind": "cx.content.text", "body": "hello"}
        }),
        authz_ref: None,
        proofs: Vec::new(),
    };

    let validation = registry.validate_envelope(&envelope).unwrap();
    assert_eq!(validation.canonical_kind, OP_MESSAGE_CREATE);

    let mut missing_flow = envelope;
    missing_flow.content = json!({"track": "discussion"});
    assert!(registry.validate_envelope(&missing_flow).is_err());
}

#[test]
fn operation_envelope_builder_covers_every_builtin_kind() {
    let registry = OperationKindRegistry::default();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap();
    let actor_id = Did::new("did:web:alice.example").unwrap();
    let hlc = Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap();

    for (index, kind) in BUILT_IN_OPERATION_KINDS.iter().enumerate() {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(format!("cx:operation:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            space_id.clone(),
            actor_id.clone(),
            *kind,
            index as u64 + 1,
            hlc.clone(),
        );
        for field in required_fields_for_operation_kind(kind) {
            builder = builder.with_content_field(field, json!("value"));
        }
        let envelope = builder.build(&registry).unwrap();
        assert_eq!(envelope.kind, *kind);
        registry.validate_envelope(&envelope).unwrap();
    }
}

#[test]
fn operation_envelope_builder_requires_registered_kind_and_payload_fields() {
    let registry = OperationKindRegistry::default();
    let builder = OperationEnvelopeBuilder::new(
        OperationId::new("cx:operation:01904100-0000-7000-8000-76b2a3b35ad0").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        OP_MESSAGE_CREATE,
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
    );

    assert!(builder.clone().build(&registry).is_err());
    let envelope = builder
        .with_content_field("flow_id", json!("cx:flow:01904100-0000-7000-8000-6c663fa0205f"))
        .with_content_field("track", json!("discussion"))
        .build(&registry)
        .unwrap();
    assert_eq!(envelope.kind, OP_MESSAGE_CREATE);

    let unknown = OperationEnvelopeBuilder::new(
        OperationId::new("cx:operation:01904100-0000-7000-8000-e9d434a97fb1").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        "unknown",
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
    );
    assert!(unknown.build(&registry).is_err());
}

#[test]
fn operation_kind_conformance_vectors_cover_every_builtin() {
    let vectors = operation_kind_conformance_vectors();
    assert_eq!(vectors.len(), BUILT_IN_OPERATION_KINDS.len());
    for kind in BUILT_IN_OPERATION_KINDS {
        assert!(
            vectors
                .iter()
                .any(|vector| { vector.input_kind == *kind && vector.canonical_kind == *kind })
        );
    }
}

#[test]
fn protocol_schema_registry_publishes_core_json_schemas() {
    let registry = ProtocolSchemaRegistry::default();
    for schema_id in [
        CURSOR_SCHEMA,
        FLOW_SCHEMA,
        VIEW_SCHEMA,
        EVENT_SCHEMA,
        OPERATION_SCHEMA,
        CAPABILITY_SCHEMA,
        ENCRYPTED_PAYLOAD_SCHEMA,
        CLIENT_SYNC_RESPONSE_SCHEMA,
    ] {
        assert!(registry.schema(schema_id).is_some());
    }

    registry
        .validate_value(
            CLIENT_SYNC_RESPONSE_SCHEMA,
            &json!({"next_batch": "s1", "spaces": {}, "unknown_future_field": true}),
        )
        .unwrap();
    assert!(registry.validate_value(CLIENT_SYNC_RESPONSE_SCHEMA, &json!({"spaces": {}})).is_err());
    registry
        .validate_value(
            FLOW_SCHEMA,
            &json!({
                "schema": FLOW_SCHEMA,
                "id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
                "type": "flow",
                "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
                "title": "Topic",
                "tracks": {"synthesis": {}},
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(CLIENT_SYNC_RESPONSE_SCHEMA, &json!({"next_batch": 1, "spaces": {}}))
            .is_err()
    );

    let event_validator = registry.generated_validator(EVENT_SCHEMA).unwrap();
    for field in [
        "event_id",
        "space_id",
        "actor_id",
        "actor_seq",
        "kind",
        "created_at",
        "hlc",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        assert!(
            event_validator
                .fields
                .iter()
                .any(|validator_field| validator_field.name == field && validator_field.required),
            "{field}"
        );
    }
}

#[test]
fn schema_registry_generates_runtime_validators_from_supported_schema_subset() {
    let mut registry = ProtocolSchemaRegistry::default();
    let validator = registry.generated_validator(OPERATION_SCHEMA).unwrap();
    assert!(validator.fields.iter().any(|field| {
        field.name == "operation_id"
            && field.required
            && field.value_type == GeneratedSchemaValueType::String
    }));

    let operation = json!({
        "operation_id": "cx:operation:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "causal": {},
        "content": {},
        "unknown_future_field": true
    });
    validator.validate(&operation).unwrap();

    let wrong_type = json!({
        "operation_id": "cx:operation:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "causal": [],
        "content": {}
    });
    assert!(validator.validate(&wrong_type).is_err());

    let sensitive_extension = json!({
        "operation_id": "cx:operation:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "causal": {},
        "content": {},
        "x-policy-critical": {}
    });
    assert!(validator.validate(&sensitive_extension).is_err());
    registry.trust_extension_prefix("x-policy-critical");
    registry.generated_validator(OPERATION_SCHEMA).unwrap().validate(&sensitive_extension).unwrap();

    registry.register(
        "cx.schema.strict.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "cx.schema.strict.v1",
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
            "additionalProperties": false
        }),
    );
    assert!(
        registry
            .generated_validator("cx.schema.strict.v1")
            .unwrap()
            .validate(&json!({"id": "1", "extra": true}))
            .is_err()
    );
}

#[test]
fn schema_registry_fails_closed_for_unknown_security_extensions() {
    let mut registry = ProtocolSchemaRegistry::default();
    let value = json!({
        "operation_id": "cx:operation:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "causal": {},
        "content": {},
        "x-security-critical": {"unknown": true}
    });

    assert!(registry.validate_value(OPERATION_SCHEMA, &value).is_err());
    registry.trust_extension_prefix("x-security-critical");
    registry.validate_value(OPERATION_SCHEMA, &value).unwrap();

    let ordinary_extension = json!({
        "operation_id": "cx:operation:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "cx:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "causal": {},
        "content": {},
        "x-ui-hint": {"preserved": true}
    });
    registry.validate_value(OPERATION_SCHEMA, &ordinary_extension).unwrap();
}

#[test]
fn schema_compatibility_table_lists_builtin_schemas() {
    let table = schema_version_compatibility_table();

    assert_eq!(table.profile, SCHEMA_COMPATIBILITY_PROFILE);
    assert!(table.entries.iter().any(|entry| {
        entry.schema_id == OPERATION_SCHEMA
            && entry.current_version == "1"
            && !entry.migration_required
    }));
    assert!(table.entries.iter().any(|entry| entry.schema_id == CLIENT_SYNC_RESPONSE_SCHEMA));
}

#[test]
fn profile_conformance_suites_cover_required_domains() {
    let suites = profile_conformance_suites();
    for profile in [
        ConformanceProfile::Encoding,
        ConformanceProfile::Hlc,
        ConformanceProfile::Cursor,
        ConformanceProfile::StateResolution,
        ConformanceProfile::Redaction,
        ConformanceProfile::Capability,
        ConformanceProfile::Sync,
        ConformanceProfile::Snapshot,
        ConformanceProfile::FederationSignatures,
        ConformanceProfile::Privacy,
        ConformanceProfile::Security,
    ] {
        assert!(suites.iter().any(|suite| suite.profile == profile && !suite.cases.is_empty()));
    }
}

#[test]
fn builtin_conformance_report_is_machine_readable_and_covers_profiles() {
    let report = run_builtin_conformance_report();

    assert_eq!(report.fixture_version, BUILT_IN_CONFORMANCE_FIXTURES_VERSION);
    assert!(report.passed);
    for profile in [
        ConformanceProfile::Encoding,
        ConformanceProfile::Hlc,
        ConformanceProfile::Cursor,
        ConformanceProfile::StateResolution,
        ConformanceProfile::Redaction,
        ConformanceProfile::Capability,
        ConformanceProfile::Sync,
        ConformanceProfile::Snapshot,
        ConformanceProfile::FederationSignatures,
        ConformanceProfile::Privacy,
        ConformanceProfile::Security,
    ] {
        let coverage = report.coverage.iter().find(|coverage| coverage.profile == profile).unwrap();
        assert!(coverage.cases_total > 0);
        assert_eq!(coverage.cases_total, coverage.cases_passed);
    }

    let encoded = serde_json::to_value(report).unwrap();
    assert!(encoded["fixture_version"].is_string());
    assert!(encoded["results"].is_array());
}

#[test]
fn conformance_fixture_set_loads_and_reports_external_json() {
    let encoded = serde_json::to_value(ConformanceFixtureSet::builtin()).unwrap();
    let fixtures = ConformanceFixtureSet::from_json(encoded).unwrap();
    let report = fixtures.run();

    assert!(report.passed);
    assert_eq!(report.fixture_version, BUILT_IN_CONFORMANCE_FIXTURES_VERSION);

    let empty = serde_json::from_value::<ConformanceFixtureSet>(json!({
        "fixture_version": "",
        "suites": []
    }))
    .unwrap();
    assert!(empty.validate().is_err());
}

#[test]
fn signature_binding_payload_matches_canonical_vector() {
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#device-1".to_owned(),
        payload_hash: Hash::new(
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        )
        .unwrap(),
        created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        domain: None,
        audience: None,
        jws: "...".to_owned(),
    };
    let payload = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());

    assert_eq!(
        canonical::canonical_sha256(&payload).unwrap(),
        "sha256:5b8863e858c1964ca1901d27ce687b65d87dcef0d3535ed617de7b4763cfdaf8"
    );
}

#[test]
fn fact_chain_echo_validates_server_proof_binding() {
    let mut echo = FactChainEcho {
        echo_id: "echo1".to_owned(),
        subject_ref: "cx:event:01904100-0000-7000-8000-834e21b98552".to_owned(),
        server_did: Did::new("did:web:server.example").unwrap(),
        operation_hash: Hash::new(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        commit_hash: Some(
            Hash::new("sha256:2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
        ),
        previous_echo_hash: None,
        observed_at: "2026-04-26T00:00:00Z".parse().unwrap(),
        proofs: Vec::new(),
    };
    let digest = Hash::new(echo.echo_digest().unwrap()).unwrap();
    echo.proofs.push(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:server.example#key-1".to_owned(),
        payload_hash: digest,
        created_at: echo.observed_at,
        domain: None,
        audience: None,
        jws: "server.signature".to_owned(),
    });

    echo.validate_server_proofs().unwrap();

    let mut tampered = echo;
    tampered.proofs[0].payload_hash =
        Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
            .unwrap();
    assert!(tampered.validate_server_proofs().is_err());
}

#[test]
fn encrypted_payload_digest_matches_conformance_vector() {
    let digest = EncryptedPayload::mls_payload_digest(
        7,
        "application/json",
        None,
        b"ciphertext-example-001",
    )
    .unwrap();

    assert_eq!(
        digest.as_str(),
        "sha256:3bef5270548d5b2c14e46ac1c9a801376d243ca6d71b914ec1d3283268a981fa"
    );
}

#[test]
fn mls_envelopes_build_protocol_operations() {
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap();
    let hash = Hash::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap();
    let proposal = MlsProposalEnvelope {
        group_id: "group1".to_owned(),
        epoch: 1,
        proposal_type: "add".to_owned(),
        proposal: "proposal-bytes".to_owned(),
        proposal_hash: hash.clone(),
        ratchet_tree: None,
    };
    let commit = MlsCommitEnvelope {
        group_id: "group1".to_owned(),
        epoch: 2,
        commit: "commit-bytes".to_owned(),
        commit_hash: hash.clone(),
        ratchet_tree: None,
        app_state_ref: None,
    };
    let welcome = MlsWelcomeEnvelope {
        group_id: "group1".to_owned(),
        epoch: 2,
        recipient_principal_id: Did::new("did:web:bob.example").unwrap(),
        recipient_device_id: DeviceId::new("dev_bob").unwrap(),
        welcome: "welcome-bytes".to_owned(),
        welcome_hash: hash,
        ratchet_tree: None,
    };

    let proposal_op = proposal
        .operation(
            OperationId::new("cx:operation:01904100-0000-7000-8000-b88de80d815c").unwrap(),
            space_id.clone(),
        )
        .unwrap();
    let commit_op = commit
        .operation(
            OperationId::new("cx:operation:01904100-0000-7000-8000-3bfead8e02bc").unwrap(),
            space_id.clone(),
        )
        .unwrap();
    let welcome_op = welcome
        .operation(
            OperationId::new("cx:operation:01904100-0000-7000-8000-059e659fdcc8").unwrap(),
            space_id,
        )
        .unwrap();

    assert_eq!(proposal_op.object_type, "mls_proposal");
    assert_eq!(commit_op.object_type, "mls_commit");
    assert_eq!(welcome_op.object_type, "mls_welcome");
    assert_eq!(proposal_op.payload["proposal_type"], "add");
    assert_eq!(commit_op.payload["epoch"], 2);
    assert_eq!(welcome_op.payload["recipient_device_id"], "dev_bob");
}

#[test]
fn hlc_sorts_by_structured_parts() {
    let mut hlcs = [
        "01970e589d21-00000004-bbbbbbbb",
        "01970e589d20-00000009-ffffffff",
        "01970e589d21-00000003-ffffffff",
        "01970e589d21-00000004-a13f9c2e",
    ]
    .map(|value| Hlc::new(value).unwrap());
    hlcs.sort();
    let actual = hlcs.map(|value| value.to_string());
    assert_eq!(
        actual,
        [
            "01970e589d20-00000009-ffffffff",
            "01970e589d21-00000003-ffffffff",
            "01970e589d21-00000004-a13f9c2e",
            "01970e589d21-00000004-bbbbbbbb",
        ]
    );
}

#[test]
fn relation_requires_exact_wire_endpoints() {
    let relation = Relation {
        schema: RELATION_SCHEMA.to_owned(),
        id: RelationId::new("cx:relation:01904100-0000-7000-8000-7b3bf7d6e46b").unwrap(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        relation_kind: RelationKind::Mentions,
        from_ref: "cx:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned(),
        to_ref: "did:web:alice.example".to_owned(),
        rank: None,
        fields: BTreeMap::new(),
        state: None,
        state_changed_at: None,
        created_by: Did::new("did:web:alice.example").unwrap(),
        created_at: Utc::now(),
    };
    relation.validate_endpoints().unwrap();
}

#[test]
fn query_request_uses_protocol_filters_array() {
    let request = QueryRequest {
        space_ids: vec![SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
        object_types: vec!["morph".to_owned()],
        morph_types: vec!["task".to_owned()],
        facets: vec![Facet::Stateful, Facet::Rankable],
        anchor_ref: None,
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
    assert!(value.get("space_ids").unwrap().is_array());
    assert!(value.get("filters").unwrap().is_array());
    assert_eq!(value["facets"], json!(["stateful", "rankable"]));
    assert_eq!(value["renderer"], "board");
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
    assert_eq!(serde_json::to_value(configs).unwrap()["renderable"]["renderers"][0], "card");
}

#[test]
fn view_supports_renderer_and_facet_config_facades() {
    let request = QueryRequest {
        space_ids: vec![SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
        object_types: Vec::new(),
        morph_types: Vec::new(),
        facets: vec![Facet::Stateful, Facet::Rankable],
        anchor_ref: None,
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
        id: ViewId::new("cx:view:01904100-0000-7000-8000-848727f328fe").unwrap(),
        space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        kind: ViewKind::Collection,
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
    assert_eq!(value["collection"]["item_facets"], json!(["stateful", "rankable"]));
}

#[test]
fn operation_serializes_protocol_field_names() {
    let mut operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-d408d6a2241c").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "morph",
        json!({"id":"cx:morph:01904100-0000-7000-8000-c12dc98b2948"}),
    );
    operation.object_id = Some("cx:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned());

    let value = serde_json::to_value(operation).unwrap();

    assert_eq!(value["type"], "operation");
    assert_eq!(value["operation_type"], "create");
    assert_eq!(value["object_id"], "cx:morph:01904100-0000-7000-8000-c12dc98b2948");
    assert_eq!(value["object_type"], "morph");
    assert!(value.get("target_object_id").is_none());
    assert_eq!(value["schema"], OPERATION_SCHEMA);
}

#[test]
fn sync_response_uses_native_spaces_only() {
    let response = SyncResponse {
        next_batch: "cx:sync:abc".to_owned(),
        spaces: BTreeMap::from([(
            SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
            SyncSpace {
                timeline: Some(SyncTimeline {
                    events: Vec::new(),
                    limited: false,
                    prev_batch: None,
                }),
                state: Vec::new(),
                summary: Value::Null,
                ephemeral: Vec::new(),
                unread: Value::Null,
            },
        )]),
        to_device: Vec::new(),
        device_lists: Value::Null,
        account_data: Vec::new(),
        presence: Vec::new(),
        partial: false,
    };

    let value = serde_json::to_value(response).unwrap();

    assert!(value.get("spaces").unwrap().is_object());
}

fn valid_proof() -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        payload_hash: Hash::new(
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
        assert!(proof.validate_production().is_err(), "should reject kind: {kind}");
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
    for alg in &["EdDSA", "ES256", "ES256K", "RS256", "PS256"] {
        let mut proof = valid_proof();
        proof.alg = alg.to_string();
        assert!(proof.validate_production().is_ok(), "should accept algorithm: {alg}");
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
fn proof_validate_binding_rejects_mismatched_payload_hash() {
    let proof = valid_proof();
    let mut expected = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());
    expected.payload_hash =
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
        "cx.message.create",
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let digest = event.event_digest().unwrap();
    let proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        payload_hash: Hash::new(digest).unwrap(),
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
        "cx.message.create",
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();

    let bad_proof = Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        payload_hash: Hash::new(
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
        "cx.message.create",
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        1,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
        json!({ "body": "hello" }),
    )
    .unwrap();
    let base_digest = event.event_digest().unwrap();

    event.schema_profile_refs.push("cx.schema.core_event.v1".to_owned());
    event.reducer_profile_ref = Some("cx.reducer.core_event.v1".to_owned());
    event.required_features.push("cx.feature.event_extensions.v1".to_owned());
    event.critical_extensions.push(CriticalExtension {
        id: "cx.feature.policy_gate.v1".to_owned(),
        scope: "authz".to_owned(),
        schema_ref: Some("cx.schema.policy.v1".to_owned()),
        fail_closed: true,
    });

    assert_ne!(base_digest, event.event_digest().unwrap());

    event.critical_extensions[0].fail_closed = false;
    assert!(event.validate_for_submit().is_err());
}

#[test]
fn operation_draft_explicitly_materializes_event_envelope_without_signed_operation_id() {
    let operation = OperationEnvelopeBuilder::new(
        OperationId::new("cx:operation:01904100-0000-7000-8000-9c5aa474063f").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        Did::new("did:web:alice.example").unwrap(),
        OP_MESSAGE_CREATE,
        7,
        Hlc::new("01970e589d21-00000004-a13f9c2e").unwrap(),
    )
    .with_content(json!({
        "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
        "track": "discussion",
        "content": {"kind": "cx.content.text", "body": "hello"}
    }))
    .build(&OperationKindRegistry::default())
    .unwrap();

    let event = operation.into_event_envelope(OperationEventConversion::default()).unwrap();
    assert_eq!(event.kind, OP_MESSAGE_CREATE);
    assert_eq!(event.actor_seq, 7);
    assert_eq!(
        event.content,
        json!({
            "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
            "track": "discussion",
            "content": {"kind": "cx.content.text", "body": "hello"}
        })
    );
    assert_eq!(
        event.unsigned["local_operation_idempotency_alias"],
        json!("cx:operation:01904100-0000-7000-8000-9c5aa474063f")
    );
    assert!(!event.digest_payload().unwrap().to_string().contains("local_operation_id"));
}

#[test]
fn rank_helpers_generate_between_and_rebalance_assignments() {
    let first = rank_between(None, None).unwrap();
    let second = rank_between(Some(&first), None).unwrap();
    assert!(first < second);
    assert!(rank_exhausted(Some("r:0000000000000001"), Some("r:0000000000000002")).unwrap());

    let assignments = container_rebalance_assignments(&[
        "cx:morph:01904100-0000-7000-8000-8b4aa2ca29ef".to_owned(),
        "cx:morph:01904100-0000-7000-8000-d5864c129df4".to_owned(),
        "cx:morph:01904100-0000-7000-8000-6057e4215f24".to_owned(),
    ])
    .unwrap();
    assert_eq!(assignments.len(), 3);
    assert!(assignments[0].rank < assignments[1].rank);
    assert!(assignments[1].rank < assignments[2].rank);
}

#[test]
fn flow_constructor_sets_protocol_shape() {
    let mut subject = Flow::new(
        "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
        SpaceId::new("cx:space:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "Payment refactor",
        Did::new("did:web:alice.example").unwrap(),
    );
    subject.summary = Some("Unify payment flows".to_owned());

    assert_eq!(subject.schema, FLOW_SCHEMA);
    assert!(serde_json::to_value(&subject).unwrap().get("type").is_none());
    assert!(subject.tracks.contains_key("synthesis"));
    assert_eq!(subject.state, Some(ObjectState::Active));
    subject.validate_title().unwrap();

    subject.title = " ".to_owned();
    assert!(subject.validate_title().is_err());
}

/// T21 — typed Flow::discussion shorthand for chat-style flows.
#[test]
fn flow_discussion_constructor_sets_room_shape() {
    let flow = Flow::discussion(
        "cx:flow:01904100-0000-7000-8000-58754cf88c25",
        SpaceId::new("cx:space:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board discussion",
        Did::new("did:web:alice.example").unwrap(),
    );
    assert!(flow.is_conversational());
    assert_eq!(flow.tracks.len(), 2, "synthesis + discussion expected");

    let synthesis = flow.tracks.get("synthesis").expect("synthesis track present");
    assert!(synthesis.is_primary != Some(true));

    let discussion = flow.tracks.get("discussion").expect("discussion track present");
    assert_eq!(discussion.is_primary, Some(true));
    assert_eq!(discussion.profile.as_deref(), Some("discussion"));
}

/// T21 — synthesis-only Flows are not conversational.
#[test]
fn synthesis_flow_is_not_conversational() {
    let flow = Flow::new(
        "cx:flow:01904100-0000-7000-8000-58754cf88c25",
        SpaceId::new("cx:space:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board synthesis",
        Did::new("did:web:alice.example").unwrap(),
    );
    assert!(!flow.is_conversational());
}

/// T21 — FlowTrackConfig typed constructors honour the standard
/// profile from spec §6.1; track names live in the parent map keys.
#[test]
fn flow_track_typed_constructors() {
    let synth = FlowTrackConfig::synthesis();
    assert!(synth.profile.is_none());
    assert!(synth.is_primary.is_none());
    validate_flow_track_name(FLOW_TRACK_NAME_SYNTHESIS).unwrap();

    let disc = FlowTrackConfig::discussion();
    assert_eq!(disc.profile.as_deref(), Some("discussion"));
    assert!(disc.is_primary.is_none());
    validate_flow_track_name(FLOW_TRACK_NAME_DISCUSSION).unwrap();

    let primary = FlowTrackConfig::discussion_primary();
    assert_eq!(primary.is_primary, Some(true));

    let custom = FlowTrackConfig::new().with_profile("review").primary();
    assert_eq!(custom.profile.as_deref(), Some("review"));
    assert_eq!(custom.is_primary, Some(true));
    validate_flow_track_name("review").unwrap();
}

/// C10.A 收尾 — Space anchor fields default to None (anchorer cell is
/// the source of truth) and the builders set them to expected values.
#[test]
fn space_anchor_fields_default_none_and_builders_apply() {
    use crate::anchorer::AnchorerValue;

    let mut space = Space::new(
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000001").unwrap(),
        "Anchor Test",
        Did::new("did:web:alice.example").unwrap(),
    );
    assert!(space.anchor_profile.is_none());
    assert!(space.anchorer.is_none());
    assert!(space.max_anchor_staleness_ms.is_none());
    assert!(space.cell_lattices.is_empty());
    assert!(space.co_write_policy.is_none());

    space = space
        .with_anchor_profile(AnchorProfile::Threshold)
        .with_anchorer(AnchorerValue::Threshold {
            k: 2,
            n: 3,
            members: vec![
                Did::new("did:web:a.example").unwrap(),
                Did::new("did:web:b.example").unwrap(),
                Did::new("did:web:c.example").unwrap(),
            ],
        })
        .with_max_anchor_staleness(60_000)
        .with_cell_lattice("cx.component.flow.track.v1", "or_set", Some("reject".to_owned()))
        .with_co_write_policy(CoWritePolicy::CausalOnly);

    assert_eq!(space.anchor_profile, Some(AnchorProfile::Threshold));
    assert!(matches!(space.anchorer, Some(AnchorerValue::Threshold { k: 2, n: 3, .. })));
    assert_eq!(space.max_anchor_staleness_ms, Some(60_000));
    assert_eq!(space.cell_lattices.len(), 1);
    assert_eq!(space.cell_lattices[0].cell_family, "cx.component.flow.track.v1");
    assert_eq!(space.cell_lattices[0].lattice, "or_set");
    assert_eq!(space.cell_lattices[0].bottom.as_deref(), Some("reject"));
    assert_eq!(space.co_write_policy, Some(CoWritePolicy::CausalOnly));

    // Round-trip through serde to confirm wire shape.
    let json = serde_json::to_value(&space).unwrap();
    assert_eq!(json["anchor_profile"], "threshold");
    assert_eq!(json["max_anchor_staleness_ms"], 60_000);
    assert_eq!(json["co_write_policy"], "causal_only");
    assert_eq!(json["cell_lattices"][0]["cell_family"], "cx.component.flow.track.v1");

    let restored: Space = serde_json::from_value(json).unwrap();
    assert_eq!(restored.anchor_profile, space.anchor_profile);
    assert_eq!(restored.max_anchor_staleness_ms, space.max_anchor_staleness_ms);
    assert_eq!(restored.co_write_policy, space.co_write_policy);
}

/// C10.A 收尾 — `Space::new` omits anchor fields from the wire when
/// they're `None` (skip_serializing_if), so sparse fixtures stay clean.
#[test]
fn space_anchor_fields_omitted_when_none() {
    let space = Space::new(
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000002").unwrap(),
        "No Anchor Hint",
        Did::new("did:web:alice.example").unwrap(),
    );
    let json = serde_json::to_value(&space).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("anchor_profile"));
    assert!(!obj.contains_key("anchorer"));
    assert!(!obj.contains_key("max_anchor_staleness_ms"));
    assert!(!obj.contains_key("cell_lattices"));
    assert!(!obj.contains_key("co_write_policy"));
}

/// T20 — CollectionProjectionResponse round-trips through serde with
/// the exact wire shape from `models/views.md` §6.3, including the
/// nested groups -> items -> position / discussion structure.
#[test]
fn collection_projection_response_serde_round_trip() {
    let payload = serde_json::json!({
        "kind": "collection",
        "renderer": "board",
        "view_id": "cx:view:019641be-0000-7000-8000-000000000000",
        "frontier": ["cx:event:01904100-0000-7000-8000-69b393b5179f"],
        "groups": [
            {
                "group_id": "cx:space:01c3b617-7000-7000-8000-000000000000",
                "title": "Review",
                "rank": "mV",
                "items": [
                    {
                        "object": {
                            "id": "cx:flow:01d2b330-0000-7000-8000-000000000000",
                            "type": "flow",
                            "title": "Legal review"
                        },
                        "position": {
                            "relation_id": "cx:relation:01b03200-0000-7000-8000-000000000000",
                            "rank": "mV"
                        },
                        "discussion": {
                            "enabled": true,
                            "visibility": "locked",
                            "lazy_link": true
                        }
                    }
                ]
            }
        ]
    });
    let resp: CollectionProjectionResponse =
        serde_json::from_value(payload.clone()).expect("deserialize");
    assert!(matches!(resp.kind, ViewKind::Collection));
    assert!(matches!(resp.renderer, ViewRenderer::Board));
    assert_eq!(resp.view_id.as_str(), "cx:view:019641be-0000-7000-8000-000000000000");
    assert_eq!(resp.frontier.len(), 1);
    assert_eq!(resp.groups.len(), 1);
    let group = &resp.groups[0];
    assert_eq!(group.group_id, "cx:space:01c3b617-7000-7000-8000-000000000000");
    assert_eq!(group.title, "Review");
    assert_eq!(group.rank.as_deref(), Some("mV"));
    assert_eq!(group.items.len(), 1);
    let item = &group.items[0];
    assert_eq!(
        item.object.get("id").and_then(|v| v.as_str()),
        Some("cx:flow:01d2b330-0000-7000-8000-000000000000")
    );
    let position = item.position.as_ref().expect("position");
    assert_eq!(position.relation_id, "cx:relation:01b03200-0000-7000-8000-000000000000");
    assert_eq!(position.rank, "mV");
    let discussion = item.discussion.as_ref().expect("discussion");
    assert!(discussion.enabled);
    assert_eq!(discussion.visibility, "locked");
    assert!(discussion.lazy_link);

    // Re-serialize: the resulting JSON must be structurally
    // equivalent (same set of fields with same values).
    let reserialized = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(reserialized, payload);
}

/// T20 — `hidden_count` is omitted from the wire when absent (None)
/// so policy-tight responses don't accidentally leak a 0 count.
#[test]
fn collection_projection_group_omits_hidden_count_when_none() {
    let group = CollectionProjectionGroup {
        group_id: "cx:space:01904100-0000-7000-8000-b83c6d2ca363".to_owned(),
        title: "List".to_owned(),
        rank: Some("a0".to_owned()),
        items: Vec::new(),
        hidden_count: None,
    };
    let json = serde_json::to_value(&group).unwrap();
    assert!(
        json.get("hidden_count").is_none(),
        "hidden_count must be omitted when None to avoid leaking aggregate counts"
    );
}

/// T20 — discussion.lazy_link defaults to false when omitted on the
/// wire (e.g. for fully readable rooms) so caller's branch logic
/// stays simple.
#[test]
fn collection_projection_discussion_lazy_link_defaults_false() {
    let payload = serde_json::json!({
        "enabled": true,
        "visibility": "readable"
    });
    let d: CollectionProjectionDiscussion = serde_json::from_value(payload).unwrap();
    assert!(d.enabled);
    assert_eq!(d.visibility, "readable");
    assert!(!d.lazy_link);
}
