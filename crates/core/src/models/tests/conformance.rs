use serde_json::json;

use super::super::*;
use super::test_realm_id;
use crate::canonical;

#[test]
fn protocol_schema_registry_publishes_core_json_schemas() {
    let registry = ProtocolSchemaRegistry::default();
    for schema_id in [
        CURSOR_SCHEMA,
        STRAND_SCHEMA,
        SPACE_SCHEMA,
        VIEW_SCHEMA,
        EVENT_SCHEMA,
        CAPABILITY_SCHEMA,
        ENCRYPTED_ENVELOPE_SCHEMA,
        ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
    ] {
        assert!(registry.schema(schema_id).is_some());
    }

    registry
        .validate_value(
            ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
            &json!({"kind": "delta", "cursor": "ck:cursor:s1", "realms": {}, "unknown_future_field": true}),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(ACCOUNT_SUBSCRIBE_FRAME_SCHEMA, &json!({"realms": {}}))
            .is_err()
    );
    registry
        .validate_value(
            STRAND_SCHEMA,
            &json!({
                "schema": STRAND_SCHEMA,
                "id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "realm_id": "ck:realm:01904100-0000-7000-8000-fd3637e8361f",
                "metadata": {"title": "Topic"},
                "stage": "draft",
                "tracks": {"synthesis": {}},
                "created_by": "did:web:alice.example",
                "created_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(
                ACCOUNT_SUBSCRIBE_FRAME_SCHEMA,
                &json!({"kind": 1, "realms": {}})
            )
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
    let validator = registry.generated_validator(EVENT_SCHEMA).unwrap();
    assert!(validator.fields.iter().any(|field| {
        field.name == "event_id"
            && field.required
            && field.value_type == GeneratedSchemaValueType::String
    }));

    let event = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ck:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "ck.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [],
        "unknown_future_field": true
    });
    validator.validate(&event).unwrap();

    let wrong_type = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ck:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "ck.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": {},
        "refs": [],
        "payload": {},
        "proofs": []
    });
    assert!(validator.validate(&wrong_type).is_err());

    let sensitive_extension = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ck:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "ck.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [],
        "x-policy-critical": {}
    });
    assert!(validator.validate(&sensitive_extension).is_err());
    registry.trust_extension_prefix("x-policy-critical");
    registry
        .generated_validator(EVENT_SCHEMA)
        .unwrap()
        .validate(&sensitive_extension)
        .unwrap();

    registry.register(
        "ck.schema.strict.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "ck.schema.strict.v1",
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
            "additionalProperties": false
        }),
    );
    let warnings = registry
        .generated_validator("ck.schema.strict.v1")
        .unwrap()
        .validate_with_warnings(&json!({"id": "1", "extra": true}))
        .unwrap();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("additional field") && warning.contains("extra")),
        "expected additional field warning for strict schema, got {warnings:?}"
    );
}

#[test]
fn schema_registry_fails_closed_for_unknown_security_extensions() {
    let mut registry = ProtocolSchemaRegistry::default();
    let value = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ck:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "ck.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [],
        "x-security-critical": {"unknown": true}
    });

    assert!(registry.validate_value(EVENT_SCHEMA, &value).is_err());
    registry.trust_extension_prefix("x-security-critical");
    registry.validate_value(EVENT_SCHEMA, &value).unwrap();

    let ordinary_extension = json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d408d6a2241c",
        "space_id": "ck:space:01904100-0000-7000-8000-fd3637e8361f",
        "actor_id": "did:web:alice.example",
        "kind": "ck.message.create",
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0000-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": {},
        "proofs": [],
        "x-ui-hint": {"preserved": true}
    });
    registry
        .validate_value(EVENT_SCHEMA, &ordinary_extension)
        .unwrap();
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
        assert!(
            suites
                .iter()
                .any(|suite| suite.profile == profile && !suite.cases.is_empty())
        );
    }
}

#[test]
fn builtin_conformance_report_is_machine_readable_and_covers_profiles() {
    let report = run_builtin_conformance_report();

    assert_eq!(
        report.fixture_version,
        BUILT_IN_CONFORMANCE_FIXTURES_VERSION
    );
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
        let coverage = report
            .coverage
            .iter()
            .find(|coverage| coverage.profile == profile)
            .unwrap();
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
    assert_eq!(
        report.fixture_version,
        BUILT_IN_CONFORMANCE_FIXTURES_VERSION
    );

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
        event_digest: Hash::new(
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
        "sha256:162e738349897274ed2feabf220989183c7342e65b607f61c955716478529de9"
    );
}

#[test]
fn fact_chain_echo_validates_server_proof_binding() {
    let mut echo = FactChainEcho {
        echo_id: "echo1".to_owned(),
        subject_ref: "ck:event:01904100-0000-7000-8000-834e21b98552".to_owned(),
        server_did: Did::new("did:web:server.example").unwrap(),
        operation_hash: Hash::new(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
        commit_digest: Some(
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
        event_digest: digest,
        created_at: echo.observed_at,
        domain: None,
        audience: None,
        jws: "server.signature".to_owned(),
    });

    echo.precheck_server_proofs().unwrap();

    let mut tampered = echo;
    tampered.proofs[0].event_digest =
        Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
            .unwrap();
    assert!(tampered.precheck_server_proofs().is_err());
}

#[test]
fn encrypted_content_digest_matches_conformance_vector() {
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
    let realm_id = test_realm_id();
    let hash = Hash::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap();
    let proposal = MlsProposalEnvelope {
        group_id: "group1".to_owned(),
        epoch: 1,
        proposal_type: "add".to_owned(),
        proposal: "proposal-bytes".to_owned(),
        proposal_digest: hash.clone(),
        ratchet_tree: None,
    };
    let commit = MlsCommitEnvelope {
        group_id: "group1".to_owned(),
        epoch: 2,
        commit: "commit-bytes".to_owned(),
        commit_digest: hash.clone(),
        ratchet_tree: None,
        app_state_ref: None,
    };
    let welcome = MlsWelcomeEnvelope {
        group_id: "group1".to_owned(),
        epoch: 2,
        recipient_principal_id: Did::new("did:web:bob.example").unwrap(),
        recipient_device_id: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000007")
            .unwrap(),
        welcome: "welcome-bytes".to_owned(),
        welcome_hash: hash,
        ratchet_tree: None,
    };

    let proposal_op = proposal
        .operation(
            OperationId::new("ck:operation:01904100-0000-7000-8000-b88de80d815c").unwrap(),
            realm_id.clone(),
        )
        .unwrap();
    let commit_op = commit
        .operation(
            OperationId::new("ck:operation:01904100-0000-7000-8000-3bfead8e02bc").unwrap(),
            realm_id.clone(),
        )
        .unwrap();
    let welcome_op = welcome
        .operation(
            OperationId::new("ck:operation:01904100-0000-7000-8000-059e659fdcc8").unwrap(),
            realm_id,
        )
        .unwrap();

    assert_eq!(proposal_op.object_type, "mls_proposal");
    assert_eq!(commit_op.object_type, "mls_commit");
    assert_eq!(welcome_op.object_type, "mls_welcome");
    assert_eq!(proposal_op.payload["proposal_type"], "add");
    assert_eq!(commit_op.payload["epoch"], 2);
    assert_eq!(
        welcome_op.payload["recipient_device_id"],
        "ck:device:01904100-0000-7000-8000-000000000007"
    );
}
