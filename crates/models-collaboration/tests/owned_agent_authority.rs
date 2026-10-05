//! Owned Agent carriers are checked against the normative canonical cases.
use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
use arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody;
use arkret_models_collaboration::governance::operation_wire::{PolicyRule, PolicySetStatePayload};
use serde_json::Value;

fn owned_grant_value() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/agent-participation-fixture.json")).unwrap(),
    )
    .unwrap();
    let input = fixture["owned_agent_authority_contract"]["schema_cases"][0]["canonical_json"]
        .as_str()
        .unwrap();
    let payload: Value = serde_json::from_str(input).unwrap();
    let mut value = payload["grant"].clone();
    value["id"] = serde_json::json!(arkret_wire::GrantId::from_event_id(
        &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [31; 32])
    ));
    value["authority_depth"] = serde_json::json!(1);
    value["authority_root_refs"] = value["issuer_authority_refs"].clone();
    value["status"] = serde_json::json!("active");
    value
}

#[test]
fn original_issuer_identity_survives_terminal_status_but_not_station_or_ref_changes() {
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilityGrant, CapabilityGrantStatus,
    };
    let mut grant: CapabilityGrant = serde_json::from_value(owned_grant_value()).unwrap();
    let original = grant.issuer_id.as_account_id().unwrap().clone();
    assert_eq!(grant.owned_agent_issuer(), Some(&original));
    grant.status = CapabilityGrantStatus::Revoked;
    assert_eq!(grant.owned_agent_issuer(), Some(&original));
    grant.status = CapabilityGrantStatus::Relinquished;
    assert_eq!(grant.owned_agent_issuer(), Some(&original));
    let changed = arkret_wire::AccountId::new(
        original.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    );
    grant.issuer_id = arkret_wire::ActorId::account(changed);
    assert!(grant.owned_agent_issuer().is_none());
    grant.issuer_id = arkret_wire::ActorId::account(original);
    grant
        .issuer_authority_refs
        .push(grant.issuer_authority_refs[0].clone());
    assert!(grant.owned_agent_issuer().is_none());
}

#[test]
fn exact_owned_grant_outcome_binds_value_and_disallows_never_written() {
    use arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome;
    let grant = owned_grant_value();
    let commit = arkret_wire::RealmCommitId::from_digest([32; 32]);
    let request: ExactCurrentResultsReadRequestBody = serde_json::from_value(serde_json::json!({
        "realm_id":grant["realm_id"], "selector":{"kind":"capability_grant", "grant_id":grant["id"]}
    }))
    .unwrap();
    let value = serde_json::json!({
        "status":"present", "realm_id":grant["realm_id"], "governance_generation":0,
        "effective_stream_head":{"stream_ref":{"kind":"realm","realm_id":grant["realm_id"]}, "commit_id":commit,"stream_position":9},
        "entry":{"selector":request.selector,"source_stream_ref":{"kind":"realm","realm_id":grant["realm_id"]},"revision":{"commit_id":commit,"stream_position":9},"value":grant}
    });
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(value.clone()).unwrap();
    outcome.validate_for_request(&request, 0).unwrap();
    let mut mismatch = value.clone();
    mismatch["entry"]["value"]["id"] = serde_json::json!(arkret_wire::GrantId::from_event_id(
        &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [33; 32])
    ));
    assert!(
        serde_json::from_value::<ExactCurrentResultsReadOutcome>(mismatch)
            .unwrap()
            .validate_for_request(&request, 0)
            .is_err()
    );
    let mut absence = value;
    absence["status"] = serde_json::json!("never_written");
    absence.as_object_mut().unwrap().remove("entry");
    absence["selector"] = serde_json::to_value(&request.selector).unwrap();
    assert!(serde_json::from_value::<ExactCurrentResultsReadOutcome>(absence).is_err());
}

#[test]
fn owned_agent_canonical_carriers_match_spec() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("fixtures/agent-participation-fixture.json")).unwrap(),
    )
    .unwrap();
    let cases = fixture["owned_agent_authority_contract"]["schema_cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 19);
    for case in cases {
        let input = case["canonical_json"].as_str().unwrap();
        let accepted = match case["fragment"].as_str().unwrap() {
            "#/$defs/capability_grant_payload" => {
                serde_json::from_str::<CapabilityGrantPayload>(input)
                    .is_ok_and(|payload| payload.grant.validate_owned_agent_shape().is_ok())
            }
            "#/$defs/policy_set_state_payload" => {
                serde_json::from_str::<PolicySetStatePayload>(input)
                    .is_ok_and(|payload| payload.validate().is_ok())
            }
            "#/$defs/policy_rule" => {
                serde_json::from_str::<PolicyRule>(input).is_ok_and(|rule| rule.validate().is_ok())
            }
            "#/$defs/exact_current_results_read_request" => {
                serde_json::from_str::<ExactCurrentResultsReadRequestBody>(input)
                    .is_ok_and(|request| request.validate().is_ok())
            }
            fragment => panic!("unhandled normative fragment {fragment}"),
        };
        assert_eq!(
            accepted,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn agent_rule_cannot_hide_generic_conditions_or_cross_kind_fields() {
    let baseline = serde_json::json!({
        "rule_id":"ban", "kind":"agent", "effect":"deny",
        "agent_target":{"kind":"all"}, "agent_operations":["join"]
    });
    for field in [
        "conditions",
        "params",
        "servers",
        "schema_ref",
        "profile_ref",
    ] {
        let mut value = baseline.clone();
        value[field] = match field {
            "servers" => serde_json::json!([]),
            "schema_ref" => serde_json::json!("ak.schema.policy.v1"),
            "profile_ref" => serde_json::json!("ak.profile.test.v1"),
            _ => serde_json::json!({"x":true}),
        };
        assert!(
            !serde_json::from_value::<PolicyRule>(value).is_ok_and(|rule| rule.validate().is_ok())
        );
    }
    let mut value = baseline.clone();
    value["agent_target"]["controller_account_id"] = serde_json::json!({"principal_id":"ak:did_core:web:someone.example","station_id":"ak:did_core:web:station.example"});
    assert!(serde_json::from_value::<PolicyRule>(value).is_err());
    let mut value = baseline.clone();
    value["kind"] = serde_json::json!("temporal");
    assert!(
        serde_json::from_value::<PolicyRule>(value)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut value = baseline;
    value["agent_operations"] = serde_json::json!(["join", "join"]);
    assert!(
        serde_json::from_value::<PolicyRule>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}
