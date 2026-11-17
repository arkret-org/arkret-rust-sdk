use serde_json::json;

use super::*;

fn realm_id() -> RealmId {
    RealmId::from_event_id(&event_id(1))
}

fn event_id(byte: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
}

fn sidecar_id() -> SidecarId {
    SidecarId::from_event_id(&event_id(2))
}

fn strand_id() -> StrandId {
    StrandId::from_event_id(&event_id(3))
}

fn account_id() -> serde_json::Value {
    json!({
        "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "station_id": "ak:did_core:web:station.example"
    })
}

const AGENT_ID: &str = "ak:did_core:webvh:z6mkfixture:agent.example";
const EXCHANGE_ID: &str = "exchange-fixture-0000001";
const HLC: &str = "0198ff000000-0001-0a0b0c0d";

#[test]
fn encrypted_control_current_is_closed_sorted_and_context_bound() {
    use crate::exact_current_state::CanonicalEventDot;
    let entry = |byte| {
        AgentSidecarExchangeControlAssertion {
        tag_id: CanonicalEventDot::new(event_id(byte), 0).unwrap(),
        value: serde_json::from_value(json!({
            "sidecar_id": sidecar_id(),
            "source_context_ref": {"kind":"strand","strand_id":strand_id()},
            "encrypted_payload": ({
                let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../../../arkret-spec/spec/v1/artifacts/fixtures/content-history-fixture.json")).unwrap();
                let mut envelope = fixture["kat"]["envelope"].clone();
                envelope["content_type"] = json!("application/vnd.arkret.agent-sidecar-exchange-control+json");
                envelope
            })
        })).unwrap(),
    }
    };
    let mut entries = vec![entry(4), entry(5)];
    entries.sort_by(|a, b| a.tag_id.cmp(&b.tag_id));
    let current = AgentSidecarExchangeControlsValue::new(entries.clone()).unwrap();
    let encoded = serde_json::to_value(&current).unwrap();
    assert_eq!(
        serde_json::from_value::<AgentSidecarExchangeControlsValue>(encoded.clone()).unwrap(),
        current
    );
    let mut unknown = encoded;
    unknown["exchange_id"] = json!(EXCHANGE_ID);
    assert!(serde_json::from_value::<AgentSidecarExchangeControlsValue>(unknown).is_err());
    entries.reverse();
    assert!(AgentSidecarExchangeControlsValue::new(entries).is_err());
    assert!(current.clone().with_assertion(entry(4)).is_err());
    let mut wrong_dot = entry(6);
    wrong_dot.tag_id = CanonicalEventDot::new(event_id(6), 1).unwrap();
    assert!(current.clone().with_assertion(wrong_dot).is_err());
    assert!(
        current
            .validate_for_context(
                &SidecarId::from_event_id(&event_id(8)),
                &arkret_wire::SidecarContextRef::Strand {
                    strand_id: strand_id()
                }
            )
            .is_err()
    );
    let selector = arkret_wire::CurrentSelector::AgentSidecarExchangeControls {
        sidecar_id: sidecar_id(),
        source_context_ref: arkret_wire::SidecarContextRef::Strand {
            strand_id: strand_id(),
        },
    };
    assert_eq!(
        serde_json::from_value::<arkret_wire::CurrentSelector>(
            serde_json::to_value(&selector).unwrap()
        )
        .unwrap(),
        selector
    );
}

#[test]
fn exchange_control_rejects_noncanonical_sets_and_invalid_tokens() {
    let mut control: AgentSidecarExchangeControl = serde_json::from_value(control_value()).unwrap();
    control.validate_shape().unwrap();
    control
        .basis_event_ids
        .push(control.basis_event_ids[0].clone());
    assert!(control.validate_shape().is_err());
    control.basis_event_ids.pop();
    control.exchange_id = "too-short".to_owned();
    assert!(control.validate_shape().is_err());
    control.exchange_id = "opaque.exchange~=0000000001".to_owned();
    control.validate_shape().unwrap();
}

fn sidecar_value() -> serde_json::Value {
    json!({
        "id": sidecar_id(),
        "schema": "ak.schema.agent_sidecar.v1",
        "realm_id": realm_id(),
        "controller_account_id": account_id(),
        "state": "active",
        "created_at": "2026-08-01T00:00:00.000Z"
    })
}

#[test]
fn agent_sidecar_round_trips_and_is_closed() {
    let value = sidecar_value();
    let parsed: AgentSidecar = serde_json::from_value(value.clone()).expect("closed sidecar");
    parsed.validate_shape().expect("valid sidecar");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("encryption_profile".to_owned(), json!("x"));
    assert!(serde_json::from_value::<AgentSidecar>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("realm_id");
    assert!(serde_json::from_value::<AgentSidecar>(missing).is_err());
}

#[test]
fn suspended_sidecar_requires_state_changed_at() {
    let mut value = sidecar_value();
    value["state"] = json!("suspended");
    let parsed: AgentSidecar = serde_json::from_value(value.clone()).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    value["state_changed_at"] = json!("2026-08-02T00:00:00.000Z");
    let parsed: AgentSidecar = serde_json::from_value(value).expect("shape parses");
    parsed.validate_shape().expect("suspended sidecar is valid");
}

#[test]
fn view_state_round_trips_and_is_closed() {
    let value = json!({
        "schema": "ak.schema.agent_sidecar_view_state.v1",
        "controller_account_id": account_id(),
        "sidecar_id": sidecar_id(),
        "context_ref": {"realm_id": realm_id(), "strand_id": strand_id()},
        "updated_hlc": HLC,
        "origin_device_id": "ak:device:0198ff00-0000-7000-8000-00000000000a"
    });
    let parsed: AgentSidecarViewState =
        serde_json::from_value(value.clone()).expect("closed view state");
    parsed.validate_shape().expect("valid view state");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("sidecar_control_frontier".to_owned(), json!([]));
    assert!(serde_json::from_value::<AgentSidecarViewState>(unknown).is_err());

    for mode in ["context_merged", "sidecar_only"] {
        let mut obsolete = value.clone();
        obsolete["display_mode"] = json!(mode);
        assert!(serde_json::from_value::<AgentSidecarViewState>(obsolete).is_err());
    }

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("updated_hlc");
    assert!(serde_json::from_value::<AgentSidecarViewState>(missing).is_err());
}

fn control_value() -> serde_json::Value {
    json!({
        "schema": "ak.schema.agent_sidecar_exchange_control.v1",
        "exchange_id": EXCHANGE_ID,
        "request_event_id": event_id(4),
        "basis_event_ids": [event_id(4), event_id(5)],
        "action": "close",
        "response_event_ids": [event_id(5)]
    })
}

#[test]
fn exchange_control_round_trips_and_is_closed() {
    let value = control_value();
    let parsed: AgentSidecarExchangeControl =
        serde_json::from_value(value.clone()).expect("closed control");
    parsed.validate_shape().expect("valid control");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("control_proposal".to_owned(), json!({}));
    assert!(serde_json::from_value::<AgentSidecarExchangeControl>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("action");
    assert!(serde_json::from_value::<AgentSidecarExchangeControl>(missing).is_err());
}

#[test]
fn terminal_and_reassign_controls_carry_disjoint_members() {
    let mut fail = control_value();
    fail["action"] = json!("fail");
    let parsed: AgentSidecarExchangeControl =
        serde_json::from_value(fail.clone()).expect("shape parses");
    assert!(parsed.validate_shape().is_err());
    fail["failure_reason_code"] = json!("agent_unavailable");
    let parsed: AgentSidecarExchangeControl = serde_json::from_value(fail).expect("shape parses");
    parsed.validate_shape().expect("fail control is valid");

    let mut reassign = control_value();
    reassign["action"] = json!("reassign_coordinator");
    let parsed: AgentSidecarExchangeControl =
        serde_json::from_value(reassign.clone()).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    reassign
        .as_object_mut()
        .unwrap()
        .remove("response_event_ids");
    reassign["expected_coordinator_agent_id"] = json!(AGENT_ID);
    reassign["coordinator_agent_id"] = json!(AGENT_ID);
    let parsed: AgentSidecarExchangeControl =
        serde_json::from_value(reassign).expect("shape parses");
    parsed.validate_shape().expect("reassign control is valid");
}

fn projection_value() -> serde_json::Value {
    json!({
        "schema": "ak.schema.agent_sidecar_exchange_projection.v1",
        "controller_account_id": account_id(),
        "sidecar_id": sidecar_id(),
        "exchange_id": EXCHANGE_ID,
        "source_track_ref": {
            "realm_id": realm_id(),
            "strand_id": strand_id(),
            "track_name": "main"
        },
        "source_hlc": HLC,
        "client_order_key": "order-1",
        "addressed_agent_ids": [AGENT_ID],
        "coordinator_agent_id": AGENT_ID,
        "coordinator_assignment_event_id": event_id(4),
        "participating_agent_ids": [AGENT_ID],
        "private_request_event_id": event_id(4),
        "user_facing_response_event_ids": [],
        "status": "delivered",
        "folded_checkpoint": {
            "event_ids": [event_id(4)],
            "event_set_digest": format!("sha256:{}", "ab".repeat(32)),
            "max_hlc": HLC
        }
    })
}

#[test]
fn exchange_projection_round_trips_and_is_closed() {
    let value = projection_value();
    let parsed: AgentSidecarExchangeProjection =
        serde_json::from_value(value.clone()).expect("closed projection");
    parsed.validate_shape().expect("valid projection");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("cas_revision".to_owned(), json!(2));
    assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("folded_checkpoint");
    assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(missing).is_err());
}

#[test]
fn failed_projection_carries_no_responses() {
    let mut value = projection_value();
    value["status"] = json!("failed");
    value["user_facing_response_event_ids"] = json!([event_id(5)]);
    value["failure_reason_code"] = json!("agent_unavailable");
    value["terminal_event_id"] = json!(event_id(6));
    let parsed: AgentSidecarExchangeProjection =
        serde_json::from_value(value.clone()).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    value["user_facing_response_event_ids"] = json!([]);
    let parsed: AgentSidecarExchangeProjection =
        serde_json::from_value(value).expect("shape parses");
    parsed.validate_shape().expect("failed projection is valid");
}

#[test]
fn request_binding_carries_only_its_request_context() {
    let value = json!({
        "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
        "exchange_id": EXCHANGE_ID,
        "role": "request",
        "request_context": {
            "source_track_ref": {
                "realm_id": realm_id(),
                "strand_id": strand_id(),
                "track_name": "main"
            },
            "source_hlc": HLC,
            "client_order_key": "order-1",
            "addressed_agent_ids": [AGENT_ID]
        }
    });
    let parsed: AgentSidecarEventExchangeBinding =
        serde_json::from_value(value.clone()).expect("closed binding");
    parsed.validate_shape().expect("valid request binding");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut with_event = value.clone();
    with_event["request_event_id"] = json!(event_id(4));
    let parsed: AgentSidecarEventExchangeBinding =
        serde_json::from_value(with_event).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("message_id".to_owned(), json!("x"));
    assert!(serde_json::from_value::<AgentSidecarEventExchangeBinding>(unknown).is_err());

    let mut missing = value;
    missing.as_object_mut().unwrap().remove("role");
    assert!(serde_json::from_value::<AgentSidecarEventExchangeBinding>(missing).is_err());
}

#[test]
fn completion_request_needs_its_coordinator_assignment() {
    let mut value = json!({
        "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
        "exchange_id": EXCHANGE_ID,
        "role": "user_facing_response",
        "request_event_id": event_id(4),
        "completes_exchange": true
    });
    let parsed: AgentSidecarEventExchangeBinding =
        serde_json::from_value(value.clone()).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    value["coordinator_assignment_event_id"] = json!(event_id(7));
    let parsed: AgentSidecarEventExchangeBinding =
        serde_json::from_value(value).expect("shape parses");
    parsed
        .validate_shape()
        .expect("completion binding is valid");
}

#[test]
fn mls_context_group_members_travel_together() {
    let value = json!({
        "participant_authority_digest": format!("sha256:{}", "cd".repeat(32)),
        "current_controller_device_ready": false
    });
    let parsed: AgentSidecarMlsContext =
        serde_json::from_value(value.clone()).expect("closed context");
    parsed.validate_shape().expect("pre-activation context");
    assert!(!parsed.is_mls_activated());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let mut partial = value.clone();
    partial["mls_group_id"] = json!("c2lkZWNhcg");
    let parsed: AgentSidecarMlsContext = serde_json::from_value(partial).expect("shape parses");
    assert!(parsed.validate_shape().is_err());

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("encryption_floor".to_owned(), json!("x"));
    assert!(serde_json::from_value::<AgentSidecarMlsContext>(unknown).is_err());

    let mut missing = value;
    missing
        .as_object_mut()
        .unwrap()
        .remove("current_controller_device_ready");
    assert!(serde_json::from_value::<AgentSidecarMlsContext>(missing).is_err());
}

#[test]
fn mls_context_rejects_removed_authority_stream_head() {
    let value = json!({
        "participant_authority_digest": format!("sha256:{}", "cd".repeat(32)),
        "authority_stream_head": [event_id(8)],
        "current_controller_device_ready": false
    });
    assert!(serde_json::from_value::<AgentSidecarMlsContext>(value).is_err());
}

fn participant_authority_kat_input() -> (
    SidecarId,
    RealmId,
    AccountId,
    Vec<SidecarParticipantAuthorityAgent>,
) {
    // Spec mls-governance-binding-closure-fixture.json, participant_authority.
    (
        SidecarId::new("ak:sidecar:AZUfzdx1qBOtCsg2CGmS3QLP7vlDe_kxRx0pxdxefWTa").unwrap(),
        RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap(),
        AccountId::new(
            DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            DidCoreId::new("ak:did_core:web:home.example").unwrap(),
        ),
        vec![
            SidecarParticipantAuthorityAgent {
                agent_id: DidCoreId::new("ak:did_core:web:agent-a.example").unwrap(),
                join_event_ref: EventId::new(
                    "ak:event:AcA5nPdCjRkbXZrp598jleLQtgLSLPlYPpGRxC_nKb8u",
                )
                .unwrap(),
            },
            SidecarParticipantAuthorityAgent {
                agent_id: DidCoreId::new("ak:did_core:web:agent-b.example").unwrap(),
                join_event_ref: EventId::new(
                    "ak:event:ASpYVGomLqFT-MXHEunAeQkyIB8o_R3J7CrK2SQvjdCM",
                )
                .unwrap(),
            },
        ],
    )
}

#[test]
fn participant_authority_digest_sorts_pairs_and_matches_kats() {
    let (sidecar, realm, controller, mut desired) = participant_authority_kat_input();
    let digest =
        sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired).unwrap();
    assert_eq!(
        digest.as_str(),
        "sha256:ea697849900138e4f6a5d3f3120240b392adb40ba88141d13b6a4b58b9ab1e7a"
    );
    desired.reverse();
    assert_eq!(
        digest,
        sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired).unwrap()
    );

    desired[1].join_event_ref =
        EventId::new("ak:event:AeSe0qZ6GDtRfsc-kB5XpuSPQWgxc_AR9o7iu3mtfFt_").unwrap();
    assert_eq!(
        sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired)
            .unwrap()
            .as_str(),
        "sha256:694ecb3b9f73cf0198c54f2fdd13246b1686959ace590c7196abc968b8d48052"
    );
    assert_eq!(
        sidecar_participant_authority_digest(&sidecar, &realm, &controller, &[])
            .unwrap()
            .as_str(),
        "sha256:ff623d87b3a84a24cda2e7ea7cc6e7145df489c9cafb29c265458aa42efb8553"
    );
}

#[test]
fn participant_authority_digest_rejects_repeated_agent_ids() {
    let (sidecar, realm, controller, mut desired) = participant_authority_kat_input();
    desired.push(desired[0].clone());
    assert!(sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired).is_err());
    desired[2].join_event_ref = event_id(9);
    assert!(sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired).is_err());
}

#[test]
fn participant_authority_digest_has_no_decoder_collection_limit() {
    let (sidecar, realm, controller, _) = participant_authority_kat_input();
    let desired = (0..65_u8)
        .map(|index| SidecarParticipantAuthorityAgent {
            agent_id: DidCoreId::new(format!("ak:did_core:web:agent-{index}.example")).unwrap(),
            join_event_ref: event_id(index),
        })
        .collect::<Vec<_>>();
    assert!(sidecar_participant_authority_digest(&sidecar, &realm, &controller, &desired).is_ok());
}

#[test]
fn pending_reconciliation_item_round_trips_and_is_closed() {
    let value = json!({"agent_id": AGENT_ID, "provisioning_phase": "mls_welcome"});
    let parsed: PendingSidecarAccessReconciliation =
        serde_json::from_value(value.clone()).expect("closed item");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    assert!(
        serde_json::from_value::<PendingSidecarAccessReconciliation>(
            json!({"agent_id": AGENT_ID, "provisioning_phase": "mls_welcome", "reason": "x"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<PendingSidecarAccessReconciliation>(json!({"agent_id": AGENT_ID}))
            .is_err()
    );
}
