use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::{DidCoreId, EventKind, test_support};

#[test]
fn schema_definition_subject_is_closed_and_bound_to_a_schema_id() {
    let value = json!({"kind":"schema_definition","schema_id":"ak.schema.custom_example.v1"});
    let selector: CurrentSelector = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(selector).unwrap(), value);
    for value in [
        json!({"kind":"schema_definition","schema_id":"ak.schema.custom_example.v1","extra":true}),
        json!({"kind":"schema_definition","schema_id":"ak.schema..v1"}),
        json!({"kind":"schema_definition","schema_id":"custom"}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(value).is_err());
    }
}

fn approval_shape_fixture() -> ApprovalSignature {
    let id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [31; 32]);
    serde_json::from_value(json!({
        "input": {
            "approval_context":{"context_kind":"realm_governance"},
            "approval_target":{"target_kind":"event","event_id":id},
            "request_canonical_digest":format!("sha256:{}", "11".repeat(32)),
            "operation":"ak.self.events.command.submit.v1",
            "action":"ak.strand.move",
            "realm_id":RealmId::from_event_id(&id),
            "initiating_actor_id":ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap()
            )),
            "approver_did":"did:web:approver.example",
            "approved_at":"2026-09-30T00:00:00.000Z",
            "nonce":"ABCDEFGHIJKLMNOPQRSTUV"
        },
        "proof":{"kind":"detached_jws","verification_method":"did:web:approver.example#key","jws":"AA..AA"}
    })).unwrap()
}

#[test]
fn approval_submission_carrier_accepts_omission_or_array_but_rejects_null() {
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [31; 32],
    ));
    // Codec shape only; actual signature admission is tested by consumers.
    let event = circle_item(realm, 1).event;
    let mut value = serde_json::to_value(EventAdmissionSubmission::new(event)).unwrap();
    let omitted: EventAdmissionSubmission = serde_json::from_value(value.clone()).unwrap();
    assert!(omitted.approval_signatures.is_none());
    let approval = approval_shape_fixture();
    value["approval_signatures"] = json!([approval]);
    let present: EventAdmissionSubmission = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(present.approval_signatures, Some(vec![approval]));
    for invalid in [Value::Null, json!({}), json!("omitted")] {
        value["approval_signatures"] = invalid.clone();
        assert!(
            serde_json::from_value::<EventAdmissionSubmission>(value.clone()).is_err(),
            "invalid registered approval carrier: {invalid}"
        );
    }
}

#[test]
fn approval_shape_validates_nonce_character_boundaries_and_registered_primitives() {
    let mut approval = approval_shape_fixture();
    approval.validate().unwrap();
    for count in [22, 256] {
        approval.input.nonce = "票".repeat(count);
        approval.validate().unwrap();
    }
    for count in [0, 21, 257] {
        approval.input.nonce = "票".repeat(count);
        assert!(approval.validate().is_err(), "nonce characters={count}");
    }
    let mut approval = approval_shape_fixture();
    approval.input.request_canonical_digest =
        Hash::new(format!("blake3:{}", "11".repeat(32))).unwrap();
    assert!(approval.validate().is_err());
    let mut approval = approval_shape_fixture();
    approval.input.operation = "ak.unregistered.command.submit.v1".into();
    assert!(approval.validate().is_err());
    let mut approval = approval_shape_fixture();
    approval.input.approval_target = ApprovalTarget::Operation;
    approval.validate().unwrap();
    approval.input.operation = "ak.self.account.read.describe.v1".into();
    assert!(crate::ServiceOperationId::from_wire(&approval.input.operation).is_some());
    assert!(approval.validate().is_err());
    for jws in ["", "AA.AA.AA", "AA..", "..AA", "AA..AA.AA", "AA=..AA"] {
        let mut approval = approval_shape_fixture();
        approval.proof.jws = jws.into();
        assert!(approval.validate().is_err(), "{jws}");
    }
    let mut approval = approval_shape_fixture();
    approval.input.approval_context = ApprovalContext::ListWip {
        list_space_id: SpaceId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [32; 32],
        )),
        list_policy_revision: CurrentRevision {
            commit_id: RealmCommitId::from_digest([33; 32]),
            stream_position: 9_007_199_254_740_992,
        },
    };
    assert!(approval.validate().is_err());
}

#[test]
fn approval_operation_shape_accepts_creation_carriers_without_opening_other_operations() {
    use crate::ManagementOperation;

    for (operation, management_operation, action) in [
        (
            crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            ManagementOperation::CreateBot,
            CapabilityActionId::AppletBotProvision,
        ),
        (
            crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            ManagementOperation::MapGhost,
            CapabilityActionId::AppletGhostProvision,
        ),
    ] {
        let mut approval = approval_shape_fixture();
        approval.input.approval_target = ApprovalTarget::Operation;
        approval.input.operation = operation.into();
        approval.input.action = action;
        approval.input.approval_context = ApprovalContext::Management {
            request_id: "original-creation-review".into(),
            management_operation,
            effective_scope: ScopeRef::Realm {
                realm_id: approval.input.realm_id.clone(),
            },
        };
        approval.validate().unwrap();
        for unregistered_carrier in [
            crate::ServiceOperationId::SELF_MANAGEMENT_REVIEW_COMMAND_DECIDE_V1,
            crate::ServiceOperationId::SELF_APPLET_BOT_COMMAND_PREVIEW_V1,
            crate::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
        ] {
            approval.input.operation = unregistered_carrier.into();
            assert!(approval.validate().is_err(), "{unregistered_carrier}");
        }
    }
}

#[test]
fn approval_shape_closed_carriers_reject_missing_extra_and_invalid_ids() {
    let value = serde_json::to_value(approval_shape_fixture()).unwrap();
    for field in ["input", "proof"] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ApprovalSignature>(invalid).is_err(),
            "missing {field}"
        );
    }
    for field in ["kind", "verification_method", "jws"] {
        let mut invalid = value.clone();
        invalid["proof"].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ApprovalSignature>(invalid).is_err(),
            "missing proof.{field}"
        );
    }
    for field in [
        "approval_context",
        "approval_target",
        "request_canonical_digest",
        "operation",
        "action",
        "realm_id",
        "initiating_actor_id",
        "approver_did",
        "approved_at",
        "nonce",
    ] {
        let mut invalid = value.clone();
        invalid["input"].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ApprovalSignature>(invalid).is_err(),
            "missing {field}"
        );
    }
    for parent in ["input", "proof"] {
        let mut invalid = value.clone();
        invalid[parent]["unregistered"] = json!(true);
        assert!(
            serde_json::from_value::<ApprovalSignature>(invalid).is_err(),
            "extra {parent}"
        );
    }
    let mut invalid = value.clone();
    invalid["unregistered"] = json!(true);
    assert!(serde_json::from_value::<ApprovalSignature>(invalid).is_err());
    for (field, bad) in [
        ("realm_id", "not-a-realm"),
        ("action", "ak.unregistered.action"),
        ("request_canonical_digest", "sha256:00"),
        ("approved_at", "2026-09-30T00:00:00Z"),
    ] {
        let mut invalid = value.clone();
        invalid["input"][field] = json!(bad);
        assert!(
            serde_json::from_value::<ApprovalSignature>(invalid).is_err(),
            "invalid {field}"
        );
    }
}

#[test]
fn actor_private_submit_outcome_is_closed_per_event_kind() {
    let event_id = "ak:event:AXrw54_r8iPVFSBGJhTZduzx5vRg62wu8bdDrUhCm9hR";
    let push: ActorPrivateEventSubmitOutcome = serde_json::from_value(json!({
        "event_kind": "ak.device.push_route",
        "accepted_event_id": event_id,
        "revision": 3
    }))
    .unwrap();
    assert_eq!(push.event_kind(), EventKind::DevicePushRoute);
    assert_eq!(
        serde_json::to_value(&push).unwrap(),
        json!({
            "event_kind": "ak.device.push_route",
            "accepted_event_id": event_id,
            "revision": 3
        })
    );
    let draft: ActorPrivateEventSubmitOutcome = serde_json::from_value(json!({
        "event_kind": "ak.agent.draft.propose",
        "accepted_event_id": event_id
    }))
    .unwrap();
    assert_eq!(draft.event_kind(), EventKind::AgentDraftPropose);
    for rejected in [
        json!({"event_kind": "ak.device.push_route", "accepted_event_id": event_id}),
        json!({"event_kind": "ak.agent.action_request", "accepted_event_id": event_id, "revision": 1}),
        json!({"event_kind": "ak.read_cursor.advance", "accepted_event_id": event_id}),
        json!({"event_kind": "ak.account.blocklist", "accepted_event_id": event_id}),
    ] {
        assert!(
            serde_json::from_value::<ActorPrivateEventSubmitOutcome>(rejected.clone()).is_err(),
            "{rejected}"
        );
    }
}

#[test]
fn ordinary_realm_bootstrap_current_selectors_match_closed_result_shapes() {
    for (selector, kind) in [
        (CurrentSelector::RealmGenesis, "realm_genesis"),
        (CurrentSelector::RealmAuthorityRoot, "realm_authority_root"),
        (CurrentSelector::RealmProfile, "realm_profile"),
        (CurrentSelector::RealmPolicyBundle, "realm_policy_bundle"),
        (CurrentSelector::RealmJoinRule, "realm_join_rule"),
        (CurrentSelector::RealmHistoryAccess, "realm_history_access"),
        (CurrentSelector::RealmPreviewPolicy, "realm_preview_policy"),
        (CurrentSelector::RealmTombstone, "realm_tombstone"),
        (CurrentSelector::RealmArchive, "realm_archive"),
        (CurrentSelector::RealmFreeze, "realm_freeze"),
        (CurrentSelector::RealmDiscovery, "realm_discovery"),
        (CurrentSelector::RealmAlias, "realm_alias"),
        (
            CurrentSelector::RealmPlaintextVisibleServices,
            "realm_plaintext_visible_services",
        ),
    ] {
        let wire = json!({"kind": kind});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        assert!(
            serde_json::from_value::<CurrentSelector>(json!({"kind": kind, "unexpected": true}),)
                .is_err()
        );
    }
}

#[test]
fn realm_set_default_strand_selector_is_exact_singleton() {
    let selector = CurrentSelector::RealmSetDefaultStrand;
    let wire = json!({"kind":"realm_set_default_strand"});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    assert!(
        serde_json::from_value::<CurrentSelector>(
            json!({"kind":"realm_set_default_strand","strand_id":"ak:strand:forged"})
        )
        .is_err()
    );
}

#[test]
fn message_revision_selector_is_exact_derived_identity() {
    let event_id = EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"message revision selector"),
    );
    let message_id = MessageId::from_event_id(&event_id);
    let selector = CurrentSelector::MessageRevision {
        message_id: message_id.clone(),
    };
    let wire = json!({"kind":"message_revision","message_id":message_id});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    assert!(
        serde_json::from_value::<CurrentSelector>(
            json!({"kind":"message_revision","message_id":message_id,"strand_id":"forged"})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<CurrentSelector>(json!({"kind":"message_revision"})).is_err());
}

#[test]
fn moderation_report_selector_is_the_report_event_identity() {
    let event_id = EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"moderation report selector"),
    );
    let selector = CurrentSelector::ModerationReport {
        event_id: event_id.clone(),
    };
    let wire = json!({"kind":"moderation_report","event_id":event_id});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    for invalid in [
        json!({"kind":"moderation_report"}),
        json!({"kind":"moderation_report","event_id":event_id,"report_id":"forged"}),
        json!({"kind":"moderation_report","event_id":MessageId::from_event_id(&event_id)}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn franking_selector_is_the_encrypted_target_event_identity() {
    let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32]);
    let selector = CurrentSelector::ModerationFrankingProof {
        event_id: event_id.clone(),
    };
    let wire = json!({"kind":"moderation_franking_proof","event_id":event_id});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    for invalid in [
        json!({"kind":"moderation_franking_proof"}),
        json!({"kind":"moderation_franking_proof","event_id":event_id,"proof_event_id":event_id}),
        json!({"kind":"moderation_franking_proof","event_id":MessageId::from_event_id(&event_id)}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn organization_selector_binds_the_existing_relationship_cell() {
    let organization = DidCoreId::new("ak:did_core:web:organization.example").unwrap();
    for relationship in [
        RealmOrganizationRelationship::Owner,
        RealmOrganizationRelationship::Governance,
        RealmOrganizationRelationship::Sponsor,
        RealmOrganizationRelationship::DirectoryCertifier,
    ] {
        let selector = CurrentSelector::RealmOrganization {
            organization_id: organization.clone(),
            relationship,
        };
        let wire = serde_json::to_value(&selector).unwrap();
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    for invalid in [
        json!({"kind":"realm_organization","organization_id":organization}),
        json!({"kind":"realm_organization","organization_id":organization,"relationship":"moderation_policy"}),
        json!({"kind":"realm_organization","organization_id":organization,"relationship":"owner","realm_id":"forged"}),
        json!({"kind":"realm_organization","organization_id":"did:web:organization.example","relationship":"owner"}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn moderation_state_selector_is_the_moderated_target() {
    let event_id = EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"moderation state selector"),
    );
    let selector = CurrentSelector::ModerationState {
        target_ref: event_id.to_string(),
    };
    let wire = json!({"kind":"moderation_state","target_ref":event_id});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    for invalid in [
        json!({"kind":"moderation_state"}),
        json!({"kind":"moderation_state","target_ref":event_id,"event_id":event_id}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn object_redaction_selector_is_the_verbatim_redaction_target() {
    let event_id = EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"object redaction selector"),
    );
    let message_id = MessageId::from_event_id(&event_id);
    for target_ref in [message_id.to_string(), event_id.to_string()] {
        let selector = CurrentSelector::ObjectRedaction {
            target_ref: target_ref.clone(),
        };
        let wire = json!({"kind":"object_redaction","target_ref":target_ref});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    for invalid in [
        json!({"kind":"object_redaction"}),
        json!({"kind":"object_redaction","message_id":message_id}),
        json!({"kind":"object_redaction","target_ref":message_id,"realm_id":"ak:realm:x"}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn policy_current_selectors_round_trip_exact_closed_branches() {
    let policy_id = PolicyId::new("ak:policy:01904100-0000-7000-8000-000000000001").unwrap();
    let cases = [
        (
            CurrentSelector::Policy {
                policy_id: policy_id.clone(),
            },
            json!({"kind":"policy","policy_id":policy_id}),
        ),
        (
            CurrentSelector::PolicyAction {
                subject: PolicyActionSelector::PolicyRef {
                    policy_id: policy_id.clone(),
                    action: PolicyActionName::new("ak.message.send").unwrap(),
                },
            },
            json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy_id,"action":"ak.message.send"}),
        ),
        (
            CurrentSelector::PolicyAction {
                subject: PolicyActionSelector::RealmAction {
                    action_id: RealmPolicyActionId::new("local_approval").unwrap(),
                },
            },
            json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval"}),
        ),
    ];
    for (selector, wire) in cases {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
}

#[test]
fn policy_current_selectors_reject_missing_mixed_and_unknown_fields() {
    let policy = "ak:policy:01904100-0000-7000-8000-000000000001";
    for invalid in [
        json!({"kind":"policy"}),
        json!({"kind":"policy","policy_id":policy,"action":"ak.message.send"}),
        json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy}),
        json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.message.send","action_id":"local_approval"}),
        json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval","policy_id":policy}),
        json!({"kind":"policy_action","branch":"realm_action","action_id":"local_approval","action":"ak.message.send"}),
        json!({"kind":"policy_action","branch":"realm_action","action_id":"ak:policy:typed"}),
        json!({"kind":"policy_action","branch":"realm_action","action_id":""}),
        json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.Message.Send"}),
        json!({"kind":"policy_action","branch":"policy_ref","policy_id":policy,"action":"ak.message..send"}),
        json!({"kind":"policy_action","branch":"other","action_id":"local_approval"}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn device_current_selectors_round_trip_exact_closed_shapes() {
    let device_id = DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000001").unwrap();
    for (selector, wire) in [
        (
            CurrentSelector::DeviceAuthorization {
                device_id: device_id.clone(),
            },
            json!({"kind":"device_authorization","device_id":device_id}),
        ),
        (
            CurrentSelector::DeviceGeneration,
            json!({"kind":"device_generation"}),
        ),
        (
            CurrentSelector::DeviceRevocationProposals {
                device_id: device_id.clone(),
            },
            json!({"kind":"device_revocation_proposals","device_id":device_id}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
}

#[test]
fn device_current_selectors_reject_missing_mirrored_and_unknown_fields() {
    let device = "ak:device:019a0000-0000-7000-8000-000000000001";
    for invalid in [
        json!({"kind":"device_authorization"}),
        json!({"kind":"device_authorization","device_id":device,"account_id":"extra"}),
        json!({"kind":"device_authorization","device_id":"not-a-device"}),
        json!({"kind":"device_generation","device_id":device}),
        json!({"kind":"device_generation","device_generation_status":"active"}),
        json!({"kind":"device_revocation_proposals"}),
        json!({"kind":"device_revocation_proposals","device_id":device,"principal_id":"extra"}),
        json!({"kind":"device_revocation_proposals","device_id":null}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn capability_grant_selector_round_trips_and_rejects_foreign_subjects() {
    let grant_id = GrantId::new("ak:grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let selector = CurrentSelector::CapabilityGrant {
        grant_id: grant_id.clone(),
    };
    let wire = json!({"kind":"capability_grant","grant_id":grant_id});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
    for invalid in [
        json!({"kind":"capability_grant"}),
        json!({"kind":"capability_grant","grant_id":"ak:capability:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        json!({"kind":"capability_grant","grant_id":grant_id,"realm_id":realm}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn strand_position_selector_validates_both_typed_components() {
    let board = SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let strand = StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let selector = CurrentSelector::StrandPosition {
        board_space_id: board.clone(),
        strand_id: strand.clone(),
    };
    let wire = json!({"kind":"strand_position","board_space_id":board,"strand_id":strand});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    for invalid in [
        json!({"kind":"strand_position","strand_id":strand}),
        json!({"kind":"strand_position","board_space_id":board}),
        json!({"kind":"strand_position","board_space_id":strand,"strand_id":strand}),
        json!({"kind":"strand_position","board_space_id":board,"strand_id":board}),
        json!({"kind":"strand_position","board_space_id":"AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7","strand_id":strand}),
        json!({"kind":"strand_position","board_space_id":board,"strand_id":strand,"subject":"hash"}),
        json!({"kind":"strand_position","subject":"AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn rsvp_current_selector_round_trips_the_closed_subject() {
    let event_ref =
        StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let responder_actor_id = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    for occurrence in [None, Some("2026-09-28".to_owned())] {
        let selector = CurrentSelector::Rsvp {
            event_ref: event_ref.clone(),
            occurrence: occurrence.clone(),
            responder_actor_id: responder_actor_id.clone(),
        };
        let wire = json!({
            "kind": "rsvp",
            "event_ref": event_ref,
            "occurrence": occurrence,
            "responder_actor_id": responder_actor_id,
        });
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    for invalid in [
        json!({"kind":"rsvp","event_ref":event_ref,"responder_actor_id":responder_actor_id}),
        json!({"kind":"rsvp","event_ref":event_ref,"occurrence":null}),
        json!({"kind":"rsvp","event_ref":event_ref,"occurrence":null,"responder_actor_id":responder_actor_id,"extra":true}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn registered_space_current_selectors_round_trip_closed_shapes() {
    let space_id = SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    for (selector, kind) in [
        (
            CurrentSelector::Space {
                space_id: space_id.clone(),
            },
            "space",
        ),
        (
            CurrentSelector::SpaceParent {
                space_id: space_id.clone(),
            },
            "space_parent",
        ),
        (
            CurrentSelector::SpaceChildScopePolicy {
                space_id: space_id.clone(),
            },
            "space_child_scope_policy",
        ),
    ] {
        let wire = json!({"kind":kind,"space_id":space_id});
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
        for invalid in [
            json!({"kind":kind}),
            json!({"kind":kind,"space_id":space_id,"realm_id":"ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
            json!({"kind":kind,"space_id":"ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        ] {
            assert!(
                serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }
}

#[test]
fn invite_current_selectors_round_trip_and_reject_foreign_subjects() {
    let invite_id =
        InviteId::new("ak:invite:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let invitee = AccountId::new(
        DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    for (selector, wire) in [
        (
            CurrentSelector::InviteLifecycle {
                invite_id: invite_id.clone(),
            },
            json!({"kind":"invite_lifecycle","invite_id":invite_id}),
        ),
        (
            CurrentSelector::InviteLiveTarget {
                invitee_account_id: invitee.clone(),
            },
            json!({"kind":"invite_live_target","invitee_account_id":invitee}),
        ),
        (
            CurrentSelector::InviteDirectedInvitee {
                invite_id: invite_id.clone(),
            },
            json!({"kind":"invite_directed_invitee","invite_id":invite_id}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
    for invalid in [
        json!({"kind":"invite_lifecycle"}),
        json!({"kind":"invite_lifecycle","invite_id":"ak:event:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        json!({"kind":"invite_live_target","invitee_account_id":invitee,"realm_id":realm}),
        json!({"kind":"invite_live_target","invitee_account_id":"ak:did_core:web:bob.example"}),
        json!({"kind":"invite_directed_invitee","invite_id":invite_id,"invitee_account_id":invitee}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn profile_and_accountability_selectors_round_trip_closed_shapes() {
    let profile_id =
        ActorProfileId::new("ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-")
            .unwrap();
    let issuer = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let subject = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
    let scope = AccountabilityScopeSet::normalize([
        crate::AccountabilityScopeKind::Employment,
        crate::AccountabilityScopeKind::AgentOperator,
    ])
    .unwrap();
    for (selector, wire) in [
        (
            CurrentSelector::ActorProfile {
                actor_profile_id: profile_id.clone(),
            },
            json!({"kind":"actor_profile","actor_profile_id":profile_id}),
        ),
        (
            CurrentSelector::IdentityAccountability {
                issuer_id: issuer.clone(),
                subject_id: subject.clone(),
                accountability_scope: scope,
            },
            json!({
                "kind":"identity_accountability",
                "issuer_id":issuer,
                "subject_id":subject,
                "accountability_scope":["agent_operator","employment"]
            }),
        ),
    ] {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    let realm = "ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7";
    for invalid in [
        json!({"kind":"actor_profile"}),
        json!({"kind":"actor_profile","actor_profile_id":profile_id,"realm_id":realm}),
        json!({"kind":"actor_profile","actor_profile_id":"ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-"}),
        json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":"employment"}),
        json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":["employment","agent_operator"]}),
        json!({"kind":"identity_accountability","issuer_id":issuer,"subject_id":subject,"accountability_scope":["employment"],"realm_id":realm}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn agent_current_selectors_round_trip_closed_shapes() {
    let agent_id = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
    let agent_key_id = AgentKeyId::new("runtime_key-1").unwrap();
    for (selector, wire) in [
        (
            CurrentSelector::AgentKey {
                agent_id: agent_id.clone(),
                agent_key_id: agent_key_id.clone(),
            },
            json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":agent_key_id}),
        ),
        (
            CurrentSelector::AgentStatus {
                agent_id: agent_id.clone(),
            },
            json!({"kind":"agent_status","agent_id":agent_id}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    for invalid in [
        json!({"kind":"agent_key","agent_id":agent_id}),
        json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":""}),
        json!({"kind":"agent_key","agent_id":agent_id,"agent_key_id":"runtime_key-1","account_id":"extra"}),
        json!({"kind":"agent_status"}),
        json!({"kind":"agent_status","agent_id":agent_id,"agent_key_id":"runtime_key-1"}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn parent_membership_revision_requires_exact_realm_actor_and_join() {
    let parent = realm(41);
    let member = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let revision = CurrentRevision {
        commit_id: RealmCommitId::from_digest([42; 32]),
        stream_position: 7,
    };
    let row = TypedCurrentRow::Value {
        selector: CurrentSelector::MemberState {
            actor_id: member.clone(),
        },
        source_stream_ref: CommitStreamRef::Realm {
            realm_id: parent.clone(),
        },
        revision: revision.clone(),
        value: json!({"membership":"join"}),
    };
    assert_eq!(
        row.parent_membership_revision(&parent, &member),
        Some(revision)
    );
    let other_station = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    ));
    assert!(
        row.parent_membership_revision(&parent, &other_station)
            .is_none()
    );
    assert!(
        row.parent_membership_revision(&realm(43), &member)
            .is_none()
    );
    for state in ["leave", "ban", "knock"] {
        let mut excluded = row.clone();
        let TypedCurrentRow::Value { value, .. } = &mut excluded;
        *value = json!({"membership":state});
        assert!(
            excluded
                .parent_membership_revision(&parent, &member)
                .is_none()
        );
    }
    let mut foreign_stream = row;
    let TypedCurrentRow::Value {
        source_stream_ref, ..
    } = &mut foreign_stream;
    *source_stream_ref = CommitStreamRef::Circle {
        realm_id: parent.clone(),
        circle_id: CircleId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [44; 32],
        )),
    };
    assert!(
        foreign_stream
            .parent_membership_revision(&parent, &member)
            .is_none()
    );
}

#[test]
fn circle_currents_reject_foreign_subjects_and_noncanonical_effective_time() {
    let circle_id = CircleId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [42; 32],
    ));
    let member_actor_id = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    for (selector, wire) in [
        (
            CurrentSelector::Circle {
                circle_id: circle_id.clone(),
            },
            json!({"kind":"circle","circle_id":circle_id}),
        ),
        (
            CurrentSelector::CircleMemberState {
                circle_id: circle_id.clone(),
                member_actor_id: member_actor_id.clone(),
            },
            json!({"kind":"circle_member_state","circle_id":circle_id,"member_actor_id":member_actor_id}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<CurrentSelector>(wire).unwrap(),
            selector
        );
    }
    for invalid in [
        json!({"kind":"circle"}),
        json!({"kind":"circle","circle_id":member_actor_id}),
        json!({"kind":"circle","circle_id":circle_id,"member_actor_id":member_actor_id}),
        json!({"kind":"circle_member_state","circle_id":circle_id}),
        json!({"kind":"circle_member_state","circle_id":circle_id,"member_actor_id":member_actor_id,"realm_id":"extra"}),
    ] {
        assert!(
            serde_json::from_value::<CurrentSelector>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
    let parent = json!({
        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
        "stream_position": 7
    });
    let current = json!({
        "membership": "join",
        "parent_membership_revision": parent,
        "effective_at": "2026-09-27T12:00:00.000Z"
    });
    let parsed = serde_json::from_value::<CircleMemberStateCurrent>(current.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), current);
    let leave = json!({"membership":"leave","effective_at":"2026-09-27T12:00:00.000Z"});
    let parsed_leave = serde_json::from_value::<CircleMemberStateCurrent>(leave.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed_leave).unwrap(), leave);
    let realm_id = realm(41);
    let parent_revision: CurrentRevision = serde_json::from_value(parent.clone()).unwrap();
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    assert!(parsed.is_effective_under_parent(
        &realm_id,
        &realm_stream,
        &parent_revision,
        MembershipState::Join
    ));
    for membership in [MembershipState::Leave, MembershipState::Ban] {
        assert!(!parsed.is_effective_under_parent(
            &realm_id,
            &realm_stream,
            &parent_revision,
            membership
        ));
    }
    let rejoined = CurrentRevision {
        commit_id: RealmCommitId::from_digest([15; 32]),
        stream_position: 15,
    };
    assert!(!parsed.is_effective_under_parent(
        &realm_id,
        &realm_stream,
        &rejoined,
        MembershipState::Join
    ));
    let circle_stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id,
    };
    assert!(!parsed.is_effective_under_parent(
        &realm_id,
        &circle_stream,
        &parent_revision,
        MembershipState::Join
    ));
    for invalid in [
        json!({"membership":"join"}),
        json!({"membership":"join","effective_at":"2026-09-27T12:00:00.000Z"}),
        json!({"membership":"join","parent_membership_revision":null,"effective_at":"2026-09-27T12:00:00.000Z"}),
        json!({"membership":"join","parent_membership_revision":{"commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"},"effective_at":"2026-09-27T12:00:00.000Z"}),
        json!({"membership":"leave","parent_membership_revision":parent,"effective_at":"2026-09-27T12:00:00.000Z"}),
        json!({"membership":"join","parent_membership_revision":parent,"effective_at":"2026-09-27T12:00:00Z"}),
        json!({"membership":"join","parent_membership_revision":parent,"effective_at":"2026-09-27T12:00:00.000Z","revision":1}),
    ] {
        assert!(
            serde_json::from_value::<CircleMemberStateCurrent>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn sidecar_current_selectors_preserve_exact_native_context_and_reject_extra_fields() {
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [46; 32]);
    let sidecar = SidecarId::from_event_id(&event);
    let strand = StrandId::from_event_id(&event);
    let relation = RelationId::from_event_id(&event);
    for value in [
        json!({"kind":"sidecar","sidecar_id":sidecar}),
        json!({"kind":"sidecar_context","sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":strand}}),
        json!({"kind":"sidecar_context","sidecar_id":sidecar,"source_context_ref":{"kind":"relation","relation_id":relation}}),
    ] {
        let selector: CurrentSelector = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(selector).unwrap(), value);
    }
    for value in [
        json!({"kind":"sidecar","sidecar_id":sidecar,"controller_account_id":"extra"}),
        json!({"kind":"sidecar_context","sidecar_id":sidecar}),
        json!({"kind":"sidecar_context","sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":relation}}),
        json!({"kind":"sidecar_context","sidecar_id":sidecar,"source_context_ref":{"kind":"strand","strand_id":strand,"relation_id":relation}}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(value).is_err());
    }
}

#[test]
fn call_current_selector_requires_the_create_derived_call_identity() {
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [43; 32]);
    let call_id = CallId::from_event_id(&event);
    let value = json!({"kind":"call_state","call_id":call_id});
    let selector: CurrentSelector = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        selector,
        CurrentSelector::CallState {
            call_id: call_id.clone()
        }
    );
    assert_eq!(serde_json::to_value(selector).unwrap(), value);
    for invalid in [
        json!({"kind":"call_state"}),
        json!({"kind":"call_state","call_id":event}),
        json!({"kind":"call_state","call_id":call_id,"realm_id":"extra"}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn applet_registration_selector_has_one_closed_applet_service_pair() {
    let applet_id = AppletId::new("ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d").unwrap();
    let service_id = DidCoreId::new("ak:did_core:web:applet-a.example").unwrap();
    let wire = json!({"kind":"applet_registration","applet_id":applet_id,"service_id":service_id});
    let selector: CurrentSelector = serde_json::from_value(wire.clone()).unwrap();
    assert!(matches!(
        &selector,
        CurrentSelector::AppletRegistration { applet_id: actual_applet, service_id: actual_service }
            if actual_applet == &applet_id && actual_service == &service_id
    ));
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    let mut other_wire = wire.clone();
    other_wire["service_id"] = json!("ak:did_core:web:applet-b.example");
    let other: CurrentSelector = serde_json::from_value(other_wire.clone()).unwrap();
    assert_ne!(selector, other);
    assert_eq!(serde_json::to_value(&other).unwrap(), other_wire);
    for invalid in [
        json!({"kind":"applet_registration"}),
        json!({"kind":"applet_registration","applet_id":applet_id}),
        json!({"kind":"applet_registration","service_id":service_id}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
    for key in ["realm_id", "actor_id", "subject", "registration_epoch"] {
        let mut invalid = wire.clone();
        invalid[key] = json!("extra");
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
    for invalid_service in [
        Value::Null,
        json!("did:web:applet-a.example"),
        json!("ak:device:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d"),
        json!({"kind":"service","service_id":service_id}),
        json!({"kind":"account","principal_id":service_id,"station_id":service_id}),
    ] {
        let mut invalid = wire.clone();
        invalid["service_id"] = invalid_service;
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn direct_conversation_binding_selector_has_only_pair_key() {
    let pair_key = Hash::new(format!("sha256:{}", "42".repeat(32))).unwrap();
    let selector = CurrentSelector::DirectConversationBinding {
        pair_key: pair_key.clone(),
    };
    let wire = json!({"kind":"direct_conversation_binding","pair_key":pair_key});
    assert_eq!(serde_json::to_value(&selector).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<CurrentSelector>(wire).unwrap(),
        selector
    );
    for invalid in [
        json!({"kind":"direct_conversation_binding"}),
        json!({"kind":"direct_conversation_binding","pair_key":pair_key,"realm_id":"extra"}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
}

#[test]
fn relation_current_carrier_reuses_the_exact_primary_domain_and_closed_value() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../../arkret-spec/spec/v1/artifacts/fixtures/exact-current-results-read-fixture.json",
    );
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let entry = fixture["valid_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "authorized_relation_present_snapshot_carrier")
        .unwrap()["value"]["entry"]
        .clone();
    let row: TypedCurrentRow = serde_json::from_value(entry.clone()).unwrap();
    assert_eq!(serde_json::to_value(&row).unwrap(), entry);
    let TypedCurrentRow::Value {
        selector: CurrentSelector::Relation {
            primary_conflict_domain,
        },
        value,
        ..
    } = row
    else {
        panic!("expected the registered Relation carrier")
    };
    let relation: crate::relation::Relation = serde_json::from_value(value.clone()).unwrap();
    relation
        .validate_current_for_domain(&relation.realm_id, &primary_conflict_domain)
        .unwrap();
    for invalid in [
        json!({"kind":"relation"}),
        json!({"kind":"relation","primary_conflict_domain":primary_conflict_domain,"relation_id":relation.id}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    }
    let mut invalid = entry["selector"].clone();
    invalid["primary_conflict_domain"]["scope_circle_id"] = Value::Null;
    assert!(serde_json::from_value::<CurrentSelector>(invalid).is_err());
    let mut invalid = value;
    invalid["extra"] = Value::Null;
    assert!(serde_json::from_value::<crate::relation::Relation>(invalid).is_err());
    let mut changed = relation.clone();
    changed.to_ref = crate::relation::RelationEndpoint::Actor(ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    )));
    assert!(
        changed
            .validate_current_for_domain(&relation.realm_id, &primary_conflict_domain)
            .is_err()
    );
    changed = relation.clone();
    changed.state = Some(crate::RelationState::Tombstoned);
    assert!(
        changed
            .validate_current_for_domain(&relation.realm_id, &primary_conflict_domain)
            .is_err()
    );
}

#[cfg(feature = "openapi")]
#[test]
fn current_selector_openapi_shape_uses_flat_branch_fields() {
    let mut components = salvo_oapi::Components::new();
    let schema = <CurrentSelector as salvo_oapi::ToSchema>::to_schema(&mut components);
    let rendered = serde_json::to_value(&schema).unwrap();
    assert_eq!(
        rendered["$ref"],
        "#/components/schemas/arkret_wire.authority_commit.CurrentSelector"
    );
    let components = serde_json::to_value(components).unwrap();
    let selector = &components["schemas"]["arkret_wire.authority_commit.CurrentSelector"];
    let branches = selector["oneOf"].as_array().unwrap();
    let action = branches
        .iter()
        .find(|branch| branch["allOf"][2]["properties"]["kind"]["enum"][0] == "policy_action")
        .expect("policy_action selector branch");
    assert!(action.to_string().contains("PolicyActionSelector"));
    assert!(!action.to_string().contains("subject"));
    let action_branches =
        &components["schemas"]["arkret_wire.authority_commit.PolicyActionSelector"]["oneOf"];
    assert_eq!(
        action_branches[0]["properties"]["branch"]["enum"][0],
        "policy_ref"
    );
    assert_eq!(
        action_branches[1]["properties"]["branch"]["enum"][0],
        "realm_action"
    );
    for (kind, fields) in [
        ("device_authorization", 2),
        ("device_generation", 1),
        ("device_revocation_proposals", 2),
        ("invite_lifecycle", 2),
        ("invite_live_target", 2),
        ("invite_directed_invitee", 2),
        ("capability_grant", 2),
    ] {
        let branch = branches
            .iter()
            .find(|branch| branch["properties"]["kind"]["enum"][0] == kind)
            .unwrap_or_else(|| panic!("{kind} selector branch"));
        assert_eq!(branch["required"].as_array().unwrap().len(), fields);
        assert!(branch["properties"].get("account_id").is_none());
        assert!(branch["properties"].get("device_status").is_none());
    }
}

fn realm(seed: u8) -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ))
}

fn signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        sig: Base64UrlString::new("AQ").unwrap(),
    }
}

fn circle_item(realm_id: RealmId, stream_position: u64) -> CommittedEventFullView {
    let circle_id = CircleId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x22; 32],
    ));
    let stream_ref = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id,
    };
    let event = test_support::raw_event_at(
        EventKind::MessageCreate.as_str(),
        match &stream_ref {
            CommitStreamRef::Circle {
                realm_id,
                circle_id,
            } => ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            _ => unreachable!(),
        },
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        json!({}),
        Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
    )
    .unwrap();
    CommittedEventFullView {
        commit: RealmCommit {
            commit_id: RealmCommitId::from_digest([stream_position as u8 + 1; 32]),
            realm_id,
            stream_ref,
            stream_position,
            previous_commit_ref: (stream_position > 0)
                .then(|| RealmCommitId::from_digest([stream_position as u8; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x33; 32],
            )),
            committed_at: Utc.timestamp_opt(1_800_000_001, 0).unwrap(),
            producer_signer_fact_digest: None,
            signature: signature(DetachedSignatureContext::RealmCommit),
        },
        event,
    }
}

#[test]
fn stream_row_rejects_a_commit_bound_to_another_independent_stream() {
    let realm_id = realm(0x10);
    let mut item = circle_item(realm_id.clone(), 0);
    item.commit.stream_ref = CommitStreamRef::Realm { realm_id };
    assert!(item.validate_shape().is_err());
}

#[test]
fn scan_without_after_position_starts_at_that_streams_genesis() {
    let realm_id = realm(0x10);
    let request = StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: circle_item(realm_id.clone(), 0).commit.stream_ref,
        direction: StreamScanDirection::After(None),
        limit: 10,
    };
    let outcome = StreamScanOutcome {
        committed_events: vec![CommittedEventView::Full(circle_item(realm_id, 1))],
        readable_floor: None,
        truncated: false,
    };
    assert!(outcome.validate_for_request(&request).is_err());
}

#[test]
fn independent_stream_gap_is_distinct_from_a_fork_or_rollback() {
    let first = circle_item(realm(0x10), 0).commit;
    let mut next = first.clone();
    next.stream_position = 2;
    next.previous_commit_ref = Some(first.commit_id.clone());
    assert!(matches!(
        next.validate_successor_of(&first),
        Err(WireError::StreamPositionGap {
            expected: 1,
            actual: 2,
            ..
        })
    ));
    next.stream_position = 1;
    next.previous_commit_ref = Some(RealmCommitId::from_digest([99; 32]));
    assert!(matches!(
        next.validate_successor_of(&first),
        Err(WireError::Protocol(_))
    ));
    assert!(matches!(
        first.validate_successor_of(&next),
        Err(WireError::Protocol(_))
    ));
}

#[test]
fn every_stream_rejects_gaps_duplicate_positions_and_foreign_predecessors() {
    let collaboration = realm(0x10);
    let pcr = realm(0x11);
    let streams = [
        CommitStreamRef::Realm {
            realm_id: collaboration.clone(),
        },
        circle_item(collaboration.clone(), 0).commit.stream_ref,
        CommitStreamRef::Sidecar {
            realm_id: collaboration,
            sidecar_id: SidecarId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x12; 32],
            )),
        },
        CommitStreamRef::Realm { realm_id: pcr },
    ];
    for stream in &streams {
        let mut first = circle_item(stream.realm_id().clone(), 0).commit;
        first.stream_ref = stream.clone();
        first.validate_shape().unwrap();
        let mut next = first.clone();
        next.stream_position = 1;
        next.commit_id = RealmCommitId::from_digest([0x22; 32]);
        next.previous_commit_ref = Some(first.commit_id.clone());
        next.validate_successor_of(&first).unwrap();
        let restored: RealmCommit =
            serde_json::from_slice(&serde_json::to_vec(&first).unwrap()).unwrap();
        next.validate_successor_of(&restored).unwrap();
        for other in &streams {
            if other != stream {
                let mut foreign = first.clone();
                foreign.realm_id = other.realm_id().clone();
                foreign.stream_ref = other.clone();
                assert!(next.validate_successor_of(&foreign).is_err());
            }
        }
        for position in [0, 2] {
            let mut wrong = next.clone();
            wrong.stream_position = position;
            assert!(wrong.validate_successor_of(&first).is_err());
        }
        let mut wrong = next;
        wrong.previous_commit_ref = Some(RealmCommitId::from_digest([0x23; 32]));
        assert!(wrong.validate_successor_of(&first).is_err());
    }
}

#[test]
fn scan_request_has_exactly_one_present_direction_even_when_null() {
    let realm_id = realm(0x10);
    let stream_ref = circle_item(realm_id.clone(), 0).commit.stream_ref;
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction,
            limit: 3,
        };
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(
            wire.get("after_position").is_some(),
            matches!(direction, StreamScanDirection::After(_))
        );
        assert_eq!(
            wire.get("before_position").is_some(),
            matches!(direction, StreamScanDirection::Before(_))
        );
        assert_eq!(
            serde_json::from_value::<StreamScanRequest>(wire).unwrap(),
            request
        );
    }
    let base = serde_json::to_value(StreamScanRequest {
        realm_id,
        stream_ref,
        direction: StreamScanDirection::After(None),
        limit: 3,
    })
    .unwrap();
    let mut both = base.clone();
    both["before_position"] = Value::Null;
    assert!(serde_json::from_value::<StreamScanRequest>(both).is_err());
    let mut neither = base.clone();
    neither.as_object_mut().unwrap().remove("after_position");
    assert!(serde_json::from_value::<StreamScanRequest>(neither).is_err());
    let mut unknown = base.clone();
    unknown["direction"] = serde_json::json!("after");
    assert!(serde_json::from_value::<StreamScanRequest>(unknown).is_err());
    let mut negative = base;
    negative["after_position"] = serde_json::json!(-1);
    assert!(serde_json::from_value::<StreamScanRequest>(negative).is_err());
}

#[test]
fn before_scan_requires_descending_chain_and_verifiable_floor() {
    let realm_id = realm(0x10);
    let rows =
        [6, 5, 4].map(|position| CommittedEventView::Full(circle_item(realm_id.clone(), position)));
    let request = StreamScanRequest {
        realm_id,
        stream_ref: rows[0].commit().stream_ref.clone(),
        direction: StreamScanDirection::Before(None),
        limit: 3,
    };
    let floor = ReadableFloor {
        oldest_position: 4,
        floor_commit_id: rows[2].commit().commit_id.clone(),
        floor_reason: ReadableFloorReason::MembershipJoin,
    };
    let outcome = StreamScanOutcome {
        committed_events: rows.to_vec(),
        readable_floor: Some(floor.clone()),
        truncated: false,
    };
    outcome.validate_for_request(&request).unwrap();
    let mut missing_floor = outcome.clone();
    missing_floor.readable_floor = None;
    assert!(missing_floor.validate_for_request(&request).is_err());
    let mut bad_anchor = outcome.clone();
    bad_anchor.readable_floor.as_mut().unwrap().floor_commit_id =
        rows[0].commit().commit_id.clone();
    assert!(bad_anchor.validate_for_request(&request).is_err());
    let mut false_truncation = outcome.clone();
    false_truncation.truncated = true;
    assert!(false_truncation.validate_for_request(&request).is_err());
    let mut ascending = outcome;
    ascending.committed_events.reverse();
    assert!(ascending.validate_for_request(&request).is_err());
    let forward = StreamScanRequest {
        direction: StreamScanDirection::After(None),
        ..request
    };
    let forward_page = StreamScanOutcome {
        committed_events: rows.into_iter().rev().collect(),
        readable_floor: Some(floor),
        truncated: true,
    };
    forward_page.validate_for_request(&forward).unwrap();
    let skipped = StreamScanRequest {
        direction: StreamScanDirection::After(Some(4)),
        ..forward
    };
    assert!(forward_page.validate_for_request(&skipped).is_err());
}

#[test]
fn committed_event_view_has_only_full_and_withheld_wire_branches() {
    let full = circle_item(realm(0x10), 0);
    let full_value = serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap();
    assert!(full_value.get("event").is_some());
    assert!(full_value.get("event_disclosure").is_none());

    let withheld = CommittedEventView::Withheld(CommittedEventWithheldView {
        commit: full.commit,
        event_disclosure: EventDisclosure {
            status: EventDisclosureStatus::Withheld,
        },
    });
    let withheld_value = serde_json::to_value(withheld).unwrap();
    assert_eq!(withheld_value["event_disclosure"]["status"], "withheld");
    assert!(withheld_value.get("event").is_none());

    let mut mixed = full_value;
    mixed["event_disclosure"] = json!({"status": "withheld"});
    assert!(serde_json::from_value::<CommittedEventView>(mixed).is_err());
    assert!(
        serde_json::from_value::<CommittedEventView>(json!({
            "commit": withheld_value["commit"].clone(),
            "redacted": true
        }))
        .is_err()
    );
}

/// The domain label and the serialized wire string are the same fact. If
/// they ever diverge, a signature made over the label would not cover the
/// context the object actually carries.
#[test]
fn every_signature_context_label_is_its_own_wire_string() {
    for context in DetachedSignatureContext::ALL {
        let encoded = serde_json::to_value(context).unwrap();
        assert_eq!(encoded.as_str().unwrap(), context.as_wire_str());
        let decoded: DetachedSignatureContext =
            serde_json::from_value(serde_json::json!(context.as_wire_str())).unwrap();
        assert_eq!(decoded, context);
    }
}

#[test]
fn approval_time_uses_the_generated_future_only_boundary() {
    let verification_time = Utc.timestamp_millis_opt(1_800_000_000_000).unwrap();
    let tolerance = arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
        arkret_identifiers::ProtocolTimeToleranceScenario::ApprovalApprovedAt,
    )
    .tolerance_ms();
    let boundary = verification_time + TimeDelta::milliseconds(tolerance);

    validate_approval_timestamp(boundary, verification_time).unwrap();
    validate_approval_timestamp(boundary - TimeDelta::milliseconds(1), verification_time).unwrap();
    assert!(
        validate_approval_timestamp(boundary + TimeDelta::milliseconds(1), verification_time)
            .is_err()
    );

    // This scenario is future-only: it must not accidentally inherit the
    // symmetric expiry lower bound used by temporal constraints.
    validate_approval_timestamp(verification_time - TimeDelta::days(365), verification_time)
        .unwrap();
}

#[test]
fn realm_stream_list_enforces_order_floor_and_continuation() {
    let realm_id: RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
        .parse()
        .unwrap();
    let head: RealmCommitId = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
        .parse()
        .unwrap();
    let realm_row = RealmStreamRow {
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        head_commit_ref: head.clone(),
        next_position: 3,
        readable_floor: Some(ReadableFloor {
            oldest_position: 0,
            floor_commit_id: head.clone(),
            floor_reason: ReadableFloorReason::StreamStart,
        }),
    };
    let page = RealmStreamList {
        realm_id: realm_id.clone(),
        streams: vec![realm_row.clone()],
        next_cursor: None,
        has_more: false,
    };
    page.validate().unwrap();
    let wire = serde_json::to_value(&page).unwrap();
    assert!(wire.get("next_cursor").is_none());
    assert_eq!(
        serde_json::from_value::<RealmStreamList>(wire.clone()).unwrap(),
        page
    );
    let mut unknown = wire;
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<RealmStreamList>(unknown).is_err());

    let mut dangling = page.clone();
    dangling.has_more = true;
    assert!(dangling.validate().is_err());
    dangling.next_cursor = Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA".to_owned());
    dangling.validate().unwrap();
    dangling.next_cursor = Some("cursor".to_owned());
    assert!(dangling.validate().is_err());

    let mut empty_chain = page.clone();
    empty_chain.streams[0].next_position = 0;
    assert!(empty_chain.validate().is_err());

    let mut floor_past_head = page.clone();
    floor_past_head.streams[0].readable_floor = Some(ReadableFloor {
        oldest_position: 3,
        floor_commit_id: head.clone(),
        floor_reason: ReadableFloorReason::MembershipJoin,
    });
    assert!(floor_past_head.validate().is_err());

    let circle_row = RealmStreamRow {
        stream_ref: CommitStreamRef::Circle {
            realm_id,
            circle_id: "ak:circle:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4"
                .parse()
                .unwrap(),
        },
        head_commit_ref: head,
        next_position: 1,
        readable_floor: None,
    };
    let mut ordered = page.clone();
    ordered.streams = vec![circle_row, realm_row.clone()];
    let first = canonical_json_bytes_for_test(&ordered.streams[0].stream_ref);
    let second = canonical_json_bytes_for_test(&ordered.streams[1].stream_ref);
    if first > second {
        ordered.streams.reverse();
    }
    ordered.validate().unwrap();
    let mut full_cut = ordered.clone();
    full_cut.streams = (0u64..501)
        .map(|index| {
            let mut token = [0u8; 33];
            token[0] = 1;
            token[1..9].copy_from_slice(&index.to_be_bytes());
            let mut row = realm_row.clone();
            row.stream_ref = CommitStreamRef::Circle {
                realm_id: full_cut.realm_id.clone(),
                circle_id: CircleId::from_event_id(&EventId::from_token_bytes(token).unwrap()),
            };
            row
        })
        .collect();
    full_cut
        .streams
        .sort_by_cached_key(|row| canonical_json_bytes_for_test(&row.stream_ref));
    RealmStreamList::validate_rows(&full_cut.realm_id, &full_cut.streams).unwrap();
    assert!(full_cut.validate().is_err());
    full_cut.streams[500] = full_cut.streams[499].clone();
    assert!(RealmStreamList::validate_rows(&full_cut.realm_id, &full_cut.streams).is_err());
    let mut reversed = ordered.clone();
    reversed.streams.reverse();
    assert!(reversed.validate().is_err());
    let mut duplicated = page.clone();
    duplicated.streams = vec![realm_row.clone(), realm_row];
    assert!(duplicated.validate().is_err());

    let mut foreign = page;
    foreign.realm_id = "ak:realm:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
        .parse()
        .unwrap();
    assert!(foreign.validate().is_err());
}

fn canonical_json_bytes_for_test(value: &CommitStreamRef) -> Vec<u8> {
    arkret_canonical::canonical::canonical_json_bytes(value).unwrap()
}

#[test]
fn list_wip_approval_context_is_closed_and_revision_bound() {
    let list = SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let revision = CurrentRevision {
        commit_id: RealmCommitId::from_digest([7; 32]),
        stream_position: 9,
    };
    let context = ApprovalContext::ListWip {
        list_space_id: list.clone(),
        list_policy_revision: revision.clone(),
    };
    let wire =
        json!({"context_kind":"list_wip","list_space_id":list,"list_policy_revision":revision});
    assert_eq!(serde_json::to_value(&context).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<ApprovalContext>(wire).unwrap(),
        context
    );
    for invalid in [
        json!({"context_kind":"list_wip","list_space_id":list}),
        json!({"context_kind":"list_wip","list_space_id":list,"list_policy_revision":revision,"grant_id":"ak:grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7"}),
        json!({"context_kind":"realm_governance","list_space_id":list,"list_policy_revision":revision}),
    ] {
        assert!(
            serde_json::from_value::<ApprovalContext>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }

    let realm = RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
    let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let event = test_support::raw_event_at(
        EventKind::StrandMove.as_str(),
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        json!({"target_space_id":list}),
        at,
    )
    .unwrap();
    let input = ApprovalSignatureInput {
        approval_context: context,
        approval_target: ApprovalTarget::Event {
            event_id: event.event_id.clone(),
        },
        request_canonical_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        operation: "ak.self.events.command.submit.v1".to_owned(),
        action: CapabilityActionId::StrandMove,
        realm_id: realm,
        initiating_actor_id: event.actor_id.clone(),
        approver_did: Did::new("did:web:manager.example".to_owned()).unwrap(),
        approved_at: at,
        nonce: "ABCDEFGHIJKLMNOPQRSTUV".to_owned(),
    };
    assert!(
        input
            .validate_list_wip_binding(&event, "ak.self.events.command.submit.v1", &list, &revision)
            .is_ok()
    );
    assert!(
        input
            .validate_list_wip_binding(
                &event,
                "ak.self.events.command.submit.v1",
                &list,
                &CurrentRevision {
                    stream_position: 10,
                    ..revision
                }
            )
            .is_err()
    );
}

#[test]
fn read_receipt_policy_selector_requires_an_exact_realm_or_circle_scope() {
    let realm = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
    let circle = "ak:circle:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI";
    for scope in [
        json!({"kind":"realm","realm_id":realm}),
        json!({"kind":"circle","realm_id":realm,"circle_id":circle}),
    ] {
        let wire = json!({"kind":"scope_read_receipt_policy","scope_ref":scope});
        let selector: CurrentSelector = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(selector).unwrap(), wire);
    }
    for wire in [
        json!({"kind":"realm_read_receipt_policy"}),
        json!({"kind":"scope_read_receipt_policy"}),
        json!({"kind":"scope_read_receipt_policy","scope_ref":{"kind":"realm_genesis"}}),
        json!({"kind":"scope_read_receipt_policy","scope_ref":{"kind":"circle","realm_id":realm}}),
        json!({"kind":"scope_read_receipt_policy","scope_ref":{"kind":"realm","realm_id":realm,"circle_id":circle}}),
    ] {
        assert!(serde_json::from_value::<CurrentSelector>(wire).is_err());
    }
}

#[test]
fn snapshot_history_purpose_binds_coverage_and_never_replaces_current() {
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [91; 32]);
    let realm_id = RealmId::from_event_id(&event);
    let stream_ref = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let commit_id = RealmCommitId::from_digest([92; 32]);
    let account = crate::AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let mut snapshot = RealmStateSnapshot {
        snapshot_id: RealmSnapshotId::from_digest([93; 32]),
        realm_id: realm_id.clone(),
        governance_generation: 0,
        purpose: RealmSnapshotPurpose::StreamHistory,
        history_basis: Some(RealmSnapshotHistoryBasis {
            account_id: account,
            stream_ref: stream_ref.clone(),
            anchor_position: 5,
            anchor_commit_ref: commit_id.clone(),
            accepted_dependency_refs: vec![],
        }),
        visible_stream_heads: vec![CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 5,
            commit_id,
        }],
        current_state_entries: vec![],
        retention_and_history_floor: RetentionAndHistoryFloor {
            history_access: crate::HistoryAccess::SinceJoin,
            stream_floors: vec![StreamHistoryFloor {
                stream_ref,
                oldest_position: 1,
            }],
        },
        created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        signature: signature(DetachedSignatureContext::RealmSnapshot),
    };
    snapshot.validate_purpose().unwrap();
    assert!(snapshot.require_full_recovery().is_err());
    let original = snapshot.clone();
    snapshot.history_basis.as_mut().unwrap().anchor_position += 1;
    assert!(snapshot.validate_purpose().is_err());
    snapshot = original.clone();
    snapshot.purpose = RealmSnapshotPurpose::FullRecovery;
    assert!(snapshot.validate_purpose().is_err());
    snapshot.history_basis = None;
    snapshot.require_full_recovery().unwrap();
    let mut null_basis = serde_json::to_value(snapshot).unwrap();
    null_basis["history_basis"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<RealmStateSnapshot>(null_basis).is_err());
    snapshot = original;
    snapshot.visible_stream_heads.push(CommitStreamHead {
        stream_ref: CommitStreamRef::Circle {
            realm_id,
            circle_id: crate::CircleId::from_event_id(&event),
        },
        stream_position: 0,
        commit_id: RealmCommitId::from_digest([94; 32]),
    });
    assert!(snapshot.validate_purpose().is_err());
}
