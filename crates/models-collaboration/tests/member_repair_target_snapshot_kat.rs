//! Executable consumer for the spec KAT
//! `fixtures/direct-conversation-fixture.json#member_repair_target_snapshot_kat`.
//!
//! `contact-and-direct-conversation.md` §8.2.1 puts snapshot member names into
//! the JCS preimage verbatim, so the SDK helper is the only place a producer or
//! verifier is allowed to build these transcripts. The Native Agent branch pins
//! the closed recipient endpoint triple: an opaque endpoint reference would hide
//! `verification_method` and `agent_key_authorize_event_id` inside the digest and
//! let two implementations disagree about the same endpoint.

use arkret_models_collaboration::direct_conversation_repair::{
    MEMBER_REPAIR_TARGET_SNAPSHOT_HUMAN_DOMAIN, MEMBER_REPAIR_TARGET_SNAPSHOT_NATIVE_AGENT_DOMAIN,
    MemberRepairHumanTarget, MemberRepairNativeAgentTarget,
    member_repair_human_target_snapshot_digest, member_repair_native_agent_target_snapshot_digest,
};
use arkret_schema::embedded_json_artifact;
use arkret_wire::{DeviceId, DeviceMessageId, DidCoreId, DidUrl, EventId};
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/direct-conversation-fixture.json";

fn kat() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded direct-conversation fixture")
        ["member_repair_target_snapshot_kat"]
        .clone()
}

fn text(node: &Value, key: &str) -> String {
    node[key]
        .as_str()
        .unwrap_or_else(|| panic!("KAT member {key} must be a string"))
        .to_owned()
}

#[test]
fn domain_separators_match_the_spec_fixture() {
    let kat = kat();
    assert_eq!(
        text(&kat["human_principal"], "domain_separator").as_bytes(),
        MEMBER_REPAIR_TARGET_SNAPSHOT_HUMAN_DOMAIN
    );
    assert_eq!(
        text(&kat["native_agent"], "domain_separator").as_bytes(),
        MEMBER_REPAIR_TARGET_SNAPSHOT_NATIVE_AGENT_DOMAIN
    );
}

#[test]
fn human_snapshot_digest_matches_and_is_enqueue_order_independent() {
    let kat = kat();
    let branch = &kat["human_principal"];
    let targets: Vec<MemberRepairHumanTarget> = branch["targets_as_enqueued"]
        .as_array()
        .expect("enqueued targets must be an array")
        .iter()
        .map(|row| MemberRepairHumanTarget {
            recipient_device_id: DeviceId::new(text(row, "recipient_device_id"))
                .expect("fixture device id is canonical"),
            device_message_id: DeviceMessageId::new(text(row, "device_message_id"))
                .expect("fixture device message id is canonical"),
        })
        .collect();

    let expected = text(branch, "target_snapshot_digest");
    let digest = member_repair_human_target_snapshot_digest(&targets)
        .expect("human snapshot transcript is constructible");
    assert_eq!(digest.as_str(), expected);

    let mut reversed = targets;
    reversed.reverse();
    let reversed_digest = member_repair_human_target_snapshot_digest(&reversed)
        .expect("human snapshot transcript is constructible");
    assert_eq!(
        reversed_digest.as_str(),
        expected,
        "the transcript is device-id sorted, so enqueue order cannot move it"
    );
}

#[test]
fn native_agent_snapshot_digest_matches_the_closed_endpoint_triple() {
    let kat = kat();
    let branch = &kat["native_agent"];
    let target = &branch["target"];
    let endpoint = MemberRepairNativeAgentTarget {
        recipient_agent_id: DidCoreId::new(text(target, "recipient_agent_id"))
            .expect("fixture agent id is a core DID id"),
        recipient_agent_verification_method: DidUrl::new(text(
            target,
            "recipient_agent_verification_method",
        ))
        .expect("fixture verification method is a DID URL"),
        recipient_agent_key_authorize_event_id: EventId::new(text(
            target,
            "recipient_agent_key_authorize_event_id",
        ))
        .expect("fixture authorize event id is canonical"),
        device_message_id: DeviceMessageId::new(text(target, "device_message_id"))
            .expect("fixture device message id is canonical"),
    };

    let digest = member_repair_native_agent_target_snapshot_digest(&endpoint)
        .expect("Native Agent snapshot transcript is constructible");
    assert_eq!(
        digest.as_str(),
        text(branch, "target_snapshot_digest"),
        "the Native Agent preimage is exactly the closed recipient endpoint triple plus the \
         frozen device_message_id"
    );
}

#[test]
fn native_agent_snapshot_binds_every_authorization_coordinate() {
    let kat = kat();
    let target = &kat["native_agent"]["target"];
    let base = MemberRepairNativeAgentTarget {
        recipient_agent_id: DidCoreId::new(text(target, "recipient_agent_id")).unwrap(),
        recipient_agent_verification_method: DidUrl::new(text(
            target,
            "recipient_agent_verification_method",
        ))
        .unwrap(),
        recipient_agent_key_authorize_event_id: EventId::new(text(
            target,
            "recipient_agent_key_authorize_event_id",
        ))
        .unwrap(),
        device_message_id: DeviceMessageId::new(text(target, "device_message_id")).unwrap(),
    };
    let pinned = member_repair_native_agent_target_snapshot_digest(&base).unwrap();

    let mut swapped_key = base.clone();
    swapped_key.recipient_agent_key_authorize_event_id =
        EventId::new("ak:event:AbhX3-n_FG8scl_4zkFai8VRhqvIwjOeWHvA8D3mQ9V7".to_owned()).unwrap();
    assert_ne!(
        member_repair_native_agent_target_snapshot_digest(&swapped_key)
            .unwrap()
            .as_str(),
        pinned.as_str(),
        "substituting the authorizing Event MUST move the digest"
    );

    let mut swapped_method = base;
    swapped_method.recipient_agent_verification_method =
        DidUrl::new("did:webvh:z6mkfixture:agent.example#ed25519-2026-06-fixture".to_owned())
            .unwrap();
    assert_ne!(
        member_repair_native_agent_target_snapshot_digest(&swapped_method)
            .unwrap()
            .as_str(),
        pinned.as_str(),
        "substituting the verification method MUST move the digest"
    );
}
