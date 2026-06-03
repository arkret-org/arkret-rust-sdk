use cokret::*;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:web:{name}.example")).unwrap()
}

#[test]
fn umbrella_crate_builds_client_signs_event_and_verifies_binding() {
    let space_id = SpaceId::new("ck:space:01904100-0000-7000-8000-000000000001").unwrap();
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let mut event = Event::new(
        OP_MESSAGE_CREATE,
        realm_id,
        did("alice"),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        json!({
            "message_id": "ck:message:01904100-0000-7000-8000-000000000001",
            "flow_id": "ck:flow:01904100-0000-7000-8000-000000000001",
            "track_name": "discussion",
            "content": {"kind": "cx.content.text", "body": "hello"}
        }),
    )
    .unwrap();
    let digest = event.event_digest().unwrap();
    event.proofs.push(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#device-1".to_owned(),
        payload_digest: Hash::new(digest).unwrap(),
        created_at: chrono::Utc::now(),
        domain: None,
        audience: None,
        jws: "AAAA.BBBB.CCCC".to_owned(),
    });
    event.validate_proof_bindings().unwrap();

    let client = BaseClient::new();
    client.process_events(&space_id, vec![event]).unwrap();
    let space = client.get_space(&space_id).unwrap();
    assert!(
        space.space_state.messages.contains_key("ck:message:01904100-0000-7000-8000-000000000001")
    );
}
