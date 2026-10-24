use arkret_identity::contact_producer_identity::{
    agent_contact_identity_did, validate_agent_contact_native_history,
};
use arkret_identity::{VerifiedDidWebvhLog, verify_did_webvh_v1_chain};
use arkret_models_collaboration::contact_operations::{ContactPeer, ContactProducerSigner};
use arkret_signatures::webvh::{
    AgentBindingUpdateInput, AgentInceptionInput, prepare_agent_binding_update,
    prepare_agent_inception,
};
use arkret_wire::{
    AccountId, ActorId, AuthorizationRef, Base64UrlString, Did, DidCoreId, DidUrl, Event, EventId,
    EventKind, Hash, RealmId, ScopeRef,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn at(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}
fn public(seed: u8) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn fixture() -> (
    Event,
    ContactPeer,
    ContactProducerSigner,
    VerifiedDidWebvhLog,
) {
    let controller = AccountId::new(
        DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let endpoint = "https://station.example/".parse().unwrap();
    let next = public(2);
    let inception = prepare_agent_inception(&AgentInceptionInput {
        principal_endpoint: &endpoint,
        local_id: "agent-contact",
        controller_principal_id: &controller.principal_id,
        version_created_at: at("2026-10-16T00:00:00Z"),
        root_seed: &[1; 32],
        next_root_public_key_multibase: &next,
    })
    .unwrap();
    let realm = RealmId::new("ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M").unwrap();
    let future = public(3);
    let binding = prepare_agent_binding_update(&AgentBindingUpdateInput {
        did: &inception.did,
        local_id: &inception.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_created_at: at("2026-10-16T00:00:01Z"),
        current_root_seed: &[2; 32],
        next_root_public_key_multibase: &future,
        controller_principal_id: &controller.principal_id,
        principal_control_realm_id: &realm,
        requested_scope_digest: &Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap(),
    })
    .unwrap();
    let did = Did::new(inception.did).unwrap();
    let history =
        verify_did_webvh_v1_chain(&did, &[inception.log_entry, binding.log_entry]).unwrap();
    let holder = ContactPeer::Agent {
        actor_id: ActorId::account(AccountId::new(
            arkret_wire::project_did_to_core_id(&did).unwrap(),
            controller.station_id.clone(),
        )),
        controller_account_id: controller,
    };
    let signer = ContactProducerSigner::direct(
        DidUrl::new(format!("{did}#runtime")).unwrap(),
        Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
        ))
        .unwrap(),
    )
    .unwrap();
    let event = Event {
        event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0;32]), kind: EventKind::ContactRequested,
        realm_id: realm.clone(), scope_ref: ScopeRef::Realm { realm_id: realm }, actor_id: holder.contact_actor_id(),
        executed_by: None, authorization_ref: None, applet_id: None, external_ref: None, created_at: at("2026-10-16T00:00:02Z"),
        semantic_refs: Vec::new(), payload: serde_json::from_value(json!({"peer":{"kind":"human","account_id":{"principal_id":"ak:did_core:web:peer.example","station_id":"ak:did_core:web:peer-station.example"}},"granted_to_peer_scopes":["direct_message"],"introduction_evidence_digest":format!("sha256:{}","a".repeat(64))})).unwrap(), producer_proof: None,
    };
    (event, holder, signer, history)
}

#[test]
fn native_history_authenticates_runtime_and_exact_controller_projection() {
    let (mut event, holder, signer, history) = fixture();
    validate_agent_contact_native_history(&event, &holder, &signer, &history).unwrap();
    let did = agent_contact_identity_did(&event, &holder, &signer).unwrap();
    let ContactPeer::Agent {
        controller_account_id,
        ..
    } = &holder
    else {
        panic!()
    };
    event.executed_by = Some(ActorId::account(controller_account_id.clone()));
    event.authorization_ref =
        Some(AuthorizationRef::new(format!("{did}#managed-controller")).unwrap());
    let delegated = ContactProducerSigner::delegated(
        DidUrl::new("did:web:controller.example#device").unwrap(),
        signer.public_key_base64url().clone(),
        did,
    )
    .unwrap();
    validate_agent_contact_native_history(&event, &holder, &delegated, &history).unwrap();
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
}

#[test]
fn native_history_rejects_another_controller_and_station() {
    let (event, mut holder, signer, history) = fixture();
    let ContactPeer::Agent {
        controller_account_id,
        ..
    } = &mut holder
    else {
        panic!()
    };
    controller_account_id.principal_id =
        DidCoreId::new("ak:did_core:web:other-controller.example").unwrap();
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
    let (event, mut holder, signer, history) = fixture();
    let ContactPeer::Agent {
        controller_account_id,
        ..
    } = &mut holder
    else {
        panic!()
    };
    controller_account_id.station_id =
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
}

#[test]
fn native_history_rejects_another_pcr_or_non_realm_scope() {
    let (mut event, holder, signer, history) = fixture();
    event.realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [24; 32],
    ));
    event.scope_ref = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
    let (mut event, holder, signer, history) = fixture();
    event.scope_ref = ScopeRef::RealmGenesis;
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
}

#[test]
fn native_history_rejects_event_before_binding_and_inception_only() {
    let (mut event, holder, signer, history) = fixture();
    event.created_at -= Duration::milliseconds(1500);
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
    event.created_at -= Duration::seconds(1);
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
    let (event, holder, signer, history) = fixture();
    let did = agent_contact_identity_did(&event, &holder, &signer).unwrap();
    let inception = verify_did_webvh_v1_chain(&did, &history.raw_entries[..1]).unwrap();
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &inception).is_err());
}

#[test]
fn native_history_rechecks_raw_signatures_and_snapshot_integrity() {
    let (event, holder, signer, mut history) = fixture();
    history.raw_entries[1]["state"]["service"][2]["serviceEndpoint"]["requested_scope_digest"] =
        json!(format!("sha256:{}", "9".repeat(64)));
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
    let (event, holder, signer, mut history) = fixture();
    history.entries[1].version_created_at += Duration::seconds(1);
    assert!(validate_agent_contact_native_history(&event, &holder, &signer, &history).is_err());
}

#[test]
fn native_history_never_accepts_an_unrelated_producer_locator() {
    let (event, holder, signer, history) = fixture();
    let wrong = ContactProducerSigner::direct(
        DidUrl::new("did:web:other.example#runtime").unwrap(),
        signer.public_key_base64url().clone(),
    )
    .unwrap();
    assert!(validate_agent_contact_native_history(&event, &holder, &wrong, &history).is_err());
    let mut wrong_kind = event;
    wrong_kind.kind = EventKind::MessageCreate;
    assert!(
        validate_agent_contact_native_history(&wrong_kind, &holder, &signer, &history).is_err()
    );
}
