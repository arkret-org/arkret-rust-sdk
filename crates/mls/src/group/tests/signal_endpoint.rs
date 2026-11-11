//! Real MLS endpoint, counter-continuity and independent authority regression.

use arkret_crypto::AeadNonceReplayTracker;
use arkret_models_crypto::ContentEndpoint;
use arkret_wire::{RealmCommitId, SignalEnvelope, SignalProof, StationSigningKey};
use ed25519_dalek::SigningKey;

use super::*;

fn signal(group: &mut ArkretMlsGroup, plaintext: &[u8]) -> (SignalEnvelope, StationSigningKey) {
    let endpoint = group.local_content_endpoint().unwrap();
    let actor = endpoint.actor_id.clone();
    let (device, method) = match endpoint.endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => {
            let principal = actor
                .signing_principal_id()
                .as_str()
                .strip_prefix("ak:did_core:web:")
                .unwrap();
            let method =
                arkret_wire::DidUrl::new(format!("did:web:{principal}#{}", device_id.as_str()))
                    .unwrap();
            (Some(device_id), method)
        }
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => (None, verification_method),
    };
    // Native producer and accepted MLS leaf keys are deliberately independent.
    let key = SigningKey::from_bytes(&[91; 32]);
    let mut envelope = SignalEnvelope {
        realm_id: group.scope().realm_id_opt().unwrap().clone(),
        scope_ref: group.scope().clone(),
        sender_actor_id: actor.clone(),
        sender_device_id: device,
        authority_commit_id: RealmCommitId::from_digest([31; 32]),
        parent_realm_authority_commit_id: None,
        signal_class: arkret_wire::SignalClass::Session,
        sent_at: "2026-11-11T00:00:00Z".parse().unwrap(),
        expires_at: "2026-11-11T00:00:20Z".parse().unwrap(),
        encrypted_payload: arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.into(),
            key_ref: arkret_wire::SignalKeyRef {
                group_state_ref: event(1).to_string(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.into(),
            aead_profile: ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.into(),
            epoch: group.epoch(),
            nonce: String::new(),
            ciphertext: String::new(),
        },
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: method.clone(),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    envelope.encrypted_payload = group
        .encrypt_signal_payload(&envelope.aead_binding(), plaintext)
        .unwrap()
        .encrypted_payload;
    resign(&mut envelope);
    let authority = StationSigningKey {
        actor,
        verification_method: method,
        public_key_base64url: Base64UrlString::new(base64url_encode(
            key.verifying_key().to_bytes(),
        ))
        .unwrap(),
        authorization_ref: endpoint.authorization_event_ref,
    };
    (envelope, authority)
}

fn resign(envelope: &mut SignalEnvelope) {
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&[91; 32]),
        &envelope.proof_binding_bytes().unwrap(),
    )
    .unwrap();
}

fn open(
    group: &ArkretMlsGroup,
    envelope: &SignalEnvelope,
    authority: &StationSigningKey,
    replay: &mut AeadNonceReplayTracker,
) -> Result<Vec<u8>> {
    group.open_signal_envelope_with_station_key(
        envelope,
        authority,
        &envelope.encrypted_payload.key_ref.group_state_ref,
        &envelope.authority_commit_id,
        replay,
    )
}

#[test]
fn signal_native_proof_key_is_independent_and_bad_authority_does_not_poison_replay() {
    let (receiver, mut sender) = application_message_pair();
    let (envelope, authority) = signal(
        &mut sender,
        b"native signature and MLS endpoint are independent",
    );
    assert_ne!(
        authority.public_key_base64url.as_str(),
        sender
            .local_content_endpoint()
            .unwrap()
            .signature_key_base64url
    );
    let mut replay = AeadNonceReplayTracker::default();
    for mutation in 0..4 {
        let mut invalid = authority.clone();
        match mutation {
            0 => invalid.authorization_ref = event(93),
            1 => invalid.actor = receiver.local_actor_id().clone(),
            2 => {
                invalid.public_key_base64url = Base64UrlString::new(base64url_encode(
                    SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes(),
                ))
                .unwrap()
            }
            _ => {
                invalid.verification_method =
                    arkret_wire::DidUrl::new("did:web:mls-member.example#another-endpoint").unwrap()
            }
        }
        assert!(open(&receiver, &envelope, &invalid, &mut replay).is_err());
    }
    let mut bad_aead = envelope.clone();
    let mut ciphertext = decode(&bad_aead.encrypted_payload.ciphertext).unwrap();
    ciphertext[0] ^= 1;
    bad_aead.encrypted_payload.ciphertext = base64url_encode(ciphertext);
    resign(&mut bad_aead);
    assert!(open(&receiver, &bad_aead, &authority, &mut replay).is_err());
    assert_eq!(
        open(&receiver, &envelope, &authority, &mut replay).unwrap(),
        b"native signature and MLS endpoint are independent"
    );
    assert!(open(&receiver, &envelope, &authority, &mut replay).is_err());
}

#[test]
fn signal_same_principal_device_other_station_is_not_an_ambiguous_sender() {
    let actor = ActorId::account(arkret_wire::AccountId::new(
        identity().actor_id.signing_principal_id().clone(),
        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    ));
    let member = ArkretMlsIdentity::new_test_human_device(
        actor,
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000071").unwrap(),
    )
    .unwrap();
    let (mut first, mut second) = application_message_pair_with_member(member);
    let (a, a_authority) = signal(&mut first, b"first Station Account");
    let (b, b_authority) = signal(&mut second, b"other Station Account");
    assert_eq!(a.encrypted_payload.nonce, b.encrypted_payload.nonce);
    assert_ne!(
        first.local_signal_nonce_context().unwrap(),
        second.local_signal_nonce_context().unwrap()
    );
    let mut replay = AeadNonceReplayTracker::default();
    assert_eq!(
        open(&first, &a, &a_authority, &mut replay).unwrap(),
        b"first Station Account"
    );
    assert_eq!(
        open(&first, &b, &b_authority, &mut replay).unwrap(),
        b"other Station Account"
    );
}

#[test]
fn signal_agent_method_and_authorization_bind_the_accepted_endpoint() {
    let actor = ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        DidCoreId::new("ak:did_core:web:mls-fixture-station.example").unwrap(),
    ));
    let member = ArkretMlsIdentity::new_agent(
        actor,
        arkret_wire::DidUrl::new("did:web:agent.example#runtime-1").unwrap(),
        event(87),
        crate::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[87; 32])),
    )
    .unwrap();
    let (receiver, mut sender) = application_message_pair_with_member(member);
    let (envelope, authority) = signal(&mut sender, b"authorized Agent runtime");
    assert!(envelope.sender_device_id.is_none());
    let mut replay = AeadNonceReplayTracker::default();
    let mut replaced = authority.clone();
    replaced.authorization_ref = event(88);
    assert!(open(&receiver, &envelope, &replaced, &mut replay).is_err());
    replaced = authority.clone();
    replaced.verification_method =
        arkret_wire::DidUrl::new("did:web:agent.example#runtime-2").unwrap();
    assert!(open(&receiver, &envelope, &replaced, &mut replay).is_err());
    assert_eq!(
        open(&receiver, &envelope, &authority, &mut replay).unwrap(),
        b"authorized Agent runtime"
    );
}

#[test]
fn signal_required_counter_state_survives_restart_and_rejects_missing_or_old_shape() {
    let (receiver, mut sender) = application_message_pair();
    let (first, _) = signal(&mut sender, b"before restart");
    let record = sender.export_state_record().unwrap();
    let mut restarted = ArkretMlsGroup::restore_from_state_record(&record).unwrap();
    let (second, _) = signal(&mut restarted, b"after restart");
    assert_ne!(
        first.encrypted_payload.nonce,
        second.encrypted_payload.nonce
    );
    assert_eq!(restarted.signal_nonce_counter(), 2);
    for legacy in [None, Some(serde_json::json!(0))] {
        let mut broken = record.clone();
        let mut value: serde_json::Value =
            serde_json::from_slice(&broken.serialized_state).unwrap();
        if let Some(legacy) = legacy {
            value["signal_nonce_counter"] = legacy;
        } else {
            value
                .as_object_mut()
                .unwrap()
                .remove("signal_nonce_counter");
        }
        broken.serialized_state = serde_json::to_vec(&value).unwrap();
        assert!(ArkretMlsGroup::restore_from_state_record(&broken).is_err());
    }
    let mut wrong_endpoint = record;
    let mut value: serde_json::Value =
        serde_json::from_slice(&wrong_endpoint.serialized_state).unwrap();
    value["signal_nonce_counter"]["context"]["sender_domain"] =
        serde_json::Value::String(receiver.local_signal_nonce_context().unwrap().sender_domain);
    wrong_endpoint.serialized_state = serde_json::to_vec(&value).unwrap();
    assert!(ArkretMlsGroup::restore_from_state_record(&wrong_endpoint).is_err());
}

#[test]
fn signal_reserved_nonce_is_bound_to_endpoint_and_cannot_rewind_or_overflow() {
    let (mut sender, other) = application_message_pair();
    let (envelope, _) = signal(&mut sender, b"initial");
    let (context, floor) = sender.signal_nonce_reservation().unwrap();
    assert_eq!(floor, 1);
    let wrong_context = other.local_signal_nonce_context().unwrap();
    let binding = envelope.aead_binding();
    assert!(
        sender
            .encrypt_signal_payload_with_reserved_nonce(&binding, b"wrong", &wrong_context, 9)
            .is_err()
    );
    assert!(
        sender
            .encrypt_signal_payload_with_reserved_nonce(&binding, b"rollback", &context, 0)
            .is_err()
    );
    assert!(
        sender
            .encrypt_signal_payload_with_reserved_nonce(&binding, b"overflow", &context, u64::MAX)
            .is_err()
    );
    let next = sender
        .encrypt_signal_payload_with_reserved_nonce(&binding, b"gap", &context, 256)
        .unwrap();
    assert_eq!(next.nonce_counter, 256);
    assert_eq!(sender.signal_nonce_counter(), 257);
    assert!(
        sender
            .encrypt_signal_payload_with_reserved_nonce(&binding, b"reused", &context, 256)
            .is_err()
    );
}

#[test]
fn signal_all_frozen_endpoint_contexts_match_production_kdf() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/arkret-private-kdf-fixture.json")
            .unwrap();
    let kat = &fixture["cases"][1];
    let root = hex::decode(kat["expected"]["signal_root_hex"].as_str().unwrap()).unwrap();
    let rows = fixture["signal_endpoint_contract"]["domains"]
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 10);
    let mut distinct = std::collections::BTreeSet::new();
    for row in rows {
        let endpoint: ContentEndpoint =
            serde_json::from_value(row["verified_endpoint"].clone()).unwrap();
        endpoint.validate().unwrap();
        let domain = canonical::canonical_json_bytes(&endpoint).unwrap();
        assert_eq!(
            std::str::from_utf8(&domain).unwrap(),
            row["sender_domain_utf8"].as_str().unwrap()
        );
        let key =
            arkret_crypto::mls_exporter::mls_expand_with_label(&root, "ak.signal-v1", &domain, 16)
                .unwrap();
        assert_eq!(hex::encode(&key), row["signal_key_hex"].as_str().unwrap());
        assert!(distinct.insert(key));
    }
}
