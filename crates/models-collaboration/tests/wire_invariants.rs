use arkret_models_collaboration::governance::audit::{AccessKind, AuditPolicyAccessPayload};
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInvite, ThirdPartyInviteOobKind,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::http_bodies::{
    AppletEventTransactionRequestBody, AppletTransactionRequestBody,
};
use arkret_wire::signal::{SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME};
use arkret_wire::{
    ConsentId, DeviceId, DidCoreId, DidUrl, Hash, RealmId, ScopeRef, SealId, SignalClass,
    SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

fn realm() -> RealmId {
    RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
}

fn core_id() -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap()
}

// The plaintext `EphemeralEnvelope` this file used to cover no longer exists in
// v1: `signal-envelope.schema.json` defines a single encrypted-only rail, and
// `zh/sync/signal.md` states there is no plaintext branch. The ephemeral lane of
// this crate's applet transaction body is now `Option<Vec<SignalEnvelope>>`, so
// the old TTL-ceiling / required-device_id / unknown-field assertions are
// restated below against that lane. The per-class TTL ceiling, the AAD binding
// and the proof transcript themselves are owned and tested by `arkret-wire`
// (`crates/wire/src/signal.rs`).

fn signal_envelope(signal_class: SignalClass, ttl_seconds: i64) -> SignalEnvelope {
    let sent_at: DateTime<Utc> = "2026-07-28T12:00:00.000Z".parse().unwrap();
    let mut envelope = SignalEnvelope {
        realm_id: realm(),
        scope_ref: ScopeRef::Realm { realm_id: realm() },
        sender_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            core_id(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
        sender_device_id: Some(device_id()),
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
        signal_class,
        sent_at,
        expires_at: sent_at + Duration::seconds(ttl_seconds),
        encrypted_payload: SignalEncryptedPayload {
            scheme: SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3".to_owned(),
            },
            purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        },
        proof: SignalProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new(format!(
                "did:webvh:z6mkfixturealice:alice.example#{}",
                device_id()
            ))
            .unwrap(),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            domain: None,
            audience: None,
            jws: "header..signature".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope
}

fn applet_transaction(signal: SignalEnvelope) -> AppletEventTransactionRequestBody {
    AppletEventTransactionRequestBody {
        applet_id: arkret_wire::AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa")
            .unwrap(),
        source_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        events: Vec::new(),
        signals: Some(vec![signal]),
    }
}

#[test]
fn applet_transaction_signal_lane_enforces_the_class_ttl_ceiling() {
    let at_ceiling = applet_transaction(signal_envelope(SignalClass::Session, 30));
    at_ceiling.signals.as_ref().unwrap()[0]
        .validate_structural()
        .expect("a 30s session signal is at the class ceiling");

    let over_ceiling = applet_transaction(signal_envelope(SignalClass::Session, 31));
    assert!(
        over_ceiling.signals.as_ref().unwrap()[0]
            .validate_structural()
            .is_err()
    );
}

#[test]
fn applet_transaction_signal_lane_preserves_closed_sender_branches_and_unknown_field_rejection() {
    let body = applet_transaction(signal_envelope(SignalClass::Session, 30));
    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<AppletTransactionRequestBody>(value.clone()).unwrap()
        )
        .unwrap(),
        value
    );

    let mut without_device = value.clone();
    without_device["signals"][0]
        .as_object_mut()
        .unwrap()
        .remove("sender_device_id");
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(without_device).is_ok());

    let mut null_device = value.clone();
    null_device["signals"][0]["sender_device_id"] = Value::Null;
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(null_device).is_err());

    let mut unknown_member = value;
    unknown_member["signals"][0]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(unknown_member).is_err());
}

#[test]
fn applet_transaction_signal_lane_keeps_plaintext_out_of_the_outer_header() {
    let encrypted = serde_json::to_value(signal_envelope(SignalClass::Session, 30)).unwrap();
    for leaked in ["kind", "signal_kind", "payload", "call_id", "strand_id"] {
        assert!(
            encrypted.get(leaked).is_none(),
            "{leaked} leaked on the outer header"
        );
    }
}

#[test]
fn third_party_invite_rejects_mode_mismatch() {
    let mut invite = ThirdPartyInvite {
        oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
        display_name_hint: None,
        token_commitment: None,
        token_salt_id: None,
        token_entropy_bits: Some(64),
        lookup_table_ref: None,
        pepper_id: None,
        max_claims: 1,
        verification_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        verification_public_key: "z6MkVK".to_owned(),
    };
    assert!(invite.validate_minimal().is_err());

    invite.token_commitment = Some(Hash::new("sha256:".to_owned() + &"0".repeat(64)).unwrap());
    invite.token_salt_id = Some("salt-1".to_owned());
    assert!(invite.validate_minimal().is_err());

    invite.token_entropy_bits = Some(128);
    assert!(invite.validate_minimal().is_ok());

    let lookup_bad = ThirdPartyInvite {
        oob_code_kind: ThirdPartyInviteOobKind::Lookup,
        display_name_hint: None,
        token_commitment: invite.token_commitment.clone(),
        ..invite
    };
    assert!(lookup_bad.validate_minimal().is_err());
}

#[test]
fn third_party_invite_lookup_binds_the_public_commitment() {
    let value = json!({
        "token_commitment": format!("sha256:{}", "ab".repeat(32)),
        "lookup_table_ref": "lookup-private-slot",
        "pepper_id": "pepper-private-slot",
        "oob_code_kind": "lookup",
        "verification_id": "ak:did_core:web:ivs.example",
        "verification_public_key": "z6MkVK",
        "max_claims": 1
    });
    let invite: ThirdPartyInvite = serde_json::from_value(value.clone()).unwrap();
    invite.validate_minimal().unwrap();
    for field in ["token_commitment", "lookup_table_ref", "pepper_id"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        let parsed: ThirdPartyInvite = serde_json::from_value(missing).unwrap();
        assert!(parsed.validate_minimal().is_err(), "missing {field}");
    }
    for (field, extra) in [
        ("token_salt_id", json!("salt")),
        ("token_entropy_bits", json!(128)),
    ] {
        let mut mixed = value.clone();
        mixed[field] = extra;
        let parsed: ThirdPartyInvite = serde_json::from_value(mixed).unwrap();
        assert!(
            parsed.validate_minimal().is_err(),
            "mixed mode field {field}"
        );
    }
}

#[test]
fn third_party_invite_presentation_accepts_short_codes_and_full_dids() {
    use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvitePresentRequestBody;
    let value = json!({
        "invite_token": "123456",
        "realm_id": realm(),
        "subject_account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station.example"
        },
        "subject_did": "did:web:alice.example",
        "claim_nonce": "0123456789abcdef"
    });
    let body: ThirdPartyInvitePresentRequestBody = serde_json::from_value(value.clone()).unwrap();
    body.validate_minimal().unwrap();
    for token in ["12345", "123 456", "123456&leak=yes"] {
        let mut invalid = value.clone();
        invalid["invite_token"] = json!(token);
        let body: ThirdPartyInvitePresentRequestBody = serde_json::from_value(invalid).unwrap();
        assert!(body.validate_minimal().is_err());
    }
    let mut different_subject = value.clone();
    different_subject["subject_did"] = json!("did:web:bob.example");
    let body: ThirdPartyInvitePresentRequestBody =
        serde_json::from_value(different_subject).unwrap();
    assert!(body.validate_minimal().is_err());
    let mut core_as_did = value;
    core_as_did["subject_did"] = json!("ak:did_core:web:alice.example");
    assert!(serde_json::from_value::<ThirdPartyInvitePresentRequestBody>(core_as_did).is_err());
}

// `validate_signal_seq` / `CallSignalState` had no v1 successor to restate them
// against: `signal-envelope.schema.json` places the sender sequence inside
// `encrypted_payload`, reachable only after a recipient decrypts. There is no
// wire-visible per-(realm, call, actor, device) sequence left for a wire
// invariant test in this crate to assert, and the outer header deliberately
// carries no `call_id` — the coverage above asserts exactly that absence.

#[test]
fn audit_policy_access_payload_validates_late_recovery_pairing() {
    let payload = AuditPolicyAccessPayload {
        realm_id: realm(),
        actor: core_id(),
        access_kind: AccessKind::E2EELateRecovery,
        late_recovery_original_event_id: None,
        observed_at: Utc::now(),
    };
    assert!(payload.validate_minimal().is_err());
}

#[test]
fn audit_policy_access_late_recovery_uses_e2ee_wire_spelling() {
    assert_eq!(
        serde_json::to_value(AccessKind::E2EELateRecovery).unwrap(),
        json!("e2ee_late_recovery")
    );
}

#[test]
fn consent_revoke_requires_observed_dots() {
    let payload = ConsentRevokePayload {
        consent_id: ConsentId::new("ak:consent:01904100-0000-7000-8000-000000000001".to_owned())
            .unwrap(),
        observed_dot_ids: Vec::new(),
        revoked_at: None,
        reason: None,
    };
    assert!(payload.validate_minimal().is_err());

    let canonical = json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dot_ids": ["ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1:7"]
    });
    let parsed: ConsentRevokePayload = serde_json::from_value(canonical).unwrap();
    assert!(parsed.validate_minimal().is_ok());
    assert!(
        serde_json::from_value::<ConsentRevokePayload>(json!({
            "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
            "observed_dot_ids": ["ak:event:not-a-uuidv7:7"]
        }))
        .is_err()
    );
    let duplicate_dots: ConsentRevokePayload = serde_json::from_value(json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dot_ids": [
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1:7",
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1:7"
        ]
    }))
    .unwrap();
    assert!(duplicate_dots.validate_minimal().is_err());
    assert!(
        serde_json::from_value::<ConsentRevokePayload>(json!({
            "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
            "peer": "ak:did_core:web:bob.example",
            "scope": "invite",
            "observed_dot_ids": [{
                "actor_id": "ak:did_core:web:alice.example",
                "actor_seq": 7
            }]
        }))
        .is_err()
    );
}
