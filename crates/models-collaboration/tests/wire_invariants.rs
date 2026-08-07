use arkret_models_collaboration::governance::audit::{AccessKind, AuditPolicyAccessPayload};
use arkret_models_collaboration::governance::moderation_appeal::{
    AppealDecisionPayload, AppealVerdict, ModerationAppealPayload,
};
use arkret_models_collaboration::governance::policy_check::compute_audit_policy_version_digest;
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInvite, ThirdPartyInviteOobKind,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_collaboration::object_lifecycle::{
    strand_tracks_patch_cell_subject, strand_update_cell_subject,
};
use arkret_wire::signal::{SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME};
use arkret_wire::{
    ConsentId, DeviceId, Did, DidUrl, EventId, Hash, RealmId, ScopeRef, SealId, SignalClass,
    SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof, StrandId, TypedAppealId,
    TypedTrustDomainId,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

fn realm() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-8000-8000-000000000001").unwrap()
}

fn did() -> Did {
    Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
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
        sender_actor_id: did(),
        sender_device_id: device_id(),
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
        signal_class,
        sent_at,
        expires_at: sent_at + Duration::seconds(ttl_seconds),
        encrypted_payload: SignalEncryptedPayload {
            scheme: SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:01904100-0000-8000-8000-000000000006".to_owned(),
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
            verification_method: DidUrl::new(format!("{}#{}", did(), device_id())).unwrap(),
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: sent_at,
            domain: None,
            audience: None,
            jws: "header..signature".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    envelope
}

fn applet_transaction(signal: SignalEnvelope) -> AppletTransactionRequestBody {
    AppletTransactionRequestBody {
        source_service_id: Did::new("did:webvh:z6mkfixture:applet.example").unwrap(),
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
fn applet_transaction_signal_lane_requires_the_sending_device_and_rejects_unknown_fields() {
    let body = applet_transaction(signal_envelope(SignalClass::Session, 30));
    let value = serde_json::to_value(&body).unwrap();
    assert_eq!(
        serde_json::from_value::<AppletTransactionRequestBody>(value.clone()).unwrap(),
        body
    );

    let mut without_device = value.clone();
    without_device["signals"][0]
        .as_object_mut()
        .unwrap()
        .remove("sender_device_id");
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(without_device).is_err());

    let mut unknown_member = value;
    unknown_member["signals"][0]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(unknown_member).is_err());
}

#[test]
fn applet_transaction_signal_lane_rejects_a_plaintext_ephemeral_envelope() {
    // The removed rail put `kind` and a cleartext `payload` on the wire. Both
    // are now inside `encrypted_payload`, so the legacy shape must not parse
    // and must not be reconstructible from the outer header.
    let legacy = json!({
        "source_service_id": "did:webvh:z6mkfixture:applet.example",
        "events": [],
        "signals": [{
            "kind": "ak.presence",
            "realm_id": realm().as_str(),
            "actor_id": did().as_str(),
            "device_id": device_id().as_str(),
            "sent_at": "2026-07-28T12:00:00.000Z",
            "expires_at": "2026-07-28T12:00:30.000Z",
            "payload": {"status": "online"}
        }]
    });
    assert!(serde_json::from_value::<AppletTransactionRequestBody>(legacy).is_err());

    let encrypted = serde_json::to_value(signal_envelope(SignalClass::Session, 30)).unwrap();
    for leaked in ["kind", "signal_kind", "payload", "call_id", "strand_id"] {
        assert!(
            encrypted.get(leaked).is_none(),
            "{leaked} leaked on the outer header"
        );
    }
}

#[test]
fn moderation_appeal_decision_modify_requires_ref() {
    let payload = ModerationAppealPayload::Decision(AppealDecisionPayload {
        appeal_id: TypedAppealId::new("ak:appeal:01904100-0000-8000-8000-000000000001").unwrap(),
        realm_id: realm(),
        reviewer: did(),
        verdict: AppealVerdict::Modify,
        reason_text_ref: "blob:reason".to_owned(),
        modify_decision_ref: None,
        decided_at: Utc::now(),
    });
    assert!(payload.validate_minimal().is_err());
}

#[test]
fn moderation_appeal_decision_uphold_rejects_modify_ref() {
    let payload = ModerationAppealPayload::Decision(AppealDecisionPayload {
        appeal_id: TypedAppealId::new("ak:appeal:01904100-0000-8000-8000-000000000001").unwrap(),
        realm_id: realm(),
        reviewer: did(),
        verdict: AppealVerdict::Uphold,
        reason_text_ref: "blob:reason".to_owned(),
        modify_decision_ref: Some(
            EventId::new("ak:event:01904100-0000-8000-8000-000000000002").unwrap(),
        ),
        decided_at: Utc::now(),
    });
    assert!(payload.validate_minimal().is_err());
}

#[test]
fn audit_policy_version_digest_is_deterministic_and_domain_separates() {
    let trust_domain = TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap();
    let other_trust_domain = TypedTrustDomainId::new("ak:trust_domain:other.example").unwrap();
    let disclosure = json!({"mode": "strict"});
    let assurance = json!("attested_hardware");
    let h1 = compute_audit_policy_version_digest(&realm(), &trust_domain, &disclosure, &assurance)
        .unwrap();
    let h2 = compute_audit_policy_version_digest(&realm(), &trust_domain, &disclosure, &assurance)
        .unwrap();
    assert_eq!(h1, h2);
    let h3 =
        compute_audit_policy_version_digest(&realm(), &other_trust_domain, &disclosure, &assurance)
            .unwrap();
    assert_ne!(h1, h3);
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
        verification_service_id: Did::new("did:webvh:z6mkfixture:auth.example").unwrap(),
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
        actor: did(),
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
        observed_dots: Vec::new(),
        revoked_at: None,
        reason: None,
    };
    assert!(payload.validate_minimal().is_err());

    let canonical = json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": ["ak:event:01904100-0000-8000-8000-000000000002:7"]
    });
    let parsed: ConsentRevokePayload = serde_json::from_value(canonical).unwrap();
    assert!(parsed.validate_minimal().is_ok());
    assert!(
        serde_json::from_value::<ConsentRevokePayload>(json!({
            "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
            "observed_dots": ["ak:event:not-a-uuidv7:7"]
        }))
        .is_err()
    );
    let duplicate_dots: ConsentRevokePayload = serde_json::from_value(json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": [
            "ak:event:01904100-0000-8000-8000-000000000002:7",
            "ak:event:01904100-0000-8000-8000-000000000002:7"
        ]
    }))
    .unwrap();
    assert!(duplicate_dots.validate_minimal().is_err());
    assert!(
        serde_json::from_value::<ConsentRevokePayload>(json!({
            "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
            "peer": "did:web:bob.example",
            "scope": "invite",
            "observed_dots": [{
                "actor_id": "did:web:alice.example",
                "actor_seq": 7
            }]
        }))
        .is_err()
    );
}

#[test]
fn strand_cell_subject_helpers_return_strand_id() {
    let strand = StrandId::new("ak:strand:01904100-0000-8000-8000-000000000004").unwrap();
    assert_eq!(strand_update_cell_subject(&strand), strand.as_str());
    assert_eq!(strand_tracks_patch_cell_subject(&strand), strand.as_str());
}
