use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::ephemeral::{
    CallSignalSeqKey, CallSignalState, EPHEMERAL_ABSOLUTE_HARD_CEILING_MS, EphemeralEnvelope,
    validate_signal_seq,
};
use arkret_models_collaboration::governance::audit::{AccessKind, AuditPolicyAccessPayload};
use arkret_models_collaboration::governance::moderation_appeal::{
    AppealDecisionPayload, AppealVerdict, ModerationAppealPayload,
};
use arkret_models_collaboration::governance::policy_check::compute_audit_policy_version_digest;
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInvite, ThirdPartyInviteOobKind,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_collaboration::object_lifecycle::{
    strand_tracks_patch_cell_subject, strand_update_cell_subject,
};
use arkret_wire::{
    CallId, ConsentId, DeviceId, Did, EventId, Hash, Proof, RealmId, StrandId, TypedAppealId,
    TypedTrustDomainId,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

fn realm() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()
}

fn did() -> Did {
    Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap()
}

fn ephemeral_payload() -> BTreeMap<String, Value> {
    BTreeMap::from([("status".to_owned(), Value::String("online".to_owned()))])
}

fn ephemeral_proof(created_at: DateTime<Utc>) -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{}#{}", did(), device_id()),
        event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at,
        domain: None,
        audience: None,
        jws: "header..signature".to_owned(),
    }
}

#[test]
fn ephemeral_envelope_rejects_window_over_ceiling() {
    let now = Utc::now();
    let bad = EphemeralEnvelope::new(
        "ak.presence",
        realm(),
        did(),
        device_id(),
        now,
        now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64 + 1),
        ephemeral_payload(),
        ephemeral_proof(now),
    );
    assert!(bad.is_err());
}

#[test]
fn ephemeral_envelope_accepts_window_at_ceiling() {
    let now = Utc::now();
    let ok = EphemeralEnvelope::new(
        "ak.presence",
        realm(),
        did(),
        device_id(),
        now,
        now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64),
        ephemeral_payload(),
        ephemeral_proof(now),
    );
    assert!(ok.is_ok());
}

#[test]
fn ephemeral_envelope_rejects_non_ephemeral_kind() {
    let now = Utc::now();
    assert!(
        EphemeralEnvelope::new(
            "ak.message.create",
            realm(),
            did(),
            device_id(),
            now,
            now + Duration::seconds(30),
            BTreeMap::new(),
            ephemeral_proof(now),
        )
        .is_err()
    );
}

#[test]
fn ephemeral_envelope_deserialization_requires_device_id() {
    let now = Utc::now();
    let envelope = EphemeralEnvelope::new(
        "ak.presence",
        realm(),
        did(),
        device_id(),
        now,
        now + Duration::seconds(30),
        ephemeral_payload(),
        ephemeral_proof(now),
    )
    .unwrap();
    let mut value = serde_json::to_value(envelope).unwrap();
    value.as_object_mut().unwrap().remove("device_id");

    assert!(serde_json::from_value::<EphemeralEnvelope>(value).is_err());
}

#[test]
fn ephemeral_envelope_deserialization_rejects_unknown_fields() {
    let now = Utc::now();
    let envelope = EphemeralEnvelope::new(
        "ak.presence",
        realm(),
        did(),
        device_id(),
        now,
        now + Duration::seconds(30),
        ephemeral_payload(),
        ephemeral_proof(now),
    )
    .unwrap();
    let mut value = serde_json::to_value(envelope).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));

    assert!(serde_json::from_value::<EphemeralEnvelope>(value).is_err());
}

#[test]
fn moderation_appeal_decision_modify_requires_ref() {
    let payload = ModerationAppealPayload::Decision(AppealDecisionPayload {
        appeal_id: TypedAppealId::new("ak:appeal:01904100-0000-7000-8000-000000000001").unwrap(),
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
        appeal_id: TypedAppealId::new("ak:appeal:01904100-0000-7000-8000-000000000001").unwrap(),
        realm_id: realm(),
        reviewer: did(),
        verdict: AppealVerdict::Uphold,
        reason_text_ref: "blob:reason".to_owned(),
        modify_decision_ref: Some(
            EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap(),
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
        token_commitment: None,
        token_salt_id: None,
        token_entropy_bits: Some(64),
        lookup_table_ref: None,
        pepper_id: None,
        max_claims: 3,
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
        token_commitment: invite.token_commitment.clone(),
        ..invite
    };
    assert!(lookup_bad.validate_minimal().is_err());
}

#[test]
fn validate_signal_seq_enforces_monotonicity() {
    assert!(validate_signal_seq(None, 0).is_ok());
    assert!(validate_signal_seq(Some(0), 1).is_ok());
    assert!(validate_signal_seq(Some(5), 6).is_ok());
    assert!(validate_signal_seq(Some(5), 5).is_err());
    assert!(validate_signal_seq(Some(5), 4).is_err());
}

#[test]
fn call_signal_state_tracks_per_key_seq() {
    let mut state = CallSignalState::new();
    let key = CallSignalSeqKey::new(
        realm(),
        CallId::new("ak:call:01904100-0000-7000-8000-000000000002").unwrap(),
        did(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000003").unwrap(),
    );
    assert!(state.observe(&key, 1).is_ok());
    assert!(state.observe(&key, 2).is_ok());
    assert!(state.observe(&key, 2).is_err());
    assert!(state.observe(&key, 5).is_ok());
}

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
        "observed_dots": ["ak:event:01904100-0000-7000-8000-000000000002:7"]
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
            "ak:event:01904100-0000-7000-8000-000000000002:7",
            "ak:event:01904100-0000-7000-8000-000000000002:7"
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
    let strand = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000004").unwrap();
    assert_eq!(strand_update_cell_subject(&strand), strand.as_str());
    assert_eq!(strand_tracks_patch_cell_subject(&strand), strand.as_str());
}
