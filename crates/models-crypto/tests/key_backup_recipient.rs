use arkret_models_crypto::{KeyBackup, RecoveryPolicy};
use arkret_wire::{ActorId, ErrorCode};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};

fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn fixture() -> (KeyBackup, RecoveryPolicy, DateTime<Utc>) {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let backup: KeyBackup =
        serde_json::from_value(fixture["root_backup"]["envelope"].clone()).unwrap();
    let now = backup.created_at;
    let reference = backup.recovery_policy_ref.as_ref().unwrap();
    let policy = serde_json::from_value(json!({
        "schema":"ak.schema.recovery_policy.v1",
        "policy_id":reference.policy_id,"account_id":backup.actor_id.as_account_id().unwrap(),
        "version":reference.policy_version,"supersedes_id":null,
        "trust_domain":"ak:trust_domain:station.example","issued_at":timestamp(now),
        "signature_proof":{
            "verification_method":"did:web:controller.example#device-1",
            "signature_algorithm":"Ed25519","signature":arkret_canonical::base64url_encode([7;64])
        },
        "methods":[{"kind":"recovery_unlock","keys":[{
            "verification_method":"did:web:controller.example#recovery-proof",
            "public_key_multibase":"z6MkRecoverySigningKey",
            "signature_algorithm":"Ed25519",
            "not_before":timestamp(now-TimeDelta::minutes(1)),"expires_at":timestamp(now+TimeDelta::days(1)),
            "backup_hpke":{
                "key_agreement_ref":backup.encryption.recipient_key_ref,
                "key_agreement_algorithm":"X25519","public_key_multibase":"z6LSBackupAgreement",
                "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                "use":"backup_hpke","not_before":timestamp(now-TimeDelta::minutes(1)),
                "expires_at":timestamp(now+TimeDelta::days(1))
            }
        }]}]
    }))
    .unwrap();
    (backup, policy, now)
}

#[test]
fn recipient_is_bound_to_the_complete_subject_and_exact_policy() {
    let (backup, policy, now) = fixture();
    backup.validate_recovery_recipient(&policy, now).unwrap();
    for field in ["account_id", "policy_id", "version"] {
        let mut wrong = serde_json::to_value(&policy).unwrap();
        match field {
            "account_id" => wrong[field]["station_id"] = json!("ak:did_core:web:another.example"),
            "policy_id" => wrong[field] = json!("ak:policy:019a0000-0000-7000-8000-000000000002"),
            _ => wrong[field] = json!(2),
        }
        let wrong = serde_json::from_value(wrong).unwrap();
        assert_eq!(
            backup
                .validate_recovery_recipient(&wrong, now)
                .unwrap_err()
                .error_code(),
            Some(ErrorCode::RecoveryPolicyMismatch),
            "{field}"
        );
    }
}

#[test]
fn signed_digest_cannot_substitute_for_the_original_ciphertext() {
    let (mut backup, ..) = fixture();
    backup.validate_ciphertext_digest().unwrap();
    backup.ciphertext_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap();
    assert!(backup.validate_ciphertext_digest().is_err());
    let (mut backup, ..) = fixture();
    backup.ciphertext =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([7; 32])).unwrap();
    assert!(backup.validate_ciphertext_digest().is_err());
}

#[test]
fn signing_keys_expired_revoked_and_ambiguous_agreements_cannot_receive_new_roots() {
    let (backup, policy, now) = fixture();
    let original = serde_json::to_value(&policy).unwrap();
    for case in [
        "signing_key",
        "revoked",
        "expired",
        "future",
        "duplicate",
        "suite",
        "policy_expired",
        "policy_future",
        "revoked_policy",
    ] {
        let mut wrong = original.clone();
        let key = &mut wrong["methods"][0]["keys"][0];
        match case {
            "signing_key" => {
                key["backup_hpke"]["key_agreement_ref"] = key["verification_method"].clone()
            }
            "revoked" => key["backup_hpke"]["revoked_at"] = json!(timestamp(now)),
            "expired" => key["backup_hpke"]["expires_at"] = json!(timestamp(now)),
            "future" => {
                key["backup_hpke"]["not_before"] =
                    json!(timestamp(now + TimeDelta::milliseconds(1)))
            }
            "duplicate" => {
                let duplicate = key.clone();
                wrong["methods"][0]["keys"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "suite" => {
                key["backup_hpke"]["hpke_suites"] = json!(["ak.hpke_x25519_aead_aes256gcm.v1"])
            }
            "policy_expired" => wrong["expires_at"] = json!(timestamp(now)),
            "policy_future" => {
                wrong["not_before"] = json!(timestamp(now + TimeDelta::milliseconds(1)))
            }
            _ => wrong["methods"] = json!([]),
        }
        let wrong: RecoveryPolicy = serde_json::from_value(wrong).unwrap();
        let expected = if case == "suite" {
            ErrorCode::UnsupportedHpkeSuite
        } else {
            ErrorCode::RecoveryPolicyMismatch
        };
        assert_eq!(
            backup
                .validate_recovery_recipient(&wrong, now)
                .unwrap_err()
                .error_code(),
            Some(expected),
            "{case}"
        );
    }
    let mut signing_recipient = backup;
    signing_recipient.encryption.recipient_key_ref =
        Some("did:web:controller.example#recovery-proof".into());
    assert!(
        signing_recipient
            .validate_recovery_recipient(&policy, now)
            .is_err()
    );
}

#[test]
fn agent_custody_resolves_the_custodian_policy_without_granting_custody() {
    let (mut backup, policy, now) = fixture();
    let controller = backup.actor_id.clone();
    let agent: ActorId = serde_json::from_value(json!({"kind":"account","account_id":{
        "principal_id":"ak:did_core:web:agent.example","station_id":policy.account_id.station_id
    }}))
    .unwrap();
    backup.actor_id = agent;
    assert!(backup.validate_recovery_recipient(&policy, now).is_err());
    backup.custodian_actor_id = Some(controller);
    backup.custody_authorization_ref = Some(
        backup
            .signature_proof
            .device_authorize_event_id
            .clone()
            .unwrap(),
    );
    backup.validate_recovery_recipient(&policy, now).unwrap();
    let mut missing_pair: Value = serde_json::to_value(&backup).unwrap();
    missing_pair
        .as_object_mut()
        .unwrap()
        .remove("custody_authorization_ref");
    let missing_pair: KeyBackup = serde_json::from_value(missing_pair).unwrap();
    assert!(
        missing_pair
            .validate_recovery_recipient(&policy, now)
            .is_err()
    );
}
