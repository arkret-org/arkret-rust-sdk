use serde_json::json;

pub(crate) const POLICY_ID: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";
pub(crate) const TRUST_DOMAIN: &str = "ak:trust_domain:example.net";
pub(crate) const RECOVERY_METHOD_URL: &str = "did:webvh:z6mkfixture:alice.example#recovery-key-1";

pub(crate) fn account_id() -> serde_json::Value {
    json!({
        "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "station_id": "ak:did_core:web:station.example"
    })
}

pub(crate) fn recovery_unlock_method() -> serde_json::Value {
    json!({
        "kind": "recovery_unlock",
        "keys": [{
            "verification_method": RECOVERY_METHOD_URL,
            "public_key_multibase": "z6MkfixtureRecoverySigningKey",
            "signature_algorithm": "Ed25519",
            "not_before": "2026-08-01T00:00:00.000Z",
            "expires_at": "2027-08-01T00:00:00.000Z",
            "backup_hpke": {
                "key_agreement_ref": "did:webvh:z6mkfixture:alice.example#backup-hpke-1",
                "key_agreement_algorithm": "X25519",
                "public_key_multibase": "z6LSfixtureBackupRecipientKey",
                "hpke_suites": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                "use": "backup_hpke",
                "not_before": "2026-08-01T00:00:00.000Z",
                "expires_at": "2027-08-01T00:00:00.000Z"
            }
        }]
    })
}

pub(crate) fn policy() -> serde_json::Value {
    json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": POLICY_ID,
        "account_id": account_id(),
        "version": 1,
        "supersedes_id": null,
        "trust_domain": TRUST_DOMAIN,
        "issued_at": "2026-08-01T00:00:00.000Z",
        "signature_proof": {
            "verification_method": "did:webvh:z6mkfixture:alice.example#founding-device",
            "signature_algorithm": "Ed25519",
            "signature": "Zml4dHVyZS1zaWduYXR1cmU"
        },
        "methods": [recovery_unlock_method()]
    })
}
