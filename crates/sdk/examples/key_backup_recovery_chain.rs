//! Build a series-chained `KeyBackup` envelope chain and walk recovery via
//! the `?series_id=` listing shape exposed by `ck.self.keys.backups.query.list` (spec
//! head 37ce729 / key-management.md §7.4 "key-backup hardening").
//!
//! The chain semantics this example exercises:
//!
//! * Every envelope in a chain shares the same `series_id` (a `ck:backup_series:` strict-typed id).
//! * `series_seq == 0` marks the genesis envelope; `supersedes` MUST be absent.
//! * `series_seq >= 1` marks a successor; `supersedes` and `supersedes_digest` are REQUIRED and the
//!   chain must be contiguous.
//! * `frontier_ref` ties the envelope to the originating-key frontier so the reducer can reject
//!   stale rollups with `backup_frontier_stale`.
//!
//! A reader wanting to drive a real soland would feed the chain to
//! `KeyBackupClient::put_key_backup` per envelope; the recovery walker would
//! call `KeyBackupClient::list_key_backups` (with the `series_id` query
//! parameter the spec adds for chain rehydration) and replay the chain in
//! `series_seq` order, validating each `supersedes_digest` against the prior
//! envelope's `ciphertext_digest`.
//!
//! ```sh
//! cargo run --example key_backup_recovery_chain
//! ```

use std::collections::BTreeMap;

use cokret::model::{
    BackupClass, KeyBackup, KeyBackupAead, KeyBackupAuthData, KeyBackupContentItem,
    KeyBackupEncryption, KeyBackupKdf, KeyBackupRecipientMethod,
};
use cokret::{BackupId, BackupSeriesId, DeviceId, Did};
use serde_json::json;

fn build_envelope(
    actor_id: &Did,
    device_id: &DeviceId,
    series_id: &BackupSeriesId,
    seq: u64,
    predecessor: Option<&KeyBackup>,
    ciphertext: &str,
) -> KeyBackup {
    let backup_id_str = format!(
        "ck:backup:01964137-0000-7000-8000-{:012x}",
        0xA000_u64 + seq
    );
    let ciphertext_digest = format!(
        "sha256:{:0>64}",
        format!("{seq:02x}")
            .repeat(32)
            .chars()
            .take(64)
            .collect::<String>()
    );
    let supersedes = predecessor.map(|p| p.backup_id.clone());
    let supersedes_digest = predecessor.map(|p| p.ciphertext_digest.clone());

    KeyBackup {
        backup_id: BackupId::new(&backup_id_str).expect("valid backup_id"),
        actor_id: actor_id.clone(),
        device_id: Some(device_id.clone()),
        backup_class: BackupClass::SecretStorage,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at: chrono::Utc::now(),
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
            recipient_key_ref: None,
            kdf: Some(KeyBackupKdf {
                name: "argon2id".to_owned(),
                salt: format!("salt-{seq}"),
                params: json!({ "memory_kib": 65_536, "iterations": 3, "parallelism": 1 }),
                degraded_profile_reason: None,
                extra: BTreeMap::new(),
            }),
            aead: KeyBackupAead {
                name: "xchacha20_poly1305".to_owned(),
                aead_profile: Some("ck.aead.xchacha20_poly1305.v1".to_owned()),
                nonce: Some(format!("nonce-{seq}")),
                nonce_salt: Some(format!("nonce-salt-{seq}")),
                extra: BTreeMap::new(),
            },
            key_commitment: None,
            extra: BTreeMap::new(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "recovery_secret".to_owned(),
            realm_id: None,
            mls_group_id: None,
            epoch: Some(seq),
            first_event_id: None,
            last_event_id: None,
            secret_id: Some(format!("recovery-{seq}")),
            extra: BTreeMap::new(),
        }],
        ciphertext: ciphertext.to_owned(),
        ciphertext_digest,
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: device_id.clone(),
            verification_method: "did:web:alice.example#device-1".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            signature: format!("sig-{seq}"),
            ssk_generation: Some(1),
            signed_fields: vec![
                "backup_id".to_owned(),
                "ciphertext_digest".to_owned(),
                "series_id".to_owned(),
                "series_seq".to_owned(),
            ],
            extra: BTreeMap::new(),
        }),
        retention: None,
        series_id: series_id.clone(),
        series_seq: seq,
        supersedes,
        supersedes_digest,
        frontier_ref: Some(format!("did:recovery:frontier:{seq}")),
        extra: BTreeMap::new(),
    }
}

fn validate_chain(envelopes: &[KeyBackup]) -> Result<(), String> {
    let Some(first) = envelopes.first() else {
        return Err("empty chain".into());
    };
    if first.series_seq != 0 {
        return Err(format!(
            "genesis must have series_seq=0, got {}",
            first.series_seq
        ));
    }
    if first.supersedes.is_some() || first.supersedes_digest.is_some() {
        return Err("genesis must not set supersedes".into());
    }
    for window in envelopes.windows(2) {
        let (prev, next) = (&window[0], &window[1]);
        if next.series_id != prev.series_id {
            return Err(format!(
                "series_id drift at seq={}: {} vs {}",
                next.series_seq,
                prev.series_id.as_str(),
                next.series_id.as_str()
            ));
        }
        if next.series_seq != prev.series_seq + 1 {
            return Err(format!(
                "non-monotonic seq: prev={} next={}",
                prev.series_seq, next.series_seq
            ));
        }
        match (&next.supersedes, &next.supersedes_digest) {
            (Some(sup), Some(digest))
                if sup == &prev.backup_id && digest == &prev.ciphertext_digest => {}
            _ => {
                return Err(format!(
                    "chain broken at seq={}: supersedes/digest mismatch",
                    next.series_seq
                ));
            }
        }
    }
    Ok(())
}

fn main() -> cokret::Result<()> {
    let actor_id = Did::new("did:web:alice.example")?;
    let device_id = DeviceId::new("ck:device:01964137-0000-7000-8000-000000000009")?;
    let series_id = BackupSeriesId::new("ck:backup_series:01964137-0000-7000-8000-000000000777")?;

    // Build the chain: genesis + two rotations.
    let genesis = build_envelope(
        &actor_id,
        &device_id,
        &series_id,
        0,
        None,
        "ciphertext-genesis",
    );
    let v1 = build_envelope(
        &actor_id,
        &device_id,
        &series_id,
        1,
        Some(&genesis),
        "ciphertext-rotated-1",
    );
    let v2 = build_envelope(
        &actor_id,
        &device_id,
        &series_id,
        2,
        Some(&v1),
        "ciphertext-rotated-2",
    );
    let chain = vec![genesis, v1, v2];

    println!(
        "built {} envelopes in series {}",
        chain.len(),
        series_id.as_str()
    );

    // Validate chain locally as a recovery walker would.
    validate_chain(&chain).expect("chain must be well-formed");
    println!("chain validates cleanly");

    // The real recovery flow: GET /_cokret/self/keys/backups?series_id=<sid>,
    // sort by series_seq, walk genesis → head verifying supersedes_digest
    // against the prior envelope's ciphertext_digest at each step.
    let recovery_path = format!(
        "/_cokret/self/keys/backups?series_id={}",
        series_id.as_str()
    );
    println!("recovery list path: {recovery_path}");

    let head = chain.last().expect("non-empty chain");
    println!(
        "head envelope: backup_id={} series_seq={} frontier_ref={:?}",
        head.backup_id.as_str(),
        head.series_seq,
        head.frontier_ref
    );

    Ok(())
}
