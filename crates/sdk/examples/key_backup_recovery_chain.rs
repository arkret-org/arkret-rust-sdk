//! Build a series-chained `KeyBackup` envelope chain and walk recovery via
//! the `?series_id=` listing shape exposed by `ak.self.keys.backups.query.list` (spec
//! head 37ce729 / key-management.md §7.4 "key-backup hardening").
//!
//! The chain semantics this example exercises:
//!
//! * Every envelope in a chain shares the same `series_id` (a `ak:backup_series:` strict-typed id).
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

use arkret::models::{
    BackupClass, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupContentItem, KeyBackupDomainSeparation, KeyBackupDomainSeparationAad,
    KeyBackupEncryption, KeyBackupFrontierRef, KeyBackupKdf, KeyBackupKdfName, KeyBackupKdfParams,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm,
};
use arkret::{BackupId, BackupSeriesId, Base64UrlString, DeviceId, Did, DidUrl, Hash};

fn build_envelope(
    actor_id: &Did,
    device_id: &DeviceId,
    series_id: &BackupSeriesId,
    seq: u64,
    predecessor: Option<&KeyBackup>,
    ciphertext: &str,
) -> KeyBackup {
    let backup_id_str = format!(
        "ak:backup:01964137-0000-7000-8000-{:012x}",
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
    let created_at = chrono::Utc::now();

    KeyBackup {
        backup_id: BackupId::new(&backup_id_str).expect("valid backup_id"),
        actor_id: actor_id.clone(),
        device_id: Some(device_id.clone()),
        backup_class: BackupClass::SecretStorage,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::PassphraseKdf,
            recipient_key_ref: None,
            kdf: Some(KeyBackupKdf {
                name: KeyBackupKdfName::Argon2id,
                salt: Base64UrlString::new(format!("salt-{seq}")).expect("valid KDF salt"),
                params: KeyBackupKdfParams {
                    memory_kib: Some(65_536),
                    iterations: Some(3),
                    parallelism: Some(1),
                    digest_algorithm: None,
                    extra: Default::default(),
                },
                degraded_profile_reason: None,
                extra: Default::default(),
            }),
            aead: KeyBackupAead {
                name: KeyBackupAeadName::Xchacha20Poly1305,
                aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                nonce: Some(Base64UrlString::new(format!("nonce-{seq}")).expect("valid nonce")),
                nonce_salt: Some(
                    Base64UrlString::new(format!("nonce-salt-{seq}")).expect("valid nonce salt"),
                ),
                enc: None,
                extra: Default::default(),
            },
            key_commitment: Some(format!(
                "sha256:{:0>64}",
                format!("{seq:02x}")
                    .repeat(32)
                    .chars()
                    .rev()
                    .take(64)
                    .collect::<String>()
            )),
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            hkdf_info: "arkret-key-backup/secret_storage/recovery/v1".to_owned(),
            subdomain: "recovery".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ak.schema.key_backup.v1".to_owned(),
                actor_id: actor_id.clone(),
                device_id: Some(device_id.as_str().to_owned()),
                backup_class: BackupClass::SecretStorage,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_types: vec!["recovery_secret".to_owned()],
                managed_principal_bindings: Vec::new(),
                recipient_method: None,
                recipient_key_ref: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "recovery_secret".to_owned(),
            realm_id: None,
            managed_principal_binding: None,
            mls_group_id: None,
            epoch: Some(seq),
            first_event_id: None,
            last_event_id: None,
            secret_id: Some(format!("recovery-{seq}")),
            secret_version: Some(seq as u32),
            extra: Default::default(),
        }],
        ciphertext: ciphertext.to_owned(),
        ciphertext_digest,
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: device_id.clone(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1")
                .expect("valid verification method"),
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new(format!("sig-{seq}")).expect("valid signature token"),
            ssk_generation: std::num::NonZeroU64::new(1),
            device_authorize_event_id: None,
            signed_fields: vec![
                "backup_id".to_owned(),
                "actor_id".to_owned(),
                "backup_class".to_owned(),
                "backup_version".to_owned(),
                "encryption".to_owned(),
                "domain_separation".to_owned(),
                "contents".to_owned(),
                "ciphertext_digest".to_owned(),
                "series_id".to_owned(),
                "series_seq".to_owned(),
            ],
            extra: Default::default(),
        }),
        retention: None,
        series_id: series_id.clone(),
        series_seq: seq,
        supersedes,
        supersedes_digest,
        frontier_ref: Some(KeyBackupFrontierRef {
            frontier_digest: Hash::new(format!("sha256:{:0>64}", format!("{seq:02x}")))
                .expect("valid frontier digest"),
            seal_ref: None,
            generation: arkret::KeyBackupFrontierGeneration::SskGeneration(
                std::num::NonZeroU64::new(1).unwrap(),
            ),
        }),
        recovery_policy_ref: None,
        extra: Default::default(),
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

fn main() -> arkret::Result<()> {
    let actor_id = Did::new("did:webvh:z6mkfixture:alice.example")?;
    let device_id = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000009")?;
    let series_id = BackupSeriesId::new("ak:backup_series:01964137-0000-7000-8000-000000000777")?;

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

    // The real recovery strand: GET /_arkret/self/keys/backups?series_id=<sid>,
    // sort by series_seq, walk genesis → head verifying supersedes_digest
    // against the prior envelope's ciphertext_digest at each step.
    let recovery_path = format!(
        "/_arkret/self/keys/backups?series_id={}",
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
