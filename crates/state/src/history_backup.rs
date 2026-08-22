//! Portable `mls_history` key-backup packing and restore.
//!
//! `zh/identity/key-management.md` §7.1 and
//! `zh/governance/history-visibility.md:417-418` bound what may cross the
//! portable-backup boundary in each direction, and both directions are asymmetric
//! on purpose:
//!
//! * **Out**: only `local_authoritative` secrets may be written, and one object belongs to exactly
//!   one exporter effective scope. A candidate that already decrypted an Event still MUST NOT be
//!   packed; it stays in the device-bound multi-candidate store (`key-management.md:866-869`).
//! * **In**: restoring on another endpoint does not re-create authority. Every unpacked epoch
//!   secret comes back as an ordinary `external_candidate` with `portable_backup` provenance and
//!   enters the bounded ledger in [`crate::history_store`] like any other received material.
//!
//! The scope half is already carried by the type system: `KeyBackupKeybag`'s
//! `mls_history` branch has exactly one `effective_scope` and only that branch
//! packs [`HistorySecretRange`]. This module adds the authority half.

use std::collections::BTreeMap;

use arkret_models_collaboration::history_key::{
    HistoryCandidateOriginAttribution, PortableBackupOriginRef, PortableBackupQuotaDomain,
};
use arkret_models_crypto::{KeyBackupKeybag, KeyBackupPlaintext};
use arkret_wire::base64url::{base64url_decode, base64url_encode};
use arkret_wire::canonical::sha256_digest;
use arkret_wire::{
    DidCoreId, Error, HISTORY_STORE_LIMITS, Hash, HistoryCandidateMaterialKey,
    HistoryEffectiveScope, HistorySecretRange, LocalAuthoritativeHistorySecret, Result,
};
use chrono::{DateTime, Utc};

/// One restored epoch secret, ready for
/// [`crate::history_store::HistoryMaterialLedger::admit_received_candidate`].
///
/// It carries no authority: the attribution is always the `portable_backup`
/// branch, and the caller stores the bytes as received candidate material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoredHistoryCandidate {
    pub attribution: HistoryCandidateOriginAttribution,
    pub secret: Vec<u8>,
}

/// Pack `local_authoritative` secrets for one exporter effective scope into the
/// closed `mls_history` keybag.
///
/// The input type is the whole point: [`LocalAuthoritativeHistorySecret`] is
/// only constructible from a verified, applied and durable local MLS
/// post-state, so no received candidate can reach a portable backup even if it
/// has successfully decrypted an Event.
///
/// `kdf_nh` MUST come from the exact winning transition resolved by
/// receipt-bound direct Seal replay; the backup never self-reports its suite
/// (`key-management.md:861-863`). Every record must name the same registered
/// ciphersuite, otherwise one packed object would mix two secret widths.
///
/// Epochs are packed into maximal contiguous runs, so the public range index
/// stays sorted, disjoint and non-adjacent without any guessing about epoch
/// counts (`history-recovery-scalability-registry.json#/backup/rule`).
pub fn pack_local_authoritative_history_backup(
    effective_scope: &HistoryEffectiveScope,
    secrets: &[LocalAuthoritativeHistorySecret],
    kdf_nh: usize,
) -> Result<KeyBackupKeybag> {
    if secrets.is_empty() {
        return Err(Error::Protocol(
            "mls_history key backup must pack at least one local-authoritative secret".to_owned(),
        ));
    }
    if kdf_nh == 0 {
        return Err(Error::Protocol(
            "MLS ciphersuite KDF.Nh must be positive".to_owned(),
        ));
    }
    let mls_ciphersuite = &secrets[0].mls_ciphersuite;
    let mut by_epoch: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for secret in secrets {
        secret.validate()?;
        if &secret.effective_scope != effective_scope {
            return Err(Error::Protocol(
                "mls_history key backup object must belong to one exporter effective scope"
                    .to_owned(),
            ));
        }
        if &secret.mls_ciphersuite != mls_ciphersuite {
            return Err(Error::Protocol(
                "mls_history key backup object must not mix MLS ciphersuites".to_owned(),
            ));
        }
        let bytes = base64url_decode(&secret.secret_b64u)?;
        if bytes.len() != kdf_nh {
            return Err(Error::Protocol(format!(
                "local-authoritative history secret for epoch {} is {} bytes; expected KDF.Nh {kdf_nh}",
                secret.epoch,
                bytes.len()
            )));
        }
        match by_epoch.insert(secret.epoch, bytes) {
            Some(previous) if previous != by_epoch[&secret.epoch] => {
                return Err(Error::Protocol(format!(
                    "two different local-authoritative secrets are retained for epoch {}",
                    secret.epoch
                )));
            }
            _ => {}
        }
    }

    let mut items: Vec<HistorySecretRange> = Vec::new();
    for (epoch, bytes) in by_epoch {
        match items.last_mut() {
            Some(range) if range.to_epoch + 1 == epoch => {
                range.to_epoch = epoch;
                let mut packed = base64url_decode(&range.secrets_b64u)?;
                packed.extend_from_slice(&bytes);
                range.secrets_b64u = base64url_encode(&packed);
            }
            _ => items.push(HistorySecretRange {
                from_epoch: epoch,
                to_epoch: epoch,
                secrets_b64u: base64url_encode(&bytes),
            }),
        }
    }
    for item in &items {
        item.validate_packed_length(kdf_nh)?;
    }
    Ok(KeyBackupKeybag::MlsHistory {
        effective_scope: effective_scope.clone(),
        items,
    })
}

/// Unpack a restored `mls_history` keybag into `external_candidate`
/// admissions with `portable_backup` provenance.
///
/// The quota domain is the stable `(backup_series_id, producer_actor_id)` pair
/// and the retrieval coordinate is the individual envelope, exactly as the
/// closed `history_candidate_origin_attribution` branch requires: swapping
/// envelopes never changes the quota identity and a backup origin is never a
/// sender identity (`history-visibility.md:424-427`).
///
/// `producer_actor_id` is the actor whose accepted device key signed the
/// envelope metadata; resolve it from the PCR authorization chain before
/// calling, because the plaintext deliberately carries no producer field.
pub fn restore_history_backup_candidates(
    plaintext: &KeyBackupPlaintext,
    producer_actor_id: &DidCoreId,
    kdf_nh: usize,
    first_observed_at: DateTime<Utc>,
) -> Result<Vec<RestoredHistoryCandidate>> {
    let KeyBackupKeybag::MlsHistory {
        effective_scope,
        items,
    } = &plaintext.keybag
    else {
        return Err(Error::Protocol(
            "history restore applies only to mls_history keybags".to_owned(),
        ));
    };
    let mls_group_id = effective_scope.canonical_mls_group_id()?;
    let expires_at = first_observed_at
        .checked_add_signed(chrono::Duration::seconds(
            HISTORY_STORE_LIMITS.origin_attribution_ttl_seconds,
        ))
        .ok_or_else(|| Error::Protocol("history candidate origin expiry overflows".to_owned()))?;
    let origin_quota_domain = PortableBackupQuotaDomain {
        backup_series_id: plaintext.series_id.to_string(),
        producer_actor_id: producer_actor_id.clone(),
    };
    let origin_ref = PortableBackupOriginRef {
        backup_origin_id: format!("backup:{}", plaintext.backup_id),
    };

    let mut restored = Vec::new();
    for item in items {
        item.validate_packed_length(kdf_nh)?;
        let packed = base64url_decode(&item.secrets_b64u)?;
        for (index, secret) in packed.chunks_exact(kdf_nh).enumerate() {
            let epoch = u64::try_from(index)
                .ok()
                .and_then(|offset| item.from_epoch.checked_add(offset))
                .ok_or_else(|| Error::Protocol("restored history epoch overflows".to_owned()))?;
            let attribution = HistoryCandidateOriginAttribution::PortableBackup {
                material_key: HistoryCandidateMaterialKey {
                    effective_scope: effective_scope.clone(),
                    mls_group_id: mls_group_id.clone(),
                    epoch,
                    candidate_digest: Hash::new(sha256_digest(secret))?,
                },
                origin_quota_domain: origin_quota_domain.clone(),
                origin_ref: origin_ref.clone(),
                first_observed_at,
                expires_at,
            };
            attribution.validate()?;
            restored.push(RestoredHistoryCandidate {
                attribution,
                secret: secret.to_vec(),
            });
        }
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{BackupId, BackupSeriesId, EventId, RealmId};

    use super::*;

    const KDF_NH: usize = 32;

    fn scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
        }
    }

    fn local_secret(epoch: u64, byte: u8) -> LocalAuthoritativeHistorySecret {
        let effective_scope = scope();
        LocalAuthoritativeHistorySecret {
            mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
            effective_scope,
            epoch,
            mls_ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            local_state_ref: "arkret/mls-state/v1/realm/7".to_owned(),
            transition_ref: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            transition_event_digest: Hash::new(sha256_digest([byte; 4])).unwrap(),
            mls_transition_digest: Hash::new(sha256_digest([byte; 8])).unwrap(),
            secret_b64u: base64url_encode([byte; KDF_NH]),
        }
    }

    #[test]
    fn contiguous_epochs_pack_into_one_range_and_gaps_split_it() {
        let keybag = pack_local_authoritative_history_backup(
            &scope(),
            &[
                local_secret(1, 1),
                local_secret(2, 2),
                local_secret(5, 5),
                local_secret(3, 3),
            ],
            KDF_NH,
        )
        .unwrap();
        let KeyBackupKeybag::MlsHistory { items, .. } = keybag else {
            panic!("mls_history keybag");
        };
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].from_epoch, items[0].to_epoch), (1, 3));
        assert_eq!((items[1].from_epoch, items[1].to_epoch), (5, 5));
        assert_eq!(base64url_decode(&items[0].secrets_b64u).unwrap().len(), 96);
    }

    #[test]
    fn a_restored_backup_comes_back_as_portable_backup_candidates() {
        let keybag = pack_local_authoritative_history_backup(
            &scope(),
            &[local_secret(7, 7), local_secret(8, 8)],
            KDF_NH,
        )
        .unwrap();
        let plaintext = KeyBackupPlaintext {
            schema: KeyBackupPlaintext::SCHEMA.to_owned(),
            backup_id: BackupId::new("ak:backup:01964137-0000-7000-8000-000000000000").unwrap(),
            series_id: BackupSeriesId::new("ak:backup_series:01964137-0000-7000-8000-000000000001")
                .unwrap(),
            series_seq: 3,
            keybag,
            extra: Default::default(),
        };
        let producer = DidCoreId::new("ak:did_core:web:acme.example:users:alice").unwrap();
        let now = Utc::now();
        let restored =
            restore_history_backup_candidates(&plaintext, &producer, KDF_NH, now).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].secret, vec![7_u8; KDF_NH]);
        assert_eq!(restored[1].secret, vec![8_u8; KDF_NH]);
        for (offset, candidate) in restored.iter().enumerate() {
            let HistoryCandidateOriginAttribution::PortableBackup {
                material_key,
                origin_quota_domain,
                origin_ref,
                ..
            } = &candidate.attribution
            else {
                panic!("restored material must carry portable_backup provenance");
            };
            assert_eq!(material_key.epoch, 7 + offset as u64);
            assert_eq!(
                material_key.candidate_digest,
                Hash::new(sha256_digest(&candidate.secret)).unwrap()
            );
            assert_eq!(
                origin_quota_domain.backup_series_id,
                "ak:backup_series:01964137-0000-7000-8000-000000000001"
            );
            assert_eq!(origin_quota_domain.producer_actor_id, producer);
            assert_eq!(
                origin_ref.backup_origin_id,
                "backup:ak:backup:01964137-0000-7000-8000-000000000000"
            );
        }
    }

    #[test]
    fn a_secret_storage_keybag_is_not_a_history_restore() {
        let plaintext = KeyBackupPlaintext {
            schema: KeyBackupPlaintext::SCHEMA.to_owned(),
            backup_id: BackupId::new("ak:backup:01964137-0000-7000-8000-000000000000").unwrap(),
            series_id: BackupSeriesId::new("ak:backup_series:01964137-0000-7000-8000-000000000001")
                .unwrap(),
            series_seq: 1,
            keybag: KeyBackupKeybag::SecretStorage { items: Vec::new() },
            extra: Default::default(),
        };
        let producer = DidCoreId::new("ak:did_core:web:acme.example:users:alice").unwrap();
        assert!(
            restore_history_backup_candidates(&plaintext, &producer, KDF_NH, Utc::now()).is_err()
        );
    }

    #[test]
    fn a_second_effective_scope_cannot_enter_one_object() {
        let other = HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")
                .unwrap(),
        };
        assert!(
            pack_local_authoritative_history_backup(&other, &[local_secret(1, 1)], KDF_NH).is_err()
        );
    }

    #[test]
    fn a_wrong_width_secret_is_refused_rather_than_packed() {
        let mut secret = local_secret(1, 1);
        secret.secret_b64u = base64url_encode([1_u8; 16]);
        assert!(pack_local_authoritative_history_backup(&scope(), &[secret], KDF_NH).is_err());
    }
}
