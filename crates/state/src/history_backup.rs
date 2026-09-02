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
    ArchiveAuthorizationTuple, HistoryCandidateOriginAttribution,
    OrganizationRecoveryArchiveListOutcome, OrganizationRecoveryArchiveListQuery,
    OrganizationRecoveryArchiveReplica, OrganizationRecoveryArchiveReplicaOutcome,
    PortableBackupOriginRef, PortableBackupQuotaDomain,
};
use arkret_models_crypto::{KeyBackupKeybag, KeyBackupPlaintext};
use arkret_wire::base64url::{base64url_decode, base64url_encode};
use arkret_wire::canonical::sha256_digest;
use arkret_wire::{
    ActorId, Hash, HistoryCandidateMaterialKey, HistoryEffectiveScope, HistorySecretRange,
    LocalAuthoritativeHistorySecret, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

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

/// Exact local coordinate protected by the organization-recovery archive GC
/// barrier.
///
/// The spec deliberately leaves the private database layout unspecified. This
/// value is therefore a deterministic decision input, not a wire object or a
/// prescribed storage row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrganizationRecoveryArchiveGcCoordinate {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub container_event_ref: arkret_wire::EventId,
    pub archive_authorization_tuple_digest: Hash,
}

/// Source-local evidence required before deleting one MLS history secret under
/// `organization_recovery_key` durability.
///
/// Callers must persist updates made by [`Self::record_durable_holder_acceptance`]
/// and [`Self::record_exact_holder_reread`] atomically with their own replica
/// receipt and barrier result. The helper owns the fail-closed comparison logic
/// while leaving transaction and table layout to the service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrganizationRecoveryArchiveGcLedger {
    pub coverage_coordinate: OrganizationRecoveryArchiveGcCoordinate,
    pub durable_holder_acceptance: bool,
    pub exact_holder_reread: bool,
    pub covered_epochs: Vec<u64>,
    pub local_history_secret_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_replica_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_receipt_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_archive_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_container_event_ref: Option<arkret_wire::EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_traversal_intent_digest: Option<Hash>,
    #[serde(skip)]
    accepted_replica: Option<OrganizationRecoveryArchiveReplica>,
    #[serde(skip)]
    first_receipt: Option<OrganizationRecoveryArchiveReplicaOutcome>,
}

/// Result of admitting an archive replica receipt into the local GC barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrganizationRecoveryArchiveReplicaAdmission {
    FirstAccepted,
    ExactDuplicate,
}

impl OrganizationRecoveryArchiveGcLedger {
    /// Start tracking one exact local history secret and its already-created
    /// archive replica. No durability is inferred merely from constructing or
    /// sending the replica.
    pub fn new(replica: &OrganizationRecoveryArchiveReplica) -> Result<Self> {
        replica.validate()?;
        let tuple = archive_authorization_tuple(&replica.archive);
        Ok(Self {
            coverage_coordinate: OrganizationRecoveryArchiveGcCoordinate {
                effective_scope: replica.archive.effective_scope.clone(),
                mls_group_id: replica.archive.mls_group_id.clone(),
                epoch: replica.archive.epoch,
                container_event_ref: replica.container_event_ref.clone(),
                archive_authorization_tuple_digest: tuple.archive_authorization_tuple_digest()?,
            },
            durable_holder_acceptance: false,
            exact_holder_reread: false,
            covered_epochs: Vec::new(),
            local_history_secret_present: true,
            archive_replica_digest: None,
            first_receipt_digest: None,
            exact_archive_digest: None,
            exact_container_event_ref: None,
            exact_traversal_intent_digest: None,
            accepted_replica: None,
            first_receipt: None,
        })
    }

    /// Record the holder's first durable acceptance, or recognize a byte-exact
    /// retry. Any later semantic retry whose replica or receipt bytes differ is
    /// a conflict and cannot refresh the GC barrier.
    pub fn record_durable_holder_acceptance(
        &mut self,
        replica: &OrganizationRecoveryArchiveReplica,
        receipt: &OrganizationRecoveryArchiveReplicaOutcome,
    ) -> Result<OrganizationRecoveryArchiveReplicaAdmission> {
        replica.validate()?;
        receipt.validate()?;
        let replica_digest = replica.archive_replica_digest()?;
        if receipt.archive_replica_digest != replica_digest
            || receipt.holder_id != replica.holder_id
            || replica.holder_id != replica.archive.holder_id
            || self.coverage_coordinate != Self::new(replica)?.coverage_coordinate
        {
            return Err(WireError::Protocol(
                "organization recovery archive acceptance does not bind the exact GC coordinate"
                    .to_owned(),
            ));
        }

        if let (Some(accepted), Some(first_receipt)) = (&self.accepted_replica, &self.first_receipt)
        {
            if accepted == replica && first_receipt == receipt {
                return Ok(OrganizationRecoveryArchiveReplicaAdmission::ExactDuplicate);
            }
            return Err(WireError::Protocol(
                "organization recovery archive acceptance conflicts with the first durable bytes"
                    .to_owned(),
            ));
        }

        let receipt_digest = Hash::new(sha256_digest(
            arkret_wire::canonical::canonical_json_bytes(receipt)?,
        ))?;
        self.durable_holder_acceptance = true;
        self.archive_replica_digest = Some(replica_digest);
        self.first_receipt_digest = Some(receipt_digest);
        self.accepted_replica = Some(replica.clone());
        self.first_receipt = Some(receipt.clone());
        Ok(OrganizationRecoveryArchiveReplicaAdmission::FirstAccepted)
    }

    /// Apply the holder-bound list barrier only when it returns the exact
    /// archive, container Event and archive-lifetime traversal retention that
    /// were durably accepted.
    pub fn record_exact_holder_reread(
        &mut self,
        query: &OrganizationRecoveryArchiveListQuery,
        outcome: &OrganizationRecoveryArchiveListOutcome,
    ) -> Result<()> {
        query.validate()?;
        outcome.validate()?;
        let replica = self.accepted_replica.as_ref().ok_or_else(|| {
            WireError::Protocol(
                "organization recovery archive GC requires durable holder acceptance".to_owned(),
            )
        })?;
        let receipt = self.first_receipt.as_ref().ok_or_else(|| {
            WireError::Protocol(
                "organization recovery archive GC requires the first durable receipt".to_owned(),
            )
        })?;
        let archive = &replica.archive;
        if query.effective_scope != archive.effective_scope
            || query.recovery_key_id != archive.recovery_key_id
            || query.key_agreement_ref != archive.key_agreement_ref
            || query.accepted_key_evidence_ref != archive.accepted_key_evidence_ref
            || query.holder_trusted_basis != archive.holder_trusted_basis
            || query.from_epoch != Some(archive.epoch)
            || query.to_epoch != Some(archive.epoch)
            || query.cursor.is_some()
            || outcome.limited
            || outcome.cursor.is_some()
            || outcome.items.len() != 1
        {
            return Err(WireError::Protocol(
                "organization recovery archive barrier did not resolve the exact accepted row"
                    .to_owned(),
            ));
        }
        let item = &outcome.items[0];
        if item.archive_sequence != receipt.archive_sequence
            || item.archive_replica_digest != receipt.archive_replica_digest
            || item.archive != replica.archive
            || item.container_event_ref != replica.container_event_ref
            || item.history_traversal_retention != replica.history_traversal_retention
        {
            return Err(WireError::Protocol(
                "organization recovery archive barrier bytes differ from the durable replica"
                    .to_owned(),
            ));
        }

        self.exact_holder_reread = true;
        self.covered_epochs = vec![archive.epoch];
        self.exact_archive_digest = Some(archive.archive_digest()?);
        self.exact_container_event_ref = Some(replica.container_event_ref.clone());
        self.exact_traversal_intent_digest = Some(
            replica
                .history_traversal_retention
                .traversal_intent_digest
                .clone(),
        );
        Ok(())
    }

    /// Delete the source-local secret only after both durable barriers are
    /// present for this exact epoch. Repeated deletion is rejected rather than
    /// being mistaken for fresh coverage.
    pub fn gc_local_history_secret(&mut self) -> Result<()> {
        if !self.durable_holder_acceptance
            || !self.exact_holder_reread
            || self.covered_epochs != [self.coverage_coordinate.epoch]
            || self.archive_replica_digest.is_none()
            || self.first_receipt_digest.is_none()
            || self.exact_archive_digest.is_none()
            || self.exact_container_event_ref.as_ref()
                != Some(&self.coverage_coordinate.container_event_ref)
            || self.exact_traversal_intent_digest.is_none()
            || !self.local_history_secret_present
        {
            return Err(WireError::Protocol(
                "failed_precondition: organization recovery archive durability barrier incomplete"
                    .to_owned(),
            ));
        }
        self.local_history_secret_present = false;
        Ok(())
    }
}

fn archive_authorization_tuple(
    archive: &arkret_wire::OrganizationRecoveryArchive,
) -> ArchiveAuthorizationTuple {
    ArchiveAuthorizationTuple {
        recovery_key_id: archive.recovery_key_id.clone(),
        key_agreement_ref: archive.key_agreement_ref.clone(),
        controller_id: archive.controller_id.clone(),
        holder_id: archive.holder_id.clone(),
        holder_signing_ref: archive.holder_signing_ref.clone(),
        accepted_key_evidence_ref: archive.accepted_key_evidence_ref.clone(),
        holder_trusted_basis: archive.holder_trusted_basis.clone(),
    }
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
        return Err(WireError::Protocol(
            "mls_history key backup must pack at least one local-authoritative secret".to_owned(),
        ));
    }
    if kdf_nh == 0 {
        return Err(WireError::Protocol(
            "MLS ciphersuite KDF.Nh must be positive".to_owned(),
        ));
    }
    let mls_ciphersuite = &secrets[0].mls_ciphersuite;
    let mut by_epoch: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for secret in secrets {
        secret.validate()?;
        if &secret.effective_scope != effective_scope {
            return Err(WireError::Protocol(
                "mls_history key backup object must belong to one exporter effective scope"
                    .to_owned(),
            ));
        }
        if &secret.mls_ciphersuite != mls_ciphersuite {
            return Err(WireError::Protocol(
                "mls_history key backup object must not mix MLS ciphersuites".to_owned(),
            ));
        }
        let bytes = base64url_decode(&secret.secret_b64u)?;
        if bytes.len() != kdf_nh {
            return Err(WireError::Protocol(format!(
                "local-authoritative history secret for epoch {} is {} bytes; expected KDF.Nh {kdf_nh}",
                secret.epoch,
                bytes.len()
            )));
        }
        match by_epoch.insert(secret.epoch, bytes) {
            Some(previous) if previous != by_epoch[&secret.epoch] => {
                return Err(WireError::Protocol(format!(
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
    producer_actor_id: &ActorId,
    kdf_nh: usize,
    first_observed_at: DateTime<Utc>,
) -> Result<Vec<RestoredHistoryCandidate>> {
    let KeyBackupKeybag::MlsHistory {
        effective_scope,
        items,
    } = &plaintext.keybag
    else {
        return Err(WireError::Protocol(
            "history restore applies only to mls_history keybags".to_owned(),
        ));
    };
    let mls_group_id = effective_scope.canonical_mls_group_id()?;
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
                .ok_or_else(|| {
                    WireError::Protocol("restored history epoch overflows".to_owned())
                })?;
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
    use arkret_models_collaboration::history_key::{
        OrganizationRecoveryArchiveListOutcome, OrganizationRecoveryArchiveListQuery,
        OrganizationRecoveryArchiveReplica, OrganizationRecoveryArchiveReplicaOutcome,
    };
    use arkret_wire::{AccountId, BackupId, BackupSeriesId, DidCoreId, EventId, RealmId};

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
        let producer = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:acme.example:users:alice").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
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
        let producer = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:acme.example:users:alice").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
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

    #[test]
    fn rrk_archive_fixture_executes_the_durable_before_gc_barrier() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let kat = &fixture["organization_recovery_archive_durable_before_gc_kat"];
        let replica: OrganizationRecoveryArchiveReplica =
            serde_json::from_value(kat["replica"].clone()).unwrap();
        let receipt: OrganizationRecoveryArchiveReplicaOutcome =
            serde_json::from_value(kat["first_receipt"].clone()).unwrap();
        let query: OrganizationRecoveryArchiveListQuery =
            serde_json::from_value(kat["barrier_query"].clone()).unwrap();
        let outcome: OrganizationRecoveryArchiveListOutcome =
            serde_json::from_value(kat["barrier_resolve_outcome"].clone()).unwrap();

        let mut ledger = OrganizationRecoveryArchiveGcLedger::new(&replica).unwrap();
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            kat["coverage_ledger"]["initial"]
        );
        assert!(ledger.gc_local_history_secret().is_err());

        assert_eq!(
            ledger
                .record_durable_holder_acceptance(&replica, &receipt)
                .unwrap(),
            OrganizationRecoveryArchiveReplicaAdmission::FirstAccepted
        );
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            kat["coverage_ledger"]["after_first_accept"]
        );
        assert_eq!(
            ledger
                .record_durable_holder_acceptance(&replica, &receipt)
                .unwrap(),
            OrganizationRecoveryArchiveReplicaAdmission::ExactDuplicate
        );
        assert_eq!(
            arkret_wire::canonical::canonical_json_bytes(&receipt).unwrap(),
            base64url_decode(kat["first_receipt_jcs_b64u"].as_str().unwrap()).unwrap()
        );

        let mut changed_replica = replica.clone();
        changed_replica.replicated_at += chrono::Duration::seconds(3);
        assert!(
            ledger
                .record_durable_holder_acceptance(&changed_replica, &receipt)
                .is_err()
        );

        let mut changed_outcome = outcome.clone();
        let ciphertext = &mut changed_outcome.items[0].archive.ciphertext;
        ciphertext.replace_range(
            0..1,
            if ciphertext.starts_with('A') {
                "B"
            } else {
                "A"
            },
        );
        assert!(
            ledger
                .record_exact_holder_reread(&query, &changed_outcome)
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            kat["coverage_ledger"]["after_first_accept"]
        );

        ledger.record_exact_holder_reread(&query, &outcome).unwrap();
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            kat["coverage_ledger"]["after_exact_reread"]
        );
        ledger.gc_local_history_secret().unwrap();
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            kat["coverage_ledger"]["after_local_gc"]
        );
    }
}
