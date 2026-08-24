//! Bounded device-local history-only store.
//!
//! `zh/governance/history-visibility.md` §7 and the machine-readable
//! `history-recovery-scalability-registry.json#/history_store` section define
//! one deterministic admission/eviction algebra for received history-secret
//! material. This module is its only implementation; clients own durability
//! and the secret bytes themselves, never the decisions.
//!
//! Three separations are structural rather than checked at run time:
//!
//! * **Bytes are not here.** The ledger holds material keys, immutable sequences, origin
//!   attribution and Event bindings. Secret bytes live in the caller's secure key store, so no
//!   ledger row can pin them (`history-visibility.md:437-439`).
//! * **`local_authoritative` is not here.** It is a separate record class
//!   ([`arkret_wire::LocalAuthoritativeHistorySecret`]) that consumes no received slot; because it
//!   cannot be represented in this ledger it can never be selected as an eviction victim
//!   (`:443-444`).
//! * **No epoch-level state.** Nothing in the ledger says an epoch is verified: an AEAD result only
//!   ever becomes one [`EventCandidateBinding`] row (`:140`, `:437-440`).

use std::collections::BTreeSet;

use arkret_models_collaboration::history_key::HistoryCandidateOriginAttribution;
use arkret_wire::{
    EventCandidateBinding, EventCandidateBindingKey, EventCandidateBindingOutcome,
    HISTORY_STORE_LIMITS, Hash, HistoryCandidateMaterialKey, HistoryEffectiveScope, Result,
    WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One resident received-material byte instance.
///
/// `material_received_sequence` is assigned once, when the bytes first become
/// resident, and is immutable: a new origin for the same bytes only adds
/// attribution, and a refetch after eviction creates a new instance with a new
/// sequence (`history_store/material_dedupe_rule`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentHistoryMaterial {
    pub material_key: HistoryCandidateMaterialKey,
    pub material_received_sequence: u64,
}

/// The durable metadata half of the history-only store.
///
/// A client persists this verbatim and applies the byte-level side effects a
/// [`ReceivedMaterialPlan`] names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryMaterialLedger {
    pub next_material_received_sequence: u64,
    pub resident: Vec<ResidentHistoryMaterial>,
    pub origins: Vec<HistoryCandidateOriginAttribution>,
    pub event_bindings: Vec<EventCandidateBinding>,
}

/// The byte-store side effects of one admission, in the order a client must
/// apply them.
///
/// `store` must be durable before the ledger is persisted, so a resident row
/// never outlives its bytes; `evict` is applied after the ledger is persisted,
/// so bytes are never orphaned by a crash between the two writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[must_use = "an admission plan is only applied when its byte-store side effects are"]
pub struct ReceivedMaterialPlan {
    /// Bytes that must become resident for this key.
    pub store: Option<HistoryCandidateMaterialKey>,
    /// Bytes that must be deleted, in the deterministic order they were
    /// selected.
    pub evict: Vec<HistoryCandidateMaterialKey>,
    /// Whether the admitted candidate is resident once the plan is applied.
    /// It is `false` exactly when the attribution lost the origin-cap contest,
    /// because without a live origin row nothing could refetch the bytes.
    pub resident: bool,
}

impl HistoryMaterialLedger {
    /// Admit one received candidate: attribute it, enforce every
    /// `history_store` cap, and select eviction victims.
    ///
    /// `attribution` must already be verified against the carrier it arrived
    /// on; this call only enforces the ledger rules. The exact secret bytes are
    /// the caller's, and their SHA-256 must equal
    /// `material_key.candidate_digest` — check that before calling, because a
    /// ledger that never sees bytes cannot check it here.
    pub fn admit_received_candidate(
        &mut self,
        attribution: &HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> Result<ReceivedMaterialPlan> {
        attribution.validate()?;
        if attribution.expires_at()? <= now {
            return Err(WireError::Protocol(
                "history candidate origin attribution is already expired".to_owned(),
            ));
        }
        let material_key = attribution.material_key().clone();

        self.admit_origin_attribution(attribution, now)?;
        let attributed = self.has_origin_row(attribution)?;
        let already_resident = self.is_resident(&material_key);

        let mut plan = ReceivedMaterialPlan::default();
        if !already_resident {
            if !attributed {
                // The only reason to hold received bytes is a live origin row
                // that can refetch them; an attribution that lost the cap
                // contest never admits bytes.
                return Ok(plan);
            }
            // Eviction runs *before* the insert, so the arriving instance is
            // never its own victim and never competes with a sequence it does
            // not yet have (`history_store/material_eviction_rule`).
            while self.resident_count(&material_key)
                >= limits().max_received_candidates_per_scope_group_epoch
            {
                let victim = self
                    .plan_material_eviction(
                        &material_key.effective_scope,
                        &material_key.mls_group_id,
                        material_key.epoch,
                    )?
                    .map(|entry| entry.material_key.clone());
                let Some(victim) = victim else { break };
                self.resident.retain(|entry| entry.material_key != victim);
                plan.evict.push(victim);
            }
            let sequence = self.next_material_received_sequence;
            self.next_material_received_sequence = sequence.checked_add(1).ok_or_else(|| {
                WireError::Protocol("history material received sequence is exhausted".to_owned())
            })?;
            self.resident.push(ResidentHistoryMaterial {
                material_key: material_key.clone(),
                material_received_sequence: sequence,
            });
            plan.store = Some(material_key.clone());
        }
        plan.resident = self.is_resident(&material_key);
        Ok(plan)
    }

    /// Record one exact Event→candidate AEAD result.
    ///
    /// AEAD over a fixed `(Event, ciphertext, candidate)` triple is
    /// deterministic, so a stored row that contradicts a later attempt is a
    /// transcript contradiction and is refused rather than silently joined by
    /// a second outcome row.
    pub fn record_event_binding(
        &mut self,
        binding: &EventCandidateBinding,
        now: DateTime<Utc>,
    ) -> Result<()> {
        binding.validate()?;
        let mut live_bindings = Vec::with_capacity(self.event_bindings.len());
        for entry in self.event_bindings.drain(..) {
            if entry.expires_at()? > now {
                live_bindings.push(entry);
            }
        }
        self.event_bindings = live_bindings;
        match self.event_bindings.iter().find(|entry| {
            entry.event_binding_key == binding.event_binding_key
                && entry.candidate_digest == binding.candidate_digest
        }) {
            Some(existing) if existing.outcome != binding.outcome => {
                return Err(WireError::Protocol(format!(
                    "durable history Event candidate binding for {} contradicts the AEAD outcome",
                    binding.event_binding_key.event_id
                )));
            }
            Some(_) => {}
            None => self.event_bindings.push(binding.clone()),
        }
        self.bound_event_bindings(&binding.event_binding_key)
    }

    /// The durable binding for one exact `(event_binding_key, candidate)`, if
    /// any.
    pub fn event_binding(
        &self,
        event_binding_key: &EventCandidateBindingKey,
        candidate_digest: &Hash,
    ) -> Option<&EventCandidateBinding> {
        self.event_bindings.iter().find(|entry| {
            &entry.event_binding_key == event_binding_key
                && &entry.candidate_digest == candidate_digest
        })
    }

    /// Resident received material for one `(scope, group, epoch)`, in the
    /// deterministic `(material_received_sequence, candidate_digest)` order
    /// every caller must try candidates in.
    pub fn resident_for_epoch(
        &self,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> Vec<&ResidentHistoryMaterial> {
        let mut rows = self
            .resident
            .iter()
            .filter(|entry| {
                entry.material_key.effective_scope == *effective_scope
                    && entry.material_key.mls_group_id == mls_group_id
                    && entry.material_key.epoch == epoch
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.material_received_sequence
                .cmp(&right.material_received_sequence)
                .then_with(|| {
                    left.material_key
                        .candidate_digest
                        .cmp(&right.material_key.candidate_digest)
                })
        });
        rows
    }

    /// Two-tier deterministic eviction victim for one `(scope, group, epoch)`.
    ///
    /// Tier 1 is material with no `success` Event binding (unbound and
    /// failure-only); tier 2 is success-bound material. Within a tier the
    /// victim is the minimum of `(material_received_sequence ascending,
    /// candidate_digest UTF-8 ascending)`. Bindings only select the tier: they
    /// never pin bytes, and `local_authoritative` is unrepresentable here so it
    /// is never a victim (`history_store/material_eviction_rule`).
    pub fn plan_material_eviction(
        &self,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> Result<Option<&ResidentHistoryMaterial>> {
        Ok(self
            .resident_for_epoch(effective_scope, mls_group_id, epoch)
            .into_iter()
            .min_by_key(|entry| {
                (
                    self.has_success_binding(&entry.material_key),
                    entry.material_received_sequence,
                    entry.material_key.candidate_digest.as_str(),
                )
            }))
    }

    fn is_resident(&self, material_key: &HistoryCandidateMaterialKey) -> bool {
        self.resident
            .iter()
            .any(|entry| &entry.material_key == material_key)
    }

    fn resident_count(&self, material_key: &HistoryCandidateMaterialKey) -> usize {
        self.resident
            .iter()
            .filter(|entry| entry.material_key.is_same_scope_group_epoch(material_key))
            .count()
    }

    fn has_success_binding(&self, material_key: &HistoryCandidateMaterialKey) -> bool {
        self.event_bindings.iter().any(|binding| {
            binding.outcome == EventCandidateBindingOutcome::Success
                && binding.candidate_digest == material_key.candidate_digest
                && binding.event_binding_key.effective_scope == material_key.effective_scope
                && binding.event_binding_key.mls_group_id == material_key.mls_group_id
                && binding.event_binding_key.epoch == material_key.epoch
        })
    }

    fn has_origin_row(&self, attribution: &HistoryCandidateOriginAttribution) -> Result<bool> {
        for row in &self.origins {
            if row.is_same_row(attribution)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Prune expired rows, admit the exact row once, then enforce the three
    /// origin caps in the registry's order.
    fn admit_origin_attribution(
        &mut self,
        attribution: &HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut live_origins = Vec::with_capacity(self.origins.len());
        for row in self.origins.drain(..) {
            if row.expires_at()? > now {
                live_origins.push(row);
            }
        }
        self.origins = live_origins;
        if !self.has_origin_row(attribution)? {
            self.origins.push(attribution.clone());
        }
        let material_key = attribution.material_key().clone();
        retain_minimum_canonical(
            &mut self.origins,
            |row| Ok(row.material_key() == &material_key),
            HistoryCandidateOriginAttribution::canonical_retention_key,
            limits().max_origin_attributions_per_candidate,
        )?;
        retain_minimum_canonical(
            &mut self.origins,
            |row| row.is_same_quota_bucket(attribution),
            HistoryCandidateOriginAttribution::canonical_retention_key,
            limits().max_origin_attributions_per_scope_group_epoch_quota_domain,
        )?;
        retain_minimum_canonical(
            &mut self.origins,
            |row| Ok(row.material_key().is_same_scope_group_epoch(&material_key)),
            HistoryCandidateOriginAttribution::canonical_retention_key,
            limits().max_origin_attributions_per_scope_group_epoch,
        )
    }

    fn bound_event_bindings(&mut self, event_binding_key: &EventCandidateBindingKey) -> Result<()> {
        let effective_scope = event_binding_key.effective_scope.clone();
        let mls_group_id = event_binding_key.mls_group_id.clone();
        let epoch = event_binding_key.epoch;
        retain_minimum_canonical(
            &mut self.event_bindings,
            |binding| {
                Ok(binding.event_binding_key.effective_scope == effective_scope
                    && binding.event_binding_key.mls_group_id == mls_group_id
                    && binding.event_binding_key.epoch == epoch)
            },
            event_binding_retention_key,
            limits().max_event_candidate_bindings_per_scope_group_epoch,
        )
    }
}

fn limits() -> arkret_wire::HistoryStoreLimits {
    HISTORY_STORE_LIMITS
}

/// `(first_observed_at, event_id, verified_sender_domain,
/// candidate_digest, outcome)` — the canonical ascending order an over-cap
/// Event-binding ledger keeps the minimum of
/// (`history_store/event_candidate_binding_rule`).
///
/// `expires_at` uses the canonical fixed-millisecond form: chrono's default
/// trims trailing subsecond zeros, so `…:00Z` would sort after `…:00.500Z`.
fn event_binding_retention_key(binding: &EventCandidateBinding) -> Result<Vec<u8>> {
    arkret_wire::canonical::canonical_json_bytes(&serde_json::json!([
        arkret_wire::canonical::format_timestamp_canonical(binding.first_observed_at),
        binding.event_binding_key.event_id,
        binding.event_binding_key.verified_sender_domain,
        binding.candidate_digest,
        binding.outcome,
    ]))
    .map_err(Into::into)
}

/// Keep at most `maximum` members of the selected subset, dropping the rows
/// whose canonical retention key sorts largest. Rows outside the subset are
/// untouched, so applying the three origin caps in sequence is well defined.
fn retain_minimum_canonical<T>(
    rows: &mut Vec<T>,
    mut selects: impl FnMut(&T) -> Result<bool>,
    retention_key: impl Fn(&T) -> Result<Vec<u8>>,
    maximum: usize,
) -> Result<()> {
    let mut members = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if selects(row)? {
            members.push((retention_key(row)?, index));
        }
    }
    if members.len() <= maximum {
        return Ok(());
    }
    members.sort_by(|left, right| left.0.cmp(&right.0));
    let dropped = members
        .into_iter()
        .skip(maximum)
        .map(|(_, index)| index)
        .collect::<BTreeSet<_>>();
    let mut index = 0_usize;
    rows.retain(|_| {
        let keep = !dropped.contains(&index);
        index += 1;
        keep
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::history_key::{
        HistoryResponseId, ResponseSenderOriginRef, ResponseSenderQuotaDomain,
    };
    use arkret_wire::{EventId, RealmId};

    use super::*;

    fn scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
        }
    }

    fn digest(byte: u8) -> Hash {
        Hash::new(arkret_wire::canonical::sha256_digest([byte; 32])).unwrap()
    }

    fn material_key(candidate_digest: Hash) -> HistoryCandidateMaterialKey {
        let effective_scope = scope();
        HistoryCandidateMaterialKey {
            mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
            effective_scope,
            epoch: 4,
            candidate_digest,
        }
    }

    fn attribution(
        candidate_digest: Hash,
        sender_domain: &str,
        response_index: u8,
        now: DateTime<Utc>,
    ) -> HistoryCandidateOriginAttribution {
        HistoryCandidateOriginAttribution::ResponseSender {
            material_key: material_key(candidate_digest),
            origin_quota_domain: ResponseSenderQuotaDomain {
                source_sender_domain: sender_domain.to_owned(),
            },
            origin_ref: ResponseSenderOriginRef {
                response_id: HistoryResponseId::new(format!(
                    "ak:history_response:019a0000-0000-7000-8000-0000000000{response_index:02x}"
                ))
                .unwrap(),
                source_record_digest: digest(0xF0 ^ response_index),
            },
            first_observed_at: now,
        }
    }

    fn binding_key(candidate_scope: &HistoryCandidateMaterialKey) -> EventCandidateBindingKey {
        EventCandidateBindingKey {
            effective_scope: candidate_scope.effective_scope.clone(),
            mls_group_id: candidate_scope.mls_group_id.clone(),
            epoch: candidate_scope.epoch,
            event_id: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            verified_sender_domain: "ak:device:sender".to_owned(),
        }
    }

    #[test]
    fn equal_bytes_from_a_second_origin_do_not_refresh_the_material_sequence() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        let first = ledger
            .admit_received_candidate(&attribution(digest(1), "sender.one", 1, now), now)
            .unwrap();
        assert_eq!(first.store, Some(material_key(digest(1))));
        let sequence = ledger.resident[0].material_received_sequence;

        let second = ledger
            .admit_received_candidate(&attribution(digest(1), "sender.two", 2, now), now)
            .unwrap();
        assert_eq!(second.store, None);
        assert!(second.resident);
        assert_eq!(ledger.resident.len(), 1);
        assert_eq!(ledger.resident[0].material_received_sequence, sequence);
        assert_eq!(ledger.origins.len(), 2);
    }

    #[test]
    fn retention_order_does_not_depend_on_subsecond_precision() {
        // A whole-second expiry and a half-second one must order by time.
        // chrono's default RFC 3339 trims the `.000`, which would put the
        // whole second after the half second because `Z` > `.` in UTF-8.
        let whole = DateTime::parse_from_rfc3339("2026-08-23T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let half = DateTime::parse_from_rfc3339("2026-08-23T10:00:00.500Z")
            .unwrap()
            .with_timezone(&Utc);
        let ttl = chrono::Duration::seconds(HISTORY_STORE_LIMITS.origin_attribution_ttl_seconds);
        let earlier = attribution(digest(1), "sender.one", 1, whole - ttl)
            .canonical_retention_key()
            .unwrap();
        let later = attribution(digest(1), "sender.one", 2, half - ttl)
            .canonical_retention_key()
            .unwrap();
        assert!(earlier < later);
    }

    #[test]
    fn an_exact_duplicate_origin_row_is_a_no_op() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        let row = attribution(digest(1), "sender.one", 1, now);
        let _ = ledger.admit_received_candidate(&row, now).unwrap();
        let later = now + chrono::Duration::days(2);
        let _ = ledger.admit_received_candidate(&row, later).unwrap();
        assert_eq!(ledger.origins.len(), 1);
        assert_eq!(ledger.origins[0].first_observed_at(), now);
        assert_eq!(
            ledger.origins[0].expires_at().unwrap(),
            row.expires_at().unwrap()
        );
    }

    #[test]
    fn origin_attribution_is_capped_per_material_key() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        for index in 0..8_u8 {
            let _ = ledger
                .admit_received_candidate(&attribution(digest(1), "sender.one", index, now), now)
                .unwrap();
        }
        assert_eq!(
            ledger.origins.len(),
            HISTORY_STORE_LIMITS.max_origin_attributions_per_candidate
        );
    }

    #[test]
    fn the_ninth_candidate_evicts_the_lowest_unbound_material() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        for index in 1..=8_u8 {
            let _ = ledger
                .admit_received_candidate(
                    &attribution(digest(index), "sender.one", index, now),
                    now,
                )
                .unwrap();
        }
        assert_eq!(ledger.resident.len(), 8);
        // Bind the lowest sequence with a success so it moves to tier 2.
        let key = material_key(digest(1));
        ledger
            .record_event_binding(
                &EventCandidateBinding::new(
                    binding_key(&key),
                    digest(1),
                    EventCandidateBindingOutcome::Success,
                    now,
                )
                .unwrap(),
                now,
            )
            .unwrap();

        let plan = ledger
            .admit_received_candidate(&attribution(digest(9), "sender.one", 9, now), now)
            .unwrap();
        assert_eq!(plan.store, Some(material_key(digest(9))));
        assert_eq!(plan.evict, vec![material_key(digest(2))]);
        assert!(plan.resident);
        assert_eq!(ledger.resident.len(), 8);
        assert!(
            ledger
                .resident
                .iter()
                .any(|entry| entry.material_key.candidate_digest == digest(1))
        );
    }

    #[test]
    fn an_arriving_candidate_is_never_its_own_eviction_victim() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        for index in 1..=8_u8 {
            let _ = ledger
                .admit_received_candidate(
                    &attribution(digest(index), "sender.one", index, now),
                    now,
                )
                .unwrap();
            // Every resident instance is success-bound, so the arriving ninth
            // is the only tier-1 member and would win the minimum contest if
            // eviction ran after the insert.
            ledger
                .record_event_binding(
                    &EventCandidateBinding::new(
                        binding_key(&material_key(digest(index))),
                        digest(index),
                        EventCandidateBindingOutcome::Success,
                        now,
                    )
                    .unwrap(),
                    now,
                )
                .unwrap();
        }
        let plan = ledger
            .admit_received_candidate(&attribution(digest(9), "sender.one", 9, now), now)
            .unwrap();
        assert_eq!(plan.store, Some(material_key(digest(9))));
        assert_eq!(plan.evict, vec![material_key(digest(1))]);
        assert!(plan.resident);
    }

    #[test]
    fn eviction_keeps_the_bounded_origin_tombstone_for_refetch() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        for index in 1..=9_u8 {
            let _ = ledger
                .admit_received_candidate(
                    &attribution(digest(index), "sender.one", index, now),
                    now,
                )
                .unwrap();
        }
        assert_eq!(ledger.resident.len(), 8);
        assert_eq!(ledger.origins.len(), 9);
    }

    #[test]
    fn a_contradicting_event_binding_is_refused() {
        let now = Utc::now();
        let key = material_key(digest(1));
        let mut ledger = HistoryMaterialLedger::default();
        ledger
            .record_event_binding(
                &EventCandidateBinding::new(
                    binding_key(&key),
                    digest(1),
                    EventCandidateBindingOutcome::Failure,
                    now,
                )
                .unwrap(),
                now,
            )
            .unwrap();
        assert!(
            ledger
                .record_event_binding(
                    &EventCandidateBinding::new(
                        binding_key(&key),
                        digest(1),
                        EventCandidateBindingOutcome::Success,
                        now,
                    )
                    .unwrap(),
                    now,
                )
                .is_err()
        );
    }

    #[test]
    fn an_expired_attribution_is_refused_rather_than_renewed() {
        let now = Utc::now();
        let mut ledger = HistoryMaterialLedger::default();
        let row = attribution(digest(1), "sender.one", 1, now);
        let after_expiry = row.expires_at().unwrap() + chrono::Duration::seconds(1);
        assert!(ledger.admit_received_candidate(&row, after_expiry).is_err());
    }
}
