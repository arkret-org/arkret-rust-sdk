//! In-memory implementations of the four store traits.
//!
//! These are the test backbone: they let SDK unit tests exercise
//! `verify_control_move` / `apply_seal` / `state_root` end-to-end without a
//! database. Production servers (soland) implement durable backends
//! against the same trait surface.

// Lock policy: recover from poisoning instead of panicking. These stores
// hold plain data (no torn multi-step invariants across a panic point), so
// `PoisonError::into_inner` is safe and keeps one panicked writer from
// cascading panics into every later caller.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use arkret_wire::event_envelope::Event;
use arkret_wire::{ControlProposalAck, ControlProposalDecision};
use async_trait::async_trait;
use serde_json::{Value, json};

use super::{
    CellStateModelBinding, CellStateRegistry, CellStore, ControlEventStore, ControlProposalIngress,
    ControlProposalIngressClass, ControlProposalSnapshot, ControlSealAttemptCompletion,
    ControlSealAttemptOutcome, ControlSealScheduleClaim, ControlSealScheduleRepairStats,
    ControlSealScheduleStats, EventCellBottom, PendingControlEventRecord, SealStore,
    SealedControlEventRecord, StoreError, StoreResult, control_event_digest,
};
use crate::state_model::ordered_log::IssuedOp;
use crate::state_model::{
    CausalRegister, Counter, DomainTransitionRule, OrSet, OrderedLog, ResolvedCellState,
    SequencedState, StateModel, StateModelKind,
};
use crate::{CellRef, Hash, RealmId, Seal, SealId};

/// In-memory `ControlEventStore`.
#[derive(Default)]
pub struct MemoryControlEventStore {
    inner: Mutex<MemoryControlEventStoreInner>,
}

#[derive(Default)]
struct MemoryControlEventStoreInner {
    /// All known control-plane Events keyed by their `event_digest`.
    events: BTreeMap<String, Event>,
    /// Trusted digest suite stored atomically with each exact Event digest.
    digest_suites: BTreeMap<String, arkret_canonical::DigestSuite>,
    /// Seal membership: event_digest → direct covering Seal ids (absent means pending).
    sealed: BTreeMap<String, BTreeSet<SealId>>,
    /// Insertion order so list_pending is deterministic.
    insertion_order: Vec<String>,
    control_proposal_acks: BTreeMap<String, ControlProposalAck>,
    /// Durable ingress classification per Event digest.
    ingress_classes: BTreeMap<String, ControlProposalIngressClass>,
    proposal_decisions: BTreeMap<String, Vec<ControlProposalDecision>>,
    decision_overdue: BTreeSet<String>,
    control_seal_schedule: BTreeMap<RealmId, MemoryControlSealSchedule>,
    control_seal_repair_after: Option<RealmId>,
    control_seal_schedule_sequence: i64,
}

#[derive(Clone, Debug)]
struct MemoryControlSealSchedule {
    generation: u64,
    first_pending_at_ms: i64,
    next_attempt_at_ms: i64,
    last_attempt_at_ms: Option<i64>,
    claim_holder: Option<String>,
    claim_fence: u64,
    claim_until_ms: Option<i64>,
    consecutive_failures: u32,
    last_outcome: Option<String>,
    scan_cursor: Option<Hash>,
}

impl MemoryControlEventStore {
    fn realm_event_count(inner: &MemoryControlEventStoreInner, realm_id: &RealmId) -> u64 {
        inner
            .events
            .values()
            .filter(|event| event.realm_id == *realm_id)
            .count() as u64
    }

    fn pending_realm_counts(inner: &MemoryControlEventStoreInner) -> BTreeMap<RealmId, u64> {
        let mut counts = BTreeMap::new();
        for (digest, event) in &inner.events {
            if inner.sealed.contains_key(digest)
                || inner
                    .proposal_decisions
                    .get(digest)
                    .is_some_and(|decisions| {
                        decisions.iter().any(ControlProposalDecision::is_reject)
                    })
            {
                continue;
            }
            *counts.entry(event.realm_id.clone()).or_default() += 1;
        }
        counts
    }

    fn ensure_realm_schedule(inner: &mut MemoryControlEventStoreInner, realm_id: &RealmId) {
        let generation = Self::realm_event_count(inner, realm_id);
        let first_pending_at_ms = if inner.control_seal_schedule.contains_key(realm_id) {
            inner.control_seal_schedule_sequence
        } else {
            inner.control_seal_schedule_sequence =
                inner.control_seal_schedule_sequence.saturating_add(1);
            inner.control_seal_schedule_sequence
        };
        let schedule = inner
            .control_seal_schedule
            .entry(realm_id.clone())
            .or_insert_with(|| MemoryControlSealSchedule {
                generation,
                // The memory backend has no storage clock. A monotonic insert
                // sequence preserves age ordering and prevents newly added
                // low Realm ids from overtaking older work indefinitely.
                first_pending_at_ms,
                next_attempt_at_ms: 0,
                last_attempt_at_ms: None,
                claim_holder: None,
                claim_fence: 0,
                claim_until_ms: None,
                consecutive_failures: 0,
                last_outcome: None,
                scan_cursor: None,
            });
        if generation > schedule.generation {
            schedule.generation = generation;
            schedule.next_attempt_at_ms = 0;
            schedule.consecutive_failures = 0;
            schedule.last_outcome = None;
        }
    }

    /// Seed a locally verified accepted Event for deterministic checkpoint
    /// replay. This bypasses pending-ingress bookkeeping only; callers still
    /// pass every Event through `apply_accepted_seal_in_context`, which repeats
    /// the registered proof, reducer, root, and Seal checks before it becomes
    /// part of the reconstructed checkpoint.
    /// Seed a verified replay Event under the digest suite selected from its
    /// authenticated historical Realm state.
    pub fn insert_verified_replay_event_with_digest_suite(
        &self,
        event: &Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<Hash> {
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| StoreError::Backend(format!("event_digest: {error}")))?,
        )
        .map_err(|error| StoreError::Backend(format!("invalid event_digest: {error}")))?;
        self.insert_verified_replay_event_with_digest(event, digest, digest_suite)
    }

    fn insert_verified_replay_event_with_digest(
        &self,
        event: &Event,
        digest: Hash,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<Hash> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = inner.events.get(digest.as_str()) {
            if existing != event || inner.digest_suites.get(digest.as_str()) != Some(&digest_suite)
            {
                return Err(StoreError::Conflict(format!(
                    "control Event digest collision at {digest}"
                )));
            }
            return Ok(digest);
        }
        inner.insertion_order.push(digest.as_str().to_owned());
        inner
            .events
            .insert(digest.as_str().to_owned(), event.clone());
        inner
            .digest_suites
            .insert(digest.as_str().to_owned(), digest_suite);
        Ok(digest)
    }
}

#[async_trait]
impl ControlEventStore for MemoryControlEventStore {
    async fn put_pending_with_ingress(
        &self,
        event: &Event,
        ingress: &ControlProposalIngress,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        let digest = control_event_digest(event, digest_suite)?;
        let control_proposal_ack = ingress.ack();
        if let Some(ack) = control_proposal_ack
            && (ack.proposal_digest != digest || ack.realm_id != event.realm_id)
        {
            return Err(StoreError::Conflict(
                "Control Proposal Ack does not bind the pending Control Move".to_owned(),
            ));
        }
        if let Some(ack) = control_proposal_ack {
            ack.validate_protocol_bounds()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
        }
        let ingress_class = ingress.class();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let (Some(ack), Some(stored)) = (
            control_proposal_ack,
            inner.control_proposal_acks.get(digest.as_str()),
        ) && stored != ack
        {
            return Err(StoreError::Conflict(
                "pending Control Move already has a different Control Proposal Ack".to_owned(),
            ));
        }
        if let Some(stored) = inner.ingress_classes.get(digest.as_str())
            && stored != &ingress_class
        {
            return Err(StoreError::Conflict(
                "pending Control Move already has a different ingress class".to_owned(),
            ));
        }
        let key = digest.as_str().to_owned();
        if let Some(existing) = inner.events.get(&key)
            && (existing != event || inner.digest_suites.get(&key) != Some(&digest_suite))
        {
            return Err(StoreError::Conflict(format!(
                "control Event digest collision at {digest}"
            )));
        }
        if !inner.events.contains_key(&key) {
            inner.insertion_order.push(key.clone());
        }
        inner
            .events
            .entry(key.clone())
            .or_insert_with(|| event.clone());
        inner.digest_suites.entry(key).or_insert(digest_suite);
        inner
            .ingress_classes
            .entry(digest.as_str().to_owned())
            .or_insert(ingress_class);
        if let Some(ack) = control_proposal_ack {
            match inner.control_proposal_acks.get(digest.as_str()) {
                Some(_) => {}
                None => {
                    inner
                        .control_proposal_acks
                        .insert(digest.as_str().to_owned(), ack.clone());
                }
            }
        }
        Self::ensure_realm_schedule(&mut inner, &event.realm_id);
        Ok(())
    }

    async fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(event) = inner.events.get(event_digest.as_str()) else {
            return Err(StoreError::NotFound(format!(
                "control Event {event_digest} not in store"
            )));
        };
        if event.realm_id != seal.realm_id || !seal.delta.contains(event_digest) {
            return Err(StoreError::Conflict(format!(
                "Seal {} does not directly cover control Event {event_digest}",
                seal.id
            )));
        }
        let mut overdue = false;
        if let Some(stored_seals) = inner.sealed.get(event_digest.as_str())
            && stored_seals.contains(&seal.id)
        {
            return Ok(());
        }
        let decisions = inner
            .proposal_decisions
            .get(event_digest.as_str())
            .cloned()
            .unwrap_or_default();
        if decisions.iter().any(ControlProposalDecision::is_reject) {
            return Err(StoreError::Conflict(format!(
                "signed-rejected control Event {event_digest} cannot be sealed"
            )));
        }
        if let Some(ack) = inner.control_proposal_acks.get(event_digest.as_str()) {
            let mut previous_due_at = ack.decision_due_at;
            for decision in &decisions {
                overdue |= !decision.satisfied_current_deadline(previous_due_at);
                previous_due_at = decision.decision_due_at();
            }
            overdue |= seal.sealed_at > previous_due_at;
        }
        if overdue {
            inner
                .decision_overdue
                .insert(event_digest.as_str().to_owned());
        }
        inner
            .sealed
            .entry(event_digest.as_str().to_owned())
            .or_default()
            .insert(seal.id.clone());
        Ok(())
    }

    async fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .get(event_digest.as_str())
            .cloned())
    }

    async fn digest_suite(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest_suites
            .get(event_digest.as_str())
            .copied())
    }

    async fn covering_seals(&self, event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sealed
            .get(event_digest.as_str())
            .map(|seals| seals.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn control_proposal_ack(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalAck>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .control_proposal_acks
            .get(event_digest.as_str())
            .cloned())
    }

    async fn control_proposal_snapshot(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalSnapshot>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(event) = inner.events.get(event_digest.as_str()) else {
            return Ok(None);
        };
        Ok(Some(ControlProposalSnapshot {
            event: event.clone(),
            digest_suite: *inner
                .digest_suites
                .get(event_digest.as_str())
                .ok_or_else(|| {
                    StoreError::Backend("control Event digest suite is missing".to_owned())
                })?,
            control_proposal_ack: inner
                .control_proposal_acks
                .get(event_digest.as_str())
                .cloned(),
            ingress_class: inner
                .ingress_classes
                .get(event_digest.as_str())
                .cloned()
                .ok_or_else(|| {
                    StoreError::Backend("control Event ingress class is missing".to_owned())
                })?,
            decisions: inner
                .proposal_decisions
                .get(event_digest.as_str())
                .cloned()
                .unwrap_or_default(),
            covering_seals: inner
                .sealed
                .get(event_digest.as_str())
                .map(|seals| seals.iter().cloned().collect())
                .unwrap_or_default(),
            decision_overdue: inner.decision_overdue.contains(event_digest.as_str()),
        }))
    }

    async fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.events.contains_key(event_digest.as_str()) {
            return Err(StoreError::NotFound(format!(
                "control Event {event_digest} not in store"
            )));
        }
        if inner.sealed.contains_key(event_digest.as_str()) {
            return Err(StoreError::Conflict(format!(
                "sealed control Event {event_digest} cannot receive another proposal decision"
            )));
        }
        let ack = inner
            .control_proposal_acks
            .get(event_digest.as_str())
            .cloned()
            .ok_or_else(|| {
                StoreError::Conflict(format!(
                    "control Event {event_digest} has no Control Proposal Ack"
                ))
            })?;
        let decisions = inner
            .proposal_decisions
            .entry(event_digest.as_str().to_owned())
            .or_default();
        if decisions.contains(decision) {
            return Ok(());
        }
        if decisions.iter().any(ControlProposalDecision::is_reject) {
            return Err(StoreError::Conflict(format!(
                "control Event {event_digest} already has a terminal signed rejection"
            )));
        }
        decision
            .validate_chain(&ack, decisions, policy)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        decisions.push(decision.clone());
        Ok(())
    }

    async fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut records = inner
            .insertion_order
            .iter()
            .filter(|digest| !inner.sealed.contains_key(*digest))
            .filter(|digest| {
                !inner
                    .proposal_decisions
                    .get(*digest)
                    .is_some_and(|decisions| {
                        decisions.iter().any(ControlProposalDecision::is_reject)
                    })
            })
            .filter_map(|digest| {
                let event = inner.events.get(digest)?;
                // Written atomically with the Event row in
                // `put_pending_with_ingress`, under the same lock.
                let ingress_class = inner.ingress_classes.get(digest)?.clone();
                let digest_suite = *inner.digest_suites.get(digest)?;
                (event.realm_id == *realm_id).then(|| PendingControlEventRecord {
                    event: event.clone(),
                    digest_suite,
                    control_proposal_ack: inner.control_proposal_acks.get(digest).cloned(),
                    decisions: inner
                        .proposal_decisions
                        .get(digest)
                        .cloned()
                        .unwrap_or_default(),
                    ingress_class,
                })
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            let key = |row: &PendingControlEventRecord| {
                (
                    row.control_proposal_ack
                        .as_ref()
                        .map(|ack| ack.absolute_due_at),
                    row.control_proposal_ack.as_ref().map_or_else(
                        || row.event.event_id.to_string(),
                        |ack| ack.proposal_digest.to_string(),
                    ),
                )
            };
            key(left).cmp(&key(right))
        });
        records.truncate(limit);
        Ok(records)
    }

    async fn claim_due_control_seal_realms(
        &self,
        holder: &str,
        now_ms: i64,
        claim_until_ms: i64,
        limit: usize,
    ) -> StoreResult<Vec<ControlSealScheduleClaim>> {
        if claim_until_ms <= now_ms {
            return Err(StoreError::Conflict(
                "Control Seal schedule claim must end after it starts".to_owned(),
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = Self::pending_realm_counts(&inner);
        let mut due = inner
            .control_seal_schedule
            .iter()
            .filter(|(realm_id, schedule)| {
                pending.contains_key(*realm_id)
                    && schedule.next_attempt_at_ms <= now_ms
                    && (schedule.claim_holder.is_none()
                        || schedule.claim_until_ms.is_some_and(|until| until <= now_ms))
            })
            .map(|(realm_id, schedule)| {
                (
                    schedule.next_attempt_at_ms,
                    schedule.first_pending_at_ms,
                    realm_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        due.sort();
        due.truncate(limit);
        let mut claims = Vec::with_capacity(due.len());
        for (_, _, realm_id) in due {
            let schedule = inner
                .control_seal_schedule
                .get_mut(&realm_id)
                .expect("selected Control Seal schedule exists");
            let isolate_candidates =
                schedule.consecutive_failures > 0 || schedule.claim_holder.is_some();
            schedule.claim_fence = schedule.claim_fence.saturating_add(1);
            schedule.claim_holder = Some(holder.to_owned());
            schedule.claim_until_ms = Some(claim_until_ms);
            schedule.last_attempt_at_ms = Some(now_ms);
            claims.push(ControlSealScheduleClaim {
                scan_cursor: schedule.scan_cursor.clone(),
                isolate_candidates,
                realm_id,
                generation: schedule.generation,
                holder: holder.to_owned(),
                fence: schedule.claim_fence,
                claimed_at_ms: now_ms,
                claim_until_ms,
            });
        }
        Ok(claims)
    }

    async fn advance_control_seal_scan(
        &self,
        claim: &ControlSealScheduleClaim,
        cursor: Option<&Hash>,
        observed_at_ms: i64,
    ) -> StoreResult<bool> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cursor) = cursor
            && inner
                .events
                .get(cursor.as_str())
                .is_none_or(|event| event.realm_id != claim.realm_id)
        {
            return Ok(false);
        }
        let Some(schedule) = inner.control_seal_schedule.get_mut(&claim.realm_id) else {
            return Ok(false);
        };
        if schedule.claim_holder.as_deref() != Some(claim.holder.as_str())
            || schedule.claim_fence != claim.fence
            || schedule
                .claim_until_ms
                .is_none_or(|until| until <= observed_at_ms)
        {
            return Ok(false);
        }
        schedule.scan_cursor = cursor.cloned();
        Ok(true)
    }

    async fn complete_control_seal_attempt(
        &self,
        claim: &ControlSealScheduleClaim,
        outcome: &ControlSealAttemptOutcome,
        observed_at_ms: i64,
    ) -> StoreResult<ControlSealAttemptCompletion> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(schedule) = inner.control_seal_schedule.get(&claim.realm_id) else {
            return Ok(ControlSealAttemptCompletion::StaleClaim);
        };
        if schedule.claim_holder.as_deref() != Some(claim.holder.as_str())
            || schedule.claim_fence != claim.fence
        {
            return Ok(ControlSealAttemptCompletion::StaleClaim);
        }
        if schedule.generation != claim.generation {
            let schedule = inner
                .control_seal_schedule
                .get_mut(&claim.realm_id)
                .expect("checked Control Seal schedule exists");
            schedule.claim_holder = None;
            schedule.claim_until_ms = None;
            schedule.next_attempt_at_ms = observed_at_ms;
            return Ok(ControlSealAttemptCompletion::ReleasedNewGeneration);
        }
        let still_pending = Self::pending_realm_counts(&inner).contains_key(&claim.realm_id);
        if !still_pending {
            inner.control_seal_schedule.remove(&claim.realm_id);
            return Ok(ControlSealAttemptCompletion::Applied);
        }
        let schedule = inner
            .control_seal_schedule
            .get_mut(&claim.realm_id)
            .expect("checked Control Seal schedule exists");
        schedule.consecutive_failures = if outcome.is_failure() {
            schedule.consecutive_failures.saturating_add(1)
        } else {
            0
        };
        schedule.next_attempt_at_ms =
            outcome.next_eligible_at_ms(observed_at_ms, schedule.consecutive_failures);
        schedule.last_outcome = Some(outcome.as_str().to_owned());
        schedule.claim_holder = None;
        schedule.claim_until_ms = None;
        Ok(ControlSealAttemptCompletion::Applied)
    }

    async fn repair_control_seal_schedule(
        &self,
        _now_ms: i64,
        limit: usize,
    ) -> StoreResult<ControlSealScheduleRepairStats> {
        if limit == 0 {
            return Ok(ControlSealScheduleRepairStats::default());
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = Self::pending_realm_counts(&inner);
        let all_realms = pending.keys().cloned().collect::<Vec<_>>();
        let mut selected = all_realms
            .iter()
            .filter(|realm_id| {
                inner
                    .control_seal_repair_after
                    .as_ref()
                    .is_none_or(|cursor| *realm_id > cursor)
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let mut cursor_wrapped = false;
        if selected.is_empty() && !all_realms.is_empty() {
            cursor_wrapped = inner.control_seal_repair_after.is_some();
            selected.extend(all_realms.iter().take(limit).cloned());
        }
        let mut stats = ControlSealScheduleRepairStats {
            scanned: selected.len(),
            cursor_wrapped,
            ..ControlSealScheduleRepairStats::default()
        };
        for realm_id in &selected {
            let generation = Self::realm_event_count(&inner, realm_id);
            match inner.control_seal_schedule.get(realm_id) {
                None => {
                    Self::ensure_realm_schedule(&mut inner, realm_id);
                    stats.inserted += 1;
                }
                Some(schedule) if schedule.generation < generation => {
                    Self::ensure_realm_schedule(&mut inner, realm_id);
                    stats.generation_repaired += 1;
                }
                Some(_) => {}
            }
        }
        inner.control_seal_repair_after = selected.last().cloned();
        let stale = inner
            .control_seal_schedule
            .keys()
            .filter(|realm_id| !pending.contains_key(*realm_id))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        for realm_id in stale {
            inner.control_seal_schedule.remove(&realm_id);
            stats.stale_deleted += 1;
        }
        Ok(stats)
    }

    async fn control_seal_schedule_stats(
        &self,
        now_ms: i64,
    ) -> StoreResult<ControlSealScheduleStats> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending_realms = Self::pending_realm_counts(&inner);
        let mut stats = ControlSealScheduleStats::default();
        for (realm_id, schedule) in &inner.control_seal_schedule {
            if !pending_realms.contains_key(realm_id) {
                continue;
            }
            stats.pending += 1;
            stats.oldest_pending_at_ms = Some(
                stats
                    .oldest_pending_at_ms
                    .map_or(schedule.first_pending_at_ms, |oldest| {
                        oldest.min(schedule.first_pending_at_ms)
                    }),
            );
            let claim_active = schedule
                .claim_until_ms
                .is_some_and(|claim_until_ms| claim_until_ms > now_ms)
                && schedule.claim_holder.is_some();
            let claim_expired = schedule
                .claim_until_ms
                .is_some_and(|claim_until_ms| claim_until_ms <= now_ms)
                && schedule.claim_holder.is_some();
            stats.claimed += usize::from(claim_active);
            stats.expired_claims += usize::from(claim_expired);
            if schedule.next_attempt_at_ms <= now_ms && !claim_active {
                stats.eligible += 1;
                stats.oldest_eligible_at_ms = Some(
                    stats
                        .oldest_eligible_at_ms
                        .map_or(schedule.next_attempt_at_ms, |oldest| {
                            oldest.min(schedule.next_attempt_at_ms)
                        }),
                );
            }
        }
        Ok(stats)
    }

    async fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<Event>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cursor_str = cursor.map(|c| c.as_str().to_owned());
        let mut started = cursor_str.is_none();
        let mut out = Vec::new();
        for digest in &inner.insertion_order {
            if !started {
                if Some(digest.as_str()) == cursor_str.as_deref() {
                    started = true;
                }
                continue;
            }
            if let Some(event) = inner.events.get(digest)
                && event.realm_id == *realm_id
                && !inner.sealed.contains_key(digest)
                && !inner
                    .proposal_decisions
                    .get(digest)
                    .is_some_and(|decisions| {
                        decisions.iter().any(ControlProposalDecision::is_reject)
                    })
            {
                out.push(event.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    async fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cursor_str = cursor.map(|c| c.as_str().to_owned());
        let mut started = cursor_str.is_none();
        let mut out = Vec::new();
        for digest in &inner.insertion_order {
            if !started {
                if Some(digest.as_str()) == cursor_str.as_deref() {
                    started = true;
                }
                continue;
            }
            if let (Some(event), Some(seals)) = (inner.events.get(digest), inner.sealed.get(digest))
                && event.realm_id == *realm_id
            {
                // Written atomically with the Event row in
                // `put_pending_with_ingress`, under the same lock.
                let Some(ingress_class) = inner.ingress_classes.get(digest).cloned() else {
                    continue;
                };
                out.push(SealedControlEventRecord {
                    event: event.clone(),
                    digest_suite: *inner.digest_suites.get(digest).ok_or_else(|| {
                        StoreError::Backend("control Event digest suite is missing".to_owned())
                    })?,
                    covering_seals: seals.iter().cloned().collect(),
                    control_proposal_ack: inner.control_proposal_acks.get(digest).cloned(),
                    decisions: inner
                        .proposal_decisions
                        .get(digest)
                        .cloned()
                        .unwrap_or_default(),
                    decision_overdue: inner.decision_overdue.contains(digest),
                    ingress_class,
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// In-memory `SealStore`.
#[derive(Default)]
pub struct MemorySealStore {
    inner: Mutex<MemorySealStoreInner>,
}

#[derive(Default)]
struct MemorySealStoreInner {
    seals: BTreeMap<String, Seal>,
    digest_suites: BTreeMap<String, arkret_canonical::DigestSuite>,
    /// realm_id → leaves (seals with no successor)
    leaves: BTreeMap<String, Vec<SealId>>,
    /// realm_id → genesis seal (first put with empty predecessors)
    genesis: BTreeMap<String, SealId>,
    signing_leases: BTreeMap<(String, String), (String, i64, u64)>,
}

impl MemorySealStoreInner {
    fn put(&mut self, seal: &Seal, digest_suite: arkret_canonical::DigestSuite) -> StoreResult<()> {
        seal.validate_id(digest_suite)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let realm = seal.realm_id.as_str().to_owned();
        let id_str = seal.id.as_str().to_owned();
        if let Some(existing) = self.seals.get(&id_str) {
            if existing != seal || self.digest_suites.get(&id_str) != Some(&digest_suite) {
                return Err(StoreError::Conflict(format!(
                    "Seal {} already exists with different canonical content or digest suite",
                    seal.id
                )));
            }
            return Ok(());
        }
        self.seals.insert(id_str.clone(), seal.clone());
        self.digest_suites.insert(id_str, digest_suite);

        if seal.predecessor_ref.is_none() {
            self.genesis
                .entry(realm.clone())
                .or_insert_with(|| seal.id.clone());
        }

        let leaves = self.leaves.entry(realm).or_default();
        leaves.retain(|leaf| !seal.predecessor_ref.iter().any(|p| p == leaf));
        if !leaves.iter().any(|leaf| leaf == &seal.id) {
            leaves.push(seal.id.clone());
        }
        Ok(())
    }

    fn frontier_matches(&self, realm_id: &RealmId, expected_leaves: &[SealId]) -> bool {
        let current: BTreeSet<&str> = self
            .leaves
            .get(realm_id.as_str())
            .into_iter()
            .flatten()
            .map(SealId::as_str)
            .collect();
        let expected: BTreeSet<&str> = expected_leaves.iter().map(SealId::as_str).collect();
        current == expected
    }
}

#[async_trait]
impl SealStore for MemorySealStore {
    async fn try_claim_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> StoreResult<Option<u64>> {
        if until_ms <= now_ms {
            return Err(StoreError::Conflict(
                "signing lease must end after its claim time".to_owned(),
            ));
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (realm_id.as_str().to_owned(), signer_slot.to_owned());
        if let Some((current_holder, current_until, _)) = inner.signing_leases.get(&key)
            && current_holder != holder
            && *current_until > now_ms
        {
            return Ok(None);
        }
        let next_fence = inner
            .signing_leases
            .get(&key)
            .map_or(1, |(_, _, fence)| fence.saturating_add(1));
        inner
            .signing_leases
            .insert(key, (holder.to_owned(), until_ms, next_fence));
        Ok(Some(next_fence))
    }

    async fn release_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        fence: u64,
    ) -> StoreResult<bool> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (realm_id.as_str().to_owned(), signer_slot.to_owned());
        let matches =
            inner
                .signing_leases
                .get(&key)
                .is_some_and(|(current_holder, _, current_fence)| {
                    current_holder == holder && *current_fence == fence
                });
        if matches && let Some((_, lease_until, _)) = inner.signing_leases.get_mut(&key) {
            *lease_until = i64::MIN;
        }
        Ok(matches)
    }

    async fn put(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.put(seal, digest_suite)
    }

    async fn put_if_frontier(
        &self,
        seal: &Seal,
        expected_leaves: &[SealId],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.frontier_matches(&seal.realm_id, expected_leaves) {
            return Ok(false);
        }
        inner.put(seal, digest_suite)?;
        Ok(true)
    }

    async fn get(&self, id: &SealId) -> StoreResult<Option<Seal>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seals
            .get(id.as_str())
            .cloned())
    }

    async fn digest_suite(
        &self,
        id: &SealId,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest_suites
            .get(id.as_str())
            .copied())
    }

    async fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .leaves
            .get(realm_id.as_str())
            .cloned()
            .unwrap_or_default())
    }

    async fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(refs.iter().all(|r| inner.seals.contains_key(r.as_str())))
    }

    async fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .genesis
            .get(realm_id.as_str())
            .cloned())
    }

    async fn successors(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::new();
        for seal in inner.seals.values() {
            if seal.realm_id.as_str() != realm_id.as_str() {
                continue;
            }
            if seal.predecessor_ref.iter().any(|p| p == seal_id) {
                out.push(seal.id.clone());
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }
}

/// In-memory `CellStore`.
#[derive(Default)]
pub struct MemoryCellStore {
    inner: Mutex<MemoryCellStoreInner>,
}

#[derive(Default)]
struct MemoryCellStoreInner {
    /// (realm, cell) -> ordered (accepting Seal, StateWrite) list
    cell_log: BTreeMap<(String, String), Vec<(SealId, IssuedOp)>>,
    /// (realm, cell, view_hash) -> ResolvedCellState
    cache: BTreeMap<(String, String, String), ResolvedCellState>,
    /// seal → ops it appended (used for rollback)
    seal_ops: BTreeMap<String, Vec<(String, IssuedOp)>>, // (realm, cell), op
}

#[async_trait]
impl CellStore for MemoryCellStore {
    async fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cells = Vec::new();
        for (realm, cell) in inner.cell_log.keys() {
            if realm == realm_id.as_str() {
                cells.push(
                    CellRef::new(cell.clone()).map_err(|e| StoreError::Backend(e.to_string()))?,
                );
            }
        }
        Ok(cells)
    }

    async fn state_writes_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
            .cell_log
            .get(&(realm_id.as_str().to_owned(), cell.as_str().to_owned()))
            .map(|entries| entries.iter().map(|(_, op)| op.clone()).collect())
            .unwrap_or_default())
    }

    async fn confirmed_write_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut batches: Vec<(SealId, Vec<IssuedOp>)> = Vec::new();
        for (seal, op) in inner
            .cell_log
            .get(&(realm_id.as_str().to_owned(), cell.as_str().to_owned()))
            .into_iter()
            .flatten()
        {
            if let Some((batch_seal, ops)) = batches.last_mut()
                && batch_seal == seal
            {
                ops.push(op.clone());
            } else {
                batches.push((seal.clone(), vec![op.clone()]));
            }
        }
        Ok(batches)
    }

    async fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<ResolvedCellState>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
            .cache
            .get(&(
                realm_id.as_str().to_owned(),
                cell.as_str().to_owned(),
                view_hash.as_str().to_owned(),
            ))
            .cloned())
    }

    async fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &ResolvedCellState,
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.cache.insert(
            (
                realm_id.as_str().to_owned(),
                cell.as_str().to_owned(),
                view_hash.as_str().to_owned(),
            ),
            state.clone(),
        );
        Ok(())
    }

    async fn append_confirmed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut applied: Vec<(String, IssuedOp)> = Vec::with_capacity(new_ops.len());
        for (cell, op) in new_ops {
            let key = (realm_id.as_str().to_owned(), cell.as_str().to_owned());
            inner
                .cell_log
                .entry(key.clone())
                .or_default()
                .push((seal.clone(), op.clone()));
            applied.push((cell.as_str().to_owned(), op.clone()));
        }
        inner.seal_ops.insert(seal.as_str().to_owned(), applied);
        // Cache invalidation: clear cache entries for cells touched by this seal.
        let touched: BTreeSet<_> = new_ops
            .iter()
            .map(|(c, _)| (realm_id.as_str().to_owned(), c.as_str().to_owned()))
            .collect();
        inner
            .cache
            .retain(|(s, c, _), _| !touched.contains(&(s.clone(), c.clone())));
        Ok(())
    }

    async fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(applied) = inner.seal_ops.remove(seal.as_str()) else {
            return Ok(()); // no-op if nothing to roll back
        };
        for (cell_str, op) in applied {
            let key = (realm_id.as_str().to_owned(), cell_str);
            if let Some(log) = inner.cell_log.get_mut(&key) {
                if let Some(pos) = log
                    .iter()
                    .rposition(|(entry_seal, entry_op)| entry_seal == seal && entry_op == &op)
                {
                    log.remove(pos);
                }
                if log.is_empty() {
                    inner.cell_log.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// In-memory registry of generated Cell-family execution contracts.
pub struct MemoryCellStateRegistry {
    bindings: BTreeMap<String, BindingDescriptor>,
}

#[derive(Clone)]
struct BindingDescriptor {
    execution: arkret_wire::EventCellExecution,
    state_model: StateModelKind,
    value_shape: arkret_wire::EventCellValueShape,
    bottom_mode: Option<EventCellBottom>,
    domain_transition: Option<DomainTransitionRule>,
}

impl Default for MemoryCellStateRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl MemoryCellStateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a registry with no implicit test or fixture bindings.
    ///
    /// Production factories should start here and install the complete
    /// spec-derived binding set explicitly.
    pub fn empty() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Register an additional binding (test fixtures / Realm-level overrides).
    pub fn register(
        &mut self,
        cell_family: impl Into<String>,
        execution: arkret_wire::EventCellExecution,
        state_model: StateModelKind,
        value_shape: arkret_wire::EventCellValueShape,
        bottom_mode: Option<EventCellBottom>,
    ) {
        debug_assert_eq!(
            execution == arkret_wire::EventCellExecution::Security,
            state_model == StateModelKind::SequencedState,
        );
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                execution,
                state_model,
                value_shape,
                bottom_mode,
                domain_transition: None,
            },
        );
    }

    pub fn register_domain_transition(
        &mut self,
        cell_family: &str,
        initial: Option<Value>,
        transitions: Vec<(Value, Value)>,
    ) -> StoreResult<()> {
        let descriptor = self
            .bindings
            .get_mut(cell_family)
            .ok_or_else(|| StoreError::NotFound(format!("unknown cell family: {cell_family}")))?;
        let mut rule = DomainTransitionRule::new(transitions);
        if let Some(initial) = initial {
            rule = rule.with_initial(initial);
        }
        descriptor.domain_transition = Some(rule);
        Ok(())
    }
}

impl CellStateRegistry for MemoryCellStateRegistry {
    fn checkpoint_context(&self, _realm_id: &RealmId) -> StoreResult<Option<Hash>> {
        // All registry mutation requires `&mut self`; an Arc-held registry is
        // therefore one immutable rule snapshot. Include domain transition
        // rules and conservatively invalidate when state resolution changes. SHA-256,
        // JCS and typed identifier ordering are fixed protocol algorithms;
        // semantic changes to those contracts must invalidate this evaluation
        // contract explicitly, rather than relying on a dependency source scan.
        static IMPLEMENTATION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let implementation = IMPLEMENTATION.get_or_init(|| {
            let sources = [
                include_str!("../../state_model/mod.rs"),
                include_str!("../../state_model/traits.rs"),
                include_str!("../../state_model/causal_register.rs"),
                include_str!("../../state_model/counter.rs"),
                include_str!("../../state_model/domain_transition.rs"),
                include_str!("../../state_model/or_set.rs"),
                include_str!("../../state_model/ordered_log.rs"),
                include_str!("../../state_model/sequenced_state.rs"),
                include_str!("../seal.rs"),
                include_str!("../state_root.rs"),
                include_str!("mod.rs"),
                include_str!("memory.rs"),
            ];
            let mut framed = Vec::new();
            for source in sources {
                framed.extend_from_slice(&(source.len() as u64).to_be_bytes());
                framed.extend_from_slice(source.as_bytes());
            }
            arkret_canonical::sha256_digest(framed)
        });
        let bindings = self
            .bindings
            .iter()
            .map(|(family, descriptor)| {
                (
                    family,
                    json!({
                        "execution": descriptor.execution,
                        "state_model": descriptor.state_model.as_wire_str(),
                        "value_shape": descriptor.value_shape,
                        "bottom_mode": descriptor.bottom_mode,
                        "domain_transition": descriptor.domain_transition.is_some(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let bytes = arkret_canonical::canonical_json_bytes(&json!({
            "evaluation_contract": "arkret-state-cell-evaluation-v1",
            "implementation": implementation,
            "bindings": bindings,
        }))
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        Hash::new(arkret_canonical::sha256_digest(bytes))
            .map(Some)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    fn resolve(&self, _realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellStateModelBinding> {
        // Parse "ak:cell:<family>:<subject>" — family is between the 2nd and 3rd colons.
        let cell_id = crate::CellId::parse(cell.as_str())
            .map_err(|e| StoreError::Backend(format!("invalid cell ref: {e}")))?;
        let family = cell_id.component();
        let descriptor = self
            .bindings
            .get(family)
            .ok_or_else(|| StoreError::NotFound(format!("unknown cell family: {family}")))?;
        let model: Box<dyn StateModel> = match descriptor.state_model {
            StateModelKind::OrSet => Box::new(OrSet),
            StateModelKind::CausalRegister => Box::new(CausalRegister),
            StateModelKind::SequencedState => Box::new(SequencedState::new(descriptor.value_shape)),
            StateModelKind::Counter => Box::new(Counter),
            StateModelKind::OrderedLog => Box::new(OrderedLog),
        };
        Ok(CellStateModelBinding {
            model,
            state_model: descriptor.state_model,
            execution: descriptor.execution,
            value_shape: descriptor.value_shape,
            bottom_mode: descriptor.bottom_mode,
            domain_transition: descriptor.domain_transition.clone(),
        })
    }
}
