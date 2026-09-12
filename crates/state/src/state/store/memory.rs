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
    CausalRegisterBottomPolicy, CellStateModelBinding, CellStateRegistry, CellStore,
    ControlEventStore, ControlProposalIngressClass, ControlProposalSnapshot,
    ControlSealAttemptCompletion, ControlSealAttemptOutcome, ControlSealScheduleClaim,
    ControlSealScheduleRepairStats, ControlSealScheduleStats, ControlUnitIngressMember,
    DecidedControlEventRecord, PendingControlEventRecord, PendingControlUnitRecord,
    SealCommandEventDecision, SealCommitStore, SealStore, StoreError, StoreResult,
    control_event_digest,
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

#[derive(Clone, Default)]
struct MemoryControlEventStoreInner {
    /// All known control-plane Events keyed by their `event_digest`.
    events: BTreeMap<String, Event>,
    /// Trusted digest suite stored atomically with each exact Event digest.
    digest_suites: BTreeMap<String, arkret_canonical::DigestSuite>,
    /// Committed coverage: event_digest → direct covering Seal ids.
    committed_coverage: BTreeMap<String, BTreeSet<SealId>>,
    /// Every accepted Seal command decision, including rejected members.
    command_decisions: BTreeMap<String, Vec<SealCommandEventDecision>>,
    /// Exact registered unit members keyed by every member digest.
    unit_members: BTreeMap<String, Vec<String>>,
    /// Unit heads in durable intake order.
    unit_order: Vec<String>,
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
            if inner.command_decisions.contains_key(digest) {
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

    /// Register exact unit boundaries from a verified retained Seal.
    /// Every member must already be resolved under its historical digest suite.
    pub fn register_verified_replay_units(&self, seal: &Seal) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen = BTreeSet::new();
        for result in &seal.command_results {
            result
                .validate_structural()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let keys = result
                .unit_event_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>();
            for digest in &result.unit_event_digests {
                let event = inner.events.get(digest.as_str()).ok_or_else(|| {
                    StoreError::NotFound(format!("replay command member {digest}"))
                })?;
                if event.realm_id != seal.realm_id || !seen.insert(digest.clone()) {
                    return Err(StoreError::Conflict(
                        "replay command units cross Realms or repeat an Event".to_owned(),
                    ));
                }
                if inner
                    .unit_members
                    .get(digest.as_str())
                    .is_some_and(|existing| existing != &keys)
                {
                    return Err(StoreError::Conflict(
                        "replay command unit differs from registered membership".to_owned(),
                    ));
                }
            }
        }
        for result in &seal.command_results {
            let keys = result
                .unit_event_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>();
            for digest in &result.unit_event_digests {
                inner
                    .unit_members
                    .insert(digest.as_str().to_owned(), keys.clone());
            }
        }
        Ok(())
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
    async fn put_pending_unit_with_ingress(
        &self,
        members: &[ControlUnitIngressMember],
    ) -> StoreResult<Vec<Hash>> {
        let Some(first) = members.first() else {
            return Err(StoreError::Conflict(
                "registered command unit must not be empty".to_owned(),
            ));
        };
        if members.len() > arkret_wire::seal::MAX_SEAL_DELTA {
            return Err(StoreError::Conflict(
                "registered command unit exceeds the protocol member limit".to_owned(),
            ));
        }
        let realm_id = first.event.realm_id.clone();
        let mut digests = Vec::with_capacity(members.len());
        let mut unique = BTreeSet::new();
        for member in members {
            if member.event.realm_id != realm_id {
                return Err(StoreError::Conflict(
                    "registered command unit crosses Realm boundaries".to_owned(),
                ));
            }
            let digest = control_event_digest(&member.event, member.digest_suite)?;
            if !unique.insert(digest.clone()) {
                return Err(StoreError::Conflict(
                    "registered command unit contains a duplicate Event".to_owned(),
                ));
            }
            if let Some(ack) = member.ingress.ack() {
                if ack.proposal_digest != digest || ack.realm_id != member.event.realm_id {
                    return Err(StoreError::Conflict(
                        "Control Proposal Ack does not bind its command unit member".to_owned(),
                    ));
                }
                ack.validate_protocol_bounds()
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
            }
            digests.push(digest);
        }
        let unit_keys = digests
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (member, digest) in members.iter().zip(&digests) {
            let key = digest.as_str();
            if let Some(existing) = inner.events.get(key)
                && (existing != &member.event
                    || inner.digest_suites.get(key) != Some(&member.digest_suite))
            {
                return Err(StoreError::Conflict(format!(
                    "control Event digest collision at {digest}"
                )));
            }
            if let Some(existing) = inner.unit_members.get(key)
                && existing != &unit_keys
            {
                return Err(StoreError::Conflict(
                    "control Event already belongs to a different registered unit".to_owned(),
                ));
            }
            let ingress_class = member.ingress.class();
            if let Some(stored) = inner.ingress_classes.get(key)
                && stored != &ingress_class
            {
                return Err(StoreError::Conflict(
                    "control Event already has a different ingress class".to_owned(),
                ));
            }
            if let (Some(ack), Some(stored)) =
                (member.ingress.ack(), inner.control_proposal_acks.get(key))
                && stored != ack
            {
                return Err(StoreError::Conflict(
                    "control Event already has a different Control Proposal Ack".to_owned(),
                ));
            }
        }
        let is_new_unit = !inner.unit_members.contains_key(unit_keys[0].as_str());
        for (member, digest) in members.iter().zip(&digests) {
            let key = digest.as_str().to_owned();
            if !inner.events.contains_key(&key) {
                inner.insertion_order.push(key.clone());
            }
            inner
                .events
                .entry(key.clone())
                .or_insert_with(|| member.event.clone());
            inner
                .digest_suites
                .entry(key.clone())
                .or_insert(member.digest_suite);
            inner
                .unit_members
                .entry(key.clone())
                .or_insert_with(|| unit_keys.clone());
            inner
                .ingress_classes
                .entry(key.clone())
                .or_insert_with(|| member.ingress.class());
            if let Some(ack) = member.ingress.ack() {
                inner
                    .control_proposal_acks
                    .entry(key)
                    .or_insert_with(|| ack.clone());
            }
        }
        if is_new_unit {
            inner.unit_order.push(unit_keys[0].clone());
        }
        Self::ensure_realm_schedule(&mut inner, &realm_id);
        Ok(digests)
    }

    async fn record_seal_command_results(&self, seal: &Seal) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record_memory_seal_command_results(&mut inner, seal)
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

    async fn registered_unit_members(&self, event_digest: &Hash) -> StoreResult<Option<Vec<Hash>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unit_members
            .get(event_digest.as_str())
            .map(|members| {
                members
                    .iter()
                    .map(|member| {
                        Hash::new(member.clone()).map_err(|error| {
                            StoreError::Backend(format!(
                                "stored registered unit digest is invalid: {error}"
                            ))
                        })
                    })
                    .collect()
            })
            .transpose()
    }

    async fn covering_seals(&self, event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .committed_coverage
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
                .committed_coverage
                .get(event_digest.as_str())
                .map(|seals| seals.iter().cloned().collect())
                .unwrap_or_default(),
            command_decisions: inner
                .command_decisions
                .get(event_digest.as_str())
                .cloned()
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
        if inner
            .proposal_decisions
            .get(event_digest.as_str())
            .is_some_and(|decisions| decisions.contains(decision))
        {
            return Ok(());
        }
        if inner.command_decisions.contains_key(event_digest.as_str()) {
            return Err(StoreError::Conflict(format!(
                "Seal-decided control Event {event_digest} cannot receive another proposal decision"
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
            .filter(|digest| !inner.command_decisions.contains_key(*digest))
            .filter_map(|digest| {
                let event = inner.events.get(digest)?;
                // Written atomically with the Event row in
                // `put_pending_unit_with_ingress`, under the same lock.
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

    async fn list_pending_units_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlUnitRecord>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cursor_str = cursor.map(|c| c.as_str().to_owned());
        let mut started = cursor_str.is_none();
        let mut out = Vec::new();
        for unit_head in &inner.unit_order {
            if !started {
                if Some(unit_head.as_str()) == cursor_str.as_deref() {
                    started = true;
                }
                continue;
            }
            let Some(member_keys) = inner.unit_members.get(unit_head) else {
                return Err(StoreError::Backend(
                    "registered command unit boundary is missing".to_owned(),
                ));
            };
            let is_pending = member_keys
                .iter()
                .all(|digest| !inner.command_decisions.contains_key(digest));
            if !is_pending {
                continue;
            }
            let members = member_keys
                .iter()
                .map(|digest| {
                    let event = inner.events.get(digest).ok_or_else(|| {
                        StoreError::Backend("registered unit Event is missing".to_owned())
                    })?;
                    let digest_suite = *inner.digest_suites.get(digest).ok_or_else(|| {
                        StoreError::Backend("control Event digest suite is missing".to_owned())
                    })?;
                    let ingress_class =
                        inner.ingress_classes.get(digest).cloned().ok_or_else(|| {
                            StoreError::Backend("control Event ingress class is missing".to_owned())
                        })?;
                    Ok(PendingControlEventRecord {
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
                .collect::<StoreResult<Vec<_>>>()?;
            if members
                .first()
                .is_some_and(|member| member.event.realm_id == *realm_id)
            {
                out.push(PendingControlUnitRecord { members });
            }
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    async fn list_decided(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<DecidedControlEventRecord>> {
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
                && inner.command_decisions.contains_key(digest)
            {
                // Written atomically with the Event row in
                // `put_pending_unit_with_ingress`, under the same lock.
                let Some(ingress_class) = inner.ingress_classes.get(digest).cloned() else {
                    continue;
                };
                out.push(DecidedControlEventRecord {
                    event: event.clone(),
                    digest_suite: *inner.digest_suites.get(digest).ok_or_else(|| {
                        StoreError::Backend("control Event digest suite is missing".to_owned())
                    })?,
                    covering_seals: inner
                        .committed_coverage
                        .get(digest)
                        .map(|seals| seals.iter().cloned().collect())
                        .unwrap_or_default(),
                    command_decisions: inner
                        .command_decisions
                        .get(digest)
                        .cloned()
                        .unwrap_or_default(),
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

#[derive(Clone, Default)]
struct MemorySealStoreInner {
    seals: BTreeMap<String, Seal>,
    digest_suites: BTreeMap<String, arkret_canonical::DigestSuite>,
    /// realm_id → unique confirmed head
    heads: BTreeMap<String, SealId>,
    /// realm_id → genesis seal (first put without a predecessor)
    genesis: BTreeMap<String, SealId>,
    signing_leases: BTreeMap<(String, String), (String, i64, u64)>,
    signing_bodies:
        BTreeMap<(String, u64), (arkret_wire::UnsignedSeal, arkret_canonical::DigestSuite)>,
}

impl MemorySealStoreInner {
    fn put(&mut self, seal: &Seal, digest_suite: arkret_canonical::DigestSuite) -> StoreResult<()> {
        if let Some((body, suite)) = self
            .signing_bodies
            .get(&(seal.realm_id.as_str().to_owned(), seal.notary_seq))
        {
            let expected = arkret_canonical::canonical_json_bytes(body)
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let received = seal
                .canonical_bytes_for_id()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            if *suite != digest_suite || expected != received {
                return Err(StoreError::Conflict(
                    "accepted Seal differs from its immutable signing reservation".to_owned(),
                ));
            }
        }
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

        self.heads.insert(realm, seal.id.clone());
        Ok(())
    }

    fn head_matches(&self, realm_id: &RealmId, expected_head: Option<&SealId>) -> bool {
        self.heads.get(realm_id.as_str()) == expected_head
    }
}

#[async_trait]
impl SealStore for MemorySealStore {
    async fn reserve_signing_body(
        &self,
        body: &arkret_wire::UnsignedSeal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<arkret_wire::UnsignedSeal> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (body.realm_id.as_str().to_owned(), body.notary_seq);
        if let Some((reserved, suite)) = inner.signing_bodies.get(&key) {
            if *suite != digest_suite {
                return Err(StoreError::Conflict(
                    "reserved signing digest suite differs".to_owned(),
                ));
            }
            return Ok(reserved.clone());
        }
        if !inner.head_matches(&body.realm_id, body.predecessor_ref.as_ref()) {
            return Err(StoreError::Conflict(
                "signing body predecessor is not the confirmed head".to_owned(),
            ));
        }
        let expected_seq = match &body.predecessor_ref {
            Some(id) => inner
                .seals
                .get(id.as_str())
                .and_then(|seal| seal.notary_seq.checked_add(1))
                .ok_or_else(|| {
                    StoreError::Conflict(
                        "signing predecessor or successor sequence is unavailable".to_owned(),
                    )
                })?,
            None => 0,
        };
        if body.notary_seq != expected_seq {
            return Err(StoreError::Conflict(
                "signing body skips its lineage sequence".to_owned(),
            ));
        }
        inner
            .signing_bodies
            .insert(key, (body.clone(), digest_suite));
        Ok(body.clone())
    }

    async fn signing_body(
        &self,
        realm_id: &RealmId,
        notary_seq: u64,
    ) -> StoreResult<Option<arkret_wire::UnsignedSeal>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
            .signing_bodies
            .get(&(realm_id.as_str().to_owned(), notary_seq))
            .map(|(body, _)| body.clone()))
    }

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

    async fn put_if_head(
        &self,
        seal: &Seal,
        expected_head: Option<&SealId>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = inner.seals.get(seal.id.as_str()) {
            return Ok(existing == seal
                && inner.digest_suites.get(seal.id.as_str()) == Some(&digest_suite));
        }
        if !inner.head_matches(&seal.realm_id, expected_head) {
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

    async fn confirmed_head(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .heads
            .get(realm_id.as_str())
            .cloned())
    }

    async fn predecessor_known(&self, predecessor_ref: Option<&SealId>) -> StoreResult<bool> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(predecessor_ref.is_none_or(|id| inner.seals.contains_key(id.as_str())))
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

#[derive(Clone, Default)]
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
    bottom_policy: Option<CausalRegisterBottomPolicy>,
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
        bottom_policy: Option<CausalRegisterBottomPolicy>,
    ) {
        debug_assert_eq!(
            execution == arkret_wire::EventCellExecution::Security,
            state_model == StateModelKind::SequencedState,
        );
        assert_eq!(
            bottom_policy.is_some(),
            state_model == StateModelKind::CausalRegister,
            "only causal_register may declare a Bottom policy",
        );
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                execution,
                state_model,
                value_shape,
                bottom_policy,
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
                        "bottom_policy": descriptor.bottom_policy,
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
            bottom_policy: descriptor.bottom_policy,
            domain_transition: descriptor.domain_transition.clone(),
        })
    }
}

fn record_memory_seal_command_results(
    inner: &mut MemoryControlEventStoreInner,
    seal: &Seal,
) -> StoreResult<()> {
    let mut decisions = Vec::new();
    for (command_index, result) in seal.command_results.iter().enumerate() {
        let unit_keys = result
            .unit_event_digests
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>();
        for (member_index, digest) in result.unit_event_digests.iter().enumerate() {
            let event = inner.events.get(digest.as_str()).ok_or_else(|| {
                StoreError::NotFound(format!("control Event {digest} not in store"))
            })?;
            if event.realm_id != seal.realm_id
                || inner.unit_members.get(digest.as_str()) != Some(&unit_keys)
            {
                return Err(StoreError::Conflict(format!(
                    "Seal {} command result does not match the registered unit for {digest}",
                    seal.id
                )));
            }
            let decision = SealCommandEventDecision {
                seal_id: seal.id.clone(),
                command_index: u32::try_from(command_index).expect("Seal command bound"),
                member_index: u32::try_from(member_index).expect("Seal member bound"),
                outcome: result.outcome,
                reason_code: result.reason_code.clone(),
            };
            if let Some(existing) = inner.command_decisions.get(digest.as_str())
                && !existing.contains(&decision)
            {
                return Err(StoreError::Conflict(format!(
                    "control Event {digest} already has a different Seal command decision"
                )));
            }
            if result.outcome == arkret_wire::CommandOutcome::Rejected
                && seal.delta.contains(digest)
            {
                return Err(StoreError::Conflict(format!(
                    "rejected control Event {digest} cannot enter Seal.delta"
                )));
            }
            decisions.push((digest.clone(), decision));
        }
    }
    for (digest, decision) in decisions {
        let prior_decisions = inner
            .proposal_decisions
            .get(digest.as_str())
            .cloned()
            .unwrap_or_default();
        let mut overdue = false;
        if let Some(ack) = inner.control_proposal_acks.get(digest.as_str()) {
            let mut previous_due_at = ack.decision_due_at;
            for prior in &prior_decisions {
                overdue |= !prior.satisfied_current_deadline(previous_due_at);
                previous_due_at = prior.decision_due_at();
            }
            overdue |= seal.sealed_at > previous_due_at;
        }
        if overdue {
            inner.decision_overdue.insert(digest.as_str().to_owned());
        }
        let stored = inner
            .command_decisions
            .entry(digest.as_str().to_owned())
            .or_default();
        if !stored.contains(&decision) {
            stored.push(decision);
        }
        if seal.delta.contains(&digest) {
            inner
                .committed_coverage
                .entry(digest.as_str().to_owned())
                .or_default()
                .insert(seal.id.clone());
        }
    }
    Ok(())
}

/// Atomic transaction view over the three in-memory stores.
pub struct MemorySealCommitStore<'a> {
    events: &'a MemoryControlEventStore,
    seals: &'a MemorySealStore,
    cells: &'a MemoryCellStore,
}

impl<'a> MemorySealCommitStore<'a> {
    pub fn new(
        events: &'a MemoryControlEventStore,
        seals: &'a MemorySealStore,
        cells: &'a MemoryCellStore,
    ) -> Self {
        Self {
            events,
            seals,
            cells,
        }
    }
}

#[async_trait]
impl SealCommitStore for MemorySealCommitStore<'_> {
    fn control_events(&self) -> &dyn ControlEventStore {
        self.events
    }
    fn seals(&self) -> &dyn SealStore {
        self.seals
    }
    fn cells(&self) -> &dyn CellStore {
        self.cells
    }
    async fn commit_seal(
        &self,
        seal: &Seal,
        new_ops: &[(CellRef, IssuedOp)],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool> {
        let mut events = self
            .events
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seals = self
            .seals
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cells = self
            .cells
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = seals.seals.get(seal.id.as_str()) {
            let expected_ops = new_ops
                .iter()
                .map(|(cell, op)| (cell.as_str().to_owned(), op.clone()))
                .collect::<Vec<_>>();
            let complete_decisions =
                seal.command_results
                    .iter()
                    .enumerate()
                    .all(|(command_index, result)| {
                        result.unit_event_digests.iter().enumerate().all(
                            |(member_index, digest)| {
                                events.command_decisions.get(digest.as_str()).is_some_and(
                                    |decisions| {
                                        decisions.contains(&SealCommandEventDecision {
                                            seal_id: seal.id.clone(),
                                            command_index: command_index as u32,
                                            member_index: member_index as u32,
                                            outcome: result.outcome,
                                            reason_code: result.reason_code.clone(),
                                        })
                                    },
                                )
                            },
                        )
                    });
            if existing != seal
                || seals.digest_suites.get(seal.id.as_str()) != Some(&digest_suite)
                || cells.seal_ops.get(seal.id.as_str()) != Some(&expected_ops)
                || !complete_decisions
            {
                return Err(StoreError::Conflict(
                    "existing Seal does not have the complete identical atomic commit".to_owned(),
                ));
            }
            return Ok(true);
        }
        if !seals.head_matches(&seal.realm_id, seal.predecessor_ref.as_ref()) {
            return Ok(false);
        }
        let mut next_events = events.clone();
        let mut next_seals = seals.clone();
        let mut next_cells = cells.clone();
        record_memory_seal_command_results(&mut next_events, seal)?;
        next_seals.put(seal, digest_suite)?;
        let mut applied = Vec::with_capacity(new_ops.len());
        let mut touched = BTreeSet::new();
        for (cell, op) in new_ops {
            let key = (seal.realm_id.as_str().to_owned(), cell.as_str().to_owned());
            next_cells
                .cell_log
                .entry(key.clone())
                .or_default()
                .push((seal.id.clone(), op.clone()));
            touched.insert(key);
            applied.push((cell.as_str().to_owned(), op.clone()));
        }
        next_cells
            .seal_ops
            .insert(seal.id.as_str().to_owned(), applied);
        next_cells
            .cache
            .retain(|(realm, cell, _), _| !touched.contains(&(realm.clone(), cell.clone())));
        *events = next_events;
        *seals = next_seals;
        *cells = next_cells;
        Ok(true)
    }
}

#[cfg(test)]
mod signing_reservation_tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{EventId, Hlc, UnsignedSeal};

    use super::*;

    fn body() -> UnsignedSeal {
        let digest = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        UnsignedSeal {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            predecessor_ref: None,
            delta: Vec::new(),
            control_event_set_root: digest.clone(),
            state_root: digest.clone(),
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: chrono::DateTime::parse_from_rfc3339("2026-09-12T00:00:00Z")
                .unwrap()
                .to_utc(),
            hlc: Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            configuration_ref: EventId::from_event_digest(&digest).unwrap(),
            command_results: Vec::new(),
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
        }
    }

    #[tokio::test]
    async fn first_signing_body_survives_lease_expiry_and_competing_candidates() {
        let store = MemorySealStore::default();
        let first = body();
        assert_eq!(
            store
                .try_claim_signing_lease(&first.realm_id, "authority", "worker-a", 0, 10)
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .reserve_signing_body(&first, DigestSuite::Sha256)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            store
                .try_claim_signing_lease(&first.realm_id, "authority", "worker-b", 11, 20)
                .await
                .unwrap(),
            Some(2)
        );
        let mut competing = first.clone();
        competing.sealed_at += chrono::Duration::seconds(1);
        competing.configuration_ref = EventId::from_digest(DigestSuite::Sha256, [2; 32]);
        assert_eq!(
            store
                .reserve_signing_body(&competing, DigestSuite::Sha256)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            store.signing_body(&first.realm_id, 0).await.unwrap(),
            Some(first.clone())
        );
        assert!(
            store
                .reserve_signing_body(&first, DigestSuite::Blake3)
                .await
                .is_err()
        );
        assert!(
            !store
                .release_signing_lease(&first.realm_id, "authority", "worker-a", 1)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn accepted_seal_cannot_bypass_the_reserved_signing_body() {
        let store = MemorySealStore::default();
        let first = body();
        store
            .reserve_signing_body(&first, DigestSuite::Sha256)
            .await
            .unwrap();
        let seal_for = |body: &UnsignedSeal| {
            let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
            let mut value = serde_json::to_value(body).unwrap();
            value["id"] = serde_json::to_value(
                Seal::id_from_canonical_bytes(&bytes, DigestSuite::Sha256).unwrap(),
            )
            .unwrap();
            value["notary_signature"] = serde_json::json!({
                "verification_method": "did:web:station.example#notary",
                "payload_digest": format!("sha256:{}", "1".repeat(64)),
                "jws": "test-store-boundary"
            });
            serde_json::from_value::<Seal>(value).unwrap()
        };
        let mut competing = first.clone();
        competing.sealed_at += chrono::Duration::seconds(1);
        assert!(
            store
                .put_if_head(&seal_for(&competing), None, DigestSuite::Sha256)
                .await
                .is_err()
        );
        assert!(
            store
                .confirmed_head(&first.realm_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .put_if_head(&seal_for(&first), None, DigestSuite::Sha256)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn first_reservation_requires_current_predecessor_and_exact_next_sequence() {
        let store = MemorySealStore::default();
        let mut candidate = body();
        candidate.notary_seq = 1;
        assert!(
            store
                .reserve_signing_body(&candidate, DigestSuite::Sha256)
                .await
                .is_err()
        );
        candidate.predecessor_ref =
            Some(SealId::new(format!("ak:seal:sha256:{}", "2".repeat(64))).unwrap());
        assert!(
            store
                .reserve_signing_body(&candidate, DigestSuite::Sha256)
                .await
                .is_err()
        );
        assert!(
            store
                .signing_body(&candidate.realm_id, 1)
                .await
                .unwrap()
                .is_none()
        );
    }
}
