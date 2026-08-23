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
use serde_json::{Value, json};

use super::{
    BottomMode, CellLatticeBinding, CellRegistry, CellStore, ControlEventStore,
    ControlProposalIngress, ControlProposalIngressClass, ControlProposalSnapshot,
    PendingControlEventRecord, SealStore, SealedControlEventRecord, StoreError, StoreResult,
    control_event_digest,
};
use crate::lattice::ordered_log::IssuedOp;
use crate::lattice::{
    CasRegister, CellState, Counter, Fsm, Lattice, LatticeKind, MvRegister, OrSet, OrderedLog,
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
}

impl MemoryControlEventStore {
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

impl ControlEventStore for MemoryControlEventStore {
    fn put_pending_with_ingress(
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
        Ok(())
    }

    fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()> {
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

    fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .get(event_digest.as_str())
            .cloned())
    }

    fn digest_suite(
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

    fn covering_seals(&self, event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sealed
            .get(event_digest.as_str())
            .map(|seals| seals.iter().cloned().collect())
            .unwrap_or_default())
    }

    fn control_proposal_ack(&self, event_digest: &Hash) -> StoreResult<Option<ControlProposalAck>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .control_proposal_acks
            .get(event_digest.as_str())
            .cloned())
    }

    fn control_proposal_snapshot(
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

    fn record_proposal_decision(
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

    fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(inner
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
            .take(limit)
            .collect())
    }

    fn list_pending_realms(&self, limit: usize) -> StoreResult<Vec<RealmId>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut realms = BTreeSet::new();
        for (digest, event) in &inner.events {
            if !inner.sealed.contains_key(digest)
                && !inner
                    .proposal_decisions
                    .get(digest)
                    .is_some_and(|decisions| {
                        decisions.iter().any(ControlProposalDecision::is_reject)
                    })
            {
                realms.insert(event.realm_id.clone());
                if realms.len() >= limit {
                    break;
                }
            }
        }
        Ok(realms.into_iter().collect())
    }

    fn list_pending_for_notary(
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

    fn list_sealed(
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

    fn list_retained_faults(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        Ok(self
            .list_sealed(realm_id, None, usize::MAX)?
            .into_iter()
            .filter(|record| record.decision_overdue)
            .take(limit)
            .collect())
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

        if seal.predecessor_refs.is_empty() {
            self.genesis
                .entry(realm.clone())
                .or_insert_with(|| seal.id.clone());
        }

        let leaves = self.leaves.entry(realm).or_default();
        leaves.retain(|leaf| !seal.predecessor_refs.iter().any(|p| p == leaf));
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

impl SealStore for MemorySealStore {
    fn try_claim_signing_lease(
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

    fn release_signing_lease(
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

    fn put(&self, seal: &Seal, digest_suite: arkret_canonical::DigestSuite) -> StoreResult<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.put(seal, digest_suite)
    }

    fn put_if_frontier(
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

    fn get(&self, id: &SealId) -> StoreResult<Option<Seal>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seals
            .get(id.as_str())
            .cloned())
    }

    fn digest_suite(&self, id: &SealId) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest_suites
            .get(id.as_str())
            .copied())
    }

    fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .leaves
            .get(realm_id.as_str())
            .cloned()
            .unwrap_or_default())
    }

    fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(refs.iter().all(|r| inner.seals.contains_key(r.as_str())))
    }

    fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .genesis
            .get(realm_id.as_str())
            .cloned())
    }

    fn successors(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::new();
        for seal in inner.seals.values() {
            if seal.realm_id.as_str() != realm_id.as_str() {
                continue;
            }
            if seal.predecessor_refs.iter().any(|p| p == seal_id) {
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
    /// (realm, cell) -> ordered (accepting Seal, SealedOp) list
    cell_log: BTreeMap<(String, String), Vec<(SealId, IssuedOp)>>,
    /// (realm, cell, view_hash) -> CellState
    cache: BTreeMap<(String, String, String), CellState>,
    /// seal → ops it appended (used for rollback)
    seal_ops: BTreeMap<String, Vec<(String, IssuedOp)>>, // (realm, cell), op
}

impl CellStore for MemoryCellStore {
    fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
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

    fn sealed_ops_for_cell(
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

    fn sealed_op_batches_for_cell(
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

    fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>> {
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

    fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
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

    fn append_sealed_effects(
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

    fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()> {
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

/// In-memory `CellRegistry` with hand-wired cell_family → Lattice mappings.
///
/// Production registry will load mappings from the spec
/// `event-kind-registry.json` `cell_family` / `lattice` / `bottom`
/// fields. This memory version covers the cell families exercised by
/// SDK tests and the move-seal-lattice fixture.
pub struct MemoryCellRegistry {
    bindings: BTreeMap<String, BindingDescriptor>,
}

#[derive(Clone)]
struct BindingDescriptor {
    kind: LatticeKind,
    bottom_mode: BottomMode,
    fsm_initial: Option<Value>,
    fsm_transitions: Vec<(Value, Value)>,
}

impl Default for MemoryCellRegistry {
    fn default() -> Self {
        let mut bindings = BTreeMap::new();

        // Membership FSM (per spec event-auth-state-resolution.md §5).
        bindings.insert(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::Fsm,
                bottom_mode: BottomMode::Reject,
                fsm_initial: Some(json!("invited")),
                fsm_transitions: vec![
                    (json!("invited"), json!("join")),
                    (json!("join"), json!("leave")),
                    (json!("join"), json!("ban")),
                    (json!("leave"), json!("join")),
                    (json!("invited"), json!("leave")),
                ],
            },
        );

        // Capability grant or-set.
        bindings.insert(
            arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Consent or-set (ak.component.consent.grant.v1) — spec consent-model §3.1.
        bindings.insert(
            arkret_wire::CellFamilyId::CONSENT_GRANT_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrSet,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Notary cell — cas-register, bottom=reject.
        bindings.insert(
            arkret_wire::CellFamilyId::NOTARY_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Generic Realm policy — cas-register, bottom=reject (spec §5 example).
        bindings.insert(
            arkret_wire::CellFamilyId::REALM_POLICY_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Realm digest suite — the create projection installs the initial
        // value and a hash-transition Move causally replaces it.
        bindings.insert(
            arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // Audit log / message log — ordered-log.
        bindings.insert(
            arkret_wire::CellFamilyId::AUDIT_ACCESS_LOG_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::OrderedLog,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );

        // MLS commit Move target cells (spec §10).
        // mls_epoch: cas-register, bottom=reject (racing commits fail closed).
        bindings.insert(
            arkret_wire::CellFamilyId::MLS_EPOCH_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        // key_schedule: cas-register, bottom=reject (one schedule per epoch).
        bindings.insert(
            arkret_wire::CellFamilyId::MLS_KEY_SCHEDULE_V1.to_owned(),
            BindingDescriptor {
                kind: LatticeKind::CasRegister,
                bottom_mode: BottomMode::Reject,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
        Self { bindings }
    }
}

impl MemoryCellRegistry {
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

    /// Return every registered cell family in deterministic order.
    pub fn registered_families(&self) -> impl Iterator<Item = &str> {
        self.bindings.keys().map(String::as_str)
    }

    /// Register an additional binding (test fixtures / Realm-level overrides).
    pub fn register(
        &mut self,
        cell_family: impl Into<String>,
        kind: LatticeKind,
        bottom_mode: BottomMode,
    ) {
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                kind,
                bottom_mode,
                fsm_initial: None,
                fsm_transitions: vec![],
            },
        );
    }

    pub fn register_fsm(
        &mut self,
        cell_family: impl Into<String>,
        initial: Option<Value>,
        transitions: Vec<(Value, Value)>,
        bottom_mode: BottomMode,
    ) {
        self.bindings.insert(
            cell_family.into(),
            BindingDescriptor {
                kind: LatticeKind::Fsm,
                bottom_mode,
                fsm_initial: initial,
                fsm_transitions: transitions,
            },
        );
    }
}

impl CellRegistry for MemoryCellRegistry {
    fn resolve(&self, _realm_id: &RealmId, cell: &CellRef) -> StoreResult<CellLatticeBinding> {
        // Parse "ak:cell:<family>:<subject>" — family is between the 2nd and 3rd colons.
        let cell_id = crate::CellId::parse(cell.as_str())
            .map_err(|e| StoreError::Backend(format!("invalid cell ref: {e}")))?;
        let family = cell_id.component();
        let descriptor = self
            .bindings
            .get(family)
            .ok_or_else(|| StoreError::NotFound(format!("unknown cell family: {family}")))?;
        let lattice: Box<dyn Lattice> = match descriptor.kind {
            LatticeKind::OrSet => Box::new(OrSet),
            LatticeKind::MvRegister => Box::new(MvRegister),
            LatticeKind::CasRegister => Box::new(CasRegister),
            LatticeKind::Fsm => {
                let mut fsm = Fsm::new(descriptor.fsm_transitions.clone());
                if let Some(initial) = descriptor.fsm_initial.clone() {
                    fsm = fsm.with_initial(initial);
                }
                Box::new(fsm)
            }
            LatticeKind::Counter => Box::new(Counter),
            LatticeKind::OrderedLog => Box::new(OrderedLog),
        };
        Ok(CellLatticeBinding {
            lattice,
            bottom_mode: descriptor.bottom_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidCoreId, DidUrl};

    use crate::lattice::SealedOp;

    fn issued(op: SealedOp) -> IssuedOp {
        IssuedOp {
            issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            op,
        }
    }

    use std::sync::{Arc, Barrier};

    use arkret_wire::ProducerEventProof;
    use arkret_wire::event_envelope::ScopeRef;
    use chrono::{TimeZone, Utc};

    use super::super::AcklessSelfPrincipalIngress;
    use super::*;
    use crate::{
        Hlc, LatticeOp, LatticeOpType, NotarySig, PayloadSignature, SealBasis, SealSignature,
    };

    const SUITE: arkret_canonical::DigestSuite = arkret_canonical::DigestSuite::Sha256;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN".to_owned()).unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    /// A Control Move: an Event carrying `seal_basis`, distinguished from
    /// its siblings by `actor_seq` so each one hashes to a different
    /// `event_digest` (the store key).
    fn control_move(actor_seq: u64) -> Event {
        let created_at = Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap();
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.member.state",
            ScopeRef::Realm { realm_id: realm() },
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureadmin".to_owned()).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap(),
            actor_seq,
            Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            serde_json::json!({"state": "join"}),
            created_at,
        )
        .unwrap();
        event.seal_basis = Some(SealBasis {
            leaves: vec![seal_id(0xaa)],
        });
        event
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        event.proofs.push(
            ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:admin.example#k1").unwrap(),
                event_digest: Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap())
                    .unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }
            .into(),
        );
        event
    }

    fn dummy_seal(id: SealId, predecessors: Vec<SealId>, delta: Vec<Hash>) -> Seal {
        let seed = u64::from_str_radix(&id.as_str()[15..17], 16).unwrap();
        let sig = SealSignature {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1").unwrap(),
            payload_digest: hash(0xff),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        };
        let mut seal = Seal {
            id,
            realm_id: realm(),
            predecessor_refs: predecessors,
            delta,
            control_event_set_root: hash(0x22),
            state_root: hash(0x77),
            completeness_root: hash(0x33),
            notary_seq: seed,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(sig),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        seal.id = seal.derive_id(SUITE).unwrap();
        seal
    }

    fn control_proposal_ack(event: &Event) -> ControlProposalAck {
        let received_at = Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap();
        let proposal_digest = control_event_digest(event, SUITE).unwrap();
        let authority_set_ref = hash(0x44);
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: event.realm_id.clone(),
            proposal_digest: proposal_digest.clone(),
            received_at,
            decision_due_at: received_at + chrono::Duration::seconds(30),
            absolute_due_at: received_at + chrono::Duration::seconds(90),
            authority_set_ref: authority_set_ref.clone(),
            signature: PayloadSignature {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1")
                    .unwrap(),
                payload_digest: hash(0),
                created_at: received_at,
                jws: "e30..c2ln".to_owned(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
        ControlProposalAck {
            kind: arkret_wire::ControlProposalAckKind::SignedAck,
            realm_id: event.realm_id.clone(),
            proposal_digest,
            received_at,
            decision_due_at: received_at + chrono::Duration::seconds(30),
            absolute_due_at: received_at + chrono::Duration::seconds(90),
            defer_count: 0,
            authority_set_ref,
            authority_acks: vec![authority_ack],
        }
    }

    fn signed_reject(ack: &ControlProposalAck) -> ControlProposalDecision {
        let decided_at = ack.received_at + chrono::Duration::seconds(20);
        let mut decision = ControlProposalDecision::SignedReject {
            realm_id: ack.realm_id.clone(),
            proposal_digest: ack.proposal_digest.clone(),
            proposal_ack_digest: ack.proposal_ack_digest().unwrap(),
            decided_at,
            decision_due_at: ack.decision_due_at,
            absolute_due_at: ack.absolute_due_at,
            defer_count: 0,
            reason_code: arkret_wire::ControlProposalRejectReason::PolicyDenied,
            authority_set_ref: ack.authority_set_ref.clone(),
            proofs: vec![PayloadSignature {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1")
                    .unwrap(),
                payload_digest: hash(0),
                created_at: decided_at,
                jws: "e30..c2ln".to_owned(),
            }],
        };
        let decision_digest = decision.decision_digest().unwrap();
        let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision else {
            unreachable!("constructed a signed reject");
        };
        proofs[0].payload_digest = decision_digest;
        decision
    }

    #[test]
    fn control_event_store_records_decision_with_effective_realm_policy() {
        let store = MemoryControlEventStore::default();
        let event = control_move(1);
        let event_digest = control_event_digest(&event, SUITE).unwrap();
        let ack = control_proposal_ack(&event);
        let decision = signed_reject(&ack);
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();

        assert!(
            decision
                .validate_chain(
                    &ack,
                    &[],
                    arkret_wire::ControlProposalDecisionPolicy::protocol_maximum(),
                )
                .is_err(),
            "the protocol ceiling must not substitute for the effective Realm policy"
        );

        store
            .put_pending_with_ingress(
                &event,
                &ControlProposalIngress::AckRequired(ack.clone()),
                SUITE,
            )
            .unwrap();
        store
            .record_proposal_decision(&event_digest, &decision, policy)
            .unwrap();
        store
            .record_proposal_decision(&event_digest, &decision, policy)
            .unwrap();
        assert!(
            store
                .list_pending_records(&event.realm_id, 10)
                .unwrap()
                .is_empty(),
            "a terminal signed rejection must remove the proposal from the pending work set"
        );
        let snapshot = store
            .control_proposal_snapshot(&event_digest)
            .unwrap()
            .expect("rejected proposal remains durable");
        assert_eq!(snapshot.control_proposal_ack, Some(ack));
        assert_eq!(snapshot.decisions, vec![decision]);
        assert!(snapshot.covering_seals.is_empty());
    }

    #[test]
    fn ack_leaves_the_proposal_pending_and_only_an_accepted_seal_finalizes_it() {
        // `event-auth-state-resolution.md` §7.2: a Control Proposal Ack proves
        // the authority set signed for the exact proposal digest and took on a
        // bounded decision obligation. It is not an acceptance. Control-plane
        // finality arrives only when an accepted Seal covers the digest.
        let store = MemoryControlEventStore::default();
        let event = control_move(1);
        let digest = control_event_digest(&event, SUITE).unwrap();
        let ack = control_proposal_ack(&event);

        store
            .put_pending_with_ingress(
                &event,
                &ControlProposalIngress::AckRequired(ack.clone()),
                SUITE,
            )
            .unwrap();

        let pending = store.list_pending_records(&realm(), 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].control_proposal_ack.as_ref(),
            Some(&ack),
            "the Ack is retained as pending evidence"
        );
        assert!(
            pending[0].decisions.is_empty(),
            "an Ack on its own decides nothing"
        );
        assert!(
            store.list_sealed(&realm(), None, 10).unwrap().is_empty(),
            "an Ack must not produce control-plane finality"
        );

        let seal = dummy_seal(seal_id(0xaa), Vec::new(), vec![digest.clone()]);
        store.mark_sealed(&digest, &seal).unwrap();
        let concurrent_seal = dummy_seal(seal_id(0xab), Vec::new(), vec![digest.clone()]);
        store.mark_sealed(&digest, &concurrent_seal).unwrap();

        assert!(
            store.list_pending_records(&realm(), 10).unwrap().is_empty(),
            "the accepted Seal is what retires the pending proposal"
        );
        let sealed = store.list_sealed(&realm(), None, 10).unwrap();
        assert_eq!(sealed.len(), 1);
        let mut expected_covering_seals = vec![seal.id, concurrent_seal.id];
        expected_covering_seals.sort();
        assert_eq!(sealed[0].covering_seals, expected_covering_seals);
    }

    #[test]
    fn control_event_store_put_and_seal_idempotent() {
        let store = MemoryControlEventStore::default();
        let first = control_move(1);
        let digest = control_event_digest(&first, SUITE).unwrap();
        let ack = control_proposal_ack(&first);
        store
            .put_pending_with_ingress(
                &first,
                &ControlProposalIngress::AckRequired(ack.clone()),
                SUITE,
            )
            .unwrap();
        store
            .put_pending_with_ingress(&first, &ControlProposalIngress::AckRequired(ack), SUITE)
            .unwrap(); // idempotent
        assert_eq!(
            store.get(&digest).unwrap().unwrap().event_id,
            first.event_id
        );

        let seal = dummy_seal(seal_id(0xaa), Vec::new(), vec![digest.clone()]);
        store.mark_sealed(&digest, &seal).unwrap();
        store.mark_sealed(&digest, &seal).unwrap(); // idempotent
        let sealed = store.list_sealed(&realm(), None, 10).unwrap();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].covering_seals, vec![seal.id]);
    }

    fn ackless_ingress() -> ControlProposalIngress {
        ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        })
    }

    #[test]
    fn control_event_store_rejects_ingress_class_mismatch_on_replay() {
        let store = MemoryControlEventStore::default();
        let event = control_move(1);
        let ack = control_proposal_ack(&event);
        store
            .put_pending_with_ingress(
                &event,
                &ControlProposalIngress::AckRequired(ack.clone()),
                SUITE,
            )
            .unwrap();
        // The same digest replayed under a different class is a conflict:
        // the first admission's class is part of the durable basis.
        let ackless = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        });
        assert!(
            store
                .put_pending_with_ingress(&event, &ackless, SUITE)
                .is_err(),
            "an Ack-required Move cannot be replayed as Ack-less"
        );
        assert!(
            store
                .put_pending_with_ingress(&event, &ControlProposalIngress::AckRequired(ack), SUITE,)
                .is_ok(),
            "the byte-identical class and Ack remain idempotent"
        );
    }

    #[test]
    fn control_event_store_retains_ackless_self_principal_classification() {
        let store = MemoryControlEventStore::default();
        let event = control_move(1);
        let class = AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 7,
            seal_basis_digest: "sha256:fixture".to_owned(),
        };
        store
            .put_pending_with_ingress(
                &event,
                &ControlProposalIngress::AcklessSelfPrincipal(class.clone()),
                SUITE,
            )
            .unwrap();
        let pending = store.list_pending_records(&realm(), 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].control_proposal_ack, None);
        assert_eq!(
            pending[0].ingress_class,
            ControlProposalIngressClass::AcklessSelfPrincipal(class),
            "the Ack-less classification is part of the durable pending row"
        );
    }

    #[test]
    fn signing_lease_fence_remains_monotonic_after_release() {
        let store = MemorySealStore::default();
        let first = store
            .try_claim_signing_lease(&realm(), "single_chain", "holder-a", 10, 20)
            .unwrap()
            .unwrap();
        assert!(
            store
                .release_signing_lease(&realm(), "single_chain", "holder-a", first)
                .unwrap()
        );
        let second = store
            .try_claim_signing_lease(&realm(), "single_chain", "holder-a", 21, 30)
            .unwrap()
            .unwrap();
        assert!(second > first);
        assert!(
            !store
                .release_signing_lease(&realm(), "single_chain", "holder-a", first)
                .unwrap()
        );
    }

    #[test]
    fn control_event_store_lists_pending_by_insertion_order() {
        let store = MemoryControlEventStore::default();
        let first = control_move(1);
        let second = control_move(2);
        store
            .put_pending_with_ingress(
                &first,
                &ControlProposalIngress::AckRequired(control_proposal_ack(&first)),
                SUITE,
            )
            .unwrap();
        store
            .put_pending_with_ingress(
                &second,
                &ControlProposalIngress::AckRequired(control_proposal_ack(&second)),
                SUITE,
            )
            .unwrap();

        let pending = store.list_pending_for_notary(&realm(), None, 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].event_id, first.event_id);
        assert_eq!(pending[1].event_id, second.event_id);

        let first_digest = control_event_digest(&first, SUITE).unwrap();
        store
            .mark_sealed(
                &first_digest,
                &dummy_seal(seal_id(0xaa), Vec::new(), vec![first_digest.clone()]),
            )
            .unwrap();
        let pending = store.list_pending_for_notary(&realm(), None, 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, second.event_id);
    }

    #[test]
    fn control_event_store_keys_on_digest_not_event_id() {
        // Two variants of one `event_id` are exactly the §6.3.2 fork case: a
        // store keyed on `event_id` would collapse them into one slot and lose
        // the evidence the quarantine rule needs.
        let store = MemoryControlEventStore::default();
        let original = control_move(1);
        let mut variant = original.clone();
        variant.created_at = Utc.with_ymd_and_hms(2026, 5, 9, 0, 0, 0).unwrap();
        assert_eq!(variant.event_id, original.event_id);

        store
            .put_pending_with_ingress(&original, &ackless_ingress(), SUITE)
            .unwrap();
        store
            .put_pending_with_ingress(&variant, &ackless_ingress(), SUITE)
            .unwrap();
        assert_ne!(
            control_event_digest(&original, SUITE).unwrap(),
            control_event_digest(&variant, SUITE).unwrap()
        );
        assert_eq!(
            store
                .list_pending_for_notary(&realm(), None, 10)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn seal_store_tracks_genesis_and_leaves() {
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xa0), vec![], vec![hash(0x01)]);
        store.put(&g, SUITE).unwrap();
        assert_eq!(store.genesis(&realm()).unwrap().unwrap(), g.id);
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![g.id.clone()]);

        let child = dummy_seal(seal_id(0xa1), vec![g.id], vec![hash(0x02)]);
        store.put(&child, SUITE).unwrap();
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![child.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_accepts_exact_set() {
        let store = MemorySealStore::default();
        let genesis = dummy_seal(seal_id(0xe0), vec![], vec![hash(0x01)]);
        assert!(store.put_if_frontier(&genesis, &[], SUITE).unwrap());

        let left = dummy_seal(seal_id(0xe1), vec![genesis.id.clone()], vec![hash(0x02)]);
        store.put(&left, SUITE).unwrap();
        let right = dummy_seal(seal_id(0xe2), vec![genesis.id], vec![hash(0x03)]);
        store.put(&right, SUITE).unwrap();

        let joined = dummy_seal(
            seal_id(0xe3),
            vec![left.id.clone(), right.id.clone()],
            vec![hash(0x04)],
        );
        assert!(
            store
                .put_if_frontier(&joined, &[right.id.clone(), left.id, right.id], SUITE)
                .unwrap()
        );
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![joined.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_rejects_stale_set_without_mutation() {
        let store = MemorySealStore::default();
        let genesis = dummy_seal(seal_id(0xf0), vec![], vec![hash(0x01)]);
        store.put(&genesis, SUITE).unwrap();
        let stale = dummy_seal(seal_id(0xf1), vec![genesis.id.clone()], vec![hash(0x02)]);

        assert!(
            !store
                .put_if_frontier(&stale, &[seal_id(0xff)], SUITE)
                .unwrap()
        );
        assert!(store.get(&stale.id).unwrap().is_none());
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![genesis.id]);
    }

    #[test]
    fn seal_store_put_if_frontier_allows_only_one_concurrent_writer() {
        let store = Arc::new(MemorySealStore::default());
        let genesis = dummy_seal(seal_id(0x90), vec![], vec![hash(0x01)]);
        store.put(&genesis, SUITE).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let writers: Vec<_> = [
            dummy_seal(seal_id(0x91), vec![genesis.id.clone()], vec![hash(0x02)]),
            dummy_seal(seal_id(0x92), vec![genesis.id.clone()], vec![hash(0x03)]),
        ]
        .into_iter()
        .map(|candidate| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let expected = genesis.id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let inserted = store
                    .put_if_frontier(&candidate, &[expected], SUITE)
                    .unwrap();
                (candidate.id, inserted)
            })
        })
        .collect();

        barrier.wait();
        let outcomes: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|(_, inserted)| *inserted).count(), 1);

        let winner = outcomes
            .iter()
            .find_map(|(id, inserted)| inserted.then_some(id.clone()))
            .unwrap();
        let loser = outcomes
            .iter()
            .find_map(|(id, inserted)| (!inserted).then_some(id.clone()))
            .unwrap();
        assert_eq!(store.list_leaves(&realm()).unwrap(), vec![winner]);
        assert!(store.get(&loser).unwrap().is_none());
    }

    #[test]
    fn seal_store_successors_lists_direct_children() {
        // genesis ─► child_a ─► leaf_x
        //          ▲
        // genesis ─┴► child_b
        let store = MemorySealStore::default();
        let g = dummy_seal(seal_id(0xa0), vec![], vec![hash(0x01)]);
        let child_a = dummy_seal(seal_id(0xa1), vec![g.id.clone()], vec![hash(0x02)]);
        let child_b = dummy_seal(seal_id(0xa2), vec![g.id.clone()], vec![hash(0x03)]);
        let leaf_x = dummy_seal(seal_id(0xa3), vec![child_a.id.clone()], vec![hash(0x04)]);
        store.put(&g, SUITE).unwrap();
        store.put(&child_a, SUITE).unwrap();
        store.put(&child_b, SUITE).unwrap();
        store.put(&leaf_x, SUITE).unwrap();

        // genesis has two direct children.
        let succ = store.successors(&realm(), &g.id).unwrap();
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&child_a.id));
        assert!(succ.contains(&child_b.id));

        // child_b is a leaf — no successors.
        assert!(store.successors(&realm(), &child_b.id).unwrap().is_empty());
    }

    #[test]
    fn seal_store_predecessor_check() {
        let store = MemorySealStore::default();
        let a = dummy_seal(seal_id(0xa0), vec![], vec![]);
        store.put(&a, SUITE).unwrap();
        assert!(store.predecessors_known(&[a.id]).unwrap());
        assert!(!store.predecessors_known(&[seal_id(0xee)]).unwrap());
        assert!(store.predecessors_known(&[]).unwrap()); // empty = trivially known
    }

    #[test]
    fn cell_store_append_and_list() {
        let store = MemoryCellStore::default();
        let op = SealedOp::new(
            hash(0x01),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        store
            .append_sealed_effects(
                &realm(),
                &seal_id(0xaa),
                &[(cell_member(), issued(op.clone()))],
            )
            .unwrap();

        let cells = store.list_cells(&realm()).unwrap();
        assert_eq!(cells.len(), 1);
        let ops = store.sealed_ops_for_cell(&realm(), &cell_member()).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, op);
    }

    #[test]
    fn cell_store_rollback_undoes_append() {
        let store = MemoryCellStore::default();
        let op = SealedOp::new(
            hash(0x01),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        let seal = seal_id(0xaa);
        store
            .append_sealed_effects(&realm(), &seal, &[(cell_member(), issued(op))])
            .unwrap();
        store.rollback_seal(&realm(), &seal).unwrap();
        assert!(
            store
                .sealed_ops_for_cell(&realm(), &cell_member())
                .unwrap()
                .is_empty()
        );
        assert!(store.list_cells(&realm()).unwrap().is_empty());
    }

    #[test]
    fn cell_store_cache_round_trip_and_invalidation() {
        let store = MemoryCellStore::default();
        let view = hash(0x33);
        store
            .put_cached_state(
                &realm(),
                &cell_member(),
                &view,
                &CellState::Value(json!("x")),
            )
            .unwrap();
        assert_eq!(
            store.cached_state(&realm(), &cell_member(), &view).unwrap(),
            Some(CellState::Value(json!("x")))
        );
        // append should invalidate cache.
        let op = SealedOp::new(
            hash(0x05),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );
        store
            .append_sealed_effects(&realm(), &seal_id(0xab), &[(cell_member(), issued(op))])
            .unwrap();
        assert!(
            store
                .cached_state(&realm(), &cell_member(), &view)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cell_registry_resolves_known_families() {
        let reg = MemoryCellRegistry::new();
        let binding = reg.resolve(&realm(), &cell_member()).unwrap();
        assert_eq!(binding.lattice.kind(), LatticeKind::Fsm);
        assert_eq!(binding.bottom_mode, BottomMode::Reject);
    }

    #[test]
    fn cell_registry_unknown_family_fails_closed() {
        let reg = MemoryCellRegistry::new();
        let weird = CellRef::new("ak:cell:ak.component.future.unknown.v1:x".to_owned()).unwrap();
        let err = reg.resolve(&realm(), &weird).unwrap_err();
        assert!(format!("{err}").contains("unknown cell family"));
    }

    #[test]
    fn cell_registry_or_set_and_cas_lattices_resolve() {
        let reg = MemoryCellRegistry::new();
        let consent =
            CellRef::new("ak:cell:ak.component.consent.grant.v1:ak.consent.x".to_owned()).unwrap();
        assert_eq!(
            reg.resolve(&realm(), &consent).unwrap().lattice.kind(),
            LatticeKind::OrSet
        );

        let policy =
            CellRef::new("ak:cell:ak.component.realm.policy.v1:ak.realm.x".to_owned()).unwrap();
        assert_eq!(
            reg.resolve(&realm(), &policy).unwrap().lattice.kind(),
            LatticeKind::CasRegister
        );
    }
}
