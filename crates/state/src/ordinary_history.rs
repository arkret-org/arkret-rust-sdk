//! Persistent ordinary-history eligibility over authenticated evidence.
//!
//! This module does not infer authorization instances from unverified payloads,
//! nor does it decide live admission after a known revocation. An evidence
//! adapter must verify historical authorization and the complete relevant
//! security prefixes before these reducers can classify ordinary history.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_wire::{
    AuthorizationClosure, CommandOutcome, Event, EventId, Hash, RealmId, ScopeRef, Seal, SealId,
};

/// A missing necessary dependency is retryable; malformed authenticated
/// material is an error and never becomes business causal coverage.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoryEvidenceError {
    #[error("necessary history evidence is unavailable: {0}")]
    Unavailable(String),
    #[error("invalid history evidence: {0}")]
    Invalid(String),
}

/// One actual historical authorization dependency, after verification.
///
/// These are runtime coordinates, not a wire claim. The verifier must include
/// every applicable member, device, installation, scope and delegated-parent
/// authorization, including all actions actually used. It must derive exact
/// instance/generation identities from authenticated historical state. Scope
/// coordinates must be normalized by those rules; this reducer does not guess
/// scope containment from names or current business state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationUse {
    pub authority_realm_id: RealmId,
    pub authorization_event_id: EventId,
    pub generation_event_id: EventId,
    pub scope_ref: ScopeRef,
    pub actions: BTreeSet<String>,
}

/// The successful output of the caller's historical authorization verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoricalAuthorization {
    Ordinary {
        uses: Vec<AuthorizationUse>,
        /// Registered execution dependencies only. Ordinary causal references
        /// do not automatically propagate a parent's quarantine status.
        execution_dependencies: BTreeSet<EventId>,
    },
    /// A verified command Event may be a causal ancestor of ordinary history.
    ConfirmedControl,
    /// The signature and content binding verified, but the complete historical
    /// authorization evidence denies this ordinary Event. Keep the evidence;
    /// do not confuse an authorization denial with a malformed signature.
    Unauthorized,
}

/// Authenticated Event bytes plus verified authorization-use coordinates.
/// There is deliberately no deserializer or unchecked public constructor.
#[derive(Clone, Debug)]
pub struct VerifiedHistoryEvent {
    event: Event,
    authorization: HistoricalAuthorization,
}

impl VerifiedHistoryEvent {
    /// `verify` must authenticate the producer proof, its key/generation,
    /// authority references, historical authorization and registered payload.
    /// For control ancestors it must prove the command was committed. Returning
    /// `Unavailable` preserves pending; an empty ordinary-use set is invalid.
    pub fn verify(
        event: Event,
        digest_suite: DigestSuite,
        verify: impl FnOnce(&Event) -> Result<HistoricalAuthorization, HistoryEvidenceError>,
    ) -> Result<Self, HistoryEvidenceError> {
        let digest = event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?;
        let digest =
            Hash::new(digest).map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?;
        let expected = EventId::from_event_digest(&digest)
            .map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?;
        if expected != event.event_id {
            return Err(HistoryEvidenceError::Invalid(
                "EventId does not bind Event bytes".into(),
            ));
        }
        let authorization = verify(&event)?;
        if let HistoricalAuthorization::Ordinary { uses, .. } = &authorization {
            if uses.is_empty() || uses.iter().any(|usage| usage.actions.is_empty()) {
                return Err(HistoryEvidenceError::Invalid(
                    "ordinary history requires nonempty verified authorization uses and actions"
                        .into(),
                ));
            }
        }
        Ok(Self {
            event,
            authorization,
        })
    }

    pub fn event(&self) -> &Event {
        &self.event
    }
    pub fn authorization(&self) -> &HistoricalAuthorization {
        &self.authorization
    }

    fn parents(&self) -> Result<BTreeSet<EventId>, HistoryEvidenceError> {
        let mut parents: BTreeSet<_> = self.event.prev_refs.iter().cloned().collect();
        for digest in &self.event.causal_refs {
            parents.insert(
                EventId::from_event_digest(digest)
                    .map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?,
            );
        }
        Ok(parents)
    }
}

/// A complete, authenticated security prefix through an exact known head.
/// Completeness is relative to this head, never a claim to know remote future
/// revocations. A receiver that has learned a newer head must rebuild it.
#[derive(Clone, Debug)]
pub struct VerifiedClosurePrefix {
    realm_id: RealmId,
    head: SealId,
    closures: Vec<AuthorizationClosure>,
}

impl VerifiedClosurePrefix {
    /// Validate a full genesis-to-head prefix. The callback must verify Seal
    /// signatures/authority, command results, and the exact closure coordinates
    /// derived from every successful closing command, including omission checks.
    /// Structural validation alone is not a valid callback implementation.
    pub fn verify_complete_prefix(
        seals: &[Seal],
        expected_head: &SealId,
        mut verify_seal_and_closure_semantics: impl FnMut(&Seal) -> Result<(), HistoryEvidenceError>,
    ) -> Result<Self, HistoryEvidenceError> {
        let Some(first) = seals.first() else {
            return Err(HistoryEvidenceError::Unavailable(
                "security prefix is empty".into(),
            ));
        };
        if seals.last().map(|seal| &seal.id) != Some(expected_head) {
            return Err(HistoryEvidenceError::Unavailable(
                "security prefix does not reach its required head".into(),
            ));
        }
        let mut previous = None;
        let mut seen = BTreeSet::new();
        let mut closures = Vec::new();
        for seal in seals {
            if seal.realm_id != first.realm_id || seal.predecessor_ref.as_ref() != previous {
                return Err(HistoryEvidenceError::Unavailable(
                    "security prefix has a missing or foreign predecessor".into(),
                ));
            }
            if !seen.insert(seal.id.clone()) {
                return Err(HistoryEvidenceError::Invalid(
                    "security prefix repeats a Seal".into(),
                ));
            }
            seal.validate_structural()
                .map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?;
            verify_seal_and_closure_semantics(seal)?;
            for closure in &seal.authorization_closures {
                let command_digest = closure.command_event_id.event_digest();
                if !seal.command_results.iter().any(|result| {
                    result.outcome == CommandOutcome::Committed
                        && result.unit_event_digests.contains(&command_digest)
                }) {
                    return Err(HistoryEvidenceError::Invalid(
                        "authorization closure is not bound to a committed command in its Seal"
                            .into(),
                    ));
                }
                closures.push(closure.clone());
            }
            previous = Some(&seal.id);
        }
        Ok(Self {
            realm_id: first.realm_id.clone(),
            head: expected_head.clone(),
            closures,
        })
    }

    pub fn head(&self) -> &SealId {
        &self.head
    }
}

/// Complete known cut inventories, indexed by their authoritative Realm.
/// A missing Realm is pending, not an empty set of cuts. In particular a
/// collaboration Realm prefix cannot replace a required device PCR prefix.
#[derive(Clone, Debug)]
pub struct VerifiedClosureInventory {
    prefixes: BTreeMap<RealmId, VerifiedClosurePrefix>,
}

impl VerifiedClosureInventory {
    pub fn from_verified_prefixes(
        prefixes: impl IntoIterator<Item = VerifiedClosurePrefix>,
    ) -> Result<Self, HistoryEvidenceError> {
        let mut result = BTreeMap::new();
        for prefix in prefixes {
            if result.insert(prefix.realm_id.clone(), prefix).is_some() {
                return Err(HistoryEvidenceError::Invalid(
                    "ambiguous security heads for one Realm".into(),
                ));
            }
        }
        if result.is_empty() {
            return Err(HistoryEvidenceError::Unavailable(
                "no authenticated security prefix".into(),
            ));
        }
        Ok(Self { prefixes: result })
    }
}

/// Supply only content-bound, historically authenticated Events. Missing
/// records must return `None` or `Unavailable`, never a fabricated leaf.
pub trait HistoryEvidenceSource {
    fn event(
        &self,
        event_id: &EventId,
    ) -> Result<Option<&VerifiedHistoryEvent>, HistoryEvidenceError>;
}

/// Complete authenticated ancestry of a finite frontier. Empty is a valid
/// finite selection. There is no sequence-number or timestamp approximation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteHistoryClosure {
    frontier: Vec<EventId>,
    event_ids: BTreeSet<EventId>,
}

impl CompleteHistoryClosure {
    pub fn frontier(&self) -> &[EventId] {
        &self.frontier
    }
    pub fn event_ids(&self) -> &BTreeSet<EventId> {
        &self.event_ids
    }
}

fn required_event<'a>(
    source: &'a impl HistoryEvidenceSource,
    id: &EventId,
) -> Result<&'a VerifiedHistoryEvent, HistoryEvidenceError> {
    let event = source
        .event(id)?
        .ok_or_else(|| HistoryEvidenceError::Unavailable(format!("missing Event {id}")))?;
    if &event.event.event_id != id {
        return Err(HistoryEvidenceError::Invalid(
            "history lookup returned another EventId".into(),
        ));
    }
    Ok(event)
}

/// Resolve and verify every signed predecessor and causal reference. Missing
/// any ancestor prevents a nonmembership conclusion for the entire frontier.
pub fn verify_complete_history_frontier(
    frontier: &[EventId],
    source: &impl HistoryEvidenceSource,
) -> Result<CompleteHistoryClosure, HistoryEvidenceError> {
    if frontier.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(HistoryEvidenceError::Invalid(
            "history frontier must be sorted and unique".into(),
        ));
    }
    let mut complete = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut stack: Vec<_> = frontier
        .iter()
        .rev()
        .cloned()
        .map(|id| (id, false))
        .collect();
    while let Some((id, exiting)) = stack.pop() {
        if exiting {
            active.remove(&id);
            complete.insert(id);
            continue;
        }
        if complete.contains(&id) {
            continue;
        }
        if !active.insert(id.clone()) {
            return Err(HistoryEvidenceError::Invalid(
                "authenticated Event ancestry contains a cycle".into(),
            ));
        }
        let event = required_event(source, &id)?;
        stack.push((id, true));
        stack.extend(
            event
                .parents()?
                .into_iter()
                .rev()
                .map(|parent| (parent, false)),
        );
    }
    Ok(CompleteHistoryClosure {
        frontier: frontier.to_vec(),
        event_ids: complete,
    })
}

/// Build the exact maximal frontier of a verified selected history set plus
/// all of its ancestors. Callers choose Events using authenticated historical
/// authorization; this function neither enumerates a store nor invents cuts.
/// Oversized frontiers must be rejected, never truncated or split into cuts.
pub fn frontier_for_complete_history(
    selected: &BTreeSet<EventId>,
    source: &impl HistoryEvidenceSource,
) -> Result<CompleteHistoryClosure, HistoryEvidenceError> {
    let mut closure =
        verify_complete_history_frontier(&selected.iter().cloned().collect::<Vec<_>>(), source)?;
    let mut maximal = closure.event_ids.clone();
    for id in &closure.event_ids {
        if matches!(
            required_event(source, id)?.authorization,
            HistoricalAuthorization::Unauthorized
        ) {
            return Err(HistoryEvidenceError::Invalid(
                "selected frontier includes historically unauthorized evidence".into(),
            ));
        }
        for parent in required_event(source, id)?.parents()? {
            maximal.remove(&parent);
        }
    }
    if maximal.len() > 4096 {
        return Err(HistoryEvidenceError::Invalid(
            "complete history frontier exceeds 4096 Events".into(),
        ));
    }
    closure.frontier = maximal.into_iter().collect();
    Ok(closure)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrdinaryHistoryEligibility {
    Eligible,
    Pending {
        reason: String,
    },
    Quarantined {
        closing_commands: BTreeSet<EventId>,
        unauthorized_events: BTreeSet<EventId>,
    },
}

fn matching_cut(usage: &AuthorizationUse, closure: &AuthorizationClosure) -> bool {
    usage.authorization_event_id == closure.authorization_event_id
        && usage.generation_event_id == closure.generation_event_id
        && usage.scope_ref == closure.scope_ref
        && closure
            .actions
            .iter()
            .any(|action| usage.actions.contains(action))
}

/// Classify an ordinary Event and its actual execution dependencies. Every
/// matching cut is evaluated; a later wider cut cannot revive an earlier
/// excluded Event. Causal-only ancestors are authenticated but their business
/// eligibility is not inherited. All needed evidence must be complete before
/// returning a terminal classification.
pub fn classify_ordinary_history(
    event_id: &EventId,
    inventory: &VerifiedClosureInventory,
    source: &impl HistoryEvidenceSource,
) -> Result<OrdinaryHistoryEligibility, HistoryEvidenceError> {
    match classify_complete(event_id, inventory, source) {
        Err(HistoryEvidenceError::Unavailable(reason)) => {
            Ok(OrdinaryHistoryEligibility::Pending { reason })
        }
        result => result,
    }
}

fn classify_complete(
    event_id: &EventId,
    inventory: &VerifiedClosureInventory,
    source: &impl HistoryEvidenceSource,
) -> Result<OrdinaryHistoryEligibility, HistoryEvidenceError> {
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut stack = vec![(event_id.clone(), false)];
    let mut excluded = BTreeSet::new();
    let mut unauthorized = BTreeSet::new();
    while let Some((id, exiting)) = stack.pop() {
        if exiting {
            active.remove(&id);
            visited.insert(id);
            continue;
        }
        if visited.contains(&id) {
            continue;
        }
        if !active.insert(id.clone()) {
            return Err(HistoryEvidenceError::Invalid(
                "ordinary execution dependencies contain a cycle".into(),
            ));
        }
        stack.push((id.clone(), true));
        let event = required_event(source, &id)?;
        verify_complete_history_frontier(std::slice::from_ref(&id), source)?;
        if matches!(event.authorization, HistoricalAuthorization::Unauthorized) {
            unauthorized.insert(id);
            continue;
        }
        let HistoricalAuthorization::Ordinary {
            uses,
            execution_dependencies,
        } = &event.authorization
        else {
            if &id == event_id {
                return Err(HistoryEvidenceError::Invalid(
                    "ordinary eligibility requested for a control Event".into(),
                ));
            }
            continue;
        };
        stack.extend(execution_dependencies.iter().cloned().map(|id| (id, false)));
        for usage in uses {
            let prefix = inventory
                .prefixes
                .get(&usage.authority_realm_id)
                .ok_or_else(|| {
                    HistoryEvidenceError::Unavailable(format!(
                        "missing security prefix for {}",
                        usage.authority_realm_id
                    ))
                })?;
            for cut in prefix
                .closures
                .iter()
                .filter(|cut| matching_cut(usage, cut))
            {
                let closure = verify_complete_history_frontier(&cut.frontier, source)?;
                if !closure.event_ids.contains(&id) {
                    excluded.insert(cut.command_event_id.clone());
                }
            }
        }
    }
    if excluded.is_empty() && unauthorized.is_empty() {
        Ok(OrdinaryHistoryEligibility::Eligible)
    } else {
        Ok(OrdinaryHistoryEligibility::Quarantined {
            closing_commands: excluded,
            unauthorized_events: unauthorized,
        })
    }
}

#[cfg(test)]
mod tests;
