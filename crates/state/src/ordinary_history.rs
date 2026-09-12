//! Low-level ordinary-history classification over explicit algorithm inputs.
//!
//! This module does not infer authorization instances from unverified payloads,
//! nor does it decide live admission after a known revocation. Input constructors
//! check content binding and coordinate structure, not signatures or permission.
//! Consequently a classifier result is conditional on its supplied inputs and
//! is not an authorization token. Production admission requires an authenticated
//! source adapter, complete business validation and authenticated closure coverage.

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

/// An explicit historical authorization dependency input to the algorithm.
///
/// These are runtime coordinates, not a wire claim. The verifier must include
/// every actual registered member, device, registration, scope and delegated-parent
/// authorization, including all actions actually used. It must derive exact
/// instance/generation identities from authenticated historical state. Scope
/// coordinates must be normalized by those rules; this reducer does not guess
/// scope containment from names or current business state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationUse {
    pub authority_realm_id: RealmId,
    pub dependency_kind: arkret_wire::AuthorizationDependencyKind,
    pub authorization_event_id: EventId,
    pub generation_event_id: EventId,
    pub scope_ref: ScopeRef,
    pub actions: BTreeSet<arkret_wire::CapabilityActionId>,
}

/// Caller-supplied algorithm input; this enum does not certify authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryAuthorizationInput {
    Ordinary {
        uses: Vec<AuthorizationUse>,
        /// Registered execution dependencies only. Ordinary causal references
        /// do not automatically propagate a parent's quarantine status.
        execution_dependencies: BTreeSet<EventId>,
    },
    /// Input asserting authenticated command bytes, before or after a
    /// terminal decision. Only committed commands provide execution effects.
    ControlEvidence {
        command_outcome: Option<CommandOutcome>,
    },
    /// Input asserting that signature and content binding verified, but historical
    /// authorization evidence denies this ordinary Event. Keep the evidence;
    /// do not confuse an authorization denial with a malformed signature.
    Unauthorized,
    /// Input asserting content and producer authentication, but business authorization
    /// still needs evidence. Pure causal observation does not execute it.
    AuthorizationPending,
}

/// Event bytes plus structurally checked classification inputs.
/// This is deliberately not named or usable as an authenticated Event token.
#[derive(Clone, Debug)]
pub struct HistoryEventInput {
    event: Event,
    authorization: HistoryAuthorizationInput,
}

impl HistoryEventInput {
    /// Check the Event digest and closed coordinate vocabulary only.
    /// No callback can turn this constructor into a cryptographic verification
    /// boundary. An empty ordinary-use set is structurally invalid.
    pub fn from_inputs(
        event: Event,
        digest_suite: DigestSuite,
        authorization: HistoryAuthorizationInput,
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
        if let HistoryAuthorizationInput::Ordinary { uses, .. } = &authorization {
            if uses.is_empty()
                || uses.iter().any(|usage| {
                    usage.actions.is_empty()
                        || usage.scope_ref.realm_id_opt() != Some(&usage.authority_realm_id)
                        || !usage.dependency_kind.permits_scope(&usage.scope_ref)
                        || usage
                            .actions
                            .iter()
                            .any(|action| !usage.dependency_kind.permits_action(*action))
                })
            {
                return Err(HistoryEvidenceError::Invalid(
                    "ordinary history requires valid nonempty registered authorization coordinates"
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
    pub fn authorization(&self) -> &HistoryAuthorizationInput {
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

/// A structurally complete security prefix input through an exact known head.
/// Completeness is relative to this head, never a claim to know remote future
/// revocations. A receiver that has learned a newer head must rebuild it.
#[derive(Clone, Debug)]
pub struct HistoryClosurePrefixInput {
    realm_id: RealmId,
    head: SealId,
    closures: Vec<AuthorizationClosure>,
    committed_events: BTreeSet<EventId>,
}

impl HistoryClosurePrefixInput {
    /// Check full genesis-to-head structure and closure-to-command membership.
    /// This does not verify authority signatures, command execution or omitted
    /// closure entries and cannot certify a production security inventory.
    pub fn from_complete_prefix_inputs(
        seals: &[Seal],
        expected_head: &SealId,
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
        let mut committed_events = BTreeSet::new();
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
            for result in seal
                .command_results
                .iter()
                .filter(|result| result.outcome == CommandOutcome::Committed)
            {
                for digest in &result.unit_event_digests {
                    committed_events.insert(
                        EventId::from_event_digest(digest)
                            .map_err(|error| HistoryEvidenceError::Invalid(error.to_string()))?,
                    );
                }
            }
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
            committed_events,
        })
    }

    pub fn head(&self) -> &SealId {
        &self.head
    }
}

/// Structurally complete cut inputs, indexed by their claimed authority Realm.
/// A missing Realm is pending, not an empty set of cuts. In particular a
/// collaboration Realm prefix cannot replace a required device PCR prefix.
#[derive(Clone, Debug)]
pub struct HistoryClosureInventoryInput {
    prefixes: BTreeMap<RealmId, HistoryClosurePrefixInput>,
}

impl HistoryClosureInventoryInput {
    pub fn from_prefix_inputs(
        prefixes: impl IntoIterator<Item = HistoryClosurePrefixInput>,
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
                "no security prefix input".into(),
            ));
        }
        Ok(Self { prefixes: result })
    }
}

/// Supply content-bound algorithm inputs. Missing
/// records must return `None` or `Unavailable`, never a fabricated leaf.
/// One classification observes a fixed evidence snapshot: repeated lookups
/// must not change bytes or authorization state during that evaluation.
pub trait HistoryInputSource {
    fn event(&self, event_id: &EventId)
    -> Result<Option<&HistoryEventInput>, HistoryEvidenceError>;
}

/// Complete ancestry of the supplied finite frontier inputs. Empty is a valid
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
    source: &'a impl HistoryInputSource,
    id: &EventId,
) -> Result<&'a HistoryEventInput, HistoryEvidenceError> {
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

fn available_or_pending<T>(
    result: Result<T, HistoryEvidenceError>,
    pending: &mut Option<String>,
) -> Result<Option<T>, HistoryEvidenceError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(HistoryEvidenceError::Unavailable(reason)) => {
            pending.get_or_insert(reason);
            Ok(None)
        }
        Err(invalid) => Err(invalid),
    }
}

/// Resolve every predecessor and causal reference in the input graph. Missing
/// any ancestor prevents a nonmembership conclusion for the entire frontier.
pub fn resolve_complete_history_frontier(
    frontier: &[EventId],
    source: &impl HistoryInputSource,
) -> Result<CompleteHistoryClosure, HistoryEvidenceError> {
    if frontier.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(HistoryEvidenceError::Invalid(
            "history frontier must be sorted and unique".into(),
        ));
    }
    let mut complete = BTreeSet::new();
    let mut pending = None;
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
                "Event input ancestry contains a cycle".into(),
            ));
        }
        let Some(event) = available_or_pending(required_event(source, &id), &mut pending)? else {
            active.remove(&id);
            continue;
        };
        stack.push((id, true));
        stack.extend(
            event
                .parents()?
                .into_iter()
                .rev()
                .map(|parent| (parent, false)),
        );
    }
    if let Some(reason) = pending {
        return Err(HistoryEvidenceError::Unavailable(reason));
    }
    Ok(CompleteHistoryClosure {
        frontier: frontier.to_vec(),
        event_ids: complete,
    })
}

/// Build the exact maximal frontier of a selected history input set plus
/// all of its ancestors. Callers choose Events using authenticated historical
/// authorization; this function neither enumerates a store nor invents cuts.
/// Oversized frontiers must be rejected, never truncated or split into cuts.
pub fn frontier_for_complete_history(
    selected: &BTreeSet<EventId>,
    source: &impl HistoryInputSource,
) -> Result<CompleteHistoryClosure, HistoryEvidenceError> {
    let mut closure =
        resolve_complete_history_frontier(&selected.iter().cloned().collect::<Vec<_>>(), source)?;
    let mut maximal = closure.event_ids.clone();
    for id in selected {
        if matches!(
            required_event(source, id)?.authorization,
            HistoryAuthorizationInput::AuthorizationPending
        ) {
            return Err(HistoryEvidenceError::Unavailable(
                "selected Event authorization is unresolved".into(),
            ));
        }
        if matches!(
            required_event(source, id)?.authorization,
            HistoryAuthorizationInput::Unauthorized
        ) {
            return Err(HistoryEvidenceError::Invalid(
                "selected frontier includes historically unauthorized evidence".into(),
            ));
        }
    }
    for id in &closure.event_ids {
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
        rejected_commands: BTreeSet<EventId>,
    },
}

fn matching_cut(usage: &AuthorizationUse, closure: &AuthorizationClosure) -> bool {
    usage.dependency_kind == closure.dependency_kind
        && usage.authorization_event_id == closure.authorization_event_id
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
/// eligibility is not inherited. Invalid evidence is rejected. A complete
/// applicable cut's definite exclusion takes priority over other missing
/// dependencies; missing evidence alone remains pending.
pub fn classify_ordinary_history(
    event_id: &EventId,
    inventory: &HistoryClosureInventoryInput,
    source: &impl HistoryInputSource,
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
    inventory: &HistoryClosureInventoryInput,
    source: &impl HistoryInputSource,
) -> Result<OrdinaryHistoryEligibility, HistoryEvidenceError> {
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut stack = vec![(event_id.clone(), false)];
    let mut excluded = BTreeSet::new();
    let mut unauthorized = BTreeSet::new();
    let mut rejected_commands = BTreeSet::new();
    let mut pending = None;
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
        let Some(event) = available_or_pending(required_event(source, &id), &mut pending)? else {
            continue;
        };
        available_or_pending(
            resolve_complete_history_frontier(std::slice::from_ref(&id), source),
            &mut pending,
        )?;
        if matches!(
            event.authorization,
            HistoryAuthorizationInput::AuthorizationPending
        ) {
            pending
                .get_or_insert_with(|| format!("ordinary Event {id} authorization is unresolved"));
            continue;
        }
        if matches!(event.authorization, HistoryAuthorizationInput::Unauthorized) {
            unauthorized.insert(id);
            continue;
        }
        if let HistoryAuthorizationInput::ControlEvidence { command_outcome } = &event.authorization
        {
            if &id == event_id {
                return Err(HistoryEvidenceError::Invalid(
                    "ordinary eligibility requested for a control Event".into(),
                ));
            }
            match command_outcome {
                Some(CommandOutcome::Committed) => {}
                Some(CommandOutcome::Rejected) => {
                    rejected_commands.insert(id);
                }
                None => {
                    pending.get_or_insert_with(|| {
                        format!("execution dependency command {id} has no terminal decision")
                    });
                }
            }
            continue;
        }
        let HistoryAuthorizationInput::Ordinary {
            uses,
            execution_dependencies,
        } = &event.authorization
        else {
            unreachable!("other evidence classes were handled above")
        };
        stack.extend(execution_dependencies.iter().cloned().map(|id| (id, false)));
        for usage in uses {
            let Some(prefix) = available_or_pending(
                inventory
                    .prefixes
                    .get(&usage.authority_realm_id)
                    .ok_or_else(|| {
                        HistoryEvidenceError::Unavailable(format!(
                            "missing security prefix for {}",
                            usage.authority_realm_id
                        ))
                    }),
                &mut pending,
            )?
            else {
                continue;
            };
            if !prefix
                .committed_events
                .contains(&usage.authorization_event_id)
                || !prefix.committed_events.contains(&usage.generation_event_id)
            {
                pending.get_or_insert_with(|| "security prefix does not confirm the exact authorization instance and generation".into());
                continue;
            }
            for cut in prefix
                .closures
                .iter()
                .filter(|cut| matching_cut(usage, cut))
            {
                let Some(closure) = available_or_pending(
                    resolve_complete_history_frontier(&cut.frontier, source),
                    &mut pending,
                )?
                else {
                    continue;
                };
                if !closure.event_ids.contains(&id) {
                    excluded.insert(cut.command_event_id.clone());
                }
            }
        }
    }
    if excluded.is_empty() && unauthorized.is_empty() && rejected_commands.is_empty() {
        Ok(match pending {
            Some(reason) => OrdinaryHistoryEligibility::Pending { reason },
            None => OrdinaryHistoryEligibility::Eligible,
        })
    } else {
        Ok(OrdinaryHistoryEligibility::Quarantined {
            closing_commands: excluded,
            unauthorized_events: unauthorized,
            rejected_commands,
        })
    }
}

#[cfg(test)]
mod tests;
