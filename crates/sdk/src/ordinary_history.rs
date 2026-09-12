//! Authentication of historical authorization source origins.
//!
//! An authenticated origin is not a business permission, an active generation,
//! a complete closure inventory, or proof of producer authorization for another
//! Event. In particular it cannot be converted into ordinary-history eligibility.
//! Unsupported source derivations and missing evidence remain retryable.

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_state::ordinary_history::HistoryEvidenceError;
use arkret_wire::{
    ActorId, AuthorizationDependencyKind, CellFamilyId, CellRef, CommandOutcome, Event, EventId,
    EventKind, Hash, NotaryValue, ProjectedOp, RealmId, ScopeRef, Seal, SealConclusionCertificate,
    SealConclusionOutcome, SealConclusionSelector, SealId,
};

/// A source origin derived from actual committed command bytes and effects.
/// There is no deserializer or public constructor accepting caller coordinates.
#[derive(Clone, Debug)]
pub struct ConfirmedAuthorizationSource {
    dependency_kind: AuthorizationDependencyKind,
    authorization_event_id: EventId,
    generation_event_id: EventId,
    scope_ref: ScopeRef,
    subject: Option<ActorId>,
}

impl ConfirmedAuthorizationSource {
    pub fn dependency_kind(&self) -> AuthorizationDependencyKind {
        self.dependency_kind
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.authorization_event_id
    }
    pub fn generation_event_id(&self) -> &EventId {
        &self.generation_event_id
    }
    pub fn scope_ref(&self) -> &ScopeRef {
        &self.scope_ref
    }
    /// The full actor, including the account's Station when applicable.
    pub fn subject(&self) -> Option<&ActorId> {
        self.subject.as_ref()
    }
}

/// Authenticated source origins at their committing Seal, not a current policy.
#[derive(Clone, Debug)]
pub struct ConfirmedAuthorizationSources {
    realm_id: RealmId,
    committing_seal: SealId,
    sources: Vec<ConfirmedAuthorizationSource>,
}

impl ConfirmedAuthorizationSources {
    /// Authenticate source Events using an independently pinned authority.
    ///
    /// `trusted_configuration_ref` and `trusted_configuration` are trust inputs:
    /// they must not be copied from the candidate Seal or its unverified genesis.
    /// This bounded adapter supports conclusions issued at the committing Seal
    /// under that exact frozen configuration. Configuration handoffs and later
    /// conclusion authorities need their own authenticated lineage adapter.
    ///
    /// Both the Seal and conclusion signatures are checked here. Each source
    /// must be an exact member of a committed unit; the signed command conclusion
    /// must equal that unit's complete result, and the registered source effect
    /// must name this Event as its revision. This authenticates the authority's
    /// decision, not an independent replay of every business admission rule.
    ///
    /// No reception timestamp, cache lifetime or online origin query is used.
    pub fn verify_at_seal(
        expected_realm: &RealmId,
        trusted_configuration_ref: &EventId,
        trusted_configuration: &NotaryValue,
        seal: &Seal,
        certificates: &[SealConclusionCertificate],
        source_events: &[Event],
        digest_suite: DigestSuite,
    ) -> Result<Self, HistoryEvidenceError> {
        if &seal.realm_id != expected_realm || &seal.configuration_ref != trusted_configuration_ref
        {
            return Err(invalid("source Seal does not match the pinned authority"));
        }
        seal.validate_id(digest_suite).map_err(invalid)?;
        arkret_signatures::verify_seal_signature(seal, trusted_configuration, digest_suite)
            .map_err(invalid)?;
        let mut facts = BTreeMap::new();
        for certificate in certificates {
            let statement = &certificate.statement;
            if &statement.realm_id != expected_realm
                || &statement.configuration_ref != trusted_configuration_ref
                || statement.authority_seal_ref != seal.id
                || statement.target_seal_ref != seal.id
            {
                return Err(invalid(
                    "source conclusion has a foreign authority or target",
                ));
            }
            arkret_signatures::verify_seal_conclusion_signature(certificate, trusted_configuration)
                .map_err(invalid)?;
            for result in &statement.results {
                let key =
                    arkret_canonical::canonical_json_bytes(&result.selector()).map_err(invalid)?;
                if facts.insert(key, result).is_some() {
                    return Err(invalid("source conclusions repeat a selector"));
                }
            }
        }
        if source_events.is_empty() {
            return Err(unavailable("no authorization source Events supplied"));
        }
        let mut sources = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for event in source_events {
            arkret_schema::validate_event_wire_schema(event).map_err(invalid)?;
            let digest = Hash::new(
                event
                    .event_digest_with_digest_suite(digest_suite)
                    .map_err(invalid)?,
            )
            .map_err(invalid)?;
            if EventId::from_event_digest(&digest).map_err(invalid)? != event.event_id
                || &event.realm_id != expected_realm
                || (event.kind != EventKind::RealmCreate
                    && event.scope_ref.realm_id_opt() != Some(expected_realm))
                || !seen.insert(event.event_id.clone())
            {
                return Err(invalid(
                    "source Event bytes, Realm or identity do not match",
                ));
            }
            let mut units = seal
                .command_results
                .iter()
                .filter(|unit| unit.unit_event_digests.contains(&digest));
            let Some(unit) = units.next() else {
                return Err(unavailable("source Event has no decision in this Seal"));
            };
            if units.next().is_some() || unit.outcome != CommandOutcome::Committed {
                return Err(invalid("source Event must belong to one committed unit"));
            }
            if !seal.delta.contains(&digest) {
                return Err(invalid("committed source is absent from the Seal delta"));
            }
            let selector = SealConclusionSelector::Command {
                event_digest: digest.clone(),
            };
            let key = arkret_canonical::canonical_json_bytes(&selector).map_err(invalid)?;
            match facts.get(&key) {
                Some(SealConclusionOutcome::Command(result))
                    if result.result.as_ref() == Some(unit) => {}
                None => return Err(unavailable("source command conclusion is missing")),
                _ => {
                    return Err(invalid(
                        "source command conclusion differs from its Seal unit",
                    ));
                }
            }
            let origins = source_origins(event, seal, trusted_configuration, digest_suite)?;
            let writes = arkret_schema::project_registered_cell_writes(event, digest_suite)
                .map_err(invalid)?;
            for (kind, family, subject) in origins {
                let mut matching = writes.iter().filter(|write| {
                    arkret_wire::cell::CellId::parse(write.cell_id.as_str())
                        .is_ok_and(|cell| cell.component() == family)
                });
                let Some(write) = matching.next() else {
                    return Err(invalid("source kind has no registered source write"));
                };
                if matching.next().is_some() {
                    return Err(invalid(
                        "source kind has ambiguous registered source writes",
                    ));
                }
                let expected_value = match &write.op {
                    ProjectedOp::TransitionTo { to } => to,
                    ProjectedOp::Direct(op) if op.op_type == arkret_wire::LatticeOpType::Set => op
                        .value
                        .as_ref()
                        .ok_or_else(|| invalid("source set has no value"))?,
                    _ => {
                        return Err(unavailable(
                            "source write needs an unsupported state derivation",
                        ));
                    }
                };
                verify_source_effect(
                    &facts,
                    &digest,
                    &write.cell_id,
                    &event.event_id,
                    expected_value,
                )?;
                let scope_ref = match event.kind {
                    EventKind::CircleMemberState => {
                        let payload: crate::CircleMemberStatePayload = serde_json::from_value(
                            serde_json::to_value(&event.payload).map_err(invalid)?,
                        )
                        .map_err(invalid)?;
                        ScopeRef::Circle {
                            realm_id: expected_realm.clone(),
                            circle_id: payload.circle_id,
                        }
                    }
                    _ => ScopeRef::Realm {
                        realm_id: expected_realm.clone(),
                    },
                };
                sources.push(ConfirmedAuthorizationSource {
                    dependency_kind: kind,
                    authorization_event_id: event.event_id.clone(),
                    generation_event_id: event.event_id.clone(),
                    scope_ref,
                    subject,
                });
            }
        }
        Ok(Self {
            realm_id: expected_realm.clone(),
            committing_seal: seal.id.clone(),
            sources,
        })
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }
    pub fn committing_seal(&self) -> &SealId {
        &self.committing_seal
    }
    pub fn sources(&self) -> &[ConfirmedAuthorizationSource] {
        &self.sources
    }
}

fn source_origins(
    event: &Event,
    seal: &Seal,
    configuration: &NotaryValue,
    suite: DigestSuite,
) -> Result<Vec<(AuthorizationDependencyKind, &'static str, Option<ActorId>)>, HistoryEvidenceError>
{
    use AuthorizationDependencyKind as Kind;
    match event.kind {
        EventKind::MemberState => {
            let payload: crate::MembershipPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            if payload.membership != crate::MembershipPayloadState::Join
                || payload.strand_id.is_some()
                || payload
                    .realm_id
                    .as_ref()
                    .is_some_and(|realm| realm != &event.realm_id)
                || !matches!(event.scope_ref, ScopeRef::Realm { .. })
            {
                return Err(unavailable("source is not a Realm membership Join"));
            }
            Ok(vec![(
                Kind::MemberJoin,
                CellFamilyId::MEMBER_STATE_V1,
                Some(payload.member_id),
            )])
        }
        EventKind::CircleMemberState => {
            let payload: crate::CircleMemberStatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            if payload.membership != crate::CircleMembership::Join {
                return Err(unavailable("source is not a Circle membership Join"));
            }
            if let ScopeRef::Circle { circle_id, .. } = &event.scope_ref {
                if circle_id != &payload.circle_id {
                    return Err(invalid(
                        "Circle membership source has a different envelope Circle",
                    ));
                }
            } else if !matches!(event.scope_ref, ScopeRef::Realm { .. }) {
                return Err(invalid(
                    "Circle membership source has an unrelated envelope scope",
                ));
            }
            Ok(vec![(
                Kind::MemberJoin,
                CellFamilyId::CIRCLE_MEMBER_V1,
                Some(payload.member_id),
            )])
        }
        EventKind::RealmCreate => {
            let payload: crate::RealmCreatePayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            payload.object.validate().map_err(invalid)?;
            if seal.predecessor_ref.is_some()
                || seal.configuration_ref != event.event_id
                || payload.object.digest_algorithm != suite
                || !matches!(payload.object.purpose, crate::RealmPurpose::Collaboration)
                || &payload.object.notary != configuration
                || event.realm_id != RealmId::from_event_id(&event.event_id)
                || !matches!(event.scope_ref, ScopeRef::RealmGenesis)
            {
                return Err(unavailable(
                    "source is not a supported initial collaboration Realm",
                ));
            }
            Ok(vec![
                (
                    Kind::RealmAuthorityGeneration,
                    CellFamilyId::REALM_AUTHORITY_ROOT_V1,
                    None,
                ),
                (
                    Kind::RealmControllerAssignment,
                    CellFamilyId::REALM_AUTHORITY_ROOT_V1,
                    Some(event.actor_id.clone()),
                ),
                (Kind::RealmNonterminal, CellFamilyId::REALM_GENESIS_V1, None),
                (Kind::RealmUnarchived, CellFamilyId::REALM_GENESIS_V1, None),
                (Kind::RealmUnfrozen, CellFamilyId::REALM_GENESIS_V1, None),
            ])
        }
        _ => Err(unavailable(
            "authorization source kind or successor generation is not supported",
        )),
    }
}

fn verify_source_effect(
    facts: &BTreeMap<Vec<u8>, &SealConclusionOutcome>,
    digest: &Hash,
    cell: &CellRef,
    event_id: &EventId,
    value: &serde_json::Value,
) -> Result<(), HistoryEvidenceError> {
    let selector = SealConclusionSelector::CommandEffect {
        event_digest: digest.clone(),
        cell_id: cell.clone(),
    };
    let key = arkret_canonical::canonical_json_bytes(&selector).map_err(invalid)?;
    match facts.get(&key) {
        Some(SealConclusionOutcome::CommandEffect(effect)) => match &effect.state {
            Some(state) if &state.revision_event_id == event_id && &state.value == value => Ok(()),
            _ => Err(invalid(
                "source effect does not establish the claimed source revision and value",
            )),
        },
        None => Err(unavailable("source committed effect conclusion is missing")),
        _ => Err(invalid(
            "source conclusion selector has the wrong result kind",
        )),
    }
}

fn invalid(error: impl std::fmt::Display) -> HistoryEvidenceError {
    HistoryEvidenceError::Invalid(error.to_string())
}
fn unavailable(message: &str) -> HistoryEvidenceError {
    HistoryEvidenceError::Unavailable(message.to_owned())
}

#[cfg(test)]
mod tests;
