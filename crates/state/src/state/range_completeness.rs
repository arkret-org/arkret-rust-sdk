//! Range-bound completeness verification for Event query consumers.
//!
//! This module deliberately verifies a complete Realm read, rather than a
//! single page. Callers must finish backfill first and pass the accepted Event
//! set plus one inline `ak.attestation.range_completeness` Event.

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::sync_frames::snapshot::{
    RangeCompletenessAttestation, RangeCompletenessAttestationEventRangeActorSeqRangesItem,
};
use arkret_wire::{
    DidCoreId, DidFullId, Event, EventId, Hash, RealmId, event_spec, project_full_id_to_core_id,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RangeCompletenessError {
    #[error("schema_violation: {0}")]
    SchemaViolation(String),
    #[error("range_completeness_root_mismatch")]
    RootMismatch,
    #[error("range_completeness_actor_seq_gap")]
    ActorSeqGap,
    #[error("witness_disagreement: {0}")]
    WitnessDisagreement(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRangeCompleteness {
    pub attestation_id: String,
    pub covered_event_ids: BTreeSet<EventId>,
    pub to_frontier: Vec<EventId>,
    pub assurance: RangeCompletenessAssurance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeCompletenessAssurance {
    SingleSource,
    FederationWitnessAttested,
}

#[derive(Serialize)]
struct RangeLeaf<'a> {
    actor_id: &'a DidCoreId,
    actor_seq: u64,
    event_id: &'a EventId,
    event_digest: &'a Hash,
}

fn hash_parts(
    suite: arkret_canonical::DigestSuite,
    parts: &[&[u8]],
) -> Result<[u8; 32], RangeCompletenessError> {
    let length = parts.iter().try_fold(0_usize, |length, part| {
        length.checked_add(part.len()).ok_or_else(|| {
            RangeCompletenessError::SchemaViolation(
                "range-completeness hash input is too large".to_owned(),
            )
        })
    })?;
    let mut input = Vec::with_capacity(length);
    for part in parts {
        input.extend_from_slice(part);
    }
    let mut raw = [0_u8; 32];
    hex::decode_to_slice(
        arkret_canonical::canonical::digest_hex(suite, &input),
        &mut raw,
    )
    .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?;
    Ok(raw)
}

fn hash_leaf(
    suite: arkret_canonical::DigestSuite,
    data: &[u8],
) -> Result<[u8; 32], RangeCompletenessError> {
    hash_parts(suite, &[&[0x00], data])
}

fn hash_node(
    suite: arkret_canonical::DigestSuite,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], RangeCompletenessError> {
    hash_parts(suite, &[&[0x01], left, right])
}

fn hash_value(
    suite: arkret_canonical::DigestSuite,
    raw: [u8; 32],
) -> Result<Hash, RangeCompletenessError> {
    Hash::new(format!("{}:{}", suite.as_str(), hex::encode(raw)))
        .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))
}

fn range_leaf_event_digest(event: &Event) -> Result<Hash, RangeCompletenessError> {
    let Some(first_proof) = event.proofs.iter().find_map(|proof| proof.as_producer()) else {
        return Err(RangeCompletenessError::SchemaViolation(
            "range Event has no proof".to_owned(),
        ));
    };
    let suite = first_proof
        .event_digest
        .as_str()
        .split_once(':')
        .map(|(suite, _)| suite)
        .ok_or_else(|| {
            RangeCompletenessError::SchemaViolation(
                "range Event proof digest has no suite prefix".to_owned(),
            )
        })?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(|error| {
            RangeCompletenessError::SchemaViolation(format!(
                "cannot derive Event digest payload: {error}"
            ))
        })?)
        .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?;
    let calculated = Hash::new(
        arkret_canonical::canonical_digest_with_suite(&canonical_bytes, suite).map_err(
            |error| {
                RangeCompletenessError::SchemaViolation(format!(
                    "cannot derive Event digest: {error}"
                ))
            },
        )?,
    )
    .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?;
    if event
        .proofs
        .iter()
        .filter_map(|proof| proof.as_producer())
        .any(|proof| proof.event_digest != calculated)
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "range Event proof digest does not match its canonical Event digest".to_owned(),
        ));
    }
    Ok(first_proof.event_digest.clone())
}

/// Compute the normative range-completeness root with the Realm's active
/// digest suite.
pub fn range_completeness_root_with_suite(
    events: &[Event],
    suite: arkret_canonical::DigestSuite,
) -> Result<(Hash, BTreeSet<EventId>), RangeCompletenessError> {
    let mut rows = Vec::new();
    let mut ids = BTreeSet::new();
    for event in events.iter().filter(|event| event.kind.is_reducer_input()) {
        if !ids.insert(event.event_id.clone()) {
            return Err(RangeCompletenessError::ActorSeqGap);
        }
        let digest = range_leaf_event_digest(event)?;
        rows.push((event, digest));
    }
    rows.sort_by(|(left, left_digest), (right, right_digest)| {
        left.actor_id
            .as_str()
            .cmp(right.actor_id.as_str())
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
            .then_with(|| left_digest.as_str().cmp(right_digest.as_str()))
    });
    let mut layer = rows
        .iter()
        .map(|(event, digest)| {
            arkret_canonical::canonical_json_bytes(&RangeLeaf {
                actor_id: &event.actor_id,
                actor_seq: event.actor_seq,
                event_id: &event.event_id,
                event_digest: digest,
            })
            .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))
            .and_then(|bytes| hash_leaf(suite, &bytes))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if layer.is_empty() {
        return Ok((hash_value(suite, hash_parts(suite, &[b""])?)?, ids));
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            next.push(match pair.get(1) {
                Some(right) => hash_node(suite, &pair[0], right)?,
                None => pair[0],
            });
        }
        layer = next;
    }
    Ok((hash_value(suite, layer[0])?, ids))
}

fn canonical_frontier(values: &[EventId]) -> Result<Vec<EventId>, RangeCompletenessError> {
    if values.is_empty() {
        return Err(RangeCompletenessError::SchemaViolation(
            "range frontier must not be empty".to_owned(),
        ));
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RangeCompletenessError::SchemaViolation(
            "range frontier contains duplicate Event ids".to_owned(),
        ));
    }
    Ok(sorted)
}

/// Derive the canonical genesis and head frontiers of a complete Realm read.
pub fn full_realm_range_frontiers(
    events: &[Event],
) -> Result<(Vec<EventId>, Vec<EventId>), RangeCompletenessError> {
    let ids = events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if ids.len() != events.len() {
        return Err(RangeCompletenessError::ActorSeqGap);
    }
    let referenced = events
        .iter()
        .flat_map(|event| event.prev_refs.iter())
        .filter(|event_id| ids.contains(*event_id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let roots = events
        .iter()
        .filter(|event| {
            event.prev_refs.is_empty()
                || event
                    .prev_refs
                    .iter()
                    .all(|event_id| !ids.contains(event_id))
        })
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let heads = events
        .iter()
        .filter(|event| !referenced.contains(&event.event_id))
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    Ok((canonical_frontier(&roots)?, canonical_frontier(&heads)?))
}

/// Return the full-Realm attestation range `(genesis frontier, heads]`.
pub fn full_realm_range_events(events: &[Event]) -> Result<Vec<Event>, RangeCompletenessError> {
    let (roots, _) = full_realm_range_frontiers(events)?;
    let roots = roots.into_iter().collect::<BTreeSet<_>>();
    Ok(events
        .iter()
        .filter(|event| !roots.contains(&event.event_id))
        .cloned()
        .collect())
}

/// Derive canonical actor-sequence envelopes for reducer-input Events.
pub fn range_completeness_actor_seq_ranges(
    events: &[Event],
) -> Result<Vec<RangeCompletenessAttestationEventRangeActorSeqRangesItem>, RangeCompletenessError> {
    let mut bounds = BTreeMap::<DidCoreId, (u64, u64)>::new();
    for event in events.iter().filter(|event| event.kind.is_reducer_input()) {
        bounds
            .entry(event.actor_id.clone())
            .and_modify(|(minimum, maximum)| {
                *minimum = (*minimum).min(event.actor_seq);
                *maximum = (*maximum).max(event.actor_seq);
            })
            .or_insert((event.actor_seq, event.actor_seq));
    }
    bounds
        .into_iter()
        .map(|(actor_id, (minimum, maximum))| {
            let minimum = i64::try_from(minimum).map_err(|_| {
                RangeCompletenessError::SchemaViolation(
                    "actor sequence cannot be represented by the attestation schema".to_owned(),
                )
            })?;
            Ok(RangeCompletenessAttestationEventRangeActorSeqRangesItem {
                actor_id,
                from_seq_exclusive: minimum - 1,
                to_seq_inclusive: maximum,
            })
        })
        .collect()
}

fn validate_actor_ranges(
    payload: &RangeCompletenessAttestation,
    range_events: &[Event],
) -> Result<(), RangeCompletenessError> {
    let mut previous_actor: Option<&DidCoreId> = None;
    let mut ranges = BTreeMap::new();
    for range in &payload.event_range.actor_seq_ranges {
        if range.from_seq_exclusive >= range.to_seq_inclusive as i64 {
            return Err(RangeCompletenessError::SchemaViolation(
                "actor sequence range is empty or reversed".to_owned(),
            ));
        }
        if previous_actor.is_some_and(|actor| actor.as_str() >= range.actor_id.as_str()) {
            return Err(RangeCompletenessError::SchemaViolation(
                "actor sequence ranges must be bytewise sorted and unique".to_owned(),
            ));
        }
        previous_actor = Some(&range.actor_id);
        ranges.insert(
            range.actor_id.clone(),
            (range.from_seq_exclusive, range.to_seq_inclusive),
        );
    }
    for event in range_events {
        if !event.kind.is_reducer_input() {
            continue;
        }
        let Some((from, to)) = ranges.get(&event.actor_id) else {
            return Err(RangeCompletenessError::ActorSeqGap);
        };
        if event.actor_seq as i128 <= *from as i128 || event.actor_seq > *to {
            return Err(RangeCompletenessError::ActorSeqGap);
        }
    }
    for (actor, (from, to)) in ranges {
        let sequences = range_events
            .iter()
            .filter(|event| {
                event.actor_id == actor
                    && event.actor_seq as i128 > from as i128
                    && event.actor_seq <= to
            })
            .map(|event| event.actor_seq)
            .collect::<BTreeSet<_>>();
        let expected_count = to as i128 - from as i128;
        if i128::try_from(sequences.len()).ok() != Some(expected_count)
            || sequences.first().copied().map(i128::from) != Some(from as i128 + 1)
            || sequences.last().copied() != Some(to)
            || !range_events.iter().any(|event| {
                event.kind.is_reducer_input()
                    && event.actor_id == actor
                    && event.actor_seq as i128 > from as i128
                    && event.actor_seq <= to
            })
        {
            return Err(RangeCompletenessError::ActorSeqGap);
        }
    }
    Ok(())
}

fn validate_witnesses(
    payload: &RangeCompletenessAttestation,
    high_assurance: bool,
    allowed_witnesses: &BTreeSet<DidCoreId>,
) -> Result<RangeCompletenessAssurance, RangeCompletenessError> {
    let witnesses = &payload.witness_attestation.witnesses;
    match witnesses.len() {
        1 => {
            if high_assurance {
                return Err(RangeCompletenessError::WitnessDisagreement(
                    "high-assurance Realm requires federation witnesses".to_owned(),
                ));
            }
            let witness = &witnesses[0];
            if witness.issuer != payload.issuer
                || witness
                    .verification_method
                    .as_str()
                    .split_once('#')
                    .and_then(|(controller, _)| DidFullId::new(controller).ok())
                    .and_then(|controller| project_full_id_to_core_id(&controller).ok())
                    .is_none_or(|controller| controller != payload.issuer)
                || !payload
                    .proofs
                    .iter()
                    .any(|proof| proof.verification_method == witness.verification_method)
            {
                return Err(RangeCompletenessError::SchemaViolation(
                    "single-source witness is not bound to the issuer".to_owned(),
                ));
            }
            Ok(RangeCompletenessAssurance::SingleSource)
        }
        2.. => {
            let issuers = witnesses
                .iter()
                .map(|witness| &witness.issuer)
                .collect::<BTreeSet<_>>();
            let methods = witnesses
                .iter()
                .map(|witness| witness.verification_method.as_str())
                .collect::<BTreeSet<_>>();
            let organizations = witnesses
                .iter()
                .map(|witness| &witness.controlling_organization)
                .collect::<BTreeSet<_>>();
            if issuers.len() != witnesses.len()
                || methods.len() != witnesses.len()
                || organizations.len() != witnesses.len()
                || witnesses
                    .iter()
                    .any(|witness| !allowed_witnesses.contains(&witness.issuer))
            {
                return Err(RangeCompletenessError::WitnessDisagreement(
                    "witness independence or policy binding failed".to_owned(),
                ));
            }
            if witnesses.iter().any(|witness| {
                !payload
                    .proofs
                    .iter()
                    .any(|proof| proof.verification_method == witness.verification_method)
            }) {
                return Err(RangeCompletenessError::WitnessDisagreement(
                    "a declared witness did not sign the payload".to_owned(),
                ));
            }
            Ok(RangeCompletenessAssurance::FederationWitnessAttested)
        }
        0 => Err(RangeCompletenessError::SchemaViolation(
            "range completeness requires at least one witness".to_owned(),
        )),
    }
}

/// Verify a completeness attestation for a finished, unfiltered full-Realm
/// read. The attestation must cover from every local genesis frontier to every
/// local head; page-only or suffix attestations are rejected.
///
/// Cryptographic proof verification remains a caller responsibility because
/// DID resolution is transport/profile specific. This function verifies both
/// proof digests, the range, Merkle root, count, actor ranges, and witness
/// policy shape.
/// Verify a full-Realm range-completeness attestation with the Realm's active
/// digest suite.
pub fn verify_full_realm_range_completeness_with_suite(
    attestation_event: &Event,
    accepted_events: &[Event],
    expected_realm: &RealmId,
    digest_suite: arkret_canonical::DigestSuite,
    high_assurance: bool,
    allowed_witnesses: &BTreeSet<DidCoreId>,
) -> Result<VerifiedRangeCompleteness, RangeCompletenessError> {
    if accepted_events.is_empty() {
        return Err(RangeCompletenessError::SchemaViolation(
            "full-Realm completeness requires at least one accepted Event".to_owned(),
        ));
    }
    if attestation_event.kind.as_str()
        != arkret_wire::event_kind_str::ATTESTATION_RANGE_COMPLETENESS
        || &attestation_event.realm_id != expected_realm
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "attestation Event kind or Realm does not match the query".to_owned(),
        ));
    }
    let payload: RangeCompletenessAttestation = attestation_event
        .typed_payload::<event_spec::AttestationRangeCompleteness>()
        .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?;
    if payload.schema != arkret_wire::SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1
        || payload.realm_id != *expected_realm
        || payload.issuer != attestation_event.actor_id
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "attestation payload binding is invalid".to_owned(),
        ));
    }
    let event_digest = attestation_event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?;
    if attestation_event.proofs.is_empty()
        || attestation_event
            .proofs
            .iter()
            .filter_map(|proof| proof.as_producer())
            .any(|proof| proof.event_digest.as_str() != event_digest)
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "attestation Event proof digest is invalid".to_owned(),
        ));
    }
    let payload_digest = arkret_canonical::sha256_digest(
        payload
            .proof_payload_bytes()
            .map_err(|error| RangeCompletenessError::SchemaViolation(error.to_string()))?,
    );
    if payload.proofs.is_empty()
        || payload
            .proofs
            .iter()
            .any(|proof| proof.payload_digest.as_str() != payload_digest)
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "attestation payload proof digest is invalid".to_owned(),
        ));
    }

    let (roots, heads) = full_realm_range_frontiers(accepted_events)?;
    if canonical_frontier(&payload.event_range.from_frontier.realm_frontier)? != roots
        || canonical_frontier(&payload.event_range.to_frontier.realm_frontier)? != heads
    {
        return Err(RangeCompletenessError::SchemaViolation(
            "attestation does not cover the full local Realm range".to_owned(),
        ));
    }
    if accepted_events
        .iter()
        .any(|event| event.realm_id != *expected_realm)
    {
        return Err(RangeCompletenessError::ActorSeqGap);
    }
    let range_events = full_realm_range_events(accepted_events)?;
    validate_actor_ranges(&payload, &range_events)?;
    let (root, covered_event_ids) =
        range_completeness_root_with_suite(&range_events, digest_suite)?;
    if root != payload.root || covered_event_ids.len() as u64 != payload.count {
        return Err(RangeCompletenessError::RootMismatch);
    }
    let assurance = validate_witnesses(&payload, high_assurance, allowed_witnesses)?;
    Ok(VerifiedRangeCompleteness {
        attestation_id: payload.attestation_id,
        covered_event_ids,
        to_frontier: heads,
        assurance,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{
        DidCoreId, DidFullId, DidUrl, EventKind, EventRequirements, PayloadProof,
        ProducerEventProof, ScopeRef, project_full_id_to_core_id, proof_kind,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::{Value, json};

    use super::*;

    fn event(id: &str, seq: u64, kind: &str, prev_refs: Vec<EventId>) -> Event {
        let actor_full = DidFullId::new("did:web:alice.example").unwrap();
        let actor = project_full_id_to_core_id(&actor_full).unwrap();
        let realm = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let mut event = Event {
            event_id: EventId::new(id).unwrap(),
            kind: EventKind::from(kind),
            realm_id: realm.clone(),
            scope_ref: ScopeRef::Realm { realm_id: realm },
            actor_id: actor.clone(),
            principal_server_id: actor,
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: seq,
            created_at: Utc.timestamp_opt(1_800_000_000 + seq as i64, 0).unwrap(),
            hlc: None,
            prev_refs,
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            payload: BTreeMap::from([("value".to_owned(), json!(seq))]),
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        };
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs.push(
            ProducerEventProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{actor_full}#device")).unwrap(),
                event_digest: digest,
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "header..signature".to_owned(),
            }
            .into(),
        );
        event
    }

    fn attestation(events: &[Event]) -> Event {
        use arkret_models_collaboration::sync_frames::snapshot::{
            RangeCompletenessAttestationEventRange,
            RangeCompletenessAttestationEventRangeFromFrontier,
            RangeCompletenessAttestationEventRangeToFrontier,
            RangeCompletenessAttestationWitnessAttestation,
            RangeCompletenessAttestationWitnessAttestationWitnessesItem,
        };

        let issuer_full = DidFullId::new("did:webvh:z6mkfixture:server.example").unwrap();
        let issuer = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let controlling_organization = DidCoreId::new("ak:did_core:webvh:z6mkfixtureorg").unwrap();
        let realm = events[0].realm_id.clone();
        let (from_frontier, to_frontier) = full_realm_range_frontiers(events).unwrap();
        let range_events = full_realm_range_events(events).unwrap();
        let (root, covered) = range_completeness_root_with_suite(
            &range_events,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let created_at = Utc.timestamp_opt(1_800_000_100, 0).unwrap();
        let mut payload = RangeCompletenessAttestation {
            attestation_id: "ak:attestation:01904100-0000-7000-8000-000000000004".to_owned(),
            schema: "ak.schema.range_completeness_attestation.v1".to_owned(),
            issuer: issuer.clone(),
            issuer_role: "events_api".to_owned(),
            realm_id: realm.clone(),
            event_range: RangeCompletenessAttestationEventRange {
                from_frontier: RangeCompletenessAttestationEventRangeFromFrontier {
                    realm_frontier: from_frontier,
                    extra: BTreeMap::new(),
                },
                to_frontier: RangeCompletenessAttestationEventRangeToFrontier {
                    realm_frontier: to_frontier.clone(),
                    extra: BTreeMap::new(),
                },
                actor_seq_ranges: range_completeness_actor_seq_ranges(&range_events).unwrap(),
            },
            root,
            count: covered.len() as u64,
            observed_at: created_at,
            witness_attestation: RangeCompletenessAttestationWitnessAttestation {
                witnesses: vec![
                    RangeCompletenessAttestationWitnessAttestationWitnessesItem {
                        issuer: issuer.clone(),
                        verification_method: DidUrl::new(format!("{issuer_full}#notary-key"))
                            .unwrap(),
                        controlling_organization,
                        attested_at: Some(created_at),
                        extra: BTreeMap::new(),
                    },
                ],
            },
            proofs: Vec::new(),
        };
        let payload_digest =
            arkret_canonical::sha256_digest(payload.proof_payload_bytes().unwrap());
        payload.proofs.push(PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new(format!("{issuer_full}#notary-key")).unwrap(),
            payload_digest: Hash::new(payload_digest).unwrap(),
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header..signature".to_owned(),
        });
        let Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
            unreachable!()
        };
        let mut event = Event {
            event_id: EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
                .unwrap(),
            kind: EventKind::AttestationRangeCompleteness,
            realm_id: realm.clone(),
            scope_ref: ScopeRef::Realm { realm_id: realm },
            actor_id: issuer.clone(),
            principal_server_id: issuer,
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: 0,
            created_at,
            hlc: None,
            prev_refs: to_frontier,
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            payload: payload.into_iter().collect(),
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        };
        event.proofs.push(
            ProducerEventProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{issuer_full}#notary-key")).unwrap(),
                event_digest: Hash::new(
                    event
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .unwrap(),
                )
                .unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "header..signature".to_owned(),
            }
            .into(),
        );
        event
    }

    #[test]
    fn root_is_order_stable_and_excludes_non_reducer_events() {
        let first = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            2,
            "ak.key_backup.active_series",
            Vec::new(),
        );
        let second = event(
            "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
            3,
            "ak.attestation.range_completeness",
            Vec::new(),
        );
        let forward = range_completeness_root_with_suite(
            &[first.clone(), second.clone()],
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let reverse = range_completeness_root_with_suite(
            &[second, first],
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.1.len(), 1);
    }

    #[test]
    fn full_realm_verifier_accepts_covered_active_series_and_rejects_tampering() {
        let genesis = event(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            0,
            "ak.realm.create",
            Vec::new(),
        );
        let active = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            1,
            "ak.key_backup.active_series",
            vec![genesis.event_id.clone()],
        );
        let accepted = vec![genesis, active.clone()];
        let proof = attestation(&accepted);
        let verified = verify_full_realm_range_completeness_with_suite(
            &proof,
            &accepted,
            &active.realm_id,
            arkret_canonical::DigestSuite::Sha256,
            false,
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(verified.covered_event_ids.contains(&active.event_id));

        let mut tampered = proof;
        tampered.payload.insert(
            "root".to_owned(),
            json!(format!("sha256:{}", "ff".repeat(32))),
        );
        let tampered_payload: RangeCompletenessAttestation = serde_json::from_value(Value::Object(
            tampered
                .payload
                .clone()
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        ))
        .unwrap();
        tampered
            .payload
            .get_mut("proofs")
            .and_then(Value::as_array_mut)
            .unwrap()[0]["payload_digest"] = json!(arkret_canonical::sha256_digest(
            tampered_payload.proof_payload_bytes().unwrap()
        ));
        tampered.proofs[0].as_producer_mut().unwrap().event_digest = Hash::new(
            tampered
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_full_realm_range_completeness_with_suite(
                &tampered,
                &accepted,
                &active.realm_id,
                arkret_canonical::DigestSuite::Sha256,
                false,
                &BTreeSet::new(),
            ),
            Err(RangeCompletenessError::RootMismatch)
        );
    }

    #[test]
    fn high_assurance_rejects_single_source() {
        let genesis = event(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            0,
            "ak.realm.create",
            Vec::new(),
        );
        let active = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            1,
            "ak.key_backup.active_series",
            vec![genesis.event_id.clone()],
        );
        let accepted = vec![genesis, active.clone()];
        assert!(matches!(
            verify_full_realm_range_completeness_with_suite(
                &attestation(&accepted),
                &accepted,
                &active.realm_id,
                arkret_canonical::DigestSuite::Sha256,
                true,
                &BTreeSet::new(),
            ),
            Err(RangeCompletenessError::WitnessDisagreement(_))
        ));
    }

    #[test]
    fn verifier_rejects_claimed_actor_sequence_gap() {
        let genesis = event(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            0,
            "ak.realm.create",
            Vec::new(),
        );
        let active = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            2,
            "ak.key_backup.active_series",
            vec![genesis.event_id.clone()],
        );
        let accepted = vec![genesis, active.clone()];
        let mut proof = attestation(&accepted);
        proof
            .payload
            .get_mut("event_range")
            .and_then(Value::as_object_mut)
            .and_then(|range| range.get_mut("actor_seq_ranges"))
            .and_then(Value::as_array_mut)
            .unwrap()[0]["from_seq_exclusive"] = json!(0);
        let tampered_payload: RangeCompletenessAttestation = serde_json::from_value(Value::Object(
            proof
                .payload
                .clone()
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        ))
        .unwrap();
        proof
            .payload
            .get_mut("proofs")
            .and_then(Value::as_array_mut)
            .unwrap()[0]["payload_digest"] = json!(arkret_canonical::sha256_digest(
            tampered_payload.proof_payload_bytes().unwrap()
        ));
        proof.proofs[0].as_producer_mut().unwrap().event_digest = Hash::new(
            proof
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_full_realm_range_completeness_with_suite(
                &proof,
                &accepted,
                &active.realm_id,
                arkret_canonical::DigestSuite::Sha256,
                false,
                &BTreeSet::new(),
            ),
            Err(RangeCompletenessError::ActorSeqGap)
        );
    }

    #[test]
    fn root_rejects_an_event_with_an_unbound_proof_digest() {
        let mut active = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            1,
            "ak.key_backup.active_series",
            Vec::new(),
        );
        active.proofs[0].as_producer_mut().unwrap().event_digest =
            Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap();
        assert!(matches!(
            range_completeness_root_with_suite(&[active], arkret_canonical::DigestSuite::Sha256,),
            Err(RangeCompletenessError::SchemaViolation(_))
        ));
    }

    #[test]
    fn root_uses_the_selected_realm_digest_suite() {
        let active = event(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            1,
            "ak.key_backup.active_series",
            Vec::new(),
        );
        let (root, covered) =
            range_completeness_root_with_suite(&[active], arkret_canonical::DigestSuite::Blake3)
                .unwrap();
        assert!(root.as_str().starts_with("blake3:"));
        assert_eq!(covered.len(), 1);
    }
}
