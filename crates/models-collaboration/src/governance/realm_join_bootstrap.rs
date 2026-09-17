//! Realm join bootstrap is a single authority-bundle plus snapshot response.
//!
//! `realm-join-intake.schema.json#/$defs/peer_bootstrap_outcome`: the verified
//! current governance Station returns one signed
//! [`arkret_wire::RealmStateSnapshot`] together with every stream head visible
//! after the membership Commit. Nothing is paged and nothing is streamed by the
//! authority; the joiner then scans each permitted stream itself, from the
//! floor the snapshot already covers up to the advertised head.
//!
//! Realm, each Circle and each Sidecar own independent commit streams. There is
//! no global chain and no global position, so catching up is one contiguity
//! check per stream, never one ordering across streams.

use std::collections::BTreeMap;

use arkret_wire::{CommitStreamHead, CommitStreamRef, RealmCommitId, Result, StreamRow, WireError};

pub use super::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody,
};

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

/// Where one permitted stream's catch-up scan currently stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmJoinBootstrapStreamScan {
    /// First stream position the joiner still has to acquire. It is the
    /// snapshot floor position plus one, or zero for a stream the snapshot does
    /// not cover at all.
    pub next_stream_position: u64,
    /// Commit the next accepted item must name in `previous_commit_ref`.
    /// `None` only while the stream is still at its genesis position.
    pub expected_previous_commit_id: Option<RealmCommitId>,
    /// Advertised head this scan has to reach before the joiner is caught up.
    pub target: CommitStreamHead,
}

impl RealmJoinBootstrapStreamScan {
    /// `true` once every commit up to and including the advertised head has
    /// been accepted by [`RealmJoinBootstrapAssembly::append`].
    pub fn is_complete(&self) -> bool {
        self.next_stream_position == self.target.stream_position.saturating_add(1)
            && self.expected_previous_commit_id.as_ref() == Some(&self.target.commit_id)
    }
}

/// Client-side assembly of one Realm join bootstrap.
///
/// The authority's answer is the trust anchor; this type is the bookkeeping
/// that turns it into a completeness decision. It checks coordinates only:
/// stream membership, per-stream contiguity and the advertised target. It does
/// not verify the snapshot signature, the authority bundle chain, or any
/// Event proof, and its output must still pass those verifications.
#[derive(Clone, Debug)]
pub struct RealmJoinBootstrapAssembly {
    outcome: PeerRealmJoinBootstrapOutcome,
    scans: BTreeMap<CommitStreamRef, RealmJoinBootstrapStreamScan>,
}

impl RealmJoinBootstrapAssembly {
    /// Freeze one bootstrap answer into a per-stream scan plan.
    ///
    /// The advertised heads must be a non-empty, per-stream unique set inside
    /// the snapshot's Realm, and no snapshot floor may sit ahead of the head
    /// advertised for the same stream — an authority that answered that way has
    /// handed the joiner a target it has already passed.
    pub fn new(outcome: PeerRealmJoinBootstrapOutcome) -> Result<Self> {
        if outcome.visible_stream_heads.is_empty() {
            return Err(invalid("realm join bootstrap advertises no visible stream"));
        }
        let realm_id = outcome.snapshot.realm_id.clone();
        if outcome.authority_bundle.realm_id != realm_id {
            return Err(invalid(
                "realm join bootstrap snapshot and authority bundle name different Realms",
            ));
        }

        let mut floors: BTreeMap<CommitStreamRef, (u64, RealmCommitId)> = BTreeMap::new();
        for floor in &outcome.snapshot.visible_stream_heads {
            let previous = floors.insert(
                floor.stream_ref.clone(),
                (floor.stream_position, floor.commit_id.clone()),
            );
            if previous.is_some() {
                return Err(invalid(
                    "realm join bootstrap snapshot repeats a stream floor",
                ));
            }
        }

        let mut scans = BTreeMap::new();
        for head in &outcome.visible_stream_heads {
            if *head.stream_ref.realm_id() != realm_id {
                return Err(invalid(
                    "realm join bootstrap advertises a stream outside the snapshot Realm",
                ));
            }
            let (next_stream_position, expected_previous_commit_id) =
                match floors.remove(&head.stream_ref) {
                    Some((floor_position, _)) if floor_position > head.stream_position => {
                        return Err(invalid(
                            "realm join bootstrap snapshot floor is ahead of the advertised head",
                        ));
                    }
                    Some((floor_position, floor_commit_id)) => {
                        (floor_position.saturating_add(1), Some(floor_commit_id))
                    }
                    None => (0, None),
                };
            let scan = RealmJoinBootstrapStreamScan {
                next_stream_position,
                expected_previous_commit_id,
                target: head.clone(),
            };
            if scans.insert(head.stream_ref.clone(), scan).is_some() {
                return Err(invalid(
                    "realm join bootstrap repeats a visible stream head",
                ));
            }
        }
        if !floors.is_empty() {
            return Err(invalid(
                "realm join bootstrap snapshot covers a stream the answer does not advertise",
            ));
        }
        Ok(Self { outcome, scans })
    }

    pub fn outcome(&self) -> &PeerRealmJoinBootstrapOutcome {
        &self.outcome
    }

    /// Scan state for every advertised stream, keyed by stream.
    pub fn scans(&self) -> &BTreeMap<CommitStreamRef, RealmJoinBootstrapStreamScan> {
        &self.scans
    }

    /// Advertised streams the joiner has not yet scanned to the head.
    pub fn incomplete_streams(&self) -> Vec<&CommitStreamRef> {
        self.scans
            .iter()
            .filter(|(_, scan)| !scan.is_complete())
            .map(|(stream_ref, _)| stream_ref)
            .collect()
    }

    /// Accept the next committed item of one advertised stream.
    ///
    /// Only the RealmCommit carries `previous_commit_ref`, and one stream
    /// advances by exactly one position, so an item is admissible only at the
    /// scan's own next position with the previous commit it names. An item for
    /// an unadvertised stream, a gap, a repeat, or a position past the
    /// advertised head is rejected rather than buffered.
    pub fn append(&mut self, item: &StreamRow) -> Result<()> {
        item.validate_shape()?;
        if item.commit.realm_id != self.outcome.snapshot.realm_id {
            return Err(invalid(
                "realm join bootstrap item crosses the bootstrapped Realm",
            ));
        }
        let scan = self
            .scans
            .get_mut(&item.commit.stream_ref)
            .ok_or_else(|| invalid("realm join bootstrap item is outside the permitted streams"))?;
        if item.commit.stream_position != scan.next_stream_position {
            return Err(invalid(
                "realm join bootstrap item is not the next position of its stream",
            ));
        }
        if item.commit.stream_position > scan.target.stream_position {
            return Err(invalid(
                "realm join bootstrap item is past the advertised stream head",
            ));
        }
        if item.commit.previous_commit_ref != scan.expected_previous_commit_id {
            return Err(invalid(
                "realm join bootstrap item does not continue its own stream",
            ));
        }
        if item.commit.stream_position == scan.target.stream_position
            && item.commit.commit_id != scan.target.commit_id
        {
            return Err(invalid(
                "realm join bootstrap head position carries another Commit",
            ));
        }
        scan.next_stream_position = item.commit.stream_position.saturating_add(1);
        scan.expected_previous_commit_id = Some(item.commit.commit_id.clone());
        Ok(())
    }

    /// The joiner is caught up only when every advertised stream reached its
    /// advertised head. A partial scan is not a usable bootstrap.
    pub fn finish(&self) -> Result<()> {
        if self
            .scans
            .values()
            .all(RealmJoinBootstrapStreamScan::is_complete)
        {
            Ok(())
        } else {
            Err(invalid(
                "realm join bootstrap is incomplete: an advertised stream head was not reached",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        Base64UrlString, CircleId, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, DidCoreId, DidUrl, Event, EventId, EventKind, Hash,
        HistoryAccess, RealmAuthorityBundle, RealmAuthorityCurrentAssertion, RealmCommit,
        RealmCommitAuthorityRef, RealmCommitId, RealmId, RealmSnapshotId, RealmStateSnapshot,
        RequestId, RetentionAndHistoryFloor, ScopeRef,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x10; 32],
        ))
    }

    fn circle_stream(realm: &RealmId) -> CommitStreamRef {
        CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: CircleId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x22; 32],
            )),
        }
    }

    fn signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
        DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            sig: Base64UrlString::new("AQ").unwrap(),
        }
    }

    fn commit_id(seed: u8) -> RealmCommitId {
        RealmCommitId::from_digest([seed; 32])
    }

    fn head(stream_ref: CommitStreamRef, stream_position: u64, seed: u8) -> CommitStreamHead {
        CommitStreamHead {
            stream_ref,
            stream_position,
            commit_id: commit_id(seed),
        }
    }

    fn scope_of(stream_ref: &CommitStreamRef) -> ScopeRef {
        match stream_ref {
            CommitStreamRef::Realm { realm_id } => ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            CommitStreamRef::Circle {
                realm_id,
                circle_id,
            } => ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            CommitStreamRef::Sidecar {
                realm_id,
                sidecar_id,
            } => ScopeRef::Sidecar {
                realm_id: realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            },
            _ => unreachable!("closed commit stream family"),
        }
    }

    fn fixture_event(stream_ref: &CommitStreamRef) -> Event {
        arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            scope_of(stream_ref),
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({}),
            Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    fn item(
        stream_ref: &CommitStreamRef,
        stream_position: u64,
        previous: Option<u8>,
        seed: u8,
    ) -> StreamRow {
        let event = fixture_event(stream_ref);
        StreamRow {
            commit: RealmCommit {
                commit_id: commit_id(seed),
                realm_id: stream_ref.realm_id().clone(),
                stream_ref: stream_ref.clone(),
                stream_position,
                previous_commit_ref: previous.map(commit_id),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x33; 32],
                )),
                committed_at: Utc.timestamp_opt(1_800_000_001, 0).unwrap(),
                signature: signature(DetachedSignatureContext::RealmCommit),
            },
            event,
        }
    }

    fn bundle(realm: &RealmId) -> RealmAuthorityBundle {
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let genesis_event = fixture_event(&realm_stream);
        RealmAuthorityBundle {
            realm_id: realm.clone(),
            genesis_commit: RealmCommit {
                commit_id: commit_id(0x01),
                realm_id: realm.clone(),
                stream_ref: realm_stream.clone(),
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: genesis_event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
                signature: signature(DetachedSignatureContext::RealmCommit),
            },
            genesis_event,
            authority_transitions: Vec::new(),
            current_generation: 0,
            current_service_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            current_route_record: json!({}),
            realm_stream_head: head(realm_stream.clone(), 1, 0x02),
            bundle_issued_at: Utc.timestamp_opt(1_800_000_002, 0).unwrap(),
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id: realm.clone(),
                current_generation: 0,
                current_service_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                last_handoff_ref: None,
                realm_stream_head: head(realm_stream, 1, 0x02),
                nonce: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
                expires_at: Utc.timestamp_opt(1_800_000_300, 0).unwrap(),
                signature: signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
            },
        }
    }

    fn snapshot(realm: &RealmId, floors: Vec<CommitStreamHead>) -> RealmStateSnapshot {
        RealmStateSnapshot {
            snapshot_id: RealmSnapshotId::from_digest([0x44; 32]),
            realm_id: realm.clone(),
            governance_generation: 0,
            visible_stream_heads: floors,
            current_state_entries: Vec::new(),
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: Vec::new(),
            },
            created_at: Utc.timestamp_opt(1_800_000_003, 0).unwrap(),
            signature: signature(DetachedSignatureContext::RealmSnapshot),
        }
    }

    fn outcome(
        realm: &RealmId,
        floors: Vec<CommitStreamHead>,
        heads: Vec<CommitStreamHead>,
    ) -> PeerRealmJoinBootstrapOutcome {
        PeerRealmJoinBootstrapOutcome {
            request_id: RequestId::new("ak:request:01964137-0000-7000-8000-000000000001").unwrap(),
            authority_bundle: bundle(realm),
            snapshot: snapshot(realm, floors),
            visible_stream_heads: heads,
        }
    }

    #[test]
    fn outcome_round_trips_and_rejects_unknown_and_missing_members() {
        let realm = realm_id();
        let stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let source = outcome(
            &realm,
            vec![head(stream.clone(), 0, 0x01)],
            vec![head(stream, 1, 0x02)],
        );
        let value = serde_json::to_value(&source).unwrap();
        let decoded: PeerRealmJoinBootstrapOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded, source);

        let mut unknown = value.clone();
        unknown["next_cursor"] = json!("more");
        assert!(serde_json::from_value::<PeerRealmJoinBootstrapOutcome>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("visible_stream_heads");
        assert!(serde_json::from_value::<PeerRealmJoinBootstrapOutcome>(missing).is_err());
    }

    #[test]
    fn assembly_completes_only_after_every_advertised_head_is_reached() {
        let realm = realm_id();
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let circle = circle_stream(&realm);
        let mut assembly = RealmJoinBootstrapAssembly::new(outcome(
            &realm,
            vec![head(realm_stream.clone(), 0, 0x01)],
            vec![
                head(realm_stream.clone(), 2, 0x03),
                head(circle.clone(), 0, 0x09),
            ],
        ))
        .unwrap();
        assert_eq!(assembly.incomplete_streams().len(), 2);
        assert!(assembly.finish().is_err());

        assembly
            .append(&item(&realm_stream, 1, Some(0x01), 0x02))
            .unwrap();
        assert!(assembly.finish().is_err());
        assembly
            .append(&item(&realm_stream, 2, Some(0x02), 0x03))
            .unwrap();
        assert_eq!(assembly.incomplete_streams().len(), 1);
        assert!(assembly.finish().is_err());

        assembly.append(&item(&circle, 0, None, 0x09)).unwrap();
        assert!(assembly.incomplete_streams().is_empty());
        assembly.finish().unwrap();
    }

    #[test]
    fn assembly_rejects_gaps_repeats_and_unadvertised_streams() {
        let realm = realm_id();
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let circle = circle_stream(&realm);
        let mut assembly = RealmJoinBootstrapAssembly::new(outcome(
            &realm,
            vec![head(realm_stream.clone(), 0, 0x01)],
            vec![head(realm_stream.clone(), 2, 0x03)],
        ))
        .unwrap();

        assert!(
            assembly
                .append(&item(&realm_stream, 2, Some(0x02), 0x03))
                .is_err(),
            "a gap must not be buffered"
        );
        assert!(
            assembly.append(&item(&circle, 0, None, 0x09)).is_err(),
            "an unadvertised stream must not be accepted"
        );
        assembly
            .append(&item(&realm_stream, 1, Some(0x01), 0x02))
            .unwrap();
        assert!(
            assembly
                .append(&item(&realm_stream, 1, Some(0x01), 0x02))
                .is_err(),
            "a repeat must not be accepted"
        );
        assert!(
            assembly
                .append(&item(&realm_stream, 2, Some(0x07), 0x03))
                .is_err(),
            "a broken previous_commit_ref must not be accepted"
        );
        assert!(
            assembly
                .append(&item(&realm_stream, 2, Some(0x02), 0x08))
                .is_err(),
            "another Commit at the advertised head position must not be accepted"
        );
    }

    #[test]
    fn assembly_rejects_an_answer_whose_floor_and_heads_disagree() {
        let realm = realm_id();
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let circle = circle_stream(&realm);

        assert!(
            RealmJoinBootstrapAssembly::new(outcome(&realm, Vec::new(), Vec::new())).is_err(),
            "an answer advertising no stream is not a bootstrap"
        );
        assert!(
            RealmJoinBootstrapAssembly::new(outcome(
                &realm,
                vec![head(realm_stream.clone(), 5, 0x05)],
                vec![head(realm_stream.clone(), 2, 0x03)],
            ))
            .is_err(),
            "a snapshot floor ahead of the advertised head is unusable"
        );
        assert!(
            RealmJoinBootstrapAssembly::new(outcome(
                &realm,
                vec![head(realm_stream.clone(), 0, 0x01), head(circle, 0, 0x09),],
                vec![head(realm_stream.clone(), 2, 0x03)],
            ))
            .is_err(),
            "a snapshot stream the answer never advertises leaves the joiner blind"
        );
        assert!(
            RealmJoinBootstrapAssembly::new(outcome(
                &realm,
                vec![head(realm_stream.clone(), 0, 0x01)],
                vec![
                    head(realm_stream.clone(), 2, 0x03),
                    head(realm_stream, 3, 0x04),
                ],
            ))
            .is_err(),
            "one stream may advertise only one head"
        );
    }
}
