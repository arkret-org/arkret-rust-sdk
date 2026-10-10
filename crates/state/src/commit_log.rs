use std::collections::BTreeMap;
use std::sync::Mutex;

use arkret_identifiers::{EventId, RealmCommitId};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventFullView, CommittedEventView, Event,
    ReadableFloor, ReadableFloorReason, RealmCommit, StreamScanDirection, StreamScanOutcome,
    StreamScanRequest,
};
use thiserror::Error;

pub type CommitLogResult<T> = Result<T, CommitLogError>;

#[derive(Clone, Debug, PartialEq)]
pub enum AppendOutcome {
    Committed(RealmCommit),
    Duplicate(RealmCommit),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CommitLogError {
    #[error("invalid RealmCommit: {0}")]
    InvalidCommit(String),
    #[error("event_ref does not match the submitted Event")]
    EventReferenceMismatch,
    #[error("RealmCommit stream does not match the Event scope")]
    StreamMismatch,
    #[error("stream head changed")]
    HeadConflict,
    #[error("event_id was already committed with different commit bytes")]
    DuplicateConflict,
}

/// Atomic persistence boundary implemented by the current governance Station.
///
/// Authorization, typed reducer execution, and signature verification happen
/// before this call. The store owns the final compare-and-swap that prevents
/// two commits from occupying one position in the same independent stream.
pub trait AuthorityCommitStore: Send + Sync {
    fn append(&self, event: &Event, commit: RealmCommit) -> CommitLogResult<AppendOutcome>;

    fn stream_head(&self, stream_ref: &CommitStreamRef) -> Option<CommitStreamHead>;

    fn commit(&self, commit_id: &RealmCommitId) -> Option<RealmCommit>;

    fn commit_for_event(&self, event_id: &EventId) -> Option<RealmCommit>;

    fn scan(&self, request: &StreamScanRequest) -> CommitLogResult<StreamScanOutcome>;
}

#[derive(Default)]
pub struct MemoryAuthorityCommitStore {
    inner: Mutex<MemoryAuthorityCommitStoreInner>,
}

#[derive(Default)]
struct MemoryAuthorityCommitStoreInner {
    heads: BTreeMap<CommitStreamRef, RealmCommitId>,
    commits: BTreeMap<RealmCommitId, RealmCommit>,
    events: BTreeMap<EventId, Event>,
    by_event: BTreeMap<EventId, RealmCommitId>,
    by_stream_position: BTreeMap<(CommitStreamRef, u64), RealmCommitId>,
}

impl AuthorityCommitStore for MemoryAuthorityCommitStore {
    fn append(&self, event: &Event, commit: RealmCommit) -> CommitLogResult<AppendOutcome> {
        commit
            .validate_shape()
            .map_err(|error| CommitLogError::InvalidCommit(error.to_string()))?;
        if commit.event_ref != event.event_id {
            return Err(CommitLogError::EventReferenceMismatch);
        }
        let expected_stream = CommitStreamRef::from_scope(
            &event.scope_ref,
            (event.scope_ref == arkret_wire::ScopeRef::RealmGenesis)
                .then_some(event.realm_id.clone()),
        )
        .map_err(|error| CommitLogError::InvalidCommit(error.to_string()))?;
        if commit.stream_ref != expected_stream {
            return Err(CommitLogError::StreamMismatch);
        }

        let mut inner = self.inner.lock().expect("authority commit store poisoned");
        if let Some(existing_id) = inner.by_event.get(&event.event_id) {
            let existing = inner
                .commits
                .get(existing_id)
                .expect("event index points to an existing commit");
            return if existing == &commit {
                Ok(AppendOutcome::Duplicate(existing.clone()))
            } else {
                Err(CommitLogError::DuplicateConflict)
            };
        }

        match inner.heads.get(&commit.stream_ref) {
            None if commit.stream_position == 0 && commit.previous_commit_ref.is_none() => {}
            Some(previous_id) => {
                let previous = inner
                    .commits
                    .get(previous_id)
                    .expect("stream head points to an existing commit");
                commit
                    .validate_successor_of(previous)
                    .map_err(|_| CommitLogError::HeadConflict)?;
            }
            _ => return Err(CommitLogError::HeadConflict),
        }

        inner
            .heads
            .insert(commit.stream_ref.clone(), commit.commit_id.clone());
        inner
            .by_event
            .insert(event.event_id.clone(), commit.commit_id.clone());
        inner.events.insert(event.event_id.clone(), event.clone());
        inner.by_stream_position.insert(
            (commit.stream_ref.clone(), commit.stream_position),
            commit.commit_id.clone(),
        );
        inner
            .commits
            .insert(commit.commit_id.clone(), commit.clone());
        Ok(AppendOutcome::Committed(commit))
    }

    fn stream_head(&self, stream_ref: &CommitStreamRef) -> Option<CommitStreamHead> {
        let inner = self.inner.lock().expect("authority commit store poisoned");
        let commit_id = inner.heads.get(stream_ref)?;
        let commit = inner.commits.get(commit_id)?;
        Some(CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        })
    }

    fn commit(&self, commit_id: &RealmCommitId) -> Option<RealmCommit> {
        self.inner
            .lock()
            .expect("authority commit store poisoned")
            .commits
            .get(commit_id)
            .cloned()
    }

    fn commit_for_event(&self, event_id: &EventId) -> Option<RealmCommit> {
        let inner = self.inner.lock().expect("authority commit store poisoned");
        inner
            .by_event
            .get(event_id)
            .and_then(|commit_id| inner.commits.get(commit_id))
            .cloned()
    }

    fn scan(&self, request: &StreamScanRequest) -> CommitLogResult<StreamScanOutcome> {
        request
            .validate()
            .map_err(|error| CommitLogError::InvalidCommit(error.to_string()))?;
        let inner = self.inner.lock().expect("authority commit store poisoned");
        let Some(head_id) = inner.heads.get(&request.stream_ref) else {
            return Ok(StreamScanOutcome {
                committed_events: Vec::new(),
                readable_floor: None,
                truncated: false,
            });
        };
        let head_position = inner
            .commits
            .get(head_id)
            .expect("stream head points to an existing commit")
            .stream_position;
        let floor_commit_id = inner
            .by_stream_position
            .get(&(request.stream_ref.clone(), 0))
            .expect("linear stream begins at position zero")
            .clone();
        let readable_floor = Some(ReadableFloor {
            oldest_position: 0,
            floor_commit_id,
            floor_reason: ReadableFloorReason::StreamStart,
        });
        let (positions, truncated): (Vec<u64>, bool) = match request.direction {
            StreamScanDirection::After(bound) => {
                let start = bound.map_or(0, |position| position.saturating_add(1));
                if start > head_position || bound == Some(u64::MAX) {
                    (Vec::new(), false)
                } else {
                    let end = start
                        .saturating_add(u64::from(request.limit) - 1)
                        .min(head_position);
                    ((start..=end).collect(), end < head_position)
                }
            }
            StreamScanDirection::Before(Some(0)) => (Vec::new(), false),
            StreamScanDirection::Before(bound) => {
                let start = bound
                    .map_or(head_position, |position| position - 1)
                    .min(head_position);
                let end = start.saturating_sub(u64::from(request.limit) - 1);
                ((end..=start).rev().collect(), end > 0)
            }
        };
        let mut committed_events = Vec::with_capacity(positions.len());
        for position in positions {
            let commit_id = inner
                .by_stream_position
                .get(&(request.stream_ref.clone(), position))
                .expect("linear stream contains every position through its head");
            let commit = inner
                .commits
                .get(commit_id)
                .expect("stream position points to an existing commit")
                .clone();
            let event = inner
                .events
                .get(&commit.event_ref)
                .expect("commit points to an existing event")
                .clone();
            committed_events.push(CommittedEventView::Full(CommittedEventFullView {
                commit,
                event,
            }));
        }
        Ok(StreamScanOutcome {
            committed_events,
            readable_floor,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_identifiers::{CircleId, DidCoreId, EventId, RealmCommitId, RealmId};
    use arkret_wire::{
        ActorId, Base64UrlString, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, DidUrl, EventKind, Hash, RealmCommitAuthorityRef, ScopeRef,
    };
    use chrono::{TimeZone, Utc};

    use super::*;

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [1; 32]))
    }

    fn event(byte: u8, scope_ref: ScopeRef) -> Event {
        Event {
            event_id: EventId::from_digest(DigestSuite::Sha256, [byte; 32]),
            kind: EventKind::MessageCreate,
            realm_id: realm(),
            scope_ref,
            actor_id: ActorId::service(
                DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
            ),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
            semantic_refs: Vec::new(),
            payload: Default::default(),
            producer_proof: None,
        }
    }

    fn commit(
        byte: u8,
        event: &Event,
        stream_ref: CommitStreamRef,
        position: u64,
        previous: Option<RealmCommitId>,
    ) -> RealmCommit {
        RealmCommit {
            commit_id: RealmCommitId::from_digest([byte; 32]),
            realm_id: realm(),
            stream_ref,
            stream_position: position,
            previous_commit_ref: previous,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                DigestSuite::Sha256,
                [9; 32],
            )),
            committed_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 1).unwrap(),
            producer_signer_fact_digest: None,
            signature: DetachedObjectSignature {
                context: DetachedSignatureContext::RealmCommit,
                signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
                signed_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                created_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 1).unwrap(),
                sig: Base64UrlString::new("AA").unwrap(),
            },
        }
    }

    #[test]
    fn realm_and_circle_advance_independently() {
        let store = MemoryAuthorityCommitStore::default();
        let realm_stream = CommitStreamRef::Realm { realm_id: realm() };
        let circle_stream = CommitStreamRef::Circle {
            realm_id: realm(),
            circle_id: CircleId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [2; 32])),
        };
        let realm_event = event(3, ScopeRef::Realm { realm_id: realm() });
        let circle_event = event(
            4,
            ScopeRef::Circle {
                realm_id: realm(),
                circle_id: match &circle_stream {
                    CommitStreamRef::Circle { circle_id, .. } => circle_id.clone(),
                    _ => unreachable!(),
                },
            },
        );
        let realm_commit = commit(5, &realm_event, realm_stream.clone(), 0, None);
        let circle_commit = commit(6, &circle_event, circle_stream.clone(), 0, None);

        assert!(matches!(
            store.append(&realm_event, realm_commit),
            Ok(AppendOutcome::Committed(_))
        ));
        assert!(matches!(
            store.append(&circle_event, circle_commit),
            Ok(AppendOutcome::Committed(_))
        ));
        assert_eq!(store.stream_head(&realm_stream).unwrap().stream_position, 0);
        assert_eq!(
            store.stream_head(&circle_stream).unwrap().stream_position,
            0
        );
    }

    #[test]
    fn scan_supports_both_directions_and_reports_physical_floor() {
        let store = MemoryAuthorityCommitStore::default();
        let stream_ref = CommitStreamRef::Realm { realm_id: realm() };
        let mut previous = None;
        for position in 0..3 {
            let item = event(position as u8 + 30, ScopeRef::Realm { realm_id: realm() });
            let sealed = commit(
                position as u8 + 40,
                &item,
                stream_ref.clone(),
                position,
                previous,
            );
            previous = Some(sealed.commit_id.clone());
            store.append(&item, sealed).unwrap();
        }
        let request = |direction| StreamScanRequest {
            realm_id: realm(),
            stream_ref: stream_ref.clone(),
            direction,
            limit: 2,
        };
        let newer = request(StreamScanDirection::After(None));
        let first = store.scan(&newer).unwrap();
        assert_eq!(
            first
                .committed_events
                .iter()
                .map(|row| row.commit().stream_position)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(first.truncated);
        first.validate_for_request(&newer).unwrap();
        let older = request(StreamScanDirection::Before(None));
        let first = store.scan(&older).unwrap();
        assert_eq!(
            first
                .committed_events
                .iter()
                .map(|row| row.commit().stream_position)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert!(first.truncated);
        first.validate_for_request(&older).unwrap();
        let final_page_request = request(StreamScanDirection::Before(Some(1)));
        let final_page = store.scan(&final_page_request).unwrap();
        assert_eq!(final_page.committed_events[0].commit().stream_position, 0);
        assert!(!final_page.truncated);
        assert_eq!(
            final_page.readable_floor.as_ref().unwrap().oldest_position,
            0
        );
        final_page
            .validate_for_request(&final_page_request)
            .unwrap();
    }

    #[test]
    fn cross_stream_predecessor_is_rejected() {
        let store = MemoryAuthorityCommitStore::default();
        let realm_stream = CommitStreamRef::Realm { realm_id: realm() };
        let first_event = event(10, ScopeRef::Realm { realm_id: realm() });
        let first = commit(11, &first_event, realm_stream, 0, None);
        store.append(&first_event, first.clone()).unwrap();

        let circle_id =
            CircleId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [12; 32]));
        let circle_stream = CommitStreamRef::Circle {
            realm_id: realm(),
            circle_id: circle_id.clone(),
        };
        let second_event = event(
            13,
            ScopeRef::Circle {
                realm_id: realm(),
                circle_id,
            },
        );
        let invalid = commit(14, &second_event, circle_stream, 1, Some(first.commit_id));
        assert_eq!(
            store.append(&second_event, invalid),
            Err(CommitLogError::HeadConflict)
        );
    }
}
