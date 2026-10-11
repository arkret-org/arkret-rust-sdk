//! Exact, non-enumerating watch current read from the governing Station.

use arkret_wire::{ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, RealmId, StrandId};
use serde::{Deserialize, Serialize};

use crate::events_payloads::strand::StrandWatchExpectedValue;

/// `ak.self.strand.watch.read.current.v1` request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentRequestBody {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
}

/// Closed selector returned with both watch-current outcome branches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentSelector {
    pub kind: StrandWatchSelectorKind,
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrandWatchSelectorKind {
    StrandWatch,
}

/// A written watch cell has a revision even when it was cleared to `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentRow {
    pub selector: StrandWatchCurrentSelector,
    /// Exact stream of the covering RealmCommit named by `revision.commit_id`.
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    /// Required on the wire, including when explicitly cleared to JSON `null`.
    pub value: StrandWatchCurrentValue,
}

/// Unlike `Option<T>`, this field does not silently accept an omitted `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StrandWatchCurrentValue {
    Set(StrandWatchExpectedValue),
    Cleared(()),
}

impl StrandWatchCurrentValue {
    pub const fn as_option(&self) -> Option<&StrandWatchExpectedValue> {
        match self {
            Self::Set(value) => Some(value),
            Self::Cleared(()) => None,
        }
    }
}

/// Absence is an explicit Station-confirmed fact, never inferred from a
/// missing snapshot entry or local raw Event order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrandWatchCurrentOutcome {
    NeverWritten {
        realm_id: RealmId,
        governance_generation: u64,
        stream_head: CommitStreamHead,
        selector: StrandWatchCurrentSelector,
    },
    Current {
        realm_id: RealmId,
        governance_generation: u64,
        stream_head: CommitStreamHead,
        result: StrandWatchCurrentRow,
    },
}

impl StrandWatchCurrentOutcome {
    /// Reject a validly shaped response for a different requested cell or
    /// Realm. Authorization and current authority verification stay server-side.
    pub fn validate_for_request(
        &self,
        request: &StrandWatchCurrentRequestBody,
    ) -> Result<(), &'static str> {
        let (realm_id, head, selector, source) = match self {
            Self::NeverWritten {
                realm_id,
                stream_head,
                selector,
                ..
            } => (realm_id, stream_head, selector, None),
            Self::Current {
                realm_id,
                stream_head,
                result,
                ..
            } => (
                realm_id,
                stream_head,
                &result.selector,
                Some((&result.source_stream_ref, &result.revision)),
            ),
        };
        if realm_id != &request.realm_id || head.stream_ref.realm_id() != &request.realm_id {
            return Err("watch-current response Realm differs from request");
        }
        if selector.strand_id != request.strand_id
            || selector.watcher_actor_id != request.watcher_actor_id
        {
            return Err("watch-current response selector differs from request");
        }
        if let Some((source_stream_ref, revision)) = source {
            // The revision position is only comparable on its own covering
            // stream; a row from another stream cannot be bounded by this head.
            if source_stream_ref != &head.stream_ref {
                return Err("watch-current source stream differs from the confirmed stream head");
            }
            if revision.stream_position > head.stream_position
                || (revision.stream_position == head.stream_position
                    && revision.commit_id != head.commit_id)
            {
                return Err("watch-current revision is not bounded by the confirmed stream head");
            }
        }
        Ok(())
    }
}
