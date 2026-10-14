//! Exact, non-enumerating watch current read from the governing Station.

use arkret_wire::{ActorId, CommitStreamHead, CommitStreamRef, CurrentRevision, RealmId, StrandId};
use serde::{Deserialize, Serialize};

use crate::events_payloads::strand::StrandWatchExpectedValue;

/// Canonical body budget shared by the self and signed peer operations.
pub const STRAND_WATCH_CURRENT_MAX_BYTES: usize = 16 * 1024;
pub const PEER_STRAND_WATCH_CURRENT_PATH: &str = "/_arkret/peer/strands/watch/current";

/// Shared self/peer request; neither operation enumerates other watchers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandWatchCurrentRequestBody {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub watcher_actor_id: ActorId,
}

impl StrandWatchCurrentRequestBody {
    pub fn validate(&self) -> Result<(), arkret_wire::WireError> {
        if arkret_canonical::canonical_json_bytes(self)
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
            .len()
            > STRAND_WATCH_CURRENT_MAX_BYTES
        {
            return Err(arkret_wire::WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::PayloadTooLarge,
                message: "watch-current request exceeds its canonical budget".to_owned(),
            });
        }
        Ok(())
    }
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
    pub const fn governance_generation(&self) -> u64 {
        match self {
            Self::NeverWritten {
                governance_generation,
                ..
            }
            | Self::Current {
                governance_generation,
                ..
            } => *governance_generation,
        }
    }

    /// The Account Station supplies its fresh nonce-bound verified authority.
    pub fn validate_for_generation(
        &self,
        request: &StrandWatchCurrentRequestBody,
        generation: u64,
    ) -> Result<(), &'static str> {
        self.validate_for_request(request)?;
        if self.governance_generation() != generation {
            return Err("watch-current response differs from the verified governing generation");
        }
        Ok(())
    }

    /// Reject a validly shaped response for a different requested cell or
    /// Realm. Authorization and current authority verification stay server-side.
    pub fn validate_for_request(
        &self,
        request: &StrandWatchCurrentRequestBody,
    ) -> Result<(), &'static str> {
        if arkret_canonical::canonical_json_bytes(self)
            .map_err(|_| "watch-current response is not canonical JSON")?
            .len()
            > STRAND_WATCH_CURRENT_MAX_BYTES
        {
            return Err("watch-current response exceeds its canonical budget");
        }
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
        if !matches!(
            &head.stream_ref,
            CommitStreamRef::Realm { .. } | CommitStreamRef::Circle { .. }
        ) {
            return Err("watch-current head is not a Realm or Circle namespace");
        }
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
