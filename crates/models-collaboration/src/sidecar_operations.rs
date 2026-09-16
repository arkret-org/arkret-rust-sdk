//! One-shot Sidecar creation/attachment through the current Realm authority.

use arkret_wire::{
    AccountId, CommitStreamHead, CommittedEventRef, EventCommitSubmission, ProtocolOperationId,
    RealmId, RelationId, SidecarId, StrandId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SidecarContextRef {
    Relation { relation_id: RelationId },
    Strand { strand_id: StrandId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarEnsureRequestBody {
    pub operation_id: ProtocolOperationId,
    pub source_realm_id: RealmId,
    pub controller_account_id: AccountId,
    pub context_ref: SidecarContextRef,
    pub create_event: EventCommitSubmission,
    pub context_attach_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarEnsureOutcome {
    pub operation_id: ProtocolOperationId,
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub create_ref: CommittedEventRef,
    pub context_attach_ref: CommittedEventRef,
    pub sidecar_stream_head: CommitStreamHead,
}
