//! MIMI interoperability moderation facade.

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    ActorId, CommittedEventRef, DidCoreId, EventCommitSubmission, PayloadProof, ReportId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReporterAuthority {
    pub actor_id: ActorId,
    pub membership_ref: CommittedEventRef,
    pub room_binding_ref: CommittedEventRef,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReportAbuseRequestBody {
    pub reporter_authority: MimiReporterAuthority,
    pub report_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReportAbuseOutcome {
    pub report_id: ReportId,
    pub status: MimiReportAbuseStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to_ids: Vec<DidCoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiReportAbuseStatus {
    Queued,
}
