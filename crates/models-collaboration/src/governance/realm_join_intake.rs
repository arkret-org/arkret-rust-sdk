//! Realm join discovery and bootstrap DTOs.
//!
//! Locator hints are untrusted. A joiner learns the current governance Station
//! only by validating the returned nonce-bound [`RealmAuthorityBundle`] from
//! Realm genesis through every authority handoff.

use arkret_wire::{
    AccountId, CommitStreamHead, DidCoreId, EventId, HistoryAccess, InviteId, JoinRule,
    RealmAuthorityBundle, RealmCommit, RealmCommitId, RealmId, RealmStateSnapshot, RequestId,
    Result, WireError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLocatorSource {
    Invite,
    Directory,
    Cache,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinTarget {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
}

impl RealmJoinTarget {
    pub fn validate(&self) -> Result<()> {
        if self.authority_locator_hints.is_empty() || self.authority_locator_hints.len() > 8 {
            return Err(WireError::Protocol(
                "realm join requires 1..=8 authority locator hints".to_owned(),
            ));
        }
        if self.invite_id.is_some() != self.invite_token.is_some() {
            return Err(WireError::Protocol(
                "invite_id and invite_token must appear together".to_owned(),
            ));
        }
        for (index, hint) in self.authority_locator_hints.iter().enumerate() {
            hint.validate()?;
            if index > 0
                && self.authority_locator_hints[index - 1].service_id.as_str()
                    >= hint.service_id.as_str()
            {
                return Err(WireError::Protocol(
                    "authority locator hints must be strictly sorted by service_id with no duplicate identity"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmJoinIntent {
    InviteAccept {
        invite_id: InviteId,
        invite_token: String,
    },
    MemberJoin,
    Knock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPublicPreview {
    pub realm_id: RealmId,
    pub join_rule: JoinRule,
    pub history_access: HistoryAccess,
    pub governance_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPreviewRequestBody {
    pub request_id: RequestId,
    pub target: RealmJoinTarget,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmJoinPreviewRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub requester_account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmJoinPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPrepareRequestBody {
    pub request_id: RequestId,
    pub target: RealmJoinTarget,
    pub intent: RealmJoinIntent,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPrepareOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub realm_stream_head: CommitStreamHead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinApplicationStatusRequest {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub application_event_id: EventId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinApplicationStatus {
    Pending,
    Committed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinApplicationStatusOutcome {
    pub request_id: RequestId,
    pub status: RealmJoinApplicationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<RealmCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

impl RealmJoinApplicationStatusOutcome {
    pub fn validate(&self) -> Result<()> {
        let valid = match self.status {
            RealmJoinApplicationStatus::Pending => {
                self.commit.is_none() && self.reason_code.is_none()
            }
            RealmJoinApplicationStatus::Committed => {
                self.commit.is_some() && self.reason_code.is_none()
            }
            RealmJoinApplicationStatus::Rejected => {
                self.commit.is_none() && self.reason_code.as_ref().is_some_and(|v| !v.is_empty())
            }
        };
        valid.then_some(()).ok_or_else(|| {
            WireError::Protocol("invalid Realm join application status outcome".to_owned())
        })
    }
}

/// A candidate names the authority-signed RealmCommit that admitted its
/// membership. The Commit id alone addresses that admission: the bootstrap
/// answer is derived from the authority's own stream, so the request carries no
/// client-supplied Event coordinates.
// Field declaration order is byte-for-byte the `properties` order of
// `realm-join-intake.schema.json#/$defs/peer_bootstrap_request_body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmJoinBootstrapRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub member_account_id: AccountId,
    pub membership_commit_id: RealmCommitId,
}

/// The verified current authority answers a bootstrap with one signed snapshot
/// plus the head of every stream the new member may read after its membership
/// Commit. The snapshot's own `visible_stream_heads` are the scan floor and
/// these are the scan target; see [`super::realm_join_bootstrap`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Field declaration order is byte-for-byte the `properties` order of
// `realm-join-intake.schema.json#/$defs/peer_bootstrap_outcome`.
pub struct PeerRealmJoinBootstrapOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub snapshot: RealmStateSnapshot,
    pub visible_stream_heads: Vec<CommitStreamHead>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateServiceKind {
    Station,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinCandidate {
    pub service_kind: RealmJoinCandidateServiceKind,
    pub service_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    pub source: AuthorityLocatorSource,
}

impl RealmJoinCandidate {
    /// Validates the locator-local constraints of the closed current-v1 core.
    ///
    /// Realm scope and freshness deliberately belong to the enclosing carrier;
    /// callers must not infer either from this untrusted locator.
    pub fn validate(&self) -> Result<()> {
        if self
            .endpoint_url
            .as_ref()
            .is_some_and(|url| !url.starts_with("https://"))
        {
            return Err(WireError::Protocol(
                "Realm join candidate endpoint_url must use https".to_owned(),
            ));
        }
        Ok(())
    }
}
