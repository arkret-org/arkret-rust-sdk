//! Realm join discovery and bootstrap DTOs.
//!
//! Locator hints are untrusted. A joiner learns the current governance Station
//! only by validating the returned nonce-bound [`RealmAuthorityBundle`] from
//! Realm genesis through every authority handoff.

use arkret_wire::{
    AccountId, CommitStreamHead, CommitStreamRef, DidCoreId, EventId, HistoryAccess, InviteId,
    JoinRule, RealmAuthorityBundle, RealmCommit, RealmCommitId, RealmId, RealmStateSnapshot,
    RequestId, Result, WireError,
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
        validate_invite_credential(self.invite_id.as_ref(), self.invite_token.as_deref())?;
        validate_authority_locator_hints(&self.authority_locator_hints)
    }
}

/// Registered `maxLength` of `public_preview.display_name`.
pub const PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS: usize = 256;

fn validate_invite_credential(invite_id: Option<&InviteId>, token: Option<&str>) -> Result<()> {
    match (invite_id, token) {
        (None, None) => Ok(()),
        (Some(_), Some(token)) => arkret_wire::validate_invite_token("Realm join", token),
        _ => Err(WireError::Protocol(
            "invite_id and invite_token must appear together".to_owned(),
        )),
    }
}

/// Registered `maxItems` bound of every `authority_locator_hints` array.
pub const AUTHORITY_LOCATOR_HINTS_MAX: usize = 8;

/// Validates one `authority_locator_hints` array exactly as every carrier that
/// references `realm-join-candidate.schema.json` registers it: one to eight
/// closed locator cores, strictly sorted by `service_id` UTF-8 bytes, with
/// `service_id` as the semantic identity key. A duplicate or a conflicting
/// representation of one `service_id` invalidates the whole array.
pub fn validate_authority_locator_hints(hints: &[RealmJoinCandidate]) -> Result<()> {
    if hints.is_empty() || hints.len() > AUTHORITY_LOCATOR_HINTS_MAX {
        return Err(WireError::Protocol(
            "authority_locator_hints requires 1..=8 locator cores".to_owned(),
        ));
    }
    for (index, hint) in hints.iter().enumerate() {
        hint.validate()?;
        if index > 0 && hints[index - 1].service_id.as_str() >= hint.service_id.as_str() {
            return Err(WireError::Protocol(
                "authority locator hints must be strictly sorted by service_id with no duplicate identity"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

/// Producer-side canonicalization of one `authority_locator_hints` array.
///
/// Orders the cores by `service_id` UTF-8 bytes and then applies the same
/// validation every consumer repeats. Two cores naming one `service_id`, even
/// byte-identical ones, reject the whole set: the producer never picks a
/// winner, merges fields, or silently deduplicates.
pub fn canonicalize_authority_locator_hints(
    mut hints: Vec<RealmJoinCandidate>,
) -> Result<Vec<RealmJoinCandidate>> {
    hints.sort_by(|left, right| {
        left.service_id
            .as_str()
            .as_bytes()
            .cmp(right.service_id.as_str().as_bytes())
    });
    validate_authority_locator_hints(&hints)?;
    Ok(hints)
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

impl RealmJoinIntent {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InviteAccept { invite_token, .. } => {
                arkret_wire::validate_invite_token("invite_accept intent", invite_token)
            }
            Self::MemberJoin | Self::Knock => Ok(()),
        }
    }
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

impl RealmPublicPreview {
    pub fn validate(&self) -> Result<()> {
        if self
            .display_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > PUBLIC_PREVIEW_DISPLAY_NAME_MAX_CHARS)
        {
            return Err(WireError::Protocol(
                "Realm preview display_name exceeds 256 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Binds one preview answer to the exact request that produced it: the
/// echoed request id, the requested Realm on both the preview and the
/// authority bundle, and the governance tenure the preview was answered under.
fn validate_preview_binding(
    request_id: &RequestId,
    realm_id: &RealmId,
    outcome_request_id: &RequestId,
    authority_bundle: &RealmAuthorityBundle,
    preview: &RealmPublicPreview,
) -> Result<()> {
    authority_bundle.validate_shape()?;
    preview.validate()?;
    if outcome_request_id != request_id
        || &preview.realm_id != realm_id
        || &authority_bundle.realm_id != realm_id
        || preview.governance_generation != authority_bundle.current_generation
    {
        return Err(WireError::Protocol(
            "Realm preview does not bind the request and authority bundle".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPreviewRequestBody {
    pub request_id: RequestId,
    pub target: RealmJoinTarget,
}

impl SelfRealmJoinPreviewRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.target.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

impl SelfRealmJoinPreviewOutcome {
    pub fn validate_for_request(&self, request: &SelfRealmJoinPreviewRequestBody) -> Result<()> {
        request.validate()?;
        validate_preview_binding(
            &request.request_id,
            &request.target.realm_id,
            &self.request_id,
            &self.authority_bundle,
            &self.preview,
        )
    }
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

impl PeerRealmJoinPreviewRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.requester_account_id.validate()?;
        validate_invite_credential(self.invite_id.as_ref(), self.invite_token.as_deref())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRealmJoinPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

impl PeerRealmJoinPreviewOutcome {
    pub fn validate_for_request(&self, request: &PeerRealmJoinPreviewRequestBody) -> Result<()> {
        request.validate()?;
        validate_preview_binding(
            &request.request_id,
            &request.realm_id,
            &self.request_id,
            &self.authority_bundle,
            &self.preview,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPrepareRequestBody {
    pub request_id: RequestId,
    pub target: RealmJoinTarget,
    pub intent: RealmJoinIntent,
}

impl SelfRealmJoinPrepareRequestBody {
    /// An `invite_accept` intent must name exactly the invite the target
    /// carries; `member_join` and `knock` are valid with or without one.
    pub fn validate(&self) -> Result<()> {
        self.target.validate()?;
        self.intent.validate()?;
        if let RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } = &self.intent
            && (self.target.invite_id.as_ref() != Some(invite_id)
                || self.target.invite_token.as_ref() != Some(invite_token))
        {
            return Err(WireError::Protocol(
                "invite_accept intent does not bind the target invite".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRealmJoinPrepareOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub realm_stream_head: CommitStreamHead,
}

impl SelfRealmJoinPrepareOutcome {
    pub fn validate_for_request(&self, request: &SelfRealmJoinPrepareRequestBody) -> Result<()> {
        request.validate()?;
        self.authority_bundle.validate_shape()?;
        let realm_stream = CommitStreamRef::Realm {
            realm_id: request.target.realm_id.clone(),
        };
        if self.request_id != request.request_id
            || self.authority_bundle.realm_id != request.target.realm_id
            || self.realm_stream_head.stream_ref != realm_stream
        {
            return Err(WireError::Protocol(
                "Realm join preparation does not bind the request and authority bundle".to_owned(),
            ));
        }
        Ok(())
    }
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
    /// Shape check plus the exact binding to one application: the echoed
    /// request id, and for `committed` the Commit that covers exactly the
    /// requested join Event in the requested Realm.
    pub fn validate_for_request(&self, request: &RealmJoinApplicationStatusRequest) -> Result<()> {
        self.validate()?;
        if self.request_id != request.request_id {
            return Err(WireError::Protocol(
                "Realm join application status does not echo the request".to_owned(),
            ));
        }
        if let Some(commit) = &self.commit {
            commit.validate_shape()?;
            if commit.realm_id != request.realm_id
                || commit.event_ref != request.application_event_id
            {
                return Err(WireError::Protocol(
                    "Realm join application Commit does not cover the requested Event".to_owned(),
                ));
            }
        }
        Ok(())
    }

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
