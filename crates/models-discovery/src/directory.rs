//! Directory search, resolve, announce, push, and takedown operation
//! wire shapes (`discovery-directory.md`; R9).

use std::collections::BTreeMap;
use std::fmt;

use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DirectoryRestrictedClaimPresentation, validate_agent_slug,
};
use arkret_models_identity::handle::Handle;
use arkret_models_identity::handle_claim::{DeliveryBindingHint, HandleClaim};
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    BlobRef, Did, Error, EventId, Hash, JoinRule, NonEmptyString, PayloadProof, Proof, RealmId,
    Result, SchemaId, SealBasis,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directory_artifacts::ObjectPreview;
use crate::service_description::DirectoryResourceKind;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchRealmsRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRealmSearchOutcome {
    #[serde(default)]
    pub realms: Vec<RealmPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmMemberCountBucketLabel {
    #[serde(rename = "1-10")]
    OneToTen,
    #[serde(rename = "11-50")]
    ElevenToFifty,
    #[serde(rename = "51-100")]
    FiftyOneToOneHundred,
    #[serde(rename = "101-500")]
    OneHundredOneToFiveHundred,
    #[serde(rename = "501-2000")]
    FiveHundredOneToTwoThousand,
    #[serde(rename = "2000+")]
    TwoThousandPlus,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmMemberCountBucket {
    Bucket(RealmMemberCountBucketLabel),
    Exact(u64),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmPreview {
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count_bucket: Option<RealmMemberCountBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discoverability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    /// Event ids this entry was derived from. Omitted when the entry has no
    /// Event provenance: `directory-operations.schema.json` keeps `minItems: 1`
    /// on the array, so an empty one is not a legal way to say "none" — and a
    /// synthesized id would be worse than absence, since it looks verifiable and
    /// resolves to nothing (`discovery-directory.md` section 7.3 invariant 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

/// Service class that can receive Realm join-side submissions.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateServiceKind {
    PrincipalServer,
    SyncNode,
    Notary,
}

/// Routing role for a Realm join candidate. This is an ordering and
/// diagnostics hint, not an authorization grant.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateRole {
    Primary,
    Mirror,
    Notary,
    Sync,
    FederationPeer,
    InviteOrigin,
    ReviewerIngress,
}

/// Join-side strand supported by a Realm join candidate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinMethod {
    InviteAccept,
    MemberJoin,
    Knock,
    Application,
    RestrictedJoin,
}

/// Source from which a Realm join candidate was derived.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateSource {
    RealmSyncEndpoint,
    DirectoryIngest,
    InviteHint,
    SignedLinkHint,
    FederationRedirect,
    LocalCache,
}

/// `ak.schema.realm_join_candidate.v1`: time-bounded routing hint for
/// submitting Realm join, invite-accept, knock, or restricted-join material.
/// It is distinct from member delivery binding and does not authorize
/// membership by itself.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmJoinCandidate {
    pub realm_id: RealmId,
    pub service_id: Did,
    pub service_kind: RealmJoinCandidateServiceKind,
    pub role: RealmJoinCandidateRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub operations: Vec<String>,
    pub join_methods: Vec<RealmJoinMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub source: RealmJoinCandidateSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<String>,
    /// Full single-leaf Control Move basis for the current accepted Realm Seal
    /// head at `as_of`. Principal server candidates MUST include this for
    /// pre-join join / invite acceptance because the invitee cannot read the
    /// membership-gated frontier view before joining.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub seal_basis: SealBasis,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl RealmJoinCandidate {
    pub const SCHEMA: &'static str = SchemaId::REALM_JOIN_CANDIDATE_V1;
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveRealmRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRealmResolutionOutcome {
    pub realm_preview: RealmPreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub stripped_state: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub join_rule: Option<JoinRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
}

/// R3.3 (AKP-0011, arkret-spec @ cced4b8) — the resolved object class of a
/// shareable address. The address grammar (`crate::models::object_address`)
/// fixes the hierarchy `realm` ⊃ `strand` ⊃ `m` (message).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Realm,
    Strand,
    Message,
}

/// R3.3 (AKP-0011) — request body for `ak.find.directory.read.resolve_target`.
///
/// `address` is a client-agnostic shareable object address in either the
/// `web+arkret:` URI form or the HTTPS-landing fragment form (see
/// `object_address::parse_address`). `token` is present iff
/// the address carries `lt=invite` or `lt=preview`; the server MUST bind it to
/// the resolved object via `object_address::verify_token_target`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveTargetRequestBody {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// R3.3 (AKP-0011) — response body for `ak.find.directory.read.resolve_target`.
///
/// Common §9.1 directory fields (`as_of`, `source_refs`, `join_candidates`,
/// `policy_revision`, `stale`, `divergent`) mirror the other directory
/// responses. `object_preview` is a target-kind-dependent opaque preview
/// (a stripped Strand / Message projection); it stays a `serde_json::Value`
/// because its shape varies by `target_kind`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryTargetResolutionOutcome {
    pub target_kind: TargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_preview: Option<RealmPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_preview: Option<ObjectPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub join_rule: Option<JoinRule>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
    pub policy_revision: NonEmptyString,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchOrganizationsRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryOrganizationSearchOutcome {
    #[serde(default)]
    pub organizations: Vec<OrganizationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationPreview {
    pub organization_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_badge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realms: Vec<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_count: Option<u64>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    /// Event ids this entry was derived from. Omitted when the entry has no
    /// Event provenance: `directory-operations.schema.json` keeps `minItems: 1`
    /// on the array, so an empty one is not a legal way to say "none" — and a
    /// synthesized id would be worse than absence, since it looks verifiable and
    /// resolves to nothing (`discovery-directory.md` section 7.3 invariant 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveOrganizationRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryOrganizationResolutionOutcome {
    pub organization_preview: OrganizationPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchActorsRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryActorSearchOutcome {
    #[serde(default)]
    pub actors: Vec<ActorPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorPreview {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    /// Event ids this entry was derived from. Omitted when the entry has no
    /// Event provenance: `directory-operations.schema.json` keeps `minItems: 1`
    /// on the array, so an empty one is not a legal way to say "none" — and a
    /// synthesized id would be worse than absence, since it looks verifiable and
    /// resolves to nothing (`discovery-directory.md` section 7.3 invariant 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<EventId>,
    pub policy_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryIntent {
    Lookup,
    Mention,
    Invite,
    MemberAdd,
    ContactRequest,
}

impl DirectoryIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Mention => "mention",
            Self::Invite => "invite",
            Self::MemberAdd => "member_add",
            Self::ContactRequest => "contact_request",
        }
    }
}

impl fmt::Display for DirectoryIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DirectoryIntent {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "lookup" => Ok(Self::Lookup),
            "mention" => Ok(Self::Mention),
            "invite" => Ok(Self::Invite),
            "member_add" => Ok(Self::MemberAdd),
            "contact_request" => Ok(Self::ContactRequest),
            other => Err(Error::Protocol(format!(
                "unsupported directory intent: {other}"
            ))),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchUsersRequestBody {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<DirectoryIntent>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSearchMembership {
    Joined,
    Invited,
    Knocked,
    Left,
    Unknown,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveHandleRequestBody {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
    /// Resolution purpose. `lookup` / `mention` return display-safe
    /// identity data; `member_add` / `invite` request a Realm/audience-bound
    /// membership candidate per `identity-handles.md` §3.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<DirectoryIntent>,
    /// DID or service DID of the requester. Required by directory policy for
    /// `member_add` / `invite` disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    /// Target Realm ID or inviting service DID the result must be bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Target Realm for membership-builder intents. Used by directory
    /// implementations to apply `delivery_binding_policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<String>,
}

/// Request body for `ak.find.directory.read.resolve_agent_selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveAgentSelectorRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub controller_handle: Handle,
    pub agent_slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_agent_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    pub intent: DirectoryIntent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub requester: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

/// Response body for `ak.find.directory.read.resolve_agent_selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAgentSelectorResolutionOutcome {
    pub controller_subject: Did,
    pub subject: Did,
    pub agent_slug: String,
    pub verified: bool,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub selector_claim: AgentSelectorClaim,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl DirectoryAgentSelectorResolutionOutcome {
    pub fn validate(&self) -> Result<()> {
        if !self.verified {
            return Err(Error::Protocol(
                "directory_agent_selector_resolution_outcome.verified must be true".to_owned(),
            ));
        }
        validate_agent_slug(&self.agent_slug)?;
        self.selector_claim.validate()?;
        if self.selector_claim.controller_subject != self.controller_subject {
            return Err(Error::Protocol(
                "selector_claim.controller_subject must match response.controller_subject"
                    .to_owned(),
            ));
        }
        if self.selector_claim.subject != self.subject {
            return Err(Error::Protocol(
                "selector_claim.subject must match response.subject".to_owned(),
            ));
        }
        if self.selector_claim.agent_slug != self.agent_slug {
            return Err(Error::Protocol(
                "selector_claim.agent_slug must match response.agent_slug".to_owned(),
            ));
        }
        Ok(())
    }
}

/// R3.2 (arkret-spec @ b56cab1) — request body for
/// `ak.find.directory.read.list_handles_for_subject`. Known holder/principal DID +
/// context → current visible handle claims (inverse of `resolve_handle`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryListHandlesForSubjectRequestBody {
    /// Holder/principal DID reverse-lookup key. NOT a Realm actor_id.
    pub subject: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryPushResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryPushRegisterResourceFilter {
    pub resource_kinds: Vec<DirectoryPushResourceKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_ids: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryPushRegisterRequestBody {
    pub subscriber_did: Did,
    pub resource_filter: DirectoryPushRegisterResourceFilter,
    pub webhook_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryPushRegisterOutcome {
    pub subscription_id: crate::SubscriptionId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAnnounceRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub discovery_state: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    pub principal_server_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_announce_id: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAnnounceOutcome {
    pub announce_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryWithdrawRequestBody {
    pub resource_id: String,
    pub governance_proof: BTreeMap<String, Value>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryWithdrawOutcome {
    pub withdrawal_ref: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub acked_at: DateTime<Utc>,
}

/// Requested outcome of a directory takedown appeal (`discovery-directory.md §8.7`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryTakedownAppealOutcomeRequest {
    Overturn,
    ReduceScope,
    Reinstate,
}

/// `ak.find.directory.command.takedown_appeal` request — resource-side appeal
/// of an operator takedown. Mirrors
/// `service-operation-dtos.schema.json#/$defs/DirectoryTakedownAppealRequestBody`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryTakedownAppealRequestBody {
    /// The operator `takedown_id` from the takedown notice
    /// (`takedown:<token>`).
    pub takedown_id: String,
    /// Realm/applet ak-id, actor DID, or handle the takedown targets.
    pub resource_id: String,
    pub appellant_did: Did,
    /// `sha256:<hex>` digest of the appeal argument / evidence bundle.
    pub argument_digest: Hash,
    pub requested_outcome: DirectoryTakedownAppealOutcomeRequest,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Signature by the resource governance key or an authorized advocate.
    pub governance_proof: BTreeMap<String, Value>,
}

/// `ak.find.directory.command.takedown_appeal` outcome — signed decision
/// receipt. Mirrors
/// `service-operation-dtos.schema.json#/$defs/DirectoryTakedownAppealOutcome`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryTakedownAppealOutcome {
    /// Directory-local audit reference (`appeal:<token>`); not a registered
    /// `ak:<kind>` typed id.
    pub appeal_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    /// Signed Directory decision receipt; status pending until adjudicated.
    pub decision_receipt: BTreeMap<String, Value>,
}

/// A single `ak.find.directory.read.search_users` result row.
///
/// Embeds the collaboration `DeliveryBindingHint` (now owned by
/// `arkret-models-identity`) and the discovery-local [`UserSearchMembership`];
/// hosting it here keeps directory user-search outcomes off the
/// the `arkret` umbrella facade without a discovery -> collaboration edge.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSearchOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// `discovery-directory.md` §9: `results[].did` is **conditional** —
    /// the directory MAY omit it when the caller is not authorized to learn
    /// the subject DID (returning a handle / display preview only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<UserSearchMembership>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryUserSearchOutcome {
    #[serde(default)]
    pub users: Vec<UserSearchOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryHandleResolutionOutcome {
    pub did: Did,
    pub handle: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<Vec<serde_json::Value>>))
    )]
    pub claims: Option<Vec<HandleClaim>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Option<serde_json::Value>))
    )]
    pub handle_claim: Option<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub divergent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_services: Vec<String>,
}

/// R3.2 — response body for `ak.find.directory.read.list_handles_for_subject`.
/// Schema `ak.schema.list_handles_for_subject_response.v1`. Every
/// `claims[].subject` MUST equal [`Self::subject`] (byte-equal); use
/// [`Self::validate`] to enforce.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySubjectHandleList {
    pub subject: Did,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claims: Vec<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Option<String>)))]
    pub primary_handle: Option<Handle>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl DirectorySubjectHandleList {
    /// Enforce the schema invariant that every claim's `subject` equals the
    /// top-level `subject`. Mismatching claims MUST be dropped or fail the
    /// response closed; this validator fails closed.
    pub fn validate(&self) -> Result<()> {
        for claim in &self.claims {
            match &claim.subject {
                Some(s) if *s == self.subject => {}
                _ => {
                    return Err(Error::Protocol(
                        "list_handles_for_subject: claims[].subject must equal response.subject"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod agent_selector_outcome_tests {
    use std::collections::BTreeMap;

    use arkret_models_identity::claim_presentation::AgentSelectorClaim;
    use arkret_models_identity::handle::{HandleBindingState, HandleVisibility};
    use arkret_wire::{Did, DidUrl, Hash, PayloadProof, SchemaId};
    use chrono::Utc;

    use super::DirectoryAgentSelectorResolutionOutcome;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn selector_claim() -> AgentSelectorClaim {
        AgentSelectorClaim {
            schema: SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned(),
            controller_subject: did("did:webvh:z6mkfixture:example.com:users:alice"),
            agent_slug: "summary".to_owned(),
            subject: did("did:webvh:z6mkfixture:agent.example"),
            issuer: did("did:webvh:z6mkfixture:example.com"),
            issuer_service_id: Some(did("did:webvh:z6mkfixture:example.com")),
            binding_state: HandleBindingState::Verified,
            visibility: HandleVisibility::Restricted,
            audience: Some("ak:realm:018f0000-0000-8000-8000-000000000001".to_owned()),
            claim_scope: BTreeMap::new(),
            expires_at: None,
            created_at: Utc::now(),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:example.com#key-1")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "aaa.bbb.ccc".to_owned(),
            }],
        }
    }

    #[test]
    fn validates_selector_outcome_matches_claim() {
        let selector_claim = selector_claim();
        let outcome = DirectoryAgentSelectorResolutionOutcome {
            controller_subject: selector_claim.controller_subject.clone(),
            subject: selector_claim.subject.clone(),
            agent_slug: selector_claim.agent_slug.clone(),
            verified: true,
            selector_claim,
            source_refs: Vec::new(),
            expires_at: None,
        };
        outcome.validate().unwrap();
    }
}
