use super::*;

/// `ck.find.directory.query.describe` returns the shared ServiceDescribe
/// contract with the registered directory-service overlay fields populated.
pub type DirectoryDescription = ServiceDescribe;

pub const DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND: &str =
    "ck.directory.restricted_claim_presentation.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DirectoryPresentedClaim {
    pub claim_id: String,
    pub subject: Did,
    pub issuer: Did,
    pub claim_kind: String,
    pub value: Value,
    pub issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disclosed_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DirectoryRestrictedClaimPresentation {
    pub kind: String,
    pub iss: Did,
    pub verification_method: String,
    pub audience: Did,
    pub nonce: String,
    pub claim: DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryRealmSearchOutcome {
    #[serde(default)]
    pub realms: Vec<RealmPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum RealmMemberCountBucket {
    Bucket(RealmMemberCountBucketLabel),
    Exact(u64),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub as_of: DateTime<Utc>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

/// Service class that can receive Realm join-side submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateServiceType {
    PrincipalServer,
    SyncNode,
    Notary,
}

/// Routing role for a Realm join candidate. This is an ordering and
/// diagnostics hint, not an authorization grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinMethod {
    InviteAccept,
    MemberJoin,
    Knock,
    Application,
    RestrictedJoin,
}

/// Source from which a Realm join candidate was derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateSource {
    RealmSyncEndpoint,
    DirectoryIngest,
    InviteHint,
    SignedLinkHint,
    FederationRedirect,
    LocalCache,
}

/// `ck.schema.realm_join_candidate.v1`: time-bounded routing hint for
/// submitting Realm join, invite-accept, knock, or restricted-join material.
/// It is distinct from member delivery binding and does not authorize
/// membership by itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmJoinCandidate {
    pub realm_id: RealmId,
    pub service_did: Did,
    pub service_type: RealmJoinCandidateServiceType,
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
    pub seal_basis: crate::SealBasis,
    pub as_of: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryRealmResolutionOutcome {
    pub realm_preview: RealmPreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stripped_state: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
}

/// R3.3 (CKP-0011, cokret-spec @ cced4b8) — the resolved object class of a
/// shareable address. The address grammar (`crate::models::object_address`)
/// fixes the hierarchy `realm` ⊃ `strand` ⊃ `m` (message).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Realm,
    Strand,
    Message,
}

/// R3.3 (CKP-0011) — request body for `ck.find.directory.query.resolve_target`.
///
/// `address` is a client-agnostic shareable object address in either the
/// `web+cokret:` URI form or the HTTPS-landing fragment form (see
/// [`crate::models::object_address::parse_address`]). `token` is present iff
/// the address carries `lt=invite` or `lt=preview`; the server MUST bind it to
/// the resolved object via [`crate::models::object_address::verify_token_target`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveTargetRequestBody {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// R3.3 (CKP-0011) — response body for `ck.find.directory.query.resolve_target`.
///
/// Common §9.1 directory fields (`as_of`, `source_refs`, `join_candidates`,
/// `policy_revision`, `stale`, `divergent`) mirror the other directory
/// responses. `object_preview` is a target-kind-dependent opaque preview
/// (a stripped Strand / Message projection); it stays a `serde_json::Value`
/// because its shape varies by `target_kind`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryTargetResolutionOutcome {
    pub target_kind: TargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_preview: Option<RealmPreview>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_preview: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    pub as_of: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergent: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryOrganizationSearchOutcome {
    #[serde(default)]
    pub organizations: Vec<OrganizationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OrganizationPreview {
    pub organization_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryOrganizationResolutionOutcome {
    pub organization_preview: OrganizationPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryActorSearchOutcome {
    #[serde(default)]
    pub actors: Vec<ActorPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorPreview {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchUsersRequestBody {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum UserSearchMembership {
    Joined,
    Invited,
    Knocked,
    Left,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub member_delivery_binding: Option<DeliveryBindingHint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryUserSearchOutcome {
    #[serde(default)]
    pub users: Vec<UserSearchOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleRequestBody {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    /// Resolution purpose. `lookup` / `mention` return display-safe
    /// identity data; `member_add` / `invite` request a Realm/audience-bound
    /// membership candidate per `identity-handles.md` §3.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryHandleResolutionOutcome {
    pub did: Did,
    pub handle: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim: Option<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

fn default_agent_selector_claim_schema() -> String {
    AGENT_SELECTOR_CLAIM_SCHEMA.to_owned()
}

/// Signed controller-scoped selector claim for
/// `@<controller-handle>/<agent_slug>` resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSelectorClaim {
    #[serde(default = "default_agent_selector_claim_schema")]
    pub schema: String,
    pub controller_subject: Did,
    pub agent_slug: String,
    pub subject: Did,
    pub issuer: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_did: Option<Did>,
    pub binding_state: HandleBindingState,
    pub visibility: HandleVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

impl AgentSelectorClaim {
    pub fn validate(&self) -> Result<()> {
        if self.schema != AGENT_SELECTOR_CLAIM_SCHEMA {
            return Err(Error::Protocol(format!(
                "agent_selector_claim schema must be {AGENT_SELECTOR_CLAIM_SCHEMA}"
            )));
        }
        validate_agent_slug(&self.agent_slug)?;
        if matches!(self.binding_state, HandleBindingState::Verified) && self.proofs.is_empty() {
            return Err(Error::Protocol(
                "verified agent_selector_claim requires proofs".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Request body for `ck.find.directory.query.resolve_agent_selector`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveAgentSelectorRequestBody {
    pub controller_handle: Handle,
    pub agent_slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_agent_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    pub intent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub requester: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Value>,
}

/// Response body for `ck.find.directory.query.resolve_agent_selector`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAgentSelectorResolutionOutcome {
    pub controller_subject: Did,
    pub subject: Did,
    pub agent_slug: String,
    pub verified: bool,
    pub selector_claim: AgentSelectorClaim,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

pub fn validate_agent_slug(value: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(Error::Protocol("agent_slug must not be empty".to_owned()));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(Error::Protocol(
            "agent_slug must start with lowercase alnum".to_owned(),
        ));
    }
    let mut last = first;
    let mut len = 1usize;
    for ch in chars {
        len += 1;
        if len > 64 {
            return Err(Error::Protocol(
                "agent_slug must be at most 64 characters".to_owned(),
            ));
        }
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '_' && ch != '-' {
            return Err(Error::Protocol(
                "agent_slug may contain lowercase alnum, underscore, or hyphen only".to_owned(),
            ));
        }
        last = ch;
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(Error::Protocol(
            "agent_slug must end with lowercase alnum".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod agent_selector_tests {
    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn selector_claim() -> AgentSelectorClaim {
        AgentSelectorClaim {
            schema: AGENT_SELECTOR_CLAIM_SCHEMA.to_owned(),
            controller_subject: did("did:web:example.com:users:alice"),
            agent_slug: "summary".to_owned(),
            subject: did("did:web:agent.example"),
            issuer: did("did:web:example.com"),
            issuer_service_did: Some(did("did:web:example.com")),
            binding_state: HandleBindingState::Verified,
            visibility: HandleVisibility::Restricted,
            audience: Some("ck:realm:018f0000-0000-7000-8000-000000000001".to_owned()),
            claim_scope: BTreeMap::new(),
            expires_at: None,
            created_at: Utc::now(),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: vec![json!({"kind": "detached_jws"})],
        }
    }

    #[test]
    fn validates_agent_slug_pattern() {
        for value in ["s", "summary", "summary_v2", "summary-v2"] {
            validate_agent_slug(value).unwrap();
        }
        for value in ["", "-summary", "summary-", "Summary", "sum.mary"] {
            assert!(validate_agent_slug(value).is_err(), "{value}");
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

/// R3.2 (cokret-spec @ b56cab1) — request body for
/// `ck.find.directory.query.list_handles_for_subject`. Known holder/principal DID +
/// context → current visible handle claims (inverse of `resolve_handle`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    pub proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// R3.2 — response body for `ck.find.directory.query.list_handles_for_subject`.
/// Schema `ck.schema.list_handles_for_subject_response.v1`. Every
/// `claims[].subject` MUST equal [`Self::subject`] (byte-equal); use
/// [`Self::validate`] to enforce.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySubjectHandleList {
    pub subject: Did,
    #[serde(default)]
    pub claims: Vec<HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_handle: Option<Handle>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectoryPushResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryPushRegisterResourceFilter {
    pub resource_kinds: Vec<DirectoryPushResourceKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryPushRegisterRequestBody {
    pub subscriber_did: Did,
    pub resource_filter: DirectoryPushRegisterResourceFilter,
    pub webhook_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryPushRegisterOutcome {
    pub subscription_id: String,
    pub effective_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAnnounceRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub discovery_state: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub principal_server_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_announce_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryAnnounceOutcome {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: u64,
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryWithdrawRequestBody {
    pub resource_id: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub governance_proof: Value,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryWithdrawOutcome {
    pub withdrawal_ref: String,
    pub acked_at: DateTime<Utc>,
}
