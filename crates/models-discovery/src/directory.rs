//! Directory search, resolve, announce, push, and takedown operation
//! wire shapes (`discovery-directory.md`; R9).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use arkret_models_identity::ServiceResolutionCarrier;
use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DirectoryRestrictedClaimPresentation, validate_agent_slug,
};
use arkret_models_identity::handle::Handle;
use arkret_models_identity::handle_claim::{DeliveryBindingHint, HandleClaim};
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    Audience, AuditReasonText, BlobRef, DidCoreId, DidUrl, EncryptionProfile, EventId, Hash,
    JoinRule, NonEmptyString, PayloadProof, ProofContextId, RealmId, Result, SchemaId, SealBasis,
    ServiceOperationId, WireError, proof_kind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directory_artifacts::ObjectPreview;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectorySearchRealmsRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_principal_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<DidCoreId>,
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
    pub organization_principal_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count_bucket: Option<RealmMemberCountBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discoverability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_access: Option<String>,
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
}

/// Routing role for a Realm join candidate. This is an ordering and
/// diagnostics hint, not an authorization grant.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmJoinCandidateRole {
    JoinedMemberPrincipalServer,
}

/// Join-side strand supported by a Realm join candidate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    InviteHint,
    MemberDeliveryBinding,
}

/// `ak.schema.realm_join_candidate.v1`: time-bounded routing hint for
/// submitting Realm join, invite-accept, knock, or restricted-join material.
/// It is distinct from member delivery binding and does not authorize
/// membership by itself.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinCandidate {
    pub realm_id: RealmId,
    pub service_id: DidCoreId,
    pub service_resolution: ServiceResolutionCarrier,
    pub service_kind: RealmJoinCandidateServiceKind,
    pub role: RealmJoinCandidateRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub operations: Vec<String>,
    pub join_methods: Vec<RealmJoinMethod>,
    /// Effective accepted Realm profile at `as_of`. Pre-join clients use this
    /// instead of reading membership-gated Realm history when applying the
    /// E2EE recovery-material gate.
    pub encryption_profile: EncryptionProfile,
    /// Verified current live digest suite at the complete accepted Seal basis.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub digest_algorithm: arkret_canonical::DigestSuite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub source: RealmJoinCandidateSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<String>,
    /// Complete Control Move basis for the current accepted Realm Seal
    /// frontier at `as_of`. Principal server candidates MUST include the full
    /// canonical antichain because a pre-join client cannot read the
    /// membership-gated frontier view.
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

    pub fn validate(&self) -> Result<()> {
        self.seal_basis.validate_protocol_bounds()?;
        if self.operations.is_empty()
            || !self
                .operations
                .iter()
                .any(|operation| operation == ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT)
            || self.join_methods.is_empty()
            || self.expires_at <= self.as_of
        {
            return Err(WireError::Protocol(
                "Realm join candidate has invalid operations, methods, basis, or lifetime"
                    .to_owned(),
            ));
        }
        let mut operations = self.operations.clone();
        operations.sort();
        operations.dedup();
        if operations.len() != self.operations.len() {
            return Err(WireError::Protocol(
                "Realm join candidate operations contain duplicates".to_owned(),
            ));
        }
        let methods = self.join_methods.iter().copied().collect::<BTreeSet<_>>();
        if methods.len() != self.join_methods.len() {
            return Err(WireError::Protocol(
                "Realm join candidate methods contain duplicates".to_owned(),
            ));
        }
        if self.source == RealmJoinCandidateSource::InviteHint && self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "invite-derived Realm join candidate requires a proof".to_owned(),
            ));
        }
        Ok(())
    }
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
    pub requester: Option<DidCoreId>,
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
    pub requester: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "openapi",
        salvo(schema(value_type = Vec<serde_json::Value>))
    )]
    pub claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl DirectoryResolveTargetRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        directory_proof_binding_bytes(
            ProofContextId::DIRECTORY_RESOLVE_TARGET_REQUEST_PROOF_V1,
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_TARGET,
            Some(directory_required_issuer(self.requester.as_ref())?),
            vec![("address", Value::String(self.address.clone()))],
            &self.payload_digest()?,
            proof,
        )
    }
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
    pub organization_principal_id: DidCoreId,
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
    pub organization_principal_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl DirectoryResolveOrganizationRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    /// This family has no originator wire field, so the binding object omits
    /// `issuer` and the signer identity is borne only by `verification_method`.
    /// Its resolution target is already fully covered by `payload_digest`, so no
    /// extra target member is added (`discovery-directory.md` §9.0.1).
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        directory_proof_binding_bytes(
            ProofContextId::DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1,
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION,
            None,
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }
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
    pub organization_principal_id: Option<DidCoreId>,
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
    pub actor_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_principal_id: Option<DidCoreId>,
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
    type Err = WireError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "lookup" => Ok(Self::Lookup),
            "mention" => Ok(Self::Mention),
            "invite" => Ok(Self::Invite),
            "member_add" => Ok(Self::MemberAdd),
            "contact_request" => Ok(Self::ContactRequest),
            other => Err(WireError::Protocol(format!(
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
    pub expected_principal_id: Option<DidCoreId>,
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
    pub requester: Option<DidCoreId>,
    /// Target Realm ID or inviting service DID the result must be bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Target Realm for membership-builder intents. Used by directory
    /// implementations to apply `delivery_binding_policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl DirectoryResolveHandleRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        directory_proof_binding_bytes(
            ProofContextId::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1,
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
            Some(directory_required_issuer(self.requester.as_ref())?),
            vec![("handle", Value::String(self.handle.clone()))],
            &self.payload_digest()?,
            proof,
        )
    }
}

/// Request body for `ak.find.directory.read.resolve_agent_selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResolveAgentSelectorRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub controller_handle: Handle,
    pub agent_slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_actor_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    pub intent: DirectoryIntent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub requester: DidCoreId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl DirectoryResolveAgentSelectorRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        directory_proof_binding_bytes(
            ProofContextId::DIRECTORY_RESOLVE_AGENT_SELECTOR_REQUEST_PROOF_V1,
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR,
            Some(serde_json::to_value(&self.requester)?),
            vec![
                (
                    "controller_handle",
                    serde_json::to_value(&self.controller_handle)?,
                ),
                ("agent_slug", Value::String(self.agent_slug.clone())),
            ],
            &self.payload_digest()?,
            proof,
        )
    }
}

/// Response body for `ak.find.directory.read.resolve_agent_selector`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAgentSelectorResolutionOutcome {
    pub controller_subject: DidCoreId,
    pub subject: DidCoreId,
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
            return Err(WireError::Protocol(
                "directory_agent_selector_resolution_outcome.verified must be true".to_owned(),
            ));
        }
        validate_agent_slug(&self.agent_slug)?;
        self.selector_claim.validate()?;
        if self.selector_claim.controller_subject != self.controller_subject {
            return Err(WireError::Protocol(
                "selector_claim.controller_subject must match response.controller_subject"
                    .to_owned(),
            ));
        }
        if self.selector_claim.subject != self.subject {
            return Err(WireError::Protocol(
                "selector_claim.subject must match response.subject".to_owned(),
            ));
        }
        if self.selector_claim.agent_slug != self.agent_slug {
            return Err(WireError::Protocol(
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
    pub subject: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl DirectoryListHandlesForSubjectRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        directory_proof_binding_bytes(
            ProofContextId::DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1,
            ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT,
            Some(directory_required_issuer(self.requester.as_ref())?),
            vec![("subject", serde_json::to_value(&self.subject)?)],
            &self.payload_digest()?,
            proof,
        )
    }
}

/// Canonical unsigned directory request: the top-level `proofs` member is
/// removed outright — never set to `null` — and every optional field that is
/// actually present is retained (`discovery-directory.md` §9.0.1).
fn directory_unsigned_request<T: Serialize>(request: &T) -> Result<Value> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            WireError::Protocol("directory request body must serialize as an object".to_owned())
        })?
        .remove("proofs");
    Ok(value)
}

fn directory_payload_digest(unsigned_request: &Value) -> Result<Hash> {
    Hash::new(arkret_canonical::canonical::canonical_sha256(
        unsigned_request,
    )?)
    .map_err(Into::into)
}

fn directory_required_issuer(requester: Option<&DidCoreId>) -> Result<Value> {
    let requester = requester.ok_or_else(|| {
        WireError::Protocol(
            "directory requester proof requires the object family's originator field".to_owned(),
        )
    })?;
    Ok(serde_json::to_value(requester)?)
}

/// Canonical directory requester-proof binding object
/// (`discovery-directory.md` §9.0.1).
///
/// `context` is the request family's own registered context, so a signature
/// valid for one family can never be accepted by another. `audience` is
/// mandatory and MUST be the target Directory `service_id` published by
/// `ak.find.directory.read.describe`, in single-valued `did_core_id` form;
/// `domain` and `proof_purpose` MUST be absent — `governance_authorization`
/// belongs to the §8.7.1 write surface only.
fn directory_proof_binding_bytes(
    context: &str,
    operation_id: &str,
    issuer: Option<Value>,
    targets: Vec<(&'static str, Value)>,
    payload_digest: &Hash,
    proof: &PayloadProof,
) -> Result<Vec<u8>> {
    proof.validate_production()?;
    if proof.proof_purpose.is_some() {
        return Err(WireError::Protocol(
            "directory requester proof must not carry proof_purpose".to_owned(),
        ));
    }
    if proof.domain.is_some() {
        return Err(WireError::Protocol(
            "directory requester proof must not carry domain".to_owned(),
        ));
    }
    if &proof.payload_digest != payload_digest {
        return Err(WireError::Protocol(
            "directory requester proof payload_digest mismatch".to_owned(),
        ));
    }
    let audience = proof.audience.as_ref().ok_or_else(|| {
        WireError::Protocol("directory requester proof requires audience".to_owned())
    })?;
    let Audience::Single(audience_value) = audience else {
        return Err(WireError::Protocol(
            "directory requester proof audience must be the single target Directory service DID"
                .to_owned(),
        ));
    };
    // Section 9.0.1 pins the target Directory service DID to the `service_id`
    // published by `ak.find.directory.read.describe`, which is a `did_core_id`.
    // The full `did:<method>:<msi>` form is not an accepted alternative: it
    // would produce different signed bytes and the mismatch is swallowed by the
    // section 9.2 indistinguishable rejection, so it fails closed here instead.
    DidCoreId::new(audience_value.as_str()).map_err(|_| {
        WireError::Protocol(
            "directory requester proof audience must be the target Directory service_id in \
             did_core_id form"
                .to_owned(),
        )
    })?;
    let mut binding = serde_json::Map::new();
    binding.insert("context".to_owned(), Value::String(context.to_owned()));
    binding.insert(
        "payload_digest".to_owned(),
        serde_json::to_value(payload_digest)?,
    );
    if let Some(issuer) = issuer {
        binding.insert("issuer".to_owned(), issuer);
    }
    binding.insert(
        "operation_id".to_owned(),
        Value::String(operation_id.to_owned()),
    );
    for (name, value) in targets {
        binding.insert(name.to_owned(), value);
    }
    binding.insert(
        "verification_method".to_owned(),
        serde_json::to_value(&proof.verification_method)?,
    );
    binding.insert(
        "created_at".to_owned(),
        Value::String(arkret_canonical::canonical::format_timestamp_canonical(
            proof.created_at,
        )),
    );
    binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
    Ok(arkret_canonical::canonical::canonical_json_bytes(
        &Value::Object(binding),
    )?)
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
    pub subscriber_principal_id: DidCoreId,
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
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub discovery_event: Event,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    pub principal_server_service_id: DidCoreId,
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

/// The only `proof_purpose` the §8.7.1 write surface admits
/// (`governance_authorization`). A single-variant closed enum, so any other
/// wire value fails closed at deserialization — before a verifier ever looks
/// at the signature.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryGovernanceProofPurpose {
    GovernanceAuthorization,
}

/// §8.7.1 governance proof for the directory write surface (`withdraw`,
/// `takedown_appeal`). Mirrors
/// `service-operation-dtos.schema.json#/$defs/DirectoryGovernanceProof`: the
/// generic non-Event detached-JWS proof leaf with the family's three choices
/// closed — `proof_purpose` MUST be `governance_authorization`, `audience`
/// MUST be the target Directory `service_id` as a single `did_core_id`, and
/// `domain` MUST be absent. `deny_unknown_fields` rejects any undeclared
/// member outright; the remaining semantic checks run in
/// [`Self::binding_bytes`] so no caller can assemble the signed transcript
/// for a non-conforming proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGovernanceProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub proof_purpose: DirectoryGovernanceProofPurpose,
    /// Target Directory `service_id` in `did_core_id` form. Typed `DidCoreId`
    /// so the full-DID, DID-URL and array shapes fail closed at
    /// deserialization (§8.7.1 audience shape paragraph).
    pub audience: DidCoreId,
    pub jws: String,
}

impl DirectoryGovernanceProof {
    /// Registered context stamped into every §8.7.1 binding object
    /// (`proof-context-registry.json` row
    /// `DirectoryGovernanceRequestProofV1`, whose `binding_fields` list is the
    /// field-name truth source this helper follows).
    pub const CONTEXT: &'static str = ProofContextId::DIRECTORY_GOVERNANCE_REQUEST_PROOF_V1;

    /// Canonical §8.7.1 binding-object bytes to verify the detached JWS
    /// against. Fails closed — before producing any transcript — unless the
    /// proof carries the production detached-JWS kind, a non-empty `jws`, and
    /// a `payload_digest` byte-identical to the recomputed digest of the
    /// closed request body without its top-level `governance_proof` member.
    /// (`proof_purpose` needs no check here: the closed
    /// [`DirectoryGovernanceProofPurpose`] enum makes any other value
    /// unrepresentable.)
    pub fn binding_bytes(
        &self,
        operation_id: &str,
        resource_id: &str,
        payload_digest: &Hash,
    ) -> Result<Vec<u8>> {
        if self.kind != proof_kind::DETACHED_JWS {
            return Err(WireError::Protocol(format!(
                "directory governance proof kind must be detached_jws, got {}",
                self.kind
            )));
        }
        if self.jws.is_empty() {
            return Err(WireError::Protocol(
                "directory governance proof jws must not be empty".to_owned(),
            ));
        }
        if &self.payload_digest != payload_digest {
            return Err(WireError::Protocol(
                "directory governance proof payload_digest mismatch".to_owned(),
            ));
        }
        let mut binding = serde_json::Map::new();
        binding.insert(
            "context".to_owned(),
            Value::String(Self::CONTEXT.to_owned()),
        );
        binding.insert(
            "payload_digest".to_owned(),
            serde_json::to_value(&self.payload_digest)?,
        );
        binding.insert(
            "operation_id".to_owned(),
            Value::String(operation_id.to_owned()),
        );
        binding.insert(
            "resource_id".to_owned(),
            Value::String(resource_id.to_owned()),
        );
        binding.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&self.verification_method)?,
        );
        binding.insert(
            "created_at".to_owned(),
            Value::String(arkret_canonical::canonical::format_timestamp_canonical(
                self.created_at,
            )),
        );
        binding.insert(
            "proof_purpose".to_owned(),
            serde_json::to_value(self.proof_purpose)?,
        );
        binding.insert("audience".to_owned(), serde_json::to_value(&self.audience)?);
        Ok(arkret_canonical::canonical::canonical_json_bytes(
            &Value::Object(binding),
        )?)
    }
}

/// Canonical unsigned §8.7.1 write request: the top-level `governance_proof`
/// member is removed outright — never set to `null` — and every optional
/// field that is actually present is retained (`discovery-directory.md`
/// §8.7.1).
fn directory_governance_unsigned_request<T: Serialize>(request: &T) -> Result<Value> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            WireError::Protocol(
                "directory governance request body must serialize as an object".to_owned(),
            )
        })?
        .remove("governance_proof");
    Ok(value)
}

/// `ak.find.directory.command.withdraw` request. Mirrors
/// `service-operation-dtos.schema.json#/$defs/DirectoryWithdrawRequestBody`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryWithdrawRequestBody {
    pub resource_id: String,
    pub governance_proof: DirectoryGovernanceProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
}

impl DirectoryWithdrawRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_governance_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.governance_proof.binding_bytes(
            ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
            &self.resource_id,
            &self.payload_digest()?,
        )
    }
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
#[serde(deny_unknown_fields)]
pub struct DirectoryTakedownAppealRequestBody {
    /// The operator `takedown_id` from the takedown notice
    /// (`takedown:<token>`).
    pub takedown_id: String,
    /// Realm/applet ak-id, actor DID, or handle the takedown targets.
    pub resource_id: String,
    pub appellant_actor_id: DidCoreId,
    /// `sha256:<hex>` digest of the appeal argument / evidence bundle.
    pub argument_digest: Hash,
    pub requested_outcome: DirectoryTakedownAppealOutcomeRequest,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Signature by the resource governance key or an authorized advocate.
    pub governance_proof: DirectoryGovernanceProof,
}

impl DirectoryTakedownAppealRequestBody {
    pub fn unsigned_payload(&self) -> Result<Value> {
        directory_governance_unsigned_request(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        directory_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.governance_proof.binding_bytes(
            ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
            &self.resource_id,
            &self.payload_digest()?,
        )
    }
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
    /// `discovery-directory.md` §9: `results[].principal_id` is conditional.
    /// the directory MAY omit it when the caller is not authorized to learn
    /// the subject DID (returning a handle / display preview only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<DidCoreId>,
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
    pub principal_id: DidCoreId,
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
    pub subject: DidCoreId,
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
                    return Err(WireError::Protocol(
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
    use arkret_wire::{DidCoreId, DidUrl, Hash, PayloadProof, SchemaId};
    use chrono::Utc;

    use super::DirectoryAgentSelectorResolutionOutcome;

    fn principal(_value: &str) -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
    }

    fn actor(_value: &str) -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
    }

    fn service(_value: &str) -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
    }

    fn selector_claim() -> AgentSelectorClaim {
        AgentSelectorClaim {
            schema: SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned(),
            controller_subject: principal("did:webvh:z6mkfixture:example.com:users:alice"),
            agent_slug: "summary".to_owned(),
            subject: principal("did:webvh:z6mkfixture:agent.example"),
            issuer: actor("did:webvh:z6mkfixture:example.com"),
            issuer_service_id: Some(service("did:webvh:z6mkfixture:example.com")),
            binding_state: HandleBindingState::Verified,
            visibility: HandleVisibility::Restricted,
            audience: Some("ak:realm:ASOikrLmQRDmUfDmMaw1Bx-NCkNptz9Sw2olIhr_M_23".to_owned()),
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

#[cfg(test)]
mod directory_requester_proof_binding_tests {
    use arkret_wire::{Audience, DidCoreId, DidUrl, Hash, PayloadProof};
    use chrono::Utc;

    use super::DirectoryResolveTargetRequestBody;

    fn body() -> DirectoryResolveTargetRequestBody {
        DirectoryResolveTargetRequestBody {
            address: "ak://realm/release".to_owned(),
            requester: Some(DidCoreId::new("ak:did_core:web:alice.example").unwrap()),
            proof_challenge: None,
            claim_presentations: Vec::new(),
            proofs: Vec::new(),
            token: None,
        }
    }

    fn proof(audience: Audience, payload_digest: Hash) -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:web:alice.example#key-1").unwrap(),
            payload_digest,
            created_at: Utc::now(),
            domain: None,
            audience: Some(audience),
            proof_purpose: None,
            jws: "aaa.bbb.ccc".to_owned(),
        }
    }

    /// `discovery-directory.md` §9.0.1 pins the binding `audience` to the target
    /// Directory `service_id` published by `ak.find.directory.read.describe`,
    /// which is a `did_core_id`. A full `did:<method>:<msi>` audience is not an
    /// accepted alternative shape: it would only surface as a signature
    /// mismatch that §9.2 collapses into an indistinguishable rejection, so the
    /// binding helper refuses to produce transcript bytes for it.
    #[test]
    fn audience_must_be_the_directory_service_id_in_core_form() {
        let body = body();
        let digest = body.payload_digest().unwrap();

        let core = proof(
            Audience::Single("ak:did_core:web:directory.example".to_owned()),
            digest.clone(),
        );
        body.proof_binding_bytes(&core)
            .expect("a did_core_id audience is the pinned form");

        let full = proof(
            Audience::Single("did:web:directory.example".to_owned()),
            digest.clone(),
        );
        body.proof_binding_bytes(&full)
            .expect_err("the full DID form MUST NOT be accepted as a second shape");

        let multiple = proof(
            Audience::Multiple(vec!["ak:did_core:web:directory.example".to_owned()]),
            digest,
        );
        body.proof_binding_bytes(&multiple)
            .expect_err("audience MUST be single valued");
    }
}

#[cfg(test)]
mod directory_governance_proof_tests {
    use arkret_wire::{AuditReasonText, DidCoreId, DidUrl, Hash, ServiceOperationId};
    use chrono::{TimeZone, Utc};
    use serde_json::{Value, json};

    use super::{
        DirectoryGovernanceProof, DirectoryGovernanceProofPurpose, DirectoryWithdrawRequestBody,
    };

    const DIRECTORY_SERVICE_ID: &str = "ak:did_core:web:directory.example";
    const VERIFICATION_METHOD: &str = "did:web:alice.example#governance-1";
    const RESOURCE_ID: &str = "ak:realm:AY0Z0alJlPB4P2wAIOCSTs_yNX_lm1mM5r3mhhQuKIFb";

    fn proof(payload_digest: Hash) -> DirectoryGovernanceProof {
        DirectoryGovernanceProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new(VERIFICATION_METHOD).unwrap(),
            payload_digest,
            created_at: Utc.timestamp_millis_opt(1_777_777_777_000).unwrap(),
            proof_purpose: DirectoryGovernanceProofPurpose::GovernanceAuthorization,
            audience: DidCoreId::new(DIRECTORY_SERVICE_ID).unwrap(),
            jws: "aaa..bbb".to_owned(),
        }
    }

    fn withdraw_body() -> DirectoryWithdrawRequestBody {
        let mut body = DirectoryWithdrawRequestBody {
            resource_id: RESOURCE_ID.to_owned(),
            governance_proof: proof(Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap()),
            reason: Some(AuditReasonText::new("offline").unwrap()),
            effective_at: None,
        };
        let digest = body.payload_digest().unwrap();
        body.governance_proof.payload_digest = digest;
        body
    }

    /// The binding object stamps the registered context and the seven
    /// `binding_fields` registered for the family
    /// (`security_strings.rs` `DirectoryGovernanceRequestProofV1` descriptor).
    #[test]
    fn binding_object_matches_the_registered_binding_fields() {
        let body = withdraw_body();
        let transcript: Value =
            serde_json::from_slice(&body.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(
            transcript["context"],
            Value::from(DirectoryGovernanceProof::CONTEXT)
        );
        assert_eq!(
            transcript["operation_id"],
            Value::from(ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW)
        );
        assert_eq!(transcript["resource_id"], Value::from(RESOURCE_ID));
        assert_eq!(transcript["verification_method"], VERIFICATION_METHOD);
        assert_eq!(transcript["proof_purpose"], "governance_authorization");
        assert_eq!(transcript["audience"], DIRECTORY_SERVICE_ID);
        let mut keys: Vec<String> = transcript
            .as_object()
            .unwrap()
            .keys()
            .map(ToOwned::to_owned)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "audience",
                "context",
                "created_at",
                "operation_id",
                "payload_digest",
                "proof_purpose",
                "resource_id",
                "verification_method",
            ]
        );
    }

    /// `operation_id` is stamped by the operation actually being served, so a
    /// signature valid for `withdraw` can never verify as `takedown_appeal`.
    #[test]
    fn withdraw_and_appeal_stamp_their_own_operation_id() {
        let body = withdraw_body();
        let proof = body.governance_proof.clone();
        let digest = body.payload_digest().unwrap();
        let withdraw_transcript: Value =
            serde_json::from_slice(&body.proof_binding_bytes().unwrap()).unwrap();
        let appeal_transcript: Value = serde_json::from_slice(
            &proof
                .binding_bytes(
                    ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
                    RESOURCE_ID,
                    &digest,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            withdraw_transcript["operation_id"],
            "ak.find.directory.command.withdraw"
        );
        assert_eq!(
            appeal_transcript["operation_id"],
            "ak.find.directory.command.takedown_appeal"
        );
    }

    /// The unsigned projection drops the whole `governance_proof` member (not
    /// just its `jws`) and keeps the remaining optional fields that are
    /// actually present.
    #[test]
    fn unsigned_payload_removes_governance_proof_and_keeps_present_optionals() {
        let body = withdraw_body();
        let unsigned = body.unsigned_payload().unwrap();
        assert!(unsigned.get("governance_proof").is_none());
        assert_eq!(unsigned["reason"], "offline");
        assert!(unsigned.get("effective_at").is_none());
    }

    /// Fail-closed semantic gates run before any transcript is produced. A
    /// wrong `proof_purpose` is unrepresentable — the closed
    /// `DirectoryGovernanceProofPurpose` enum rejects it at deserialization
    /// (covered by `wire_shape_is_closed`).
    #[test]
    fn binding_bytes_rejects_non_conforming_proofs() {
        let body = withdraw_body();
        let digest = body.payload_digest().unwrap();

        let mut wrong_kind = body.governance_proof.clone();
        wrong_kind.kind = "attached_jws".to_owned();
        wrong_kind
            .binding_bytes(
                ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
                RESOURCE_ID,
                &digest,
            )
            .expect_err("proof kind MUST be detached_jws");

        let mut empty_jws = body.governance_proof.clone();
        empty_jws.jws = String::new();
        empty_jws
            .binding_bytes(
                ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
                RESOURCE_ID,
                &digest,
            )
            .expect_err("jws MUST NOT be empty");

        let other_digest = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        body.governance_proof
            .binding_bytes(
                ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
                RESOURCE_ID,
                &other_digest,
            )
            .expect_err("payload_digest MUST be byte-identical to the recomputed digest");
    }

    /// §8.7.1 closes the wire shape: undeclared members (`domain` included),
    /// a wrong `proof_purpose`, and any `audience` shape other than a single
    /// `did_core_id` MUST fail deserialization.
    #[test]
    fn wire_shape_is_closed() {
        let base = json!({
            "kind": "detached_jws",
            "verification_method": VERIFICATION_METHOD,
            "payload_digest": format!("sha256:{}", "0".repeat(64)),
            "created_at": "2026-05-02T00:00:00.000Z",
            "proof_purpose": "governance_authorization",
            "audience": DIRECTORY_SERVICE_ID,
            "jws": "aaa..bbb",
        });
        serde_json::from_value::<DirectoryGovernanceProof>(base.clone())
            .expect("the closed shape deserializes");

        let mut with_domain = base.clone();
        with_domain["domain"] = json!("directory.example");
        serde_json::from_value::<DirectoryGovernanceProof>(with_domain)
            .expect_err("domain MUST be absent");

        let mut with_extra = base.clone();
        with_extra["challenge"] = json!("n-1");
        serde_json::from_value::<DirectoryGovernanceProof>(with_extra)
            .expect_err("undeclared members MUST be rejected");

        let mut wrong_purpose = base.clone();
        wrong_purpose["proof_purpose"] = json!("issuer_attestation");
        serde_json::from_value::<DirectoryGovernanceProof>(wrong_purpose)
            .expect_err("proof_purpose MUST be governance_authorization");

        let mut full_did_audience = base.clone();
        full_did_audience["audience"] = json!("did:web:directory.example");
        serde_json::from_value::<DirectoryGovernanceProof>(full_did_audience)
            .expect_err("the full DID form is not an accepted audience shape");

        let mut array_audience = base;
        array_audience["audience"] = json!([DIRECTORY_SERVICE_ID]);
        serde_json::from_value::<DirectoryGovernanceProof>(array_audience)
            .expect_err("audience MUST be single valued");
    }

    /// Byte-level KAT: the 6th directory proof-context vector from
    /// `fixtures/proof-context-transcript-fixture.json`
    /// (`ak.vector.proof_context.transcript.directory_governance_request.v1`).
    #[test]
    fn spec_vector_directory_governance_request_matches_byte_for_byte() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/proof-context-transcript-fixture.json")
                .expect("embedded fixture");
        let cases = fixture["cases"].as_array().expect("cases");
        let vector = cases
            .iter()
            .find(|case| {
                case["vector_id"].as_str()
                    == Some("ak.vector.proof_context.transcript.directory_governance_request.v1")
            })
            .expect("directory governance transcript vector");

        let proof: DirectoryGovernanceProof = serde_json::from_value(json!({
            "kind": "detached_jws",
            "verification_method": vector["binding_object"]["verification_method"],
            "payload_digest": vector["binding_object"]["payload_digest"],
            "created_at": vector["binding_object"]["created_at"],
            "proof_purpose": vector["binding_object"]["proof_purpose"],
            "audience": vector["binding_object"]["audience"],
            "jws": vector["detached_jws"],
        }))
        .expect("vector proof leaf fits the closed wire shape");

        // `canonical_sha256` already returns the typed `sha256:<hex>` form.
        let recomputed = arkret_canonical::canonical::canonical_sha256(&vector["unsigned_object"])
            .expect("unsigned digest");
        assert_eq!(
            recomputed,
            vector["unsigned_digest"].as_str().unwrap(),
            "SHA-256(JCS(request_without_governance_proof)) must match"
        );
        assert_eq!(
            proof.payload_digest.as_str(),
            vector["unsigned_digest"].as_str().unwrap()
        );

        let binding = proof
            .binding_bytes(
                vector["binding_object"]["operation_id"].as_str().unwrap(),
                vector["binding_object"]["resource_id"].as_str().unwrap(),
                &proof.payload_digest.clone(),
            )
            .expect("binding bytes");
        assert_eq!(
            binding,
            vector["binding_jcs"].as_str().unwrap().as_bytes(),
            "canonical binding object must be byte-identical to the spec vector"
        );

        // The vector signature is a real Ed25519 signature over
        // `signing_input_ascii` under the shared conformance test key.
        let public_key_bytes =
            arkret_canonical::base64url_decode(fixture["test_key"]["public_key"].as_str().unwrap())
                .expect("test key decode");
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(public_key_bytes.as_slice()).unwrap(),
        )
        .unwrap();
        let jws = vector["detached_jws"].as_str().unwrap();
        let (header_segment, signature_segment) = jws
            .split_once("..")
            .expect("detached JWS has an empty payload segment");
        let signing_input_ascii = vector["signing_input_ascii"].as_str().unwrap();
        assert!(
            signing_input_ascii.starts_with(header_segment),
            "the signing input starts with the protected header segment"
        );
        let signature_bytes =
            arkret_canonical::base64url_decode(signature_segment).expect("signature decode");
        let signature =
            ed25519_dalek::Signature::from_slice(&signature_bytes).expect("64-byte signature");
        use ed25519_dalek::Verifier as _;
        verifying_key
            .verify(signing_input_ascii.as_bytes(), &signature)
            .expect("vector signature verifies over the reconstructed signing input");
    }
}
