//! Directory handle-resolution DTOs retained by `arkret-core`.
//!
//! The directory search/resolve/announce/push/takedown DTOs migrated to
//! `arkret-models-discovery`; the claim-presentation and agent-selector
//! claim shapes migrated to `arkret-models-identity` (both re-exported
//! below). The handle-resolution and user-search outcome DTOs stay here
//! because they embed `HandleClaim` / `DeliveryBindingHint` from
//! `arkret-models-collaboration`, which `arkret-models-discovery` must
//! not depend on.

pub use arkret_models_discovery::directory::*;
pub use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, validate_agent_slug,
};

use super::*;

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
pub struct DirectoryHandleResolutionOutcome {
    pub did: Did,
    pub handle: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<HandleClaim>>,
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

/// R3.2 — response body for `ak.find.directory.query.list_handles_for_subject`.
/// Schema `ak.schema.list_handles_for_subject_response.v1`. Every
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
