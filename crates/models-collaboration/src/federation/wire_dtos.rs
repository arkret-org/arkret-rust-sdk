//! Federation realm-membership and actor-verification wire DTOs.
//!
//! Transaction / push / pull bodies that bind
//! `arkret_event_draft::Operation` are owned by `arkret-event-draft`, which
//! keeps this model crate free of behavior dependencies.

use arkret_wire::{Did, Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::federation::frames::VerifyActorChallengeSignature;
use crate::sync_frames::account_sync::MembershipState;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationRealmMemberList {
    #[serde(default)]
    pub members: Vec<MemberRef>,
    pub membership_frontier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberRef {
    pub principal_id: Did,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub membership: MembershipState,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorRequestBody {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_payload_digest: Option<Hash>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub signature: VerifyActorChallengeSignature,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorOutcome {
    pub valid: bool,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub warnings: Vec<String>,
}
