//! Federation realm-membership and actor-verification wire DTOs.
//!
//! Transaction / push / pull bodies that bind
//! `arkret_event_draft::ProjectedEventOperation` are owned by `arkret-event-draft`, which
//! keeps this model crate free of behavior dependencies.

use arkret_wire::{DidCoreId, Hash, RealmId};
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
    pub principal_id: DidCoreId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub membership: MembershipState,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorRequestBody {
    pub actor_id: DidCoreId,
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

impl FederationVerifyActorRequestBody {
    pub fn actor_signature_transcript_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        let mut unsigned = serde_json::to_value(self)?;
        let object = unsigned.as_object_mut().ok_or_else(|| {
            arkret_canonical::CanonicalError::Protocol(
                "federation verify-actor request must serialize as an object".to_owned(),
            )
        })?;
        object.remove("signature");
        let request_binding_digest = arkret_canonical::canonical_sha256(&unsigned)?;
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "type": "ak.federation.verify_actor.signature.v1",
            "actor_id": self.actor_id.as_str(),
            "purpose": self.purpose,
            "challenge": self.challenge,
            "signed_payload_digest": self.signed_payload_digest.as_ref().map(|value| value.as_str()),
            "realm_id": self.realm_id.as_ref().map(|value| value.as_str()),
            "request_binding_digest": request_binding_digest,
        }))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationVerifyActorOutcome {
    pub valid: bool,
    pub actor_id: DidCoreId,
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
