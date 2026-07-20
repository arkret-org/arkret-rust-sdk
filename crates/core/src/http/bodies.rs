//! HTTP JSON request/outcome DTOs retained by `arkret-core`.
//!
//! The events/projection/blob/MIMI bodies migrated to
//! `arkret-models-collaboration`, the key-package and key-backup bodies to
//! `arkret-models-crypto`, the private-contact-discovery and service-describe
//! bodies to `arkret-models-discovery`, the applet third-party lookups to
//! `arkret-models-integration`, and the identity/account request bodies and
//! identity-describe outcome wrappers to `arkret-models-identity` (all
//! re-exported below). This module keeps only the DTOs still bound to
//! core-resident model types (`SnapshotBootstrap`, `ContactIntroductionEvidence`,
//! `PublicKey`/`DeviceMetadata`, `GrantSnapshot`, `BlobUploadMetadata`,
//! `GrantList`) until those types land in the model crates.

use std::collections::BTreeMap;

pub use arkret_models_collaboration::http_bodies::*;
// Session-grant request/outcome DTO family migrated to
// `arkret-models-collaboration` (phase 5 http-face batch 0f). Re-exported so
// the `arkret_core::SessionGrant*` paths and the Salvo OpenAPI bindings stay
// stable.
pub use arkret_models_collaboration::session_grant_bodies::*;
pub use arkret_models_crypto::http_bodies::*;
pub use arkret_models_discovery::http_bodies::*;
// Identity/account request bodies and identity-describe outcome wrappers
// migrated to `arkret-models-identity` (phase 5 http-face batch 0g).
pub use arkret_models_identity::http_bodies::*;
pub use arkret_models_integration::http_bodies::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsQueryOutcome {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range_completeness: Option<EventsRangeCompleteness>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactRequestRequestBody {
    pub target: Did,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Cross-Principal-Server addressing (spec contact-and-direct-conversation.md
    /// §4.1): when `target` is hosted on a different Principal Server, the
    /// requester MUST supply the target's home service DID so the issuer-side
    /// server can federate the signed `ak.contact.requested` fact via
    /// `ak.peer.contacts.command.submit`. Omit for same-server requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction_evidence: Option<ContactIntroductionEvidence>,
}

// ContactListQuery / ContactList bind to the core-resident `Cursor`
// (`arkret_hlc::Cursor`, re-exported at the core root), which the model crates
// cannot reach without a forbidden hlc edge. They stay here until Cursor is
// rehomed; the contact directory row/state types they reference live in
// `arkret-models-collaboration` and reach these definitions via the glob
// re-export above.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    feature = "salvo",
    derive(salvo::oapi::ToParameters, salvo::oapi::ToSchema)
)]
pub struct ContactListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub cursor: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(parameter(parameter_in = Query)))]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContactList {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: NonEmptyString,
    pub new_device_pubkey: PublicKey,
    pub challenge_signature: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_grant: Option<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_hint: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = BlobUploadMetadata)))]
pub struct BlobUploadRequestBody(pub BlobUploadMetadata);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = GrantList)))]
pub struct GrantListOutcome(pub GrantList);
