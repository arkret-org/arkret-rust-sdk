//! Federation transaction / push / pull operation bodies.
//!
//! These wire DTOs bind [`Operation`], the SDK-local draft record owned by
//! this crate, so they cannot live in the model layer (the model crates must
//! not depend on `arkret-event-draft`). They stay here alongside `Operation`.
//! The realm-membership listing and actor-verification DTOs live in
//! `arkret-models-collaboration` (`federation::wire_dtos`).

use arkret_models_collaboration::http_bodies::EventsSubmitRejectedItem;
use arkret_models_collaboration::sync_frames::snapshot::SnapshotBootstrap;
use arkret_wire::{Did, EventBatchReceipt, OperationId, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Operation;

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationTransactionRequestBody {
    pub origin: Did,
    pub destination: Did,
    pub service_binding_ref: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub receipts: Vec<EventBatchReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationTransactionOutcome {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub historical_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_outcome: Option<Box<FederationTransactionOutcome>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPushOperationsRequestBody {
    pub origin: Did,
    pub destination: Did,
    pub realm_id: RealmId,
    pub service_binding_ref: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub operations: Vec<Operation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPushOperationsOutcome {
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<OperationId>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationPullOperationsOutcome {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}
