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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionRequestBody {
    pub origin: Did,
    pub destination: Did,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<EventBatchReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionOutcome {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub historical_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_outcome: Option<Box<FederationTransactionOutcome>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsRequestBody {
    pub origin: Did,
    pub destination: Did,
    pub realm_id: RealmId,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsOutcome {
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<EventsSubmitRejectedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<OperationId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct FederationPullOperationsOutcome {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}
