//! Transient Signal submission results.

use arkret_wire::{Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalSubmitOutcome {
    pub accepted: bool,
    pub realm_id: RealmId,
    pub envelope_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_recipient_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub server_received_at: Option<DateTime<Utc>>,
}
