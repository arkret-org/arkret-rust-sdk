//! Consent event payloads.

use arkret_wire::ConsentScope;

use crate::account_lifecycle::ConsentPeer;
use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/consent_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantPayload {
    pub consent_id: ConsentId,
    pub peer: ConsentPeer,
    pub consent_scope: ConsentScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
