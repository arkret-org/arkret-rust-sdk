//! Actor profile model.

use std::collections::BTreeMap;

use arkret_wire::{ActorKind, ActorProfileId, ActorStatus, BlobRef, CoreId, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfile {
    /// The object id.
    ///
    /// Absent on a create payload, and absent on a view synthesised from an
    /// account record that has no `ak.profile.create` behind it — an
    /// `event_derived` id exists only where an Event made it (spec
    /// `zh/models/common-fields.md` section 6.0). Present on every projected
    /// snapshot of a real profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ActorProfileId>,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub principal_id: CoreId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ActorStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<CoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<crate::PrincipalResolutionProjection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<CoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ActorProfile {
    pub const SCHEMA: &'static str = SchemaId::ACTOR_PROFILE_V1;
}
