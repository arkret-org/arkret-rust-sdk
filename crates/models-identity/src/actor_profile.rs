//! Actor profile model.

use std::collections::BTreeMap;
use std::ops::Deref;

use arkret_wire::{ActorKind, ActorProfileId, ActorStatus, BlobRef, DidCoreId, RealmId, SchemaId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de};
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
    pub principal_id: DidCoreId,
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
    pub accountable_principal_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<crate::PrincipalResolutionProjection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ActorProfile {
    pub const SCHEMA: &'static str = SchemaId::ACTOR_PROFILE_V1;
}

/// Actor Profile materialized from an accepted `ak.profile.create` lineage.
///
/// Create authoring deliberately uses [`ActorProfile`] because `id` is absent
/// until the Event ID is known. Account read/write outcomes use this wrapper so
/// an omitted create-derived ID or PCR Realm fails during deserialization
/// instead of leaking an authoring shape into an accepted projection.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct AccountMaterializedProfile(ActorProfile);

impl AccountMaterializedProfile {
    pub fn new(profile: ActorProfile) -> arkret_wire::Result<Self> {
        if profile.id.is_none() || profile.realm_id.is_none() {
            return Err(arkret_wire::Error::Protocol(
                "materialized account profile requires id and realm_id".to_owned(),
            ));
        }
        Ok(Self(profile))
    }

    pub fn into_inner(self) -> ActorProfile {
        self.0
    }
}

impl Deref for AccountMaterializedProfile {
    type Target = ActorProfile;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<ActorProfile> for AccountMaterializedProfile {
    type Error = arkret_wire::Error;

    fn try_from(profile: ActorProfile) -> Result<Self, Self::Error> {
        Self::new(profile)
    }
}

impl From<AccountMaterializedProfile> for ActorProfile {
    fn from(profile: AccountMaterializedProfile) -> Self {
        profile.into_inner()
    }
}

impl<'de> Deserialize<'de> for AccountMaterializedProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let profile = ActorProfile::deserialize(deserializer)?;
        Self::new(profile).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::AccountMaterializedProfile;

    fn profile_value() -> serde_json::Value {
        json!({
            "id": "ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
            "schema": "ak.schema.actor_profile.v1",
            "realm_id": "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD",
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "actor_kind": "user",
            "display_name": "Fixture User",
            "created_at": "2026-08-11T00:00:00.000Z"
        })
    }

    #[test]
    fn materialized_account_profile_requires_create_id_and_realm() {
        let profile: AccountMaterializedProfile =
            serde_json::from_value(profile_value()).expect("materialized profile");
        assert!(profile.id.is_some());
        assert!(profile.realm_id.is_some());

        let mut missing_id = profile_value();
        missing_id.as_object_mut().unwrap().remove("id");
        assert!(serde_json::from_value::<AccountMaterializedProfile>(missing_id).is_err());

        let mut missing_realm = profile_value();
        missing_realm.as_object_mut().unwrap().remove("realm_id");
        assert!(serde_json::from_value::<AccountMaterializedProfile>(missing_realm).is_err());
    }
}
