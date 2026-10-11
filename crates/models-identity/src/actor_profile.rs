//! Actor profile model.

use std::collections::BTreeMap;
use std::ops::Deref;

use arkret_wire::{
    ActorId, ActorKind, ActorProfileId, BlobRef, DidCoreId, RealmId, SchemaId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<crate::PrincipalResolutionProjection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ActorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl ActorProfile {
    pub const SCHEMA: &'static str = SchemaId::ACTOR_PROFILE_V1;

    /// The `ak.profile.create` result projection: the author's closed
    /// definition plus the registered create-lock derivations
    /// (`object_schema_identifier`, `object_realm_binding`,
    /// `object_create_time`). A create has not been updated, so the update
    /// members stay absent.
    pub fn materialize_create(
        definition: ActorProfileDefinition,
        id: ActorProfileId,
        realm_id: RealmId,
        created_at: DateTime<Utc>,
    ) -> arkret_wire::Result<Self> {
        definition.validate()?;
        Ok(Self {
            id: Some(id),
            schema: Self::SCHEMA.to_owned(),
            realm_id: Some(realm_id),
            principal_id: definition.principal_id,
            actor_kind: definition.actor_kind,
            display_name: definition.display_name,
            handle: definition.handle,
            agent_slug: definition.agent_slug,
            avatar_blob_ref: definition.avatar_blob_ref,
            accountable_principal_ids: definition.accountable_principal_ids,
            resolution: None,
            profile_fields: definition.profile_fields,
            created_at,
            updated_by: None,
            updated_at: None,
        })
    }

    /// Validate the display members every materialized value must satisfy
    /// (`actor-profile.schema.json`).
    pub fn validate_display_members(&self) -> arkret_wire::Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(
                "actor profile schema must be ak.schema.actor_profile.v1".to_owned(),
            ));
        }
        validate_display_members(
            self.actor_kind,
            &self.display_name,
            self.handle.as_deref(),
            self.agent_slug.as_deref(),
            &self.profile_fields,
        )
    }
}

/// The closed author region of `ak.profile.create`
/// (`actor-profile.schema.json#/$defs/actor_profile_definition`).
///
/// `schema`, `realm_id`, `created_at`, `updated_by` and `updated_at` are
/// reducer derivations and `id`/`resolution` are never authored, so none of
/// them is representable here. `principal_id` and `actor_kind` are author
/// input and create-locked afterwards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileDefinition {
    pub principal_id: DidCoreId,
    pub actor_kind: ActorKind,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
}

impl ActorProfileDefinition {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        validate_display_members(
            self.actor_kind,
            &self.display_name,
            self.handle.as_deref(),
            self.agent_slug.as_deref(),
            &self.profile_fields,
        )
    }
}

const PROFILE_TEXT_FIELD_MAX: usize = 256;

fn validate_display_members(
    actor_kind: ActorKind,
    display_name: &str,
    handle: Option<&str>,
    agent_slug: Option<&str>,
    profile_fields: &BTreeMap<String, Value>,
) -> arkret_wire::Result<()> {
    arkret_wire::validate_single_line_display_text(display_name, 128)?;
    if let Some(handle) = handle {
        arkret_wire::validate_canonical_handle(handle)?;
    }
    if let Some(agent_slug) = agent_slug {
        if actor_kind != ActorKind::Agent {
            return Err(WireError::Protocol(
                "agent_slug is only valid on an actor_kind=agent profile".to_owned(),
            ));
        }
        crate::claim_presentation::validate_agent_slug(agent_slug)?;
    }
    if let Some(value) = profile_fields.get("applet_interaction") {
        if !matches!(actor_kind, ActorKind::Bot | ActorKind::Integration) {
            return Err(WireError::Protocol(
                "applet_interaction requires a managed Bot or Ghost profile".into(),
            ));
        }
        let intent: AppletInteractionIntent = serde_json::from_value(value.clone())?;
        if intent.effective_scope.realm_id_opt().is_none() {
            return Err(WireError::Protocol(
                "Applet interaction intent needs business scope".into(),
            ));
        }
    }
    for member in ["bio", "status_message"] {
        match profile_fields.get(member) {
            None => {}
            Some(Value::String(text)) if text.chars().count() <= PROFILE_TEXT_FIELD_MAX => {}
            Some(_) => {
                return Err(WireError::Protocol(format!(
                    "profile_fields.{member} must be a string of at most \
                     {PROFILE_TEXT_FIELD_MAX} code points"
                )));
            }
        }
    }
    Ok(())
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
            return Err(WireError::Protocol(
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
    type Error = WireError;

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
    fn definition_is_the_closed_author_region() {
        let definition: super::ActorProfileDefinition = serde_json::from_value(json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "actor_kind": "user",
            "display_name": "Fixture User"
        }))
        .expect("author region");
        definition.validate().unwrap();
        for member in [
            ("schema", json!("ak.schema.actor_profile.v1")),
            (
                "realm_id",
                json!("ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD"),
            ),
            ("created_at", json!("2026-08-11T00:00:00.000Z")),
            (
                "id",
                json!("ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-"),
            ),
            ("status", json!("active")),
        ] {
            let mut value = serde_json::to_value(&definition).unwrap();
            value[member.0] = member.1;
            assert!(
                serde_json::from_value::<super::ActorProfileDefinition>(value).is_err(),
                "{} is not author input",
                member.0
            );
        }
        let mut slug = definition;
        slug.agent_slug = Some("summary".to_owned());
        assert!(
            slug.validate().is_err(),
            "agent_slug requires actor_kind=agent"
        );
        assert!(
            serde_json::from_value::<super::ActorProfile>(json!({
                "schema": "ak.schema.actor_profile.v1",
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "actor_kind": "user",
                "display_name": "Fixture User",
                "status": "active",
                "created_at": "2026-08-11T00:00:00.000Z"
            }))
            .is_err()
        );
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

/// Subject-original public/private intent. Management policy is evaluated separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInteractionIntent {
    pub effective_scope: arkret_wire::ScopeRef,
    pub mode: AppletInteractionMode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletInteractionMode {
    Private,
    Public,
}
