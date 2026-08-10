//! Closed selector used by capability and widget token scopes.
//!
//! Relocated from `arkret-models-collaboration` (`governance::resource_selector`)
//! so both the collaboration governance surface and the integration applet
//! surface can name it within the frozen layering. It is a cross-domain wire
//! vocabulary of the same nature as `consent_scope`.

use serde::{Deserialize, Serialize, de};

use crate::{
    BlobRef, CircleId, DidCoreId, Error, EventId, InviteId, MessageId, MorphId, PolicyId, RealmId,
    RelationId, Result, SpaceId, StrandId, ViewId,
};

/// Opaque object reference wire scalar (`ak:object:...` and friends).
pub type ObjectRef = String;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelectorKind {
    Realm,
    Space,
    Circle,
    Strand,
    Message,
    Morph,
    Object,
    Relation,
    View,
    Event,
    Actor,
    Schema,
    Policy,
    Invite,
    Notification,
    ReadCursor,
    Blob,
    #[serde(rename = "*")]
    All,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMatchScope {
    Exact,
    Subtree,
    Children,
    RealmWide,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WireResourceSelector {
    pub kind: ResourceSelectorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_id: Option<MorphId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_ref: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_scope: Option<ResourceMatchScope>,
}

impl WireResourceSelector {
    fn for_kind(kind: ResourceSelectorKind, realm_id: Option<RealmId>) -> Self {
        Self {
            kind,
            realm_id,
            space_id: None,
            circle_id: None,
            object_kind: None,
            object_ref: None,
            strand_id: None,
            message_id: None,
            morph_id: None,
            morph_kind: None,
            relation_kind: None,
            relation_id: None,
            view_id: None,
            event_id: None,
            actor_id: None,
            schema_ref: None,
            policy_id: None,
            invite_id: None,
            blob_ref: None,
            match_scope: None,
        }
    }

    pub fn realm(realm_id: RealmId) -> Self {
        Self::for_kind(ResourceSelectorKind::Realm, Some(realm_id))
    }

    pub fn space(realm_id: RealmId, space_id: SpaceId) -> Self {
        let mut selector = Self::for_kind(ResourceSelectorKind::Space, Some(realm_id));
        selector.space_id = Some(space_id);
        selector
    }

    pub fn circle(realm_id: RealmId, circle_id: CircleId) -> Self {
        let mut selector = Self::for_kind(ResourceSelectorKind::Circle, Some(realm_id));
        selector.circle_id = Some(circle_id);
        selector
    }

    pub fn strand(realm_id: RealmId, strand_id: StrandId) -> Self {
        let mut selector = Self::for_kind(ResourceSelectorKind::Strand, Some(realm_id));
        selector.strand_id = Some(strand_id);
        selector
    }

    pub fn validate(&self) -> Result<()> {
        let realm_scoped = matches!(
            self.kind,
            ResourceSelectorKind::Space
                | ResourceSelectorKind::Circle
                | ResourceSelectorKind::Strand
                | ResourceSelectorKind::Message
                | ResourceSelectorKind::Morph
                | ResourceSelectorKind::Object
                | ResourceSelectorKind::Relation
                | ResourceSelectorKind::View
                | ResourceSelectorKind::Event
                | ResourceSelectorKind::Policy
                | ResourceSelectorKind::Invite
                | ResourceSelectorKind::Notification
                | ResourceSelectorKind::ReadCursor
        );
        if realm_scoped && self.realm_id.is_none() {
            return Err(Error::Protocol(
                "realm-scoped resource selector requires realm_id".to_owned(),
            ));
        }
        if self.kind == ResourceSelectorKind::Actor && self.actor_id.is_none() {
            return Err(Error::Protocol(
                "actor resource selector requires actor_id".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceSelectorWire {
    kind: ResourceSelectorKind,
    #[serde(default)]
    realm_id: Option<RealmId>,
    #[serde(default)]
    space_id: Option<SpaceId>,
    #[serde(default)]
    circle_id: Option<CircleId>,
    #[serde(default)]
    object_kind: Option<String>,
    #[serde(default)]
    object_ref: Option<ObjectRef>,
    #[serde(default)]
    strand_id: Option<StrandId>,
    #[serde(default)]
    message_id: Option<MessageId>,
    #[serde(default)]
    morph_id: Option<MorphId>,
    #[serde(default)]
    morph_kind: Option<String>,
    #[serde(default)]
    relation_kind: Option<String>,
    #[serde(default)]
    relation_id: Option<RelationId>,
    #[serde(default)]
    view_id: Option<ViewId>,
    #[serde(default)]
    event_id: Option<EventId>,
    #[serde(default)]
    actor_id: Option<DidCoreId>,
    #[serde(default)]
    schema_ref: Option<String>,
    #[serde(default)]
    policy_id: Option<PolicyId>,
    #[serde(default)]
    invite_id: Option<InviteId>,
    #[serde(default)]
    blob_ref: Option<BlobRef>,
    #[serde(default)]
    match_scope: Option<ResourceMatchScope>,
}

impl<'de> Deserialize<'de> for WireResourceSelector {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResourceSelectorWire::deserialize(deserializer)?;
        let selector = Self {
            kind: wire.kind,
            realm_id: wire.realm_id,
            space_id: wire.space_id,
            circle_id: wire.circle_id,
            object_kind: wire.object_kind,
            object_ref: wire.object_ref,
            strand_id: wire.strand_id,
            message_id: wire.message_id,
            morph_id: wire.morph_id,
            morph_kind: wire.morph_kind,
            relation_kind: wire.relation_kind,
            relation_id: wire.relation_id,
            view_id: wire.view_id,
            event_id: wire.event_id,
            actor_id: wire.actor_id,
            schema_ref: wire.schema_ref,
            policy_id: wire.policy_id,
            invite_id: wire.invite_id,
            blob_ref: wire.blob_ref,
            match_scope: wire.match_scope,
        };
        selector.validate().map_err(de::Error::custom)?;
        Ok(selector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_rejects_missing_conditional_fields_and_unknown_fields() {
        assert!(serde_json::from_str::<WireResourceSelector>(r#"{"kind":"message"}"#).is_err());
        assert!(serde_json::from_str::<WireResourceSelector>(r#"{"kind":"actor"}"#).is_err());
        assert!(
            serde_json::from_str::<WireResourceSelector>(r#"{"kind":"*","unknown":true}"#).is_err()
        );
    }
}
