//! Closed selector used by capability and widget token scopes.

use serde::de;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ResourceMatchScope {
    Exact,
    Subtree,
    Children,
    RealmWide,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WireResourceSelector {
    pub kind: ResourceSelectorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_id: Option<MorphId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morph_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_id: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
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
    object_type: Option<String>,
    #[serde(default)]
    object_ref: Option<ObjectRef>,
    #[serde(default)]
    strand_id: Option<StrandId>,
    #[serde(default)]
    message_id: Option<MessageId>,
    #[serde(default)]
    morph_id: Option<MorphId>,
    #[serde(default)]
    morph_type: Option<String>,
    #[serde(default)]
    relation_kind: Option<String>,
    #[serde(default)]
    relation_id: Option<RelationId>,
    #[serde(default)]
    view_id: Option<ViewId>,
    #[serde(default)]
    event_id: Option<EventId>,
    #[serde(default)]
    actor_id: Option<Did>,
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
            object_type: wire.object_type,
            object_ref: wire.object_ref,
            strand_id: wire.strand_id,
            message_id: wire.message_id,
            morph_id: wire.morph_id,
            morph_type: wire.morph_type,
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
