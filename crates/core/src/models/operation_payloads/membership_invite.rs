use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::{deserialize_canonical_timestamp, serialize_canonical_timestamp};
use crate::*;

/// Canonical membership state for `ck.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_state`).
///
/// Distinct from [`super::MembershipState`] (the roster projection enum, which
/// only models the live `join`/`invite`/`knock` states): the FSM transition
/// payload additionally carries the terminal `leave`/`ban` states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MembershipPayloadState {
    Join,
    Invite,
    Knock,
    Leave,
    Ban,
}

/// Strong type for `ck.member.state` payloads
/// (`event-payload.schema.json#/$defs/membership_payload`).
///
/// `additionalProperties:false`: the removed `handle` / `from` keys that older
/// yougen call sites tried to emit are intentionally NOT representable here —
/// `handle` has no spec-legal home in this payload (the member identity is
/// carried by `actor_id`; handle evidence lives in signed `HandleClaim`
/// objects on the roster, not the durable membership event), and the FSM
/// `from` precondition is expressed via the operation `preconditions`/effect
/// `transition`, not the payload body.
///
/// Conditional required fields (schema `allOf`): when `membership == join`,
/// `realm_id` + `actor_id` + `delivery_status` are required; and additionally
/// when `delivery_status == routable`, `delivery_binding` is required. These
/// are enforced by [`MembershipPayload::to_value`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MembershipPayload {
    pub membership: MembershipPayloadState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<DeliveryStatus>,
    /// `member_delivery_binding` carried opaquely as a `Value`.
    ///
    /// NOTE: we intentionally do NOT type this as the SDK
    /// [`MemberDeliveryBinding`] struct: that struct models the `*_ref`
    /// fields (e.g. `service_acceptance_ref`) as the rich `EventRef`
    /// `{id, role, …}` object, whereas the spec
    /// `member_delivery_binding.service_acceptance_ref` is a bare
    /// `event_ref` string (`^ck:event:…$`). Routing a spec-correct binding
    /// through that struct fails to deserialize. The binding wire shape is
    /// validated by soland's `validate_payload` against the canonical schema;
    /// see the "real wire divergence" note in the migration spec. Producers
    /// build the binding `Value` directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_proofs: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_service_dids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `oneOf(event_ref | invite_id)` — both are opaque strings on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_ref: Option<String>,
}

impl MembershipPayload {
    /// Build a non-`join` transition payload (`invite`/`knock`/`leave`/`ban`).
    pub fn transition(
        membership: MembershipPayloadState,
        actor_id: Did,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership,
            strand_id: None,
            realm_id: None,
            actor_id: Some(actor_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_dids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    /// Build a `join` transition payload with the schema-required
    /// `realm_id` + `actor_id` + `delivery_status` fields.
    pub fn join(
        realm_id: RealmId,
        actor_id: Did,
        delivery_status: DeliveryStatus,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(realm_id),
            actor_id: Some(actor_id),
            delivery_status: Some(delivery_status),
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_dids: Vec::new(),
            reason: Some(reason.into()),
            invite_ref: None,
        }
    }

    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    pub fn with_delivery_binding(mut self, binding: Value) -> Self {
        self.delivery_binding = Some(binding);
        self
    }

    pub fn with_invite_ref(mut self, invite_ref: impl Into<String>) -> Self {
        self.invite_ref = Some(invite_ref.into());
        self
    }

    /// Validate the schema-level conditional required fields, then serialize.
    pub fn to_value(&self) -> Result<Value> {
        if self.membership == MembershipPayloadState::Join {
            if self.realm_id.is_none() || self.actor_id.is_none() || self.delivery_status.is_none()
            {
                return Err(Error::Protocol(
                    "membership_payload{join} requires realm_id, actor_id, delivery_status"
                        .to_owned(),
                ));
            }
            if self.delivery_status == Some(DeliveryStatus::Routable)
                && self.delivery_binding.is_none()
            {
                return Err(Error::Protocol(
                    "membership_payload{join,routable} requires delivery_binding".to_owned(),
                ));
            }
        }
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("membership payload serialize: {err}")))
    }
}

/// serde adapter that maps a `BTreeMap<String, Value>` to/from wire keys
/// carrying the mandatory `x_` extension prefix.
mod x_prefixed_map {
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<String, Value>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            let key = if k.starts_with("x_") {
                k.clone()
            } else {
                format!("x_{k}")
            };
            m.serialize_entry(&key, v)?;
        }
        m.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<String, Value>, D::Error> {
        let raw = BTreeMap::<String, Value>::deserialize(deserializer)?;
        Ok(raw
            .into_iter()
            .map(|(k, v)| (k.strip_prefix("x_").map(str::to_owned).unwrap_or(k), v))
            .collect())
    }
}

/// Directed-create form of `invite_payload`
/// (`event-payload.schema.json#/$defs/invite_payload`, anyOf branch that
/// requires `invitee + invite_delivery_target + introduction_evidence_digest
/// + expires_at`). Carried by `ck.invite.create`.
///
/// The schema allows `x_*` extension properties (patternProperties
/// `^x_[a-z][a-z0-9_]{0,63}$`) but is otherwise `additionalProperties:false`;
/// the typed `x_*` extensions (e.g. `x_role`) are carried in [`Self::extensions`]
/// and re-prefixed on serialize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct InviteCreatePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    pub invitee: Did,
    pub invite_delivery_target: InviteDeliveryTarget,
    pub introduction_evidence_digest: Hash,
    #[serde(
        serialize_with = "serialize_canonical_timestamp",
        deserialize_with = "deserialize_canonical_timestamp"
    )]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `x_*` extension properties (key is stored WITHOUT the `x_` prefix; the
    /// prefix is re-applied on serialize). e.g. `role` => wire `x_role`.
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten, default, with = "x_prefixed_map")]
    pub extensions: BTreeMap<String, Value>,
}

impl InviteCreatePayload {
    pub fn new(
        invite_id: InviteId,
        invitee: Did,
        invite_delivery_target: InviteDeliveryTarget,
        introduction_evidence_digest: Hash,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            invite_id: Some(invite_id),
            invitee,
            invite_delivery_target,
            introduction_evidence_digest,
            expires_at,
            reason: None,
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    pub fn from_wire_value(value: &Value) -> Result<Self> {
        schema::event_payload_validator_catalog()
            .validate_payload(events::kinds::EventKind::InviteCreate.as_str(), value)
            .map_err(|err| Error::Protocol(format!("invite create payload schema: {err}")))?;
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|err| Error::Protocol(format!("invite create payload decode: {err}")))?;
        payload.invite_delivery_target.validate()?;
        Ok(payload)
    }

    pub fn to_value(&self) -> Result<Value> {
        self.invite_delivery_target.validate()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite create payload serialize: {err}")))
    }
}

/// Reference-by-id form of `invite_payload` (anyOf branch requiring
/// `invite_id`). Carried by `ck.invite.accept` / `ck.invite.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InviteRefPayload {
    pub invite_id: InviteId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InviteRefPayload {
    pub fn new(invite_id: InviteId) -> Self {
        Self {
            invite_id,
            reason: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("invite ref payload serialize: {err}")))
    }
}

/// Flat-form payload for `ck.relation.create`
/// (`#/$defs/relation_create_payload`).
///
/// The spec `anyOf` allows either an embedded `{relation: <object_snapshot>}`
/// or the flat `{kind, from_ref, to_ref}` triple; this strong type models the
/// flat form (the only shape yougen constructs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RelationCreatePayload {
    /// Registered `relation_kind` (e.g. `ck.relation.parent_of`).
    pub kind: String,
    /// Source endpoint `object_ref` (canonical typed id / did / digest).
    pub from_ref: ObjectRef,
    /// Target endpoint `object_ref`.
    pub to_ref: ObjectRef,
    /// Optional lexical ordering rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
}

impl RelationCreatePayload {
    pub fn new(
        kind: impl Into<String>,
        from_ref: impl Into<ObjectRef>,
        to_ref: impl Into<ObjectRef>,
    ) -> Self {
        Self {
            kind: kind.into(),
            from_ref: from_ref.into(),
            to_ref: to_ref.into(),
            rank: None,
        }
    }

    pub fn with_rank(mut self, rank: impl Into<String>) -> Self {
        self.rank = Some(rank.into());
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("relation create payload serialize: {err}")))
    }
}
