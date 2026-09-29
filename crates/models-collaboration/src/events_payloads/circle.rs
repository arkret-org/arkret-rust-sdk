//! Circle event payloads.

use arkret_wire::ActorId;

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CircleCreatePayload {
    pub object: Circle,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_member_state_payload`.
///
/// The expected-value guard is tri-state: omission leaves legality to the
/// registered transition guard, null asserts that the
/// actor has no membership record yet, and a concrete state asserts that exact
/// current membership.
///
/// A `join` carries the producer-signed `parent_membership_revision`, the exact
/// typed revision of the member's current parent Realm `member_state` join;
/// every other transition forbids it (`zh/models/circle.md` section 9.1).
/// Deserialization enforces that conditional; a locally built value is checked
/// by [`CircleMemberStatePayload::validate`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "CircleMemberStatePayloadWire")]
pub struct CircleMemberStatePayload {
    pub circle_id: CircleId,
    pub member_id: ActorId,
    pub membership: CircleMembership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_membership_revision: Option<CurrentRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "WirePresence::is_missing")]
    pub expected_membership: WirePresence<CircleMembership>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CircleMemberStatePayloadWire {
    circle_id: CircleId,
    member_id: ActorId,
    membership: CircleMembership,
    #[serde(
        default,
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    parent_membership_revision: Option<CurrentRevision>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    effective_at: Option<DateTime<Utc>>,
    #[serde(default)]
    expected_membership: WirePresence<CircleMembership>,
}

impl TryFrom<CircleMemberStatePayloadWire> for CircleMemberStatePayload {
    type Error = WireError;

    fn try_from(value: CircleMemberStatePayloadWire) -> Result<Self> {
        let payload = Self {
            circle_id: value.circle_id,
            member_id: value.member_id,
            membership: value.membership,
            parent_membership_revision: value.parent_membership_revision,
            reason: value.reason,
            effective_at: value.effective_at,
            expected_membership: value.expected_membership,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl CircleMemberStatePayload {
    /// `parent_membership_revision` is present exactly on `membership=join`.
    pub fn validate(&self) -> Result<()> {
        validate_parent_membership_revision(
            self.membership == CircleMembership::Join,
            self.parent_membership_revision.is_some(),
        )
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CirclePatchPayload {
    pub circle_id: CircleId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}
