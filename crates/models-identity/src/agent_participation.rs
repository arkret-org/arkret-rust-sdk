//! Controller-owned Agent participation leaves shared by issuer metadata and governance.

use serde::{Deserialize, Serialize};

impl ParticipationBits {
    pub const NONE: Self = Self {
        message_creation_allowed: false,
        reaction_addition_allowed: false,
        reaction_removal_allowed: false,
        third_party_mention_delivery_allowed: false,
        acting_on_behalf_allowed: false,
    };

    pub const ALL: Self = Self {
        message_creation_allowed: true,
        reaction_addition_allowed: true,
        reaction_removal_allowed: true,
        third_party_mention_delivery_allowed: true,
        acting_on_behalf_allowed: true,
    };

    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            message_creation_allowed: self.message_creation_allowed
                && other.message_creation_allowed,
            reaction_addition_allowed: self.reaction_addition_allowed
                && other.reaction_addition_allowed,
            reaction_removal_allowed: self.reaction_removal_allowed
                && other.reaction_removal_allowed,
            third_party_mention_delivery_allowed: self.third_party_mention_delivery_allowed
                && other.third_party_mention_delivery_allowed,
            acting_on_behalf_allowed: self.acting_on_behalf_allowed
                && other.acting_on_behalf_allowed,
        }
    }

    #[must_use]
    pub fn is_subset_of(self, ceiling: Self) -> bool {
        (!self.message_creation_allowed || ceiling.message_creation_allowed)
            && (!self.reaction_addition_allowed || ceiling.reaction_addition_allowed)
            && (!self.reaction_removal_allowed || ceiling.reaction_removal_allowed)
            && (!self.third_party_mention_delivery_allowed
                || ceiling.third_party_mention_delivery_allowed)
            && (!self.acting_on_behalf_allowed || ceiling.acting_on_behalf_allowed)
    }
}

impl ParticipationScope {
    pub fn realm_id(&self) -> &arkret_wire::RealmId {
        match self {
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Strand { realm_id, .. } => realm_id,
        }
    }

    /// Stable account-data key used by participation projections.
    ///
    /// Each scope component remains a complete typed ID. Event-derived tokens
    /// must never be reduced to an untyped suffix in account-data authority
    /// keys.
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Realm { realm_id } => format!("realm:{realm_id}"),
            Self::Circle {
                realm_id,
                circle_id,
            } => format!("circle:{realm_id}:{circle_id}"),
            Self::Strand {
                realm_id,
                strand_id,
            } => format!("strand:{realm_id}:{strand_id}"),
        }
    }
}

/// Largest accepted version that can still be echoed into the next replace
/// request under the closed schema.
pub const MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION: u64 = i64::MAX as u64 - 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationNextReplaceInput {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "serde_helpers::participation_expected_version_decimal")]
    pub expected_version: u64,
}

pub mod serde_helpers {
    pub mod participation_expected_version_decimal {
        pub fn serialize<S: serde::Serializer>(
            value: &u64,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            if *value > super::super::MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION {
                return Err(serde::ser::Error::custom(
                    "participation replace version exhausted",
                ));
            }
            arkret_canonical::serde_helpers::nonnegative_int64_decimal::serialize(value, serializer)
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<u64, D::Error> {
            let value = arkret_canonical::serde_helpers::nonnegative_int64_decimal::deserialize(
                deserializer,
            )?;
            if value > super::super::MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION {
                return Err(serde::de::Error::custom(
                    "participation replace version exhausted",
                ));
            }
            Ok(value)
        }
    }
}

/// One controller-owned, versioned per-scope participation selection.
/// Governance and deployment ceilings are evaluated at action time and are
/// intentionally not copied into this authority record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationView {
    pub target_scope: ParticipationScope,
    pub selection: ParticipationBits,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "arkret_canonical::serde_helpers::nonnegative_int64_decimal")]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_replace_input: Option<ParticipationNextReplaceInput>,
}

impl AgentParticipationView {
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 || self.version > i64::MAX as u64 {
            return Err(
                "agent participation entry version is outside the replace echo range".to_owned(),
            );
        }
        let expected =
            (self.version <= MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION).then_some(self.version);
        if self
            .next_replace_input
            .as_ref()
            .map(|input| input.expected_version)
            != expected
        {
            return Err(
                "agent participation next_replace_input.expected_version must equal version"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentParticipationViewWire {
    target_scope: ParticipationScope,
    selection: ParticipationBits,
    #[serde(with = "arkret_canonical::serde_helpers::nonnegative_int64_decimal")]
    version: u64,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    next_replace_input: Option<ParticipationNextReplaceInput>,
}

impl<'de> Deserialize<'de> for AgentParticipationView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentParticipationViewWire::deserialize(deserializer)?;
        let entry = Self {
            target_scope: wire.target_scope,
            selection: wire.selection,
            version: wire.version,
            next_replace_input: wire.next_replace_input,
        };
        entry.validate().map_err(serde::de::Error::custom)?;
        Ok(entry)
    }
}

include!("generated/agent_participation_contracts.rs");
