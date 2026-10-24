//! AKP-0010 — Agent participation policy.
//!
//! Five orthogonal autonomous-behavior bits an Agent's
//! controller may enable in a scope, each capped by a monotone
//! `deployment ⊇ Realm ⊇ Circle ⊇ Strand` ceiling. The effective
//! participation in a scope is `effective_ceiling ∩ controller_selection`,
//! where `effective_ceiling` is the bitwise AND of every enclosing
//! level's ceiling (AKP-0010 §3–§5).
//!
//! Participation is an additional execution gate, never a capability grant.
//! An action is allowed only when ordinary capability/lifecycle checks pass
//! and the current selection/ceiling intersection enables its bit.

use arkret_wire::{CircleId, RealmId, StrandId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationBits {
    pub message_creation_allowed: bool,
    pub reaction_addition_allowed: bool,
    pub reaction_removal_allowed: bool,
    pub third_party_mention_delivery_allowed: bool,
    pub acting_on_behalf_allowed: bool,
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ParticipationScope {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
    Strand {
        realm_id: RealmId,
        strand_id: StrandId,
    },
}

impl ParticipationScope {
    pub fn realm_id(&self) -> &RealmId {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplaceRequestBody {
    pub target_scope: ParticipationScope,
    pub selection: ParticipationBits,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "participation_expected_version_decimal")]
    pub expected_version: u64,
}

/// Governance object shape used by Realm, Circle and Strand schemas.
/// Agent permissions are explicitly namespaced so future
/// applet-agent policy cannot be confused with this ceiling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<ParticipationBits>,
}

/// Error surfaced by the reducer-pure participation validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentParticipationError {
    /// An inner-scope ceiling enables a bit its parent ceiling disables.
    #[error(
        "reason=agent_participation_ceiling_widen: child {child:?} widens parent ceiling {parent:?}"
    )]
    CeilingWiden {
        parent: ParticipationBits,
        child: ParticipationBits,
    },
}

/// Reducer-pure validator (AKP-0010 §3 invariant 1): an inner scope's
/// participation ceiling MAY only tighten (drop bits from) its parent
/// ceiling, never widen it. Returns `Ok(())` iff `child ⊆ parent`.
pub fn validate_agent_participation_tightens(
    parent: ParticipationBits,
    child: ParticipationBits,
) -> Result<(), AgentParticipationError> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(AgentParticipationError::CeilingWiden { parent, child })
    }
}

/// Validate a partial child ceiling declaration against its parent and
/// return the materialized child ceiling.
pub fn validate_agent_participation_ceiling_tightens(
    parent: ParticipationBits,
    child: ParticipationBits,
) -> Result<ParticipationBits, AgentParticipationError> {
    validate_agent_participation_tightens(parent, child)?;
    Ok(child)
}

/// Fold a ceiling chain by intersection, seeded with [`ParticipationBits::ALL`].
/// Because invariant 1 already guarantees monotone tightening, this is
/// equivalent to taking the innermost explicit value, but folding by AND
/// is fail-closed against historically non-conforming data (AKP-0010 §4.4).
pub fn fold_ceiling_chain<I>(chain: I) -> ParticipationBits
where
    I: IntoIterator<Item = ParticipationBits>,
{
    chain
        .into_iter()
        .fold(ParticipationBits::ALL, |acc, c| acc.intersect(c))
}

/// Effective participation = effective ceiling ∩ controller selection
/// (AKP-0010 §2).
#[must_use]
pub fn effective_participation(
    ceiling: ParticipationBits,
    selection: ParticipationBits,
) -> ParticipationBits {
    ceiling.intersect(selection)
}

/// Largest accepted version that can still be echoed into the next replace
/// request under the closed schema.
pub const MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION: u64 = i64::MAX as u64 - 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationNextReplaceInput {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "participation_expected_version_decimal")]
    pub expected_version: u64,
}

mod participation_expected_version_decimal {
    pub fn serialize<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if *value > super::MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION {
            return Err(serde::ser::Error::custom(
                "participation replace version exhausted",
            ));
        }
        arkret_canonical::serde_helpers::nonnegative_int64_decimal::serialize(value, serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value =
            arkret_canonical::serde_helpers::nonnegative_int64_decimal::deserialize(deserializer)?;
        if value > super::MAX_PARTICIPATION_REPLACE_EXPECTED_VERSION {
            return Err(serde::de::Error::custom(
                "participation replace version exhausted",
            ));
        }
        Ok(value)
    }
}

/// One controller-owned, versioned per-scope participation selection.
/// Governance and deployment ceilings are evaluated at action time and are
/// intentionally not copied into this authority record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentParticipationEntry {
    #[serde(rename = "target_scope")]
    pub scope: ParticipationScope,
    pub selection: ParticipationBits,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    #[serde(with = "arkret_canonical::serde_helpers::nonnegative_int64_decimal")]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_replace_input: Option<ParticipationNextReplaceInput>,
}

impl AgentParticipationEntry {
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
struct AgentParticipationEntryWire {
    #[serde(rename = "target_scope")]
    scope: ParticipationScope,
    selection: ParticipationBits,
    #[serde(with = "arkret_canonical::serde_helpers::nonnegative_int64_decimal")]
    version: u64,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    next_replace_input: Option<ParticipationNextReplaceInput>,
}

impl<'de> Deserialize<'de> for AgentParticipationEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentParticipationEntryWire::deserialize(deserializer)?;
        let entry = Self {
            scope: wire.scope,
            selection: wire.selection,
            version: wire.version,
            next_replace_input: wire.next_replace_input,
        };
        entry.validate().map_err(serde::de::Error::custom)?;
        Ok(entry)
    }
}

/// An observation from one exact authenticated Agent session. This local
/// value is never a participation-current verdict or a wire carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentParticipationObservation {
    pub agent_account: arkret_wire::AccountId,
    pub controller_account: arkret_wire::AccountId,
    pub grant_id: arkret_wire::SessionGrantId,
    pub agent_key_authorization_ref: arkret_wire::EventId,
    pub verification_method: arkret_wire::DidUrl,
    pub session_id: String,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub entries: Vec<AgentParticipationEntry>,
}

impl AgentParticipationObservation {
    /// The caller authenticates the exact session claims before using this
    /// helper. Claim parsing alone does not authenticate an issuer.
    pub fn from_authenticated_claims(
        claims: &arkret_models_identity::SignedSessionGrantClaims,
    ) -> Result<Self, String> {
        let arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } = &claims.holder_binding
        else {
            return Err("participation overlay requires an Agent runtime session".into());
        };
        if agent_id != &claims.account_id.principal_id
            || claims.account_id.station_id != claims.audience_id
        {
            return Err("Agent participation observation has another Account/Station".into());
        }
        let details = claims
            .scope_details
            .as_ref()
            .ok_or("Agent session has no scope details")?;
        let controller: arkret_wire::DidCoreId = serde_json::from_value(
            details
                .get("controller_principal_id")
                .ok_or("Agent session has no controller binding")?
                .clone(),
        )
        .map_err(|e| e.to_string())?;
        let entries: Vec<AgentParticipationEntry> = serde_json::from_value(
            details
                .get("participations")
                .ok_or("Agent session has no participation observation")?
                .clone(),
        )
        .map_err(|e| e.to_string())?;
        let mut scopes = std::collections::BTreeSet::new();
        for entry in &entries {
            entry.validate()?;
            if !scopes.insert(entry.scope.scope_key()) {
                return Err("duplicate participation target scope".into());
            }
        }
        Ok(Self {
            agent_account: claims.account_id.clone(),
            controller_account: arkret_wire::AccountId::new(
                controller,
                claims.account_id.station_id.clone(),
            ),
            grant_id: claims.grant_id.clone(),
            agent_key_authorization_ref: agent_key_authorization_ref.clone(),
            verification_method: verification_method.clone(),
            session_id: claims.session_id.clone(),
            observed_at: claims.not_before,
            expires_at: claims.expires_at,
            entries,
        })
    }

    /// Use the most specific observed selection only to suppress local work.
    /// This does not assert that the owner-current or governance cut is current.
    pub fn observed_selection_for_scopes(
        &self,
        scopes: &[ParticipationScope],
    ) -> Option<ParticipationBits> {
        scopes.iter().rev().find_map(|scope| {
            self.entries
                .iter()
                .find(|entry| &entry.scope == scope)
                .map(|entry| entry.selection)
        })
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), String> {
        if self.agent_account != next.agent_account
            || self.controller_account != next.controller_account
            || self.agent_key_authorization_ref != next.agent_key_authorization_ref
            || self.verification_method != next.verification_method
            || next.observed_at < self.observed_at
        {
            return Err("participation observation changed owner or moved backwards".into());
        }
        for entry in &next.entries {
            if let Some(old) = self.entries.iter().find(|old| old.scope == entry.scope)
                && (entry.version < old.version
                    || (entry.version == old.version && entry.selection != old.selection))
            {
                return Err("participation selection version regressed or conflicts".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    fn observation() -> AgentParticipationObservation {
        let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [7; 32],
        ));
        let scope = ParticipationScope::Realm { realm_id: realm };
        AgentParticipationObservation {
            agent_account: arkret_wire::AccountId::new(
                "ak:did_core:web:agent.example".parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            ),
            controller_account: arkret_wire::AccountId::new(
                "ak:did_core:web:controller.example".parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            ),
            grant_id: arkret_wire::SessionGrantId::from_issuance_digest([8; 32]),
            agent_key_authorization_ref: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [9; 32],
            ),
            verification_method: arkret_wire::DidUrl::new("did:web:agent.example#runtime").unwrap(),
            session_id: "session".into(),
            observed_at: "2026-10-05T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-10-05T00:05:00.000Z".parse().unwrap(),
            entries: vec![AgentParticipationEntry {
                scope,
                selection: ParticipationBits::ALL,
                version: 2,
                next_replace_input: Some(ParticipationNextReplaceInput {
                    expected_version: 2,
                }),
            }],
        }
    }
    #[test]
    fn exhausted_version_is_readable_but_cannot_be_a_replace_input() {
        let maximum = i64::MAX as u64;
        let mut entry = observation().entries[0].clone();
        entry.version = maximum;
        entry.next_replace_input = None;
        entry.validate().unwrap();
        let wire = serde_json::to_value(&entry).unwrap();
        assert_eq!(wire["version"], maximum.to_string());
        assert!(wire.get("next_replace_input").is_none());
        assert!(serde_json::from_value::<AgentParticipationEntry>(wire).is_ok());
        let exhausted = serde_json::json!({"expected_version": maximum.to_string()});
        assert!(serde_json::from_value::<ParticipationNextReplaceInput>(exhausted).is_err());
        assert!(
            serde_json::to_value(ParticipationNextReplaceInput {
                expected_version: maximum
            })
            .is_err()
        );
    }

    #[test]
    fn authenticated_claims_consume_the_canonical_participations_member() {
        use arkret_models_identity::{
            CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantHolderBinding,
            SessionGrantIssuanceNonce, SignedSessionGrantClaims,
        };
        let expected = observation();
        let mut claims = SignedSessionGrantClaims {
            kind: "ak.session.grant".into(),
            grant_id: expected.grant_id.clone(),
            issuer_id: "ak:did_core:web:authority.example".parse().unwrap(),
            issuance_nonce: SessionGrantIssuanceNonce::from_bytes([5; 32]),
            account_id: expected.agent_account.clone(),
            session_public_key: CanonicalSessionPublicJwk::new(
                r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            ).unwrap(),
            audience_id: expected.agent_account.station_id.clone(),
            scopes: vec!["ak.self.committed_event.read.scan.v1".into()],
            not_before: expected.observed_at,
            expires_at: expected.expires_at,
            session_id: expected.session_id.clone(),
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::AgentRuntime {
                agent_id: expected.agent_account.principal_id.clone(),
                agent_key_authorization_ref: expected.agent_key_authorization_ref.clone(),
                verification_method: expected.verification_method.clone(),
            },
            device_binding: None,
            proof_kind: None,
            scope_details: Some(serde_json::json!({
                "controller_principal_id":expected.controller_account.principal_id,
                "participations":expected.entries,
            }).as_object().unwrap().clone()),
        };
        assert_eq!(
            AgentParticipationObservation::from_authenticated_claims(&claims).unwrap(),
            expected
        );
        let details = claims.scope_details.as_mut().unwrap();
        let entries = details.remove("participations").unwrap();
        details.insert("participation".into(), entries);
        assert!(AgentParticipationObservation::from_authenticated_claims(&claims).is_err());
    }

    #[test]
    fn refresh_observation_rejects_rollback_conflict_and_changed_owner() {
        let old = observation();
        let mut next = old.clone();
        next.entries[0].version = 1;
        next.entries[0]
            .next_replace_input
            .as_mut()
            .unwrap()
            .expected_version = 1;
        assert!(old.validate_successor(&next).is_err());
        let mut next = old.clone();
        next.entries[0].selection = ParticipationBits::NONE;
        assert!(old.validate_successor(&next).is_err());
        next.entries[0].version = 3;
        next.entries[0]
            .next_replace_input
            .as_mut()
            .unwrap()
            .expected_version = 3;
        old.validate_successor(&next).unwrap();
        assert_eq!(
            next.observed_selection_for_scopes(&[next.entries[0].scope.clone()]),
            Some(ParticipationBits::NONE)
        );
        next.controller_account.station_id = "ak:did_core:web:another.example".parse().unwrap();
        assert!(old.validate_successor(&next).is_err());
        let mut next = old.clone();
        next.agent_key_authorization_ref =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [10; 32]);
        assert!(old.validate_successor(&next).is_err());
    }
}

include!("generated/agent_participation_contracts.rs");
