//! Closed exact-current Relation and moderation read carriers.
//!
//! These types intentionally live in the collaboration model crate: the
//! Relation conflict-domain type is owned here, while moving it into
//! `arkret-wire` would introduce a dependency cycle. The operation-specific
//! selector is field-for-field equivalent to the formal closed selector and
//! never falls back to `serde_json::Value`.

use std::fmt;
use std::sync::OnceLock;

use arkret_wire::{CommitStreamHead, CurrentRevision, EventId, RealmId, Result, WireError};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::events_payloads::moderation::{
    ModerationDecisionLiftPayload, ModerationDecisionPayload,
};
use crate::objects::relation::{
    Relation, RelationPrimaryConflictDomain, RelationPrimaryConflictDomainKind,
};

/// A formal `object_ref` restricted by the exact schema pattern at decode time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactModerationTargetRef(String);

impl ExactModerationTargetRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        static OBJECT_REF: OnceLock<Regex> = OnceLock::new();
        let pattern = OBJECT_REF.get_or_init(|| {
            Regex::new(concat!(
                r"^((?:ak:realm:[A-Za-z0-9_-]{44}|",
                r"ak:(circle|space|actor_profile|strand|message|morph|relation|view|event|grant|invite|call|report):[A-Za-z0-9_-]{44}|",
                r"ak:(policy|blob):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})|",
                r"ak:blob:(sha256|blake3):[0-9a-f]{64}|did:[^\s]+|(sha256|blake3):[0-9a-f]{64})$"
            ))
            .expect("formal object_ref regex is valid")
        });
        if !pattern.is_match(&value) {
            return Err(WireError::Protocol(
                "exact-current moderation target_ref is not a formal object_ref".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for ExactModerationTargetRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExactModerationTargetRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Canonical `<event_id>:<write_index>` reducer dot.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalEventDot {
    event_id: EventId,
    write_index: u16,
}

impl CanonicalEventDot {
    pub fn new(event_id: EventId, write_index: u16) -> Result<Self> {
        if write_index > 999 {
            return Err(WireError::Protocol(
                "canonical Event dot write_index must be 0..=999".to_owned(),
            ));
        }
        Ok(Self {
            event_id,
            write_index,
        })
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub const fn write_index(&self) -> u16 {
        self.write_index
    }
}

impl fmt::Display for CanonicalEventDot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.event_id.as_str(), self.write_index)
    }
}

impl Serialize for CanonicalEventDot {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalEventDot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let (event_id, write_index) = value
            .rsplit_once(':')
            .ok_or_else(|| serde::de::Error::custom("canonical Event dot lacks write_index"))?;
        if write_index.len() > 1 && write_index.starts_with('0') {
            return Err(serde::de::Error::custom(
                "canonical Event dot write_index has a leading zero",
            ));
        }
        let write_index = write_index
            .parse::<u16>()
            .map_err(serde::de::Error::custom)?;
        let event_id = EventId::new(event_id).map_err(serde::de::Error::custom)?;
        Self::new(event_id, write_index).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationExactCurrentSelectorKind {
    Relation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationExactCurrentSelector {
    pub kind: RelationExactCurrentSelectorKind,
    pub primary_conflict_domain: RelationPrimaryConflictDomain,
}

impl RelationExactCurrentSelector {
    pub fn new(primary_conflict_domain: RelationPrimaryConflictDomain) -> Result<Self> {
        primary_conflict_domain.validate()?;
        Ok(Self {
            kind: RelationExactCurrentSelectorKind::Relation,
            primary_conflict_domain,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationStateExactCurrentSelectorKind {
    ModerationState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationStateExactCurrentSelector {
    pub kind: ModerationStateExactCurrentSelectorKind,
    pub target_ref: ExactModerationTargetRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExactCurrentResultSelector {
    Relation(RelationExactCurrentSelector),
    ModerationState(ModerationStateExactCurrentSelector),
}

impl ExactCurrentResultSelector {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Relation(selector) => selector.primary_conflict_domain.validate(),
            Self::ModerationState(_) => Ok(()),
        }
    }
}

/// `ak.self.current_results.read.exact.v1` request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCurrentResultsReadRequestBody {
    pub realm_id: RealmId,
    pub selector: ExactCurrentResultSelector,
}

impl ExactCurrentResultsReadRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.selector.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationExactCurrentResult {
    pub selector: RelationExactCurrentSelector,
    pub revision: CurrentRevision,
    pub value: Relation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ModerationAssertionValue {
    Decision(ModerationDecisionPayload),
    Lift(ModerationDecisionLiftPayload),
}

impl ModerationAssertionValue {
    fn target_ref(&self) -> &str {
        match self {
            Self::Decision(value) => &value.target_ref,
            Self::Lift(value) => &value.target_ref,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationDecisionEntry {
    pub tag_id: CanonicalEventDot,
    pub value: ModerationAssertionValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationStateCurrentValue {
    pub assertions: Vec<ModerationDecisionEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationStateExactCurrentResult {
    pub selector: ModerationStateExactCurrentSelector,
    pub revision: CurrentRevision,
    pub value: ModerationStateCurrentValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExactCurrentResultEntry {
    Relation(RelationExactCurrentResult),
    ModerationState(ModerationStateExactCurrentResult),
}

impl ExactCurrentResultEntry {
    fn revision(&self) -> &CurrentRevision {
        match self {
            Self::Relation(entry) => &entry.revision,
            Self::ModerationState(entry) => &entry.revision,
        }
    }

    fn matches_selector(&self, requested: &ExactCurrentResultSelector) -> bool {
        matches!(
            (self, requested),
            (Self::Relation(entry), ExactCurrentResultSelector::Relation(selector))
                if &entry.selector == selector
        ) || matches!(
            (self, requested),
            (
                Self::ModerationState(entry),
                ExactCurrentResultSelector::ModerationState(selector)
            ) if &entry.selector == selector
        )
    }

    fn validate_value(&self, realm_id: &RealmId) -> Result<()> {
        match self {
            Self::Relation(entry) => {
                entry.selector.primary_conflict_domain.validate()?;
                if &entry.value.realm_id != realm_id {
                    return Err(WireError::Protocol(
                        "exact-current Relation value belongs to a different Realm".to_owned(),
                    ));
                }
                let domain = &entry.selector.primary_conflict_domain;
                let same_identity = domain.relation_kind == entry.value.relation_kind
                    && domain.from_ref == entry.value.from_ref
                    && match domain.domain_kind {
                        RelationPrimaryConflictDomainKind::Tuple => {
                            domain.to_ref.as_ref() == Some(&entry.value.to_ref)
                        }
                        RelationPrimaryConflictDomainKind::From => domain.to_ref.is_none(),
                    };
                if !same_identity {
                    return Err(WireError::Protocol(
                        "exact-current Relation value differs from its primary conflict domain"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            Self::ModerationState(entry) => {
                if entry
                    .value
                    .assertions
                    .windows(2)
                    .any(|pair| pair[0].tag_id >= pair[1].tag_id)
                {
                    return Err(WireError::Protocol(
                        "moderation assertions must be strictly sorted and unique by tag_id"
                            .to_owned(),
                    ));
                }
                if entry.value.assertions.iter().any(|assertion| {
                    assertion.value.target_ref() != entry.selector.target_ref.as_str()
                }) {
                    return Err(WireError::Protocol(
                        "moderation assertion target_ref differs from its selector".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Same-cut outcome. The `NeverWritten` branch is structurally Relation-only;
/// moderation can therefore never be mistaken for a null-CAS create opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactCurrentResultsReadOutcome {
    Present {
        realm_id: RealmId,
        governance_generation: u64,
        effective_stream_head: CommitStreamHead,
        entry: ExactCurrentResultEntry,
    },
    NeverWritten {
        realm_id: RealmId,
        governance_generation: u64,
        effective_stream_head: CommitStreamHead,
        selector: RelationExactCurrentSelector,
    },
}

impl ExactCurrentResultsReadOutcome {
    /// Validate every caller-visible binding before the result can supply a CAS
    /// basis. The governing generation must come from the caller's separately
    /// verified current Station state.
    pub fn validate_for_request(
        &self,
        request: &ExactCurrentResultsReadRequestBody,
        expected_governance_generation: u64,
    ) -> Result<()> {
        request.validate()?;
        let (realm_id, generation, head) = match self {
            Self::Present {
                realm_id,
                governance_generation,
                effective_stream_head,
                ..
            }
            | Self::NeverWritten {
                realm_id,
                governance_generation,
                effective_stream_head,
                ..
            } => (realm_id, governance_generation, effective_stream_head),
        };
        if realm_id != &request.realm_id || head.stream_ref.realm_id() != &request.realm_id {
            return Err(WireError::Protocol(
                "exact-current response Realm differs from request".to_owned(),
            ));
        }
        if *generation != expected_governance_generation {
            return Err(WireError::Protocol(
                "exact-current response uses a stale governance generation".to_owned(),
            ));
        }
        match self {
            Self::NeverWritten { selector, .. } => {
                if !matches!(
                    &request.selector,
                    ExactCurrentResultSelector::Relation(requested) if requested == selector
                ) {
                    return Err(WireError::Protocol(
                        "exact-current never_written selector differs from request".to_owned(),
                    ));
                }
            }
            Self::Present { entry, .. } => {
                if !entry.matches_selector(&request.selector) {
                    return Err(WireError::Protocol(
                        "exact-current present selector differs from request".to_owned(),
                    ));
                }
                let revision = entry.revision();
                if revision.stream_position > head.stream_position
                    || (revision.stream_position == head.stream_position
                        && revision.commit_id != head.commit_id)
                {
                    return Err(WireError::Protocol(
                        "exact-current revision is not bounded by the effective stream head"
                            .to_owned(),
                    ));
                }
                entry.validate_value(realm_id)?;
            }
        }
        Ok(())
    }
}
