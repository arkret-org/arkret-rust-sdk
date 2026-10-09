//! Closed exact-current Relation, moderation, Agent mode and issuer grant reads.
//!
//! The operation-specific selectors reuse the shared wire conflict-domain
//! identity, remain field-for-field equivalent to the closed selectors, and
//! never fall back to `serde_json::Value`.

use std::fmt;
use std::sync::OnceLock;

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CurrentRevision, EventId, GrantId, RealmId, Result,
    WireError,
};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::agent_interaction::{
    AgentInteractionExactCurrentResult, AgentInteractionExactCurrentSelector,
};
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

#[cfg(test)]
mod canonical_dot_order_tests {
    use super::*;

    #[test]
    fn dots_compare_numeric_write_indices_after_event_id_bytes() {
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let two = CanonicalEventDot::new(event.clone(), 2).unwrap();
        let ten = CanonicalEventDot::new(event, 10).unwrap();
        assert!(two < ten);
        assert!(two.to_string() > ten.to_string());
        let other = CanonicalEventDot::new(
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x22; 32]),
            0,
        )
        .unwrap();
        assert_eq!(
            two.cmp(&other),
            two.event_id()
                .as_str()
                .as_bytes()
                .cmp(other.event_id().as_str().as_bytes())
        );
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
    AgentInteraction(AgentInteractionExactCurrentSelector),
    CapabilityGrant(CapabilityGrantExactCurrentSelector),
    Policy(PolicyExactCurrentSelector),
    CalendarScheduleSource(CalendarScheduleSourceExactSelector),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarScheduleSourceExactSelectorKind {
    CalendarScheduleSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarScheduleSourceExactSelector {
    pub kind: CalendarScheduleSourceExactSelectorKind,
    pub strand_id: arkret_wire::StrandId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarScheduleSourceExactResult {
    pub selector: CalendarScheduleSourceExactSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: arkret_wire::CalendarScheduleSourceValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGrantExactCurrentSelectorKind {
    CapabilityGrant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantExactCurrentSelector {
    pub kind: CapabilityGrantExactCurrentSelectorKind,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantExactCurrentResult {
    pub selector: CapabilityGrantExactCurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: crate::governance::grant_constraint::CapabilityGrant,
}

impl ExactCurrentResultSelector {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Relation(selector) => selector.primary_conflict_domain.validate(),
            Self::ModerationState(_)
            | Self::AgentInteraction(_)
            | Self::Policy(_)
            | Self::CapabilityGrant(_)
            | Self::CalendarScheduleSource(_) => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyExactCurrentSelectorKind {
    Policy,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExactCurrentSelector {
    pub kind: PolicyExactCurrentSelectorKind,
    pub policy_id: arkret_wire::PolicyId,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExactCurrentResult {
    pub selector: PolicyExactCurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: crate::governance::operation_wire::PolicySetStatePayload,
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
    /// Exact stream of the covering RealmCommit named by `revision.commit_id`.
    pub source_stream_ref: CommitStreamRef,
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
    /// Exact stream of the covering RealmCommit named by `revision.commit_id`.
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: ModerationStateCurrentValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExactCurrentResultEntry {
    Relation(RelationExactCurrentResult),
    ModerationState(ModerationStateExactCurrentResult),
    AgentInteraction(AgentInteractionExactCurrentResult),
    CapabilityGrant(CapabilityGrantExactCurrentResult),
    Policy(PolicyExactCurrentResult),
    CalendarScheduleSource(CalendarScheduleSourceExactResult),
}

impl ExactCurrentResultEntry {
    fn revision(&self) -> &CurrentRevision {
        match self {
            Self::Relation(entry) => &entry.revision,
            Self::ModerationState(entry) => &entry.revision,
            Self::AgentInteraction(entry) => &entry.revision,
            Self::CapabilityGrant(entry) => &entry.revision,
            Self::Policy(entry) => &entry.revision,
            Self::CalendarScheduleSource(entry) => &entry.revision,
        }
    }

    fn source_stream_ref(&self) -> &CommitStreamRef {
        match self {
            Self::Relation(entry) => &entry.source_stream_ref,
            Self::ModerationState(entry) => &entry.source_stream_ref,
            Self::AgentInteraction(entry) => &entry.source_stream_ref,
            Self::CapabilityGrant(entry) => &entry.source_stream_ref,
            Self::Policy(entry) => &entry.source_stream_ref,
            Self::CalendarScheduleSource(entry) => &entry.source_stream_ref,
        }
    }

    fn matches_selector(&self, requested: &ExactCurrentResultSelector) -> bool {
        if let (Self::Policy(entry), ExactCurrentResultSelector::Policy(selector)) =
            (self, requested)
        {
            return &entry.selector == selector;
        }
        if let (
            Self::CalendarScheduleSource(entry),
            ExactCurrentResultSelector::CalendarScheduleSource(selector),
        ) = (self, requested)
        {
            return &entry.selector == selector;
        }
        if let (
            Self::CapabilityGrant(entry),
            ExactCurrentResultSelector::CapabilityGrant(selector),
        ) = (self, requested)
        {
            return &entry.selector == selector;
        }
        if let (
            Self::AgentInteraction(entry),
            ExactCurrentResultSelector::AgentInteraction(selector),
        ) = (self, requested)
        {
            return &entry.selector == selector;
        }
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
            Self::Policy(entry) => {
                entry.value.validate()?;
                if entry.selector.policy_id != entry.value.policy_id
                    || entry.source_stream_ref
                        != (CommitStreamRef::Realm {
                            realm_id: realm_id.clone(),
                        })
                {
                    return Err(WireError::Protocol(
                        "exact Policy current binding mismatch".into(),
                    ));
                }
                match &entry.value.value {
                    crate::governance::operation_wire::PolicySetValue::Governance(policy)
                        if matches!(
                            policy.policy_kind,
                            arkret_wire::PolicyKind::Agent | arkret_wire::PolicyKind::Applet
                        ) && policy.realm_id.as_ref() == Some(realm_id) =>
                    {
                        Ok(())
                    }
                    _ => Err(WireError::Protocol(
                        "exact Policy supply requires managed family".into(),
                    )),
                }
            }
            Self::CalendarScheduleSource(entry) => entry.value.validate_for_current(
                realm_id,
                &entry.source_stream_ref,
                &entry.revision,
            ),
            Self::CapabilityGrant(entry) => {
                if entry.value.id != entry.selector.grant_id
                    || entry.value.realm_id.as_ref() != Some(realm_id)
                    || entry.value.owned_agent_issuer().is_none()
                    || entry.source_stream_ref
                        != (CommitStreamRef::Realm {
                            realm_id: realm_id.clone(),
                        })
                {
                    return Err(WireError::Protocol(
                        "exact-current grant identity or Realm stream mismatch".into(),
                    ));
                }
                Ok(())
            }
            Self::AgentInteraction(entry) => {
                if entry.source_stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                {
                    return Err(WireError::Protocol(
                        "Agent interaction current must use the Realm stream".into(),
                    ));
                }
                Ok(())
            }
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

/// Closed absence selector; moderation has no never-written create opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NeverWrittenExactCurrentSelector {
    Policy(PolicyExactCurrentSelector),
    Relation(RelationExactCurrentSelector),
    AgentInteraction(AgentInteractionExactCurrentSelector),
}

/// Same-cut outcome, including explicit never-written Agent defaults.
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
        selector: NeverWrittenExactCurrentSelector,
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
                if matches!(
                    selector,
                    NeverWrittenExactCurrentSelector::AgentInteraction(_)
                        | NeverWrittenExactCurrentSelector::Policy(_)
                ) && head.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                {
                    return Err(WireError::Protocol(
                        "Agent interaction absence must use the Realm stream".into(),
                    ));
                }
                if !matches!(
                    (&request.selector, selector),
                    (ExactCurrentResultSelector::Relation(requested), NeverWrittenExactCurrentSelector::Relation(actual)) if requested == actual
                ) && !matches!((&request.selector, selector), (ExactCurrentResultSelector::AgentInteraction(requested), NeverWrittenExactCurrentSelector::AgentInteraction(actual)) if requested == actual)
                    && !matches!((&request.selector,selector),(ExactCurrentResultSelector::Policy(requested),NeverWrittenExactCurrentSelector::Policy(actual)) if requested==actual)
                {
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
                // The revision position is only comparable on its own covering
                // stream; never bound a row by another stream's same position.
                if entry.source_stream_ref() != &head.stream_ref {
                    return Err(WireError::Protocol(
                        "exact-current source stream differs from the effective stream head"
                            .to_owned(),
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

/// Validate minimal Calendar sources against the same authenticated current cut.
pub fn validate_calendar_current_pairs(
    realm: &RealmId,
    entries: &[arkret_wire::TypedCurrentResult],
) -> Result<()> {
    use arkret_wire::{CurrentSelector as S, TypedCurrentResult as R};
    let reject = |message: &str| WireError::Protocol(message.into());
    for entry in entries {
        let R::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        match selector {
            S::CalendarScheduleSource { strand_id } => {
                if entries.iter().filter(|entry| matches!(entry, R::Value { selector: S::CalendarScheduleSource { strand_id: id }, .. } if id == strand_id)).count() != 1 {
                    return Err(reject("Calendar source selector is duplicated"));
                }
                let mut paired = entries.iter().filter_map(|entry| {
                    let R::Value { selector, source_stream_ref, revision, value } = entry;
                    matches!(selector, S::Strand { strand_id: id } if id == strand_id).then_some((source_stream_ref, revision, value))
                });
                let (stream, basis, strand_value) = paired.next().ok_or_else(|| reject("Calendar source lacks its paired Strand"))?;
                if paired.next().is_some() || stream != source_stream_ref || basis != revision {
                    return Err(reject("Calendar source and Strand do not share one exact cut"));
                }
                let source: arkret_wire::CalendarScheduleSourceValue = serde_json::from_value(value.clone())?;
                source.validate_for_current(realm, stream, basis)?;
                let strand: crate::objects::strand::Strand = serde_json::from_value(strand_value.clone())?;
                let scope = match &strand.scope_circle_id {
                    Some(circle_id) => arkret_wire::ScopeRef::Circle { realm_id: strand.realm_id.clone(), circle_id: circle_id.clone() },
                    None => arkret_wire::ScopeRef::Realm { realm_id: strand.realm_id.clone() },
                };
                if source.effective_scope != scope { return Err(reject("Calendar source scope differs from its Strand")); }
                match (&strand.encrypted_metadata, &source.metadata_context) {
                    (Some(envelope), Some(context)) if envelope.payload_digest()? == context.payload_digest => {},
                    (None, None) => {},
                    _ => return Err(reject("Calendar metadata context differs from current ciphertext")),
                }
            }
            S::Strand { strand_id } if value.get("encrypted_metadata").is_some_and(|v| !v.is_null()) || value.pointer("/metadata/fields/calendar").is_some() => {
                if !entries.iter().any(|entry| matches!(entry, R::Value { selector: S::CalendarScheduleSource { strand_id: id }, .. } if id == strand_id)) {
                    return Err(reject("Calendar Strand lacks a current source sibling"));
                }
            }
            _ => {},
        }
    }
    Ok(())
}

#[cfg(test)]
mod calendar_current_pair_tests {
    use arkret_wire::{
        ActorId, CalendarScheduleSourceValue, CommittedEventRef, CurrentSelector, EventId,
        ScopeRef, StrandId, TypedCurrentResult,
    };
    use serde_json::json;

    use super::*;
    fn event(byte: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }
    fn rows() -> (RealmId, Vec<TypedCurrentResult>) {
        let realm = RealmId::from_event_id(&event(1));
        let id = StrandId::from_event_id(&event(2));
        let stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let revision = CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([5; 32]),
            stream_position: 5,
        };
        let mut strand = crate::objects::strand::Strand::discussion(
            id.clone(),
            realm.clone(),
            "calendar",
            ActorId::service(
                arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example").unwrap(),
            ),
        );
        strand.metadata.as_mut().unwrap().fields.insert("calendar".into(), json!({"start":"2026-10-07","end":"2026-10-08","timezone":"UTC","tzdb_version":"2025b","all_day":true,"status":"confirmed"}));
        let source = CalendarScheduleSourceValue {
            effective_scope: ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            source: Some(CommittedEventRef {
                event_id: event(3),
                commit_id: arkret_wire::RealmCommitId::from_digest([3; 32]),
                stream_ref: stream.clone(),
                stream_position: 3,
            }),
            strand_revision: revision.clone(),
            metadata_context: None,
        };
        (
            realm,
            vec![
                TypedCurrentResult::Value {
                    selector: CurrentSelector::Strand {
                        strand_id: id.clone(),
                    },
                    source_stream_ref: stream.clone(),
                    revision: revision.clone(),
                    value: serde_json::to_value(strand).unwrap(),
                },
                TypedCurrentResult::Value {
                    selector: CurrentSelector::CalendarScheduleSource { strand_id: id },
                    source_stream_ref: stream,
                    revision,
                    value: serde_json::to_value(source).unwrap(),
                },
            ],
        )
    }
    #[test]
    fn calendar_source_reconstructs_below_floor_and_rejects_missing_or_mismatched_pair() {
        let (realm, rows) = rows();
        validate_calendar_current_pairs(&realm, &rows).unwrap();
        assert!(validate_calendar_current_pairs(&realm, &rows[..1]).is_err());
        assert!(validate_calendar_current_pairs(&realm, &rows[1..]).is_err());
        let mut bad = rows.clone();
        let TypedCurrentResult::Value { revision, .. } = &mut bad[1];
        revision.stream_position += 1;
        assert!(validate_calendar_current_pairs(&realm, &bad).is_err());
        let mut bad = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut bad[1];
        value["source"]["stream_position"] = json!(6);
        assert!(validate_calendar_current_pairs(&realm, &bad).is_err());
        let mut bad = rows.clone();
        let TypedCurrentResult::Value { value, .. } = &mut bad[1];
        value["effective_scope"]["realm_id"] = json!(RealmId::from_event_id(&event(9)));
        assert!(validate_calendar_current_pairs(&realm, &bad).is_err());
    }
    #[test]
    fn encrypted_calendar_context_binds_ciphertext_kind_and_unique_pair() {
        let (realm, mut rows) = rows();
        let envelope =
            arkret_models_crypto::EncryptedEnvelope {
                version: "1.0".into(),
                content_type: "application/vnd.arkret.strand-metadata+json".into(),
                encryption_context:
                    arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(1, event(4)),
                ciphertext: "AQID".into(),
            };
        let TypedCurrentResult::Value { value, .. } = &mut rows[0];
        value.as_object_mut().unwrap().remove("metadata");
        value["encrypted_metadata"] = serde_json::to_value(&envelope).unwrap();
        let TypedCurrentResult::Value { value, .. } = &mut rows[1];
        value["metadata_context"] = json!({"source":value["source"],"event_kind":"ak.strand.update","signer_id":ActorId::service(arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example").unwrap()),"payload_digest":envelope.payload_digest().unwrap()});
        validate_calendar_current_pairs(&realm, &rows).unwrap();
        for (field, replacement) in [
            (
                "payload_digest",
                json!(arkret_wire::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap()),
            ),
            ("event_kind", json!("ak.message.create")),
            (
                "signer_id",
                json!({"kind":"service","service_id":"invalid"}),
            ),
        ] {
            let mut bad = rows.clone();
            let TypedCurrentResult::Value { value, .. } = &mut bad[1];
            value["metadata_context"][field] = replacement;
            assert!(validate_calendar_current_pairs(&realm, &bad).is_err());
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[1].clone());
        assert!(validate_calendar_current_pairs(&realm, &duplicate).is_err());
    }
    #[test]
    fn calendar_nullable_source_and_context_are_required_closed_members() {
        let (_, rows) = rows();
        let TypedCurrentResult::Value { value, .. } = &rows[1];
        for member in ["source", "metadata_context"] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(member);
            assert!(serde_json::from_value::<CalendarScheduleSourceValue>(bad).is_err());
        }
        let mut empty = value.clone();
        empty["source"] = json!(null);
        serde_json::from_value::<CalendarScheduleSourceValue>(empty).unwrap();
    }
}
