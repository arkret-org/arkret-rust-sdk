//! Paged transport of the authorized governance replay closure.
use std::collections::BTreeSet;

use arkret_wire::{AccountId, ActorId, Event, Hash, RealmId, RequestId, Result, Seal, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::realm_join_intake::{RealmJoinBootstrapRequestBody, RealmJoinGovernanceFacts};
use crate::governance_dependencies::GovernanceDependency;

pub const MAX_BOOTSTRAP_RECORDS: usize = 65_536;
pub const MAX_BOOTSTRAP_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_BOOTSTRAP_PAGE_RECORDS: usize = 128;
pub const MAX_BOOTSTRAP_PAGE_STEPS: usize = 1024;
pub const MAX_BOOTSTRAP_PAGES_PER_ATTEMPT: usize = 64;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.into())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmJoinBootstrapReadRequest {
    Initial(RealmJoinBootstrapRequestBody),
    Continue(RealmJoinBootstrapContinuation),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinBootstrapContinuation {
    pub cursor: String,
}

impl RealmJoinBootstrapReadRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Initial(request) => request.validate(),
            Self::Continue(request)
                if !request.cursor.is_empty() && request.cursor.len() <= 4096 =>
            {
                Ok(())
            }
            _ => Err(invalid("invalid bootstrap cursor")),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RealmJoinBootstrapRecord {
    Seal {
        seal: Seal,
    },
    ControlMove {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        event: Event,
    },
    GovernanceDependency {
        dependency: GovernanceDependency,
    },
    ApplicantPredecessor {
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        event: Event,
    },
}

impl RealmJoinBootstrapRecord {
    pub fn key(&self) -> Result<String> {
        Ok(match self {
            Self::Seal { seal } => format!("seal:{}", seal.id),
            Self::ControlMove { event } => format!("control:{}", event.event_id),
            Self::ApplicantPredecessor { event } => format!("applicant:{}", event.event_id),
            Self::GovernanceDependency { dependency } => format!(
                "dependency:{}",
                arkret_canonical::canonical_sha256(&dependency.selector())?
            ),
        })
    }
    pub fn validate_scope(&self, realm: &RealmId, account: &AccountId) -> Result<()> {
        match self {
            Self::Seal { seal } if &seal.realm_id == realm => seal.validate_structural(),
            Self::ControlMove { event }
                if &event.realm_id == realm && event.kind.is_control_plane() =>
            {
                Ok(())
            }
            Self::ApplicantPredecessor { event }
                if &event.realm_id == realm
                    && event.actor_id == ActorId::account(account.clone()) =>
            {
                Ok(())
            }
            Self::GovernanceDependency { dependency } => {
                dependency.dependency_selectors().map(|_| ())
            }
            _ => Err(invalid("bootstrap record crosses the authorized scope")),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinBootstrapOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub applicant_account_id: AccountId,
    pub request_digest: Hash,
    pub governance_facts: RealmJoinGovernanceFacts,
    pub page_index: u32,
    pub records: Vec<RealmJoinBootstrapRecord>,
    #[serde(deserialize_with = "required_cursor")]
    pub next_cursor: Option<String>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

fn required_cursor<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

impl RealmJoinBootstrapOutcome {
    pub const SCHEMA: &'static str = arkret_wire::SchemaId::REALM_JOIN_BOOTSTRAP_OUTCOME_V1;
    pub const MAX_CANONICAL_BYTES: usize = 8 * 1024 * 1024;
    pub fn validate_structural(&self) -> Result<()> {
        self.applicant_account_id.validate()?;
        self.governance_facts.validate()?;
        if self.page_index >= 65_536
            || self.records.len() > MAX_BOOTSTRAP_PAGE_RECORDS
            || self.expires_at <= self.observed_at
            || self.expires_at > self.observed_at + chrono::Duration::seconds(300)
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 4096)
            || arkret_canonical::canonical_json_bytes(self)?.len() > Self::MAX_CANONICAL_BYTES
        {
            return Err(invalid("invalid bootstrap page bounds or expiry"));
        }
        let mut seen = BTreeSet::new();
        for record in &self.records {
            record.validate_scope(&self.realm_id, &self.applicant_account_id)?;
            if !seen.insert(record.key()?) {
                return Err(invalid("duplicate bootstrap record"));
            }
        }
        Ok(())
    }
    pub fn validate_for_request(&self, request: &RealmJoinBootstrapRequestBody) -> Result<()> {
        self.validate_for_request_digest(request, &request.request_digest()?)
    }
    pub fn validate_for_request_digest(
        &self,
        request: &RealmJoinBootstrapRequestBody,
        digest: &Hash,
    ) -> Result<()> {
        self.validate_structural()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.applicant_account_id != request.applicant_account_id
            || &self.request_digest != digest
        {
            return Err(invalid("bootstrap page answers another request"));
        }
        Ok(())
    }
}

/// Transport assembly only. `finish` does not authenticate governance; its
/// output must still pass the ordinary complete governance replay verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmJoinBootstrapAssembly {
    pub first: RealmJoinBootstrapOutcome,
    pub records: Vec<RealmJoinBootstrapRecord>,
    pub next_cursor: Option<String>,
    pub next_page: u32,
    bytes: usize,
    seen: BTreeSet<String>,
}

impl RealmJoinBootstrapAssembly {
    /// Reject missing or unsolicited graph objects before replay. This checks
    /// declared dependency coordinates, not signatures or reducer validity.
    pub fn validate_closure_coordinates(&self) -> Result<()> {
        use std::collections::{BTreeMap, VecDeque};

        use crate::governance_dependencies::governance_runtime_dependency_selector_coordinates_for_acquisition as coordinates;
        let mut seals = BTreeMap::new();
        let mut events = BTreeMap::new();
        let mut dependencies = BTreeMap::new();
        let mut predecessors = Vec::new();
        for record in &self.records {
            match record {
                RealmJoinBootstrapRecord::Seal { seal } => {
                    seals.insert(seal.id.clone(), seal);
                }
                RealmJoinBootstrapRecord::ControlMove { event } => {
                    events.insert(event.event_id.event_digest(), event);
                }
                RealmJoinBootstrapRecord::GovernanceDependency { dependency } => {
                    dependencies.insert(
                        arkret_canonical::canonical_sha256(dependency.selector())?,
                        dependency,
                    );
                }
                RealmJoinBootstrapRecord::ApplicantPredecessor { event } => {
                    predecessors.push(event)
                }
            }
        }
        if predecessors.len() > 64
            || predecessors.first().is_some_and(|first| {
                predecessors
                    .iter()
                    .any(|event| event.actor_seq != first.actor_seq)
            })
        {
            return Err(invalid(
                "bootstrap applicant frontier is not one bounded sibling set",
            ));
        }
        let mut pending = VecDeque::from(self.first.governance_facts.seal_basis.leaves.clone());
        let mut seen_seals = BTreeSet::new();
        let mut seen_events = BTreeSet::new();
        let mut pending_dependencies = VecDeque::new();
        while let Some(id) = pending.pop_front() {
            if !seen_seals.insert(id.clone()) {
                continue;
            }
            let seal = seals
                .get(&id)
                .ok_or_else(|| invalid("bootstrap omitted a Seal predecessor"))?;
            pending.extend(seal.predecessor_refs.iter().cloned());
            pending_dependencies.extend(coordinates(std::slice::from_ref(*seal), &[])?);
            for digest in &seal.delta {
                if !seen_events.insert(digest.clone()) {
                    continue;
                }
                let event = events
                    .get(digest)
                    .ok_or_else(|| invalid("bootstrap omitted a covered Control Move"))?;
                pending_dependencies.extend(coordinates(&[], std::slice::from_ref(*event))?);
            }
        }
        let mut seen_dependencies = BTreeSet::new();
        while let Some(selector) = pending_dependencies.pop_front() {
            let key = arkret_canonical::canonical_sha256(&selector)?;
            if !seen_dependencies.insert(key.clone()) {
                continue;
            }
            let dependency = dependencies
                .get(&key)
                .ok_or_else(|| invalid("bootstrap omitted a governance dependency"))?;
            pending_dependencies.extend(dependency.dependency_selectors()?);
        }
        if seen_seals.len() != seals.len()
            || seen_events.len() != events.len()
            || seen_dependencies.len() != dependencies.len()
        {
            return Err(invalid("bootstrap contains unsolicited governance objects"));
        }
        Ok(())
    }
    pub fn new(
        page: RealmJoinBootstrapOutcome,
        request: &RealmJoinBootstrapRequestBody,
    ) -> Result<Self> {
        if page.page_index != 0 {
            return Err(invalid("bootstrap starts with page zero"));
        }
        let mut result = Self {
            first: page.clone(),
            records: vec![],
            next_cursor: Some(String::new()),
            next_page: 0,
            bytes: 0,
            seen: BTreeSet::new(),
        };
        result.first.records.clear();
        result.append(page, request)?;
        Ok(result)
    }
    pub fn append(
        &mut self,
        page: RealmJoinBootstrapOutcome,
        request: &RealmJoinBootstrapRequestBody,
    ) -> Result<()> {
        page.validate_for_request(request)?;
        if self.next_cursor.is_none()
            || page.page_index != self.next_page
            || page.governance_facts != self.first.governance_facts
            || page.observed_at != self.first.observed_at
            || page.expires_at != self.first.expires_at
        {
            return Err(invalid("bootstrap page order or frozen context mismatch"));
        }
        let bytes = arkret_canonical::canonical_json_bytes(&page)?.len();
        if self.bytes + bytes > MAX_BOOTSTRAP_BYTES
            || self.records.len() + page.records.len() > MAX_BOOTSTRAP_RECORDS
        {
            return Err(invalid("bootstrap context resource budget exhausted"));
        }
        let keys = page
            .records
            .iter()
            .map(RealmJoinBootstrapRecord::key)
            .collect::<Result<Vec<_>>>()?;
        if keys.iter().any(|k| self.seen.contains(k)) {
            return Err(invalid("bootstrap repeats an earlier record"));
        }
        self.seen.extend(keys);
        self.bytes += bytes;
        self.next_page += 1;
        self.next_cursor = page.next_cursor;
        self.records.extend(page.records);
        Ok(())
    }
    pub fn finish(&self, now: DateTime<Utc>) -> Result<()> {
        if self.next_cursor.is_some() || now >= self.first.expires_at {
            return Err(invalid("bootstrap is incomplete or expired"));
        }
        Ok(())
    }
}
