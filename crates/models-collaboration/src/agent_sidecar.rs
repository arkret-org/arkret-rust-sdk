//! Agent Sidecar: the controller-account-owned private AI workspace.
//!
//! The owner's home Station governs the private group and its signed events.
//! Each owner/source-Realm pair has one Sidecar. Strand bindings select the
//! displayed context. Project reads and publication use the project's authority.

use arkret_wire::{
    AccountId, CommitStreamHead, DeviceId, DidCoreId, EventId, Hash, Hlc, RealmId, Result,
    SidecarId, StrandId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Failure reason a controller derives when it closes an exchange that produced
/// no validated user-facing response.
pub const SIDECAR_EXCHANGE_CLOSED_EMPTY_REASON: &str = "controller_closed_empty";
/// Failure reason a controller derives when it cancels an exchange.
pub const SIDECAR_EXCHANGE_CANCELLED_REASON: &str = "controller_cancelled";

/// Accepted participant inputs observed by the owning Station. This internal
/// authority provider result does not introduce a new wire object or operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarParticipantAuthorityCut {
    pub realm_id: RealmId,
    pub sidecar_id: SidecarId,
    pub controller_account_id: AccountId,
    pub desired_agent_ids: Vec<DidCoreId>,
    pub participant_authority_digest: Hash,
    pub visible_stream_heads: Vec<CommitStreamHead>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarState {
    Active,
    Suspended,
    Tombstoned,
}

// Field declaration order is byte-for-byte the properties order of
// agent-sidecar.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecar {
    pub id: SidecarId,
    pub schema: String,
    pub realm_id: RealmId,
    pub source_realm_id: RealmId,
    pub controller_account_id: AccountId,
    pub state: AgentSidecarState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl AgentSidecar {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != arkret_wire::SchemaId::AGENT_SIDECAR_V1 {
            return Err(WireError::Protocol(
                "agent sidecar schema is invalid".to_owned(),
            ));
        }
        if matches!(
            self.state,
            AgentSidecarState::Suspended | AgentSidecarState::Tombstoned
        ) && self.state_changed_at.is_none()
        {
            return Err(WireError::Protocol(
                "a suspended or tombstoned Sidecar carries state_changed_at".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-view-state.schema.json#/$defs/strand_context_ref.

// Controller-private encrypted account-data plaintext for one hosted Sidecar
// context. It changes only private presentation and never mutates a Strand,
// Track, access, read state, notification, search index, or event ownership.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-view-state.schema.json#/properties.

impl AgentSidecarViewState {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != arkret_wire::SchemaId::AGENT_SIDECAR_VIEW_STATE_V1 {
            return Err(WireError::Protocol(
                "agent sidecar view state schema is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeAction {
    Close,
    Cancel,
    Fail,
    ReassignCoordinator,
}

// Closed plaintext encrypted inside the payload of
// `ak.agent.sidecar.exchange.control`. Only the Sidecar controller may author
// this durable private-Strand Event; it is the sole source of coordinator
// reassignment and terminal exchange state.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-control.schema.json#/properties.

impl AgentSidecarExchangeControl {
    pub fn validate_shape(&self) -> Result<()> {
        validate_exchange_token(&self.exchange_id, 22)?;
        if self
            .basis_event_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .response_event_ids
                .as_ref()
                .is_some_and(|ids| ids.windows(2).any(|pair| pair[0] >= pair[1]))
        {
            return Err(WireError::Protocol(
                "exchange control Event sets must be sorted and unique".to_owned(),
            ));
        }
        if self
            .failure_reason_code
            .as_ref()
            .is_some_and(|reason| !sidecar_code(reason))
        {
            return Err(WireError::Protocol(
                "exchange failure reason is not a registered code shape".to_owned(),
            ));
        }
        if self.schema != arkret_wire::SchemaId::AGENT_SIDECAR_EXCHANGE_CONTROL_V1 {
            return Err(WireError::Protocol(
                "agent sidecar exchange control schema is invalid".to_owned(),
            ));
        }
        if self.basis_event_ids.is_empty() {
            return Err(WireError::Protocol(
                "exchange control carries at least one basis Event id".to_owned(),
            ));
        }
        let terminal = matches!(
            self.action,
            AgentSidecarExchangeAction::Close
                | AgentSidecarExchangeAction::Cancel
                | AgentSidecarExchangeAction::Fail
        );
        if terminal {
            if self.response_event_ids.is_none() {
                return Err(WireError::Protocol(
                    "a terminal exchange control carries response_event_ids".to_owned(),
                ));
            }
            if self.expected_coordinator_agent_id.is_some() || self.coordinator_agent_id.is_some() {
                return Err(WireError::Protocol(
                    "a terminal exchange control carries no coordinator members".to_owned(),
                ));
            }
        } else {
            if self.response_event_ids.is_some() {
                return Err(WireError::Protocol(
                    "coordinator reassignment carries no response_event_ids".to_owned(),
                ));
            }
            if self.expected_coordinator_agent_id.is_none() || self.coordinator_agent_id.is_none() {
                return Err(WireError::Protocol(
                    "coordinator reassignment carries both coordinator members".to_owned(),
                ));
            }
        }
        if (self.action == AgentSidecarExchangeAction::Fail) != self.failure_reason_code.is_some() {
            return Err(WireError::Protocol(
                "failure_reason_code is carried by action=fail alone".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Closed, canonical assertion set for one native Sidecar source context.
/// Exchange identities remain encrypted inside each carrier, never in this
/// value's selector or an additional plaintext member.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControlsValue {
    assertions: Vec<AgentSidecarExchangeControlAssertion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSidecarExchangeControlsValueWire {
    assertions: Vec<AgentSidecarExchangeControlAssertion>,
}

impl AgentSidecarExchangeControlsValue {
    pub fn new(assertions: Vec<AgentSidecarExchangeControlAssertion>) -> Result<Self> {
        if assertions
            .iter()
            .any(|entry| entry.tag_id.write_index() != 0)
            || assertions
                .windows(2)
                .any(|pair| pair[0].tag_id >= pair[1].tag_id)
        {
            return Err(WireError::Protocol(
                "Sidecar control assertions require sorted unique Event dots at write index 0"
                    .to_owned(),
            ));
        }
        for entry in &assertions {
            entry.value.encrypted_payload.validate()?;
        }
        if assertions.windows(2).any(|pair| {
            pair[0].value.sidecar_id != pair[1].value.sidecar_id
                || pair[0].value.source_context_ref != pair[1].value.source_context_ref
        }) {
            return Err(WireError::Protocol(
                "Sidecar control assertions cross their native source context".to_owned(),
            ));
        }
        Ok(Self { assertions })
    }

    pub fn assertions(&self) -> &[AgentSidecarExchangeControlAssertion] {
        &self.assertions
    }

    pub fn with_assertion(mut self, entry: AgentSidecarExchangeControlAssertion) -> Result<Self> {
        match self
            .assertions
            .binary_search_by(|current| current.tag_id.cmp(&entry.tag_id))
        {
            Ok(_) => Err(WireError::Protocol(
                "Sidecar control assertion dot already exists".to_owned(),
            )),
            Err(index) => {
                self.assertions.insert(index, entry);
                Self::new(self.assertions)
            }
        }
    }

    pub fn validate_for_context(
        &self,
        sidecar_id: &SidecarId,
        source_context_ref: &arkret_wire::SidecarContextRef,
    ) -> Result<()> {
        if self.assertions.iter().any(|entry| {
            &entry.value.sidecar_id != sidecar_id
                || &entry.value.source_context_ref != source_context_ref
        }) {
            return Err(WireError::Protocol(
                "Sidecar control value differs from its exact selector".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AgentSidecarExchangeControlsValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentSidecarExchangeControlsValueWire::deserialize(deserializer)?;
        Self::new(wire.assertions).map_err(serde::de::Error::custom)
    }
}

// Track coordinate of the source-routed exchange. The same closed shape backs
// agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref and
// agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context/
// properties/source_track_ref.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref.

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeStatus {
    Delivered,
    Responding,
    Complete,
    Failed,
}

// Local cache coverage. `event_ids` are the canonical sorted maximal causal
// heads of every contributing accepted exchange fact; `event_set_digest`
// commits to the canonical sorted complete contributing Event-id set;
// `max_hlc` is display/cache metadata and never proves causal dominance.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/$defs/folded_checkpoint.

// Disposable controller-device-local cache for one source-routed native
// Sidecar exchange. Every member is a deterministic fold of accepted
// Sidecar-scoped Events: this is not wire truth, not Account Data, never
// merged across devices, and may always be deleted and rebuilt.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/properties.

impl AgentSidecarExchangeProjection {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != arkret_wire::SchemaId::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1 {
            return Err(WireError::Protocol(
                "agent sidecar exchange projection schema is invalid".to_owned(),
            ));
        }
        if self.folded_checkpoint.event_ids.is_empty() {
            return Err(WireError::Protocol(
                "a folded checkpoint carries at least one Event id".to_owned(),
            ));
        }
        match self.status {
            AgentSidecarExchangeStatus::Delivered => {
                if !self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_some()
                {
                    return Err(WireError::Protocol(
                        "a delivered exchange carries no responses and no terminal members"
                            .to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Responding => {
                if self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_some()
                {
                    return Err(WireError::Protocol(
                        "a responding exchange carries responses and no terminal members"
                            .to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Complete => {
                if self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_some()
                    || self.terminal_event_id.is_none()
                {
                    return Err(WireError::Protocol(
                        "a complete exchange carries responses and its terminal Event".to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeStatus::Failed => {
                if !self.user_facing_response_event_ids.is_empty()
                    || self.failure_reason_code.is_none()
                    || self.terminal_event_id.is_none()
                {
                    return Err(WireError::Protocol(
                        "a failed exchange carries no responses, a reason code and its terminal Event"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Closed disposition of a Sidecar-scoped Message event inside one exchange.
/// Consumers fail closed to non-echo on any value outside this set.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeRole {
    Request,
    UserFacingResponse,
    Internal,
}

// Write-once exchange identity carried only on `role=request`. Any controller
// device rebuilding the projection copies these values verbatim, so
// cross-device bit-identity is anchored to the accepted request Event instead
// of device-local state.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context.

// Closed typed binding tying one native-Sidecar-scoped Message event to one
// source-routed exchange. It is legal only inside encrypted metadata plaintext
// of an event whose `scope_ref.kind` is `sidecar`, and it is the only
// normative way to declare an explicit user-facing response; invalid or absent
// bindings are non-echo.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-event-exchange-binding.schema.json#/properties.

impl AgentSidecarEventExchangeBinding {
    pub fn validate_shape(&self) -> Result<()> {
        validate_exchange_token(&self.exchange_id, 22)?;
        if let Some(context) = &self.request_context {
            validate_exchange_token(&context.client_order_key, 1)?;
            if !sidecar_code(&context.source_track_ref.track_name)
                || context.addressed_agent_ids.is_empty()
                || context
                    .addressed_agent_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != context.addressed_agent_ids.len()
                || match &context.coordinator_agent_id {
                    Some(coordinator) => !context.addressed_agent_ids.contains(coordinator),
                    None => context.addressed_agent_ids.len() != 1,
                }
            {
                return Err(WireError::Protocol(
                    "exchange request has an invalid track, addressed set or coordinator"
                        .to_owned(),
                ));
            }
        }
        if self.schema != arkret_wire::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1 {
            return Err(WireError::Protocol(
                "agent sidecar event exchange binding schema is invalid".to_owned(),
            ));
        }
        if self.completes_exchange.is_some_and(|value| !value) {
            return Err(WireError::Protocol(
                "completes_exchange is present only as true".to_owned(),
            ));
        }
        match self.role {
            AgentSidecarExchangeRole::Request => {
                if self.request_context.is_none()
                    || self.request_event_id.is_some()
                    || self.completes_exchange.is_some()
                {
                    return Err(WireError::Protocol(
                        "a request binding carries its request context alone".to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeRole::Internal => {
                if self.request_event_id.is_none()
                    || self.request_context.is_some()
                    || self.completes_exchange.is_some()
                {
                    return Err(WireError::Protocol(
                        "an internal binding carries its request Event id alone".to_owned(),
                    ));
                }
            }
            AgentSidecarExchangeRole::UserFacingResponse => {
                if self.request_event_id.is_none() || self.request_context.is_some() {
                    return Err(WireError::Protocol(
                        "a user-facing response binding carries its request Event id".to_owned(),
                    ));
                }
            }
        }
        if self.completes_exchange.is_some() != self.coordinator_assignment_event_id.is_some() {
            return Err(WireError::Protocol(
                "coordinator_assignment_event_id is carried by completes_exchange alone".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_exchange_token(value: &str, minimum: usize) -> Result<()> {
    if !(minimum..=128).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
        })
    {
        return Err(WireError::Protocol(
            "exchange identity or order key has an invalid opaque-token shape".to_owned(),
        ));
    }
    Ok(())
}

fn sidecar_code(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Readiness of the controller device's access to the Sidecar MLS scope.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarAccessReadiness {
    Opening,
    KeyMaterialPending,
    EpochUpdateRequired,
    Ready,
    Failed,
}

/// Closed reconciliation phase. Clients derive localized explanatory text from
/// the phase; no parallel reason string is carried.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarAccessProvisioningPhase {
    MlsWelcome,
    MlsRemove,
    EpochRotation,
    DeviceKeyMaterial,
}

// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/pending_sidecar_access_reconciliation.

/// Domain member for the signed Sidecar participant-authority transcript.
pub const SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN: &str = "ak.sidecar.participant_authority.v1";

/// Compute the canonical participant-authority digest for one Sidecar.
///
/// Desired Agent/join pairs are sorted by Agent ID UTF-8 bytes before hashing
/// the generated five-member preimage. Repeated Agent IDs are rejected, even
/// when their join refs agree. Native eligibility is the owning Station's
/// responsibility; this helper only commits the supplied membership instances.
pub fn sidecar_participant_authority_digest(
    sidecar_id: &SidecarId,
    realm_id: &RealmId,
    controller_account_id: &AccountId,
    desired_agents: &[SidecarParticipantAuthorityAgent],
) -> Result<Hash> {
    controller_account_id.validate()?;
    let mut desired_agents = desired_agents.to_vec();
    desired_agents.sort_by(|left, right| {
        left.agent_id
            .as_str()
            .as_bytes()
            .cmp(right.agent_id.as_str().as_bytes())
    });
    if desired_agents
        .windows(2)
        .any(|pair| pair[0].agent_id == pair[1].agent_id)
    {
        return Err(WireError::Protocol(
            "Sidecar participant authority requires unique Agent IDs".to_owned(),
        ));
    }

    Hash::new(arkret_canonical::canonical_sha256(
        &SidecarParticipantAuthorityPreimage {
            domain: SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN.to_owned(),
            sidecar_id: sidecar_id.clone(),
            realm_id: realm_id.clone(),
            controller_account_id: controller_account_id.clone(),
            desired_agents,
        },
    )?)
    .map_err(Into::into)
}

// MLS coordinates of one Sidecar scope. The MLS scope is plaintext before its
// own accepted `ak.mls.genesis` and irreversibly activates to standard
// RFC 9420 afterwards.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_sidecar_mls_context.

impl AgentSidecarMlsContext {
    pub fn validate_shape(&self) -> Result<()> {
        let present = usize::from(self.mls_group_id.is_some())
            + usize::from(self.epoch.is_some())
            + usize::from(self.genesis_event_ref.is_some());
        if present != 0 && present != 3 {
            return Err(WireError::Protocol(
                "sidecar MLS group id, epoch and genesis ref are carried together".to_owned(),
            ));
        }
        Ok(())
    }

    /// True once the scope has an accepted `ak.mls.genesis`; the transition is
    /// irreversible.
    pub fn is_mls_activated(&self) -> bool {
        self.mls_group_id.is_some()
    }
}

#[cfg(test)]
mod tests;

include!("generated/agent_sidecar_contracts.rs");
