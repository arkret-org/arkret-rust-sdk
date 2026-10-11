//! Agent Sidecar: the controller-account-owned private AI workspace.
//!
//! A Sidecar is a first-class native protocol scope bound one-to-one to
//! `(realm_id, controller_account_id)` — not a Circle profile, a backing Circle,
//! or an editable membership container. Its shared MLS scope carries only
//! `ak.mls.genesis` and `ak.mls.commit`; the exchange objects below are
//! controller-private plaintext or device-local caches.

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

/// Accepted participant inputs at one durable cut. This internal authority
/// provider result does not introduce a new wire object or operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarParticipantAuthorityCut {
    pub realm_id: RealmId,
    pub sidecar_id: SidecarId,
    pub controller_account_id: AccountId,
    pub desired_agent_ids: Vec<DidCoreId>,
    pub participant_authority_digest: Hash,
    pub authority_stream_head: Vec<EventId>,
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarStrandContextRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
}

/// Controller-private encrypted account-data plaintext for one hosted Sidecar
/// context. It changes only private presentation and never mutates a Strand,
/// Track, access, read state, notification, search index, or event ownership.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-view-state.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarViewState {
    pub schema: String,
    pub controller_account_id: AccountId,
    pub sidecar_id: SidecarId,
    pub context_ref: SidecarStrandContextRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapsed: Option<bool>,
    pub updated_hlc: Hlc,
    pub origin_device_id: DeviceId,
}

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

/// Closed plaintext encrypted inside the payload of
/// `ak.agent.sidecar.exchange.control`. Only the Sidecar controller may author
/// this durable private-Strand Event; it is the sole source of coordinator
/// reassignment and terminal exchange state.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-control.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControl {
    pub schema: String,
    pub exchange_id: String,
    pub request_event_id: EventId,
    /// Canonical UTF-8 byte-order sorted maximal causal heads of the exchange
    /// facts observed when this control was authored.
    pub basis_event_ids: Vec<EventId>,
    pub action: AgentSidecarExchangeAction,
    /// Exact canonical set of validated user-facing response Event ids covered
    /// by `basis_event_ids`. Required for every terminal action, including an
    /// empty array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_event_ids: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_agent_id: Option<DidCoreId>,
}

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

/// One accepted encrypted control carrier, identified by the Event's only
/// registered keyed-set write (`typed-current-result.schema.json`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControlAssertion {
    pub tag_id: crate::exact_current_results::CanonicalEventDot,
    pub value: crate::events_payloads::sidecar::AgentSidecarExchangeControlPayload,
}

/// Closed, canonical assertion set for one native Sidecar source context.
/// Exchange identities remain encrypted inside each carrier, never in this
/// value's selector or an additional plaintext member.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeControlsCurrentValue {
    assertions: Vec<AgentSidecarExchangeControlAssertion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSidecarExchangeControlsCurrentValueWire {
    assertions: Vec<AgentSidecarExchangeControlAssertion>,
}

impl AgentSidecarExchangeControlsCurrentValue {
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

impl<'de> Deserialize<'de> for AgentSidecarExchangeControlsCurrentValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentSidecarExchangeControlsCurrentValueWire::deserialize(deserializer)?;
        Self::new(wire.assertions).map_err(serde::de::Error::custom)
    }
}

/// Track coordinate of the source-routed exchange. The same closed shape backs
/// agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref and
/// agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context/
/// properties/source_track_ref.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/$defs/source_track_ref.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarSourceTrackRef {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSidecarExchangeStatus {
    Delivered,
    Responding,
    Complete,
    Failed,
}

/// Local cache coverage. `event_ids` are the canonical sorted maximal causal
/// heads of every contributing accepted exchange fact; `event_set_digest`
/// commits to the canonical sorted complete contributing Event-id set;
/// `max_hlc` is display/cache metadata and never proves causal dominance.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/$defs/folded_checkpoint.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarFoldedCheckpoint {
    pub event_ids: Vec<EventId>,
    pub event_set_digest: Hash,
    pub max_hlc: Hlc,
}

/// Disposable controller-device-local cache for one source-routed native
/// Sidecar exchange. Every member is a deterministic fold of accepted
/// Sidecar-scoped Events: this is not wire truth, not Account Data, never
/// merged across devices, and may always be deleted and rebuilt.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-exchange-projection.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeProjection {
    pub schema: String,
    pub controller_account_id: AccountId,
    pub sidecar_id: SidecarId,
    pub exchange_id: String,
    pub source_track_ref: SidecarSourceTrackRef,
    /// Accepted Event id copied from the request context as this exchange's
    /// source Event. It identifies one Event, not a checkpoint or trust anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<EventId>,
    pub source_hlc: Hlc,
    pub client_order_key: String,
    pub addressed_agent_ids: Vec<DidCoreId>,
    pub coordinator_agent_id: DidCoreId,
    pub coordinator_assignment_event_id: EventId,
    pub participating_agent_ids: Vec<DidCoreId>,
    pub private_request_event_id: EventId,
    pub user_facing_response_event_ids: Vec<EventId>,
    pub status: AgentSidecarExchangeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason_code: Option<String>,
    /// Controller-authored `ak.agent.sidecar.exchange.control` Event that
    /// produced `complete` or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_event_id: Option<EventId>,
    pub folded_checkpoint: AgentSidecarFoldedCheckpoint,
}

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

/// Write-once exchange identity carried only on `role=request`. Any controller
/// device rebuilding the projection copies these values verbatim, so
/// cross-device bit-identity is anchored to the accepted request Event instead
/// of device-local state.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-event-exchange-binding.schema.json#/$defs/request_context.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarExchangeRequestContext {
    pub source_track_ref: SidecarSourceTrackRef,
    pub source_hlc: Hlc,
    pub client_order_key: String,
    pub addressed_agent_ids: Vec<DidCoreId>,
    /// Initial coordinator. It must be one of `addressed_agent_ids`, and may be
    /// omitted only when that array holds exactly one item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_agent_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_checkpoint_anchor_id: Option<EventId>,
}

/// Closed typed binding tying one native-Sidecar-scoped Message event to one
/// source-routed exchange. It is legal only inside encrypted metadata plaintext
/// of an event whose `scope_ref.kind` is `sidecar`, and it is the only
/// normative way to declare an explicit user-facing response; invalid or absent
/// bindings are non-echo.
// Field declaration order is byte-for-byte the properties order of
// agent-sidecar-event-exchange-binding.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarEventExchangeBinding {
    pub schema: String,
    /// Opaque controller-private idempotency identity copied verbatim from the
    /// request binding. It is not a Sidecar locator and must not appear on any
    /// public or shared surface.
    pub exchange_id: String,
    pub role: AgentSidecarExchangeRole,
    /// Accepted Event id of the private request event of the same exchange.
    /// Event id is the only canonical reference form here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_id: Option<EventId>,
    /// Coordinator completion request; legal only with
    /// `role=user_facing_response`. It does not itself make the exchange
    /// terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completes_exchange: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_assignment_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_context: Option<AgentSidecarExchangeRequestContext>,
}

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
// agent-operations.schema.json#/$defs/pending_sidecar_access_reconciliation_row.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSidecarAccessReconciliation {
    pub agent_id: DidCoreId,
    pub provisioning_phase: SidecarAccessProvisioningPhase,
}

/// Upper bound of `authority_stream_head`, equal to the MLS governance binding
/// decoder `maximum_collection_items`.
pub const SIDECAR_AUTHORITY_STREAM_HEAD_MAX_ITEMS: usize = 64;

/// Domain member for the signed Sidecar participant-authority transcript.
pub const SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN: &str = "ak.sidecar.participant_authority.v1";

#[derive(Serialize)]
struct SidecarParticipantAuthorityTranscript<'a> {
    domain: &'static str,
    sidecar_id: &'a SidecarId,
    realm_id: &'a RealmId,
    controller_account_id: &'a AccountId,
    desired_agent_ids: Vec<DidCoreId>,
}

/// Compute the canonical participant-authority digest for one Sidecar.
///
/// `desired_agent_ids` is normalized by UTF-8 byte order before the exact
/// five-member transcript is hashed. The effective MLS roster and authority
/// stream head are deliberately not part of this digest.
pub fn sidecar_participant_authority_digest(
    sidecar_id: &SidecarId,
    realm_id: &RealmId,
    controller_account_id: &AccountId,
    desired_agent_ids: &[DidCoreId],
) -> Result<Hash> {
    controller_account_id.validate()?;
    let mut desired_agent_ids = desired_agent_ids.to_vec();
    desired_agent_ids
        .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    desired_agent_ids.dedup_by(|left, right| left.as_str() == right.as_str());

    Hash::new(arkret_canonical::canonical_sha256(
        &SidecarParticipantAuthorityTranscript {
            domain: SIDECAR_PARTICIPANT_AUTHORITY_DOMAIN,
            sidecar_id,
            realm_id,
            controller_account_id,
            desired_agent_ids,
        },
    )?)
    .map_err(Into::into)
}

/// Return the canonical Sidecar authority cut: UTF-8 sorted, deduplicated and
/// bounded to the MLS governance-binding decoder's 64-item limit.
pub fn normalize_sidecar_authority_stream_head(authority_refs: &[EventId]) -> Result<Vec<EventId>> {
    let mut normalized = authority_refs.to_vec();
    normalized.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    normalized.dedup_by(|left, right| left.as_str() == right.as_str());
    if normalized.is_empty() || normalized.len() > SIDECAR_AUTHORITY_STREAM_HEAD_MAX_ITEMS {
        return Err(WireError::Protocol(
            "sidecar MLS authority refs must normalize to 1..=64 items".to_owned(),
        ));
    }
    Ok(normalized)
}

/// MLS coordinates of one Sidecar scope. The MLS scope is plaintext before its
/// own accepted `ak.mls.genesis` and irreversibly activates to standard
/// RFC 9420 afterwards.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_sidecar_mls_context.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarMlsContext {
    pub participant_authority_digest: Hash,
    /// UTF-8 byte-lexicographically sorted accepted refs for Sidecar genesis,
    /// ownership, Agent lifecycle/runtime-key authorization, and exact Realm
    /// membership. Action grants, participation selections and key-readiness
    /// results are excluded.
    pub authority_stream_head: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_event_ref: Option<String>,
    /// True only when the authenticated controller session device is the
    /// accepted genesis creator device or has completed matching Welcome and
    /// KeyPackage consume evidence.
    pub current_controller_device_ready: bool,
}

impl AgentSidecarMlsContext {
    pub fn validate_shape(&self) -> Result<()> {
        if self.authority_stream_head.is_empty()
            || self.authority_stream_head.len() > SIDECAR_AUTHORITY_STREAM_HEAD_MAX_ITEMS
        {
            return Err(WireError::Protocol(
                "sidecar MLS context carries 1..=64 authority refs".to_owned(),
            ));
        }
        if self
            .authority_stream_head
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(WireError::Protocol(
                "sidecar MLS authority refs must be sorted and unique".to_owned(),
            ));
        }
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
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&event_id(1))
    }

    fn event_id(byte: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    fn sidecar_id() -> SidecarId {
        SidecarId::from_event_id(&event_id(2))
    }

    fn strand_id() -> StrandId {
        StrandId::from_event_id(&event_id(3))
    }

    fn account_id() -> serde_json::Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
            "station_id": "ak:did_core:web:station.example"
        })
    }

    fn typed_account_id() -> AccountId {
        serde_json::from_value(account_id()).unwrap()
    }

    const AGENT_ID: &str = "ak:did_core:webvh:z6mkfixture:agent.example";
    const EXCHANGE_ID: &str = "exchange-fixture-0000001";
    const HLC: &str = "0198ff000000-0001-0a0b0c0d";

    #[test]
    fn encrypted_control_current_is_closed_sorted_and_context_bound() {
        use crate::exact_current_results::CanonicalEventDot;
        let entry = |byte| {
            AgentSidecarExchangeControlAssertion {
            tag_id: CanonicalEventDot::new(event_id(byte), 0).unwrap(),
            value: serde_json::from_value(json!({
                "sidecar_id": sidecar_id(),
                "source_context_ref": {"kind":"strand","strand_id":strand_id()},
                "encrypted_payload": {"version":"1.0","content_type":"application/vnd.arkret.agent-sidecar-exchange-control+json",
                    "encryption_context":{"epoch":1,"group_state_ref":event_id(7)},"ciphertext":"AQIDBA"}
            })).unwrap(),
        }
        };
        let mut entries = vec![entry(4), entry(5)];
        entries.sort_by(|a, b| a.tag_id.cmp(&b.tag_id));
        let current = AgentSidecarExchangeControlsCurrentValue::new(entries.clone()).unwrap();
        let encoded = serde_json::to_value(&current).unwrap();
        assert_eq!(
            serde_json::from_value::<AgentSidecarExchangeControlsCurrentValue>(encoded.clone())
                .unwrap(),
            current
        );
        let mut unknown = encoded;
        unknown["exchange_id"] = json!(EXCHANGE_ID);
        assert!(
            serde_json::from_value::<AgentSidecarExchangeControlsCurrentValue>(unknown).is_err()
        );
        entries.reverse();
        assert!(AgentSidecarExchangeControlsCurrentValue::new(entries).is_err());
        assert!(current.clone().with_assertion(entry(4)).is_err());
        let mut wrong_dot = entry(6);
        wrong_dot.tag_id = CanonicalEventDot::new(event_id(6), 1).unwrap();
        assert!(current.clone().with_assertion(wrong_dot).is_err());
        assert!(
            current
                .validate_for_context(
                    &SidecarId::from_event_id(&event_id(8)),
                    &arkret_wire::SidecarContextRef::Strand {
                        strand_id: strand_id()
                    }
                )
                .is_err()
        );
        let selector = arkret_wire::CurrentSelector::AgentSidecarExchangeControls {
            sidecar_id: sidecar_id(),
            source_context_ref: arkret_wire::SidecarContextRef::Strand {
                strand_id: strand_id(),
            },
        };
        assert_eq!(
            serde_json::from_value::<arkret_wire::CurrentSelector>(
                serde_json::to_value(&selector).unwrap()
            )
            .unwrap(),
            selector
        );
    }

    #[test]
    fn exchange_control_rejects_noncanonical_sets_and_invalid_tokens() {
        let mut control: AgentSidecarExchangeControl =
            serde_json::from_value(control_value()).unwrap();
        control.validate_shape().unwrap();
        control
            .basis_event_ids
            .push(control.basis_event_ids[0].clone());
        assert!(control.validate_shape().is_err());
        control.basis_event_ids.pop();
        control.exchange_id = "too-short".to_owned();
        assert!(control.validate_shape().is_err());
        control.exchange_id = "opaque.exchange~=0000000001".to_owned();
        control.validate_shape().unwrap();
    }

    fn sidecar_value() -> serde_json::Value {
        json!({
            "id": sidecar_id(),
            "schema": "ak.schema.agent_sidecar.v1",
            "realm_id": realm_id(),
            "controller_account_id": account_id(),
            "state": "active",
            "created_at": "2026-08-01T00:00:00.000Z"
        })
    }

    #[test]
    fn agent_sidecar_round_trips_and_is_closed() {
        let value = sidecar_value();
        let parsed: AgentSidecar = serde_json::from_value(value.clone()).expect("closed sidecar");
        parsed.validate_shape().expect("valid sidecar");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("encryption_profile".to_owned(), json!("x"));
        assert!(serde_json::from_value::<AgentSidecar>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("realm_id");
        assert!(serde_json::from_value::<AgentSidecar>(missing).is_err());
    }

    #[test]
    fn suspended_sidecar_requires_state_changed_at() {
        let mut value = sidecar_value();
        value["state"] = json!("suspended");
        let parsed: AgentSidecar = serde_json::from_value(value.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        value["state_changed_at"] = json!("2026-08-02T00:00:00.000Z");
        let parsed: AgentSidecar = serde_json::from_value(value).expect("shape parses");
        parsed.validate_shape().expect("suspended sidecar is valid");
    }

    #[test]
    fn view_state_round_trips_and_is_closed() {
        let value = json!({
            "schema": "ak.schema.agent_sidecar_view_state.v1",
            "controller_account_id": account_id(),
            "sidecar_id": sidecar_id(),
            "context_ref": {"realm_id": realm_id(), "strand_id": strand_id()},
            "updated_hlc": HLC,
            "origin_device_id": "ak:device:0198ff00-0000-7000-8000-00000000000a"
        });
        let parsed: AgentSidecarViewState =
            serde_json::from_value(value.clone()).expect("closed view state");
        parsed.validate_shape().expect("valid view state");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("sidecar_control_frontier".to_owned(), json!([]));
        assert!(serde_json::from_value::<AgentSidecarViewState>(unknown).is_err());

        for mode in ["context_merged", "sidecar_only"] {
            let mut obsolete = value.clone();
            obsolete["display_mode"] = json!(mode);
            assert!(serde_json::from_value::<AgentSidecarViewState>(obsolete).is_err());
        }

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("updated_hlc");
        assert!(serde_json::from_value::<AgentSidecarViewState>(missing).is_err());
    }

    fn control_value() -> serde_json::Value {
        json!({
            "schema": "ak.schema.agent_sidecar_exchange_control.v1",
            "exchange_id": EXCHANGE_ID,
            "request_event_id": event_id(4),
            "basis_event_ids": [event_id(4), event_id(5)],
            "action": "close",
            "response_event_ids": [event_id(5)]
        })
    }

    #[test]
    fn exchange_control_round_trips_and_is_closed() {
        let value = control_value();
        let parsed: AgentSidecarExchangeControl =
            serde_json::from_value(value.clone()).expect("closed control");
        parsed.validate_shape().expect("valid control");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("control_proposal".to_owned(), json!({}));
        assert!(serde_json::from_value::<AgentSidecarExchangeControl>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("action");
        assert!(serde_json::from_value::<AgentSidecarExchangeControl>(missing).is_err());
    }

    #[test]
    fn terminal_and_reassign_controls_carry_disjoint_members() {
        let mut fail = control_value();
        fail["action"] = json!("fail");
        let parsed: AgentSidecarExchangeControl =
            serde_json::from_value(fail.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());
        fail["failure_reason_code"] = json!("agent_unavailable");
        let parsed: AgentSidecarExchangeControl =
            serde_json::from_value(fail).expect("shape parses");
        parsed.validate_shape().expect("fail control is valid");

        let mut reassign = control_value();
        reassign["action"] = json!("reassign_coordinator");
        let parsed: AgentSidecarExchangeControl =
            serde_json::from_value(reassign.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        reassign
            .as_object_mut()
            .unwrap()
            .remove("response_event_ids");
        reassign["expected_coordinator_agent_id"] = json!(AGENT_ID);
        reassign["coordinator_agent_id"] = json!(AGENT_ID);
        let parsed: AgentSidecarExchangeControl =
            serde_json::from_value(reassign).expect("shape parses");
        parsed.validate_shape().expect("reassign control is valid");
    }

    fn projection_value() -> serde_json::Value {
        json!({
            "schema": "ak.schema.agent_sidecar_exchange_projection.v1",
            "controller_account_id": account_id(),
            "sidecar_id": sidecar_id(),
            "exchange_id": EXCHANGE_ID,
            "source_track_ref": {
                "realm_id": realm_id(),
                "strand_id": strand_id(),
                "track_name": "main"
            },
            "source_hlc": HLC,
            "client_order_key": "order-1",
            "addressed_agent_ids": [AGENT_ID],
            "coordinator_agent_id": AGENT_ID,
            "coordinator_assignment_event_id": event_id(4),
            "participating_agent_ids": [AGENT_ID],
            "private_request_event_id": event_id(4),
            "user_facing_response_event_ids": [],
            "status": "delivered",
            "folded_checkpoint": {
                "event_ids": [event_id(4)],
                "event_set_digest": format!("sha256:{}", "ab".repeat(32)),
                "max_hlc": HLC
            }
        })
    }

    #[test]
    fn exchange_projection_round_trips_and_is_closed() {
        let value = projection_value();
        let parsed: AgentSidecarExchangeProjection =
            serde_json::from_value(value.clone()).expect("closed projection");
        parsed.validate_shape().expect("valid projection");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("cas_revision".to_owned(), json!(2));
        assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("folded_checkpoint");
        assert!(serde_json::from_value::<AgentSidecarExchangeProjection>(missing).is_err());
    }

    #[test]
    fn failed_projection_carries_no_responses() {
        let mut value = projection_value();
        value["status"] = json!("failed");
        value["user_facing_response_event_ids"] = json!([event_id(5)]);
        value["failure_reason_code"] = json!("agent_unavailable");
        value["terminal_event_id"] = json!(event_id(6));
        let parsed: AgentSidecarExchangeProjection =
            serde_json::from_value(value.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        value["user_facing_response_event_ids"] = json!([]);
        let parsed: AgentSidecarExchangeProjection =
            serde_json::from_value(value).expect("shape parses");
        parsed.validate_shape().expect("failed projection is valid");
    }

    #[test]
    fn request_binding_carries_only_its_request_context() {
        let value = json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": EXCHANGE_ID,
            "role": "request",
            "request_context": {
                "source_track_ref": {
                    "realm_id": realm_id(),
                    "strand_id": strand_id(),
                    "track_name": "main"
                },
                "source_hlc": HLC,
                "client_order_key": "order-1",
                "addressed_agent_ids": [AGENT_ID]
            }
        });
        let parsed: AgentSidecarEventExchangeBinding =
            serde_json::from_value(value.clone()).expect("closed binding");
        parsed.validate_shape().expect("valid request binding");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut with_event = value.clone();
        with_event["request_event_id"] = json!(event_id(4));
        let parsed: AgentSidecarEventExchangeBinding =
            serde_json::from_value(with_event).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("message_id".to_owned(), json!("x"));
        assert!(serde_json::from_value::<AgentSidecarEventExchangeBinding>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("role");
        assert!(serde_json::from_value::<AgentSidecarEventExchangeBinding>(missing).is_err());
    }

    #[test]
    fn completion_request_needs_its_coordinator_assignment() {
        let mut value = json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": EXCHANGE_ID,
            "role": "user_facing_response",
            "request_event_id": event_id(4),
            "completes_exchange": true
        });
        let parsed: AgentSidecarEventExchangeBinding =
            serde_json::from_value(value.clone()).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        value["coordinator_assignment_event_id"] = json!(event_id(7));
        let parsed: AgentSidecarEventExchangeBinding =
            serde_json::from_value(value).expect("shape parses");
        parsed
            .validate_shape()
            .expect("completion binding is valid");
    }

    #[test]
    fn mls_context_group_members_travel_together() {
        let value = json!({
            "participant_authority_digest": format!("sha256:{}", "cd".repeat(32)),
            "authority_stream_head": [event_id(8)],
            "current_controller_device_ready": false
        });
        let parsed: AgentSidecarMlsContext =
            serde_json::from_value(value.clone()).expect("closed context");
        parsed.validate_shape().expect("pre-activation context");
        assert!(!parsed.is_mls_activated());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut partial = value.clone();
        partial["mls_group_id"] = json!("c2lkZWNhcg");
        let parsed: AgentSidecarMlsContext = serde_json::from_value(partial).expect("shape parses");
        assert!(parsed.validate_shape().is_err());

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("encryption_floor".to_owned(), json!("x"));
        assert!(serde_json::from_value::<AgentSidecarMlsContext>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("current_controller_device_ready");
        assert!(serde_json::from_value::<AgentSidecarMlsContext>(missing).is_err());
    }

    #[test]
    fn mls_context_authority_stream_head_is_bounded() {
        let mut head = (0..=64_u8).map(event_id).collect::<Vec<_>>();
        head.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut context = AgentSidecarMlsContext {
            participant_authority_digest: Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
            authority_stream_head: head,
            mls_group_id: None,
            epoch: None,
            genesis_event_ref: None,
            current_controller_device_ready: false,
        };
        assert!(context.validate_shape().is_err());
        context.authority_stream_head.pop();
        context
            .validate_shape()
            .expect("64 refs fit the decoder bound");
    }

    #[test]
    fn participant_authority_digest_normalizes_desired_agents_and_matches_kat() {
        let agent_a = DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent-a.example").unwrap();
        let agent_b = DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent-b.example").unwrap();
        let unordered = vec![agent_b.clone(), agent_a.clone(), agent_b];
        let digest = sidecar_participant_authority_digest(
            &SidecarId::new("ak:sidecar:AZUfzdx1qBOtCsg2CGmS3QLP7vlDe_kxRx0pxdxefWTa").unwrap(),
            &RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap(),
            &typed_account_id(),
            &unordered,
        )
        .unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:8dd408915026b3c60d80b0d4f8959196ea9efcdcfff0f8227c3ba97fcc6224d6"
        );
        assert_eq!(
            digest,
            sidecar_participant_authority_digest(
                &SidecarId::new("ak:sidecar:AZUfzdx1qBOtCsg2CGmS3QLP7vlDe_kxRx0pxdxefWTa",)
                    .unwrap(),
                &RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",).unwrap(),
                &typed_account_id(),
                &[
                    agent_a,
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent-b.example",).unwrap(),
                ],
            )
            .unwrap()
        );
    }

    #[test]
    fn authority_stream_head_normalizer_sorts_deduplicates_and_bounds() {
        let normalized = normalize_sidecar_authority_stream_head(&[
            event_id(3),
            event_id(1),
            event_id(3),
            event_id(2),
        ])
        .unwrap();
        assert_eq!(normalized.len(), 3);
        assert!(
            normalized
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str())
        );
        assert!(normalize_sidecar_authority_stream_head(&[]).is_err());

        let too_many = (0..=64_u8).map(event_id).collect::<Vec<_>>();
        assert!(normalize_sidecar_authority_stream_head(&too_many).is_err());
    }

    #[test]
    fn pending_reconciliation_item_round_trips_and_is_closed() {
        let value = json!({"agent_id": AGENT_ID, "provisioning_phase": "mls_welcome"});
        let parsed: PendingSidecarAccessReconciliation =
            serde_json::from_value(value.clone()).expect("closed item");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        assert!(
            serde_json::from_value::<PendingSidecarAccessReconciliation>(
                json!({"agent_id": AGENT_ID, "provisioning_phase": "mls_welcome", "reason": "x"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<PendingSidecarAccessReconciliation>(
                json!({"agent_id": AGENT_ID})
            )
            .is_err()
        );
    }
}
