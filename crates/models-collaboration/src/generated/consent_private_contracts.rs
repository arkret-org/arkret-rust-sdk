//! @generated; do not edit by hand.
//! Generator: tools/generate-closed-models.py
//!
//! Input: schemas/consent-private-operations.schema.json
//! sha256=3287e8cd6cf6fba95c82b87ec67eb4ed409e68e81afe14a57acbf2e208872627
//!
//! Bindings: tools/closed-model-bindings.json
//! sha256=107c58e1dbd8a2701005c9cd1dc573b3c5e861cc4f3c68403bae0ff3d579bd03

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/holder_session_context/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateHolderSessionContextKind {
    #[serde(rename = "holder_session")]
    HolderSession,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/holder_session_context`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateHolderSessionContext {
    pub kind: ConsentPrivateHolderSessionContextKind,
    pub actor_id: arkret_wire::ActorId,
    pub device_id: arkret_wire::DeviceId,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/station_context/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateStationContextKind {
    #[serde(rename = "station")]
    Station,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/station_context`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateStationContext {
    pub kind: ConsentPrivateStationContextKind,
    pub actor_id: arkret_wire::ActorId,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/proxy_request_body/properties/context`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConsentPrivateContext {
    HolderSession(ConsentPrivateHolderSessionContext),
    Station(ConsentPrivateStationContext),
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/list_command/properties/body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEmptyBody {}

/// Counterpart: `consent-private-operations.schema.json#/$defs/list_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateListCommandKind {
    #[serde(rename = "list")]
    List,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/list_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateListCommand {
    pub kind: ConsentPrivateListCommandKind,
    pub body: ConsentPrivateEmptyBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/version_command/properties/body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateVersionBody {
    pub peer: crate::events_payloads::consent::ConsentPeer,
    pub event_id: arkret_wire::EventId,
    pub commit_id: arkret_wire::RealmCommitId,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/version_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateVersionCommandKind {
    #[serde(rename = "version")]
    Version,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/version_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateVersionCommand {
    pub kind: ConsentPrivateVersionCommandKind,
    pub body: ConsentPrivateVersionBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/effects_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateEffectsCommandKind {
    #[serde(rename = "effects")]
    Effects,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/effects_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEffectsCommand {
    pub kind: ConsentPrivateEffectsCommandKind,
    pub body: ConsentPrivateEmptyBody,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/invite_policy_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateInvitePolicyCommandKind {
    #[serde(rename = "invite_policy")]
    InvitePolicy,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/invite_policy_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInvitePolicyCommand {
    pub kind: ConsentPrivateInvitePolicyCommandKind,
    pub body: crate::governance::invite_addressing::InviteReceivePolicy,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/invite_delivery_command/properties/body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInviteDeliveryBody {
    pub notification_source_service_id: arkret_wire::DidCoreId,
    pub delivery: crate::governance::invite_addressing::InviteDeliveryRequestBody,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/invite_delivery_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateInviteDeliveryCommandKind {
    #[serde(rename = "invite_delivery")]
    InviteDelivery,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/invite_delivery_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInviteDeliveryCommand {
    pub kind: ConsentPrivateInviteDeliveryCommandKind,
    pub body: ConsentPrivateInviteDeliveryBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/request_command/properties/body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateRequestBody {
    pub requester_actor_id: arkret_wire::ActorId,
    pub request: crate::consent_operations::ConsentRequestRequestBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/request_command/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateRequestCommandKind {
    #[serde(rename = "request")]
    Request,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/request_command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateRequestCommand {
    pub kind: ConsentPrivateRequestCommandKind,
    pub body: ConsentPrivateRequestBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/command`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
#[serde(untagged)]
pub enum ConsentPrivateCommand {
    List(ConsentPrivateListCommand),
    Version(ConsentPrivateVersionCommand),
    Effects(ConsentPrivateEffectsCommand),
    InvitePolicy(ConsentPrivateInvitePolicyCommand),
    InviteDelivery(ConsentPrivateInviteDeliveryCommand),
    Request(ConsentPrivateRequestCommand),
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_response_body/properties/body/properties/
/// holder_quarantine/oneOf/0`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateHolderQuarantineCell {
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub revision: u64,
    pub content: crate::governance::holder_quarantine::HolderQuarantine,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_response_body/properties/body/properties/
/// invite_delivery/oneOf/0`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInviteDeliveryCell {
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub revision: u64,
    pub content: crate::governance::invite_addressing::InviteDelivery,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_response_body/properties/body/properties/
/// invite_receive_policy/oneOf/0`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInviteReceivePolicyCell {
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub revision: u64,
    pub content: crate::governance::invite_addressing::InviteReceivePolicy,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_response_body/properties/body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEffects {
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub holder_quarantine: Option<ConsentPrivateHolderQuarantineCell>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub invite_delivery: Option<ConsentPrivateInviteDeliveryCell>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_required_nullable")]
    pub invite_receive_policy: Option<ConsentPrivateInviteReceivePolicyCell>,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/list_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateListOutcomeKind {
    #[serde(rename = "list")]
    List,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/list_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateListResponseBody {
    pub kind: ConsentPrivateListOutcomeKind,
    pub body: crate::consent_operations::ConsentList,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/version_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateVersionOutcomeKind {
    #[serde(rename = "version")]
    Version,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/version_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateVersionResponseBody {
    pub kind: ConsentPrivateVersionOutcomeKind,
    pub body: crate::consent_operations::ConsentView,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateEffectsOutcomeKind {
    #[serde(rename = "effects")]
    Effects,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/effects_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEffectsResponseBody {
    pub kind: ConsentPrivateEffectsOutcomeKind,
    pub body: ConsentPrivateEffects,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/invite_policy_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateInvitePolicyOutcomeKind {
    #[serde(rename = "invite_policy")]
    InvitePolicy,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/invite_policy_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInvitePolicyResponseBody {
    pub kind: ConsentPrivateInvitePolicyOutcomeKind,
    pub body: ConsentPrivateInviteReceivePolicyCell,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/invite_delivery_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateInviteDeliveryOutcomeKind {
    #[serde(rename = "invite_delivery")]
    InviteDelivery,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/invite_delivery_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateInviteDeliveryResponseBody {
    pub kind: ConsentPrivateInviteDeliveryOutcomeKind,
    pub body: crate::governance::invite_addressing::InviteDeliveryResponseBody,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/request_response_body/properties/kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateRequestOutcomeKind {
    #[serde(rename = "request")]
    Request,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/request_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateRequestResponseBody {
    pub kind: ConsentPrivateRequestOutcomeKind,
    pub body: crate::consent_operations::ConsentRequestResponseBody,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/command_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConsentPrivateCommandResponseBody {
    List(ConsentPrivateListResponseBody),
    Version(ConsentPrivateVersionResponseBody),
    Effects(ConsentPrivateEffectsResponseBody),
    InvitePolicy(ConsentPrivateInvitePolicyResponseBody),
    InviteDelivery(ConsentPrivateInviteDeliveryResponseBody),
    Request(ConsentPrivateRequestResponseBody),
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/proxy_request_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateProxyRequestBody {
    pub holder_account_id: arkret_wire::AccountId,
    pub realm_id: arkret_wire::RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub nonce: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub context: ConsentPrivateContext,
    pub command: ConsentPrivateCommand,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/proxy_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateProxyResponseBody {
    pub request_digest: String,
    pub realm_id: arkret_wire::RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub effective_stream_head: arkret_wire::CommitStreamHead,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub response_body: ConsentPrivateCommandResponseBody,
}

/// Counterpart:
/// `consent-private-operations.schema.json#/$defs/effects_publish_response_body/properties/status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsentPrivateEffectsPublishStatus {
    #[serde(rename = "applied")]
    Applied,
    #[serde(rename = "duplicate")]
    Duplicate,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/effects_publish_request_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEffectsPublishRequestBody {
    pub holder_account_id: arkret_wire::AccountId,
    pub realm_id: arkret_wire::RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub nonce: String,
    pub effective_stream_head: arkret_wire::CommitStreamHead,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub effects: ConsentPrivateEffects,
}

/// Counterpart: `consent-private-operations.schema.json#/$defs/effects_publish_response_body`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPrivateEffectsPublishResponseBody {
    pub request_digest: String,
    pub status: ConsentPrivateEffectsPublishStatus,
}
