//! Event wire schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/disappearing-messages.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisappearingMessages {
    MessageExpiry(MessageExpiry),
    DisappearingPolicy(DisappearingPolicy),
}

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeAad {
    pub realm_id: RealmId,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_ref_digests: Option<Vec<Hash>>,
}

impl EncryptedEnvelopeAad {
    /// Build the minimal AAD allowed for hidden event-id visibility.
    pub fn hidden(realm_id: RealmId, event_kind: impl Into<String>) -> Self {
        Self {
            realm_id,
            event_kind: event_kind.into(),
            event_id: None,
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedEnvelopeAadVisibility {
    Hidden,
    RoutingDigest,
    OpaqueId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedEnvelopeKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
    #[serde(rename = "MLS-EXPORTER-AEAD")]
    MlsExporterAead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedEnvelopeGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeKeyRef {
    pub algorithm: EncryptedEnvelopeKeyAlgorithm,
    pub group_state_ref: EncryptedEnvelopeGroupStateRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub scheme: EncryptedPayloadScheme,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: EncryptedEnvelopeAadVisibility,
    pub aad: EncryptedEnvelopeAad,
    pub key_ref: EncryptedEnvelopeKeyRef,
    pub payload_digest: Hash,
    pub aad_digest: Hash,
}

impl EncryptedEnvelope {
    pub fn validate(&self) -> Result<()> {
        if !major_minor_version(&self.version) {
            return Err(Error::Protocol(
                "encrypted envelope version must be major.minor".to_owned(),
            ));
        }
        if !base64url_token(&self.group_id) {
            return Err(Error::Protocol(
                "encrypted envelope group_id is invalid".to_owned(),
            ));
        }
        if !content_type_token(&self.content_type) {
            return Err(Error::Protocol(
                "encrypted envelope content_type is invalid".to_owned(),
            ));
        }
        if !base64url_token(&self.ciphertext) {
            return Err(Error::Protocol(
                "encrypted envelope ciphertext is invalid".to_owned(),
            ));
        }
        let expected_algorithm = match self.scheme {
            EncryptedPayloadScheme::MlsRfc9420 => EncryptedEnvelopeKeyAlgorithm::Mls,
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                EncryptedEnvelopeKeyAlgorithm::MlsExporterAead
            }
        };
        if self.key_ref.algorithm != expected_algorithm {
            return Err(Error::Protocol(
                "encrypted envelope key_ref.algorithm does not match scheme".to_owned(),
            ));
        }
        if self.aad.causal_refs.is_some() && self.aad.causal_ref_digests.is_some() {
            return Err(Error::Protocol(
                "encrypted envelope aad cannot carry both causal_refs and causal_ref_digests"
                    .to_owned(),
            ));
        }
        match self.aad_visibility_event_id {
            EncryptedEnvelopeAadVisibility::Hidden => {
                if self.aad.event_id.is_some() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "hidden encrypted envelope aad forbids event identifiers".to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::RoutingDigest => {
                if self.aad.event_ref_digest.is_none() || self.aad.event_id.is_some() {
                    return Err(Error::Protocol(
                        "routing_digest encrypted envelope aad requires event_ref_digest only"
                            .to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::OpaqueId => {
                if self.aad.event_id.is_none() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "opaque_id encrypted envelope aad requires event_id only".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `major.minor` numeric version token (e.g. `1.0`); both parts non-empty and
/// ASCII-digit only. Shared wire-token validator (reused by `arkret-sdk`).
pub fn major_minor_version(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

/// Non-empty base64url token (`[A-Za-z0-9_-]+`, no padding). Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `type/subtype` content-type token with restricted byte alphabet. Shared
/// wire-token validator (reused by `arkret-sdk`).
pub fn content_type_token(value: &str) -> bool {
    let Some((ty, subtype)) = value.split_once('/') else {
        return false;
    };
    !ty.is_empty()
        && !subtype.is_empty()
        && ty.bytes().all(content_type_byte)
        && subtype.bytes().all(content_type_byte)
}

/// Admissible byte inside a [`content_type_token`] segment. Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn content_type_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'+' | b'-')
}

/// Counterpart for `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/subject_ref`.
pub type SubjectRef = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/verification_stub`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSubject {
    pub kind: String,
    pub subject_ref: SubjectRef,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubScope {
    pub storage_boundary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_refs: Option<Vec<SubjectRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_scope: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStubSealInclusion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStub {
    pub stub_schema: String,
    pub subject: VerificationStubSubject,
    pub scope: VerificationStubScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_digests: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_inclusion: Option<VerificationStubSealInclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_authorization_ref: Option<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold_ref: Option<LegalHoldRef>,
    pub receipt_id: String,
    pub completed_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum EventBatchReceiptScope {
    DeviceReanchor(DeviceReanchorReceiptScope),
    Ordinary(EventBatchOrdinaryReceiptScope),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventBatchOrdinaryReceiptScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum DeviceReanchorReceiptScopeKind {
    #[serde(rename = "device_reanchor_unit")]
    DeviceReanchorUnit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceReanchorReceiptScope {
    pub kind: DeviceReanchorReceiptScopeKind,
    pub principal_id: Did,
    pub realm_id: RealmId,
    pub did_version_id: NonEmptyString,
    pub registry_head: Hash,
    pub reanchor_digest: Hash,
    pub replacement_authorize_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptFrontier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceipt {
    pub schema: String,
    pub receipt_id: ReceiptId,
    pub issuer: Did,
    pub scope: EventBatchReceiptScope,
    pub frontier: EventBatchReceiptFrontier,
    pub events: Vec<EventBatchReceiptEvent>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum EventBatchReceiptEvent {
    Event(EventId),
    Digest(Hash),
    Item(EventBatchReceiptItem),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EventBatchReceiptItem {
    pub event_id: EventId,
    pub event_digest: Hash,
    pub kind: NonEmptyString,
}

impl EventBatchReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "ak.schema.event_batch_receipt.v1" {
            return Err(Error::Protocol(
                "event batch receipt schema must be ak.schema.event_batch_receipt.v1".to_owned(),
            ));
        }
        if self.events.is_empty() || self.proofs.is_empty() {
            return Err(Error::Protocol(
                "event batch receipt requires events and proofs".to_owned(),
            ));
        }
        if self.frontier.actor_seq.is_none()
            && self.frontier.event_id.is_none()
            && self.frontier.event_digest.is_none()
            && self.frontier.hlc.is_none()
        {
            return Err(Error::Protocol(
                "event batch receipt frontier must not be empty".to_owned(),
            ));
        }
        match &self.scope {
            EventBatchReceiptScope::Ordinary(scope) => {
                if scope.actor_id.is_none()
                    && scope.realm_id.is_none()
                    && scope.query_digest.is_none()
                {
                    return Err(Error::Protocol(
                        "event batch receipt ordinary scope must not be empty".to_owned(),
                    ));
                }
            }
            EventBatchReceiptScope::DeviceReanchor(scope) => {
                let [
                    EventBatchReceiptEvent::Item(reanchor),
                    EventBatchReceiptEvent::Item(authorize),
                ] = self.events.as_slice()
                else {
                    return Err(Error::Protocol(
                        "device reanchor receipt must contain exactly two typed event items"
                            .to_owned(),
                    ));
                };
                if reanchor.kind.as_str() != "ak.device.reanchor"
                    || authorize.kind.as_str() != "ak.device.authorize"
                    || reanchor.event_digest != scope.reanchor_digest
                    || authorize.event_digest != scope.replacement_authorize_digest
                {
                    return Err(Error::Protocol(
                        "device reanchor receipt event binding mismatch".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/board_space_id`.
pub type BoardSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/event_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProof {
    pub kind: String,
    pub verification_method: Did,
    pub alg: String,
    pub event_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<EventProofAudience>,
    pub jws: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventProofAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LegalHoldRef {
    PolicyId(PolicyId),
    Hash(Hash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLifecycleState {
    Active,
    Redacted,
}

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/feature_ref`.
pub type FeatureRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/grant_ref`.
pub type GrantRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/list_space_id`.
pub type ListSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/profile_ref`.
pub type ProfileRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/rank`.
pub type Rank = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/track_name`.
pub type TrackName = String;

/// Counterpart for `spec/v1/artifacts/schemas/message.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: MessageId,
    pub schema: String,
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    pub track_name: MessageTrackName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    pub state: MessageLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_root: Option<MessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_ref: Option<EventId>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}
