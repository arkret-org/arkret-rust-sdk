//! Encrypted event envelope counterpart for `encrypted-envelope.schema.json`.
//!
//! The wire envelope is intentionally minimal. Cryptographic code reconstructs
//! the closed pre-encryption header from the signed outer Event, the exact
//! winning MLS group state, and the envelope's small encryption context.

use arkret_canonical::canonical;
use arkret_wire::{
    EncryptedPayloadScheme, EventId, Hash, MlsGroupId, Result, SchemaId, ScopeRef, WireError,
    event_kind_str,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Purpose fixed by `encryption-and-audit.md` §2.3 for RFC 9420 content.
pub const EVENT_CONTENT_ENCRYPTION_PURPOSE: &str = "arkret_event_content";

/// Canonical JSON numbers are bounded by encoding.md §1. Nonce byte width
/// does not enlarge the integer range of the envelope's JSON carrier.
pub const MAX_EVENT_CONTENT_INTEGER: u64 = 9_007_199_254_740_991;

mod content_integer {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &u64,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if *value > MAX_EVENT_CONTENT_INTEGER {
            return Err(serde::ser::Error::custom(
                "content integer exceeds the canonical JSON range",
            ));
        }
        serializer.serialize_u64(*value)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<u64, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_EVENT_CONTENT_INTEGER {
            return Err(serde::de::Error::custom(
                "content integer exceeds the canonical JSON range",
            ));
        }
        Ok(value)
    }
}

/// Reaction-only routing fields carried by the minimal encrypted envelope.
///
/// The reaction kind and hourly routing window are derived from the signed
/// outer Event and therefore are deliberately absent here.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeRoutingContext {
    pub target_ref: EventId,
    pub routing_tag: String,
}

/// Routing branch reconstructed into the authenticated pre-encryption header.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventContentRoutingContext {
    None,
    Reaction {
        target_ref: EventId,
        routing_window: u64,
        routing_tag: String,
    },
}

/// Closed authenticated-data object reconstructed before both seal and open.
///
/// None of these fields, other than the minimal encryption context, is copied
/// into the encrypted-envelope wire object.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContentPreEncryptionHeader {
    pub purpose: String,
    pub envelope_version: String,
    pub content_type: String,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub effective_scope: ScopeRef,
    pub event_kind: String,
    pub mls_group_id: MlsGroupId,
    pub epoch: u64,
    pub group_state_ref: EventId,
    pub sender_domain: String,
    pub routing_context: EventContentRoutingContext,
}

impl EventContentPreEncryptionHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct(
        envelope_version: impl Into<String>,
        content_type: impl Into<String>,
        scheme: EncryptedPayloadScheme,
        effective_scope: ScopeRef,
        event_kind: impl Into<String>,
        epoch: u64,
        group_state_ref: EventId,
        sender_domain: impl Into<String>,
        routing_context: EventContentRoutingContext,
    ) -> Result<Self> {
        let header = Self {
            purpose: EVENT_CONTENT_ENCRYPTION_PURPOSE.to_owned(),
            envelope_version: envelope_version.into(),
            content_type: content_type.into(),
            mls_group_id: effective_scope.canonical_mls_group_id()?,
            scheme,
            effective_scope,
            event_kind: event_kind.into(),
            epoch,
            group_state_ref,
            sender_domain: sender_domain.into(),
            routing_context,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<()> {
        if self.purpose != EVENT_CONTENT_ENCRYPTION_PURPOSE {
            return Err(WireError::Protocol(
                "event-content pre-encryption purpose mismatch".to_owned(),
            ));
        }
        if self.envelope_version != "1.0" || !content_type_token(&self.content_type) {
            return Err(WireError::Protocol(
                "event-content pre-encryption envelope metadata is invalid".to_owned(),
            ));
        }
        if self.mls_group_id != self.effective_scope.canonical_mls_group_id()? {
            return Err(WireError::Protocol(
                "event-content pre-encryption mls_group_id does not match effective_scope"
                    .to_owned(),
            ));
        }
        if self.event_kind.trim().is_empty() || self.sender_domain.trim().is_empty() {
            return Err(WireError::Protocol(
                "event-content pre-encryption Event kind and sender domain are required".to_owned(),
            ));
        }
        let reaction_kind = matches!(
            self.event_kind.as_str(),
            event_kind_str::REACTION_ADD | event_kind_str::REACTION_REMOVE
        );
        match (&self.routing_context, reaction_kind) {
            (EventContentRoutingContext::None, false) => {}
            (EventContentRoutingContext::Reaction { routing_tag, .. }, true)
                if fixed_base64url_token(routing_tag, 43) => {}
            _ => {
                return Err(WireError::Protocol(
                    "event-content routing context does not match the outer Event kind".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(canonical::canonical_json_bytes(self)?)
    }
}

/// Closed RFC 9420 application-message encryption context.
///
/// It is cross-checked against the exact winning `group_state_ref`; no
/// caller-supplied scheme selector exists on the wire.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum EncryptedEnvelopeEncryptionContext {
    StandardMls {
        #[serde(with = "content_integer")]
        epoch: u64,
        group_state_ref: EventId,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_routing_context"
        )]
        routing_context: Option<EncryptedEnvelopeRoutingContext>,
    },
}

fn present_routing_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<EncryptedEnvelopeRoutingContext>, D::Error> {
    EncryptedEnvelopeRoutingContext::deserialize(deserializer).map(Some)
}

impl EncryptedEnvelopeEncryptionContext {
    pub fn standard(epoch: u64, group_state_ref: EventId) -> Self {
        Self::StandardMls {
            epoch,
            group_state_ref,
            routing_context: None,
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            Self::StandardMls { epoch, .. } => *epoch,
        }
    }

    pub fn group_state_ref(&self) -> &EventId {
        match self {
            Self::StandardMls {
                group_state_ref, ..
            } => group_state_ref,
        }
    }

    pub fn routing_context(&self) -> Option<&EncryptedEnvelopeRoutingContext> {
        match self {
            Self::StandardMls {
                routing_context, ..
            } => routing_context.as_ref(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
pub struct EncryptedEnvelope {
    pub version: String,
    pub content_type: String,
    pub encryption_context: EncryptedEnvelopeEncryptionContext,
    pub ciphertext: String,
}

impl EncryptedEnvelope {
    pub const SCHEMA: &'static str = SchemaId::ENCRYPTED_ENVELOPE_V1;
    pub fn validate(&self) -> Result<()> {
        if self.encryption_context.epoch() > MAX_EVENT_CONTENT_INTEGER {
            return Err(WireError::Protocol(
                "content integer exceeds the canonical JSON range".to_owned(),
            ));
        }
        if self.version != "1.0" {
            return Err(WireError::Protocol(
                "encrypted envelope version must equal 1.0".to_owned(),
            ));
        }
        if !content_type_token(&self.content_type) {
            return Err(WireError::Protocol(
                "encrypted envelope content_type is invalid".to_owned(),
            ));
        }
        if !base64url_token(&self.ciphertext) {
            return Err(WireError::Protocol(
                "encrypted envelope ciphertext is invalid".to_owned(),
            ));
        }
        if let Some(routing) = self.encryption_context.routing_context()
            && !fixed_base64url_token(&routing.routing_tag, 43)
        {
            return Err(WireError::Protocol(
                "encrypted envelope routing_tag must be 43 base64url characters".to_owned(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_pre_encryption_header(
        &self,
        scheme: EncryptedPayloadScheme,
        effective_scope: ScopeRef,
        event_kind: impl Into<String>,
        sender_domain: impl Into<String>,
        reaction_routing_window: Option<u64>,
    ) -> Result<EventContentPreEncryptionHeader> {
        self.validate()?;
        let event_kind = event_kind.into();
        let routing_context = match (
            self.encryption_context.routing_context(),
            reaction_routing_window,
        ) {
            (None, None) => EventContentRoutingContext::None,
            (Some(wire), Some(routing_window)) => EventContentRoutingContext::Reaction {
                target_ref: wire.target_ref.clone(),
                routing_window,
                routing_tag: wire.routing_tag.clone(),
            },
            _ => {
                return Err(WireError::Protocol(
                    "encrypted envelope routing context is incomplete or unexpected".to_owned(),
                ));
            }
        };
        EventContentPreEncryptionHeader::reconstruct(
            self.version.clone(),
            self.content_type.clone(),
            scheme,
            effective_scope,
            event_kind,
            self.encryption_context.epoch(),
            self.encryption_context.group_state_ref().clone(),
            sender_domain,
            routing_context,
        )
    }

    /// Digest used only for local ciphertext caching and content-addressed
    /// references. It is not a field of the minimal wire envelope.
    pub fn payload_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Metadata<'a> {
            version: &'a str,
            content_type: &'a str,
            encryption_context: &'a EncryptedEnvelopeEncryptionContext,
        }

        self.validate()?;
        let mut preimage = canonical::canonical_json_bytes(&Metadata {
            version: &self.version,
            content_type: &self.content_type,
            encryption_context: &self.encryption_context,
        })?;
        let ciphertext = arkret_canonical::base64url::base64url_decode(&self.ciphertext)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        preimage.extend_from_slice(&ciphertext);
        Ok(Hash::new(canonical::sha256_digest(&preimage))?)
    }
}

/// Decode and validate an encrypted envelope without initializing an MLS group machine.
pub fn parse_and_validate_encrypted_envelope(value: Value) -> Result<EncryptedEnvelope> {
    let envelope: EncryptedEnvelope = serde_json::from_value(value)
        .map_err(|error| WireError::Protocol(format!("encrypted envelope schema: {error}")))?;
    envelope.validate()?;
    Ok(envelope)
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

pub fn fixed_base64url_token(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && base64url_token(value)
}

/// `type/constraint_subkind` content-type token with restricted byte alphabet. Shared
/// wire-token validator (reused by `arkret-sdk`).
pub fn content_type_token(value: &str) -> bool {
    let Some((ty, constraint_subkind)) = value.split_once('/') else {
        return false;
    };
    !ty.is_empty()
        && !constraint_subkind.is_empty()
        && ty.bytes().all(content_type_byte)
        && constraint_subkind.bytes().all(content_type_byte)
}

/// Admissible byte inside a [`content_type_token`] segment. Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn content_type_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'+' | b'-')
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPayload {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub group_id: MlsGroupId,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub pre_encryption_header: EventContentPreEncryptionHeader,
    pub payload_digest: Hash,
}

impl EncryptedPayload {
    fn envelope_from_parts(
        header: &EventContentPreEncryptionHeader,
        ciphertext: String,
    ) -> Result<EncryptedEnvelope> {
        header.validate()?;
        let routing_context = match &header.routing_context {
            EventContentRoutingContext::None => None,
            EventContentRoutingContext::Reaction {
                target_ref,
                routing_tag,
                ..
            } => Some(EncryptedEnvelopeRoutingContext {
                target_ref: target_ref.clone(),
                routing_tag: routing_tag.clone(),
            }),
        };
        let encryption_context = EncryptedEnvelopeEncryptionContext::StandardMls {
            epoch: header.epoch,
            group_state_ref: header.group_state_ref.clone(),
            routing_context,
        };
        let envelope = EncryptedEnvelope {
            version: header.envelope_version.clone(),
            content_type: header.content_type.clone(),
            encryption_context,
            ciphertext,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn to_envelope(&self) -> Result<EncryptedEnvelope> {
        if self.scheme != self.pre_encryption_header.scheme
            || self.group_id != self.pre_encryption_header.mls_group_id
            || self.epoch != self.pre_encryption_header.epoch
            || self.content_type != self.pre_encryption_header.content_type
        {
            return Err(WireError::Protocol(
                "internal encrypted payload does not match its pre-encryption header".to_owned(),
            ));
        }
        Self::envelope_from_parts(&self.pre_encryption_header, self.ciphertext.clone())
    }

    pub fn payload_digest_for_header(
        header: &EventContentPreEncryptionHeader,
        ciphertext: String,
    ) -> Result<Hash> {
        Self::envelope_from_parts(header, ciphertext)?.payload_digest()
    }

    pub fn verify_payload_digest(&self) -> Result<()> {
        let expected = self.to_envelope()?.payload_digest()?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(WireError::Protocol(
                "encrypted payload digest mismatch".to_owned(),
            ))
        }
    }
}
