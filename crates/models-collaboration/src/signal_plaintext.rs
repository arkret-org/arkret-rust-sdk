//! Signal plaintext payload profile family (`sync/signal.md` §1.1).
//!
//! Every registered profile is a closed schema that MUST carry the same two
//! fields: `kind`, the only post-decryption payload discriminator, and
//! `payload_sequence`, the third component of the
//! `(sender_device_id, scope_ref, payload_sequence)` receiver dedupe triple.
//! They are not per-profile decoration — they are the rail's routing and
//! dedupe precondition — so this module owns the one construction and
//! validation entry for the whole family instead of each profile spelling the
//! minimum again.
//!
//! [`SignalPlaintextProfile`] is what makes "forgot `payload_sequence`" a
//! compile error: a profile type that cannot produce a sequence cannot
//! implement the trait, and [`seal_signal_plaintext`] is generic over it, so
//! there is no path from a profile struct to plaintext bytes that skips the
//! minimum.
//!
//! The receive direction is [`open_signal_plaintext`]: it reads `kind`, selects
//! the corresponding closed type, and rejects an unregistered `kind` as
//! `schema_violation`. Nothing here parses a plaintext by field name.

use arkret_wire::signal::MAX_SIGNAL_PLAINTEXT_BYTES;
use arkret_wire::{
    Did, Error, ErrorCode, EventId, Hlc, ReadReceiptScope, Result, SchemaId, StrandId, canonical,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::call_signal::CallSignalPlaintext;
use crate::signal_message_stream::MessageStreamFrame;

/// Session-class TTL ceiling in milliseconds (`sync/signal.md` §2).
///
/// A plaintext `ttl_ms` may only tighten the enclosing envelope lifetime, so
/// the largest value that can ever be meaningful is the class ceiling itself.
pub const MAX_SIGNAL_PLAINTEXT_TTL_MS: u64 = 30_000;

/// Closed v1 registry of Signal plaintext payload kinds.
///
/// The set is closed by `signal.md` §1.1: a new profile is a new registry row,
/// never a new endpoint, stream-frame kind or server-visible selector.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalPlaintextKind {
    #[serde(rename = "ak.presence")]
    Presence,
    #[serde(rename = "ak.typing")]
    Typing,
    #[serde(rename = "ak.receipt.read")]
    ReadReceipt,
    #[serde(rename = "ak.call.signal")]
    CallSignal,
    #[serde(rename = "ak.message.stream")]
    MessageStream,
}

impl SignalPlaintextKind {
    pub const ALL: [Self; 5] = [
        Self::Presence,
        Self::Typing,
        Self::ReadReceipt,
        Self::CallSignal,
        Self::MessageStream,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Presence => "ak.presence",
            Self::Typing => "ak.typing",
            Self::ReadReceipt => "ak.receipt.read",
            Self::CallSignal => "ak.call.signal",
            Self::MessageStream => "ak.message.stream",
        }
    }

    /// Registered closed schema the decrypted payload is validated against.
    pub fn schema_id(self) -> &'static str {
        match self {
            Self::Presence => SchemaId::SIGNAL_PRESENCE_V1,
            Self::Typing => SchemaId::SIGNAL_TYPING_V1,
            Self::ReadReceipt => SchemaId::READ_RECEIPT_V1,
            Self::CallSignal => SchemaId::CALL_SIGNAL_PLAINTEXT_V1,
            Self::MessageStream => SchemaId::SIGNAL_MESSAGE_STREAM_V1,
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// The common minimal set every registered plaintext profile carries.
///
/// Implementing this is what admits a type to the Signal rail. The two required
/// members mirror the two fields §1.1 makes mandatory, so a profile that omits
/// `payload_sequence` simply cannot satisfy the trait.
pub trait SignalPlaintextProfile: Serialize + DeserializeOwned {
    /// Value of the profile's `kind` const.
    const KIND: SignalPlaintextKind;

    /// Sender-device sequence within the signed Signal scope. Independent of
    /// any product sequence the profile also carries (`ak.call.signal`'s
    /// per-call `seq`, `ak.message.stream`'s per-stream `seq`); neither
    /// substitutes for the other.
    fn payload_sequence(&self) -> u64;

    /// In-ciphertext reader / publisher identity, when the profile expresses
    /// one. Receivers MUST check it equals the envelope `sender_actor_id`.
    fn actor_id(&self) -> Option<&Did> {
        None
    }

    /// Plaintext lifetime hint. It may only tighten the envelope `expires_at`.
    fn ttl_ms(&self) -> Option<u64> {
        None
    }

    /// Profile rules that JSON Schema cannot express.
    fn validate_profile(&self) -> Result<()> {
        Ok(())
    }
}

fn schema_violation(message: impl AsRef<str>) -> Error {
    Error::Protocol(format!(
        "{}: {}",
        ErrorCode::SCHEMA_VIOLATION,
        message.as_ref()
    ))
}

/// Validate the common minimal set plus the profile's own rules and produce the
/// canonical plaintext bytes to seal.
///
/// This is the only supported way to turn a profile value into Signal
/// plaintext. Callers do not hand-assemble the object and do not top up missing
/// common fields afterwards.
pub fn seal_signal_plaintext<P: SignalPlaintextProfile>(payload: &P) -> Result<Vec<u8>> {
    validate_signal_plaintext(payload)?;
    let bytes = canonical::canonical_json_bytes(payload)?;
    if bytes.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
        return Err(Error::Protocol(format!(
            "{} Signal plaintext exceeds {MAX_SIGNAL_PLAINTEXT_BYTES} bytes",
            P::KIND.as_str()
        )));
    }
    Ok(bytes)
}

/// Every rule decidable from the plaintext alone: the shared minimum plus the
/// profile's own closed-schema-inexpressible checks.
pub fn validate_signal_plaintext<P: SignalPlaintextProfile>(payload: &P) -> Result<()> {
    if let Some(ttl_ms) = payload.ttl_ms()
        && (ttl_ms == 0 || ttl_ms > MAX_SIGNAL_PLAINTEXT_TTL_MS)
    {
        return Err(schema_violation(format!(
            "{} ttl_ms must be within 1..={MAX_SIGNAL_PLAINTEXT_TTL_MS}",
            P::KIND.as_str()
        )));
    }
    payload.validate_profile()
}

/// A decrypted, kind-dispatched Signal plaintext.
///
/// Deliberately not `#[serde(untagged)]`: the union is entered through
/// [`open_signal_plaintext`], which reads `kind` first and picks exactly one
/// closed type, so a payload can never be admitted by a sibling profile that
/// happens to accept its fields.
#[derive(Clone, Debug, PartialEq)]
pub enum SignalPlaintext {
    Presence(PresencePlaintext),
    Typing(TypingPlaintext),
    ReadReceipt(ReadReceipt),
    CallSignal(CallSignalPlaintext),
    MessageStream(MessageStreamFrame),
}

impl SignalPlaintext {
    pub fn kind(&self) -> SignalPlaintextKind {
        match self {
            Self::Presence(_) => SignalPlaintextKind::Presence,
            Self::Typing(_) => SignalPlaintextKind::Typing,
            Self::ReadReceipt(_) => SignalPlaintextKind::ReadReceipt,
            Self::CallSignal(_) => SignalPlaintextKind::CallSignal,
            Self::MessageStream(_) => SignalPlaintextKind::MessageStream,
        }
    }

    pub fn payload_sequence(&self) -> u64 {
        match self {
            Self::Presence(payload) => payload.payload_sequence(),
            Self::Typing(payload) => payload.payload_sequence(),
            Self::ReadReceipt(payload) => payload.payload_sequence(),
            Self::CallSignal(payload) => payload.payload_sequence(),
            Self::MessageStream(payload) => payload.payload_sequence(),
        }
    }

    pub fn actor_id(&self) -> Option<&Did> {
        match self {
            Self::Presence(payload) => payload.actor_id(),
            Self::Typing(payload) => payload.actor_id(),
            Self::ReadReceipt(payload) => payload.actor_id(),
            Self::CallSignal(payload) => payload.actor_id(),
            Self::MessageStream(payload) => payload.actor_id(),
        }
    }

    pub fn ttl_ms(&self) -> Option<u64> {
        match self {
            Self::Presence(payload) => payload.ttl_ms(),
            Self::Typing(payload) => payload.ttl_ms(),
            Self::ReadReceipt(payload) => payload.ttl_ms(),
            Self::CallSignal(payload) => payload.ttl_ms(),
            Self::MessageStream(payload) => payload.ttl_ms(),
        }
    }

    /// Bind the plaintext to the envelope that carried it.
    ///
    /// Two rules from §1.1 that only exist across the boundary: an `actor_id`
    /// inside the ciphertext MUST equal the envelope `sender_actor_id`, and a
    /// plaintext `ttl_ms` MUST NOT widen the envelope lifetime. Realm scope,
    /// sending device and send time are read from the envelope; the plaintext
    /// never restates them.
    pub fn bind_to_envelope(
        &self,
        sender_actor_id: &Did,
        sent_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        if let Some(actor_id) = self.actor_id()
            && actor_id != sender_actor_id
        {
            return Err(schema_violation(format!(
                "{} actor_id must equal the envelope sender_actor_id",
                self.kind().as_str()
            )));
        }
        if let Some(ttl_ms) = self.ttl_ms() {
            let envelope_ms = (expires_at - sent_at).num_milliseconds();
            if envelope_ms <= 0 || i128::from(ttl_ms) > i128::from(envelope_ms) {
                return Err(schema_violation(format!(
                    "{} ttl_ms may only tighten the envelope expires_at",
                    self.kind().as_str()
                )));
            }
        }
        Ok(())
    }

    /// Effective lifetime: the minimum of the plaintext hint and the envelope.
    pub fn effective_expires_at(
        &self,
        sent_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> DateTime<Utc> {
        match self.ttl_ms().and_then(|ttl_ms| i64::try_from(ttl_ms).ok()) {
            Some(ttl_ms) => expires_at.min(sent_at + chrono::Duration::milliseconds(ttl_ms)),
            None => expires_at,
        }
    }
}

/// Decrypted-plaintext ingress: validate the shared minimum, dispatch on
/// `kind`, then validate the selected closed profile.
///
/// An unregistered `kind`, a missing `kind`, or a payload the selected closed
/// schema rejects is dropped as `schema_violation`. There is no field-name
/// fallback and no "best effort" branch: a receiver that cannot name the
/// profile has nothing it is allowed to do with the payload.
pub fn open_signal_plaintext(bytes: &[u8]) -> Result<SignalPlaintext> {
    if bytes.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
        return Err(schema_violation(format!(
            "Signal plaintext exceeds {MAX_SIGNAL_PLAINTEXT_BYTES} bytes"
        )));
    }
    let value: Value = canonical::from_canonical_json_slice(bytes)?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_violation("Signal plaintext is missing the kind discriminator"))?;
    let kind = SignalPlaintextKind::from_wire(kind).ok_or_else(|| {
        schema_violation(format!("'{kind}' is not a registered Signal payload kind"))
    })?;
    match kind {
        SignalPlaintextKind::Presence => decode_profile(value).map(SignalPlaintext::Presence),
        SignalPlaintextKind::Typing => decode_profile(value).map(SignalPlaintext::Typing),
        SignalPlaintextKind::ReadReceipt => decode_profile(value).map(SignalPlaintext::ReadReceipt),
        SignalPlaintextKind::CallSignal => decode_profile(value).map(SignalPlaintext::CallSignal),
        SignalPlaintextKind::MessageStream => {
            decode_profile(value).map(SignalPlaintext::MessageStream)
        }
    }
}

fn decode_profile<P: SignalPlaintextProfile>(value: Value) -> Result<P> {
    let payload: P = serde_json::from_value(value)
        .map_err(|error| schema_violation(format!("{} plaintext: {error}", P::KIND.as_str())))?;
    validate_signal_plaintext(&payload)?;
    Ok(payload)
}

/// Marker for the `kind` const of a profile whose only legal value is one
/// registry row. Kept per profile so the closed schema's `const` survives
/// round-trips instead of becoming a free-form string.
macro_rules! plaintext_kind_marker {
    ($name:ident, $wire:literal) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[default]
            #[serde(rename = $wire)]
            Value,
        }
    };
}

plaintext_kind_marker!(PresencePlaintextKind, "ak.presence");
plaintext_kind_marker!(TypingPlaintextKind, "ak.typing");
plaintext_kind_marker!(ReadReceiptPlaintextKind, "ak.receipt.read");

/// Closed v1 presence state set (`discovery/profiles-presence.md` §3.3).
///
/// Invisibility is not a state: it is `ak.presence.visibility=nobody`. An
/// unknown value is a `schema_violation`, never an approximation onto a
/// neighbouring state, so this stays a closed enum.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Online,
    Idle,
    Offline,
    Dnd,
}

/// Counterpart for `spec/v1/artifacts/schemas/signal-presence.schema.json`
/// (`ak.schema.signal_presence.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresencePlaintext {
    pub kind: PresencePlaintextKind,
    pub payload_sequence: u64,
    pub actor_id: Did,
    pub state: PresenceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// RFC 3339 instant or a `<start>/<end>` bucket. Kept as the wire string
    /// because the bucket form is not a single timestamp and the granularity
    /// bound is a Realm-policy check the receiver runs, not a parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<String>,
    pub ttl_ms: u64,
}

impl PresencePlaintext {
    /// `payload_sequence` is the first parameter and has no default: the shared
    /// minimum is part of constructing a presence signal, not something a
    /// caller tops up afterwards.
    pub fn new(
        payload_sequence: u64,
        actor_id: Did,
        state: PresenceState,
        ttl_ms: u64,
    ) -> Result<Self> {
        let payload = Self {
            kind: PresencePlaintextKind::Value,
            payload_sequence,
            actor_id,
            state,
            status_message: None,
            last_active_at: None,
            ttl_ms,
        };
        validate_signal_plaintext(&payload)?;
        Ok(payload)
    }

    pub fn with_status_message(mut self, status_message: impl Into<String>) -> Result<Self> {
        self.status_message = Some(status_message.into());
        validate_signal_plaintext(&self)?;
        Ok(self)
    }

    pub fn with_last_active_at(mut self, last_active_at: impl Into<String>) -> Self {
        self.last_active_at = Some(last_active_at.into());
        self
    }
}

impl SignalPlaintextProfile for PresencePlaintext {
    const KIND: SignalPlaintextKind = SignalPlaintextKind::Presence;

    fn payload_sequence(&self) -> u64 {
        self.payload_sequence
    }

    fn actor_id(&self) -> Option<&Did> {
        Some(&self.actor_id)
    }

    fn ttl_ms(&self) -> Option<u64> {
        Some(self.ttl_ms)
    }

    fn validate_profile(&self) -> Result<()> {
        if let Some(status_message) = &self.status_message {
            if status_message.chars().count() > 256 {
                return Err(schema_violation(
                    "presence status_message exceeds 256 code points",
                ));
            }
            if status_message
                .chars()
                .any(|value| value.is_control() && value != '\t' && value != '\n')
            {
                return Err(schema_violation(
                    "presence status_message carries a forbidden control character",
                ));
            }
        }
        Ok(())
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/signal-typing.schema.json`
/// (`ak.schema.signal_typing.v1`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypingTrackName {
    Discussion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypingPlaintext {
    pub kind: TypingPlaintextKind,
    pub payload_sequence: u64,
    pub strand_id: StrandId,
    /// Optional on the wire; an absent value resolves to `discussion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<TypingTrackName>,
    pub typing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
}

impl TypingPlaintext {
    pub fn new(payload_sequence: u64, strand_id: StrandId, typing: bool) -> Result<Self> {
        let payload = Self {
            kind: TypingPlaintextKind::Value,
            payload_sequence,
            strand_id,
            track_name: None,
            typing,
            ttl_ms: None,
        };
        validate_signal_plaintext(&payload)?;
        Ok(payload)
    }

    pub fn with_ttl_ms(mut self, ttl_ms: u64) -> Result<Self> {
        self.ttl_ms = Some(ttl_ms);
        validate_signal_plaintext(&self)?;
        Ok(self)
    }

    /// Resolved track: absent means `discussion`.
    pub fn track_name(&self) -> TypingTrackName {
        self.track_name.unwrap_or(TypingTrackName::Discussion)
    }
}

impl SignalPlaintextProfile for TypingPlaintext {
    const KIND: SignalPlaintextKind = SignalPlaintextKind::Typing;

    fn payload_sequence(&self) -> u64 {
        self.payload_sequence
    }

    fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/read-receipt.schema.json`
/// (`ak.schema.read_receipt.v1`).
///
/// A read receipt is a Signal plaintext, not a durable object: it never enters
/// Event history, so it carries no `id`, no `schema`, no `created_at` and no
/// `realm_id`. Realm scope is already bound into the ciphertext by the Signal
/// AAD, the sending device and send time are on the signed envelope, and the
/// payload kind is the `kind` const. One type both seals and opens — the
/// closed schema and this struct describe the same five fields, so a sender's
/// own bytes deserialize back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub kind: ReadReceiptPlaintextKind,
    pub payload_sequence: u64,
    pub actor_id: Did,
    pub event_id: EventId,
    /// Required only when a Sync Service must compare receipts across devices
    /// for the same actor under merge / debounce rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub read_scope: ReadReceiptScope,
}

impl ReadReceipt {
    pub const SCHEMA: &'static str = SchemaId::READ_RECEIPT_V1;

    pub fn new(
        payload_sequence: u64,
        actor_id: Did,
        event_id: EventId,
        read_scope: ReadReceiptScope,
    ) -> Result<Self> {
        let receipt = Self {
            kind: ReadReceiptPlaintextKind::Value,
            payload_sequence,
            actor_id,
            event_id,
            hlc: None,
            read_scope,
        };
        validate_signal_plaintext(&receipt)?;
        Ok(receipt)
    }

    pub fn with_hlc(mut self, hlc: Hlc) -> Self {
        self.hlc = Some(hlc);
        self
    }

    /// Deserialize an inbound read receipt after canonical JSON ingress checks.
    ///
    /// Prefer [`open_signal_plaintext`], which dispatches on `kind` instead of
    /// assuming the caller already knows the profile.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        let receipt: Self = canonical::from_canonical_json_slice(bytes)?;
        validate_signal_plaintext(&receipt)?;
        Ok(receipt)
    }
}

impl SignalPlaintextProfile for ReadReceipt {
    const KIND: SignalPlaintextKind = SignalPlaintextKind::ReadReceipt;

    fn payload_sequence(&self) -> u64 {
        self.payload_sequence
    }

    fn actor_id(&self) -> Option<&Did> {
        Some(&self.actor_id)
    }

    fn validate_profile(&self) -> Result<()> {
        self.read_scope.validate()
    }
}

impl SignalPlaintextProfile for CallSignalPlaintext {
    const KIND: SignalPlaintextKind = SignalPlaintextKind::CallSignal;

    fn payload_sequence(&self) -> u64 {
        self.payload_sequence
    }
}

impl SignalPlaintextProfile for MessageStreamFrame {
    const KIND: SignalPlaintextKind = SignalPlaintextKind::MessageStream;

    fn payload_sequence(&self) -> u64 {
        self.payload_sequence()
    }

    fn validate_profile(&self) -> Result<()> {
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
    }

    fn strand_id() -> StrandId {
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap()
    }

    #[test]
    fn every_registered_kind_maps_to_its_schema_id() {
        for kind in SignalPlaintextKind::ALL {
            assert_eq!(SignalPlaintextKind::from_wire(kind.as_str()), Some(kind));
            assert!(kind.schema_id().starts_with("ak.schema."));
        }
        assert_eq!(SignalPlaintextKind::ALL.len(), 5);
    }

    #[test]
    fn a_read_receipt_seals_and_opens_as_the_same_type() {
        // The old durable shape could not do this: `deny_unknown_fields` on a
        // type carrying `receipt_kind` / `schema` / `realm_id` / `created_at`
        // meant a sender's own body did not deserialize back.
        let receipt = ReadReceipt::new(7, actor(), event_id(), ReadReceiptScope::realm()).unwrap();
        let bytes = seal_signal_plaintext(&receipt).unwrap();
        let opened = open_signal_plaintext(&bytes).unwrap();
        assert_eq!(opened.kind(), SignalPlaintextKind::ReadReceipt);
        assert_eq!(opened.payload_sequence(), 7);
        assert_eq!(opened, SignalPlaintext::ReadReceipt(receipt));
    }

    #[test]
    fn the_retired_durable_read_receipt_fields_are_rejected() {
        let base = json!({
            "kind": "ak.receipt.read",
            "payload_sequence": 1,
            "actor_id": actor(),
            "event_id": event_id(),
            "read_scope": {"kind": "realm"}
        });
        serde_json::from_value::<ReadReceipt>(base.clone()).expect("closed shape decodes");
        for retired in ["receipt_kind", "schema", "realm_id", "created_at"] {
            let mut legacy = base.clone();
            legacy[retired] = json!("x");
            serde_json::from_value::<ReadReceipt>(legacy)
                .expect_err("a durable-object leftover must not deserialize");
        }
    }

    #[test]
    fn a_plaintext_without_payload_sequence_is_a_schema_violation() {
        let missing = json!({
            "kind": "ak.receipt.read",
            "actor_id": actor(),
            "event_id": event_id(),
            "read_scope": {"kind": "realm"}
        });
        let error = open_signal_plaintext(&canonical::canonical_json_bytes(&missing).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("schema_violation"), "{error}");
        assert!(error.contains("payload_sequence"), "{error}");
    }

    #[test]
    fn an_unregistered_kind_is_dropped_rather_than_parsed_by_field_name() {
        let unregistered = json!({
            "kind": "ak.receipt.delivered",
            "payload_sequence": 1,
            "actor_id": actor(),
            "event_id": event_id(),
            "read_scope": {"kind": "realm"}
        });
        let error = open_signal_plaintext(&canonical::canonical_json_bytes(&unregistered).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("schema_violation"), "{error}");
        assert!(
            error.contains("not a registered Signal payload kind"),
            "{error}"
        );
    }

    #[test]
    fn presence_and_typing_round_trip_through_the_shared_entry() {
        let presence = PresencePlaintext::new(3, actor(), PresenceState::Online, 30_000).unwrap();
        let opened = open_signal_plaintext(&seal_signal_plaintext(&presence).unwrap()).unwrap();
        assert_eq!(opened, SignalPlaintext::Presence(presence));
        assert_eq!(opened.ttl_ms(), Some(30_000));

        let typing = TypingPlaintext::new(4, strand_id(), true)
            .unwrap()
            .with_ttl_ms(5_000)
            .unwrap();
        let opened = open_signal_plaintext(&seal_signal_plaintext(&typing).unwrap()).unwrap();
        assert_eq!(opened, SignalPlaintext::Typing(typing));
    }

    #[test]
    fn the_session_ttl_ceiling_is_enforced_at_construction() {
        assert!(PresencePlaintext::new(1, actor(), PresenceState::Online, 30_001).is_err());
        assert!(PresencePlaintext::new(1, actor(), PresenceState::Online, 0).is_err());
        assert!(
            TypingPlaintext::new(1, strand_id(), true)
                .unwrap()
                .with_ttl_ms(30_001)
                .is_err()
        );
    }

    #[test]
    fn envelope_binding_rejects_a_foreign_actor_and_a_widening_ttl() {
        let sent_at = "2026-08-01T00:00:00.000Z".parse::<DateTime<Utc>>().unwrap();
        let expires_at = sent_at + chrono::Duration::seconds(10);
        let presence = SignalPlaintext::Presence(
            PresencePlaintext::new(1, actor(), PresenceState::Online, 30_000).unwrap(),
        );
        // 30s plaintext hint inside a 10s envelope widens the lifetime.
        assert!(
            presence
                .bind_to_envelope(&actor(), sent_at, expires_at)
                .is_err()
        );

        let tightened = SignalPlaintext::Presence(
            PresencePlaintext::new(1, actor(), PresenceState::Online, 5_000).unwrap(),
        );
        tightened
            .bind_to_envelope(&actor(), sent_at, expires_at)
            .unwrap();
        assert_eq!(
            tightened.effective_expires_at(sent_at, expires_at),
            sent_at + chrono::Duration::seconds(5)
        );

        let mallory = Did::new("did:webvh:z6mkfixture:mallory.example").unwrap();
        assert!(
            tightened
                .bind_to_envelope(&mallory, sent_at, expires_at)
                .is_err()
        );
    }
}
