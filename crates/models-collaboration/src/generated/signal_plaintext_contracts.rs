// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/signal-presence.schema.json
// sha256=564bb16a63b97cead164817cb9789d57c8ff86a2e92efb35a2d5a15030cbfce4
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/signal-typing.schema.json
// sha256=d92f677628318c885606b06efe06ec636c7c9f0904974effe04c669d6a412545
//
// Input: schemas/read-receipt.schema.json
// sha256=989122536e827d56f7f2c0eaea5395316bcc3e4058f4b4a22b2eadbb3e40a632
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

/// Counterpart: `signal-presence.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/signal-presence.schema.json`
/// (`ak.schema.signal_presence.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresencePlaintext {
    pub kind: PresencePlaintextKind,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub payload_sequence: u64,
    pub actor_id: ActorId,
    pub state: PresenceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub status_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub last_active_at: Option<String>,
    pub ttl_ms: u64,
}

/// Counterpart: `signal-typing.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/signal-typing.schema.json`
/// (`ak.schema.signal_typing.v1`).
///
/// The profile is fixed to the discussion track family and the plaintext
/// therefore carries no `track_name` at all
/// (`zh/discovery/profiles-presence.md` Â§3.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypingPlaintext {
    pub kind: TypingPlaintextKind,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub payload_sequence: u64,
    pub strand_id: StrandId,
    pub typing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub ttl_ms: Option<u64>,
}

/// Counterpart: `read-receipt.schema.json`.
/// Counterpart for `spec/v1/artifacts/schemas/read-receipt.schema.json`
/// (`ak.schema.read_receipt.v1`).
///
/// A read receipt is a Signal plaintext, not a durable object: it never enters
/// Event history, so it carries no `id`, no `schema`, no `created_at` and no
/// `realm_id`. Realm scope is already bound into the ciphertext by the Signal
/// AAD, the sending device and send time are on the signed envelope, and the
/// payload kind is the `kind` const. One type both seals and opens â€” the
/// closed schema and this struct describe the same five fields, so a sender's
/// own bytes deserialize back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub kind: ReadReceiptPlaintextKind,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub payload_sequence: u64,
    pub actor_id: ActorId,
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub hlc: Option<Hlc>,
    pub read_scope: ReadReceiptScope,
}
