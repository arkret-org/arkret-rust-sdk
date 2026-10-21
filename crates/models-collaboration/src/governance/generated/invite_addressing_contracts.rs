// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/invite-delivery.schema.json
// sha256=6a86ebab62e42642d14fcd077e135d1302383fd561f76682c4c9775c11c6b751
//
// Input: schemas/invite-delivery-request.schema.json
// sha256=7ee223b5038b4f00ed268ddacb76eaea1f6bd656b09f97f29e1b091ce6f5c807
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=1d0ad5c145091c227cb414f5a677679d5e286d16a5e5819328c907b2432e5350
//
// Bindings: tools/closed-model-bindings.json
// sha256=845a18ec30cf4928c1f028c2c06dbd9f098a9996b00093b60ded7690cd8ad896

/// Counterpart: `invite-delivery.schema.json`.
/// Strong cell value for the `ak.account.invite_delivery` account-data key
/// ([`arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY`]), whose wire
/// schema is `spec/v1/artifacts/schemas/invite-delivery.schema.json`
/// (`ak.schema.invite_delivery.v1`).
///
/// Actor-private plaintext carrier for delivered directed invites on the
/// notify branch (invite-addressing.md section 7), written by the recipient
/// Station through the delivery path. It carries invite references and
/// untrusted locator hints but no bearer credential. The cell is a bounded CAS register: at most
/// [`InviteDelivery::MAX_ENTRIES`] entries, at most one entry per
/// `invite_id` (a redelivery replaces the previous entry), expired entries
/// are purged on the next write and overflow evicts the oldest entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteDelivery {
    pub schema: String,
    #[serde(with = "canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub delivery_entries: Vec<InviteDeliveryEntry>,
}

/// Counterpart: `invite-delivery.schema.json#/$defs/delivery_entry`.
/// One delivered directed invite inside [`InviteDelivery`]
/// (`invite-delivery.schema.json#/$defs/delivery_entry`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct InviteDeliveryEntry {
    pub invite_id: InviteId,
    pub realm_id: RealmId,
    pub inviter_account_id: AccountId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
    #[serde(with = "canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

/// Counterpart: `invite-delivery-request.schema.json`.
/// Private service-to-service invite delivery request
/// (`invite-delivery-request.schema.json`).
///
/// The current Realm governance Station emits it after committing the invite
/// Event. `invite_commit` is the Realm-stream authority commit of exactly that
/// Event; `authority_locator_hints` are untrusted discovery hints only. Field
/// declaration order is the schema `properties` order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteDeliveryRequestBody {
    pub schema: String,
    pub invite_event: Event,
    pub invite_commit: RealmCommit,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    pub producer_signer_fact: Option<crate::authority_commit::AccountDeviceHistoricalSignerFact>,
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
    pub invite_address: InviteAddress,
    pub introduction_evidence: IntroductionEvidence,
    pub idempotency_key: String,
}
