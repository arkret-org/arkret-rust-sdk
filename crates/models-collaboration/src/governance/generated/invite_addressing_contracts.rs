// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/invite-delivery.schema.json
// sha256=c5fc0f581533d3d37e53da70f81e4ac2288f56f6685789f7c4c95cb5f3bed720
//
// Input: schemas/invite-delivery-request.schema.json
// sha256=ecd58685089565c3be1be0f793252fde9cd2dc73fadca161a733b096f98705c7
//
// Input: schemas/authority-commit-operations.schema.json
// sha256=e621293b9e2e5e08de76450a99b0e8069fa9bb92c806fe8dfe3134176e8c63b9
//
// Bindings: tools/closed-model-bindings.json
// sha256=ea613fae32e25a94687889845566828fe050317b185350eceb320391ae60c2f4

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
