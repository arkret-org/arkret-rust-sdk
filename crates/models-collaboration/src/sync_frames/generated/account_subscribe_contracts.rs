// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-subscribe-frame.schema.json
// sha256=48a324e92b530353a9ed88132e43855789e4f60f6af2368682c7e84de5e552f1
//
// Bindings: tools/closed-model-bindings.json
// sha256=90e21e77dae771f2c5ed933d3a57a684de6d47d3e4b73f568536e81a8e4fb8b9

/// Counterpart: `account-subscribe-frame.schema.json#/$defs/account_filter`.
/// The Account subscribe filter,
/// `account-subscribe-frame.schema.json#/$defs/account_filter`.
///
/// Field declaration order is byte-for-byte the schema `properties` order.
/// `max_window_event_count` is the per-visible-stream item ceiling of a stream window,
/// never a per-Realm budget. `stream_refs` optionally selects the window's
/// stream set; every entry must belong to a Realm named in `realm_ids`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFilter {
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_refs: Option<Vec<CommitStreamRef>>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_window_event_count: Option<u32>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub lazy_load_members: Option<bool>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub include_redundant_members: Option<bool>,
}

/// Counterpart: `account-subscribe-frame.schema.json#/$defs/realm_detail_baseline`.
/// Per-Realm detail baseline carried by one [`RealmSyncEntry`].
///
/// `snapshot_cursor` identifies the frozen baseline generation and is repeated
/// identically in every segment of it; it is opaque, never an ordered token,
/// and never reused as the account `after` parameter. `cut_revision` is the
/// committed revision the cut was taken at. `complete` reports delivery of this
/// Realm's baseline only: it is independent of the account-level baseline and
/// proves neither authentication, decryption, nor any read permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDetailBaseline {
    pub snapshot_cursor: String,
    pub cut_revision: u64,
    pub coverage: AccountCurrentCoverage,
    pub complete: bool,
}
