// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-subscribe-frame.schema.json
// sha256=51401641a42572fe13acee54f815d95360745e3f590436f243ccb2ac3136d31b
//
// Bindings: tools/closed-model-bindings.json
// sha256=8f43ab7f7fe4be59fd38447b7690378c53af63212ce0eb1df8f8d25fa2a14315

/// Counterpart: `account-subscribe-frame.schema.json#/$defs/account_filter`.
/// The Account subscribe filter,
/// `account-subscribe-frame.schema.json#/$defs/account_filter`.
///
/// Field declaration order is byte-for-byte the schema `properties` order.
/// `window_limit` is the per-visible-stream item ceiling of a stream window,
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
    pub window_limit: Option<u32>,
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
