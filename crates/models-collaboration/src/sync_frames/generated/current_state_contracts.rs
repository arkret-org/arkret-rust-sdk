// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-state-view.schema.json
// sha256=b21766ffb5b612a5397c34b45369a766a7fdef8f60c316c11cf72db55e70b340
//
// Bindings: tools/closed-model-bindings.json
// sha256=13aff1fc7ba8bd04dc6586b917faf46593a6d0e4beeadb69db75284c9e17a6f7

/// Counterpart: `account-state-view.schema.json#/$defs/current`.
/// The Account Station's view of one Realm's authority-committed current state.
/// Spec: `account-state-view.schema.json`.
///
/// `governance_generation` names which governance generation materialized these
/// entries, and `stream_heads` is the per-stream position each entry was
/// materialized at. There is deliberately no single "Realm position" here: a
/// Realm's own stream, its Circles and its Sidecars advance independently, and
/// one number could not state where this result stands in all of them.
///
/// Convergence is by stable domain selector plus `expected_revision` CAS, so a
/// caller writes back against the `revision` of the exact entry it read â€” never
/// against a whole-Realm token.
/// Field declaration order is byte-for-byte the `properties` order of
/// `account-state-view.schema.json#/$defs/current`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStateView {
    pub realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub governance_generation: u64,
    pub stream_heads: Vec<CommitStreamHead>,
    pub entries: Vec<CurrentState>,
}

/// Counterpart: `account-state-view.schema.json#/$defs/coverage`.
/// How much of one Realm a current-state read actually covered.
///
/// Every Realm, Circle and Sidecar keeps its own commit stream, so coverage is
/// a set of per-stream heads and never a single global position.
/// `complete_for_authorized_streams` is scoped exactly as its name says: it
/// asserts that the reader saw every stream it is authorized to read, never
/// that it saw the whole Realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCurrentCoverage {
    pub realm_id: RealmId,
    pub stream_heads: Vec<CommitStreamHead>,
    pub complete_for_authorized_streams: bool,
}
