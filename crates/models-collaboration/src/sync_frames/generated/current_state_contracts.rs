// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-state-view.schema.json
// sha256=25b316c622b40dd0719802a94561c9993e77b0e91a476e58ad282851f8547b26
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
