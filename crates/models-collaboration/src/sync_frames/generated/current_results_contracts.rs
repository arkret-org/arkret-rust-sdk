// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-current-result.schema.json
// sha256=0ed02242d247bdb8e3a64be04b72444de792d027f76d8d34fef0be0911e87641
//
// Bindings: tools/closed-model-bindings.json
// sha256=1651c7a364d583147739726313af4bcf4b1346ca585e5a19e90e50705f09898d

/// Counterpart: `account-current-result.schema.json#/$defs/current`.
/// The Account Station's view of one Realm's authority-committed current state.
/// Spec: `account-current-result.schema.json`.
///
/// `governance_generation` names which governance generation materialized these
/// entries, and `stream_heads` is the per-stream position each entry was
/// materialized at. There is deliberately no single "Realm position" here: a
/// Realm's own stream, its Circles and its Sidecars advance independently, and
/// one number could not state where this result stands in all of them.
///
/// Convergence is by stable domain selector plus `expected_revision` CAS, so a
/// caller writes back against the `revision` of the exact entry it read — never
/// against a whole-Realm token.
/// Field declaration order is byte-for-byte the `properties` order of
/// `account-current-result.schema.json#/$defs/current`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCurrentView {
    pub realm_id: RealmId,
    pub governance_generation: u64,
    pub stream_heads: Vec<CommitStreamHead>,
    pub entries: Vec<TypedCurrentRow>,
}

/// Counterpart: `account-current-result.schema.json#/$defs/coverage`.
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
