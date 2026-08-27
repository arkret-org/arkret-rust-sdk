//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/history-recovery-scalability-registry.json; version=2026-08-24.1;
//! sha256=fe0da5a3e8c7f734196cf0a55d0da9302067183ba3a8e290f0b15a4920e126c5
//! Entries: history_store_limits=7

/// Machine-readable `history_store` section of
/// `registry/history-recovery-scalability-registry.json`, the single source
/// of truth for the device-local history-only store quotas.
///
/// Material dedupe rule: Received secret bytes are globally deduplicated by material_key; origin
/// never participates in material identity. A material instance receives one immutable monotonic
/// material_received_sequence when bytes first become resident. The same bytes from a new origin
/// add only CandidateOriginAttribution and never refresh that sequence. After bytes are evicted, a
/// later refetch creates a new resident material instance and receives a new sequence.
///
/// Material quota rule: The 8-slot limit counts only resident received candidate material instances
/// under material_key. local_authoritative material is stored in a separate accounting class,
/// consumes no received slot, and is never evicted. CandidateOriginAttribution and
/// EventCandidateBinding metadata consume no material slot and never pin bytes.
///
/// Material eviction rule: Before inserting resident received material over quota,
/// deterministically evict secret bytes in two tiers: first material with no success
/// EventCandidateBinding, including unbound and failure-only; then success-bound material. Within a
/// tier choose (material_received_sequence ascending,candidate_digest UTF-8 ascending).
/// Success/failure bindings only select the tier and never pin bytes. Eviction deletes bytes plus
/// the resident sequence only, preserves bounded origin attribution/Event binding tombstones for
/// refetch, and never selects local_authoritative.
///
/// Origin attribution rule: CandidateOriginAttribution key is exactly
/// (material_key,origin_domain,origin_ref), while quotas use the separately persisted stable
/// origin_quota_domain. The ledger admits at most 4 rows per material_key, 64 rows per exact
/// (scope,group,epoch,origin_domain,origin_quota_domain), and 256 rows total per
/// (scope,group,epoch). first_observed_at is immutable; expiry is computed as
/// first_observed_at+2592000 seconds, is not stored, cannot be extended by duplicate/refetch, and
/// timestamp overflow fails closed. Exact duplicate is a no-op. Before admission prune expired
/// rows, then when any cap remains exceeded retain the minimum canonical tuple
/// (first_observed_at,material_key.candidate_digest,origin_domain,JCS(origin_quota_domain),
/// JCS(origin_ref)) and reject/prune larger rows. Origin attribution never duplicates bytes or
/// changes material_received_sequence.
///
/// Event candidate binding rule: EventCandidateBinding key is exactly
/// (event_binding_key,candidate_digest,outcome), where
/// event_binding_key=(effective_scope,mls_group_id,epoch,event_id,verified_sender_domain) and
/// outcome is success|failure. The suite-bearing event_id losslessly supplies the Event digest. The
/// binding contains no origin and origin cannot be inferred from it. The independent ledger is
/// capped at 256 rows per (scope,group,epoch); expiry is computed as immutable first_observed_at
/// plus 2592000 seconds, is not stored, and timestamp overflow fails closed. Prune expired rows
/// first, then (first_observed_at,event_id,verified_sender_domain,candidate_digest,outcome)
/// canonical ascending. Pruning never changes the ciphertext replay ledger, material authority, or
/// local_authoritative.
///
/// `candidate_digest` preimage: sha256 over exact history-secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryStoreLimits {
    pub event_candidate_binding_ttl_seconds: i64,
    pub max_event_candidate_bindings_per_scope_group_epoch: usize,
    pub max_origin_attributions_per_candidate: usize,
    pub max_origin_attributions_per_scope_group_epoch: usize,
    pub max_origin_attributions_per_scope_group_epoch_quota_domain: usize,
    pub max_received_candidates_per_scope_group_epoch: usize,
    pub origin_attribution_ttl_seconds: i64,
}

/// The registered `history_store` limits.
pub const HISTORY_STORE_LIMITS: HistoryStoreLimits = HistoryStoreLimits {
    event_candidate_binding_ttl_seconds: 2592000,
    max_event_candidate_bindings_per_scope_group_epoch: 256,
    max_origin_attributions_per_candidate: 4,
    max_origin_attributions_per_scope_group_epoch: 256,
    max_origin_attributions_per_scope_group_epoch_quota_domain: 64,
    max_received_candidates_per_scope_group_epoch: 8,
    origin_attribution_ttl_seconds: 2592000,
};
