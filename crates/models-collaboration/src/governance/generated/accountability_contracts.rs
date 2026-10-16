// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/accountability-grant.schema.json
// sha256=9e331547042f7dfb85303a90881452979462544b609fc7f81003e1bdb2735245
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=a815d160b11bd278cacb26a2d096a99bf7042e5f84772a439fcda2a7f9dedf7c

/// Counterpart: `accountability-grant.schema.json#/$defs/accountability_projection`.
/// Canonical business value of the `identity_accountability` typed current
/// result (`accountability-grant.schema.json#/$defs/accountability_projection`).
///
/// One record has two registered writers: the independent
/// `ak.identity.accountability_grant` and the atomic accountability projection
/// of `ak.agent.provision` (`zh/models/actor.md` section 3.3.1). Neither the
/// inner proof nor a source Event reference is part of the value; the head
/// Event and its accepting Commit carry provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityProjection {
    pub issuer_id: DidCoreId,
    pub subject_id: DidCoreId,
    pub accountability_scope: AccountabilityScopeSet,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub grant_status: AccountabilityGrantStatus,
}
