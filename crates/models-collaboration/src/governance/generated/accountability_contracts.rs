// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/accountability-grant.schema.json
// sha256=422d77a7750de6f6c7a974b75936d2663a5d07d1377056bb1d9f1d2fc9627728
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=dc92c416f466a595bc16d56fbbae216e8c660c38914459081d8340c5b55ebb2d

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
