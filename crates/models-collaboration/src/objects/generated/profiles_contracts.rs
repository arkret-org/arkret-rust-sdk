// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/identity-link.schema.json
// sha256=290ceb17aae10a0e049b79a8ae3d108b24cabc9f232d290dc1303634576b84e9
//
// Input: schemas/strand.schema.json
// sha256=6730b70c528b57a0f7340fc42882d080ae2ff51e6c1b2140fb952f64fa6afd27
//
// Input: schemas/common-ids.schema.json
// sha256=dadc47194ca411baa38f3a7f44ae8115bec7cbcd98e68a2fffd389fdfc039713
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/policy.schema.json
// sha256=f31a32e76dd6026205c48226af03e5b860c147c87335da0ff60ea481c9755729
//
// Bindings: tools/closed-model-bindings.json
// sha256=a78e63d1f3a48c87115a3e40e578dc4aeb5f619833613e5eb9fae1be319bff29

/// Counterpart: `identity-link.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLink {
    pub schema: String,
    pub status: IdentityLinkStatus,
    pub pairwise_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub strand_id: Option<StrandId>,
    #[serde(
        rename = "track_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub track: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub mls_group_id: Option<String>,
    pub mls_leaf_index: u64,
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    pub mls_epoch: u64,
    pub response_signing_verification_method: DidUrl,
    pub response_signing_algorithm: IdentityLinkResponseSigningAlgorithm,
    pub response_signing_public_key_base64url: Base64UrlString,
    pub response_signing_public_key_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub disclosure_policy_id: Option<PolicyId>,
    pub proof: IdentityLinkProof,
}

/// Counterpart: `identity-link.schema.json#/$defs/proof`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLinkProof {
    pub verification_method: DidUrl,
    pub signature_algorithm: String,
    pub payload_digest: Hash,
    pub signature: String,
}
