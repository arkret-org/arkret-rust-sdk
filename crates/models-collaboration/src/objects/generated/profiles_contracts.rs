// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/identity-link.schema.json
// sha256=d1636e81bcf6b2ac420070f731c1617a2125fd88041562fda66b346807392a5b
//
// Input: schemas/strand.schema.json
// sha256=857a35af89123d63b0b4248701c9aafe70948538b05b93ba32f41e8c636ae894
//
// Input: schemas/common-ids.schema.json
// sha256=993d518acb9207f123eeb5496c0e313320ad296ab0547c308fcf3fb3bf7faa2f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/policy.schema.json
// sha256=b6d399554a12c940bc78470ac0954c08e051caaf735625e065dddae01320354a
//
// Bindings: tools/closed-model-bindings.json
// sha256=08dd3be10645b0c4e133fe72a1a0f80596e47ca0c707a290dcd23d1116f56607

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
    pub mls_epoch: u64,
    pub response_signing_verification_method: DidUrl,
    pub response_signing_algorithm: IdentityLinkResponseSigningAlgorithm,
    pub response_signing_public_key_b64u: Base64UrlString,
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
