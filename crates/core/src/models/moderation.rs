use super::*;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModerationEvidencePackage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<Hash>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportRequestBody {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    pub target_ref: String,
    pub report_reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub evidence_package: Option<ModerationEvidencePackage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub franking_proof: Option<FrankingProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportOutcome {
    pub report_id: String,
    pub status: String,
    /// DIDs the report was routed to. Per
    /// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`
    /// this is an array of DID strings (the schema is closed), matching the
    /// `routed_to | did[]` shape in `content-moderation.md` /
    /// `service-http-binding.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to: Vec<Did>,
}
