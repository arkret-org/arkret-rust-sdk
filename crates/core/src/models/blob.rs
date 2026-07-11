use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BlobVisibility {
    Public,
    #[default]
    RealmBound,
    ActorPrivate,
    DeviceBound,
}

impl BlobVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::RealmBound => "realm_bound",
            Self::ActorPrivate => "actor_private",
            Self::DeviceBound => "device_bound",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Hash>,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadOutcome {
    pub blob_ref: BlobRef,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub content_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_receipt: Option<UploadReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignRequestBody {
    pub blob_ref: BlobRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignOutcome {
    pub url: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub nonce: String,
    pub access_scope: BlobPresignAccessScope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignAccessScope {
    pub method: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_range: Option<[u64; 2]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignPayload {
    pub scheme: String,
    pub blob_ref: BlobRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer_service_id: Did,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub purpose: String,
    pub nonce: String,
    pub access_scope: BlobPresignAccessScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience_hint: Option<Did>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignDetachedJwsProof {
    pub kind: String,
    pub alg: String,
    pub kid: String,
    pub jws: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignEnvelope {
    pub payload: BlobPresignPayload,
    pub proof: BlobPresignDetachedJwsProof,
}
