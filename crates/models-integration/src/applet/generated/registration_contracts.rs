// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-registration-epoch-transcript.schema.json
// sha256=a0103ec29a9c5dbfe919b3cd8a72b37bda027e3af1438cc57d05052fba4ce94d
//
// Input: schemas/account-operations.schema.json
// sha256=09a9261669e5c9730cf71fb0ac935cd8bcb4d6d937273778151f9a58495bf5f6
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/applet-registration-epoch-evidence.schema.json
// sha256=4b3f70151b981ebc878afc584d5ad3d0e8a07d87c180747fcd4f35eff3bd67e6
//
// Bindings: tools/closed-model-bindings.json
// sha256=7ef2bac74ff32b9de78cac5bb9318e8c3d600fb7d2d320e1f3fd2fa3d5a5493c

/// Counterpart: `applet-registration-epoch-transcript.schema.json#/$defs/did_method_version`.
/// Method-specific version evidence captured with an Applet registration
/// epoch (`applet-registration-epoch-transcript.schema.json#/$defs/did_method_version`).
///
/// Only the versioned `did:webvh` and `did:key` adapters are accepted: a
/// `did:key` carries its synthetic immutable `version_id`, and a `did:webvh`
/// carries `version_id`, `version_created_at`, or both. `unversioned_refetch` is
/// always `false`, because a `did:web` current snapshot cannot support
/// historical producer verification. Deserialization enforces the same
/// closed shape.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppletDidMethodVersionEvidence {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub version_created_at: Option<DateTime<Utc>>,
    pub unversioned_refetch: bool,
}

/// Counterpart: `applet-registration-epoch-evidence.schema.json`.
/// Captured DID-document and signing-key evidence for an Applet registration
/// epoch. Reducers expand this snapshot when checking delegated Applet grants
/// and fail closed if the service DID document or accepted signing key set no
/// longer matches the install-time epoch.
///
/// Deserialization enforces the closed
/// `applet-registration-epoch-evidence.schema.json` shape: `did` is a bare
/// `did:webvh` or `did:key` whose method equals
/// `method_version_evidence.method`, and `accepted_signing_keys` is
/// `minItems: 1` / `uniqueItems: true`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AppletRegistrationEpochEvidence {
    pub did: Did,
    pub document_digest: Hash,
    pub method_version_evidence: AppletDidMethodVersionEvidence,
    pub accepted_signing_keys: Vec<AppletAcceptedSigningKeyEvidence>,
}
