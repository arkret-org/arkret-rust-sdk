// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/applet-registration-epoch-transcript.schema.json
// sha256=a67eef6a3366af77862fc14c120746072433f244fc653196afb4960e2080faea
//
// Input: schemas/account-operations.schema.json
// sha256=c6611a13d214c89389ba946b1a4d7b61450fe3d21caf07fce698927c51666d05
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/applet-registration-epoch-evidence.schema.json
// sha256=e37fbee7e8449347f9fd34508bf93e3ea709db3cd9e31e01ece79b0c0f0f09ae
//
// Bindings: tools/closed-model-bindings.json
// sha256=b257098f22d86bc6df1aedba2505bb77e493706f81c77fbf48be9755e324fe59

/// Counterpart: `applet-registration-epoch-transcript.schema.json#/$defs/did_method_version`.
/// Method-specific version evidence captured with an Applet registration
/// epoch (`applet-registration-epoch-transcript.schema.json#/$defs/did_method_version`).
///
/// Only the versioned `did:webvh` and `did:key` adapters are accepted: a
/// `did:key` carries its synthetic immutable `version_id`, and a `did:webvh`
/// carries `version_id`, `version_time`, or both. `unversioned_refetch` is
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
    pub version_time: Option<DateTime<Utc>>,
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
