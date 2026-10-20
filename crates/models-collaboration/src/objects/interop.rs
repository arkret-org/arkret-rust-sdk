//! Interop schema artifact counterparts (MIMI and media faces).

use std::collections::BTreeMap;

use arkret_wire::{
    DidCoreId, Hash, MimiRoomUri, MimiUri, MlsGroupId, PayloadProof, ProofContextId, RealmId,
    StrandId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
/// Counterpart for
/// `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/provider_directory/properties/mimi`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProviderDirectoryMimi {
    pub protocol_draft: String,
    pub content_draft: String,
    pub room_policy_draft: String,
    pub identifier_draft: String,
    pub base_url: String,
    pub provider_id: MimiUri,
    pub endpoints: Vec<ProviderDirectoryEndpoint>,
    pub features: Vec<String>,
    pub mls_cipher_suites: Vec<String>,
    pub content_profiles: Vec<String>,
    pub room_policy_components: Vec<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

/// One signed feature-to-path row in a MIMI provider directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProviderDirectoryEndpoint {
    pub endpoint_id: String,
    pub relative_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(transparent)]
pub struct ProviderDirectoryProof(pub PayloadProof);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ProviderDirectory {
    pub schema: String,
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub supported_profiles: Vec<String>,
    pub mimi: ProviderDirectoryMimi,
    pub proof: ProviderDirectoryProof,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

impl ProviderDirectory {
    /// Exact signed projection from `mimi-interop.md` section 3.1. Draft
    /// extensions and the proof wrapper are deliberately excluded.
    pub fn unsigned_projection(&self) -> Value {
        serde_json::json!({
            "context": ProofContextId::MIMI_PROVIDER_DIRECTORY_PROOF_V1,
            "schema": self.schema,
            "service_id": self.service_id,
            "service_kind": self.service_kind,
            "supported_profiles": self.supported_profiles,
            "mimi": {
                "protocol_draft": self.mimi.protocol_draft,
                "content_draft": self.mimi.content_draft,
                "room_policy_draft": self.mimi.room_policy_draft,
                "identifier_draft": self.mimi.identifier_draft,
                "base_url": self.mimi.base_url,
                "provider_id": self.mimi.provider_id,
                "endpoints": self.mimi.endpoints,
                "features": self.mimi.features,
                "mls_cipher_suites": self.mimi.mls_cipher_suites,
                "content_profiles": self.mimi.content_profiles,
                "room_policy_components": self.mimi.room_policy_components,
            }
        })
    }

    pub fn unsigned_projection_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&self.unsigned_projection())
    }

    pub fn payload_digest(&self) -> arkret_wire::Result<Hash> {
        Ok(Hash::new(arkret_canonical::sha256_digest(
            &self.unsigned_projection_bytes()?,
        ))?)
    }

    /// The registry binding signs the projection digest AND proof metadata.
    /// Signing only the projection would leave freshness unauthenticated.
    pub fn proof_binding_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        if self.proof.0.payload_digest != self.payload_digest()? {
            return Err(arkret_wire::WireError::Protocol(
                "MIMI directory projection digest mismatch".into(),
            ));
        }
        let mut binding = self.unsigned_projection();
        let object = binding.as_object_mut().expect("typed projection object");
        object.insert(
            "payload_digest".into(),
            serde_json::to_value(&self.proof.0.payload_digest)?,
        );
        object.insert(
            "verification_method".into(),
            serde_json::to_value(&self.proof.0.verification_method)?,
        );
        object.insert(
            "created_at".into(),
            Value::String(arkret_canonical::format_timestamp_canonical(
                self.proof.0.created_at,
            )),
        );
        Ok(arkret_canonical::canonical_json_bytes(&binding)?)
    }

    /// Validate the closed v1 capability declaration without normalizing it.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        fn invalid(message: &str) -> arkret_wire::WireError {
            arkret_wire::WireError::Protocol(message.into())
        }
        fn sorted(values: &[String]) -> bool {
            !values.is_empty()
                && values.iter().all(|v| !v.trim().is_empty())
                && values.windows(2).all(|v| v[0].as_bytes() < v[1].as_bytes())
        }
        if self.schema != arkret_wire::SchemaId::MIMI_INTEROP_V1
            || self.service_kind != "mimi_provider_facade"
            || !sorted(&self.supported_profiles)
            || !self
                .supported_profiles
                .iter()
                .any(|v| v == arkret_wire::ProfileId::MIMI_INTEROP_V1)
            || self.mimi.protocol_draft != "draft-ietf-mimi-protocol-06"
            || self.mimi.content_draft != "draft-ietf-mimi-content-08"
            || self.mimi.room_policy_draft != "draft-ietf-mimi-room-policy-03"
            || self.mimi.identifier_draft != "draft-kohbrok-mimi-identifiers-01"
        {
            return Err(invalid("MIMI directory profile or draft mismatch"));
        }
        const FEATURES: &[&str] = &[
            "consent",
            "identifier_query",
            "key_material",
            "notify",
            "proxy_download",
            "report_abuse",
            "room_update",
            "submit_message",
        ];
        const CONTENT: &[&str] = &[
            "application/mimi-content",
            "application/vnd.arkret.content+json",
            "text/markdown;variant=GFM-MIMI",
            "text/plain;charset=utf-8",
        ];
        if !sorted(&self.mimi.features)
            || self
                .mimi
                .features
                .iter()
                .any(|v| !FEATURES.contains(&v.as_str()))
            || !sorted(&self.mimi.mls_cipher_suites)
            || self
                .mimi
                .mls_cipher_suites
                .iter()
                .any(|v| v != "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
            || !sorted(&self.mimi.content_profiles)
            || self
                .mimi
                .content_profiles
                .iter()
                .any(|v| !CONTENT.contains(&v.as_str()))
            || !sorted(&self.mimi.room_policy_components)
            || self.mimi.endpoints.is_empty()
            || !self
                .mimi
                .endpoints
                .windows(2)
                .all(|v| v[0].endpoint_id.as_bytes() < v[1].endpoint_id.as_bytes())
            || self.mimi.endpoints.iter().any(|v| {
                !FEATURES.contains(&v.endpoint_id.as_str())
                    || !valid_directory_path(&v.relative_path)
            })
        {
            return Err(invalid(
                "MIMI directory capabilities or endpoint rows are invalid",
            ));
        }
        self.proof.0.validate_production()?;
        Ok(())
    }
}

fn valid_directory_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\\' | '?' | '#'))
    {
        return false;
    }
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hex = |v: u8| (v as char).to_digit(16).map(|v| v as u8);
            let Some(high) = bytes.next().and_then(hex) else {
                return false;
            };
            let Some(low) = bytes.next().and_then(hex) else {
                return false;
            };
            let byte = high * 16 + low;
            if matches!(byte, b'/' | b'\\') {
                return false;
            }
            decoded.push(byte);
        } else {
            decoded.push(byte);
        }
    }
    !decoded
        .split(|v| *v == b'/')
        .any(|s| s == b"." || s == b"..")
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/room_binding/properties/payload/
/// properties/binding_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBindingPayloadBindingScope {
    pub realm_id: RealmId,
    pub strand_id: StrandId,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBindingPayload {
    pub profile: String,
    pub mimi_room_uri: MimiRoomUri,
    pub binding_scope: RoomBindingPayloadBindingScope,
    pub hub_provider_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follower_provider_ids: Option<Vec<DidCoreId>>,
    pub local_provider_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<MlsGroupId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub kind: String,
    pub payload: RoomBindingPayload,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

include!("generated/interop_contracts.rs");
