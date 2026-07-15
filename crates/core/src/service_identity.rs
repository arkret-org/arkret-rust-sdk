//! Service identity registration, recovery, and runtime state.
//!
//! These types implement the wire contract in
//! `service-operation-dtos.schema.json` and the lifecycle rules in
//! `identity-did.md` section 3.7. Services and providers use these types
//! directly; product crates must not define parallel request/response DTOs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{Did, Error, KeyStore, Result, ServiceType, canonical};

pub const SERVICE_REGISTRATION_ENSURE_OPERATION: &str =
    "ak.root.identity.service_registration.command.ensure";
pub const SERVICE_REGISTRATION_GET_OPERATION: &str =
    "ak.root.identity.service_registration.resource.get";
pub const SERVICE_REGISTRATION_ENSURE_PATH: &str =
    "/_arkret/root/identity/service-registrations:ensure";
pub const SERVICE_REGISTRATION_GET_PATH: &str = "/_arkret/root/identity/service-registrations";

/// Canonical public base URL used as one half of a service registration key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[cfg_attr(feature = "salvo", salvo(schema(value_type = String)))]
pub struct CanonicalServiceUrl(String);

impl CanonicalServiceUrl {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref().trim();
        let mut url = Url::parse(raw)
            .map_err(|error| Error::Protocol(format!("invalid service public base: {error}")))?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(Error::Protocol(
                "service public base scheme must be https or explicit-development http".to_owned(),
            ));
        }
        if url.host_str().is_none() {
            return Err(Error::Protocol(
                "service public base must include a host".to_owned(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Protocol(
                "service public base must not contain userinfo".to_owned(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(Error::Protocol(
                "service public base must not contain a query or fragment".to_owned(),
            ));
        }
        if url.port() == url.port_or_known_default() {
            url.set_port(None).map_err(|()| {
                Error::Protocol("service public base contains an invalid port".to_owned())
            })?;
        }
        let path = url.path().trim_end_matches('/');
        let canonical_path = if path.is_empty() {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        url.set_path(&canonical_path);
        let canonical = url.to_string();
        if canonical != raw {
            return Err(Error::Protocol(format!(
                "service public base is not canonical; use {canonical}"
            )));
        }
        Ok(Self(canonical))
    }

    pub fn canonicalize(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref().trim();
        let mut url = Url::parse(raw)
            .map_err(|error| Error::Protocol(format!("invalid service public base: {error}")))?;
        if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
            return Err(Error::Protocol(
                "service public base must be an http(s) URL with a host".to_owned(),
            ));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Protocol(
                "service public base must not contain userinfo, query, or fragment".to_owned(),
            ));
        }
        if url.port() == url.port_or_known_default() {
            url.set_port(None).map_err(|()| {
                Error::Protocol("service public base contains an invalid port".to_owned())
            })?;
        }
        let path = url.path().trim_end_matches('/');
        let canonical_path = if path.is_empty() {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        url.set_path(&canonical_path);
        Self::new(url.as_str())
    }

    pub fn require_https(&self) -> Result<()> {
        if self.0.starts_with("https://") {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "production service public base must use https: {}",
                self.0
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_url(&self) -> Url {
        Url::parse(&self.0).expect("CanonicalServiceUrl always stores a parsed URL")
    }
}

impl fmt::Debug for CanonicalServiceUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalServiceUrl")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalServiceUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for CanonicalServiceUrl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalServiceUrl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Stable provider lookup key. Only the three service-identity-owning roles
/// registered for `service_registration_key` are accepted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ServiceRegistrationKey {
    service_type: ServiceType,
    public_base: CanonicalServiceUrl,
}

impl ServiceRegistrationKey {
    pub fn new(service_type: ServiceType, public_base: CanonicalServiceUrl) -> Result<Self> {
        if !matches!(
            service_type,
            ServiceType::PrincipalServer | ServiceType::AuthServer | ServiceType::IdentityRegistry
        ) {
            return Err(Error::Protocol(format!(
                "service_type {} is not valid in a service registration key",
                service_type.as_str()
            )));
        }
        Ok(Self {
            service_type,
            public_base,
        })
    }

    pub fn service_type(&self) -> &ServiceType {
        &self.service_type
    }

    pub fn public_base(&self) -> &CanonicalServiceUrl {
        &self.public_base
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRegistrationKeyWire {
    service_type: ServiceType,
    public_base: CanonicalServiceUrl,
}

impl<'de> Deserialize<'de> for ServiceRegistrationKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServiceRegistrationKeyWire::deserialize(deserializer)?;
        Self::new(wire.service_type, wire.public_base).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceDidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: Did,
    pub public_key_multibase: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceDidEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub service_type: ServiceType,
    pub service_endpoint: CanonicalServiceUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceDidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Did,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    pub verification_method: Vec<ServiceDidVerificationMethod>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub service: Vec<ServiceDidEndpoint>,
}

impl ServiceDidDocument {
    pub fn validate_for(&self, key: &ServiceRegistrationKey) -> Result<()> {
        if self.id.method() != "webvh" {
            return Err(Error::Protocol(
                "service registration DID document id must use did:webvh".to_owned(),
            ));
        }
        if !self
            .context
            .iter()
            .any(|value| value == "https://www.w3.org/ns/did/v1")
        {
            return Err(Error::Protocol(
                "service DID document must include the DID Core context".to_owned(),
            ));
        }
        if self.verification_method.is_empty()
            || self.authentication.is_empty()
            || self.assertion_method.is_empty()
        {
            return Err(Error::Protocol(
                "service DID document must publish verification, authentication, and assertion keys"
                    .to_owned(),
            ));
        }
        for method in &self.verification_method {
            if method.method_type != "Multikey" || method.controller != self.id {
                return Err(Error::Protocol(
                    "service DID verification methods must be Multikey entries controlled by the service DID"
                        .to_owned(),
                ));
            }
            if !method.id.starts_with(&format!("{}#", self.id))
                || !is_multibase_base58(&method.public_key_multibase)
            {
                return Err(Error::Protocol(
                    "service DID verification method id or publicKeyMultibase is invalid"
                        .to_owned(),
                ));
            }
        }
        for reference in self.authentication.iter().chain(&self.assertion_method) {
            if !self
                .verification_method
                .iter()
                .any(|method| method.id == *reference)
            {
                return Err(Error::Protocol(
                    "service DID authentication and assertion methods must reference declared verification methods"
                        .to_owned(),
                ));
            }
        }
        for endpoint in &self.service {
            if endpoint.endpoint_type != "ArkretService"
                || !endpoint.id.starts_with(&format!("{}#", self.id))
                || !matches!(
                    endpoint.service_type,
                    ServiceType::PrincipalServer
                        | ServiceType::AuthServer
                        | ServiceType::IdentityRegistry
                )
            {
                return Err(Error::Protocol(
                    "service DID endpoints must use the closed ArkretService registration profile"
                        .to_owned(),
                ));
            }
        }
        let bindings = self
            .service
            .iter()
            .filter(|entry| {
                entry.endpoint_type == "ArkretService"
                    && entry.service_type == *key.service_type()
                    && entry.service_endpoint == *key.public_base()
            })
            .count();
        if bindings != 1 {
            return Err(Error::Protocol(
                "signed inception must contain exactly one ArkretService endpoint matching service_type and public_base"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn signing_key_multibase(&self) -> Option<&str> {
        let active = self.assertion_method.first()?;
        self.verification_method
            .iter()
            .find(|method| &method.id == active)
            .map(|method| method.public_key_multibase.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceWebvhInceptionParameters {
    pub scid: String,
    pub method: String,
    pub update_keys: Vec<String>,
    pub next_key_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceWebvhDataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
}

impl ServiceWebvhDataIntegrityProof {
    pub fn validate_shape(&self) -> Result<()> {
        if self.proof_type != "DataIntegrityProof"
            || self.cryptosuite != "eddsa-jcs-2022"
            || self.proof_purpose != "assertionMethod"
            || !is_multibase_base58(&self.proof_value)
            || !is_did_url(&self.verification_method)
        {
            return Err(Error::Protocol(
                "service identity proof does not match the eddsa-jcs-2022 profile".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceWebvhInceptionOperation {
    pub version_id: String,
    pub version_time: DateTime<Utc>,
    pub parameters: ServiceWebvhInceptionParameters,
    pub state: ServiceDidDocument,
    pub proof: Vec<ServiceWebvhDataIntegrityProof>,
}

impl ServiceWebvhInceptionOperation {
    pub fn validate_for(&self, key: &ServiceRegistrationKey) -> Result<()> {
        if !self.version_id.starts_with("1-")
            || self.parameters.method != "did:webvh:1.0"
            || self.parameters.update_keys.len() != 1
            || self.parameters.next_key_hashes.len() != 1
            || self.proof.is_empty()
        {
            return Err(Error::Protocol(
                "service registration requires a complete did:webvh v1 inception operation"
                    .to_owned(),
            ));
        }
        let version_hash = self.version_id.strip_prefix("1-").unwrap_or_default();
        if !is_base58btc_payload(version_hash)
            || !is_base58btc_payload(&self.parameters.scid)
            || self
                .parameters
                .update_keys
                .iter()
                .any(|key| !is_multibase_base58(key))
            || self
                .parameters
                .update_keys
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.parameters.update_keys.len()
        {
            return Err(Error::Protocol(
                "service registration WebVH identifiers or updateKeys are not canonical base58btc"
                    .to_owned(),
            ));
        }
        let did_prefix = format!("did:webvh:{}:", self.parameters.scid);
        if !self.state.id.as_str().starts_with(&did_prefix) {
            return Err(Error::Protocol(
                "WebVH inception SCID does not match the DID document id".to_owned(),
            ));
        }
        self.state.validate_for(key)?;
        for proof in &self.proof {
            proof.validate_shape()?;
            let public_key = proof
                .verification_method
                .strip_prefix("did:key:")
                .and_then(|value| value.split_once('#').map(|(key, _)| key))
                .ok_or_else(|| {
                    Error::Protocol(
                        "WebVH inception proof verificationMethod must be did:key".to_owned(),
                    )
                })?;
            if !self
                .parameters
                .update_keys
                .iter()
                .any(|key| key == public_key)
            {
                return Err(Error::Protocol(
                    "WebVH inception proof must reference an updateKeys entry".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn log_head_digest(&self) -> Result<String> {
        sha256_canonical(self)
    }

    pub fn control_key_digest(&self) -> Result<String> {
        let key = self.parameters.update_keys.first().ok_or_else(|| {
            Error::Protocol("WebVH inception updateKeys must not be empty".to_owned())
        })?;
        Ok(sha256_bytes(key.as_bytes()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ServiceRegistrationReceipt {
    pub receipt_id: String,
    pub registration_key: ServiceRegistrationKey,
    pub service_id: Did,
    pub version_id: String,
    pub log_head_digest: String,
    pub control_key_digest: String,
    pub issued_at: DateTime<Utc>,
    pub provider_service_id: Did,
    pub proof: ServiceWebvhDataIntegrityProof,
}

impl ServiceRegistrationReceipt {
    /// Recompute the stable receipt identifier from the canonical claims that
    /// exclude both `receipt_id` and `proof`.
    pub fn expected_receipt_id(&self) -> Result<String> {
        let claims = serde_json::json!({
            "registration_key": &self.registration_key,
            "service_id": &self.service_id,
            "version_id": &self.version_id,
            "log_head_digest": &self.log_head_digest,
            "control_key_digest": &self.control_key_digest,
            "issued_at": self.issued_at,
            "provider_service_id": &self.provider_service_id,
        });
        let digest = sha256_canonical(&claims)?;
        Ok(format!(
            "ak:service_registration_receipt:{}",
            digest.strip_prefix("sha256:").unwrap_or(&digest)
        ))
    }

    /// Build the exact `eddsa-jcs-2022` signing input for this receipt.
    ///
    /// The proof configuration excludes `proofValue`; the signed document
    /// excludes the complete `proof` object. Each canonical JSON value is
    /// hashed independently and the two 32-byte digests are concatenated.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut proof_config = serde_json::to_value(&self.proof)?;
        proof_config
            .as_object_mut()
            .ok_or_else(|| {
                Error::Protocol("service registration proof must be an object".to_owned())
            })?
            .remove("proofValue");
        let mut document = serde_json::to_value(self)?;
        document
            .as_object_mut()
            .ok_or_else(|| {
                Error::Protocol("service registration receipt must be an object".to_owned())
            })?
            .remove("proof");
        let proof_config = canonical::canonical_json_bytes(&proof_config)?;
        let document = canonical::canonical_json_bytes(&document)?;
        let mut binding = Vec::with_capacity(64);
        binding.extend_from_slice(&Sha256::digest(proof_config));
        binding.extend_from_slice(&Sha256::digest(document));
        Ok(binding)
    }

    /// Validate all proof bindings that can be checked without resolving the
    /// Provider DID verification method.
    pub fn validate_proof_binding(&self) -> Result<()> {
        self.proof.validate_shape()?;
        if self.receipt_id != self.expected_receipt_id()? {
            return Err(Error::Protocol(
                "service registration receipt_id does not match its canonical claims".to_owned(),
            ));
        }
        let provider_prefix = format!("{}#", self.provider_service_id);
        if !self.proof.verification_method.starts_with(&provider_prefix) {
            return Err(Error::Protocol(
                "service registration proof verificationMethod is not controlled by provider_service_id"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for(&self, key: &ServiceRegistrationKey, service_id: &Did) -> Result<()> {
        if &self.registration_key != key || &self.service_id != service_id {
            return Err(Error::Protocol(
                "service registration receipt key or service DID mismatch".to_owned(),
            ));
        }
        if !self
            .receipt_id
            .starts_with("ak:service_registration_receipt:")
            || !is_sha256_digest(&self.log_head_digest)
            || !is_sha256_digest(&self.control_key_digest)
        {
            return Err(Error::Protocol(
                "service registration receipt contains an invalid id or digest".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ServiceRegistrationEnsureRequestBody {
    pub service_type: ServiceType,
    pub public_base: CanonicalServiceUrl,
    pub inception_operation: ServiceWebvhInceptionOperation,
    pub idempotency_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_receipt: Option<ServiceRegistrationReceipt>,
}

impl ServiceRegistrationEnsureRequestBody {
    pub fn new(
        key: ServiceRegistrationKey,
        inception_operation: ServiceWebvhInceptionOperation,
        previous_receipt: Option<ServiceRegistrationReceipt>,
    ) -> Result<Self> {
        inception_operation.validate_for(&key)?;
        if let Some(receipt) = &previous_receipt {
            receipt.validate_for(&key, &inception_operation.state.id)?;
        }
        let idempotency_key = service_registration_idempotency_key(&key)?;
        Ok(Self {
            service_type: key.service_type,
            public_base: key.public_base,
            inception_operation,
            idempotency_key,
            previous_receipt,
        })
    }

    pub fn registration_key(&self) -> Result<ServiceRegistrationKey> {
        ServiceRegistrationKey::new(self.service_type, self.public_base.clone())
    }

    pub fn validate(&self) -> Result<()> {
        let key = self.registration_key()?;
        self.inception_operation.validate_for(&key)?;
        if self.idempotency_key != service_registration_idempotency_key(&key)? {
            return Err(Error::Protocol(
                "service registration idempotency_key does not match the registration key"
                    .to_owned(),
            ));
        }
        if let Some(receipt) = &self.previous_receipt {
            receipt.validate_for(&key, &self.inception_operation.state.id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ServiceRegistrationOutcome {
    pub service_id: Did,
    pub did_document: ServiceDidDocument,
    pub version_id: String,
    pub registration_receipt: ServiceRegistrationReceipt,
    pub created: bool,
}

impl ServiceRegistrationOutcome {
    pub fn validate_for(&self, key: &ServiceRegistrationKey) -> Result<()> {
        if self.did_document.id != self.service_id {
            return Err(Error::Protocol(
                "service registration outcome DID document id mismatch".to_owned(),
            ));
        }
        self.did_document.validate_for(key)?;
        self.registration_receipt
            .validate_for(key, &self.service_id)?;
        if self.registration_receipt.version_id != self.version_id {
            return Err(Error::Protocol(
                "service registration receipt version_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_ensure_response(
        &self,
        request: &ServiceRegistrationEnsureRequestBody,
    ) -> Result<()> {
        request.validate()?;
        let key = request.registration_key()?;
        self.validate_for(&key)?;
        if self.service_id != request.inception_operation.state.id {
            return Err(Error::Protocol(
                "Provider returned a service DID different from the signed inception".to_owned(),
            ));
        }
        if self.did_document != request.inception_operation.state {
            return Err(Error::Protocol(
                "Provider returned a DID document different from the signed inception".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn service_registration_idempotency_key(key: &ServiceRegistrationKey) -> Result<String> {
    let canonical = canonical::canonical_json_bytes(&serde_json::to_value(key)?)?;
    Ok(format!(
        "ak:service-registration:{}",
        hex::encode(Sha256::digest(canonical))
    ))
}

/// Deterministic WebVH local id for a registration key. The principal
/// server's own long-standing `service` slot is retained; every other role is
/// namespaced by the canonical registration-key digest.
pub fn service_registration_local_id(key: &ServiceRegistrationKey) -> Result<String> {
    if key.service_type() == &ServiceType::PrincipalServer {
        return Ok("service".to_owned());
    }
    Ok(format!("service-{}", &bundle_key_digest(key)?[..24]))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceIdentityKeyRef(String);

impl ServiceIdentityKeyRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::Protocol(
                "service identity key reference must not be empty".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentityProviderRef {
    pub name: String,
    pub endpoint: CanonicalServiceUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalServiceIdentity {
    pub service_id: Did,
    pub registration_key: ServiceRegistrationKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<ServiceIdentityProviderRef>,
    pub signing_key_refs: Vec<ServiceIdentityKeyRef>,
    pub active_signing_key_ref: ServiceIdentityKeyRef,
    pub control_key_ref: ServiceIdentityKeyRef,
    pub version_id: String,
    pub last_verified_at: DateTime<Utc>,
}

impl LocalServiceIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.signing_key_refs.is_empty()
            || !self.signing_key_refs.contains(&self.active_signing_key_ref)
            || self.version_id.is_empty()
        {
            return Err(Error::Protocol(
                "local service identity key references or version are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredServiceIdentity {
    pub identity: LocalServiceIdentity,
    pub did_document: ServiceDidDocument,
    pub registration_receipt: ServiceRegistrationReceipt,
    pub stored_at: DateTime<Utc>,
}

impl StoredServiceIdentity {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        self.did_document
            .validate_for(&self.identity.registration_key)?;
        if self.did_document.id != self.identity.service_id
            || self.registration_receipt.version_id != self.identity.version_id
        {
            return Err(Error::Protocol(
                "stored service identity document or receipt does not match the runtime identity"
                    .to_owned(),
            ));
        }
        self.registration_receipt
            .validate_for(&self.identity.registration_key, &self.identity.service_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentityBundle {
    pub schema: String,
    pub identity: StoredServiceIdentity,
    pub webvh_history: Vec<ServiceWebvhInceptionOperation>,
    pub receipt_chain: Vec<ServiceRegistrationReceipt>,
    pub exported_at: DateTime<Utc>,
}

impl ServiceIdentityBundle {
    pub const SCHEMA: &'static str = "ak.service_identity_bundle.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.webvh_history.is_empty()
            || self.receipt_chain.is_empty()
        {
            return Err(Error::Protocol(
                "identity bundle schema, WebVH history, or receipt chain is incomplete".to_owned(),
            ));
        }
        self.identity.validate()?;
        let key = &self.identity.identity.registration_key;
        self.webvh_history
            .first()
            .expect("checked non-empty")
            .validate_for(key)?;
        if self
            .webvh_history
            .first()
            .expect("checked non-empty")
            .state
            .id
            != self.identity.identity.service_id
        {
            return Err(Error::Protocol(
                "identity bundle history belongs to a different service DID".to_owned(),
            ));
        }
        for receipt in &self.receipt_chain {
            receipt.validate_for(key, &self.identity.identity.service_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceIdentityDiagnostic {
    ProviderAmbiguous,
    ProviderNotConfigured,
    KeyMismatch,
    RestoreFailed,
    FirstProvisioningRequired,
    RegistrationKeyDrift,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServiceIdentityState {
    Ready {
        identity: LocalServiceIdentity,
    },
    DegradedStored {
        identity: LocalServiceIdentity,
        retry_at: DateTime<Utc>,
        last_error: String,
    },
    WaitingProvider {
        registration_key: ServiceRegistrationKey,
        retry_at: DateTime<Utc>,
    },
    RegistrationKeyDrift {
        identity: LocalServiceIdentity,
        stored_key: ServiceRegistrationKey,
        computed_key: ServiceRegistrationKey,
    },
    Conflict {
        stored_service_id: Did,
        provider_service_id: Did,
    },
    Faulted {
        diagnostic: ServiceIdentityDiagnostic,
        next_action: String,
    },
}

impl ServiceIdentityState {
    pub fn identity(&self) -> Option<&LocalServiceIdentity> {
        match self {
            Self::Ready { identity }
            | Self::DegradedStored { identity, .. }
            | Self::RegistrationKeyDrift { identity, .. } => Some(identity),
            Self::WaitingProvider { .. } | Self::Conflict { .. } | Self::Faulted { .. } => None,
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(
            self,
            Self::Ready { .. } | Self::DegradedStored { .. } | Self::RegistrationKeyDrift { .. }
        )
    }

    pub fn permits_identity_mutation(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(identity) = self.identity() {
            identity.validate()?;
        }
        match self {
            Self::DegradedStored { last_error, .. } if last_error.trim().is_empty() => {
                return Err(Error::Protocol(
                    "degraded service identity state must include a last_error".to_owned(),
                ));
            }
            Self::RegistrationKeyDrift {
                identity,
                stored_key,
                computed_key,
            } => {
                if stored_key != &identity.registration_key {
                    return Err(Error::Protocol(
                        "stored registration key must match the active service identity".to_owned(),
                    ));
                }
                if computed_key == stored_key {
                    return Err(Error::Protocol(
                        "registration key drift requires distinct stored and computed keys"
                            .to_owned(),
                    ));
                }
            }
            Self::Conflict {
                stored_service_id,
                provider_service_id,
            } if stored_service_id == provider_service_id => {
                return Err(Error::Protocol(
                    "service identity conflict requires distinct stored and Provider DIDs"
                        .to_owned(),
                ));
            }
            Self::Faulted { next_action, .. } if next_action.trim().is_empty() => {
                return Err(Error::Protocol(
                    "faulted service identity state must include a next_action".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedService {
    pub service_id: Did,
    pub service_type: ServiceType,
    pub endpoint: CanonicalServiceUrl,
    pub supported_operations: Vec<String>,
    pub resolved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ResolvedService {
    pub fn validate(&self) -> Result<()> {
        if self
            .supported_operations
            .iter()
            .any(|operation| !self.service_type.permits_operation(operation))
        {
            return Err(Error::Protocol(format!(
                "resolved {} advertises an operation forbidden for {}",
                self.service_id,
                self.service_type.as_str()
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityBundleBackendAvailability {
    Available,
    Unavailable(String),
}

pub trait IdentityBundleBackend: Send + Sync {
    fn probe(&self) -> IdentityBundleBackendAvailability;
    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<ServiceIdentityBundle>>;
    fn store(&self, bundle: &ServiceIdentityBundle) -> Result<()>;
    fn delete(&self, key: &ServiceRegistrationKey) -> Result<()>;
}

pub struct FileIdentityBundleBackend {
    directory: PathBuf,
}

impl FileIdentityBundleBackend {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path_for(&self, key: &ServiceRegistrationKey) -> Result<PathBuf> {
        Ok(self
            .directory
            .join(format!("{}.json", bundle_key_digest(key)?)))
    }
}

impl IdentityBundleBackend for FileIdentityBundleBackend {
    fn probe(&self) -> IdentityBundleBackendAvailability {
        match fs::create_dir_all(&self.directory) {
            Ok(()) => IdentityBundleBackendAvailability::Available,
            Err(error) => IdentityBundleBackendAvailability::Unavailable(error.to_string()),
        }
    }

    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<ServiceIdentityBundle>> {
        let path = self.path_for(key)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_protocol_error("read identity bundle", &path, error)),
        };
        let bundle: ServiceIdentityBundle = serde_json::from_slice(&bytes)?;
        bundle.validate()?;
        Ok(Some(bundle))
    }

    fn store(&self, bundle: &ServiceIdentityBundle) -> Result<()> {
        bundle.validate()?;
        fs::create_dir_all(&self.directory).map_err(|error| {
            io_protocol_error("create identity bundle directory", &self.directory, error)
        })?;
        let path = self.path_for(&bundle.identity.identity.registration_key)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let bytes = serde_json::to_vec_pretty(bundle)?;
        fs::write(&temporary, bytes)
            .map_err(|error| io_protocol_error("write identity bundle", &temporary, error))?;
        fs::rename(&temporary, &path)
            .map_err(|error| io_protocol_error("commit identity bundle", &path, error))
    }

    fn delete(&self, key: &ServiceRegistrationKey) -> Result<()> {
        let path = self.path_for(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_protocol_error("delete identity bundle", &path, error)),
        }
    }
}

pub struct KeyStoreIdentityBundleBackend {
    key_store: Arc<dyn KeyStore>,
    namespace: String,
}

impl KeyStoreIdentityBundleBackend {
    pub fn new(key_store: Arc<dyn KeyStore>, namespace: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        if namespace.trim().is_empty() {
            return Err(Error::Protocol(
                "identity bundle KeyStore namespace must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            key_store,
            namespace,
        })
    }

    fn storage_id(&self, key: &ServiceRegistrationKey) -> Result<String> {
        Ok(format!("{}:{}", self.namespace, bundle_key_digest(key)?))
    }
}

impl IdentityBundleBackend for KeyStoreIdentityBundleBackend {
    fn probe(&self) -> IdentityBundleBackendAvailability {
        match self.key_store.list() {
            Ok(_) => IdentityBundleBackendAvailability::Available,
            Err(error) => IdentityBundleBackendAvailability::Unavailable(error.to_string()),
        }
    }

    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<ServiceIdentityBundle>> {
        let id = self.storage_id(key)?;
        let bytes = match self.key_store.load(&id) {
            Ok(bytes) => bytes,
            Err(error) if error.is_key_store_not_found() => return Ok(None),
            Err(error) => return Err(error),
        };
        let bundle: ServiceIdentityBundle = serde_json::from_slice(bytes.as_slice())?;
        bundle.validate()?;
        Ok(Some(bundle))
    }

    fn store(&self, bundle: &ServiceIdentityBundle) -> Result<()> {
        bundle.validate()?;
        let id = self.storage_id(&bundle.identity.identity.registration_key)?;
        self.key_store.store(&id, &serde_json::to_vec(bundle)?)
    }

    fn delete(&self, key: &ServiceRegistrationKey) -> Result<()> {
        self.key_store.delete(&self.storage_id(key)?)
    }
}

fn bundle_key_digest(key: &ServiceRegistrationKey) -> Result<String> {
    let bytes = canonical::canonical_json_bytes(&serde_json::to_value(key)?)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn sha256_canonical(value: &impl Serialize) -> Result<String> {
    let bytes = canonical::canonical_json_bytes(&serde_json::to_value(value)?)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_base58btc_payload(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
        })
}

fn is_multibase_base58(value: &str) -> bool {
    value.strip_prefix('z').is_some_and(is_base58btc_payload)
}

fn is_did_url(value: &str) -> bool {
    value
        .split_once('#')
        .is_some_and(|(did, fragment)| !fragment.is_empty() && Did::new(did.to_owned()).is_ok())
}

fn io_protocol_error(action: &str, path: &Path, error: std::io::Error) -> Error {
    Error::Protocol(format!("failed to {action} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryKeyStore;

    fn registration_key() -> ServiceRegistrationKey {
        ServiceRegistrationKey::new(
            ServiceType::AuthServer,
            CanonicalServiceUrl::new("https://auth.example/").unwrap(),
        )
        .unwrap()
    }

    fn inception() -> ServiceWebvhInceptionOperation {
        let did = Did::new("did:webvh:QmScid:identity.example:webvh:auth").unwrap();
        let signing_key = "z6MkiSigning".to_owned();
        let update_key = "z6MkiUpdate".to_owned();
        let signing_id = format!("{did}#did-key-1");
        ServiceWebvhInceptionOperation {
            version_id: "1-QmVersion".to_owned(),
            version_time: "2026-07-15T00:00:00Z".parse().unwrap(),
            parameters: ServiceWebvhInceptionParameters {
                scid: "QmScid".to_owned(),
                method: "did:webvh:1.0".to_owned(),
                update_keys: vec![update_key.clone()],
                next_key_hashes: vec!["QmNextKeyHash".to_owned()],
            },
            state: ServiceDidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: did.clone(),
                also_known_as: Vec::new(),
                verification_method: vec![ServiceDidVerificationMethod {
                    id: signing_id.clone(),
                    method_type: "Multikey".to_owned(),
                    controller: did.clone(),
                    public_key_multibase: signing_key,
                }],
                authentication: vec![signing_id.clone()],
                assertion_method: vec![signing_id],
                service: vec![ServiceDidEndpoint {
                    id: format!("{did}#service"),
                    endpoint_type: "ArkretService".to_owned(),
                    service_type: ServiceType::AuthServer,
                    service_endpoint: CanonicalServiceUrl::new("https://auth.example/").unwrap(),
                }],
            },
            proof: vec![ServiceWebvhDataIntegrityProof {
                proof_type: "DataIntegrityProof".to_owned(),
                cryptosuite: "eddsa-jcs-2022".to_owned(),
                verification_method: format!("did:key:{update_key}#{update_key}"),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: "zProof".to_owned(),
            }],
        }
    }

    fn receipt(operation: &ServiceWebvhInceptionOperation) -> ServiceRegistrationReceipt {
        let provider_service_id =
            Did::new("did:webvh:QmProvider:identity.example:webvh:service").unwrap();
        let mut receipt = ServiceRegistrationReceipt {
            receipt_id: format!("ak:service_registration_receipt:{}", "a".repeat(64)),
            registration_key: registration_key(),
            service_id: operation.state.id.clone(),
            version_id: operation.version_id.clone(),
            log_head_digest: operation.log_head_digest().unwrap(),
            control_key_digest: operation.control_key_digest().unwrap(),
            issued_at: "2026-07-15T00:00:01Z".parse().unwrap(),
            provider_service_id: provider_service_id.clone(),
            proof: ServiceWebvhDataIntegrityProof {
                proof_type: "DataIntegrityProof".to_owned(),
                cryptosuite: "eddsa-jcs-2022".to_owned(),
                verification_method: format!("{provider_service_id}#service-key"),
                proof_purpose: "assertionMethod".to_owned(),
                proof_value: "zReceiptProof".to_owned(),
            },
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        receipt
    }

    fn stored_identity() -> StoredServiceIdentity {
        let operation = inception();
        let receipt = receipt(&operation);
        StoredServiceIdentity {
            identity: LocalServiceIdentity {
                service_id: operation.state.id.clone(),
                registration_key: registration_key(),
                provider: Some(ServiceIdentityProviderRef {
                    name: "provider".to_owned(),
                    endpoint: CanonicalServiceUrl::new("https://identity.example/").unwrap(),
                }),
                signing_key_refs: vec![ServiceIdentityKeyRef::new("signing-key").unwrap()],
                active_signing_key_ref: ServiceIdentityKeyRef::new("signing-key").unwrap(),
                control_key_ref: ServiceIdentityKeyRef::new("control-key").unwrap(),
                version_id: operation.version_id.clone(),
                last_verified_at: "2026-07-15T00:00:01Z".parse().unwrap(),
            },
            did_document: operation.state,
            registration_receipt: receipt,
            stored_at: "2026-07-15T00:00:01Z".parse().unwrap(),
        }
    }

    #[test]
    fn canonical_service_url_rejects_noncanonical_input() {
        assert!(CanonicalServiceUrl::new("HTTPS://AUTH.EXAMPLE").is_err());
        assert_eq!(
            CanonicalServiceUrl::canonicalize("HTTPS://AUTH.EXAMPLE")
                .unwrap()
                .as_str(),
            "https://auth.example/"
        );
        assert!(CanonicalServiceUrl::new("https://auth.example/?x=1").is_err());
    }

    #[test]
    fn registration_key_rejects_non_identity_service_type() {
        assert!(
            ServiceRegistrationKey::new(
                ServiceType::MediaService,
                CanonicalServiceUrl::new("https://media.example/").unwrap()
            )
            .is_err()
        );
        let json = serde_json::json!({
            "service_type": "media_service",
            "public_base": "https://media.example/"
        });
        assert!(serde_json::from_value::<ServiceRegistrationKey>(json).is_err());
    }

    #[test]
    fn service_document_rejects_endpoints_outside_registration_context() {
        let mut operation = inception();
        operation.state.service.push(ServiceDidEndpoint {
            id: format!("{}#notary", operation.state.id),
            endpoint_type: "ArkretService".to_owned(),
            service_type: ServiceType::Notary,
            service_endpoint: CanonicalServiceUrl::new("https://notary.example/").unwrap(),
        });
        assert!(operation.validate_for(&registration_key()).is_err());
    }

    #[test]
    fn ensure_request_and_outcome_validate_endpoint_binding() {
        let operation = inception();
        let request =
            ServiceRegistrationEnsureRequestBody::new(registration_key(), operation.clone(), None)
                .unwrap();
        request.validate().unwrap();
        let outcome = ServiceRegistrationOutcome {
            service_id: operation.state.id.clone(),
            did_document: operation.state.clone(),
            version_id: operation.version_id.clone(),
            registration_receipt: receipt(&operation),
            created: true,
        };
        outcome.validate_ensure_response(&request).unwrap();

        let mut wrong = request;
        wrong.public_base = CanonicalServiceUrl::new("https://other.example/").unwrap();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn service_registration_receipt_binds_claims_and_provider_controller() {
        let operation = inception();
        let receipt = receipt(&operation);
        receipt
            .validate_for(&registration_key(), &operation.state.id)
            .unwrap();

        let mut tampered = receipt.clone();
        tampered.control_key_digest = format!("sha256:{}", "b".repeat(64));
        assert!(tampered.validate_proof_binding().is_err());

        let mut wrong_controller = receipt;
        wrong_controller.proof.verification_method =
            "did:webvh:QmOther:identity.example:webvh:service#service-key".to_owned();
        assert!(wrong_controller.validate_proof_binding().is_err());
    }

    #[test]
    fn keystore_bundle_backend_round_trips_and_validates() {
        let operation = inception();
        let stored = stored_identity();
        let bundle = ServiceIdentityBundle {
            schema: ServiceIdentityBundle::SCHEMA.to_owned(),
            receipt_chain: vec![stored.registration_receipt.clone()],
            identity: stored,
            webvh_history: vec![operation],
            exported_at: "2026-07-15T00:00:02Z".parse().unwrap(),
        };
        let backend = KeyStoreIdentityBundleBackend::new(
            Arc::new(InMemoryKeyStore::new()),
            "arkret:identity-bundle",
        )
        .unwrap();
        backend.store(&bundle).unwrap();
        assert_eq!(backend.load(&registration_key()).unwrap(), Some(bundle));
        backend.delete(&registration_key()).unwrap();
        assert!(backend.load(&registration_key()).unwrap().is_none());
    }

    #[test]
    fn degraded_stored_runs_but_cannot_mutate_identity() {
        let identity = stored_identity().identity;
        let retry_at: DateTime<Utc> = "2026-07-15T00:05:00Z".parse().unwrap();
        let state = ServiceIdentityState::DegradedStored {
            identity,
            retry_at,
            last_error: "provider unavailable".to_owned(),
        };
        assert!(state.is_ready());
        assert!(!state.permits_identity_mutation());
        state.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&state).unwrap()["retry_at"],
            "2026-07-15T00:05:00Z"
        );
    }

    #[test]
    fn registration_key_drift_serves_without_identity_mutation() {
        let identity = stored_identity().identity;
        let state = ServiceIdentityState::RegistrationKeyDrift {
            stored_key: identity.registration_key.clone(),
            computed_key: ServiceRegistrationKey::new(
                ServiceType::AuthServer,
                CanonicalServiceUrl::new("https://new-auth.example/").unwrap(),
            )
            .unwrap(),
            identity,
        };
        assert!(state.identity().is_some());
        assert!(state.is_ready());
        assert!(!state.permits_identity_mutation());
        state.validate().unwrap();
    }

    #[test]
    fn conflicting_provider_mapping_fails_closed() {
        let state = ServiceIdentityState::Conflict {
            stored_service_id: Did::new("did:webvh:QmStored:identity.example:webvh:auth").unwrap(),
            provider_service_id: Did::new("did:webvh:QmProvider:identity.example:webvh:auth")
                .unwrap(),
        };
        assert!(state.identity().is_none());
        assert!(!state.is_ready());
        assert!(!state.permits_identity_mutation());
        state.validate().unwrap();
        let serialized = serde_json::to_value(&state).unwrap();
        assert_eq!(
            serde_json::from_value::<ServiceIdentityState>(serialized).unwrap(),
            state
        );

        let same_did = Did::new("did:webvh:QmStored:identity.example:webvh:auth").unwrap();
        assert!(
            ServiceIdentityState::Conflict {
                stored_service_id: same_did.clone(),
                provider_service_id: same_did,
            }
            .validate()
            .is_err()
        );
    }
}
