//! Service identity registration wire contract.
//!
//! These types implement the wire contract in
//! `service-operation-dtos.schema.json` and the lifecycle rules in
//! `identity-did.md` section 3.7. Services and providers use these types
//! directly; product crates must not define parallel request/response DTOs.
//! Runtime state (local identity bundles and KeyStore/file persistence) is
//! owned by `arkret-identity`.

use std::fmt;

use arkret_canonical::canonical;
use arkret_wire::{Did, Error, Result, ServiceKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use url::Url;

pub const SERVICE_REGISTRATION_ENSURE_PATH: &str =
    "/_arkret/root/identity/service-registrations:ensure";
pub const SERVICE_REGISTRATION_GET_PATH: &str = "/_arkret/root/identity/service-registrations";

/// Canonical public base URL used as one half of a service registration key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRegistrationKey {
    service_kind: ServiceKind,
    public_base: CanonicalServiceUrl,
}

impl ServiceRegistrationKey {
    pub fn new(service_kind: ServiceKind, public_base: CanonicalServiceUrl) -> Result<Self> {
        if !matches!(
            service_kind,
            ServiceKind::PrincipalServer | ServiceKind::AuthServer | ServiceKind::IdentityRegistry
        ) {
            return Err(Error::Protocol(format!(
                "service_kind {} is not valid in a service registration key",
                service_kind.as_str()
            )));
        }
        Ok(Self {
            service_kind,
            public_base,
        })
    }

    pub fn service_kind(&self) -> &ServiceKind {
        &self.service_kind
    }

    pub fn public_base(&self) -> &CanonicalServiceUrl {
        &self.public_base
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRegistrationKeyWire {
    service_kind: ServiceKind,
    public_base: CanonicalServiceUrl,
}

impl<'de> Deserialize<'de> for ServiceRegistrationKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServiceRegistrationKeyWire::deserialize(deserializer)?;
        Self::new(wire.service_kind, wire.public_base).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceDidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: Did,
    pub public_key_multibase: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceDidEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub service_kind: ServiceKind,
    pub service_endpoint: CanonicalServiceUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
                    endpoint.service_kind,
                    ServiceKind::PrincipalServer
                        | ServiceKind::AuthServer
                        | ServiceKind::IdentityRegistry
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
                    && entry.service_kind == *key.service_kind()
                    && entry.service_endpoint == *key.public_base()
            })
            .count();
        if bindings != 1 {
            return Err(Error::Protocol(
                "signed inception must contain exactly one ArkretService endpoint matching service_kind and public_base"
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceWebvhInceptionParameters {
    pub scid: String,
    pub method: String,
    pub update_keys: Vec<String>,
    pub next_key_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRegistrationReceipt {
    pub receipt_id: String,
    pub registration_key: ServiceRegistrationKey,
    pub service_id: Did,
    pub version_id: String,
    pub log_head_digest: String,
    pub control_key_digest: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
            "issued_at": canonical::format_timestamp_canonical(self.issued_at),
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceRegistrationEnsureRequestBody {
    pub service_kind: ServiceKind,
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
            service_kind: key.service_kind,
            public_base: key.public_base,
            inception_operation,
            idempotency_key,
            previous_receipt,
        })
    }

    pub fn registration_key(&self) -> Result<ServiceRegistrationKey> {
        ServiceRegistrationKey::new(self.service_kind, self.public_base.clone())
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
    Ok(format!(
        "ak:service-registration:{}",
        canonical::sha256_hex(canonical::canonical_json_bytes(&serde_json::to_value(
            key
        )?)?)
    ))
}

/// Deterministic WebVH local id for a registration key. The principal
/// server's own long-standing `service` slot is retained; every other role is
/// namespaced by the canonical registration-key digest.
pub fn service_registration_local_id(key: &ServiceRegistrationKey) -> Result<String> {
    if key.service_kind() == &ServiceKind::PrincipalServer {
        return Ok("service".to_owned());
    }
    Ok(format!(
        "service-{}",
        &service_registration_key_digest(key)?[..24]
    ))
}

pub fn service_registration_key_digest(key: &ServiceRegistrationKey) -> Result<String> {
    Ok(canonical::sha256_hex(canonical::canonical_json_bytes(
        &serde_json::to_value(key)?,
    )?))
}

fn sha256_canonical(value: &impl Serialize) -> Result<String> {
    Ok(canonical::canonical_sha256(&serde_json::to_value(value)?)?)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    canonical::sha256_digest(bytes)
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
