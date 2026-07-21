//! Service identity runtime state and bundle persistence.
//!
//! The registration wire contract (canonical URLs, registration keys, DID
//! documents, WebVH inception operations, receipts, ensure request/outcome
//! DTOs) is owned by `arkret_models_identity::service_identity`; this module
//! keeps the runtime side: local identity state, identity bundles, and their
//! file / KeyStore persistence backends. `arkret-core` re-exports both halves
//! so downstream `arkret_core::` / `arkret_sdk::` paths stay byte-stable until
//! the facade retires.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_keystore::KeyStore;
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceDidDocument, ServiceRegistrationKey, ServiceRegistrationReceipt,
    ServiceWebvhInceptionOperation, service_registration_key_digest,
};
use arkret_wire::{Did, ServiceType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{IdentityError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceIdentityKeyRef(String);

impl ServiceIdentityKeyRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentityError::Protocol(
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub last_verified_at: DateTime<Utc>,
}

impl LocalServiceIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.signing_key_refs.is_empty()
            || !self.signing_key_refs.contains(&self.active_signing_key_ref)
            || self.version_id.is_empty()
        {
            return Err(IdentityError::Protocol(
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
            return Err(IdentityError::Protocol(
                "stored service identity document or receipt does not match the runtime identity"
                    .to_owned(),
            ));
        }
        Ok(self
            .registration_receipt
            .validate_for(&self.identity.registration_key, &self.identity.service_id)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentityBundle {
    pub schema: String,
    pub identity: StoredServiceIdentity,
    pub webvh_history: Vec<ServiceWebvhInceptionOperation>,
    pub receipt_chain: Vec<ServiceRegistrationReceipt>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub exported_at: DateTime<Utc>,
}

impl ServiceIdentityBundle {
    pub const SCHEMA: &'static str = "ak.service_identity_bundle.v1";

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.webvh_history.is_empty()
            || self.receipt_chain.is_empty()
        {
            return Err(IdentityError::Protocol(
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
            return Err(IdentityError::Protocol(
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
        #[serde(
            serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
        )]
        retry_at: DateTime<Utc>,
        last_error: String,
    },
    WaitingProvider {
        registration_key: ServiceRegistrationKey,
        #[serde(
            serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
        )]
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
                return Err(IdentityError::Protocol(
                    "degraded service identity state must include a last_error".to_owned(),
                ));
            }
            Self::RegistrationKeyDrift {
                identity,
                stored_key,
                computed_key,
            } => {
                if stored_key != &identity.registration_key {
                    return Err(IdentityError::Protocol(
                        "stored registration key must match the active service identity".to_owned(),
                    ));
                }
                if computed_key == stored_key {
                    return Err(IdentityError::Protocol(
                        "registration key drift requires distinct stored and computed keys"
                            .to_owned(),
                    ));
                }
            }
            Self::Conflict {
                stored_service_id,
                provider_service_id,
            } if stored_service_id == provider_service_id => {
                return Err(IdentityError::Protocol(
                    "service identity conflict requires distinct stored and Provider DIDs"
                        .to_owned(),
                ));
            }
            Self::Faulted { next_action, .. } if next_action.trim().is_empty() => {
                return Err(IdentityError::Protocol(
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
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub resolved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ResolvedService {
    pub fn validate(&self) -> Result<()> {
        if self
            .supported_operations
            .iter()
            .any(|operation| !self.service_type.permits_operation(operation))
        {
            return Err(IdentityError::Protocol(format!(
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
            return Err(IdentityError::Protocol(
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
            Err(error) if error.is_not_found() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let bundle: ServiceIdentityBundle = serde_json::from_slice(bytes.as_slice())?;
        bundle.validate()?;
        Ok(Some(bundle))
    }

    fn store(&self, bundle: &ServiceIdentityBundle) -> Result<()> {
        bundle.validate()?;
        let id = self.storage_id(&bundle.identity.identity.registration_key)?;
        Ok(self.key_store.store(&id, &serde_json::to_vec(bundle)?)?)
    }

    fn delete(&self, key: &ServiceRegistrationKey) -> Result<()> {
        Ok(self.key_store.delete(&self.storage_id(key)?)?)
    }
}

fn bundle_key_digest(key: &ServiceRegistrationKey) -> Result<String> {
    Ok(service_registration_key_digest(key)?)
}

fn io_protocol_error(action: &str, path: &Path, error: std::io::Error) -> IdentityError {
    IdentityError::Protocol(format!("failed to {action} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arkret_keystore::InMemoryKeyStore;
    use arkret_models_identity::service_identity::{
        CanonicalServiceUrl, ServiceDidDocument, ServiceDidEndpoint, ServiceDidVerificationMethod,
        ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey, ServiceRegistrationOutcome,
        ServiceRegistrationReceipt, ServiceWebvhDataIntegrityProof, ServiceWebvhInceptionOperation,
        ServiceWebvhInceptionParameters,
    };
    use arkret_wire::{Did, ServiceType};
    use chrono::{DateTime, Utc};

    use super::{
        IdentityBundleBackend, KeyStoreIdentityBundleBackend, LocalServiceIdentity,
        ServiceIdentityBundle, ServiceIdentityKeyRef, ServiceIdentityProviderRef,
        ServiceIdentityState, StoredServiceIdentity,
    };

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
            version_time: "2026-07-15T00:00:00.000Z".parse().unwrap(),
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
            issued_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
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
                last_verified_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
            },
            did_document: operation.state,
            registration_receipt: receipt,
            stored_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
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
    fn canonical_service_url_preserves_non_default_port() {
        assert_eq!(
            CanonicalServiceUrl::canonicalize("http://localhost:18080")
                .unwrap()
                .as_str(),
            "http://localhost:18080/"
        );
        assert!(CanonicalServiceUrl::new("http://localhost:18080/").is_ok());
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
            exported_at: "2026-07-15T00:00:02.000Z".parse().unwrap(),
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
        let retry_at: DateTime<Utc> = "2026-07-15T00:05:00.000Z".parse().unwrap();
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
            "2026-07-15T00:05:00.000Z"
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
