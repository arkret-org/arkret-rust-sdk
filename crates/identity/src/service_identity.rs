//! Service identity runtime state and bundle persistence.
//!
//! The registration wire contract (canonical URLs, registration keys, DID
//! documents, WebVH inception operations, receipts, ensure request/outcome
//! DTOs) is owned by `arkret_models_identity::service_identity`; this module
//! keeps the runtime side: local identity state, identity bundles, and their
//! file / KeyStore persistence backends. The `arkret` umbrella re-exports both
//! halves as one public service-identity surface.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_keystore::KeyStore;
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceDidDocument, ServiceRegistrationKey, ServiceRegistrationReceipt,
    ServiceWebvhInceptionOperation, service_registration_key_digest,
};
use arkret_wire::{Did, DidCoreId, ServiceKind, project_did_to_core_id};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{IdentityError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DidCoreIdentityKeyRef(String);

impl DidCoreIdentityKeyRef {
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
pub struct DidCoreIdentityProviderRef {
    pub name: String,
    pub endpoint: CanonicalServiceUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDidCoreIdentity {
    pub service_id: DidCoreId,
    pub did: Did,
    pub registration_key: ServiceRegistrationKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<DidCoreIdentityProviderRef>,
    pub signing_key_refs: Vec<DidCoreIdentityKeyRef>,
    pub active_signing_key_ref: DidCoreIdentityKeyRef,
    pub control_key_ref: DidCoreIdentityKeyRef,
    pub version_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub last_verified_at: DateTime<Utc>,
}

impl LocalDidCoreIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.signing_key_refs.is_empty()
            || !self.signing_key_refs.contains(&self.active_signing_key_ref)
            || self.version_id.is_empty()
        {
            return Err(IdentityError::Protocol(
                "local service identity key references or version are inconsistent".to_owned(),
            ));
        }
        if project_did_to_core_id(&self.did)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?
            != self.service_id
        {
            return Err(IdentityError::Protocol(
                "local service identity did does not project to service_id".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDidCoreIdentity {
    pub identity: LocalDidCoreIdentity,
    pub did_document: ServiceDidDocument,
    pub registration_receipt: ServiceRegistrationReceipt,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub stored_at: DateTime<Utc>,
}

impl StoredDidCoreIdentity {
    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        self.did_document
            .validate_service_kind(self.identity.registration_key.service_kind())?;
        if self.did_document.id != self.identity.did
            || self.registration_receipt.version_id != self.identity.version_id
        {
            return Err(IdentityError::Protocol(
                "stored service identity document or receipt does not match the runtime identity"
                    .to_owned(),
            ));
        }
        Ok(self.registration_receipt.validate_for(
            &self.identity.registration_key,
            &self.identity.service_id,
            &self.identity.did,
        )?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidCoreIdentityBundle {
    pub schema: String,
    pub identity: StoredDidCoreIdentity,
    /// Receipts for this DID, oldest first, ending with the one
    /// [`Self::identity`] carries.
    ///
    /// A restore replays the log from its inception, and the inception commit
    /// is checked against the receipt issued for it, so the chain has to keep
    /// the earlier receipts rather than only the current one.
    pub receipt_chains: Vec<ServiceRegistrationReceipt>,
    /// The complete method-native log, oldest entry first.
    ///
    /// Typed as raw entries because only the first one is an inception: a
    /// service DID advances by successor entries, and
    /// `ServiceWebvhInceptionOperation` rejects anything whose `versionId` is
    /// not `1-`. `service-identity-bundle.schema.json` always described this
    /// field as an array of log entries; carrying only the inception was an
    /// implementation limit, and it left a rotated DID with no representable
    /// bundle at all.
    pub webvh_history_entries: Vec<Value>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub exported_at: DateTime<Utc>,
}

impl DidCoreIdentityBundle {
    pub const SCHEMA: &'static str = arkret_wire::SchemaId::SERVICE_IDENTITY_BUNDLE_V1;

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.webvh_history_entries.is_empty()
            || self.receipt_chains.is_empty()
        {
            return Err(IdentityError::Protocol(
                "identity bundle schema, WebVH history, or receipt chain is incomplete".to_owned(),
            ));
        }
        self.identity.validate()?;
        let key = &self.identity.identity.registration_key;
        let did = &self.identity.identity.did;

        let inception: ServiceWebvhInceptionOperation = serde_json::from_value(
            self.webvh_history_entries
                .first()
                .expect("checked non-empty")
                .clone(),
        )
        .map_err(|error| {
            IdentityError::Protocol(format!("identity bundle inception is malformed: {error}"))
        })?;
        inception.validate_for(key)?;
        if project_did_to_core_id(&inception.state.id)? != self.identity.identity.service_id {
            return Err(IdentityError::Protocol(
                "identity bundle history belongs to a different service DID".to_owned(),
            ));
        }

        // Verify native portability as well as key authorization before accepting
        // a bundle whose historical DID locations differ from its current DID.
        let mut log_bytes = Vec::new();
        for entry in &self.webvh_history_entries {
            log_bytes.extend(arkret_canonical::canonical_json_bytes(entry)?);
            log_bytes.push(b'\n');
        }
        crate::verify_did_webvh_v1_chain_and_witness_bytes(did, &log_bytes, None)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?;

        let head = self
            .webvh_history_entries
            .last()
            .expect("checked non-empty");
        let head_version_id = head
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                IdentityError::Protocol("identity bundle history head has no versionId".to_owned())
            })?;
        if head_version_id != self.identity.identity.version_id {
            return Err(IdentityError::Protocol(
                "identity bundle history head does not match the bundled identity version"
                    .to_owned(),
            ));
        }
        if head.get("state") != Some(&serde_json::to_value(&self.identity.did_document)?) {
            return Err(IdentityError::Protocol(
                "identity bundle history head does not match the bundled DID document".to_owned(),
            ));
        }
        if self.receipt_chains.len() != self.webvh_history_entries.len() {
            return Err(IdentityError::Protocol(
                "identity bundle must carry exactly one receipt for every WebVH entry".to_owned(),
            ));
        }
        if self
            .receipt_chains
            .last()
            .is_none_or(|receipt| receipt.version_id != self.identity.identity.version_id)
        {
            return Err(IdentityError::Protocol(
                "identity bundle receipt chain does not end at the bundled identity version"
                    .to_owned(),
            ));
        }
        for (entry, receipt) in self.webvh_history_entries.iter().zip(&self.receipt_chains) {
            let entry_did: Did =
                serde_json::from_value(entry.pointer("/state/id").cloned().ok_or_else(|| {
                    IdentityError::Protocol("identity bundle entry omits its DID".to_owned())
                })?)?;
            receipt.validate_for(key, &self.identity.identity.service_id, &entry_did)?;
            let version_id = entry
                .get("versionId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    IdentityError::Protocol(
                        "identity bundle WebVH entry has no versionId".to_owned(),
                    )
                })?;
            let update_key = entry
                .pointer("/parameters/updateKeys/0")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    IdentityError::Protocol(
                        "identity bundle WebVH entry has no active update key".to_owned(),
                    )
                })?;
            let event_digest = arkret_canonical::canonical_sha256(entry)?;
            let control_key_digest = arkret_canonical::sha256_digest(update_key.as_bytes());
            if receipt.version_id != version_id
                || receipt.log_head_digest != event_digest
                || receipt.control_key_digest != control_key_digest
            {
                return Err(IdentityError::Protocol(
                    "identity bundle receipt does not bind its WebVH entry".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidCoreIdentityDiagnostic {
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
pub enum DidCoreIdentityState {
    Ready {
        identity: LocalDidCoreIdentity,
    },
    DegradedStored {
        identity: LocalDidCoreIdentity,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        retry_at: DateTime<Utc>,
        last_error: String,
    },
    WaitingProvider {
        registration_key: ServiceRegistrationKey,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        retry_at: DateTime<Utc>,
    },
    RegistrationKeyDrift {
        identity: LocalDidCoreIdentity,
        stored_key: ServiceRegistrationKey,
        computed_key: ServiceRegistrationKey,
    },
    Conflict {
        stored_service_id: DidCoreId,
        provider_id: DidCoreId,
    },
    Faulted {
        diagnostic: DidCoreIdentityDiagnostic,
        next_action: String,
    },
}

impl DidCoreIdentityState {
    pub fn identity(&self) -> Option<&LocalDidCoreIdentity> {
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
                provider_id,
            } if stored_service_id == provider_id => {
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
    pub service_id: DidCoreId,
    pub service_kind: ServiceKind,
    pub endpoint: CanonicalServiceUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub resolved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ResolvedService {
    pub fn validate(&self) -> Result<()> {
        // Endpoint resolution identifies only the service and route. Exact
        // callable carriers are obtained from the role-scoped ServiceDescribe
        // after reverse-binding verification; duplicating them here would
        // create a second, stale capability advertisement.
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
    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<DidCoreIdentityBundle>>;
    fn store(&self, bundle: &DidCoreIdentityBundle) -> Result<()>;
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

    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<DidCoreIdentityBundle>> {
        let path = self.path_for(key)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_protocol_error("read identity bundle", &path, error)),
        };
        let bundle: DidCoreIdentityBundle = serde_json::from_slice(&bytes)?;
        bundle.validate()?;
        Ok(Some(bundle))
    }

    fn store(&self, bundle: &DidCoreIdentityBundle) -> Result<()> {
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

    fn load(&self, key: &ServiceRegistrationKey) -> Result<Option<DidCoreIdentityBundle>> {
        let id = self.storage_id(key)?;
        let bytes = match self.key_store.load(&id) {
            Ok(bytes) => bytes,
            Err(error) if error.is_not_found() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let bundle: DidCoreIdentityBundle = serde_json::from_slice(bytes.as_slice())?;
        bundle.validate()?;
        Ok(Some(bundle))
    }

    fn store(&self, bundle: &DidCoreIdentityBundle) -> Result<()> {
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

/// Verify the Provider proof of a service-registration receipt exactly as
/// `identity/identity-did.md` §3.7 receipt transcript step 4 requires of every
/// consumer, including the offline identity-bundle restore path.
///
/// `provider_did` MUST have been obtained independently of the receipt —
/// from the Provider's own resolution surface or an operator pin — and
/// `provider_log_bytes` MUST be the `did.jsonl` published for it. The complete
/// method-native history is verified here (SCID derivation from entry 0, the
/// entry hash chain, every entry proof and the update-key rotation
/// authorization), so no part of this decision rests on the transport that
/// delivered either input.
///
/// The steps follow the normative order: method-native history verification,
/// `project(provider_did) == provider_id` together with the bare
/// controller DID of `verificationMethod`, `assertionMethod` membership in the
/// DID Document that was effective at `issued_at`, then the Ed25519 detached
/// JWS itself. The verified history is returned so callers can additionally
/// pin the head against a separately obtained resolution commitment.
pub fn verify_registration_receipt_provider_proof(
    receipt: &ServiceRegistrationReceipt,
    provider_did: &Did,
    provider_log_bytes: &[u8],
) -> Result<crate::VerifiedDidWebvhLog> {
    let verified = crate::verify_did_webvh_v1_chain_bytes(provider_did, provider_log_bytes)?;
    receipt.validate_provider_did(provider_did)?;
    let mut previous_version_time: Option<DateTime<Utc>> = None;
    for entry in &verified.entries {
        if previous_version_time.is_some_and(|previous| entry.version_time <= previous) {
            return Err(IdentityError::Protocol(
                "provider did:webvh history versionTime is not strictly increasing".to_owned(),
            ));
        }
        previous_version_time = Some(entry.version_time);
    }
    let effective = verified
        .entries
        .iter()
        .rev()
        .find(|entry| entry.version_time <= receipt.issued_at)
        .ok_or_else(|| {
            IdentityError::Protocol(
                "provider did:webvh history has no version effective when the receipt was issued"
                    .to_owned(),
            )
        })?;
    let document: ServiceDidDocument = serde_json::from_value(effective.state.clone())?;
    if document.id != *provider_did {
        return Err(IdentityError::Protocol(
            "provider did:webvh state at issuance is not the resolved provider DID".to_owned(),
        ));
    }
    arkret_signatures::service_identity::verify_registration_receipt_proof(receipt, &document)?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
    use arkret_models_identity::service_identity::{
        CanonicalServiceUrl, ServiceDidEndpoint, ServiceRegistrationEnsureRequestBody,
        ServiceRegistrationKey, ServiceRegistrationOutcome, ServiceRegistrationReceipt,
        ServiceWebvhInceptionOperation,
    };
    use arkret_wire::{
        Did, DidCoreId, DidUrl, Hash, PayloadProof, ServiceKind, project_did_to_core_id, proof_kind,
    };
    use chrono::{DateTime, Utc};
    use rand_core::SeedableRng;

    use super::{
        DidCoreIdentityBundle, DidCoreIdentityKeyRef, DidCoreIdentityProviderRef,
        DidCoreIdentityState, IdentityBundleBackend, KeyStoreIdentityBundleBackend,
        LocalDidCoreIdentity, StoredDidCoreIdentity,
    };

    #[derive(Default)]
    struct TestKeyStore {
        keys: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl KeyStore for TestKeyStore {
        fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
            self.keys
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .map(KeyBytes::new)
                .ok_or_else(|| KeyStoreError::not_found(id))
        }

        fn store(&self, id: &str, key: &[u8]) -> Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys
                .lock()
                .unwrap()
                .insert(id.to_owned(), key.to_vec());
            Ok(())
        }

        fn list(&self) -> Result<Vec<String>, KeyStoreError> {
            Ok(self.keys.lock().unwrap().keys().cloned().collect())
        }

        fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys.lock().unwrap().remove(id);
            Ok(())
        }
    }

    fn registration_key() -> ServiceRegistrationKey {
        ServiceRegistrationKey::new(
            ServiceKind::Station,
            CanonicalServiceUrl::new("https://station.example/").unwrap(),
        )
        .unwrap()
    }

    fn prepared_inception() -> arkret_signatures::webvh::PreparedInception {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([31; 32]);
        let endpoint = "https://identity.example/".parse().unwrap();
        let prepared = arkret_signatures::webvh::prepare_service_registration_inception(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &endpoint,
                registration_key: &registration_key(),
                also_known_as: &[],
                version_time: "2026-07-15T00:00:00Z".parse().unwrap(),
                did_key_fragment: None,
            },
        )
        .unwrap();
        prepared
    }

    fn inception() -> ServiceWebvhInceptionOperation {
        serde_json::from_value(prepared_inception().log_entry.clone()).unwrap()
    }

    fn receipt(operation: &ServiceWebvhInceptionOperation) -> ServiceRegistrationReceipt {
        let provider_did = Did::new("did:webvh:QmProvider:identity.example:webvh:service").unwrap();
        let provider_id = project_did_to_core_id(&provider_did).unwrap();
        let service_id = project_did_to_core_id(&operation.state.id).unwrap();
        let mut receipt = ServiceRegistrationReceipt {
            registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            registration_key: registration_key(),
            service_id,
            did: operation.state.id.clone(),
            version_id: operation.version_id.clone(),
            log_head_digest: operation.log_head_digest().unwrap(),
            control_key_digest: operation.control_key_digest().unwrap(),
            issued_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
            provider_id,
            proof: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{provider_did}#service-key")).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: "2026-07-15T00:00:01.000Z".parse().unwrap(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "placeholder".to_owned(),
            },
        };
        receipt.registration_receipt_id = receipt.expected_registration_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
            &receipt,
            &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
        )
        .unwrap();
        receipt
    }

    fn stored_identity() -> StoredDidCoreIdentity {
        let operation = inception();
        let receipt = receipt(&operation);
        StoredDidCoreIdentity {
            identity: LocalDidCoreIdentity {
                service_id: project_did_to_core_id(&operation.state.id).unwrap(),
                did: operation.state.id.clone(),
                registration_key: registration_key(),
                provider: Some(DidCoreIdentityProviderRef {
                    name: "provider".to_owned(),
                    endpoint: CanonicalServiceUrl::new("https://identity.example/").unwrap(),
                }),
                signing_key_refs: vec![DidCoreIdentityKeyRef::new("signing-key").unwrap()],
                active_signing_key_ref: DidCoreIdentityKeyRef::new("signing-key").unwrap(),
                control_key_ref: DidCoreIdentityKeyRef::new("control-key").unwrap(),
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
    fn registration_key_rejects_non_identity_service_kind() {
        assert!(
            ServiceRegistrationKey::new(
                ServiceKind::MediaService,
                CanonicalServiceUrl::new("https://media.example/").unwrap()
            )
            .is_err()
        );
        let json = serde_json::json!({
            "service_kind": "media_service",
            "public_base_url": "https://media.example/"
        });
        assert!(serde_json::from_value::<ServiceRegistrationKey>(json).is_err());
    }

    #[test]
    fn service_document_rejects_endpoints_outside_registration_context() {
        let mut operation = inception();
        operation.state.service.push(ServiceDidEndpoint {
            id: format!("{}#archive", operation.state.id),
            endpoint_type: "ArkretService".to_owned(),
            service_kind: ServiceKind::ArchiveNode,
            service_endpoint: CanonicalServiceUrl::new("https://archive.example/").unwrap(),
        });
        assert!(operation.validate_for(&registration_key()).is_err());
    }

    #[test]
    fn ensure_request_and_outcome_validate_endpoint_binding() {
        let operation = inception();
        let request = ServiceRegistrationEnsureRequestBody::new(
            registration_key(),
            operation.clone(),
            "ensure-attempt-1",
            None,
        )
        .unwrap();
        request.validate().unwrap();
        let outcome = ServiceRegistrationOutcome {
            did_document: operation.state.clone(),
            registration_receipt: receipt(&operation),
            created: true,
        };
        outcome.validate_ensure_response(&request).unwrap();

        let mut wrong = request;
        wrong.public_base_url = CanonicalServiceUrl::new("https://other.example/").unwrap();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn service_registration_receipt_binds_claims_and_provider_controller() {
        let operation = inception();
        let receipt = receipt(&operation);
        let service_id = project_did_to_core_id(&operation.state.id).unwrap();
        receipt
            .validate_for(&registration_key(), &service_id, &operation.state.id)
            .unwrap();
        let provider_did = Did::new("did:webvh:QmProvider:identity.example:webvh:service").unwrap();
        receipt.validate_provider_did(&provider_did).unwrap();

        let mut tampered = receipt.clone();
        tampered.control_key_digest = format!("sha256:{}", "b".repeat(64));
        assert!(tampered.validate_proof_binding().is_err());

        let mut wrong_controller = receipt;
        wrong_controller.proof.verification_method =
            DidUrl::new("did:webvh:QmOther:identity.example:webvh:service#service-key").unwrap();
        assert!(
            wrong_controller
                .validate_provider_did(&provider_did)
                .is_err()
        );
    }

    #[test]
    fn bundle_retains_historical_did_locations_across_native_portability() {
        let prepared = prepared_inception();
        let operation = inception();
        let old_receipt = receipt(&operation);
        let mut stored = stored_identity();
        let scid = prepared.did.split(':').nth(2).unwrap();
        let target = format!("did:webvh:{scid}:moved.example:webvh:service");
        let mut state: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&prepared.log_entry["state"])
                .unwrap()
                .replace(&prepared.did, &target),
        )
        .unwrap();
        state["alsoKnownAs"] = serde_json::json!([prepared.did]);
        let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[33; 32])
                .verifying_key()
                .as_bytes(),
        );
        let moved = arkret_signatures::webvh::prepare_webvh_relocation(
            &arkret_signatures::webvh::WebvhRelocationInput {
                current_did: &prepared.did,
                target_did: &target,
                previous_entries: std::slice::from_ref(&prepared.log_entry),
                version_time: "2026-07-15T00:00:02Z".parse().unwrap(),
                current_update_seed: &prepared.next_update_key_seed,
                next_update_public_key_multibase: &next_key,
                state: &state,
            },
        )
        .unwrap();
        let mut current_receipt = old_receipt.clone();
        current_receipt.did = Did::new(&target).unwrap();
        current_receipt.version_id = moved.version_id.clone();
        current_receipt.issued_at = "2026-07-15T00:00:03Z".parse().unwrap();
        current_receipt.proof.created_at = current_receipt.issued_at;
        current_receipt.log_head_digest =
            arkret_canonical::canonical_sha256(&moved.log_entry).unwrap();
        current_receipt.control_key_digest = arkret_canonical::sha256_digest(
            moved.log_entry["parameters"]["updateKeys"][0]
                .as_str()
                .unwrap()
                .as_bytes(),
        );
        current_receipt.registration_receipt_id =
            current_receipt.expected_registration_receipt_id().unwrap();
        current_receipt.proof.payload_digest = current_receipt.expected_payload_digest().unwrap();
        current_receipt.proof =
            arkret_signatures::service_identity::sign_registration_receipt_proof(
                &current_receipt,
                &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
            )
            .unwrap();
        stored.identity.did = Did::new(target).unwrap();
        stored.identity.version_id = moved.version_id;
        stored.did_document = serde_json::from_value(state).unwrap();
        stored.registration_receipt = current_receipt.clone();
        let mut bundle = DidCoreIdentityBundle {
            schema: DidCoreIdentityBundle::SCHEMA.to_owned(),
            identity: stored,
            receipt_chains: vec![old_receipt, current_receipt],
            webvh_history_entries: vec![prepared.log_entry.clone(), moved.log_entry],
            exported_at: "2026-07-15T00:00:03Z".parse().unwrap(),
        };
        bundle.validate().unwrap();
        bundle.webvh_history_entries[1]["state"]["alsoKnownAs"] = serde_json::json!([]);
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn keystore_bundle_backend_round_trips_and_validates() {
        let operation = inception();
        let stored = stored_identity();
        let bundle = DidCoreIdentityBundle {
            schema: DidCoreIdentityBundle::SCHEMA.to_owned(),
            receipt_chains: vec![stored.registration_receipt.clone()],
            identity: stored,
            webvh_history_entries: vec![serde_json::to_value(&operation).unwrap()],
            exported_at: "2026-07-15T00:00:02.000Z".parse().unwrap(),
        };
        let backend = KeyStoreIdentityBundleBackend::new(
            Arc::new(TestKeyStore::default()),
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
        let state = DidCoreIdentityState::DegradedStored {
            identity,
            retry_at,
            last_error: "provider unavailable".to_owned(),
        };
        assert!(state.is_ready());
        state.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&state).unwrap()["retry_at"],
            "2026-07-15T00:05:00.000Z"
        );
    }

    #[test]
    fn registration_key_drift_serves_without_identity_mutation() {
        let identity = stored_identity().identity;
        let state = DidCoreIdentityState::RegistrationKeyDrift {
            stored_key: identity.registration_key.clone(),
            computed_key: ServiceRegistrationKey::new(
                ServiceKind::Station,
                CanonicalServiceUrl::new("https://new-station.example/").unwrap(),
            )
            .unwrap(),
            identity,
        };
        assert!(state.identity().is_some());
        assert!(state.is_ready());
        state.validate().unwrap();
    }

    #[test]
    fn conflicting_provider_mapping_fails_closed() {
        let state = DidCoreIdentityState::Conflict {
            stored_service_id: DidCoreId::new("ak:did_core:webvh:QmStored").unwrap(),
            provider_id: DidCoreId::new("ak:did_core:webvh:QmProvider").unwrap(),
        };
        assert!(state.identity().is_none());
        assert!(!state.is_ready());
        state.validate().unwrap();
        let serialized = serde_json::to_value(&state).unwrap();
        assert_eq!(
            serde_json::from_value::<DidCoreIdentityState>(serialized).unwrap(),
            state
        );

        let same_id = DidCoreId::new("ak:did_core:webvh:QmStored").unwrap();
        assert!(
            DidCoreIdentityState::Conflict {
                stored_service_id: same_id.clone(),
                provider_id: same_id,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn resolved_service_omitted_expires_at_round_trip() {
        let service = super::ResolvedService {
            service_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:auth.example").unwrap(),
            service_kind: ServiceKind::Station,
            endpoint: CanonicalServiceUrl::new("https://station.example/").unwrap(),
            resolved_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
            expires_at: None,
        };

        let serialized = serde_json::to_value(&service).unwrap();
        assert!(!serialized.as_object().unwrap().contains_key("expires_at"));

        let restored: super::ResolvedService = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, service);
    }

    const PROVIDER_ASSERTION_FRAGMENT: &str = "service-key";

    /// A real, self-certifying Provider `did:webvh` inception whose DID
    /// assertion key is `assertion_seed`.
    fn provider_history(
        assertion_seed: &[u8; 32],
        update_entropy: [u8; 32],
    ) -> arkret_signatures::webvh::PreparedInception {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(update_entropy);
        arkret_signatures::webvh::prepare_service_registration_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &url::Url::parse("https://identity.example/").unwrap(),
                registration_key: &ServiceRegistrationKey::new(
                    ServiceKind::Station,
                    CanonicalServiceUrl::new("https://identity.example/").unwrap(),
                )
                .unwrap(),
                also_known_as: &[],
                version_time: "2026-07-15T00:00:00Z".parse().unwrap(),
                did_key_fragment: Some(PROVIDER_ASSERTION_FRAGMENT),
            },
            assertion_seed,
        )
        .unwrap()
    }

    fn did_jsonl(prepared: &arkret_signatures::webvh::PreparedInception) -> Vec<u8> {
        format!("{}\n", serde_json::to_string(&prepared.log_entry).unwrap()).into_bytes()
    }

    /// A receipt for the registered Station, issued and signed by the
    /// Provider whose history is `provider`.
    fn provider_signed_receipt(
        provider: &arkret_signatures::webvh::PreparedInception,
        provider_assertion_seed: &[u8; 32],
        issued_at: DateTime<Utc>,
    ) -> ServiceRegistrationReceipt {
        let provider_did = Did::new(provider.did.clone()).unwrap();
        let operation = inception();
        let mut receipt = ServiceRegistrationReceipt {
            registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            registration_key: registration_key(),
            service_id: project_did_to_core_id(&operation.state.id).unwrap(),
            did: operation.state.id.clone(),
            version_id: operation.version_id.clone(),
            log_head_digest: operation.log_head_digest().unwrap(),
            control_key_digest: operation.control_key_digest().unwrap(),
            issued_at,
            provider_id: project_did_to_core_id(&provider_did).unwrap(),
            proof: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!(
                    "{provider_did}#{PROVIDER_ASSERTION_FRAGMENT}"
                ))
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "placeholder".to_owned(),
            },
        };
        receipt.registration_receipt_id = receipt.expected_registration_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
            &receipt,
            &ed25519_dalek::SigningKey::from_bytes(provider_assertion_seed),
        )
        .unwrap();
        receipt
    }

    /// `identity-did.md` §3.7 transcript step 4: the Provider proof is only
    /// accepted after its method-native history has been verified and the
    /// receipt's `provider_id` projects from the resolved DID.
    #[test]
    fn provider_proof_verifies_against_the_resolved_method_native_history() {
        let seed = [11_u8; 32];
        let provider = provider_history(&seed, [21_u8; 32]);
        let provider_did = Did::new(provider.did.clone()).unwrap();
        let receipt =
            provider_signed_receipt(&provider, &seed, "2026-07-15T00:00:01Z".parse().unwrap());

        let verified = super::verify_registration_receipt_provider_proof(
            &receipt,
            &provider_did,
            &did_jsonl(&provider),
        )
        .expect("a receipt signed by the resolved provider assertion key must verify");
        assert_eq!(verified.head_version_id, provider.version_id);
    }

    /// A forged signature is rejected even though every structural binding in
    /// the receipt still recomputes.
    #[test]
    fn forged_provider_signature_is_rejected() {
        let seed = [11_u8; 32];
        let provider = provider_history(&seed, [21_u8; 32]);
        let provider_did = Did::new(provider.did.clone()).unwrap();
        let mut receipt =
            provider_signed_receipt(&provider, &seed, "2026-07-15T00:00:01Z".parse().unwrap());
        let forged = provider_signed_receipt(
            &provider,
            &[12_u8; 32],
            "2026-07-15T00:00:01Z".parse().unwrap(),
        );
        receipt.proof.jws = forged.proof.jws;

        assert!(
            super::verify_registration_receipt_provider_proof(
                &receipt,
                &provider_did,
                &did_jsonl(&provider),
            )
            .is_err()
        );
    }

    /// Swapping the Provider's controlling key material mints a different DID,
    /// so the receipt no longer projects onto the resolved provider.
    #[test]
    fn receipt_from_a_different_provider_controller_is_rejected() {
        let seed = [11_u8; 32];
        let provider = provider_history(&seed, [21_u8; 32]);
        let other_seed = [12_u8; 32];
        let other = provider_history(&other_seed, [22_u8; 32]);
        let receipt =
            provider_signed_receipt(&other, &other_seed, "2026-07-15T00:00:01Z".parse().unwrap());

        assert!(
            super::verify_registration_receipt_provider_proof(
                &receipt,
                &Did::new(provider.did.clone()).unwrap(),
                &did_jsonl(&provider),
            )
            .is_err()
        );
    }

    /// The history that mattered is the one effective when the receipt was
    /// issued; a receipt predating the Provider's inception has none.
    #[test]
    fn receipt_issued_before_the_provider_history_begins_is_rejected() {
        let seed = [11_u8; 32];
        let provider = provider_history(&seed, [21_u8; 32]);
        let receipt =
            provider_signed_receipt(&provider, &seed, "2026-07-14T23:59:59Z".parse().unwrap());

        assert!(
            super::verify_registration_receipt_provider_proof(
                &receipt,
                &Did::new(provider.did.clone()).unwrap(),
                &did_jsonl(&provider),
            )
            .is_err()
        );
    }

    /// A history served for a different DID than the one the consumer
    /// independently resolved never verifies.
    #[test]
    fn provider_history_for_a_different_did_is_rejected() {
        let seed = [11_u8; 32];
        let provider = provider_history(&seed, [21_u8; 32]);
        let other = provider_history(&[12_u8; 32], [22_u8; 32]);
        let receipt =
            provider_signed_receipt(&provider, &seed, "2026-07-15T00:00:01Z".parse().unwrap());

        assert!(
            super::verify_registration_receipt_provider_proof(
                &receipt,
                &Did::new(provider.did.clone()).unwrap(),
                &did_jsonl(&other),
            )
            .is_err()
        );
    }
}
