//! DID, DID document and handle management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Did, Error, Result};

/// Minimal DID document model used by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// DID subject.
    pub id: Did,
    /// Verification methods by key ID.
    pub verification_methods: BTreeMap<String, String>,
    /// Also-known-as handles or URLs.
    pub also_known_as: Vec<String>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

impl DidDocument {
    /// Create a DID document with one key.
    pub fn new(id: Did, key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            id,
            verification_methods: BTreeMap::from([(key_id.into(), public_key.into())]),
            also_known_as: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    /// Validate required DID document fields.
    pub fn validate(&self) -> Result<()> {
        if self.verification_methods.is_empty() {
            return Err(Error::Protocol("did document has no verification methods".to_owned()));
        }
        Ok(())
    }
}

/// DID migration record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMigration {
    /// Old DID.
    pub from: Did,
    /// New DID.
    pub to: Did,
    /// Migration proof.
    pub proof: String,
    /// Migration time.
    pub migrated_at: DateTime<Utc>,
}

/// Handle attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    /// Issuer DID.
    pub issuer: Did,
    /// Attestation proof.
    pub proof: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Handle claim state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleClaim {
    /// Claimed handle.
    pub handle: String,
    /// Owner DID.
    pub user_id: Did,
    /// Validation challenge.
    pub challenge: String,
    /// Whether the claim is verified.
    pub verified: bool,
    /// Optional attestation.
    pub attestation: Option<HandleAttestation>,
}

/// Identity manager.
#[derive(Clone, Debug, Default)]
pub struct IdentityManager {
    documents: BTreeMap<Did, DidDocument>,
    migrations: Vec<DidMigration>,
    handles: BTreeMap<String, HandleClaim>,
}

impl IdentityManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a DID document after validation.
    pub fn upsert_document(&mut self, document: DidDocument) -> Result<()> {
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Resolve a DID document.
    pub fn resolve(&self, did: &Did) -> Option<&DidDocument> {
        self.documents.get(did)
    }

    /// Rotate or add a verification key.
    pub fn rotate_key(
        &mut self,
        did: &Did,
        key_id: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Result<()> {
        let document = self
            .documents
            .get_mut(did)
            .ok_or_else(|| Error::Protocol("did document not found".to_owned()))?;
        document.verification_methods.insert(key_id.into(), public_key.into());
        document.updated_at = Utc::now();
        Ok(())
    }

    /// Migrate one DID to another.
    pub fn migrate_did(&mut self, from: Did, to: Did, proof: impl Into<String>) -> DidMigration {
        let migration = DidMigration { from, to, proof: proof.into(), migrated_at: Utc::now() };
        self.migrations.push(migration.clone());
        migration
    }

    /// Bind a handle and issue a validation challenge.
    pub fn bind_handle(&mut self, handle: impl Into<String>, user_id: Did) -> HandleClaim {
        let handle = normalize_handle(&handle.into());
        let challenge = sha256_hex(format!("{handle}:{}:{}", user_id, Utc::now()).as_bytes());
        let claim = HandleClaim {
            handle: handle.clone(),
            user_id,
            challenge,
            verified: false,
            attestation: None,
        };
        self.handles.insert(handle, claim.clone());
        claim
    }

    /// Validate a handle claim proof. Expected proof is SHA-256(handle + DID + challenge).
    pub fn validate_handle_claim(&mut self, handle: &str, proof: &str) -> Result<()> {
        let handle = normalize_handle(handle);
        let claim = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| Error::Protocol("handle claim not found".to_owned()))?;
        let expected = handle_claim_proof(&claim.handle, &claim.user_id, &claim.challenge);
        if expected != proof {
            return Err(Error::Protocol("invalid handle claim proof".to_owned()));
        }
        claim.verified = true;
        Ok(())
    }

    /// Add an attestation to a verified handle.
    pub fn attest_handle(
        &mut self,
        handle: &str,
        issuer: Did,
        proof: impl Into<String>,
    ) -> Result<()> {
        let handle = normalize_handle(handle);
        let claim = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| Error::Protocol("handle claim not found".to_owned()))?;
        if !claim.verified {
            return Err(Error::Protocol("handle claim is not verified".to_owned()));
        }
        claim.attestation =
            Some(HandleAttestation { issuer, proof: proof.into(), created_at: Utc::now() });
        Ok(())
    }

    /// Get a handle claim.
    pub fn handle_claim(&self, handle: &str) -> Option<&HandleClaim> {
        self.handles.get(&normalize_handle(handle))
    }

    /// Migration records.
    pub fn migrations(&self) -> &[DidMigration] {
        &self.migrations
    }
}

/// Compute the expected proof for a handle claim.
pub fn handle_claim_proof(handle: &str, user_id: &Did, challenge: &str) -> String {
    sha256_hex(format!("{}:{}:{}", normalize_handle(handle), user_id, challenge).as_bytes())
}

fn normalize_handle(handle: &str) -> String {
    handle.trim().trim_start_matches('@').to_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn identity_resolves_validates_rotates_and_migrates_dids() {
        let alice = did("alice");
        let alice_v2 = did("alice-v2");
        let mut manager = IdentityManager::new();
        manager.upsert_document(DidDocument::new(alice.clone(), "key-1", "pubkey-1")).unwrap();

        assert!(manager.resolve(&alice).unwrap().validate().is_ok());
        manager.rotate_key(&alice, "key-2", "pubkey-2").unwrap();
        assert!(manager.resolve(&alice).unwrap().verification_methods.contains_key("key-2"));

        manager.migrate_did(alice, alice_v2, "proof");
        assert_eq!(manager.migrations().len(), 1);
    }

    #[test]
    fn identity_binds_validates_and_attests_handles() {
        let alice = did("alice");
        let issuer = did("issuer");
        let mut manager = IdentityManager::new();

        let claim = manager.bind_handle("@Alice", alice.clone());
        let proof = handle_claim_proof("alice", &alice, &claim.challenge);
        manager.validate_handle_claim("alice", &proof).unwrap();
        manager.attest_handle("alice", issuer, "attestation").unwrap();

        let claim = manager.handle_claim("@alice").unwrap();
        assert!(claim.verified);
        assert!(claim.attestation.is_some());
    }
}
