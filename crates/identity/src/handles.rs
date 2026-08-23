use arkret_wire::{DidCoreId, DidFullId, project_full_id_to_core_id};

use super::*;

/// Visibility scope for a DID.
///
/// Controls whether a DID is globally public, scoped to a specific peer
/// relationship (pairwise), or private to the local device/user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidVisibility {
    /// DID is globally resolvable and publicly visible.
    Public,
    /// DID is scoped to a specific peer relationship (pairwise).
    Pairwise,
    /// DID is private to the local device or user only.
    Private,
}

/// Pairwise DID binding: a unique DID derived for a specific peer relationship.
///
/// Pairwise DIDs prevent correlation across different peers. Each user derives
/// a distinct DID for each counterparty, so a compromised pairwise DID does not
/// expose the user's activity with other peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseActorBinding {
    /// Realm-scoped actor core id (unique per peer relationship).
    pub pairwise_actor_id: DidCoreId,
    /// The stable principal core id represented by this actor.
    pub principal_id: DidCoreId,
    /// The counterparty principal core id this binding is scoped to.
    pub peer_principal_id: DidCoreId,
    /// Optional space or context this binding is limited to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// When this pairwise binding was created.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// When this pairwise binding expires (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Proof required before revealing a pairwise DID's parent DID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseActorResolutionProof {
    pub pairwise_actor_id: DidCoreId,
    pub requester: DidCoreId,
    pub peer_principal_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub challenge: String,
    pub proof: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl PairwiseActorBinding {
    /// Create a new pairwise actor binding.
    pub fn new(
        pairwise_actor_id: DidCoreId,
        principal_id: DidCoreId,
        peer_principal_id: DidCoreId,
        scope: Option<String>,
    ) -> Self {
        Self {
            pairwise_actor_id,
            principal_id,
            peer_principal_id,
            scope,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Set an expiration time for this pairwise binding.
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check whether this binding has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Build a deterministic proof allowing a scoped peer to resolve this binding.
    pub fn resolution_proof(
        &self,
        requester: DidCoreId,
        challenge: impl Into<String>,
    ) -> PairwiseActorResolutionProof {
        let challenge = challenge.into();
        let proof = pairwise_actor_resolution_proof(
            &self.pairwise_actor_id,
            &requester,
            &self.peer_principal_id,
            self.scope.as_deref(),
            &challenge,
        );
        PairwiseActorResolutionProof {
            pairwise_actor_id: self.pairwise_actor_id.clone(),
            requester,
            peer_principal_id: self.peer_principal_id.clone(),
            scope: self.scope.clone(),
            challenge,
            proof,
            created_at: Utc::now(),
        }
    }
}

/// Compute the deterministic proof for gated pairwise DID resolution.
pub fn pairwise_actor_resolution_proof(
    pairwise_actor_id: &DidCoreId,
    requester: &DidCoreId,
    peer_principal_id: &DidCoreId,
    scope: Option<&str>,
    challenge: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        pairwise_actor_id,
        requester,
        peer_principal_id,
        scope.unwrap_or(""),
        challenge
    );
    sha256_hex(payload.as_bytes())
}

/// Manages pairwise DID bindings for privacy-preserving identity.
#[derive(Clone, Debug, Default)]
pub struct PairwiseActorStore {
    /// Bindings indexed by pairwise actor core id.
    by_pairwise: BTreeMap<DidCoreId, PairwiseActorBinding>,
    /// Reverse index: principal core id → all its pairwise actors.
    by_principal: BTreeMap<DidCoreId, Vec<DidCoreId>>,
}

impl PairwiseActorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pairwise actor binding.
    pub fn insert(&mut self, binding: PairwiseActorBinding) -> Result<()> {
        let pairwise = binding.pairwise_actor_id.clone();
        let principal = binding.principal_id.clone();
        self.by_pairwise.insert(pairwise.clone(), binding);
        self.by_principal
            .entry(principal)
            .or_default()
            .push(pairwise);
        Ok(())
    }

    /// Look up the binding for a pairwise DID.
    pub fn get(&self, pairwise_actor_id: &DidCoreId) -> Option<&PairwiseActorBinding> {
        self.by_pairwise.get(pairwise_actor_id)
    }

    /// Resolve a pairwise DID to its parent DID.
    pub fn resolve_principal(&self, pairwise_actor_id: &DidCoreId) -> Option<&DidCoreId> {
        self.by_pairwise
            .get(pairwise_actor_id)
            .map(|binding| &binding.principal_id)
    }

    /// Resolve a pairwise DID to its parent DID only after validating proof.
    pub fn resolve_principal_with_proof(
        &self,
        pairwise_actor_id: &DidCoreId,
        proof: &PairwiseActorResolutionProof,
    ) -> Result<&DidCoreId> {
        let binding = self.by_pairwise.get(pairwise_actor_id).ok_or_else(|| {
            IdentityError::Protocol("pairwise actor binding not found".to_owned())
        })?;
        if binding.is_expired() {
            return Err(IdentityError::Protocol(
                "pairwise DID binding expired".to_owned(),
            ));
        }
        if &proof.pairwise_actor_id != pairwise_actor_id {
            return Err(IdentityError::Protocol(
                "pairwise DID proof target mismatch".to_owned(),
            ));
        }
        if proof.requester != binding.peer_principal_id && proof.requester != binding.principal_id {
            return Err(IdentityError::Protocol(
                "pairwise DID proof requester is not authorized".to_owned(),
            ));
        }
        if proof.peer_principal_id != binding.peer_principal_id || proof.scope != binding.scope {
            return Err(IdentityError::Protocol(
                "pairwise DID proof scope mismatch".to_owned(),
            ));
        }
        let expected = pairwise_actor_resolution_proof(
            pairwise_actor_id,
            &proof.requester,
            &binding.peer_principal_id,
            binding.scope.as_deref(),
            &proof.challenge,
        );
        if proof.proof != expected {
            return Err(IdentityError::Protocol(
                "invalid pairwise DID resolution proof".to_owned(),
            ));
        }
        Ok(&binding.principal_id)
    }

    /// Check if a pairwise DID is valid (exists and not expired).
    pub fn is_valid(&self, pairwise_actor_id: &DidCoreId) -> bool {
        self.by_pairwise
            .get(pairwise_actor_id)
            .is_some_and(|b| !b.is_expired())
    }

    /// List all pairwise DIDs for a parent DID.
    pub fn pairwise_actor_ids_for(&self, principal: &DidCoreId) -> Vec<&PairwiseActorBinding> {
        self.by_principal
            .get(principal)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.by_pairwise.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove expired bindings.
    pub fn purge_expired(&mut self) {
        let expired: Vec<DidCoreId> = self
            .by_pairwise
            .iter()
            .filter(|(_, b)| b.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(binding) = self.by_pairwise.remove(&id)
                && let Some(actor_ids) = self.by_principal.get_mut(&binding.principal_id)
            {
                actor_ids.retain(|actor_id| actor_id != &id);
            }
        }
    }
}

/// Client-local handle claim challenge state tracked by [`IdentityManager`].
///
/// This is NOT the wire handle-claim resource — that is
/// `arkret_models_collaboration::HandleClaim` (handle-claim schema counterpart). This type
/// only tracks the local challenge/verification lifecycle before a claim is
/// published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleClaimChallenge {
    /// Claimed handle.
    pub handle: String,
    /// DID of the principal claiming the handle.
    pub subject: DidCoreId,
    /// Validation challenge.
    pub challenge: String,
    /// Whether the claim is verified.
    pub verified: bool,
    /// Optional attestation.
    pub attestation: Option<HandleAttestation>,
}

/// External proof profile for handle ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleProofProfile {
    DnsTxt,
    WellKnown,
}

/// Host-fetched DNS TXT or well-known handle proof validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalHandleProof {
    pub profile: HandleProofProfile,
    pub handle: String,
    pub subject: DidCoreId,
    pub challenge: String,
    pub proof: String,
}

impl ExternalHandleProof {
    pub fn validate(&self) -> Result<()> {
        let expected = handle_claim_proof(&self.handle, &self.subject, &self.challenge);
        if self.proof.trim() == expected {
            Ok(())
        } else {
            Err(IdentityError::Protocol("handle proof mismatch".to_owned()))
        }
    }
}

/// Identity manager.
#[derive(Clone, Debug, Default)]
pub struct IdentityManager {
    documents: BTreeMap<DidFullId, DidDocument>,
    handles: BTreeMap<String, HandleClaimChallenge>,
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
    pub fn resolve(&self, did: &DidFullId) -> Option<&DidDocument> {
        self.documents.get(did)
    }

    /// Rotate or add a verification key.
    pub fn rotate_key(
        &mut self,
        did: &DidFullId,
        key_id: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Result<()> {
        let document = self
            .documents
            .get_mut(did)
            .ok_or_else(|| IdentityError::Protocol("did document not found".to_owned()))?;
        document
            .verification_methods
            .insert(key_id.into(), public_key.into());
        document.updated_at = Some(Utc::now());
        Ok(())
    }

    /// Bind a handle and issue a validation challenge.
    pub fn bind_handle(
        &mut self,
        handle: impl Into<String>,
        subject: DidCoreId,
    ) -> HandleClaimChallenge {
        let handle = normalize_handle(&handle.into());
        let challenge = sha256_hex(format!("{handle}:{}:{}", subject, Utc::now()).as_bytes());
        let claim = HandleClaimChallenge {
            handle: handle.clone(),
            subject,
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
            .ok_or_else(|| IdentityError::Protocol("handle claim not found".to_owned()))?;
        let expected = handle_claim_proof(&claim.handle, &claim.subject, &claim.challenge);
        if expected != proof {
            return Err(IdentityError::Protocol(
                "invalid handle claim proof".to_owned(),
            ));
        }
        claim.verified = true;
        Ok(())
    }

    /// Add an attestation to a verified handle.
    pub fn attest_handle(
        &mut self,
        handle: &str,
        issuer: DidCoreId,
        proof: impl Into<String>,
    ) -> Result<()> {
        let handle = normalize_handle(handle);
        let claim = self
            .handles
            .get_mut(&handle)
            .ok_or_else(|| IdentityError::Protocol("handle claim not found".to_owned()))?;
        if !claim.verified {
            return Err(IdentityError::Protocol(
                "handle claim is not verified".to_owned(),
            ));
        }
        claim.attestation = Some(HandleAttestation {
            issuer,
            proof: proof.into(),
            created_at: Utc::now(),
        });
        Ok(())
    }

    /// Get a handle claim challenge.
    pub fn handle_claim(&self, handle: &str) -> Option<&HandleClaimChallenge> {
        self.handles.get(&normalize_handle(handle))
    }

    /// Verify a handle through bidirectional `also_known_as` linking.
    ///
    /// This checks that:
    /// 1. The DID document for `subject` exists and lists the handle in `also_known_as`.
    /// 2. A handle claim exists linking the handle to the same `subject`.
    /// 3. The handle claim has been verified through a proof challenge.
    ///
    /// If both conditions hold, the handle is considered bidirectionally verified:
    /// the DID document asserts the handle, and the handle claim proves the DID.
    pub fn verify_handle_bidirectional(&self, handle: &str, subject: &DidCoreId) -> Result<()> {
        let normalized = normalize_handle(handle);
        let document = self
            .documents
            .values()
            .find(|document| {
                project_full_id_to_core_id(&document.id)
                    .is_ok_and(|core_id| core_id.as_str() == subject.as_str())
            })
            .ok_or_else(|| IdentityError::Protocol("DID document not found for user".to_owned()))?;

        // Check that the DID document lists the handle in also_known_as
        let handle_variants: Vec<String> = vec![normalized.clone(), format!("@{normalized}")];
        let listed_in_document = document.also_known_as.iter().any(|aka| {
            let normalized_aka = normalize_handle(aka);
            handle_variants.contains(&normalized_aka)
        });
        if !listed_in_document {
            return Err(IdentityError::Protocol(format!(
                "handle '{}' is not listed in DID document also_known_as for {}",
                normalized, subject
            )));
        }

        // Check that the handle claim exists and is verified
        let claim = self.handles.get(&normalized).ok_or_else(|| {
            IdentityError::Protocol(format!("handle claim not found for '{}'", normalized))
        })?;
        if claim.subject != *subject {
            return Err(IdentityError::Protocol(format!(
                "handle claim links to {} but expected {}",
                claim.subject, subject
            )));
        }
        if !claim.verified {
            return Err(IdentityError::Protocol(format!(
                "handle '{}' claim for {} is not yet verified",
                normalized, subject
            )));
        }

        Ok(())
    }

    /// Return all handles listed in a DID document's `also_known_as` that
    /// are not yet claimed in this manager.
    pub fn unclaimed_handles_for_did(&self, did: &DidFullId) -> Vec<String> {
        let Some(document) = self.documents.get(did) else {
            return Vec::new();
        };
        document
            .also_known_as
            .iter()
            .filter(|aka| {
                let normalized = normalize_handle(aka);
                // Only return entries that look like handles (not URLs)
                !normalized.contains("://") && !normalized.is_empty()
            })
            .filter(|aka| {
                let normalized = normalize_handle(aka);
                !self.handles.contains_key(&normalized)
            })
            .cloned()
            .collect()
    }
}

/// Compute the expected proof for a handle claim.
pub fn handle_claim_proof(handle: &str, subject: &DidCoreId, challenge: &str) -> String {
    sha256_hex(format!("{}:{}:{}", normalize_handle(handle), subject, challenge).as_bytes())
}

/// DNS TXT name that should contain the Arkret handle proof.
pub fn handle_dns_txt_name(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!("_arkret-handle.{local}.{domain}"))
}

/// HTTPS well-known URL that should return the Arkret handle proof.
pub fn handle_well_known_url(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!(
        "https://{domain}/.well-known/arkret/handle/{local}.json"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn pairwise_actor_binding_omitted_expires_at_round_trip() {
        let binding = PairwiseActorBinding {
            pairwise_actor_id: did("pairwise"),
            principal_id: did("alice"),
            peer_principal_id: did("bob"),
            scope: None,
            created_at: "2026-08-18T00:00:00.000Z".parse().unwrap(),
            expires_at: None,
        };

        let serialized = serde_json::to_value(&binding).unwrap();
        assert!(!serialized.as_object().unwrap().contains_key("expires_at"));

        let restored: PairwiseActorBinding = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored, binding);
    }
}
