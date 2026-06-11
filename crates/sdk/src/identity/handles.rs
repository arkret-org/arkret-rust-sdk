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
pub struct PairwiseDidBinding {
    /// The pairwise DID (unique per peer relationship).
    pub pairwise_did: Did,
    /// The real/parent DID that this pairwise DID represents.
    pub parent_did: Did,
    /// The counterparty DID this pairwise binding is scoped to.
    pub peer_did: Did,
    /// Optional space or context this binding is limited to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// When this pairwise binding was created.
    pub created_at: DateTime<Utc>,
    /// When this pairwise binding expires (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Proof required before revealing a pairwise DID's parent DID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseDidResolutionProof {
    pub pairwise_did: Did,
    pub requester: Did,
    pub peer_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub challenge: String,
    pub proof: String,
    pub created_at: DateTime<Utc>,
}

impl PairwiseDidBinding {
    /// Create a new pairwise DID binding.
    pub fn new(pairwise_did: Did, parent_did: Did, peer_did: Did, scope: Option<String>) -> Self {
        Self {
            pairwise_did,
            parent_did,
            peer_did,
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
        requester: Did,
        challenge: impl Into<String>,
    ) -> PairwiseDidResolutionProof {
        let challenge = challenge.into();
        let proof = pairwise_resolution_proof(
            &self.pairwise_did,
            &requester,
            &self.peer_did,
            self.scope.as_deref(),
            &challenge,
        );
        PairwiseDidResolutionProof {
            pairwise_did: self.pairwise_did.clone(),
            requester,
            peer_did: self.peer_did.clone(),
            scope: self.scope.clone(),
            challenge,
            proof,
            created_at: Utc::now(),
        }
    }
}

/// Compute the deterministic proof for gated pairwise DID resolution.
pub fn pairwise_resolution_proof(
    pairwise_did: &Did,
    requester: &Did,
    peer_did: &Did,
    scope: Option<&str>,
    challenge: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        pairwise_did,
        requester,
        peer_did,
        scope.unwrap_or(""),
        challenge
    );
    sha256_hex(payload.as_bytes())
}

/// Manages pairwise DID bindings for privacy-preserving identity.
#[derive(Clone, Debug, Default)]
pub struct PairwiseDidStore {
    /// Bindings indexed by pairwise DID.
    by_pairwise: BTreeMap<Did, PairwiseDidBinding>,
    /// Reverse index: parent DID → all its pairwise DIDs.
    by_parent: BTreeMap<Did, Vec<Did>>,
}

impl PairwiseDidStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pairwise DID binding.
    pub fn insert(&mut self, binding: PairwiseDidBinding) -> Result<()> {
        let pairwise = binding.pairwise_did.clone();
        let parent = binding.parent_did.clone();
        self.by_pairwise.insert(pairwise.clone(), binding);
        self.by_parent.entry(parent).or_default().push(pairwise);
        Ok(())
    }

    /// Look up the binding for a pairwise DID.
    pub fn get(&self, pairwise_did: &Did) -> Option<&PairwiseDidBinding> {
        self.by_pairwise.get(pairwise_did)
    }

    /// Resolve a pairwise DID to its parent DID.
    pub fn resolve_parent(&self, pairwise_did: &Did) -> Option<&Did> {
        self.by_pairwise.get(pairwise_did).map(|b| &b.parent_did)
    }

    /// Resolve a pairwise DID to its parent DID only after validating proof.
    pub fn resolve_parent_with_proof(
        &self,
        pairwise_did: &Did,
        proof: &PairwiseDidResolutionProof,
    ) -> Result<&Did> {
        let binding = self
            .by_pairwise
            .get(pairwise_did)
            .ok_or_else(|| Error::Protocol("pairwise DID binding not found".to_owned()))?;
        if binding.is_expired() {
            return Err(Error::Protocol("pairwise DID binding expired".to_owned()));
        }
        if &proof.pairwise_did != pairwise_did {
            return Err(Error::Protocol(
                "pairwise DID proof target mismatch".to_owned(),
            ));
        }
        if proof.requester != binding.peer_did && proof.requester != binding.parent_did {
            return Err(Error::Protocol(
                "pairwise DID proof requester is not authorized".to_owned(),
            ));
        }
        if proof.peer_did != binding.peer_did || proof.scope != binding.scope {
            return Err(Error::Protocol(
                "pairwise DID proof scope mismatch".to_owned(),
            ));
        }
        let expected = pairwise_resolution_proof(
            pairwise_did,
            &proof.requester,
            &binding.peer_did,
            binding.scope.as_deref(),
            &proof.challenge,
        );
        if proof.proof != expected {
            return Err(Error::Protocol(
                "invalid pairwise DID resolution proof".to_owned(),
            ));
        }
        Ok(&binding.parent_did)
    }

    /// Check if a pairwise DID is valid (exists and not expired).
    pub fn is_valid(&self, pairwise_did: &Did) -> bool {
        self.by_pairwise
            .get(pairwise_did)
            .is_some_and(|b| !b.is_expired())
    }

    /// List all pairwise DIDs for a parent DID.
    pub fn pairwise_dids_for(&self, parent: &Did) -> Vec<&PairwiseDidBinding> {
        self.by_parent
            .get(parent)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.by_pairwise.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove expired bindings.
    pub fn purge_expired(&mut self) {
        let expired: Vec<Did> = self
            .by_pairwise
            .iter()
            .filter(|(_, b)| b.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(binding) = self.by_pairwise.remove(&id)
                && let Some(parent_ids) = self.by_parent.get_mut(&binding.parent_did)
            {
                parent_ids.retain(|pid| pid != &id);
            }
        }
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
    pub user_id: Did,
    pub challenge: String,
    pub proof: String,
}

impl ExternalHandleProof {
    pub fn validate(&self) -> Result<()> {
        let expected = handle_claim_proof(&self.handle, &self.user_id, &self.challenge);
        if self.proof.trim() == expected {
            Ok(())
        } else {
            Err(Error::Protocol("handle proof mismatch".to_owned()))
        }
    }
}

/// Verified handle ↔ DID binding cached after bidirectional verification
/// per `identity-handles.md` §6.1.
///
/// A binding is only valid when **both** directions agree:
///
/// - The DID's resolved document lists the handle in `alsoKnownAs`, and
/// - The handle's external proof (DNS TXT, well-known, etc.) names the same DID.
///
/// The cache key MUST cover everything that could shift the binding —
/// `handle`, `did`, `document_hash`, `also_known_as_proof`, `expires_at`,
/// and the `resolver_policy` digest. Bindings reused across resolver
/// policies could otherwise leak across trust boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedHandleBinding {
    pub handle: String,
    pub did: Did,
    /// Canonical SHA-256 of the resolved DID document at verification time.
    pub document_hash: String,
    /// External proof linking the handle to the DID
    /// (DNS TXT body, well-known body, etc.).
    pub also_known_as_proof: String,
    /// Cache expiry; bindings MUST be re-verified after.
    pub expires_at: DateTime<Utc>,
    /// Digest of the [`ResolverPolicy`] under which this binding was
    /// produced. Bindings with mismatched digests MUST NOT be reused.
    pub resolver_policy_digest: String,
}

impl VerifiedHandleBinding {
    /// Compute the canonical cache key for this binding.
    pub fn cache_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.handle,
            self.did.as_str(),
            self.document_hash,
            sha256_hex(self.also_known_as_proof.as_bytes()),
            self.expires_at.to_rfc3339(),
            self.resolver_policy_digest
        )
    }

    /// Whether the binding has expired at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Validate the bidirectional consistency:
    ///
    /// 1. `document` MUST list `handle` in `alsoKnownAs`;
    /// 2. `handle_proof` MUST validate against the same DID;
    /// 3. `document_hash` MUST match the canonical hash of `document`.
    ///
    /// On success, returns a fresh binding with the supplied `expires_at`
    /// and `resolver_policy_digest`.
    pub fn verify(
        handle: &str,
        document: &DidDocument,
        handle_proof: &ExternalHandleProof,
        also_known_as_proof: impl Into<String>,
        expires_at: DateTime<Utc>,
        resolver_policy_digest: impl Into<String>,
    ) -> Result<Self> {
        let normalized = normalize_handle(handle);
        if handle_proof.handle != normalized {
            return Err(Error::Protocol(
                "handle in proof does not match requested handle".to_owned(),
            ));
        }
        if handle_proof.user_id != document.id {
            return Err(Error::Protocol(
                "handle proof DID does not match document subject".to_owned(),
            ));
        }
        if !document.also_known_as.iter().any(|aka| {
            normalize_handle(aka) == normalized || aka.trim_end_matches('/').ends_with(&normalized)
        }) {
            return Err(Error::Protocol(
                "did document does not list handle in alsoKnownAs".to_owned(),
            ));
        }
        handle_proof.validate()?;

        let document_hash = sha256_hex(&cokret_core::canonical::canonical_json_bytes(document)?);

        Ok(Self {
            handle: normalized,
            did: document.id.clone(),
            document_hash: format!("sha256:{}", document_hash),
            also_known_as_proof: also_known_as_proof.into(),
            expires_at,
            resolver_policy_digest: resolver_policy_digest.into(),
        })
    }
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
        document
            .verification_methods
            .insert(key_id.into(), public_key.into());
        document.updated_at = Utc::now();
        Ok(())
    }

    /// Migrate one DID to another.
    pub fn migrate_did(&mut self, from: Did, to: Did, proof: impl Into<String>) -> DidMigration {
        let migration = DidMigration {
            from,
            to,
            proof: proof.into(),
            migrated_at: Utc::now(),
        };
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
        claim.attestation = Some(HandleAttestation {
            issuer,
            proof: proof.into(),
            created_at: Utc::now(),
        });
        Ok(())
    }

    /// Get a handle claim.
    pub fn handle_claim(&self, handle: &str) -> Option<&HandleClaim> {
        self.handles.get(&normalize_handle(handle))
    }

    /// Verify a handle through bidirectional `also_known_as` linking.
    ///
    /// This checks that:
    /// 1. The DID document for `user_id` exists and lists the handle in `also_known_as`.
    /// 2. A handle claim exists linking the handle to the same `user_id`.
    /// 3. The handle claim has been verified through a proof challenge.
    ///
    /// If both conditions hold, the handle is considered bidirectionally verified:
    /// the DID document asserts the handle, and the handle claim proves the DID.
    pub fn verify_handle_bidirectional(&self, handle: &str, user_id: &Did) -> Result<()> {
        let normalized = normalize_handle(handle);
        let document = self
            .documents
            .get(user_id)
            .ok_or_else(|| Error::Protocol("DID document not found for user".to_owned()))?;

        // Check that the DID document lists the handle in also_known_as
        let handle_variants: Vec<String> = vec![normalized.clone(), format!("@{normalized}")];
        let listed_in_document = document.also_known_as.iter().any(|aka| {
            let normalized_aka = normalize_handle(aka);
            handle_variants.contains(&normalized_aka)
        });
        if !listed_in_document {
            return Err(Error::Protocol(format!(
                "handle '{}' is not listed in DID document also_known_as for {}",
                normalized, user_id
            )));
        }

        // Check that the handle claim exists and is verified
        let claim = self.handles.get(&normalized).ok_or_else(|| {
            Error::Protocol(format!("handle claim not found for '{}'", normalized))
        })?;
        if claim.user_id != *user_id {
            return Err(Error::Protocol(format!(
                "handle claim links to {} but expected {}",
                claim.user_id, user_id
            )));
        }
        if !claim.verified {
            return Err(Error::Protocol(format!(
                "handle '{}' claim for {} is not yet verified",
                normalized, user_id
            )));
        }

        Ok(())
    }

    /// Return all handles listed in a DID document's `also_known_as` that
    /// are not yet claimed in this manager.
    pub fn unclaimed_handles_for_did(&self, did: &Did) -> Vec<String> {
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

    /// Migration records.
    pub fn migrations(&self) -> &[DidMigration] {
        &self.migrations
    }
}

/// Compute the expected proof for a handle claim.
pub fn handle_claim_proof(handle: &str, user_id: &Did, challenge: &str) -> String {
    sha256_hex(format!("{}:{}:{}", normalize_handle(handle), user_id, challenge).as_bytes())
}

/// DNS TXT name that should contain the Cokret handle proof.
pub fn handle_dns_txt_name(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!("_cokret-handle.{local}.{domain}"))
}

/// HTTPS well-known URL that should return the Cokret handle proof.
pub fn handle_well_known_url(handle: &str) -> Result<String> {
    let (local, domain) = split_domain_handle(handle)?;
    Ok(format!(
        "https://{domain}/.well-known/cokret/handle/{local}.json"
    ))
}
