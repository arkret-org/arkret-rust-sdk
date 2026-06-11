use std::collections::HashMap;

use super::*;

/// Resolve DID documents for one or more DID methods.
pub trait DidResolver {
    /// Return whether this resolver can handle the DID method or concrete DID.
    fn supports(&self, did: &Did) -> bool;

    /// Resolve a DID document.
    fn resolve_did(&self, did: &Did) -> Result<DidDocument>;
}

/// Public key material resolved from a DID document verification method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedVerificationMethodKey {
    pub did: Did,
    pub verification_method: String,
    pub public_key: cokret_signatures::PublicKeyMaterial,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Did>,
}

/// Extract the controller DID portion from a DID URL verification method.
pub fn verification_method_did(verification_method: &str) -> Result<Did> {
    if verification_method.trim().is_empty() {
        return Err(Error::Protocol("verification_method must not be empty".to_owned()));
    }
    let hash = verification_method.find('#');
    let query = verification_method.find('?');
    let end = match (hash, query) {
        (Some(hash), Some(query)) => hash.min(query),
        (Some(hash), None) => hash,
        (None, Some(query)) => query,
        (None, None) => verification_method.len(),
    };
    Did::new(verification_method[..end].to_owned()).map_err(Error::from)
}

/// Resolve a verification method key from an already-resolved DID document.
pub fn resolve_verification_method_key_from_document(
    document: &DidDocument,
    verification_method: &str,
) -> Result<ResolvedVerificationMethodKey> {
    let (method_id, public_key_value) =
        lookup_verification_method_value(document, verification_method)?;
    Ok(ResolvedVerificationMethodKey {
        did: document.id.clone(),
        verification_method: method_id.to_owned(),
        public_key: public_key_material_from_did_document_value(&public_key_value)?,
        controller: None,
    })
}

/// Resolve a verification method key through any [`DidResolver`].
pub fn resolve_verification_method_key<R>(
    resolver: &R,
    verification_method: &str,
) -> Result<ResolvedVerificationMethodKey>
where
    R: DidResolver + ?Sized,
{
    let did = verification_method_did(verification_method)?;
    let document = resolver.resolve_did(&did)?;
    resolve_verification_method_key_from_document(&document, verification_method)
}

/// Adapter that lets the signatures crate verify proofs through a live DID
/// resolver instead of a static trusted-key map.
#[derive(Clone, Copy, Debug)]
pub struct DidDocumentVerificationMethodResolver<'a, R: DidResolver + ?Sized> {
    resolver: &'a R,
}

impl<'a, R: DidResolver + ?Sized> DidDocumentVerificationMethodResolver<'a, R> {
    pub fn new(resolver: &'a R) -> Self {
        Self { resolver }
    }
}

impl<R> cokret_signatures::DidVerificationMethodResolver
    for DidDocumentVerificationMethodResolver<'_, R>
where
    R: DidResolver + ?Sized,
{
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> Result<cokret_signatures::VerificationMethodDocument> {
        let did = verification_method_did(verification_method)?;
        let document = self.resolver.resolve_did(&did)?;
        let (method_id, public_key_value) =
            lookup_verification_method_value(&document, verification_method)?;
        Ok(cokret_signatures::VerificationMethodDocument {
            did: document.id,
            verification_method: method_id.to_owned(),
            public_key_multibase: public_key_value.to_owned(),
            controller: None,
        })
    }
}

/// Verify a Cokret [`Proof`] over caller-supplied canonical bytes by
/// resolving `proof.verification_method` through a DID document.
///
/// `binding_actor_id` is the `actor_id` folded into the canonical proof
/// binding object (`encoding.md` §6) — for Event proofs this is the Event
/// envelope's `actor_id` field, which may differ from the controller actor
/// (`executed_by`) used for the verification-method binding check.
pub fn verify_canonical_proof_with_did_resolver<R>(
    canonical_bytes: &[u8],
    proof: &crate::Proof,
    binding_actor_id: &cokret_core::Did,
    context: &cokret_signatures::ProofVerificationContext,
    resolver: &R,
) -> Result<cokret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let adapter = DidDocumentVerificationMethodResolver::new(resolver);
    cokret_signatures::verify_proof_with_resolver(proof, context, &adapter, |method, proof| {
        let public_key = public_key_material_from_did_document_value(&method.public_key_multibase)?;
        cokret_signatures::verify_eddsa_detached_jws_proof(
            proof,
            canonical_bytes,
            binding_actor_id,
            &public_key,
        )
        .map_err(Error::from)?;
        Ok(true)
    })
}

/// Verify an Event Envelope proof with DID-document key discovery.
///
/// When `event.executed_by` is present, the proof controller is bound to
/// that DID; otherwise it is bound to `event.actor_id`.
pub fn verify_event_proof_with_did_resolver<R>(
    event: &crate::Event,
    proof: &crate::Proof,
    resolver: &R,
) -> Result<cokret_signatures::SignatureVerification>
where
    R: DidResolver + ?Sized,
{
    let builder = cokret_signatures::EventProofBuilder::new();
    let canonical_bytes = builder.envelope_bytes(event)?;
    let expected_digest =
        crate::Hash::new(cokret_core::canonical::sha256_digest(&canonical_bytes))?;
    let signing_actor = event.executed_by.clone().unwrap_or_else(|| event.actor_id.clone());
    let context = cokret_signatures::ProofVerificationContext::new(signing_actor, expected_digest);
    // Binding object `actor_id` is the Event envelope's `actor_id` (spec §6
    // L201), independent of the controller actor (`executed_by`) above.
    verify_canonical_proof_with_did_resolver(
        &canonical_bytes,
        proof,
        &event.actor_id,
        &context,
        resolver,
    )
}

fn lookup_verification_method_value(
    document: &DidDocument,
    verification_method: &str,
) -> Result<(String, String)> {
    if let Some(value) = document.verification_methods.get(verification_method) {
        return Ok((verification_method.to_owned(), value.clone()));
    }
    if let Some(fragment) = verification_method_fragment(verification_method)
        && let Some(value) = document.verification_methods.get(fragment)
    {
        return Ok((fragment.to_owned(), value.clone()));
    }
    if document.verification_methods.len() == 1
        && let Some((method_id, value)) = document.verification_methods.iter().next()
    {
        return Ok((method_id.clone(), value.clone()));
    }
    Err(Error::Protocol(format!(
        "verification_method `{verification_method}` not found in DID document for `{}`",
        document.id
    )))
}

fn verification_method_fragment(verification_method: &str) -> Option<&str> {
    let (_, after_hash) = verification_method.split_once('#')?;
    let end = after_hash.find('?').unwrap_or(after_hash.len());
    Some(&after_hash[..end])
}

fn public_key_material_from_did_document_value(
    value: &str,
) -> Result<cokret_signatures::PublicKeyMaterial> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') {
        let jwk: Value = serde_json::from_str(trimmed)?;
        return Ok(cokret_signatures::PublicKeyMaterial::Jwk { value: jwk });
    }
    let multibase = trimmed.strip_prefix("did:key:").unwrap_or(trimmed);
    if multibase.starts_with('z') {
        return Ok(cokret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    Err(Error::Protocol(
        "DID verification method must carry Ed25519 publicKeyMultibase or publicKeyJwk".to_owned(),
    ))
}

/// Policy controlling DID resolution per `identity-handles.md` §5 /
/// `device-lifecycle.md` §4.
///
/// `allowed_methods` and `default_principal_method` MUST be applied
/// before dispatching a resolver, so a misconfigured peer can't smuggle
/// a `did:bogus:` through. `trust_roots` is method-specific (e.g. for
/// `did:web` it's a list of accepted authorities; for `did:keri` it's
/// a list of witness DIDs). `ttl` bounds the cache lifetime; `fail_mode`
/// decides whether to return stale cache entries when the upstream is
/// unreachable.
#[derive(Clone, Debug)]
pub struct ResolverPolicy {
    /// DID method prefixes (e.g. `"did:web:"`, `"did:key:"`) the
    /// resolver is allowed to dispatch. An empty allow list means
    /// "any method"; that's only safe for trusted contexts.
    pub allowed_methods: Vec<String>,
    /// Default method prefix for principal IDs (`actor_id`). Resolution
    /// of an actor that doesn't carry its own method MUST use this.
    pub default_principal_method: Option<String>,
    /// Trust roots accepted for the active method. Interpretation is
    /// up to the underlying resolver implementation.
    pub trust_roots: Vec<String>,
    /// Maximum lifetime of a cached resolution. `None` disables caching.
    pub ttl: Option<chrono::Duration>,
    /// Fail-mode for upstream errors.
    pub fail_mode: ResolverFailMode,
}

/// Behavior when DID resolution fails (network outage, signature
/// mismatch, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResolverFailMode {
    /// Refuse to use any cached state. Safest default.
    #[default]
    FailClosed,
    /// Allow returning a still-valid cache hit (within TTL) on
    /// transient upstream errors.
    AllowCachedOnError,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            allowed_methods: Vec::new(),
            default_principal_method: None,
            trust_roots: Vec::new(),
            ttl: Some(chrono::Duration::minutes(15)),
            fail_mode: ResolverFailMode::FailClosed,
        }
    }
}

impl ResolverPolicy {
    /// Whether `did` is permitted by `allowed_methods`.
    pub fn permits(&self, did: &Did) -> bool {
        if self.allowed_methods.is_empty() {
            return true;
        }
        let s = did.as_str();
        self.allowed_methods.iter().any(|prefix| s.starts_with(prefix))
    }

    /// Validate `did` against the policy. Returns
    /// `Err(Error::Protocol("unauthorized_method"))` when the method is
    /// not in the allow list.
    pub fn validate(&self, did: &Did) -> Result<()> {
        if self.permits(did) {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "unauthorized_method: '{}' not in resolver allow list",
                did.as_str()
            )))
        }
    }
}

/// Limited `did:web` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidWebResolver {
    documents: BTreeMap<Did, DidDocument>,
}

/// Host-fetched `did:web` document response validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebDocumentOutcome {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl DidWebResolver {
    /// Create an empty `did:web` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a limited `did:web` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "web" || did_web_document_url(&document.id).is_none() {
            return Err(Error::Protocol("unsupported did:web form".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Return the HTTPS DID document URL for the limited supported form.
    pub fn document_url(did: &Did) -> Result<String> {
        did_web_document_url(did)
            .ok_or_else(|| Error::Protocol("unsupported did:web form".to_owned()))
    }

    /// Validate a host-fetched HTTPS response and cache the DID document.
    pub fn insert_from_https_response(
        &mut self,
        did: &Did,
        response: DidWebDocumentOutcome,
    ) -> Result<DidDocument> {
        let expected_url = Self::document_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:web response URL mismatch".to_owned()));
        }
        if !is_allowed_did_web_content_type(&response.content_type) {
            return Err(Error::Protocol("unsupported did:web content type".to_owned()));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES {
            return Err(Error::Protocol("did:web document exceeds size limit".to_owned()));
        }
        let document: DidDocument = serde_json::from_slice(&response.body)?;
        if &document.id != did {
            return Err(Error::Protocol("did:web document id mismatch".to_owned()));
        }
        self.insert(document.clone())?;
        Ok(document)
    }
}

impl DidResolver for DidWebResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "web" && did_web_document_url(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:web resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:web document not found".to_owned()))
    }
}

/// `did:webvh` resolver. Mirrors the offline-friendly shape of
/// [`DidWebResolver`]: callers fetch `did.json` / `did.jsonl` over
/// HTTPS using whatever HTTP client they already use, then hand the
/// bytes to the SDK for validation. The SDK enforces:
///
/// - the `did:webvh:<scid>:<host[:port]>[:path]` shape
/// - that the fetched document `id` equals the requested DID
/// - the SCID present on every log entry matches the DID
/// - the entry chain (`prevVersionId` → `versionId`) is contiguous
/// - the document size is bounded by [`DID_WEB_MAX_DOCUMENT_BYTES`]
/// - **full `did:webvh` v1.0 cryptographic verification** — SCID
///   derivation from the initial entry, the per-entry hash chain, every
///   entry's `eddsa-jcs-2022` Data Integrity proof, and the key-rotation
///   authorization chain (see [`verify_webvh_log`]). Any failure is
///   fatal: the whole log is rejected (fail-closed).
#[derive(Clone, Debug, Default)]
pub struct DidWebvhResolver {
    documents: BTreeMap<Did, DidDocument>,
    logs: BTreeMap<Did, Vec<DidWebvhLogEntry>>,
}

/// A single line from a `did.jsonl` log file. The shape is permissive
/// so the SDK can evolve alongside the W3C draft without breaking
/// callers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebvhLogEntry {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "versionTime")]
    pub version_time: DateTime<Utc>,
    pub parameters: Value,
    pub state: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof: Vec<Value>,
}

/// Bytes returned from fetching `did.json` over HTTPS, mirroring
/// [`DidWebDocumentOutcome`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebvhDocumentOutcome {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Bytes returned from fetching `did.jsonl` over HTTPS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebvhLogOutcome {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl DidWebvhResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// HTTPS URL where the current `did.json` is hosted.
    pub fn document_url(did: &Did) -> Result<String> {
        did_webvh_document_url(did)
            .ok_or_else(|| Error::Protocol("unsupported did:webvh form".to_owned()))
    }

    /// HTTPS URL of the append-only history.
    pub fn log_url(did: &Did) -> Result<String> {
        did_webvh_log_url(did)
            .ok_or_else(|| Error::Protocol("unsupported did:webvh form".to_owned()))
    }

    /// Validate and cache a `did.json` response.
    pub fn insert_from_https_response(
        &mut self,
        did: &Did,
        response: DidWebvhDocumentOutcome,
    ) -> Result<DidDocument> {
        let expected_url = Self::document_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:webvh response URL mismatch".to_owned()));
        }
        if !is_allowed_did_web_content_type(&response.content_type) {
            return Err(Error::Protocol("unsupported did:webvh content type".to_owned()));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES {
            return Err(Error::Protocol("did:webvh document exceeds size limit".to_owned()));
        }
        let document: DidDocument = serde_json::from_slice(&response.body)?;
        if &document.id != did {
            return Err(Error::Protocol("did:webvh document id mismatch".to_owned()));
        }
        document.validate()?;
        self.documents.insert(did.clone(), document.clone());
        Ok(document)
    }

    /// Parse and validate a `did.jsonl` response. Returns the verified
    /// log; throws if the SCID, chain or DID don't agree.
    pub fn ingest_log(
        &mut self,
        did: &Did,
        response: DidWebvhLogOutcome,
    ) -> Result<Vec<DidWebvhLogEntry>> {
        let expected_url = Self::log_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:webvh log URL mismatch".to_owned()));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES * 32 {
            return Err(Error::Protocol("did:webvh log exceeds maximum size".to_owned()));
        }
        let scid = did_webvh_scid(did)
            .ok_or_else(|| Error::Protocol("did:webvh DID has no SCID".to_owned()))?;
        let mut entries = Vec::new();
        // Raw JSON value of each line, preserving every field (including
        // ones the typed [`DidWebvhLogEntry`] does not model). Cryptographic
        // verification MUST run over the producer's exact object, so the
        // canonicalization step uses these raw values rather than a
        // re-serialized typed struct.
        let mut raw_entries: Vec<Value> = Vec::new();
        let mut last_version_id: Option<String> = None;
        for line in response.body.split(|b| *b == b'\n').filter(|chunk| !chunk.is_empty()) {
            let raw: Value = serde_json::from_slice(line)?;
            let entry: DidWebvhLogEntry = serde_json::from_value(raw.clone())?;
            // SCID consistency.
            let entry_scid =
                entry.parameters.get("scid").and_then(Value::as_str).unwrap_or_default();
            if !entry_scid.is_empty() && entry_scid != scid {
                return Err(Error::Protocol(
                    "did:webvh log entry SCID does not match DID".to_owned(),
                ));
            }
            // Sequential version chain. Entries follow `<seq>-<hash>`.
            let (seq, _) = entry.version_id.split_once('-').ok_or_else(|| {
                Error::Protocol("did:webvh entry has malformed versionId".to_owned())
            })?;
            let seq: u64 = seq.parse().map_err(|_| {
                Error::Protocol("did:webvh entry versionId seq not numeric".to_owned())
            })?;
            if seq != entries.len() as u64 + 1 {
                return Err(Error::Protocol(
                    "did:webvh entry versions are not sequential".to_owned(),
                ));
            }
            // Every entry MUST carry at least one Data Integrity proof. An
            // entry with no proof is trivially forgeable, so reject it
            // outright (fail-closed) rather than accepting an unsigned
            // history line.
            if entry.proof.is_empty() {
                return Err(Error::Protocol("did:webvh entry is missing its proof".to_owned()));
            }
            // Optional `prevVersionId` field for >1 entries.
            if let Some(prev) = entry
                .parameters
                .get("prevVersionId")
                .or_else(|| entry.parameters.get("previousVersionId"))
                .and_then(Value::as_str)
                && Some(prev) != last_version_id.as_deref()
            {
                return Err(Error::Protocol(
                    "did:webvh entry prevVersionId does not match previous head".to_owned(),
                ));
            }
            last_version_id = Some(entry.version_id.clone());
            entries.push(entry);
            raw_entries.push(raw);
        }
        if entries.is_empty() {
            return Err(Error::Protocol("did:webvh log is empty".to_owned()));
        }
        // Cryptographic verification: SCID derivation, per-entry EdDSA proof
        // verification, and the key-rotation authorization chain. Any failure
        // here is fatal (fail-closed) — the log is never accepted.
        verify_webvh_log(&scid, &entries, &raw_entries)?;
        // Version-rollback protection: a re-ingested log MUST NOT be shorter
        // than one we already accepted for this DID. This prevents an
        // attacker who controls the host from serving a truncated history
        // that rewinds to an earlier key state.
        if let Some(existing) = self.logs.get(did)
            && entries.len() < existing.len()
        {
            return Err(Error::Protocol(
                "did:webvh log rolls back to an earlier version".to_owned(),
            ));
        }
        self.logs.insert(did.clone(), entries.clone());
        Ok(entries)
    }

    /// Latest verified entry for a previously-ingested DID.
    pub fn latest_entry(&self, did: &Did) -> Option<&DidWebvhLogEntry> {
        self.logs.get(did).and_then(|entries| entries.last())
    }
}

impl DidResolver for DidWebvhResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "webvh" && did_webvh_document_url(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol(
                "unsupported DID method for did:webvh resolver".to_owned(),
            ));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:webvh document not cached".to_owned()))
    }
}

/// Full cryptographic verification of a parsed `did:webvh` log.
///
/// Implements the `did:webvh` v1.0 integrity model on top of the
/// `eddsa-jcs-2022` Data Integrity suite (per `identity-did.md` §3.4,
/// which delegates to the DIF `did:webvh` v1.0 method specification):
///
/// 1. **SCID derivation** — the first entry's SCID MUST be reproducible
///    from the entry's own content (every literal SCID occurrence
///    replaced by the `{SCID}` placeholder, JCS-canonicalized, hashed
///    with SHA-256, wrapped in a multihash, base58btc/multibase encoded).
/// 2. **Entry hash chain** — each `versionId`'s hash component MUST equal
///    the multihash of the entry canonicalized with its `versionId`
///    replaced by the predecessor's `versionId` (the SCID for entry 1)
///    and the `proof` removed.
/// 3. **Per-entry proof verification** — every Data Integrity proof on an
///    entry MUST verify with Ed25519 over `hash(proofConfig) ||
///    hash(transformedDoc)`, using the public key named by the proof's
///    `verificationMethod`.
/// 4. **Key-rotation authorization chain** — entry 1's proof key MUST be
///    one of the `updateKeys` the SCID commits to; entry N's proof key
///    MUST be one of the `updateKeys` authorized by entry N-1 (carried
///    forward when an entry does not re-declare them). This binds every
///    `updateKeys` change to the previous version's authority.
///
/// Any failure is fatal: the function returns `Err` and the caller MUST
/// reject the whole log (fail-closed).
fn verify_webvh_log(scid: &str, entries: &[DidWebvhLogEntry], raw_entries: &[Value]) -> Result<()> {
    // SCID derivation check, anchored on the first entry.
    let derived = derive_webvh_scid(scid, &raw_entries[0])?;
    if derived != scid {
        return Err(Error::Protocol(
            "did:webvh SCID does not derive from initial entry".to_owned(),
        ));
    }

    // `updateKeys` authorized by the *previous* version. For the first
    // entry the authority is the key set the SCID commits to (the entry's
    // own declared `updateKeys`).
    let mut authorized_keys = webvh_update_keys(&entries[0].parameters)?;
    if authorized_keys.is_empty() {
        return Err(Error::Protocol("did:webvh initial entry declares no updateKeys".to_owned()));
    }

    let mut prev_version_id: Option<&str> = None;
    for (index, (entry, raw)) in entries.iter().zip(raw_entries.iter()).enumerate() {
        // Entry-hash chain: the `versionId` hash MUST commit to the entry
        // body (predecessor versionId substituted, proof removed).
        let prev_anchor = prev_version_id.unwrap_or(scid);
        verify_webvh_entry_hash(&entry.version_id, prev_anchor, raw)?;

        // Proof verification + authorization. At least one proof MUST
        // verify under a currently-authorized key. We require *every*
        // proof on the entry to be a well-formed, key-authorized,
        // cryptographically valid signature (fail-closed on any bad one).
        let mut any_authorized = false;
        for proof in &entry.proof {
            let vm = proof.get("verificationMethod").and_then(Value::as_str).ok_or_else(|| {
                Error::Protocol("did:webvh proof missing verificationMethod".to_owned())
            })?;
            let key_multibase = webvh_verification_method_key(vm);
            verify_webvh_proof(raw, proof, &key_multibase)?;
            if authorized_keys.iter().any(|k| k == &key_multibase) {
                any_authorized = true;
            } else {
                return Err(Error::Protocol(
                    "did:webvh proof key is not authorized by the previous version".to_owned(),
                ));
            }
        }
        if !any_authorized {
            return Err(Error::Protocol(
                "did:webvh entry has no proof from an authorized key".to_owned(),
            ));
        }

        // Key rotation: the keys this entry declares become the authority
        // for the *next* entry. An entry that omits `updateKeys` carries
        // the previous authority forward unchanged.
        let declared = webvh_update_keys(&entry.parameters)?;
        if !declared.is_empty() {
            authorized_keys = declared;
        }
        let _ = index;
        prev_version_id = Some(&entry.version_id);
    }
    Ok(())
}

/// Recursively replace every string occurrence of `scid` with the
/// `{SCID}` placeholder inside `value`. `did:webvh` derives the SCID over
/// the initial entry with all SCID references blanked to this placeholder.
fn webvh_placeholder(value: &Value, scid: &str) -> Value {
    match value {
        Value::String(s) => Value::String(s.replace(scid, "{SCID}")),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| webvh_placeholder(item, scid)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter().map(|(k, v)| (k.clone(), webvh_placeholder(v, scid))).collect(),
        ),
        other => other.clone(),
    }
}

/// Derive the SCID from the initial log entry: replace SCID references
/// with `{SCID}`, also blank the `versionId` to the placeholder, drop the
/// `proof`, JCS-canonicalize, and take the multihash/multibase digest.
fn derive_webvh_scid(scid: &str, raw_first: &Value) -> Result<String> {
    let mut preliminary = webvh_placeholder(raw_first, scid);
    if let Some(obj) = preliminary.as_object_mut() {
        obj.remove("proof");
        // During derivation the initial versionId is the SCID placeholder.
        obj.insert("versionId".to_owned(), Value::String("{SCID}".to_owned()));
    }
    let bytes = cokret_core::canonical::canonical_json_bytes(&preliminary)
        .map_err(|e| Error::Protocol(format!("did:webvh SCID canonicalization failed: {e}")))?;
    Ok(webvh_multihash_base58(&bytes))
}

/// Verify the `versionId`'s entry-hash component. `version_id` is
/// `<seq>-<hash>`; `prev_anchor` is the predecessor `versionId` (or the
/// SCID for the first entry). The hash MUST equal the multihash of the
/// entry canonicalized with `versionId = prev_anchor` and `proof` removed.
fn verify_webvh_entry_hash(version_id: &str, prev_anchor: &str, raw: &Value) -> Result<()> {
    let (_, declared_hash) = version_id
        .split_once('-')
        .ok_or_else(|| Error::Protocol("did:webvh entry has malformed versionId".to_owned()))?;
    let mut preimage = raw.clone();
    if let Some(obj) = preimage.as_object_mut() {
        obj.remove("proof");
        obj.insert("versionId".to_owned(), Value::String(prev_anchor.to_owned()));
    }
    let bytes = cokret_core::canonical::canonical_json_bytes(&preimage)
        .map_err(|e| Error::Protocol(format!("did:webvh entry canonicalization failed: {e}")))?;
    let computed = webvh_multihash_base58(&bytes);
    if computed != declared_hash {
        return Err(Error::Protocol("did:webvh entry hash does not match versionId".to_owned()));
    }
    Ok(())
}

/// Verify one `eddsa-jcs-2022` Data Integrity proof over `raw_entry`.
///
/// The signing input is `SHA-256(JCS(proofConfig)) || SHA-256(JCS(doc))`,
/// where `proofConfig` is the proof object without `proofValue` and `doc`
/// is the entry without its `proof` field. `key_multibase` is the
/// `z6Mk…` Ed25519 public key the proof's `verificationMethod` names.
fn verify_webvh_proof(raw_entry: &Value, proof: &Value, key_multibase: &str) -> Result<()> {
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("did:webvh proof missing proofValue".to_owned()))?;

    // proofConfig = proof minus proofValue.
    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
    }
    // transformed document = entry minus proof.
    let mut doc = raw_entry.clone();
    if let Some(obj) = doc.as_object_mut() {
        obj.remove("proof");
    }

    let proof_config_bytes = cokret_core::canonical::canonical_json_bytes(&proof_config)
        .map_err(|e| Error::Protocol(format!("did:webvh proofConfig canonicalization: {e}")))?;
    let doc_bytes = cokret_core::canonical::canonical_json_bytes(&doc)
        .map_err(|e| Error::Protocol(format!("did:webvh proof doc canonicalization: {e}")))?;

    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&Sha256::digest(&proof_config_bytes));
    signing_input.extend_from_slice(&Sha256::digest(&doc_bytes));

    // `proofValue` is multibase base58btc (`z…`) of the raw 64-byte
    // signature (no multicodec tag, per Data Integrity proofValue).
    let sig_body = proof_value.strip_prefix('z').ok_or_else(|| {
        Error::Protocol("did:webvh proofValue is not multibase base58btc".to_owned())
    })?;
    let sig_bytes = decode_base58btc(sig_body)
        .ok_or_else(|| Error::Protocol("did:webvh proofValue base58 decode failed".to_owned()))?;
    let signature: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        Error::Protocol("did:webvh proofValue is not a 64-byte signature".to_owned())
    })?;

    let key_bytes = binding::decode_multicodec_ed25519(key_multibase)
        .map_err(|e| Error::Protocol(format!("did:webvh proof key decode failed: {e}")))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::Protocol(format!("did:webvh proof key is not Ed25519: {e}")))?;
    verifying_key
        .verify_strict(&signing_input, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| Error::Protocol("did:webvh proof signature verification failed".to_owned()))
}

/// Extract a `verificationMethod`'s key portion. did:webvh uses
/// `did:key:z6Mk…#z6Mk…` form; both halves carry the same multibase key,
/// so we take the fragment when present and otherwise the method id.
fn webvh_verification_method_key(vm: &str) -> String {
    let after_fragment = vm.rsplit('#').next().unwrap_or(vm);
    // Strip a leading `did:key:` if the key sits in the method id.
    after_fragment.strip_prefix("did:key:").unwrap_or(after_fragment).to_owned()
}

/// Read the `updateKeys` multibase strings from an entry's `parameters`.
fn webvh_update_keys(parameters: &Value) -> Result<Vec<String>> {
    let Some(keys) = parameters.get("updateKeys") else {
        return Ok(Vec::new());
    };
    let array = keys
        .as_array()
        .ok_or_else(|| Error::Protocol("did:webvh updateKeys is not an array".to_owned()))?;
    let mut out = Vec::with_capacity(array.len());
    for key in array {
        let s = key.as_str().ok_or_else(|| {
            Error::Protocol("did:webvh updateKeys entry is not a string".to_owned())
        })?;
        out.push(s.strip_prefix("did:key:").unwrap_or(s).to_owned());
    }
    Ok(out)
}

/// Limited `did:keri` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidKeriResolver {
    documents: BTreeMap<Did, DidDocument>,
}

impl DidKeriResolver {
    /// Create an empty `did:keri` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:keri` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "keri" {
            return Err(Error::Protocol("did:keri resolver only accepts did:keri".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidKeriResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "keri"
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:keri resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:keri document not found".to_owned()))
    }
}

/// Resolver for `did:key` identifiers with base58btc multicodec validation.
#[derive(Clone, Debug, Default)]
pub struct DidKeyResolver;

impl DidKeyResolver {
    /// Create a `did:key` resolver.
    pub fn new() -> Self {
        Self
    }
}

impl DidResolver for DidKeyResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "key" && did_key_material(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        let key = did_key_material(did)
            .ok_or_else(|| Error::Protocol("unsupported did:key form".to_owned()))?;
        Ok(DidDocument::new(did.clone(), format!("{}#{key}", did.as_str()), key))
    }
}

/// Resolver that tries registered adapters in order.
#[derive(Default)]
pub struct CompositeDidResolver {
    resolvers: Vec<Box<dyn DidResolver + Send + Sync>>,
    policy: ResolverPolicy,
}

impl CompositeDidResolver {
    /// Create an empty resolver chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the active [`ResolverPolicy`].
    pub fn with_policy(mut self, policy: ResolverPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Read the active policy.
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// Append a resolver adapter.
    pub fn push<R>(&mut self, resolver: R)
    where
        R: DidResolver + Send + Sync + 'static,
    {
        self.resolvers.push(Box::new(resolver));
    }
}

impl std::fmt::Debug for CompositeDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeDidResolver")
            .field("resolver_count", &self.resolvers.len())
            .field("policy", &self.policy)
            .finish()
    }
}

impl DidResolver for CompositeDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.policy.permits(did) && self.resolvers.iter().any(|resolver| resolver.supports(did))
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        self.policy.validate(did)?;
        self.resolvers
            .iter()
            .find(|resolver| resolver.supports(did))
            .ok_or_else(|| Error::Protocol("unsupported DID method".to_owned()))?
            .resolve_did(did)
    }
}

// ============================================================================
// DID 解析缓存与新鲜度类型(S1 / S2)
//
// `CompositeDidResolver` 上的 `ResolverPolicy.ttl` 此前仅是元数据——
// resolver 不缓存,每次 `resolve_did` 都重走 resolver 链。下面的类型在
// 不改动任何现有 public API 的前提下,以纯粹的「加法」补上缓存层:
//
// - `Freshness` 描述一次取值相对 TTL 的新鲜程度(新鲜 / 过期 / 缺失)。
// - `CachedResolution` 是单条缓存记录,携带文档、缓存/过期时间戳、文档
//   规范哈希,以及可选的 webvh 日志头与版本号。
// - `CachingDidResolver<R>` 包装任意 `R: DidResolver`,内部以
//   `Mutex<CacheState>` 保存条目并执行 LRU + TTL 逐出。
// ============================================================================

/// 一次缓存取值相对其 TTL 的新鲜程度。
///
/// - `Fresh`:命中且仍在 TTL 窗口内。
/// - `Stale { age }`:命中但已过期(`age` 是相对 `expires_at` 超出的时长);
///   仅在 `ResolverFailMode::AllowCachedOnError` 且底层 resolver 出错时返回。
/// - `Missing`:缓存里没有这个 DID(或缓存被关闭),需要走底层 resolver。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// 命中且未过期。
    Fresh,
    /// 命中但已过期;`age` 为超过 `expires_at` 的时长。
    Stale { age: chrono::Duration },
    /// 缓存里没有该条目。
    Missing,
}

/// 单条 DID 解析缓存记录。
///
/// `document_hash` 用现有 canonical 工具([`cokret_core::canonical`])对
/// 文档做规范化后取 SHA-256(带 `sha256:` 前缀),便于上层做去重 / 变更
/// 检测。`log_head` 与 `version` 是可选的 `did:webvh` 元数据,缓存层本身
/// 不依赖它们,只作透传携带。
#[derive(Clone, Debug)]
pub struct CachedResolution {
    /// 缓存的 DID 文档。
    pub document: DidDocument,
    /// 写入缓存的时刻。
    pub cached_at: DateTime<Utc>,
    /// 过期时刻(`cached_at + ttl`)。
    pub expires_at: DateTime<Utc>,
    /// 文档的规范化 SHA-256 摘要(带 `sha256:` 前缀)。
    pub document_hash: String,
    /// 可选:`did:webvh` 日志头(最新 `versionId`)。
    pub log_head: Option<String>,
    /// 可选:文档版本号。
    pub version: Option<String>,
}

impl CachedResolution {
    /// 用规范化哈希构造一条缓存记录。`log_head` / `version` 默认为 `None`,
    /// 可在构造后按需填充。
    fn new(
        document: DidDocument,
        cached_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let document_hash = document_canonical_hash(&document)?;
        Ok(Self { document, cached_at, expires_at, document_hash, log_head: None, version: None })
    }

    /// 相对 `now` 计算这条记录的新鲜程度。
    fn freshness_at(&self, now: DateTime<Utc>) -> Freshness {
        if now < self.expires_at {
            Freshness::Fresh
        } else {
            Freshness::Stale { age: now - self.expires_at }
        }
    }
}

/// 用现有 canonical 工具计算文档的规范化 SHA-256 摘要(带 `sha256:` 前缀)。
fn document_canonical_hash(document: &DidDocument) -> Result<String> {
    let bytes = cokret_core::canonical::canonical_json_bytes(document)
        .map_err(|e| Error::Protocol(format!("DID document canonicalization failed: {e}")))?;
    Ok(cokret_core::canonical::sha256_digest(bytes))
}

/// `CachingDidResolver` 的内部可变状态,由 `Mutex` 保护。
#[derive(Debug)]
struct CacheState {
    entries: HashMap<String, CachedResolution>,
    max_entries: usize,
}

impl CacheState {
    /// LRU 取值:命中且未过期返回克隆;过期则惰性删除并返回 `None`。
    /// 供 [`DidResolver::resolve_did`] 使用——那条路径不需要 stale 回退,
    /// 因此过期即删,保持 `len()` 诚实。
    fn get_fresh(&mut self, key: &str, now: DateTime<Utc>) -> Option<CachedResolution> {
        match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// 仅查看新鲜条目,**不删除**过期项——`resolve_with_freshness` 在
    /// `AllowCachedOnError` 下需要保留过期条目以备 stale 回退。
    fn peek_fresh(&self, key: &str, now: DateTime<Utc>) -> Option<CachedResolution> {
        match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.clone()),
            _ => None,
        }
    }

    /// 写入一条记录,超过容量时按 `cached_at` 逐出最旧(O(n) 扫描)。
    /// `max_entries == 0` 时不接纳任何条目(缓存关闭)。
    fn insert(&mut self, key: String, entry: CachedResolution) {
        if self.max_entries == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            if let Some(victim) =
                self.entries.iter().min_by_key(|(_, e)| e.cached_at).map(|(k, _)| k.clone())
            {
                self.entries.remove(&victim);
            }
        }
        self.entries.insert(key, entry);
    }
}

/// 给任意 [`DidResolver`] 加上 TTL + LRU 缓存的包装。
///
/// `resolve_did` 实现 [`DidResolver`]:先查缓存(命中且未过期直接返回),
/// miss / 过期才调底层 resolver 并回填。[`Self::resolve_with_freshness`]
/// 在此之上额外返回 [`Freshness`],并遵循 [`ResolverPolicy::fail_mode`]:
/// 仅 `AllowCachedOnError` 时在底层错误下回退到过期缓存。
///
/// 设计上保持对底层 resolver 的通用性(`R: DidResolver`),
/// [`ResolverPolicy`] 由单独字段持有——既可在构造时直接传入,也可从被
/// 包装的 [`CompositeDidResolver`] 复制其 policy。
pub struct CachingDidResolver<R: DidResolver> {
    inner: R,
    policy: ResolverPolicy,
    state: std::sync::Mutex<CacheState>,
}

impl<R: DidResolver> CachingDidResolver<R> {
    /// 用显式 policy 与容量构造缓存包装。`max_entries == 0` 关闭缓存。
    pub fn new(inner: R, policy: ResolverPolicy, max_entries: usize) -> Self {
        Self {
            inner,
            policy,
            state: std::sync::Mutex::new(CacheState { entries: HashMap::new(), max_entries }),
        }
    }

    /// 读取生效的 policy。
    pub fn policy(&self) -> &ResolverPolicy {
        &self.policy
    }

    /// 借用底层 resolver。
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// 当前缓存条目数(惰性逐出之外的即时计数)。
    pub fn len(&self) -> usize {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len()
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 丢弃某个 DID 的缓存(例如收到吊销 / 轮换事件时)。
    pub fn invalidate(&self, did: &Did) {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.remove(did.as_str());
    }

    /// 清空全部缓存。
    pub fn clear(&self) {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.clear();
    }

    /// 依据 `policy.ttl` 计算 `expires_at`。`ttl == None` 表示禁用缓存,
    /// 此处用零时长(写入即过期),配合 `max_entries` 共同决定是否真正缓存。
    fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self.policy.ttl {
            Some(ttl) => now + ttl,
            None => now,
        }
    }

    /// 解析并返回文档及其 [`Freshness`]。
    ///
    /// 流程:
    /// 1. 命中且未过期 → 返回 `(doc, Fresh)`。
    /// 2. 否则调用底层 resolver:
    ///    - 成功 → 回填缓存,返回 `(doc, Missing)`(本次取自上游,非缓存)。
    ///    - 失败 → 若 `fail_mode == AllowCachedOnError` 且存在过期缓存,
    ///      返回 `(stale_doc, Stale { age })`;否则向上抛错(fail-closed)。
    pub fn resolve_with_freshness(
        &self,
        did: &Did,
        now: DateTime<Utc>,
    ) -> Result<(DidDocument, Freshness)> {
        let key = did.as_str().to_owned();

        // 1. 命中且新鲜(此处用 peek,不删除过期项,以便步骤 2 的
        //    stale 回退仍能读到过期条目)。
        if let Some(entry) = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).peek_fresh(&key, now)
        {
            return Ok((entry.document, Freshness::Fresh));
        }

        // 2. miss / 过期:走底层 resolver。
        match self.inner.resolve_did(did) {
            Ok(document) => {
                let expires_at = self.expires_at(now);
                let entry = CachedResolution::new(document.clone(), now, expires_at)?;
                self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key, entry);
                Ok((document, Freshness::Missing))
            }
            Err(err) => {
                // 仅在 AllowCachedOnError 下回退到过期缓存。
                if self.policy.fail_mode == ResolverFailMode::AllowCachedOnError {
                    let stale =
                        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.get(&key).cloned();
                    if let Some(entry) = stale {
                        let freshness = entry.freshness_at(now);
                        return Ok((entry.document, freshness));
                    }
                }
                Err(err)
            }
        }
    }
}

impl<R: DidResolver> DidResolver for CachingDidResolver<R> {
    fn supports(&self, did: &Did) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        let now = Utc::now();
        let key = did.as_str().to_owned();

        if let Some(entry) = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get_fresh(&key, now) {
            return Ok(entry.document);
        }

        let document = self.inner.resolve_did(did)?;
        let expires_at = self.expires_at(now);
        let entry = CachedResolution::new(document.clone(), now, expires_at)?;
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key, entry);
        Ok(document)
    }
}

impl<R: DidResolver + std::fmt::Debug> std::fmt::Debug for CachingDidResolver<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry_count = self.state.lock().map(|s| s.entries.len()).unwrap_or(0);
        f.debug_struct("CachingDidResolver")
            .field("inner", &self.inner)
            .field("policy", &self.policy)
            .field("entries", &entry_count)
            .finish()
    }
}

// ============================================================================
// 缓存 / 新鲜度单测(S3)
// ============================================================================
#[cfg(test)]
mod caching_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// 可控桩 resolver:记录 `resolve_did` 调用次数,并可被切换为「失败」。
    /// 每次解析成功时返回携带递增计数的文档,便于断言「是否真的走了上游」。
    #[derive(Debug)]
    struct StubResolver {
        calls: AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    impl StubResolver {
        fn new() -> Self {
            Self { calls: AtomicUsize::new(0), fail: std::sync::atomic::AtomicBool::new(false) }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            did.method() == "key"
        }

        fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::Protocol("stub resolver forced failure".to_owned()));
            }
            let key = did_key_material(did)
                .ok_or_else(|| Error::Protocol("stub: unsupported did:key".to_owned()))?;
            Ok(DidDocument::new(did.clone(), format!("{}#{key}", did.as_str()), key))
        }
    }

    fn sample_did(suffix: &str) -> Did {
        // 一组合法的 did:key Ed25519 multibase 标识。
        let base = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        Did::new(format!("{base}{suffix}")).unwrap_or_else(|_| Did::new(base.to_owned()).unwrap())
    }

    fn policy(ttl: Option<chrono::Duration>, fail_mode: ResolverFailMode) -> ResolverPolicy {
        ResolverPolicy {
            allowed_methods: Vec::new(),
            default_principal_method: None,
            trust_roots: Vec::new(),
            ttl,
            fail_mode,
        }
    }

    #[test]
    fn cache_hit_avoids_second_upstream_call() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::FailClosed),
            128,
        );
        let did = sample_did("");

        let now = Utc::now();
        let (_doc, f1) = resolver.resolve_with_freshness(&did, now).expect("first resolve");
        assert_eq!(f1, Freshness::Missing, "首次解析来自上游");
        assert_eq!(resolver.inner().calls(), 1);

        // 同一 TTL 窗口内再次解析:命中缓存,不再调用上游。
        let (_doc, f2) = resolver
            .resolve_with_freshness(&did, now + chrono::Duration::minutes(1))
            .expect("second resolve");
        assert_eq!(f2, Freshness::Fresh, "命中且新鲜");
        assert_eq!(resolver.inner().calls(), 1, "上游只被调用一次");

        // document_hash 已计算且带前缀。
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn ttl_expiry_triggers_miss() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::FailClosed),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        resolver.resolve_with_freshness(&did, now).expect("first");
        assert_eq!(resolver.inner().calls(), 1);

        // 超过 TTL 后再解析:过期 → miss → 重新走上游。
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) = resolver.resolve_with_freshness(&did, later).expect("after expiry");
        assert_eq!(f, Freshness::Missing, "过期后重新取自上游");
        assert_eq!(resolver.inner().calls(), 2);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let stub = StubResolver::new();
        // 容量 2:写入三个不同 DID 后,最旧的应被逐出。
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::FailClosed),
            2,
        );

        let base = Utc::now();
        let d1 = sample_did("");
        // 通过不同的 did:key 标识区分条目。
        let d2 = Did::new("did:key:z6MkfGFvHcKHd9YEK5sBYqLqHs5GpD3xKCJQyZK7r2pHpkpf".to_owned())
            .expect("valid did:key");
        let d3 = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned())
            .expect("valid did:key");

        resolver.resolve_with_freshness(&d1, base).expect("d1");
        resolver.resolve_with_freshness(&d2, base + chrono::Duration::seconds(1)).expect("d2");
        assert_eq!(resolver.len(), 2);

        // 写入第三个,最旧的 d1(cached_at 最早)应被逐出。
        resolver.resolve_with_freshness(&d3, base + chrono::Duration::seconds(2)).expect("d3");
        assert_eq!(resolver.len(), 2, "容量上限保持为 2");

        // d1 现在 miss(会再次走上游),d2/d3 仍命中。
        let calls_before = resolver.inner().calls();
        let (_doc, f1) = resolver
            .resolve_with_freshness(&d1, base + chrono::Duration::seconds(3))
            .expect("d1 re-resolve");
        assert_eq!(f1, Freshness::Missing, "最旧条目已被逐出");
        assert_eq!(resolver.inner().calls(), calls_before + 1);

        let (_doc, f2) = resolver
            .resolve_with_freshness(&d3, base + chrono::Duration::seconds(3))
            .expect("d3 still cached");
        assert_eq!(f2, Freshness::Fresh, "d3 仍在缓存中");
    }

    #[test]
    fn max_entries_zero_disables_cache() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::FailClosed),
            0,
        );
        let did = sample_did("");
        let now = Utc::now();

        resolver.resolve_with_freshness(&did, now).expect("first");
        resolver.resolve_with_freshness(&did, now).expect("second");
        // 缓存关闭:每次都走上游,且永远不留存条目。
        assert_eq!(resolver.len(), 0, "缓存关闭,无任何条目");
        assert_eq!(resolver.inner().calls(), 2, "每次都调用上游");
    }

    #[test]
    fn fail_closed_propagates_error() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::FailClosed),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        // 先成功填充一条缓存。
        resolver.resolve_with_freshness(&did, now).expect("warm cache");
        // 切换为失败,并越过 TTL 触发上游调用。
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let result = resolver.resolve_with_freshness(&did, later);
        assert!(result.is_err(), "FailClosed 模式下底层错误必须上抛");
    }

    #[test]
    fn allow_cached_on_error_returns_stale() {
        let stub = StubResolver::new();
        let resolver = CachingDidResolver::new(
            stub,
            policy(Some(chrono::Duration::minutes(15)), ResolverFailMode::AllowCachedOnError),
            128,
        );
        let did = sample_did("");
        let now = Utc::now();

        // 先成功填充缓存。
        resolver.resolve_with_freshness(&did, now).expect("warm cache");
        // 切换为失败,越过 TTL。
        resolver.inner().set_fail(true);
        let later = now + chrono::Duration::minutes(16);
        let (_doc, f) =
            resolver.resolve_with_freshness(&did, later).expect("stale fallback succeeds");
        match f {
            Freshness::Stale { age } => {
                // age 约为超过 expires_at 的 1 分钟(16 - 15)。
                assert!(age >= chrono::Duration::seconds(30), "返回的过期时长应为正且合理");
            }
            other => panic!("期望 Stale,实际为 {other:?}"),
        }
    }
}
