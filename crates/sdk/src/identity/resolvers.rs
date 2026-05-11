use super::*;

/// Resolve DID documents for one or more DID methods.
pub trait DidResolver {
    /// Return whether this resolver can handle the DID method or concrete DID.
    fn supports(&self, did: &Did) -> bool;

    /// Resolve a DID document.
    fn resolve_did(&self, did: &Did) -> Result<DidDocument>;
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

/// In-memory resolver for registered `did:uuid` documents.
#[derive(Clone, Debug, Default)]
pub struct DidUuidResolver {
    documents: BTreeMap<Did, DidDocument>,
}

impl DidUuidResolver {
    /// Create an empty `did:uuid` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `did:uuid` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if !document.id.is_uuid() {
            return Err(Error::Protocol("did:uuid resolver only accepts did:uuid".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }
}

impl DidResolver for DidUuidResolver {
    fn supports(&self, did: &Did) -> bool {
        did.is_uuid()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol("unsupported DID method for did:uuid resolver".to_owned()));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:uuid document not found".to_owned()))
    }
}

/// Limited `did:web` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidWebResolver {
    documents: BTreeMap<Did, DidDocument>,
}

/// Host-fetched `did:web` document response validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebDocumentResponse {
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
        response: DidWebDocumentResponse,
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
///
/// Cryptographic proof verification is delegated to the caller for now
/// — the registry already verifies proofs server-side and the SDK does
/// not yet bring an Ed25519 dependency by default.
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
/// [`DidWebDocumentResponse`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebvhDocumentResponse {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Bytes returned from fetching `did.jsonl` over HTTPS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebvhLogResponse {
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
        response: DidWebvhDocumentResponse,
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
        response: DidWebvhLogResponse,
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
        let mut last_version_id: Option<String> = None;
        for line in response.body.split(|b| *b == b'\n').filter(|chunk| !chunk.is_empty()) {
            let entry: DidWebvhLogEntry = serde_json::from_slice(line)?;
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
        }
        if entries.is_empty() {
            return Err(Error::Protocol("did:webvh log is empty".to_owned()));
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
