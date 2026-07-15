use super::basics::*;
use crate::identity::helpers::*;
use crate::identity::*;

/// `did:webvh` resolver. Mirrors the offline-friendly shape of
/// [`DidWebResolver`]: callers fetch `did.json` / `did.jsonl` over
/// HTTPS using whatever HTTP client they already use, then hand the
/// bytes to the SDK for validation. The SDK enforces:
///
/// - the `did:webvh:<scid>:<host[:port]>[:path]` shape
/// - that the fetched document `id` equals the requested DID
/// - the SCID present on every log entry matches the DID
/// - the `versionId` hash chain is contiguous
/// - the document size is bounded by [`DID_WEB_MAX_DOCUMENT_BYTES`]
/// - **full `did:webvh` v1.0 cryptographic verification** — SCID derivation from the initial entry,
///   the per-entry hash chain, every entry's `eddsa-jcs-2022` Data Integrity proof, and the
///   key-rotation authorization chain (see [`verify_did_webvh_v1_chain`]). Any failure is fatal:
///   the whole log is rejected (fail-closed).
#[derive(Clone, Debug, Default)]
pub struct DidWebvhResolver {
    documents: BTreeMap<Did, DidDocument>,
    logs: BTreeMap<Did, Vec<DidWebvhLogEntry>>,
    raw_logs: BTreeMap<Did, Vec<Value>>,
    conflicted: std::collections::BTreeSet<Did>,
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

/// Result of fail-closed verification of a complete WebVH history. Raw entries
/// and head state are retained so callers can preserve fork evidence and
/// compare a separately fetched `did.json` without discarding DID Core fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDidWebvhLog {
    pub raw_entries: Vec<Value>,
    pub entries: Vec<DidWebvhLogEntry>,
    pub head_version_id: String,
    pub head_state: Value,
    pub active_update_keys: Vec<String>,
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
        if self.conflicted.contains(did) {
            return Err(Error::Protocol(
                "did:webvh history is conflicted; current state is unavailable".to_owned(),
            ));
        }
        let expected_url = Self::document_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol(
                "did:webvh response URL mismatch".to_owned(),
            ));
        }
        if !is_allowed_did_web_content_type(&response.content_type) {
            return Err(Error::Protocol(
                "unsupported did:webvh content type".to_owned(),
            ));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES {
            return Err(Error::Protocol(
                "did:webvh document exceeds size limit".to_owned(),
            ));
        }
        let document: DidDocument = serde_json::from_slice(&response.body)?;
        if &document.id != did {
            return Err(Error::Protocol("did:webvh document id mismatch".to_owned()));
        }
        document.validate()?;
        if let Some(entries) = self.logs.get(did)
            && let Some(head) = entries.last()
        {
            verify_document_matches_webvh_head(&document, &head.state)?;
        }
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
        if self.conflicted.contains(did) {
            return Err(Error::Protocol(
                "did:webvh history is conflicted; current state is unavailable".to_owned(),
            ));
        }
        let expected_url = Self::log_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:webvh log URL mismatch".to_owned()));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES * 32 {
            return Err(Error::Protocol(
                "did:webvh log exceeds maximum size".to_owned(),
            ));
        }
        let verified = verify_did_webvh_v1_chain_bytes(did, &response.body)?;
        if let Some(existing) = self.raw_logs.get(did) {
            let shared_length = existing.len().min(verified.raw_entries.len());
            if existing[..shared_length] != verified.raw_entries[..shared_length] {
                self.mark_conflicted(did);
                return Err(Error::Protocol(
                    "did:webvh sibling history detected; current state is unavailable".to_owned(),
                ));
            }
        }
        let entries = verified.entries;
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
        if let Some(document) = self.documents.get(did) {
            verify_document_matches_webvh_head(document, &verified.head_state)?;
        }
        self.raw_logs.insert(did.clone(), verified.raw_entries);
        self.logs.insert(did.clone(), entries.clone());
        Ok(entries)
    }

    /// Latest verified entry for a previously-ingested DID.
    pub fn latest_entry(&self, did: &Did) -> Option<&DidWebvhLogEntry> {
        self.logs.get(did).and_then(|entries| entries.last())
    }

    pub fn is_conflicted(&self, did: &Did) -> bool {
        self.conflicted.contains(did)
    }

    fn mark_conflicted(&mut self, did: &Did) {
        self.conflicted.insert(did.clone());
        self.documents.remove(did);
        self.logs.remove(did);
        self.raw_logs.remove(did);
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
        if self.conflicted.contains(did) {
            return Err(Error::Protocol(
                "did:webvh history is conflicted; current state is unavailable".to_owned(),
            ));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:webvh document not cached".to_owned()))
    }
}

/// Parse and verify a complete JSON-lines Arkret principal WebVH history.
pub fn verify_did_webvh_v1_log_bytes(did: &Did, bytes: &[u8]) -> Result<VerifiedDidWebvhLog> {
    let raw_entries = parse_did_webvh_json_lines(bytes)?;
    verify_did_webvh_v1_log(did, &raw_entries)
}

/// Parse and verify the generic WebVH integrity/current-key profile.
pub fn verify_did_webvh_v1_chain_bytes(did: &Did, bytes: &[u8]) -> Result<VerifiedDidWebvhLog> {
    let raw_entries = parse_did_webvh_json_lines(bytes)?;
    verify_did_webvh_v1_chain(did, &raw_entries)
}

fn parse_did_webvh_json_lines(bytes: &[u8]) -> Result<Vec<Value>> {
    let mut raw_entries = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        raw_entries.push(serde_json::from_slice(line)?);
    }
    Ok(raw_entries)
}

/// Fail-closed verification of the entire current-entry/pre-rotation/spent-key
/// model. Every entry explicitly declares and is signed by its current root
/// key; after inception that key must match the previous entry's commitment,
/// and a previously activated root key can never become active again.
pub fn verify_did_webvh_v1_log(did: &Did, raw_entries: &[Value]) -> Result<VerifiedDidWebvhLog> {
    verify_did_webvh_v1_internal(did, raw_entries, true)
}

/// Verify generic WebVH SCID/hash-chain/proof/current-key integrity. Rotation
/// requires the previous entry's pre-rotation commitment, while a single-head
/// service or organization DID need not advertise a future key.
pub fn verify_did_webvh_v1_chain(did: &Did, raw_entries: &[Value]) -> Result<VerifiedDidWebvhLog> {
    verify_did_webvh_v1_internal(did, raw_entries, false)
}

fn verify_did_webvh_v1_internal(
    did: &Did,
    raw_entries: &[Value],
    principal_profile: bool,
) -> Result<VerifiedDidWebvhLog> {
    if did.method() != "webvh" {
        return Err(Error::Protocol("DID is not did:webvh".to_owned()));
    }
    let scid = did_webvh_scid(did)
        .ok_or_else(|| Error::Protocol("did:webvh DID has no SCID".to_owned()))?;
    if raw_entries.is_empty() {
        return Err(Error::Protocol("did:webvh log is empty".to_owned()));
    }
    let entries = raw_entries
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<DidWebvhLogEntry>, _>>()?;
    if derive_webvh_scid(&scid, &raw_entries[0])? != scid {
        return Err(Error::Protocol(
            "did:webvh SCID does not derive from initial entry".to_owned(),
        ));
    }

    let mut spent_keys = std::collections::BTreeSet::new();
    let mut previous_version_id: Option<&str> = None;
    let mut previous_next_hashes: Option<Vec<String>> = None;
    let mut active_update_keys = Vec::new();

    for (index, (entry, raw)) in entries.iter().zip(raw_entries).enumerate() {
        let expected_sequence = index as u64 + 1;
        let (sequence, _) = entry
            .version_id
            .split_once('-')
            .ok_or_else(|| Error::Protocol("did:webvh entry has malformed versionId".to_owned()))?;
        if sequence.parse::<u64>().ok() != Some(expected_sequence)
            || (sequence.len() > 1 && sequence.starts_with('0'))
        {
            return Err(Error::Protocol(
                "did:webvh entry versions are not sequential".to_owned(),
            ));
        }
        if entry.parameters.get("scid").and_then(Value::as_str) != Some(scid.as_str()) {
            return Err(Error::Protocol(
                "did:webvh log entry SCID does not match DID".to_owned(),
            ));
        }
        if entry.parameters.get("method").and_then(Value::as_str) != Some("did:webvh:1.0") {
            return Err(Error::Protocol(
                "did:webvh log entry method must be did:webvh:1.0".to_owned(),
            ));
        }
        if entry.state.get("id").and_then(Value::as_str) != Some(did.as_str()) {
            return Err(Error::Protocol(
                "did:webvh log state id does not match DID".to_owned(),
            ));
        }
        let previous_anchor = previous_version_id.unwrap_or(scid.as_str());
        verify_webvh_entry_hash(&entry.version_id, previous_anchor, raw)?;

        let current_keys = webvh_update_keys(&entry.parameters)?;
        if current_keys.is_empty() {
            return Err(Error::Protocol(
                "did:webvh entry must explicitly declare updateKeys".to_owned(),
            ));
        }
        ensure_unique_webvh_values("updateKeys", &current_keys)?;
        for key in &current_keys {
            binding::decode_multicodec_ed25519(key).map_err(|error| {
                Error::Protocol(format!("did:webvh update key is not Ed25519: {error}"))
            })?;
            if spent_keys.contains(key) {
                return Err(Error::Protocol(
                    "did:webvh spent update key cannot become active again".to_owned(),
                ));
            }
        }
        if index > 0 && previous_next_hashes.is_none() {
            return Err(Error::Protocol(
                "did:webvh rotation has no previous nextKeyHashes authorization".to_owned(),
            ));
        }
        if let Some(committed_hashes) = &previous_next_hashes {
            for key in &current_keys {
                let commitment = webvh_multihash_base58(key.as_bytes());
                if !committed_hashes.contains(&commitment) {
                    return Err(Error::Protocol(
                        "did:webvh current update key was not committed by the previous entry"
                            .to_owned(),
                    ));
                }
            }
        }
        if principal_profile {
            let forbidden_roots = spent_keys
                .iter()
                .chain(current_keys.iter())
                .map(String::as_str)
                .collect::<Vec<_>>();
            arkret_signatures::webvh::validate_principal_did_document_profile(
                did.as_str(),
                &entry.state,
                &forbidden_roots,
            )
            .map_err(|error| Error::Protocol(format!("invalid principal DID profile: {error}")))?;
        }

        if entry.proof.is_empty() {
            return Err(Error::Protocol(
                "did:webvh entry is missing its proof".to_owned(),
            ));
        }
        for proof in &entry.proof {
            let verification_method = proof
                .get("verificationMethod")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::Protocol("did:webvh proof missing verificationMethod".to_owned())
                })?;
            let key_multibase = webvh_verification_method_key(verification_method);
            let exact_method = format!("did:key:{key_multibase}#{key_multibase}");
            if verification_method != exact_method {
                return Err(Error::Protocol(
                    "did:webvh proof verificationMethod is not canonical did:key form".to_owned(),
                ));
            }
            if !current_keys.contains(&key_multibase) {
                return Err(Error::Protocol(
                    "did:webvh proof key is not active in the current entry".to_owned(),
                ));
            }
            verify_webvh_proof(raw, proof, &key_multibase)?;
        }

        let next_hashes = webvh_next_key_hashes(&entry.parameters)?;
        if principal_profile && next_hashes.is_empty() {
            return Err(Error::Protocol(
                "did:webvh principal entry must declare nextKeyHashes".to_owned(),
            ));
        }
        ensure_unique_webvh_values("nextKeyHashes", &next_hashes)?;
        for activated_key in spent_keys.iter().chain(current_keys.iter()) {
            let activated_commitment = webvh_multihash_base58(activated_key.as_bytes());
            if next_hashes.contains(&activated_commitment) {
                return Err(Error::Protocol(
                    "did:webvh nextKeyHashes cannot recommit an activated or spent update key"
                        .to_owned(),
                ));
            }
        }

        spent_keys.extend(current_keys.iter().cloned());
        active_update_keys = current_keys;
        previous_next_hashes = Some(next_hashes);
        previous_version_id = Some(&entry.version_id);
    }

    let head = entries.last().expect("non-empty checked above");
    Ok(VerifiedDidWebvhLog {
        raw_entries: raw_entries.to_vec(),
        entries: entries.clone(),
        head_version_id: head.version_id.clone(),
        head_state: head.state.clone(),
        active_update_keys,
    })
}

fn verify_document_matches_webvh_head(document: &DidDocument, head_state: &Value) -> Result<()> {
    let document_value = serde_json::to_value(document)?;
    let document_bytes = arkret_canonical::canonical::canonical_json_bytes(&document_value)
        .map_err(|error| {
            Error::Protocol(format!("did:webvh document canonicalization: {error}"))
        })?;
    let head_bytes = arkret_canonical::canonical::canonical_json_bytes(head_state)
        .map_err(|error| Error::Protocol(format!("did:webvh head canonicalization: {error}")))?;
    if document_bytes != head_bytes {
        return Err(Error::Protocol(
            "did:webvh did.json does not match the verified log head state".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_unique_webvh_values(field: &str, values: &[String]) -> Result<()> {
    let unique = values.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(Error::Protocol(format!(
            "did:webvh {field} contains duplicate values"
        )));
    }
    Ok(())
}

/// Recursively replace every string occurrence of `scid` with the
/// `{SCID}` placeholder inside `value`. `did:webvh` derives the SCID over
/// the initial entry with all SCID references blanked to this placeholder.
fn webvh_placeholder(value: &Value, scid: &str) -> Value {
    match value {
        Value::String(s) => Value::String(s.replace(scid, "{SCID}")),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| webvh_placeholder(item, scid))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), webvh_placeholder(v, scid)))
                .collect(),
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
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&preliminary)
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
        obj.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
    }
    let bytes = arkret_canonical::canonical::canonical_json_bytes(&preimage)
        .map_err(|e| Error::Protocol(format!("did:webvh entry canonicalization failed: {e}")))?;
    let computed = webvh_multihash_base58(&bytes);
    if computed != declared_hash {
        return Err(Error::Protocol(
            "did:webvh entry hash does not match versionId".to_owned(),
        ));
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
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof")
        || proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022")
        || proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod")
    {
        return Err(Error::Protocol(
            "did:webvh proof must be an eddsa-jcs-2022 assertionMethod proof".to_owned(),
        ));
    }
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

    let proof_config_bytes = arkret_canonical::canonical::canonical_json_bytes(&proof_config)
        .map_err(|e| Error::Protocol(format!("did:webvh proofConfig canonicalization: {e}")))?;
    let doc_bytes = arkret_canonical::canonical::canonical_json_bytes(&doc)
        .map_err(|e| Error::Protocol(format!("did:webvh proof doc canonicalization: {e}")))?;

    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&crate::canonical::sha256_bytes(&proof_config_bytes));
    signing_input.extend_from_slice(&crate::canonical::sha256_bytes(&doc_bytes));

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
        .verify_strict(
            &signing_input,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| Error::Protocol("did:webvh proof signature verification failed".to_owned()))
}

/// Extract a `verificationMethod`'s key portion. did:webvh uses
/// `did:key:z6Mk…#z6Mk…` form; both halves carry the same multibase key,
/// so we take the fragment when present and otherwise the method id.
fn webvh_verification_method_key(vm: &str) -> String {
    let after_fragment = vm.rsplit('#').next().unwrap_or(vm);
    // Strip a leading `did:key:` if the key sits in the method id.
    after_fragment
        .strip_prefix("did:key:")
        .unwrap_or(after_fragment)
        .to_owned()
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

fn webvh_next_key_hashes(parameters: &Value) -> Result<Vec<String>> {
    let Some(hashes) = parameters.get("nextKeyHashes") else {
        return Ok(Vec::new());
    };
    let hashes = hashes
        .as_array()
        .ok_or_else(|| Error::Protocol("did:webvh nextKeyHashes is not an array".to_owned()))?;
    hashes
        .iter()
        .map(|hash| {
            let hash = hash.as_str().ok_or_else(|| {
                Error::Protocol("did:webvh nextKeyHashes entry is not a string".to_owned())
            })?;
            let decoded = arkret_core::decode_base58btc(hash).map_err(|_| {
                Error::Protocol("did:webvh nextKeyHashes entry is not base58btc".to_owned())
            })?;
            if decoded.len() != 34 || decoded[..2] != [0x12, 0x20] {
                return Err(Error::Protocol(
                    "did:webvh nextKeyHashes entry is not a sha2-256 multihash".to_owned(),
                ));
            }
            if arkret_core::encode_base58btc(&decoded) != hash {
                return Err(Error::Protocol(
                    "did:webvh nextKeyHashes entry is not canonical base58btc".to_owned(),
                ));
            }
            Ok(hash.to_owned())
        })
        .collect()
}
