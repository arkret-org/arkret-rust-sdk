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
/// - the entry chain (`prevVersionId` → `versionId`) is contiguous
/// - the document size is bounded by [`DID_WEB_MAX_DOCUMENT_BYTES`]
/// - **full `did:webvh` v1.0 cryptographic verification** — SCID derivation from the initial entry,
///   the per-entry hash chain, every entry's `eddsa-jcs-2022` Data Integrity proof, and the
///   key-rotation authorization chain (see [`verify_webvh_log`]). Any failure is fatal: the whole
///   log is rejected (fail-closed).
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
            return Err(Error::Protocol(
                "did:webvh log exceeds maximum size".to_owned(),
            ));
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
        for line in response
            .body
            .split(|b| *b == b'\n')
            .filter(|chunk| !chunk.is_empty())
        {
            let raw: Value = serde_json::from_slice(line)?;
            let entry: DidWebvhLogEntry = serde_json::from_value(raw.clone())?;
            // SCID consistency.
            let entry_scid = entry
                .parameters
                .get("scid")
                .and_then(Value::as_str)
                .unwrap_or_default();
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
                return Err(Error::Protocol(
                    "did:webvh entry is missing its proof".to_owned(),
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
/// 1. **SCID derivation** — the first entry's SCID MUST be reproducible from the entry's own
///    content (every literal SCID occurrence replaced by the `{SCID}` placeholder,
///    JCS-canonicalized, hashed with SHA-256, wrapped in a multihash, base58btc/multibase encoded).
/// 2. **Entry hash chain** — each `versionId`'s hash component MUST equal the multihash of the
///    entry canonicalized with its `versionId` replaced by the predecessor's `versionId` (the SCID
///    for entry 1) and the `proof` removed.
/// 3. **Per-entry proof verification** — every Data Integrity proof on an entry MUST verify with
///    Ed25519 over `hash(proofConfig) || hash(transformedDoc)`, using the public key named by the
///    proof's `verificationMethod`.
/// 4. **Key-rotation authorization chain** — entry 1's proof key MUST be one of the `updateKeys`
///    the SCID commits to; entry N's proof key MUST be one of the `updateKeys` authorized by entry
///    N-1 (carried forward when an entry does not re-declare them). This binds every `updateKeys`
///    change to the previous version's authority.
///
/// Any failure is fatal: the function returns `Err` and the caller MUST
/// reject the whole log (fail-closed).
fn verify_webvh_log(scid: &str, entries: &[DidWebvhLogEntry], raw_entries: &[Value]) -> Result<()> {
    // SCID derivation check, sealed on the first entry.
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
        return Err(Error::Protocol(
            "did:webvh initial entry declares no updateKeys".to_owned(),
        ));
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
            let vm = proof
                .get("verificationMethod")
                .and_then(Value::as_str)
                .ok_or_else(|| {
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
    let bytes = arkret_core::canonical::canonical_json_bytes(&preliminary)
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
    let bytes = arkret_core::canonical::canonical_json_bytes(&preimage)
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

    let proof_config_bytes = arkret_core::canonical::canonical_json_bytes(&proof_config)
        .map_err(|e| Error::Protocol(format!("did:webvh proofConfig canonicalization: {e}")))?;
    let doc_bytes = arkret_core::canonical::canonical_json_bytes(&doc)
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
