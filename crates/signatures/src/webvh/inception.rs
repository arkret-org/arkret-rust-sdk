//! Embedded `did:webvh` inception builder, shared by clients and servers.
//!
//! Soland accepts WebVH inception as a protocol DID operation at
//! `/_cokret/root/identity/submit-did-operation`. Soland's embedded WebVH
//! profile requires the client to:
//!
//! 1. generate the DID's verification keypair and a separate update keypair,
//! 2. construct the inception webvh log entry with `{SCID}` placeholders,
//! 3. derive the SCID (sha256-multihash-multibase of the canonical-JCS skeleton),
//! 4. substitute the SCID and compute `versionId = 1-<entryHash>`,
//! 5. sign the entry (sans `proof`) under `cryptosuite: eddsa-jcs-2022` with the update key —
//!    soland verifies that signature in `verify_webvh_log_proof`.
//!
//! This module owns step 1–5. It returns a typed DID-operation request, the
//! resulting DID, and the secret seed bytes for both the DID key and the update
//! key so the caller can persist them.
//!
//! The algorithm intentionally mirrors soland's helpers byte-for-byte:
//! `sha256_multihash_multibase`, `strip_webvh_entry_for_hash`,
//! `substitute_webvh_scid`, and the eddsa-jcs-2022 proof shape are all
//! re-implemented here, and the test module includes an in-crate copy of
//! soland's `verify_webvh_log_proof` so any divergence trips CI.
//!
//! HTTP transport (POSTing the prepared operation to soland) deliberately lives
//! outside this crate: this module is pure build + cryptography so clients
//! (sodmin / inkson) and servers (soland / coauth) can all share one
//! implementation with no drift.

use arkret_core::{
    Did, DidOperationSubmitRequestBody, decode_base58btc, decode_ed25519_multibase,
    encode_base58btc,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
};
use rand_core::RngCore;
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Errors produced while preparing a `did:webvh` inception entry.
///
/// Only build / cryptography failures live here; transport (HTTP submit) and
/// storage errors stay in the caller (e.g. coauth's `SolandWebvhError`).
#[derive(Debug, Error)]
pub enum WebvhInceptionError {
    #[error("principal-server endpoint is not a valid URL: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("principal-server endpoint must include a host with a dot for did:webvh")]
    EndpointHostInvalid,
    #[error("local_id failed normalisation (must be 1-64 ascii [a-z0-9._-])")]
    InvalidLocalId,
    #[error("webvh key fragment failed normalisation")]
    InvalidKeyFragment,
    #[error("computed DID failed SDK validation: {0}")]
    InvalidDid(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("webvh proof rejected: {0}")]
    InvalidProof(String),
}

/// Result of `prepare_inception` — everything the caller needs to POST the
/// registration to soland and persist the secrets for later rotation.
///
/// The two `*_seed` fields are DID root key material: `Debug` renders them
/// redacted (mirroring `arkret_crypto::VaultKek`) and both are zeroized on
/// drop so they never leak into logs, backtraces or freed memory.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct PreparedInception {
    /// The minted DID, e.g.
    /// `did:webvh:zQm...:local.host%3A8080:webvh:01krmccd...`.
    #[zeroize(skip)]
    pub did: String,
    /// The DID-method authority (host or `host%3Aport`). Stored so callers
    /// can sanity-check or reconstruct URLs without re-parsing.
    #[zeroize(skip)]
    pub method_authority: String,
    /// The matching HTTPS authority (`host` or `host:port`).
    #[zeroize(skip)]
    pub https_authority: String,
    /// Normalised webvh `local_id` — the URL path segment under
    /// `/webvh/<local_id>/did.json`.
    #[zeroize(skip)]
    pub local_id: String,
    /// `versionTime` recorded on the inception entry (RFC3339).
    #[zeroize(skip)]
    pub version_time: String,
    /// `versionId` of the inception entry (`1-<entryHash>`).
    #[zeroize(skip)]
    pub version_id: String,
    /// Final inception webvh log entry, with SCID substituted and proof
    /// attached.
    #[zeroize(skip)]
    pub log_entry: Value,
    /// Typed request body for `ck.root.identity.command.submit_did_operation`.
    #[zeroize(skip)]
    pub submit_body: DidOperationSubmitRequestBody,
    /// Multibase ed25519 **public** key for the DID's verification method.
    #[zeroize(skip)]
    pub did_public_key_multibase: String,
    /// Multibase ed25519 **public** key for `updateKeys[0]`.
    #[zeroize(skip)]
    pub update_public_key_multibase: String,
    /// DID + key fragment, e.g. `did:webvh:...#did-key-1`.
    #[zeroize(skip)]
    pub did_key_id: String,
    /// DID + update-key fragment, e.g. `did:webvh:...#update-key-1`.
    #[zeroize(skip)]
    pub update_key_id: String,
    /// Protocol document read URL.
    #[zeroize(skip)]
    pub document_url: String,
    /// Protocol log read URL.
    #[zeroize(skip)]
    pub log_url: String,
    /// 32-byte ed25519 secret seed for the DID key.
    pub did_key_seed: [u8; 32],
    /// 32-byte ed25519 secret seed for the update key — caller must persist
    /// this (encrypted) to sign future rotations.
    pub update_key_seed: [u8; 32],
}

impl std::fmt::Debug for PreparedInception {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedInception")
            .field("did", &self.did)
            .field("method_authority", &self.method_authority)
            .field("https_authority", &self.https_authority)
            .field("local_id", &self.local_id)
            .field("version_time", &self.version_time)
            .field("version_id", &self.version_id)
            .field("log_entry", &self.log_entry)
            .field("submit_body", &self.submit_body)
            .field("did_public_key_multibase", &self.did_public_key_multibase)
            .field(
                "update_public_key_multibase",
                &self.update_public_key_multibase,
            )
            .field("did_key_id", &self.did_key_id)
            .field("update_key_id", &self.update_key_id)
            .field("document_url", &self.document_url)
            .field("log_url", &self.log_url)
            .field("did_key_seed", &"<redacted>")
            .field("update_key_seed", &"<redacted>")
            .finish()
    }
}

/// Inputs to `prepare_inception`. Borrowed and explicit so callers cannot
/// accidentally pass their own URL builder when they meant the principal
/// server's endpoint.
pub struct InceptionInput<'a> {
    /// Soland's base endpoint, e.g. `https://local.host:8080/`. Drives the
    /// DID method authority, the in-document `serviceEndpoint`, and the
    /// `also_known_as` reverse-link surface.
    pub principal_endpoint: &'a Url,
    /// Stable per-user identifier — typically the user's ULID lower-cased.
    /// Validated against soland's `normalize_webvh_local_id` rules.
    pub local_id: &'a str,
    /// Optional `alsoKnownAs` entries (e.g. the user's `@handle@host`).
    pub also_known_as: &'a [String],
    /// `versionTime` for the inception entry. Soland requires RFC3339.
    pub version_time: DateTime<Utc>,
    /// Optional verification-method fragment (`#<frag>`). Defaults to
    /// `did-key-1` to match soland's documented default.
    pub did_key_fragment: Option<&'a str>,
    /// Device-enrollment-authority DID (`did:key:z…`) written into the minted
    /// DID document as the `CokretDeviceEnrollmentAuthority` service
    /// `serviceEndpoint`. This designates the authority allowed to attest
    /// `service_attested` `ck.device.authorize` events for this principal
    /// (decision 0002 / device-lifecycle §5.4).
    pub enrollment_authority_did: &'a str,
}

/// Inputs for a client-authored WebVH inception. The client supplies the DID
/// and update public keys plus the signed log proof; the server reconstructs
/// the exact inception entry, verifies the proof locally, and submits the typed
/// DID operation to soland.
pub struct SuppliedInceptionInput<'a> {
    pub principal_endpoint: &'a Url,
    pub local_id: &'a str,
    pub also_known_as: &'a [String],
    pub version_time: &'a str,
    pub did_public_key_multibase: &'a str,
    pub update_public_key_multibase: &'a str,
    pub did_key_fragment: Option<&'a str>,
    pub update_key_fragment: Option<&'a str>,
    pub proof: Value,
    pub enrollment_authority_did: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct SubmittedInception {
    pub did: String,
    pub local_id: String,
    pub version_id: String,
    pub submit_body: DidOperationSubmitRequestBody,
    pub did_key_id: String,
    pub update_key_id: String,
    pub did_public_key_multibase: String,
    pub update_public_key_multibase: String,
    pub key_log_head: String,
    pub document_url: String,
    pub log_url: String,
    pub provider_id: String,
    pub did_document: Value,
    pub did_log: Vec<Value>,
}

/// Prepare a `did:webvh` inception entry for soland's embedded provider.
///
/// Generates two fresh ed25519 keypairs (DID key + update key), constructs
/// the inception log entry, derives the SCID + version hash, signs the proof,
/// and returns everything the caller needs to (a) POST to soland and (b)
/// persist the secrets for future rotations.
///
/// The function is deterministic given the RNG and inputs: the same RNG seed
/// + inputs always produce the same DID, which the tests exploit.
pub fn prepare_inception<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &InceptionInput<'_>,
) -> Result<PreparedInception, WebvhInceptionError> {
    let (method_authority, https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;

    let did_key_seed = random_seed(rng);
    let update_key_seed = random_seed(rng);
    let did_signing = SigningKey::from_bytes(&did_key_seed);
    let update_signing = SigningKey::from_bytes(&update_key_seed);
    let did_public_key_multibase =
        encode_ed25519_pubkey_multibase(&did_signing.verifying_key().to_bytes());
    let update_public_key_multibase =
        encode_ed25519_pubkey_multibase(&update_signing.verifying_key().to_bytes());

    let did_key_fragment = normalize_key_fragment(input.did_key_fragment.unwrap_or("did-key-1"))
        .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let update_key_fragment =
        normalize_key_fragment("update-key-1").ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let placeholder_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let version_time = input
        .version_time
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // An empty enrollment authority yields a service-shaped document (no
    // device-enrollment-authority service entry). This mirrors the branch in
    // `prepare_supplied_inception` and is what `prepare_service_inception`
    // relies on to self-mint a service DID.
    let document_skeleton = if input.enrollment_authority_did.is_empty() {
        embedded_webvh_document_value_without_enrollment(
            &placeholder_did,
            &placeholder_key_id,
            &did_public_key_multibase,
            input.also_known_as,
            &service_endpoint,
        )
    } else {
        embedded_webvh_document_value(
            &placeholder_did,
            &placeholder_key_id,
            &did_public_key_multibase,
            input.also_known_as,
            &service_endpoint,
            input.enrollment_authority_did,
        )
    };
    let entry_skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [update_public_key_multibase],
        },
        "state": document_skeleton,
    });

    let scid = sha256_multihash_multibase(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid);
    let version_hash = sha256_multihash_multibase(&canonical_bytes(&strip_for_hash(&log_entry))?);
    let version_id = format!("1-{version_hash}");
    if let Value::Object(map) = &mut log_entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
    }

    let did = format_webvh_did(&method_authority, &scid, &local_id);
    let did_key_id = format!("{did}#{did_key_fragment}");
    let update_key_id = format!("{did}#{update_key_fragment}");
    let proof = build_proof(&log_entry, &update_signing, &update_public_key_multibase)?;
    if let Value::Object(map) = &mut log_entry {
        map.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    verify_webvh_log_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
    let submit_body = did_submit_body(&did, 1, log_entry.clone(), &local_id)?;
    let document_url = identity_document_url(input.principal_endpoint, &did)?;
    let log_url = identity_log_url(input.principal_endpoint, &did)?;

    Ok(PreparedInception {
        did,
        method_authority,
        https_authority,
        local_id,
        version_time,
        version_id,
        log_entry,
        submit_body,
        did_public_key_multibase,
        update_public_key_multibase,
        did_key_id,
        update_key_id,
        document_url,
        log_url,
        did_key_seed,
        update_key_seed,
    })
}

/// Inputs for a service's own `did:webvh` self-mint.
///
/// Unlike [`InceptionInput`], there is no `enrollment_authority_did`: a service
/// DID is the identity of the service itself and carries no device-enrollment
/// authority (that concept applies to principal / user DIDs). The resulting DID
/// document therefore omits the enrollment-authority service entry.
pub struct ServiceInceptionInput<'a> {
    /// The service's own public base endpoint, e.g. `https://auth.example.com/`.
    /// Drives the DID method authority and the in-document `serviceEndpoint`.
    pub principal_endpoint: &'a Url,
    /// Normalised path segment under `/webvh/<local_id>/did.json`. Service DIDs
    /// conventionally use `"service"`, yielding
    /// `did:webvh:<scid>:<authority>:webvh:service`.
    pub local_id: &'a str,
    /// Optional `alsoKnownAs` entries. Usually empty for a service DID.
    pub also_known_as: &'a [String],
    /// `versionTime` for the inception entry (RFC3339-serialised internally).
    pub version_time: DateTime<Utc>,
    /// Optional verification-method fragment; defaults to `did-key-1`.
    pub did_key_fragment: Option<&'a str>,
}

/// Prepare a `did:webvh` inception entry for a service's own service DID.
///
/// The service-identity counterpart to [`prepare_inception`]: it self-generates
/// the DID + update keypairs and constructs a byte-identical inception via the
/// same SCID / version-hash / `eddsa-jcs-2022` proof machinery, but produces a
/// service-shaped DID document with no device-enrollment-authority service
/// entry. Used by a service (e.g. a principal server hosting its own webvh log,
/// or an auth server minting against such a host) to bootstrap its own stable
/// service identity without an external minting round-trip.
pub fn prepare_service_inception<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceInceptionInput<'_>,
) -> Result<PreparedInception, WebvhInceptionError> {
    prepare_inception(
        rng,
        &InceptionInput {
            principal_endpoint: input.principal_endpoint,
            local_id: input.local_id,
            also_known_as: input.also_known_as,
            version_time: input.version_time,
            did_key_fragment: input.did_key_fragment,
            enrollment_authority_did: "",
        },
    )
}

/// Reconstruct a client-authored inception entry, verify the supplied proof,
/// and produce the typed DID operation. The client owns the keys and the
/// signature; this function never sees secret material.
pub fn prepare_supplied_inception(
    input: &SuppliedInceptionInput<'_>,
) -> Result<SubmittedInception, WebvhInceptionError> {
    if !valid_multibase_key(input.did_public_key_multibase) {
        return Err(WebvhInceptionError::InvalidProof(
            "did_public_key_multibase must be a non-empty multibase value".to_owned(),
        ));
    }
    if !valid_multibase_key(input.update_public_key_multibase) {
        return Err(WebvhInceptionError::InvalidProof(
            "update_public_key_multibase must be a non-empty multibase value".to_owned(),
        ));
    }
    if input.did_public_key_multibase == input.update_public_key_multibase {
        return Err(WebvhInceptionError::InvalidProof(
            "did and update keys must be separate".to_owned(),
        ));
    }
    DateTime::parse_from_rfc3339(input.version_time).map_err(|_| {
        WebvhInceptionError::InvalidProof("version_time must be RFC3339".to_owned())
    })?;

    let (method_authority, _https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let did_key_fragment = normalize_key_fragment(input.did_key_fragment.unwrap_or("did-key-1"))
        .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let update_key_fragment =
        normalize_key_fragment(input.update_key_fragment.unwrap_or("update-key-1"))
            .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let placeholder_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let enrollment_authority_did = input.enrollment_authority_did.unwrap_or_default();
    let document_skeleton = if enrollment_authority_did.is_empty() {
        embedded_webvh_document_value_without_enrollment(
            &placeholder_did,
            &placeholder_key_id,
            input.did_public_key_multibase,
            input.also_known_as,
            &service_endpoint,
        )
    } else {
        embedded_webvh_document_value(
            &placeholder_did,
            &placeholder_key_id,
            input.did_public_key_multibase,
            input.also_known_as,
            &service_endpoint,
            enrollment_authority_did,
        )
    };
    let entry_skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": input.version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [input.update_public_key_multibase],
        },
        "state": document_skeleton,
    });
    let scid = sha256_multihash_multibase(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid);
    let version_hash = sha256_multihash_multibase(&canonical_bytes(&strip_for_hash(&log_entry))?);
    let version_id = format!("1-{version_hash}");
    if let Value::Object(map) = &mut log_entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
        map.insert("proof".to_owned(), Value::Array(vec![input.proof.clone()]));
    }
    verify_webvh_log_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;

    let did = format_webvh_did(&method_authority, &scid, &local_id);
    let did_key_id = format!("{did}#{did_key_fragment}");
    let update_key_id = format!("{did}#{update_key_fragment}");
    let submit_body = did_submit_body(&did, 1, log_entry.clone(), &local_id)?;
    let document_url = identity_document_url(input.principal_endpoint, &did)?;
    let log_url = identity_log_url(input.principal_endpoint, &did)?;
    let did_document = log_entry
        .get("state")
        .cloned()
        .unwrap_or_else(|| json!({"id": did.clone()}));

    Ok(SubmittedInception {
        did,
        local_id,
        version_id: version_id.clone(),
        submit_body,
        did_key_id,
        update_key_id,
        did_public_key_multibase: input.did_public_key_multibase.to_owned(),
        update_public_key_multibase: input.update_public_key_multibase.to_owned(),
        key_log_head: version_id,
        document_url,
        log_url,
        provider_id: "soland.protocol".to_owned(),
        did_document,
        did_log: vec![log_entry],
    })
}

fn random_seed<R: RngCore + ?Sized>(rng: &mut R) -> [u8; SECRET_KEY_LENGTH] {
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut seed);
    seed
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, WebvhInceptionError> {
    arkret_core::canonical::canonical_json_bytes(value)
        .map_err(|err| WebvhInceptionError::Canonical(err.to_string()))
}

fn embedded_webvh_document_value_without_enrollment(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    also_known_as: &[String],
    service_endpoint: &str,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did_key_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": did_public_key_multibase,
        }],
        "authentication": [did_key_id],
        "assertionMethod": [did_key_id],
        "alsoKnownAs": also_known_as,
        "service": [
            {
                "id": format!("{did}#soland"),
                "type": "CokretPrincipalServer",
                "serviceEndpoint": service_endpoint,
            }
        ],
    })
}

fn embedded_webvh_document_value(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    also_known_as: &[String],
    service_endpoint: &str,
    enrollment_authority_did: &str,
) -> Value {
    let mut document = embedded_webvh_document_value_without_enrollment(
        did,
        did_key_id,
        did_public_key_multibase,
        also_known_as,
        service_endpoint,
    );
    if let Some(services) = document.get_mut("service").and_then(Value::as_array_mut) {
        services.push(json!({
            "id": format!("{did}#enrollment-authority"),
            "type": arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
            "serviceEndpoint": enrollment_authority_did,
        }));
    }
    document
}

fn did_submit_body(
    did: &str,
    seq: u64,
    operation: Value,
    local_id: &str,
) -> Result<DidOperationSubmitRequestBody, WebvhInceptionError> {
    let typed_did = Did::new(did.to_owned())
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    Ok(DidOperationSubmitRequestBody {
        did: typed_did,
        did_method: "did:webvh".to_owned(),
        seq: Some(seq),
        prev_event_digest: None,
        operation,
        policy_context: json!({
            "provider_id": "soland.protocol",
            "profile": "ak.identity.webvh.provider.v1",
            "local_id": local_id,
        }),
        proofs: Vec::new(),
    })
}

fn identity_document_url(endpoint: &Url, did: &str) -> Result<String, WebvhInceptionError> {
    let mut url = endpoint
        .join("/_cokret/root/identity/document")
        .map_err(WebvhInceptionError::InvalidEndpoint)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url.to_string())
}

fn identity_log_url(endpoint: &Url, did: &str) -> Result<String, WebvhInceptionError> {
    let mut url = endpoint
        .join("/_cokret/root/identity/log")
        .map_err(WebvhInceptionError::InvalidEndpoint)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url.to_string())
}

fn build_proof(
    log_entry: &Value,
    update_signing: &SigningKey,
    update_public_key_multibase: &str,
) -> Result<Value, WebvhInceptionError> {
    let mut payload_entry = log_entry.clone();
    if let Value::Object(map) = &mut payload_entry {
        map.remove("proof");
    }
    let payload = canonical_bytes(&payload_entry)?;
    let signature = update_signing.sign(&payload);
    let proof_value = format!("z{}", encode_base58btc(signature.to_bytes()));
    let verification_method =
        format!("did:key:{update_public_key_multibase}#{update_public_key_multibase}");
    Ok(json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }))
}

/// Local mirror of soland's `verify_webvh_log_proof`. The inception builder runs
/// this against its own output so a build that soland would reject never leaves
/// the process.
fn verify_webvh_log_proof(entry: &Value) -> Result<(), String> {
    let proof = entry
        .get("proof")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or_else(|| "entry must include proof[0]".to_owned())?;
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
        return Err("proof type must be DataIntegrityProof".to_owned());
    }
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
        return Err("proof cryptosuite must be eddsa-jcs-2022".to_owned());
    }
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_key_multibase = verification_method
        .rsplit_once('#')
        .map_or(verification_method, |(_, fragment)| fragment);
    let update_keys = entry
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !update_keys.contains(&public_key_multibase) {
        return Err("proof verificationMethod must reference updateKeys[0]".to_owned());
    }
    let public_key = decode_ed25519_multibase(public_key_multibase)
        .map_err(|error| format!("public key must be base58btc ed25519-pub multibase: {error}"))
        .and_then(|bytes| {
            VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid ed25519 public key".to_owned())
        })?;
    let signature = decode_webvh_signature(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let mut canonical = entry.clone();
    if let Value::Object(map) = &mut canonical {
        map.remove("proof");
    }
    let payload =
        arkret_core::canonical::canonical_json_bytes(&canonical).map_err(|e| e.to_string())?;
    public_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "webvh log proof signature is invalid".to_owned())
}

fn decode_webvh_signature(value: &str) -> Result<Signature, String> {
    let rest = value
        .strip_prefix('z')
        .ok_or_else(|| "proofValue must use base58btc multibase".to_owned())?;
    let raw = decode_base58btc(rest)
        .map_err(|error| format!("proofValue base58 decode failed: {error}"))?;
    if raw.len() != SIGNATURE_LENGTH {
        return Err("ed25519 proofValue must be 64 bytes".to_owned());
    }
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(&raw);
    Ok(Signature::from_bytes(&signature_bytes))
}

fn strip_for_hash(value: &Value) -> Value {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    clone
}

fn substitute_scid(value: &Value, scid: &str) -> Value {
    let Ok(text) = serde_json::to_string(value) else {
        return value.clone();
    };
    serde_json::from_str(&text.replace(WEBVH_SCID_PLACEHOLDER, scid))
        .unwrap_or_else(|_| value.clone())
}

fn sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = arkret_core::canonical::sha256_bytes(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    format!("z{}", encode_base58btc(&multihash))
}

fn encode_ed25519_pubkey_multibase(public_key: &[u8; 32]) -> String {
    let mut envelope = Vec::with_capacity(2 + public_key.len());
    envelope.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    envelope.extend_from_slice(public_key);
    format!("z{}", encode_base58btc(&envelope))
}

fn format_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}")
}

/// Mirror of soland's `embedded_webvh_authority`. Returns (method_authority,
/// https_authority) — the first uses `%3A` for ports (DID-syntax safe), the
/// second uses a literal colon (URL-syntax safe).
fn authority_pair(endpoint: &Url) -> Result<(String, String), WebvhInceptionError> {
    let host = endpoint
        .host_str()
        .ok_or(WebvhInceptionError::EndpointHostInvalid)?;
    if !host.contains('.') {
        return Err(WebvhInceptionError::EndpointHostInvalid);
    }
    let method_authority = match endpoint.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_owned(),
    };
    let https_authority = match endpoint.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok((method_authority, https_authority))
}

fn trimmed_endpoint(endpoint: &Url) -> String {
    endpoint.as_str().trim_end_matches('/').to_owned()
}

/// Mirror of soland's `normalize_webvh_local_id` so the local_id we send is
/// guaranteed accepted on the wire.
fn normalize_local_id(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

fn normalize_key_fragment(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('#').to_owned();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

fn valid_multibase_key(value: &str) -> bool {
    decode_ed25519_multibase(value).is_ok()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, VerifyingKey};
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    /// In-crate copy of soland's `verify_webvh_log_proof`. If soland tightens
    /// its verification rules, this copy must be updated — and the test below
    /// will fail until it is, which is exactly the byte-for-byte guard we want.
    fn verify_proof_like_soland(entry: &Value) -> Result<(), String> {
        let proof = entry
            .get("proof")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_object)
            .ok_or_else(|| "entry must include proof[0]".to_owned())?;
        if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
            return Err("proof type must be DataIntegrityProof".to_owned());
        }
        if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
            return Err("proof cryptosuite must be eddsa-jcs-2022".to_owned());
        }
        let vm = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let public_key_multibase = vm.rsplit_once('#').map_or(vm, |(_, f)| f);
        let update_keys = entry
            .pointer("/parameters/updateKeys")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if !update_keys.contains(&public_key_multibase) {
            return Err("proof verificationMethod must reference updateKeys[0]".to_owned());
        }
        let public_key = decode_pubkey(public_key_multibase)?;
        let signature = decode_signature(
            proof
                .get("proofValue")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        let mut canonical = entry.clone();
        if let Value::Object(map) = &mut canonical {
            map.remove("proof");
        }
        let payload =
            arkret_core::canonical::canonical_json_bytes(&canonical).map_err(|e| e.to_string())?;
        public_key
            .verify_strict(&payload, &signature)
            .map_err(|_| "signature invalid".to_owned())
    }

    fn decode_pubkey(value: &str) -> Result<VerifyingKey, String> {
        let rest = value.strip_prefix('z').ok_or("missing z prefix")?;
        let raw = decode_base58btc(rest).map_err(|_| "base58 decode failed")?;
        let bytes = raw
            .strip_prefix(&ED25519_MULTICODEC_PREFIX)
            .ok_or("missing ed25519 multicodec")?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err("public key must be 32 bytes".to_owned());
        }
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(bytes);
        VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
    }

    fn decode_signature(value: &str) -> Result<Signature, String> {
        let rest = value.strip_prefix('z').ok_or("missing z prefix")?;
        let raw = decode_base58btc(rest).map_err(|_| "base58 decode failed")?;
        if raw.len() != SIGNATURE_LENGTH {
            return Err("signature must be 64 bytes".to_owned());
        }
        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(&raw);
        Ok(Signature::from_bytes(&arr))
    }

    fn run_prepare(seed: u64) -> PreparedInception {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let input = InceptionInput {
            principal_endpoint: &endpoint,
            local_id: "01krmccd3cehqbtvzg383m3maf",
            also_known_as: &["acct:user@local.host".to_owned()],
            version_time: DateTime::parse_from_rfc3339("2026-05-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            did_key_fragment: None,
            enrollment_authority_did: "did:key:z6MkEnrollmentAuthorityTestKey00000000000000",
        };
        prepare_inception(&mut rng, &input).expect("prepare ok")
    }

    #[test]
    fn did_format_matches_soland_authority() {
        let prepared = run_prepare(1);
        assert!(
            prepared.did.starts_with("did:webvh:")
                && prepared.did.contains(":local.host%3A8080:webvh:")
                && prepared.did.ends_with(":01krmccd3cehqbtvzg383m3maf"),
            "unexpected DID: {}",
            prepared.did
        );
        assert_eq!(prepared.method_authority, "local.host%3A8080");
        assert_eq!(prepared.https_authority, "local.host:8080");
        assert_eq!(prepared.local_id, "01krmccd3cehqbtvzg383m3maf");
        assert!(prepared.version_id.starts_with("1-z"));
    }

    #[test]
    fn proof_passes_soland_verification() {
        let prepared = run_prepare(42);
        verify_proof_like_soland(&prepared.log_entry).expect("soland-shape verify");
    }

    #[test]
    fn proof_payload_excludes_proof_but_keeps_version_id() {
        // soland's verify removes only `proof` from the entry before hashing.
        // A common bug would be to also remove `versionId`; this test pins the
        // correct behaviour by tampering with versionId after signing and
        // confirming the proof no longer verifies.
        let mut prepared = run_prepare(7);
        if let Value::Object(map) = &mut prepared.log_entry {
            map.insert(
                "versionId".to_owned(),
                Value::String("1-zTAMPERED".to_owned()),
            );
        }
        let err = verify_proof_like_soland(&prepared.log_entry).expect_err("must fail");
        assert!(err.contains("signature"), "got: {err}");
    }

    #[test]
    fn submit_body_matches_cokret_protocol() {
        let prepared = run_prepare(3);
        let body = &prepared.submit_body;
        assert_eq!(body.did.as_str(), prepared.did.as_str());
        assert_eq!(body.did_method, "did:webvh");
        assert_eq!(body.seq, Some(1));
        assert!(body.prev_event_digest.is_none());
        assert!(body.proofs.is_empty());
        assert_eq!(
            body.policy_context["local_id"].as_str(),
            Some(prepared.local_id.as_str())
        );
        assert_eq!(
            body.operation["state"]["verificationMethod"][0]["publicKeyMultibase"].as_str(),
            Some(prepared.did_public_key_multibase.as_str()),
        );
        assert_eq!(
            body.operation["parameters"]["updateKeys"][0].as_str(),
            Some(prepared.update_public_key_multibase.as_str()),
        );
        assert_ne!(
            body.operation["state"]["verificationMethod"][0]["publicKeyMultibase"],
            body.operation["parameters"]["updateKeys"][0],
            "did key and update key must differ",
        );
        assert_eq!(
            body.operation["versionTime"].as_str(),
            Some(prepared.version_time.as_str())
        );
        let proof = &body.operation["proof"][0];
        assert!(proof.is_object());
        assert_eq!(proof["cryptosuite"].as_str(), Some("eddsa-jcs-2022"));
    }

    #[test]
    fn supplied_inception_reconstructs_submit_body() {
        let prepared = run_prepare(31);
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let proof = prepared.log_entry["proof"][0].clone();
        let also_known_as = ["acct:user@local.host".to_owned()];
        let supplied = prepare_supplied_inception(&SuppliedInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &prepared.local_id,
            also_known_as: &also_known_as,
            version_time: &prepared.version_time,
            did_public_key_multibase: &prepared.did_public_key_multibase,
            update_public_key_multibase: &prepared.update_public_key_multibase,
            did_key_fragment: Some("did-key-1"),
            update_key_fragment: Some("update-key-1"),
            proof,
            enrollment_authority_did: Some("did:key:z6MkEnrollmentAuthorityTestKey00000000000000"),
        })
        .expect("supplied inception ok");

        assert_eq!(supplied.did, prepared.did);
        assert_eq!(supplied.key_log_head, prepared.version_id);
        assert_eq!(
            supplied.submit_body.operation,
            prepared.submit_body.operation
        );
        assert_eq!(supplied.submit_body.did.as_str(), prepared.did.as_str());
        verify_webvh_log_proof(&supplied.did_log[0]).expect("proof still verifies");
    }

    #[test]
    fn document_carries_enrollment_authority_service() {
        let prepared = run_prepare(11);
        let services = prepared
            .log_entry
            .pointer("/state/service")
            .and_then(Value::as_array)
            .expect("state.service array");
        let entry = services
            .iter()
            .find(|svc| {
                svc.get("type").and_then(Value::as_str)
                    == Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
            })
            .expect("enrollment-authority service entry present");
        assert_eq!(
            entry.get("serviceEndpoint").and_then(Value::as_str),
            Some("did:key:z6MkEnrollmentAuthorityTestKey00000000000000"),
        );
        let id = entry.get("id").and_then(Value::as_str).unwrap_or_default();
        assert!(
            id.ends_with("#enrollment-authority"),
            "service id must use the #enrollment-authority fragment, got {id}"
        );
        // The signed proof MUST still verify with the extra service entry in
        // the canonical document.
        verify_proof_like_soland(&prepared.log_entry).expect("soland-shape verify with service");
    }

    #[test]
    fn rejects_endpoint_without_dot() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let endpoint = Url::parse("http://localhost:8080/").unwrap();
        let input = InceptionInput {
            principal_endpoint: &endpoint,
            local_id: "abc",
            also_known_as: &[],
            version_time: Utc::now(),
            did_key_fragment: None,
            enrollment_authority_did: "did:key:z6MkEnrollmentAuthorityTestKey00000000000000",
        };
        let err = prepare_inception(&mut rng, &input).unwrap_err();
        assert!(matches!(err, WebvhInceptionError::EndpointHostInvalid));
    }

    #[test]
    fn rejects_invalid_local_id() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let input = InceptionInput {
            principal_endpoint: &endpoint,
            local_id: "../etc/passwd",
            also_known_as: &[],
            version_time: Utc::now(),
            did_key_fragment: None,
            enrollment_authority_did: "did:key:z6MkEnrollmentAuthorityTestKey00000000000000",
        };
        let err = prepare_inception(&mut rng, &input).unwrap_err();
        assert!(matches!(err, WebvhInceptionError::InvalidLocalId));
    }

    #[test]
    fn determinism_under_fixed_rng() {
        let a = run_prepare(123);
        let b = run_prepare(123);
        assert_eq!(a.did, b.did);
        assert_eq!(a.version_id, b.version_id);
        assert_eq!(a.update_key_seed, b.update_key_seed);
    }

    #[test]
    fn no_default_port_in_authority() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let endpoint = Url::parse("https://local.host/").unwrap();
        let input = InceptionInput {
            principal_endpoint: &endpoint,
            local_id: "abc",
            also_known_as: &[],
            version_time: Utc::now(),
            did_key_fragment: None,
            enrollment_authority_did: "did:key:z6MkEnrollmentAuthorityTestKey00000000000000",
        };
        let prepared = prepare_inception(&mut rng, &input).unwrap();
        assert_eq!(prepared.method_authority, "local.host");
        assert!(prepared.did.contains(":local.host:webvh:"));
    }

    fn run_prepare_service(seed: u64) -> PreparedInception {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let endpoint = Url::parse("https://auth.example.com/").unwrap();
        let input = ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: DateTime::parse_from_rfc3339("2026-07-05T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            did_key_fragment: None,
        };
        prepare_service_inception(&mut rng, &input).expect("service prepare ok")
    }

    #[test]
    fn service_inception_has_service_did_shape() {
        let prepared = run_prepare_service(5);
        assert!(prepared.did.starts_with("did:webvh:"), "{}", prepared.did);
        assert!(
            prepared.did.contains(":auth.example.com:webvh:") && prepared.did.ends_with(":service"),
            "unexpected service DID: {}",
            prepared.did
        );
        assert_eq!(prepared.local_id, "service");
        verify_proof_like_soland(&prepared.log_entry).expect("service inception proof verifies");
    }

    #[test]
    fn service_inception_omits_enrollment_authority() {
        let prepared = run_prepare_service(9);
        let services = prepared
            .log_entry
            .pointer("/state/service")
            .and_then(Value::as_array)
            .expect("state.service array");
        assert!(
            services.iter().all(|svc| {
                svc.get("type").and_then(Value::as_str)
                    != Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
            }),
            "service DID document must not carry a device-enrollment-authority entry",
        );
        assert!(
            services.iter().any(|svc| {
                svc.get("type").and_then(Value::as_str) == Some("CokretPrincipalServer")
            }),
            "service DID document should keep the CokretPrincipalServer entry",
        );
    }

    #[test]
    fn service_inception_determinism_under_fixed_rng() {
        let a = run_prepare_service(77);
        let b = run_prepare_service(77);
        assert_eq!(a.did, b.did);
        assert_eq!(a.version_id, b.version_id);
        assert_eq!(a.update_key_seed, b.update_key_seed);
    }
}
