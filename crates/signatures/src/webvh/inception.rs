//! Embedded `did:webvh` inception builder, shared by clients and servers.
//!
//! Soland accepts WebVH inception as a protocol DID operation at
//! `/_arkret/root/identity/submit-did-operation`. Soland's embedded WebVH
//! profile requires the client to:
//!
//! 1. derive the cold root keypair and its next-generation pre-rotation commitment,
//! 2. construct the inception webvh log entry with `{SCID}` placeholders (`versionId` is the bare
//!    `{SCID}` placeholder, per DIF did:webvh v1.0),
//! 3. derive the SCID (base58btc sha256-multihash — no multibase prefix — of the canonical-JCS
//!    skeleton),
//! 4. substitute the SCID and compute `versionId = 1-<entryHash>`, where the entryHash preimage
//!    carries `versionId = <SCID>` (the predecessor anchor) and no `proof`,
//! 5. sign the entry (sans `proof`) under `cryptosuite: eddsa-jcs-2022` with the update key —
//!    soland verifies that signature in `verify_webvh_log_proof`.
//!
//! Principal builders borrow cold root material and never return it. Service
//! builders retain their separate assertion/update key result because a
//! service owns and durably operates both keys.
//!
//! The algorithm intentionally mirrors soland's helpers byte-for-byte:
//! `sha256_multihash_base58btc`, `strip_webvh_entry_for_hash`,
//! `substitute_webvh_scid`, and the eddsa-jcs-2022 proof shape are all
//! re-implemented here, and the test module includes an in-crate copy of
//! soland's `verify_webvh_log_proof` so any divergence trips CI.
//!
//! HTTP transport (POSTing the prepared operation to soland) deliberately lives
//! outside this crate: this module is pure build + cryptography so clients
//! (sodmin / inkson) and servers (soland / coauth) can all share one
//! implementation with no drift.

use std::collections::{BTreeMap, BTreeSet};

use arkret_core::{
    CanonicalServiceUrl, Did, DidOperationSubmitRequestBody, Hash, IdentityCreationControlProof,
    ServiceRegistrationKey, ServiceType, ServiceWebvhInceptionOperation, base64url_encode,
    decode_ed25519_multibase, service_registration_local_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use rand_core::RngCore;
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
#[cfg(test)]
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
    #[error("service registration input is invalid: {0}")]
    InvalidRegistration(String),
}

/// Prepared service inception. Principal inception uses
/// [`PreparedPrincipalInception`] and never exposes a DID-document assertion
/// key or returns cold root material.
///
/// The two `*_seed` fields are DID root key material: `Debug` renders them
/// redacted (mirroring `arkret_crypto::VaultKek`) and both are zeroized on
/// drop so they never leak into logs, backtraces or freed memory.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct PreparedInception {
    /// The minted DID, e.g.
    /// `did:webvh:Qm...:local.host%3A8080:webvh:01krmccd...`.
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
    /// Typed request body for `ak.root.identity.command.submit_did_operation`.
    #[zeroize(skip)]
    pub submit_body: DidOperationSubmitRequestBody,
    /// Multibase ed25519 **public** key for the DID's verification method.
    #[zeroize(skip)]
    pub did_public_key_multibase: String,
    /// Multibase ed25519 **public** key for `updateKeys[0]`.
    #[zeroize(skip)]
    pub update_public_key_multibase: String,
    /// Multibase ed25519 public key committed by `nextKeyHashes[0]`.
    #[zeroize(skip)]
    pub next_update_public_key_multibase: String,
    /// Bare multihash commitment to `next_update_public_key_multibase`.
    #[zeroize(skip)]
    pub next_update_key_hash: String,
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
    /// 32-byte ed25519 secret seed for the precommitted next update key.
    pub next_update_key_seed: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct PreparedPrincipalInception {
    pub did: String,
    pub method_authority: String,
    pub https_authority: String,
    pub local_id: String,
    pub version_time: String,
    pub version_id: String,
    pub log_entry: Value,
    pub submit_body: DidOperationSubmitRequestBody,
    pub root_public_key_multibase: String,
    pub root_verification_method: String,
    pub next_root_public_key_multibase: String,
    pub next_root_key_hash: String,
    pub document_url: String,
    pub log_url: String,
}

/// Public facts extracted from a fully validated principal inception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPrincipalInception {
    /// Principal DID declared by the operation wrapper and DID document.
    pub principal_id: Did,
    /// Canonical digest of the complete typed submit request.
    pub operation_digest: Hash,
    /// The method-native identity root selected from `parameters.updateKeys[0]`.
    pub root_public_key_multibase: String,
    /// DID-document profile selected by the inception state.
    pub document_profile: PrincipalDidDocumentProfile,
    /// External enrollment authority for the B model, when present.
    pub enrollment_authority: Option<Did>,
}

/// Validate a complete, signed `did:webvh` entry-0 operation before it is
/// reserved by an Account Authority.
///
/// This validates the wrapper, entry sequence, SCID and entry hash, the
/// method-native `eddsa-jcs-2022` controller proof, the principal document
/// profile, and root-key separation. It never resolves an already-published
/// DID and never selects authority from a DID Document verification method.
pub fn validate_principal_inception_operation(
    request: &DidOperationSubmitRequestBody,
) -> Result<ValidatedPrincipalInception, WebvhInceptionError> {
    request
        .validate()
        .map_err(|error| WebvhInceptionError::InvalidProof(error.to_string()))?;
    if request.did_method != "webvh"
        || request.seq != Some(1)
        || request.prev_event_digest.is_some()
    {
        return Err(WebvhInceptionError::InvalidProof(
            "identity creation requires a did:webvh entry-0 operation with seq=1 and no predecessor"
                .to_owned(),
        ));
    }

    let entry = Value::Object(request.operation.clone().into_iter().collect());
    if entry.pointer("/parameters/method").and_then(Value::as_str) != Some(WEBVH_METHOD_VERSION) {
        return Err(WebvhInceptionError::InvalidProof(
            "identity creation requires did:webvh:1.0 parameters".to_owned(),
        ));
    }
    let update_keys = entry
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 1)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal inception must declare exactly one updateKeys root".to_owned(),
            )
        })?;
    let root_public_key_multibase = update_keys[0].as_str().ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "principal inception updateKeys[0] must be a string".to_owned(),
        )
    })?;
    if !valid_multibase_key(root_public_key_multibase) {
        return Err(WebvhInceptionError::InvalidProof(
            "principal inception updateKeys[0] must be an Ed25519 multikey".to_owned(),
        ));
    }

    let claimed_scid = entry
        .pointer("/parameters/scid")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal inception must declare parameters.scid".to_owned(),
            )
        })?;
    let did_scid = request.did.as_str().split(':').nth(2).unwrap_or_default();
    if claimed_scid != did_scid {
        return Err(WebvhInceptionError::InvalidProof(
            "principal inception SCID does not match the wrapper DID".to_owned(),
        ));
    }
    let skeleton = scid_skeleton_from_genesis(&entry, claimed_scid)?;
    let derived_scid = sha256_multihash_base58btc(&canonical_bytes(&skeleton)?);
    if derived_scid != claimed_scid {
        return Err(WebvhInceptionError::InvalidProof(
            "principal inception SCID does not match its canonical skeleton".to_owned(),
        ));
    }
    let expected_version_id = format!(
        "1-{}",
        sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(&entry, claimed_scid))?)
    );
    if entry.get("versionId").and_then(Value::as_str) != Some(expected_version_id.as_str()) {
        return Err(WebvhInceptionError::InvalidProof(
            "principal inception versionId does not match its canonical entry hash".to_owned(),
        ));
    }
    verify_webvh_log_proof(&entry).map_err(WebvhInceptionError::InvalidProof)?;

    let state = entry.get("state").ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "principal inception must contain a DID document state".to_owned(),
        )
    })?;
    let document_profile = validate_principal_did_document_profile(
        request.did.as_str(),
        state,
        &[root_public_key_multibase],
    )?;
    let enrollment_authority = if document_profile == PrincipalDidDocumentProfile::ExternalAuthority
    {
        state
            .get("service")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|service| {
                service.get("type").and_then(Value::as_str)
                    == Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
            })
            .and_then(|service| service.get("serviceEndpoint"))
            .and_then(Value::as_str)
            .map(|did| Did::new(did.to_owned()))
            .transpose()
            .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?
    } else {
        None
    };
    let operation_digest = Hash::new(
        arkret_core::canonical::canonical_sha256(request)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;

    Ok(ValidatedPrincipalInception {
        principal_id: request.did.clone(),
        operation_digest,
        root_public_key_multibase: root_public_key_multibase.to_owned(),
        document_profile,
        enrollment_authority,
    })
}

/// Verify the account-binding control proof with the inception operation's
/// method-native identity root.
pub fn verify_identity_creation_control_proof(
    request: &DidOperationSubmitRequestBody,
    proof: &IdentityCreationControlProof,
) -> Result<ValidatedPrincipalInception, WebvhInceptionError> {
    let validated = validate_principal_inception_operation(request)?;
    if proof.principal_id != validated.principal_id
        || proof.operation_digest != validated.operation_digest
        || proof.verification_key_multibase != validated.root_public_key_multibase
    {
        return Err(WebvhInceptionError::InvalidProof(
            "identity-creation proof does not match the reserved inception root or operation"
                .to_owned(),
        ));
    }
    let signing_bytes = proof
        .canonical_signing_bytes()
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let public_key = crate::proof::PublicKeyMaterial::Ed25519Multibase {
        value: validated.root_public_key_multibase.clone(),
    };
    if !crate::proof::verify_detached_ed25519_signature(
        &public_key,
        &signing_bytes,
        &proof.signature,
    ) {
        return Err(WebvhInceptionError::InvalidProof(
            "identity-creation control signature is invalid".to_owned(),
        ));
    }
    Ok(validated)
}

/// Sign an identity-creation control transcript with a borrowed cold root.
/// The caller remains responsible for zeroizing and never persisting the seed.
pub fn sign_identity_creation_control_proof(
    proof: &mut IdentityCreationControlProof,
    root_seed: &[u8; SECRET_KEY_LENGTH],
) -> Result<(), WebvhInceptionError> {
    let signing_bytes = proof
        .canonical_signing_bytes()
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let signature = SigningKey::from_bytes(root_seed).sign(&signing_bytes);
    proof.signature = base64url_encode(signature.to_bytes());
    Ok(())
}

/// Inputs for one canonical principal root rotation. `previous_entries` must
/// be the complete, ordered log through the current head so the builder can
/// enforce the permanent no-reuse rule across every activated root.
pub struct PrincipalRotationInput<'a> {
    pub did: &'a str,
    pub local_id: &'a str,
    pub previous_entries: &'a [Value],
    pub version_time: DateTime<Utc>,
    pub current_root_seed: &'a [u8; SECRET_KEY_LENGTH],
    pub next_root_public_key_multibase: &'a str,
    pub state: &'a Value,
}

/// Canonical principal WebVH rotation operation ready for protocol submit.
/// No root secret is returned or retained.
#[derive(Clone, Debug)]
pub struct PreparedPrincipalRotation {
    pub did: String,
    pub local_id: String,
    pub version_time: String,
    pub previous_version_id: String,
    pub version_id: String,
    pub log_entry: Value,
    pub submit_body: DidOperationSubmitRequestBody,
    pub current_root_public_key_multibase: String,
    pub current_root_verification_method: String,
    pub next_root_public_key_multibase: String,
    pub next_root_key_hash: String,
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
            .field(
                "next_update_public_key_multibase",
                &self.next_update_public_key_multibase,
            )
            .field("next_update_key_hash", &self.next_update_key_hash)
            .field("did_key_id", &self.did_key_id)
            .field("update_key_id", &self.update_key_id)
            .field("document_url", &self.document_url)
            .field("log_url", &self.log_url)
            .field("did_key_seed", &"<redacted>")
            .field("update_key_seed", &"<redacted>")
            .field("next_update_key_seed", &"<redacted>")
            .finish()
    }
}

impl PreparedInception {
    /// Convert the prepared log entry into the closed service-registration
    /// wire type. This is the only supported bridge from the WebVH builder's
    /// internal JSON construction to the Provider contract.
    pub fn service_registration_operation(
        &self,
    ) -> Result<ServiceWebvhInceptionOperation, WebvhInceptionError> {
        serde_json::from_value(self.log_entry.clone()).map_err(|error| {
            WebvhInceptionError::InvalidRegistration(format!(
                "prepared WebVH entry does not match the service-registration schema: {error}"
            ))
        })
    }
}

pub enum PrincipalEnrollmentDelegation<'a> {
    ExternalAuthority {
        authority_did: &'a str,
    },
    SelfAuthority {
        principal_signing_public_key_multibase: &'a str,
        enrollment_public_key_multibase: &'a str,
        principal_signing_fragment: Option<&'a str>,
        enrollment_fragment: Option<&'a str>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalDidDocumentProfile {
    ExternalAuthority,
    SelfAuthority,
}

/// Inputs to a client-authored principal inception. The caller must derive
/// `root_seed` and `next_root_public_key_multibase` from the same confirmed
/// recovery secret before publishing the result.
pub struct PrincipalInceptionInput<'a> {
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
    pub root_seed: &'a [u8; SECRET_KEY_LENGTH],
    pub next_root_public_key_multibase: &'a str,
    pub enrollment: PrincipalEnrollmentDelegation<'a>,
}

/// Inputs for a client-authored WebVH inception. The client supplies the DID
/// and update public keys plus the signed log proof; the server reconstructs
/// the exact inception entry, verifies the proof locally, and submits the typed
/// DID operation to soland.
pub struct SuppliedPrincipalInceptionInput<'a> {
    pub principal_endpoint: &'a Url,
    pub local_id: &'a str,
    pub also_known_as: &'a [String],
    pub version_time: &'a str,
    pub root_public_key_multibase: &'a str,
    pub next_root_public_key_multibase: &'a str,
    pub proof: Value,
    pub enrollment: PrincipalEnrollmentDelegation<'a>,
}

#[derive(Debug, Clone)]
pub struct SubmittedInception {
    pub did: String,
    pub local_id: String,
    pub version_id: String,
    pub submit_body: DidOperationSubmitRequestBody,
    pub root_verification_method: String,
    pub root_public_key_multibase: String,
    pub next_root_public_key_multibase: String,
    pub next_root_key_hash: String,
    pub key_log_head: String,
    pub document_url: String,
    pub log_url: String,
    pub provider_id: String,
    pub did_document: Value,
    pub did_log: Vec<Value>,
}

/// Prepare a principal `did:webvh` inception entry using a borrowed cold root
/// seed and a caller-supplied next-generation public commitment.
pub fn prepare_principal_inception(
    input: &PrincipalInceptionInput<'_>,
) -> Result<PreparedPrincipalInception, WebvhInceptionError> {
    let (method_authority, https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let root_signing = SigningKey::from_bytes(input.root_seed);
    let root_public_key_multibase =
        encode_ed25519_pubkey_multibase(&root_signing.verifying_key().to_bytes());
    validate_principal_key_separation(
        &root_public_key_multibase,
        input.next_root_public_key_multibase,
        &input.enrollment,
    )?;
    let next_root_key_hash = webvh_next_key_hash(input.next_root_public_key_multibase)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let version_time = input
        .version_time
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let document_skeleton = principal_document_value(
        &placeholder_did,
        input.also_known_as,
        &service_endpoint,
        &input.enrollment,
    )?;
    validate_principal_did_document_profile(
        &placeholder_did,
        &document_skeleton,
        &[
            root_public_key_multibase.as_str(),
            input.next_root_public_key_multibase,
        ],
    )?;
    let entry_skeleton = json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [root_public_key_multibase],
            "nextKeyHashes": [next_root_key_hash],
        },
        "state": document_skeleton,
    });

    let scid = sha256_multihash_base58btc(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid);
    let version_hash =
        sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(&log_entry, &scid))?);
    let version_id = format!("1-{version_hash}");
    if let Value::Object(map) = &mut log_entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
    }

    let did = format_webvh_did(&method_authority, &scid, &local_id);
    let root_verification_method = did_key_verification_method(&root_public_key_multibase);
    let proof = build_proof(&log_entry, &root_signing, &root_public_key_multibase)?;
    if let Value::Object(map) = &mut log_entry {
        map.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    verify_webvh_log_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
    let submit_body = did_submit_body(&did, 1, None, log_entry.clone())?;
    let document_url = identity_document_url(input.principal_endpoint, &did)?;
    let log_url = identity_log_url(input.principal_endpoint, &did)?;

    Ok(PreparedPrincipalInception {
        did,
        method_authority,
        https_authority,
        local_id,
        version_time,
        version_id,
        log_entry,
        submit_body,
        root_public_key_multibase,
        root_verification_method,
        next_root_public_key_multibase: input.next_root_public_key_multibase.to_owned(),
        next_root_key_hash,
        document_url,
        log_url,
    })
}

fn validate_principal_rotation_history<'a>(
    did: &str,
    entries: &'a [Value],
) -> Result<(&'a Value, BTreeSet<String>), WebvhInceptionError> {
    if entries.is_empty() {
        return Err(WebvhInceptionError::InvalidProof(
            "principal rotation requires the complete non-empty preceding log".to_owned(),
        ));
    }
    let scid = did.split(':').nth(2).ok_or_else(|| {
        WebvhInceptionError::InvalidDid("did:webvh is missing its SCID".to_owned())
    })?;
    let mut activated_roots = BTreeSet::new();
    let mut previous_version_id: Option<&str> = None;
    let mut previous_next_hash: Option<String> = None;

    for (index, entry) in entries.iter().enumerate() {
        let sequence = index + 1;
        let version_id = entry
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} is missing versionId"
                ))
            })?;
        if !version_id.starts_with(&format!("{sequence}-")) {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} has a non-contiguous versionId"
            )));
        }
        if entry.pointer("/state/id").and_then(Value::as_str) != Some(did) {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} state id does not match DID"
            )));
        }
        let parameters = entry
            .get("parameters")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} is missing parameters"
                ))
            })?;
        if parameters.get("method").and_then(Value::as_str) != Some(WEBVH_METHOD_VERSION)
            || parameters.get("scid").and_then(Value::as_str) != Some(scid)
        {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} method or SCID does not match DID"
            )));
        }
        let update_keys = parameters
            .get("updateKeys")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} is missing updateKeys"
                ))
            })?;
        if update_keys.len() != 1 {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} must contain exactly one update key"
            )));
        }
        let update_key = update_keys[0].as_str().ok_or_else(|| {
            WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} update key is not a string"
            ))
        })?;
        decode_ed25519_multibase(update_key).map_err(|error| {
            WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} update key is invalid: {error}"
            ))
        })?;
        if !activated_roots.insert(update_key.to_owned()) {
            return Err(WebvhInceptionError::InvalidProof(
                "principal history reuses an activated root".to_owned(),
            ));
        }
        if let Some(expected_commitment) = previous_next_hash.as_deref() {
            let actual_commitment = webvh_next_key_hash(update_key)?;
            if expected_commitment != actual_commitment {
                return Err(WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} root was not precommitted by its predecessor"
                )));
            }
        }

        let next_hashes = parameters
            .get("nextKeyHashes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} is missing nextKeyHashes"
                ))
            })?;
        if next_hashes.len() != 1 {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} must contain exactly one next root commitment"
            )));
        }
        previous_next_hash = Some(
            next_hashes[0]
                .as_str()
                .ok_or_else(|| {
                    WebvhInceptionError::InvalidProof(format!(
                        "principal history entry {sequence} next root commitment is not a string"
                    ))
                })?
                .to_owned(),
        );

        let hash_anchor = previous_version_id.unwrap_or(scid);
        let expected_hash =
            sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(entry, hash_anchor))?);
        if version_id != format!("{sequence}-{expected_hash}") {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} versionId hash is invalid"
            )));
        }
        verify_webvh_log_proof(entry).map_err(WebvhInceptionError::InvalidProof)?;
        previous_version_id = Some(version_id);
    }

    Ok((
        entries.last().expect("history is non-empty"),
        activated_roots,
    ))
}

/// Build one principal rotation after validating the complete preceding log.
/// The builder refuses both an uncommitted current root and any next root that
/// appeared in an earlier `updateKeys` generation.
pub fn prepare_principal_rotation(
    input: &PrincipalRotationInput<'_>,
) -> Result<PreparedPrincipalRotation, WebvhInceptionError> {
    let did = Did::new(input.did.to_owned())
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    if did.method() != "webvh" {
        return Err(WebvhInceptionError::InvalidDid(
            "principal rotation requires did:webvh".to_owned(),
        ));
    }
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    if !input.did.ends_with(&format!(":{local_id}")) {
        return Err(WebvhInceptionError::InvalidDid(
            "local_id does not match the principal DID".to_owned(),
        ));
    }
    let (previous_entry, activated_roots) =
        validate_principal_rotation_history(input.did, input.previous_entries)?;
    let previous_version_id = previous_entry
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous principal entry is missing versionId".to_owned(),
            )
        })?;
    let (previous_sequence, _) = previous_version_id.split_once('-').ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "previous principal entry has malformed versionId".to_owned(),
        )
    })?;
    let sequence = previous_sequence
        .parse::<u64>()
        .ok()
        .filter(|value| {
            *value > 0 && !(previous_sequence.len() > 1 && previous_sequence.starts_with('0'))
        })
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous principal entry sequence cannot advance".to_owned(),
            )
        })?;
    let parameters = previous_entry
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous principal entry is missing parameters".to_owned(),
            )
        })?;
    if parameters.get("method").and_then(Value::as_str) != Some(WEBVH_METHOD_VERSION) {
        return Err(WebvhInceptionError::InvalidProof(
            "previous principal entry has unsupported method".to_owned(),
        ));
    }
    let scid = parameters
        .get("scid")
        .and_then(Value::as_str)
        .filter(|value| input.did.split(':').nth(2) == Some(*value))
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous principal entry SCID does not match DID".to_owned(),
            )
        })?;
    let current_signing = SigningKey::from_bytes(input.current_root_seed);
    let current_root_public_key_multibase =
        encode_ed25519_pubkey_multibase(&current_signing.verifying_key().to_bytes());
    if current_root_public_key_multibase == input.next_root_public_key_multibase {
        return Err(WebvhInceptionError::InvalidProof(
            "current and next root keys must be distinct".to_owned(),
        ));
    }
    if activated_roots.contains(input.next_root_public_key_multibase) {
        return Err(WebvhInceptionError::InvalidProof(
            "next principal root was already activated and cannot be reused".to_owned(),
        ));
    }
    let current_commitment = webvh_next_key_hash(&current_root_public_key_multibase)?;
    let previous_next_hashes = parameters
        .get("nextKeyHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous principal entry is missing nextKeyHashes".to_owned(),
            )
        })?;
    if previous_next_hashes.len() != 1
        || previous_next_hashes[0].as_str() != Some(current_commitment.as_str())
    {
        return Err(WebvhInceptionError::InvalidProof(
            "current root was not uniquely precommitted by the previous entry".to_owned(),
        ));
    }
    let next_root_key_hash = webvh_next_key_hash(input.next_root_public_key_multibase)?;
    validate_principal_did_document_profile(
        input.did,
        input.state,
        &[
            current_root_public_key_multibase.as_str(),
            input.next_root_public_key_multibase,
        ],
    )?;

    let version_time = input
        .version_time
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut log_entry = json!({
        "versionId": previous_version_id,
        "versionTime": version_time,
        "parameters": {
            "scid": scid,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [current_root_public_key_multibase],
            "nextKeyHashes": [next_root_key_hash],
        },
        "state": input.state,
    });
    let version_hash = sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(
        &log_entry,
        previous_version_id,
    ))?);
    let version_id = format!("{sequence}-{version_hash}");
    if let Value::Object(properties) = &mut log_entry {
        properties.insert("versionId".to_owned(), Value::String(version_id.clone()));
    }
    let current_root_verification_method =
        did_key_verification_method(&current_root_public_key_multibase);
    let proof = build_proof(
        &log_entry,
        &current_signing,
        &current_root_public_key_multibase,
    )?;
    if let Value::Object(properties) = &mut log_entry {
        properties.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    verify_webvh_log_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
    let previous_event_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(previous_entry)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let submit_body = did_submit_body(
        input.did,
        sequence,
        Some(previous_event_digest),
        log_entry.clone(),
    )?;

    Ok(PreparedPrincipalRotation {
        did: did.to_string(),
        local_id,
        version_time,
        previous_version_id: previous_version_id.to_owned(),
        version_id,
        log_entry,
        submit_body,
        current_root_public_key_multibase,
        current_root_verification_method,
        next_root_public_key_multibase: input.next_root_public_key_multibase.to_owned(),
        next_root_key_hash,
    })
}

/// Inputs for a service's own `did:webvh` self-mint.
///
/// A service DID is the identity of the service itself and carries no
/// device-enrollment authority. The resulting DID document therefore omits the
/// enrollment-authority service entry.
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

/// Inputs for a service DID hosted by a Service Identity Provider.
///
/// `provider_endpoint` determines the did:webvh method authority and read
/// URLs. The signed DID document endpoint and role come exclusively from
/// `registration_key`, so a Provider cannot rewrite them.
pub struct ServiceRegistrationInceptionInput<'a> {
    pub provider_endpoint: &'a Url,
    pub registration_key: &'a ServiceRegistrationKey,
    pub also_known_as: &'a [String],
    pub version_time: DateTime<Utc>,
    pub did_key_fragment: Option<&'a str>,
}

/// Prepare a `did:webvh` inception entry for a service's own service DID.
///
/// The service-identity counterpart to [`prepare_principal_inception`]: it self-generates
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
    prepare_service_inception_internal(rng, input, None)
}

/// Prepare a service WebVH inception whose DID assertion key is supplied by
/// the service's durable signing-key custody layer.
///
/// This is the correct primitive when the same service identity signs Arkret
/// credentials or notary Seals: the resulting DID document publishes the
/// public half of `did_key_seed`, while the WebVH update key remains freshly
/// generated from `rng`. The secret seed is copied into the returned
/// [`PreparedInception`] so its existing zeroization guarantees still apply.
pub fn prepare_service_inception_with_did_key_seed<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceInceptionInput<'_>,
    did_key_seed: &[u8; SECRET_KEY_LENGTH],
) -> Result<PreparedInception, WebvhInceptionError> {
    prepare_service_inception_internal(rng, input, Some(did_key_seed))
}

pub fn prepare_service_registration_inception<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceRegistrationInceptionInput<'_>,
) -> Result<PreparedInception, WebvhInceptionError> {
    prepare_service_registration_inception_internal(rng, input, None)
}

pub fn prepare_service_registration_inception_with_did_key_seed<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceRegistrationInceptionInput<'_>,
    did_key_seed: &[u8; SECRET_KEY_LENGTH],
) -> Result<PreparedInception, WebvhInceptionError> {
    prepare_service_registration_inception_internal(rng, input, Some(did_key_seed))
}

fn prepare_service_registration_inception_internal<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceRegistrationInceptionInput<'_>,
    supplied_did_key_seed: Option<&[u8; SECRET_KEY_LENGTH]>,
) -> Result<PreparedInception, WebvhInceptionError> {
    let local_id = service_registration_local_id(input.registration_key)
        .map_err(|error| WebvhInceptionError::InvalidRegistration(error.to_string()))?;
    prepare_service_inception_parts(
        rng,
        input.provider_endpoint,
        input.registration_key.public_base(),
        *input.registration_key.service_type(),
        &local_id,
        input.also_known_as,
        input.version_time,
        input.did_key_fragment,
        supplied_did_key_seed,
    )
}

fn prepare_service_inception_internal<R: RngCore + ?Sized>(
    rng: &mut R,
    input: &ServiceInceptionInput<'_>,
    supplied_did_key_seed: Option<&[u8; SECRET_KEY_LENGTH]>,
) -> Result<PreparedInception, WebvhInceptionError> {
    let public_base = CanonicalServiceUrl::canonicalize(input.principal_endpoint.as_str())
        .map_err(|error| WebvhInceptionError::InvalidRegistration(error.to_string()))?;
    prepare_service_inception_parts(
        rng,
        input.principal_endpoint,
        &public_base,
        ServiceType::PrincipalServer,
        input.local_id,
        input.also_known_as,
        input.version_time,
        input.did_key_fragment,
        supplied_did_key_seed,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_service_inception_parts<R: RngCore + ?Sized>(
    rng: &mut R,
    provider_endpoint: &Url,
    public_base: &CanonicalServiceUrl,
    service_type: ServiceType,
    local_id: &str,
    also_known_as: &[String],
    version_time: DateTime<Utc>,
    did_key_fragment: Option<&str>,
    supplied_did_key_seed: Option<&[u8; SECRET_KEY_LENGTH]>,
) -> Result<PreparedInception, WebvhInceptionError> {
    let (method_authority, https_authority) = authority_pair(provider_endpoint)?;
    let local_id = normalize_local_id(local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let did_key_seed = supplied_did_key_seed
        .copied()
        .unwrap_or_else(|| random_seed(rng));
    let update_key_seed = random_seed(rng);
    let next_update_key_seed = random_seed(rng);
    let did_signing = SigningKey::from_bytes(&did_key_seed);
    let update_signing = SigningKey::from_bytes(&update_key_seed);
    let next_update_signing = SigningKey::from_bytes(&next_update_key_seed);
    let did_public_key_multibase =
        encode_ed25519_pubkey_multibase(&did_signing.verifying_key().to_bytes());
    let update_public_key_multibase =
        encode_ed25519_pubkey_multibase(&update_signing.verifying_key().to_bytes());
    let next_update_public_key_multibase =
        encode_ed25519_pubkey_multibase(&next_update_signing.verifying_key().to_bytes());
    let next_update_key_hash = webvh_next_key_hash(&next_update_public_key_multibase)?;
    let did_key_fragment = normalize_key_fragment(did_key_fragment.unwrap_or("did-key-1"))
        .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let update_key_fragment =
        normalize_key_fragment("update-key-1").ok_or(WebvhInceptionError::InvalidKeyFragment)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let placeholder_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let service_endpoint = public_base.as_str();
    let version_time = version_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let document_skeleton = embedded_webvh_document_value_without_enrollment(
        &placeholder_did,
        &placeholder_key_id,
        &did_public_key_multibase,
        also_known_as,
        service_endpoint,
        service_type,
    );
    let entry_skeleton = json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [update_public_key_multibase],
            "nextKeyHashes": [next_update_key_hash],
        },
        "state": document_skeleton,
    });
    let scid = sha256_multihash_base58btc(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid);
    let version_hash =
        sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(&log_entry, &scid))?);
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
    let submit_body = did_submit_body(&did, 1, None, log_entry.clone())?;
    let document_url = identity_document_url(provider_endpoint, &did)?;
    let log_url = identity_log_url(provider_endpoint, &did)?;
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
        next_update_public_key_multibase,
        next_update_key_hash,
        did_key_id,
        update_key_id,
        document_url,
        log_url,
        did_key_seed,
        update_key_seed,
        next_update_key_seed,
    })
}

/// Reconstruct a client-authored principal inception entry, verify its cold
/// root proof, and produce the typed DID operation without receiving secret
/// material.
pub fn prepare_supplied_principal_inception(
    input: &SuppliedPrincipalInceptionInput<'_>,
) -> Result<SubmittedInception, WebvhInceptionError> {
    validate_principal_key_separation(
        input.root_public_key_multibase,
        input.next_root_public_key_multibase,
        &input.enrollment,
    )?;
    DateTime::parse_from_rfc3339(input.version_time).map_err(|_| {
        WebvhInceptionError::InvalidProof("version_time must be RFC3339".to_owned())
    })?;

    let (method_authority, _https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let document_skeleton = principal_document_value(
        &placeholder_did,
        input.also_known_as,
        &service_endpoint,
        &input.enrollment,
    )?;
    validate_principal_did_document_profile(
        &placeholder_did,
        &document_skeleton,
        &[
            input.root_public_key_multibase,
            input.next_root_public_key_multibase,
        ],
    )?;
    let next_root_key_hash = webvh_next_key_hash(input.next_root_public_key_multibase)?;
    let entry_skeleton = json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
        "versionTime": input.version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [input.root_public_key_multibase],
            "nextKeyHashes": [next_root_key_hash],
        },
        "state": document_skeleton,
    });
    let scid = sha256_multihash_base58btc(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid);
    let version_hash =
        sha256_multihash_base58btc(&canonical_bytes(&strip_for_hash(&log_entry, &scid))?);
    let version_id = format!("1-{version_hash}");
    if let Value::Object(map) = &mut log_entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
        map.insert("proof".to_owned(), Value::Array(vec![input.proof.clone()]));
    }
    verify_webvh_log_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;

    let did = format_webvh_did(&method_authority, &scid, &local_id);
    let root_verification_method = did_key_verification_method(input.root_public_key_multibase);
    let submit_body = did_submit_body(&did, 1, None, log_entry.clone())?;
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
        root_verification_method,
        root_public_key_multibase: input.root_public_key_multibase.to_owned(),
        next_root_public_key_multibase: input.next_root_public_key_multibase.to_owned(),
        next_root_key_hash,
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
    arkret_canonical::canonical::canonical_json_bytes(value)
        .map_err(|err| WebvhInceptionError::Canonical(err.to_string()))
}

fn embedded_webvh_document_value_without_enrollment(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    also_known_as: &[String],
    service_endpoint: &str,
    service_type: ServiceType,
) -> Value {
    let mut verification_methods = vec![json!({
        "id": did_key_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": did_public_key_multibase,
    })];
    let authentication = vec![did_key_id.to_owned()];
    let mut assertion_methods = vec![did_key_id.to_owned()];
    if service_type == ServiceType::PrincipalServer {
        let federation_key_id = format!("{did}#federation-fanout-key");
        if federation_key_id != did_key_id {
            verification_methods.push(json!({
                "id": federation_key_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": did_public_key_multibase,
            }));
            assertion_methods.push(federation_key_id);
        }
    }
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": verification_methods,
        "authentication": authentication,
        "assertionMethod": assertion_methods,
        "alsoKnownAs": also_known_as,
        "service": [
            {
                "id": format!("{did}#service"),
                "type": "ArkretService",
                "serviceType": service_type,
                "serviceEndpoint": service_endpoint,
            }
        ],
    })
}

fn principal_document_value(
    did: &str,
    also_known_as: &[String],
    service_endpoint: &str,
    enrollment: &PrincipalEnrollmentDelegation<'_>,
) -> Result<Value, WebvhInceptionError> {
    let mut services = vec![json!({
        "id": format!("{did}#soland"),
        "type": "ArkretPrincipalServer",
        "serviceEndpoint": service_endpoint,
    })];
    let mut document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": also_known_as,
    });

    match enrollment {
        PrincipalEnrollmentDelegation::ExternalAuthority { authority_did } => {
            Did::new((*authority_did).to_owned()).map_err(|error| {
                WebvhInceptionError::InvalidDid(format!(
                    "enrollment authority DID is invalid: {error}"
                ))
            })?;
            services.push(json!({
                "id": format!("{did}#enrollment-authority"),
                "type": arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                "serviceEndpoint": authority_did,
            }));
        }
        PrincipalEnrollmentDelegation::SelfAuthority {
            principal_signing_public_key_multibase,
            enrollment_public_key_multibase,
            principal_signing_fragment,
            enrollment_fragment,
        } => {
            let principal_fragment = normalize_key_fragment(
                principal_signing_fragment.unwrap_or("principal-signing-key"),
            )
            .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
            let enrollment_fragment = normalize_key_fragment(
                enrollment_fragment.unwrap_or("device-enrollment-authority"),
            )
            .ok_or(WebvhInceptionError::InvalidKeyFragment)?;
            if principal_fragment == enrollment_fragment {
                return Err(WebvhInceptionError::InvalidKeyFragment);
            }
            let principal_id = format!("{did}#{principal_fragment}");
            let enrollment_id = format!("{did}#{enrollment_fragment}");
            if let Value::Object(properties) = &mut document {
                properties.insert(
                    "verificationMethod".to_owned(),
                    json!([
                        {
                            "id": principal_id,
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": principal_signing_public_key_multibase,
                        },
                        {
                            "id": enrollment_id,
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": enrollment_public_key_multibase,
                        }
                    ]),
                );
                properties.insert("assertionMethod".to_owned(), json!([principal_id]));
                properties.insert("capabilityDelegation".to_owned(), json!([enrollment_id]));
            }
        }
    }
    if let Value::Object(properties) = &mut document {
        properties.insert("service".to_owned(), Value::Array(services));
    }
    Ok(document)
}

/// Validate the two mutually exclusive principal DID-document profiles and
/// ensure no current or caller-known future root key is exposed as a DID Core
/// verification method.
pub fn validate_principal_did_document_profile(
    did: &str,
    state: &Value,
    forbidden_root_keys: &[&str],
) -> Result<PrincipalDidDocumentProfile, WebvhInceptionError> {
    let object = state.as_object().ok_or_else(|| {
        WebvhInceptionError::InvalidProof("principal DID document must be an object".to_owned())
    })?;
    if object.get("id").and_then(Value::as_str) != Some(did) {
        return Err(WebvhInceptionError::InvalidProof(
            "principal DID document id mismatch".to_owned(),
        ));
    }
    let services = object
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal DID document must declare services".to_owned(),
            )
        })?;
    let enrollment_services = services
        .iter()
        .filter(|service| {
            service.get("type").and_then(Value::as_str)
                == Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
        })
        .collect::<Vec<_>>();
    if enrollment_services.len() > 1 {
        return Err(WebvhInceptionError::InvalidProof(
            "principal DID document has duplicate enrollment authority services".to_owned(),
        ));
    }

    if let Some(service) = enrollment_services.first() {
        if object.get("verificationMethod").is_some()
            || object.get("assertionMethod").is_some()
            || object.get("capabilityDelegation").is_some()
        {
            return Err(WebvhInceptionError::InvalidProof(
                "external enrollment authority is mutually exclusive with self-authority keys"
                    .to_owned(),
            ));
        }
        let endpoint = service
            .get("serviceEndpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(
                    "external enrollment authority serviceEndpoint must be a DID".to_owned(),
                )
            })?;
        Did::new(endpoint.to_owned()).map_err(|error| {
            WebvhInceptionError::InvalidDid(format!("enrollment authority DID is invalid: {error}"))
        })?;
        return Ok(PrincipalDidDocumentProfile::ExternalAuthority);
    }

    let methods = object
        .get("verificationMethod")
        .and_then(Value::as_array)
        .filter(|methods| methods.len() == 2)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "self-authority principal must declare exactly two verification methods".to_owned(),
            )
        })?;
    let mut method_keys = BTreeMap::new();
    for method in methods {
        let method = method.as_object().ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal verification method must be an object".to_owned(),
            )
        })?;
        let id = method.get("id").and_then(Value::as_str).ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal verification method id is required".to_owned(),
            )
        })?;
        if !id.starts_with(&format!("{did}#"))
            || method.get("controller").and_then(Value::as_str) != Some(did)
            || method.get("type").and_then(Value::as_str) != Some("Multikey")
        {
            return Err(WebvhInceptionError::InvalidProof(
                "principal verification method id, controller, or type is invalid".to_owned(),
            ));
        }
        let key = method
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(
                    "principal verification method publicKeyMultibase is required".to_owned(),
                )
            })?;
        if !valid_multibase_key(key) {
            return Err(WebvhInceptionError::InvalidProof(
                "principal verification method must contain an Ed25519 multikey".to_owned(),
            ));
        }
        if forbidden_root_keys.contains(&key) {
            return Err(WebvhInceptionError::InvalidProof(
                "identity root keys must not appear in the principal DID document".to_owned(),
            ));
        }
        if method_keys.insert(id, key).is_some() {
            return Err(WebvhInceptionError::InvalidProof(
                "principal verification method ids must be distinct".to_owned(),
            ));
        }
    }
    let unique_keys = method_keys.values().copied().collect::<BTreeSet<_>>();
    if unique_keys.len() != method_keys.len() {
        return Err(WebvhInceptionError::InvalidProof(
            "principal signing and enrollment keys must be distinct".to_owned(),
        ));
    }
    let assertion = single_relationship_reference(object, "assertionMethod")?;
    let delegation = single_relationship_reference(object, "capabilityDelegation")?;
    if assertion == delegation
        || !method_keys.contains_key(assertion)
        || !method_keys.contains_key(delegation)
    {
        return Err(WebvhInceptionError::InvalidProof(
            "principal assertion and enrollment relationships must reference distinct local methods"
                .to_owned(),
        ));
    }
    Ok(PrincipalDidDocumentProfile::SelfAuthority)
}

fn single_relationship_reference<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, WebvhInceptionError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .filter(|references| references.len() == 1)
        .and_then(|references| references[0].as_str())
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(format!(
                "principal {field} must contain exactly one string reference"
            ))
        })
}

fn validate_principal_key_separation(
    root_public_key_multibase: &str,
    next_root_public_key_multibase: &str,
    enrollment: &PrincipalEnrollmentDelegation<'_>,
) -> Result<(), WebvhInceptionError> {
    let mut named_keys = vec![
        ("root", root_public_key_multibase),
        ("next root", next_root_public_key_multibase),
    ];
    if let PrincipalEnrollmentDelegation::SelfAuthority {
        principal_signing_public_key_multibase,
        enrollment_public_key_multibase,
        ..
    } = enrollment
    {
        named_keys.push(("principal signing", principal_signing_public_key_multibase));
        named_keys.push(("enrollment", enrollment_public_key_multibase));
    }
    for (name, key) in &named_keys {
        if !valid_multibase_key(key) {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "{name} key must be an Ed25519 public multikey"
            )));
        }
    }
    for left in 0..named_keys.len() {
        for right in (left + 1)..named_keys.len() {
            if named_keys[left].1 == named_keys[right].1 {
                return Err(WebvhInceptionError::InvalidProof(format!(
                    "{} and {} keys must be distinct",
                    named_keys[left].0, named_keys[right].0
                )));
            }
        }
    }
    Ok(())
}

fn did_key_verification_method(public_key_multibase: &str) -> String {
    format!("did:key:{public_key_multibase}#{public_key_multibase}")
}

/// Compute a did:webvh v1.0 pre-rotation commitment for an Ed25519 public
/// multikey: `base58btc(multihash(sha2-256, UTF8(multikey)))`.
pub fn webvh_next_key_hash(public_key_multibase: &str) -> Result<String, WebvhInceptionError> {
    if !valid_multibase_key(public_key_multibase) {
        return Err(WebvhInceptionError::InvalidProof(
            "next root key must be an Ed25519 public multikey".to_owned(),
        ));
    }
    Ok(sha256_multihash_base58btc(public_key_multibase.as_bytes()))
}

fn did_submit_body(
    did: &str,
    seq: u64,
    prev_event_digest: Option<Hash>,
    operation: Value,
) -> Result<DidOperationSubmitRequestBody, WebvhInceptionError> {
    let typed_did = Did::new(did.to_owned())
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    let Value::Object(operation) = operation else {
        return Err(WebvhInceptionError::Canonical(
            "did:webvh operation must be a JSON object".to_owned(),
        ));
    };
    Ok(DidOperationSubmitRequestBody {
        did: typed_did,
        did_method: "webvh".to_owned(),
        seq: Some(seq),
        prev_event_digest,
        operation: operation.into_iter().collect(),
    })
}

fn identity_document_url(endpoint: &Url, did: &str) -> Result<String, WebvhInceptionError> {
    let mut url = endpoint
        .join("/_arkret/root/identity/document")
        .map_err(WebvhInceptionError::InvalidEndpoint)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url.to_string())
}

fn identity_log_url(endpoint: &Url, did: &str) -> Result<String, WebvhInceptionError> {
    let mut url = endpoint
        .join("/_arkret/root/identity/log")
        .map_err(WebvhInceptionError::InvalidEndpoint)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url.to_string())
}

fn build_proof(
    log_entry: &Value,
    update_signing: &SigningKey,
    update_public_key_multibase: &str,
) -> Result<Value, WebvhInceptionError> {
    let verification_method = did_key_verification_method(update_public_key_multibase);
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    });
    let mut document = log_entry.clone();
    if let Value::Object(map) = &mut document {
        map.remove("proof");
    }
    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(
        &canonical_bytes(&proof_config)?,
    ));
    signing_input.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(
        &canonical_bytes(&document)?,
    ));
    let signature = update_signing.sign(&signing_input);
    let mut proof = proof_config;
    if let Value::Object(properties) = &mut proof {
        properties.insert(
            "proofValue".to_owned(),
            Value::String(arkret_canonical::encode_multibase_base58btc(
                signature.to_bytes(),
            )),
        );
    }
    Ok(proof)
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
    if update_keys.first().copied() != Some(public_key_multibase) {
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
    let mut proof_config = Value::Object(proof.clone());
    if let Value::Object(properties) = &mut proof_config {
        properties.remove("proofValue");
    }
    let mut document = entry.clone();
    if let Value::Object(properties) = &mut document {
        properties.remove("proof");
    }
    let proof_config = arkret_canonical::canonical::canonical_json_bytes(&proof_config)
        .map_err(|error| error.to_string())?;
    let document = arkret_canonical::canonical::canonical_json_bytes(&document)
        .map_err(|error| error.to_string())?;
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&proof_config));
    payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&document));
    public_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "webvh log proof signature is invalid".to_owned())
}

fn decode_webvh_signature(value: &str) -> Result<Signature, String> {
    let signature_bytes = arkret_canonical::decode_ed25519_signature_multibase(value)
        .map_err(|error| format!("invalid ed25519 proofValue: {error}"))?;
    Ok(Signature::from_bytes(&signature_bytes))
}

/// Build the DIF did:webvh v1.0 entry-hash preimage: drop `proof[]` and set
/// `versionId` to the predecessor anchor — the SCID for the inception entry,
/// or the previous entry's `versionId` for subsequent entries.
fn strip_for_hash(value: &Value, prev_anchor: &str) -> Value {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
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

fn scid_skeleton_from_genesis(
    entry: &Value,
    claimed_scid: &str,
) -> Result<Value, WebvhInceptionError> {
    let mut stripped = entry.clone();
    if let Value::Object(map) = &mut stripped {
        map.remove("proof");
        map.remove("versionId");
        map.remove("witness");
    }
    let encoded = serde_json::to_string(&stripped)
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let mut skeleton: Value =
        serde_json::from_str(&encoded.replace(claimed_scid, WEBVH_SCID_PLACEHOLDER))
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let object = skeleton.as_object_mut().ok_or_else(|| {
        WebvhInceptionError::InvalidProof("principal inception must be an object".to_owned())
    })?;
    object.insert(
        "versionId".to_owned(),
        Value::String(WEBVH_SCID_PLACEHOLDER.to_owned()),
    );
    Ok(skeleton)
}

/// `base58btc(0x12 0x20 || sha256(bytes))` — the sha2-256 multihash, base58btc
/// encoded WITHOUT a multibase prefix, per DIF did:webvh v1.0 (SCIDs and entry
/// hashes are 46-char `Qm…` strings; multibase `z` applies to keys/signatures
/// only).
fn sha256_multihash_base58btc(bytes: &[u8]) -> String {
    arkret_canonical::sha256_multihash_base58btc(bytes)
}

fn encode_ed25519_pubkey_multibase(public_key: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(public_key)
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
    use arkret_core::decode_base58btc;
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
        let mut proof_config = Value::Object(proof.clone());
        if let Value::Object(properties) = &mut proof_config {
            properties.remove("proofValue");
        }
        let mut document = entry.clone();
        if let Value::Object(properties) = &mut document {
            properties.remove("proof");
        }
        let proof_config = arkret_canonical::canonical::canonical_json_bytes(&proof_config)
            .map_err(|error| error.to_string())?;
        let document = arkret_canonical::canonical::canonical_json_bytes(&document)
            .map_err(|error| error.to_string())?;
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&proof_config));
        payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&document));
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

    fn public_multikey(seed: u8) -> String {
        encode_ed25519_pubkey_multibase(
            SigningKey::from_bytes(&[seed; SECRET_KEY_LENGTH])
                .verifying_key()
                .as_bytes(),
        )
    }

    fn run_prepare(seed: u8) -> PreparedPrincipalInception {
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let root_seed = [seed; SECRET_KEY_LENGTH];
        let next_root_public_key_multibase = public_multikey(seed.wrapping_add(1));
        let input = PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "01krmccd3cehqbtvzg383m3maf",
            also_known_as: &["acct:user@local.host".to_owned()],
            version_time: DateTime::parse_from_rfc3339("2026-05-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root_public_key_multibase,
            enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: "did:web:coauth.example.com",
            },
        };
        prepare_principal_inception(&input).expect("prepare ok")
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
        // DIF did:webvh v1.0: entry hashes are bare base58btc sha256
        // multihashes — 46 chars, `Qm…`, no multibase `z` prefix.
        assert!(
            prepared.version_id.starts_with("1-Qm"),
            "unexpected versionId: {}",
            prepared.version_id
        );
        let scid = prepared.did.split(':').nth(2).unwrap_or_default();
        assert!(
            scid.starts_with("Qm") && scid.len() == 46,
            "SCID must be a bare 46-char base58btc multihash, got: {scid}"
        );
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
    fn submit_body_matches_arkret_protocol() {
        let prepared = run_prepare(3);
        let body = &prepared.submit_body;
        assert_eq!(body.did.as_str(), prepared.did.as_str());
        assert_eq!(body.did_method, "webvh");
        assert_eq!(body.seq, Some(1));
        assert!(body.prev_event_digest.is_none());
        assert_eq!(
            body.operation["parameters"]["updateKeys"][0].as_str(),
            Some(prepared.root_public_key_multibase.as_str()),
        );
        assert_eq!(
            body.operation["parameters"]["nextKeyHashes"][0].as_str(),
            Some(prepared.next_root_key_hash.as_str()),
        );
        assert!(body.operation["state"].get("verificationMethod").is_none());
        assert_eq!(
            body.operation["versionTime"].as_str(),
            Some(prepared.version_time.as_str())
        );
        let proof = &body.operation["proof"][0];
        assert!(proof.is_object());
        assert_eq!(proof["cryptosuite"].as_str(), Some("eddsa-jcs-2022"));
    }

    #[test]
    fn account_binding_control_proof_uses_entry_zero_root() {
        let prepared = run_prepare(19);
        let validated = validate_principal_inception_operation(&prepared.submit_body)
            .expect("inception validates");
        assert_eq!(validated.principal_id.as_str(), prepared.did);
        assert_eq!(
            validated.document_profile,
            PrincipalDidDocumentProfile::ExternalAuthority
        );
        assert_eq!(
            validated.enrollment_authority.as_ref().map(Did::as_str),
            Some("did:web:coauth.example.com")
        );

        let issued_at = DateTime::parse_from_rfc3339("2026-05-15T00:01:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut proof = IdentityCreationControlProof {
            proof_kind: arkret_core::IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: "challenge_0123456789012345678901".to_owned(),
            challenge: "nonce_0123456789012345678901".to_owned(),
            purpose: arkret_core::IdentityBindingPurpose::AccountBinding,
            principal_id: validated.principal_id.clone(),
            operation_digest: validated.operation_digest.clone(),
            lease_id: "lease_0123456789012345678901".to_owned(),
            lease_fence: 1,
            dpop_jkt: "a".repeat(43),
            audience: Did::new("did:web:coauth.example.com").unwrap(),
            origin: "https://coauth.example.com".to_owned(),
            trust_domain: arkret_core::TypedTrustDomainId::new(
                "ak:trust_domain:example.com".to_owned(),
            )
            .unwrap(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
            verification_key_multibase: prepared.root_public_key_multibase.clone(),
            signature: String::new(),
        };
        sign_identity_creation_control_proof(&mut proof, &[19; SECRET_KEY_LENGTH])
            .expect("proof signs");
        verify_identity_creation_control_proof(&prepared.submit_body, &proof)
            .expect("root proof verifies");

        proof.verification_key_multibase = public_multikey(20);
        assert!(verify_identity_creation_control_proof(&prepared.submit_body, &proof).is_err());
    }

    #[test]
    fn supplied_inception_reconstructs_submit_body() {
        let prepared = run_prepare(31);
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let proof = prepared.log_entry["proof"][0].clone();
        let also_known_as = ["acct:user@local.host".to_owned()];
        let supplied = prepare_supplied_principal_inception(&SuppliedPrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &prepared.local_id,
            also_known_as: &also_known_as,
            version_time: &prepared.version_time,
            root_public_key_multibase: &prepared.root_public_key_multibase,
            next_root_public_key_multibase: &prepared.next_root_public_key_multibase,
            proof,
            enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: "did:web:coauth.example.com",
            },
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
            Some("did:web:coauth.example.com"),
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
        let endpoint = Url::parse("http://localhost:8080/").unwrap();
        let root_seed = [1; SECRET_KEY_LENGTH];
        let next_root = public_multikey(2);
        let input = PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "abc",
            also_known_as: &[],
            version_time: Utc::now(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root,
            enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: "did:web:coauth.example.com",
            },
        };
        let err = prepare_principal_inception(&input).unwrap_err();
        assert!(matches!(err, WebvhInceptionError::EndpointHostInvalid));
    }

    #[test]
    fn rejects_invalid_local_id() {
        let endpoint = Url::parse("https://local.host:8080/").unwrap();
        let root_seed = [1; SECRET_KEY_LENGTH];
        let next_root = public_multikey(2);
        let input = PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "../etc/passwd",
            also_known_as: &[],
            version_time: Utc::now(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root,
            enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: "did:web:coauth.example.com",
            },
        };
        let err = prepare_principal_inception(&input).unwrap_err();
        assert!(matches!(err, WebvhInceptionError::InvalidLocalId));
    }

    #[test]
    fn determinism_under_fixed_root_schedule() {
        let a = run_prepare(123);
        let b = run_prepare(123);
        assert_eq!(a.did, b.did);
        assert_eq!(a.version_id, b.version_id);
        assert_eq!(a.root_public_key_multibase, b.root_public_key_multibase);
    }

    #[test]
    fn principal_rotation_activates_only_the_precommitted_root() {
        let genesis = run_prepare(1);
        let next_root = public_multikey(3);
        let rotated = prepare_principal_rotation(&PrincipalRotationInput {
            did: &genesis.did,
            local_id: &genesis.local_id,
            previous_entries: std::slice::from_ref(&genesis.log_entry),
            version_time: DateTime::parse_from_rfc3339("2026-05-16T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            current_root_seed: &[2; SECRET_KEY_LENGTH],
            next_root_public_key_multibase: &next_root,
            state: &genesis.log_entry["state"],
        })
        .unwrap();

        assert!(rotated.version_id.starts_with("2-Qm"));
        assert_eq!(rotated.previous_version_id, genesis.version_id);
        assert!(
            rotated.log_entry["parameters"]
                .get("prevVersionId")
                .is_none()
        );
        assert!(
            rotated.log_entry["parameters"]
                .get("previousVersionId")
                .is_none()
        );
        assert_eq!(
            rotated.log_entry["parameters"]["updateKeys"][0],
            public_multikey(2)
        );
        assert_eq!(rotated.submit_body.did_method, "webvh");
        assert_eq!(rotated.submit_body.seq, Some(2));
        assert_eq!(
            rotated
                .submit_body
                .prev_event_digest
                .as_ref()
                .map(Hash::as_str),
            Some(
                arkret_canonical::canonical::canonical_sha256(&genesis.log_entry)
                    .unwrap()
                    .as_str()
            )
        );
        verify_webvh_log_proof(&rotated.log_entry).unwrap();

        let error = prepare_principal_rotation(&PrincipalRotationInput {
            did: &genesis.did,
            local_id: &genesis.local_id,
            previous_entries: std::slice::from_ref(&genesis.log_entry),
            version_time: Utc::now(),
            current_root_seed: &[4; SECRET_KEY_LENGTH],
            next_root_public_key_multibase: &next_root,
            state: &genesis.log_entry["state"],
        })
        .unwrap_err();
        assert!(error.to_string().contains("not uniquely precommitted"));
    }

    #[test]
    fn principal_rotation_rejects_any_previously_activated_root() {
        let genesis = run_prepare(1);
        let third_root = public_multikey(3);
        let first_rotation = prepare_principal_rotation(&PrincipalRotationInput {
            did: &genesis.did,
            local_id: &genesis.local_id,
            previous_entries: std::slice::from_ref(&genesis.log_entry),
            version_time: DateTime::parse_from_rfc3339("2026-05-16T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            current_root_seed: &[2; SECRET_KEY_LENGTH],
            next_root_public_key_multibase: &third_root,
            state: &genesis.log_entry["state"],
        })
        .unwrap();
        let history = vec![genesis.log_entry.clone(), first_rotation.log_entry.clone()];

        let error = prepare_principal_rotation(&PrincipalRotationInput {
            did: &genesis.did,
            local_id: &genesis.local_id,
            previous_entries: &history,
            version_time: DateTime::parse_from_rfc3339("2026-05-17T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            current_root_seed: &[3; SECRET_KEY_LENGTH],
            next_root_public_key_multibase: &public_multikey(1),
            state: &first_rotation.log_entry["state"],
        })
        .unwrap_err();

        assert!(error.to_string().contains("already activated"));
    }

    #[test]
    fn no_default_port_in_authority() {
        let endpoint = Url::parse("https://local.host/").unwrap();
        let root_seed = [1; SECRET_KEY_LENGTH];
        let next_root = public_multikey(2);
        let input = PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "abc",
            also_known_as: &[],
            version_time: Utc::now(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root,
            enrollment: PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: "did:web:coauth.example.com",
            },
        };
        let prepared = prepare_principal_inception(&input).unwrap();
        assert_eq!(prepared.method_authority, "local.host");
        assert!(prepared.did.contains(":local.host:webvh:"));
    }

    #[test]
    fn self_authority_keeps_all_principal_keys_separate() {
        let endpoint = Url::parse("https://local.host/").unwrap();
        let root_seed = [1; SECRET_KEY_LENGTH];
        let next_root = public_multikey(2);
        let principal_signing = public_multikey(3);
        let enrollment = public_multikey(4);
        let prepared = prepare_principal_inception(&PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "abc",
            also_known_as: &[],
            version_time: Utc::now(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root,
            enrollment: PrincipalEnrollmentDelegation::SelfAuthority {
                principal_signing_public_key_multibase: &principal_signing,
                enrollment_public_key_multibase: &enrollment,
                principal_signing_fragment: None,
                enrollment_fragment: None,
            },
        })
        .unwrap();

        let state = &prepared.log_entry["state"];
        assert_eq!(state["verificationMethod"].as_array().unwrap().len(), 2);
        assert_eq!(state["assertionMethod"].as_array().unwrap().len(), 1);
        assert_eq!(state["capabilityDelegation"].as_array().unwrap().len(), 1);
        assert!(
            state["verificationMethod"]
                .as_array()
                .unwrap()
                .iter()
                .all(|method| method["publicKeyMultibase"] != prepared.root_public_key_multibase)
        );
    }

    #[test]
    fn principal_profile_rejects_mixed_or_dangling_enrollment_authority() {
        let did = "did:webvh:{SCID}:local.host:webvh:abc";
        let root = public_multikey(1);
        let principal_signing = public_multikey(2);
        let enrollment = public_multikey(3);
        let principal_method = format!("{did}#principal-signing-key");
        let enrollment_method = format!("{did}#device-enrollment-authority");
        let mut state = json!({
            "id": did,
            "verificationMethod": [
                {
                    "id": principal_method,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": principal_signing,
                },
                {
                    "id": enrollment_method,
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": enrollment,
                }
            ],
            "assertionMethod": [principal_method],
            "capabilityDelegation": [enrollment_method],
            "service": [{
                "id": format!("{did}#soland"),
                "type": "ArkretPrincipalServer",
                "serviceEndpoint": "https://local.host"
            }]
        });
        assert_eq!(
            validate_principal_did_document_profile(did, &state, &[&root]).unwrap(),
            PrincipalDidDocumentProfile::SelfAuthority
        );

        state["capabilityDelegation"] = json!([format!("{did}#missing")]);
        assert!(validate_principal_did_document_profile(did, &state, &[&root]).is_err());

        state["capabilityDelegation"] = json!([enrollment_method]);
        state["service"].as_array_mut().unwrap().push(json!({
            "id": format!("{did}#enrollment-authority"),
            "type": arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
            "serviceEndpoint": "did:web:coauth.example.com"
        }));
        assert!(validate_principal_did_document_profile(did, &state, &[&root]).is_err());
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
    fn service_inception_has_service_id_shape() {
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
                svc.get("type").and_then(Value::as_str) == Some("ArkretService")
                    && svc.get("serviceType").and_then(Value::as_str) == Some("principal_server")
            }),
            "service DID document should carry the typed ArkretService entry",
        );
    }

    #[test]
    fn provider_host_and_registered_public_base_are_independent() {
        let mut rng = ChaCha20Rng::seed_from_u64(29);
        let provider_endpoint = Url::parse("https://identity.example/").unwrap();
        let registration_key = ServiceRegistrationKey::new(
            ServiceType::AuthServer,
            CanonicalServiceUrl::new("https://auth.example/").unwrap(),
        )
        .unwrap();
        let prepared = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &provider_endpoint,
                registration_key: &registration_key,
                also_known_as: &[],
                version_time: DateTime::parse_from_rfc3339("2026-07-15T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                did_key_fragment: None,
            },
        )
        .unwrap();

        assert!(prepared.did.contains(":identity.example:webvh:"));
        let operation = prepared.service_registration_operation().unwrap();
        operation.validate_for(&registration_key).unwrap();
        assert_eq!(
            operation.state.service[0].service_endpoint.as_str(),
            "https://auth.example/"
        );
        assert_eq!(
            operation.state.service[0].service_type,
            ServiceType::AuthServer
        );
    }

    #[test]
    fn service_inception_can_publish_durable_signing_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(19);
        let endpoint = Url::parse("https://auth.example.com/").unwrap();
        let input = ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: DateTime::parse_from_rfc3339("2026-07-05T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            did_key_fragment: Some("notary-key"),
        };
        let signing_seed = [0x5au8; SECRET_KEY_LENGTH];
        let prepared = prepare_service_inception_with_did_key_seed(&mut rng, &input, &signing_seed)
            .expect("service prepare with durable key");
        let expected_public_key = encode_ed25519_pubkey_multibase(
            SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );

        assert_eq!(prepared.did_key_seed, signing_seed);
        assert_eq!(prepared.did_public_key_multibase, expected_public_key);
        assert_eq!(prepared.did_key_id, format!("{}#notary-key", prepared.did));
        assert_eq!(
            prepared.log_entry["state"]["verificationMethod"][0]["id"],
            prepared.did_key_id,
        );
        assert_eq!(
            prepared.log_entry["state"]["verificationMethod"][0]["publicKeyMultibase"],
            expected_public_key,
        );
        assert_eq!(
            prepared.log_entry["state"]["verificationMethod"][1]["id"],
            format!("{}#federation-fanout-key", prepared.did),
        );
        assert_eq!(
            prepared.log_entry["state"]["verificationMethod"][1]["publicKeyMultibase"],
            expected_public_key,
        );
        assert_eq!(
            prepared.log_entry["state"]["assertionMethod"][1],
            format!("{}#federation-fanout-key", prepared.did),
        );
        verify_proof_like_soland(&prepared.log_entry).expect("service inception proof verifies");
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
