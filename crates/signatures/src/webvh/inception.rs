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
//! 5. sign the entry (sans `proof`) under `cryptosuite: eddsa-jcs-2022` with the update key.
//!
//! Principal builders borrow cold root material and never return it. Service
//! builders retain their separate assertion/update key result because a
//! service owns and durably operates both keys.
//!
//! Authoritative history verification is owned by `arkret-identity`; this
//! module still self-validates every proof it constructs and every proof
//! accepted by its public inception validator.
//!
//! HTTP transport (POSTing the prepared operation to soland) deliberately lives
//! outside this crate: this module is pure build + cryptography so clients
//! (sodmin / inkson) and servers (soland / coauth) can all share one
//! implementation with no drift.

use std::collections::BTreeSet;

use arkret_canonical::base64url::base64url_encode;
use arkret_canonical::multibase::decode_ed25519_multibase;
use arkret_models_identity::identity::DidOperationSubmitRequestBody;
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationKey, ServiceWebvhInceptionOperation,
    service_registration_local_id,
};
use arkret_models_identity::{IdentityCreationControlProof, UnsignedIdentityCreationControlProof};
use arkret_wire::{
    Base64UrlString, DidBindingEvidenceKind, DidBindingEvidenceReceipt, DidBindingMethodProof,
    DidBindingMethodProofKind, DidCoreId, DidFullId, DidUrl, Hash, RegistrationControlSignature,
    RegistrationDidEvidenceDraft, ServiceKind,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use rand_core::RngCore;
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";
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
    pub principal_id: DidCoreId,
    /// Canonical digest of the complete typed submit request.
    pub operation_digest: Hash,
    /// Method-native inception versionId.
    pub did_version_id: String,
    /// Canonical digest of the exact method-native inception log entry.
    pub log_head_digest: Hash,
    /// Digest of the active inception update key bytes.
    pub control_key_digest: Hash,
    /// The method-native identity root selected from `parameters.updateKeys[0]`.
    pub root_public_key_multibase: String,
}

/// One cryptographically verified method-native history state selected at an
/// exact wall-clock instant. The returned document and update key come from the
/// same validated entry; callers must not combine either with current resolve
/// output.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedWebvhHistoryPoint {
    pub did: DidFullId,
    pub version_id: String,
    pub version_time: DateTime<Utc>,
    pub document: Value,
    pub active_update_key_multibase: String,
}

/// Validate a complete `did:webvh` history and select the entry effective at
/// `at`. Hash-chain, pre-rotation commitment and every Data Integrity proof are
/// checked before a point is returned.
pub fn validate_webvh_history_at(
    did: &DidFullId,
    entries: &[Value],
    at: DateTime<Utc>,
) -> Result<ValidatedWebvhHistoryPoint, WebvhInceptionError> {
    if did.method() != "webvh" {
        return Err(WebvhInceptionError::InvalidDid(
            "historical verification requires did:webvh".to_owned(),
        ));
    }
    validate_principal_rotation_history(did.as_str(), entries)?;

    let mut previous_time = None;
    let mut selected = None;
    for entry in entries {
        let version_time = entry
            .get("versionTime")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(
                    "webvh history entry is missing versionTime".to_owned(),
                )
            })?
            .parse::<DateTime<Utc>>()
            .map_err(|_| {
                WebvhInceptionError::InvalidProof(
                    "webvh history entry has a non-canonical versionTime".to_owned(),
                )
            })?;
        if previous_time.is_some_and(|previous| version_time <= previous) {
            return Err(WebvhInceptionError::InvalidProof(
                "webvh history versionTime is not strictly increasing (fork or reorder)".to_owned(),
            ));
        }
        previous_time = Some(version_time);
        if version_time <= at {
            selected = Some((entry, version_time));
        }
    }

    let (entry, version_time) = selected.ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "webvh history has no entry effective at the requested time".to_owned(),
        )
    })?;
    if entry
        .pointer("/parameters/deactivated")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(WebvhInceptionError::InvalidProof(
            "webvh DID was deactivated at the requested time".to_owned(),
        ));
    }
    let version_id = entry
        .get("versionId")
        .and_then(Value::as_str)
        .expect("validated history entry has versionId")
        .to_owned();
    let active_update_key_multibase = entry
        .pointer("/parameters/updateKeys/0")
        .and_then(Value::as_str)
        .expect("validated history entry has one update key")
        .to_owned();
    let document = entry.get("state").cloned().ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "webvh history entry is missing its DID document state".to_owned(),
        )
    })?;
    Ok(ValidatedWebvhHistoryPoint {
        did: did.clone(),
        version_id,
        version_time,
        document,
        active_update_key_multibase,
    })
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
    verify_constructed_webvh_proof(&entry).map_err(WebvhInceptionError::InvalidProof)?;
    let state = entry.get("state").ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "principal inception must contain a DID document state".to_owned(),
        )
    })?;
    validate_principal_did_document_profile(
        request.did.as_str(),
        state,
        &[root_public_key_multibase],
    )?;
    let operation_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(request)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let log_head_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(&entry)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let root_key_bytes = decode_ed25519_multibase(root_public_key_multibase)
        .map_err(|error| WebvhInceptionError::InvalidProof(error.to_string()))?;
    let control_key_digest = Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(root_key_bytes)
    ))
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;

    let principal_id = arkret_wire::project_full_id_to_core_id(&request.did)
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    Ok(ValidatedPrincipalInception {
        principal_id,
        operation_digest,
        did_version_id: expected_version_id,
        log_head_digest,
        control_key_digest,
        root_public_key_multibase: root_public_key_multibase.to_owned(),
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
        || proof.did_version_id != validated.did_version_id
        || proof.log_head_digest != validated.log_head_digest
        || proof.control_key_digest != validated.control_key_digest
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

/// Verify the dedicated frozen registration-evidence proof against the exact
/// method-native inception operation. This never performs current resolution.
pub fn verify_registration_did_evidence_draft(
    request: &DidOperationSubmitRequestBody,
    draft: &RegistrationDidEvidenceDraft,
) -> Result<ValidatedPrincipalInception, WebvhInceptionError> {
    draft
        .validate_shape()
        .map_err(|error| WebvhInceptionError::InvalidProof(error.to_string()))?;
    let validated = validate_principal_inception_operation(request)?;
    let entry = Value::Object(request.operation.clone().into_iter().collect());
    let document = entry.get("state").ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "registration evidence operation has no DID document state".to_owned(),
        )
    })?;
    let document_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(document)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let empty_witness_proofs_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(&Vec::<Value>::new())
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let method_proof = draft.method_evidence.method_proofs.first();
    if draft.principal_id != validated.principal_id
        || draft.full_id != request.did
        || draft.adapter_version != WEBVH_METHOD_VERSION
        || draft.version_id != validated.did_version_id
        || draft.method_history_head != validated.log_head_digest.as_str()
        || draft.control_key_digest != validated.control_key_digest
        || draft.method_evidence.method != "webvh"
        || draft.method_evidence.document_digest != document_digest
        || draft.method_evidence.method_proofs.len() != 1
        || method_proof.is_none_or(|proof| {
            proof.history_head != validated.log_head_digest.as_str()
                || !proof.witnesses.is_empty()
                || proof.witness_proofs_digest != empty_witness_proofs_digest
        })
    {
        return Err(WebvhInceptionError::InvalidProof(
            "registration DID evidence does not match the accepted inception operation".to_owned(),
        ));
    }
    let key = crate::proof::PublicKeyMaterial::Ed25519Multibase {
        value: validated.root_public_key_multibase.clone(),
    };
    let signing_bytes = draft
        .canonical_control_proof_signing_bytes()
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    if !crate::proof::verify_detached_ed25519_signature(
        &key,
        &signing_bytes,
        draft.control_proof.jws.as_str(),
    ) {
        return Err(WebvhInceptionError::InvalidProof(
            "registration DID evidence control signature is invalid".to_owned(),
        ));
    }
    Ok(validated)
}

/// Build and sign the dedicated historical registration-evidence draft from
/// the exact inception operation. The returned object deliberately has no
/// `accepted_at`; the Account Authority assigns that after registry acceptance.
pub fn sign_registration_did_evidence_draft(
    request: &DidOperationSubmitRequestBody,
    created_at: DateTime<Utc>,
    root_seed: &[u8; SECRET_KEY_LENGTH],
) -> Result<RegistrationDidEvidenceDraft, WebvhInceptionError> {
    let validated = validate_principal_inception_operation(request)?;
    let entry = Value::Object(request.operation.clone().into_iter().collect());
    let document = entry.get("state").ok_or_else(|| {
        WebvhInceptionError::InvalidProof(
            "registration evidence operation has no DID document state".to_owned(),
        )
    })?;
    let document_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(document)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let witness_proofs_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(&Vec::<Value>::new())
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let verification_method = DidUrl::new(format!("{}#registration-root", request.did))
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    let mut draft = RegistrationDidEvidenceDraft {
        principal_id: validated.principal_id,
        full_id: request.did.clone(),
        adapter_version: WEBVH_METHOD_VERSION.to_owned(),
        method_history_head: validated.log_head_digest.to_string(),
        version_id: validated.did_version_id,
        control_key_digest: validated.control_key_digest,
        method_evidence: DidBindingEvidenceReceipt {
            kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".to_owned(),
            document_digest,
            method_proofs: vec![DidBindingMethodProof {
                kind: DidBindingMethodProofKind::WebvhLog,
                history_head: validated.log_head_digest.to_string(),
                witnesses: Vec::new(),
                witness_proofs_digest,
            }],
        },
        control_proof: RegistrationControlSignature {
            verification_method,
            created_at,
            jws: Base64UrlString::new("AA".to_owned())
                .map_err(|error| WebvhInceptionError::InvalidProof(error.to_owned()))?,
        },
    };
    let signing_bytes = draft
        .canonical_control_proof_signing_bytes()
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let signing_key = SigningKey::from_bytes(root_seed);
    draft.control_proof.jws = Base64UrlString::new(base64url_encode(
        signing_key.sign(&signing_bytes).to_bytes(),
    ))
    .map_err(|error| WebvhInceptionError::InvalidProof(error.to_owned()))?;
    verify_registration_did_evidence_draft(request, &draft)?;
    Ok(draft)
}

/// Sign an identity-creation control transcript with a borrowed cold root.
/// The caller remains responsible for zeroizing and never persisting the seed.
pub fn sign_identity_creation_control_proof(
    proof: UnsignedIdentityCreationControlProof,
    root_seed: &[u8; SECRET_KEY_LENGTH],
) -> Result<IdentityCreationControlProof, WebvhInceptionError> {
    let signing_bytes = proof
        .canonical_signing_bytes()
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let signature = SigningKey::from_bytes(root_seed).sign(&signing_bytes);
    let signature = Base64UrlString::new(base64url_encode(signature.to_bytes()))
        .map_err(|error| WebvhInceptionError::Canonical(error.to_owned()))?;
    proof
        .attach_signature(signature)
        .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))
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

/// Inputs for one method-native same-SCID WebVH relocation successor. The
/// preceding log must be complete through `current_did`, and inception must
/// have committed `portable=true`.
pub struct WebvhRelocationInput<'a> {
    pub current_did: &'a str,
    pub target_did: &'a str,
    pub previous_entries: &'a [Value],
    pub version_time: DateTime<Utc>,
    pub current_update_seed: &'a [u8; SECRET_KEY_LENGTH],
    pub next_update_public_key_multibase: &'a str,
    /// Complete successor DID Document. Its `id` must equal `target_did` and
    /// `alsoKnownAs` must contain `current_did`.
    pub state: &'a Value,
}

/// Canonical n+1 rename entry ready for submission to the current owner.
#[derive(Clone, Debug)]
pub struct PreparedWebvhRelocation {
    pub predecessor_did: String,
    pub did: String,
    pub version_time: String,
    pub previous_version_id: String,
    pub version_id: String,
    pub log_entry: Value,
    pub submit_body: DidOperationSubmitRequestBody,
    pub current_update_public_key_multibase: String,
    pub current_update_verification_method: String,
    pub next_update_public_key_multibase: String,
    pub next_update_key_hash: String,
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

/// Inputs to a client-authored principal inception. The caller must derive
/// `root_seed` and `next_root_public_key_multibase` from the same confirmed
/// recovery secret before publishing the result.
pub struct PrincipalInceptionInput<'a> {
    /// Soland's base endpoint, e.g. `https://local.host:8080/`. Drives the
    /// DID method authority, the in-document `serviceEndpoint`, and the
    /// `also_known_as` reverse-link surface.
    pub principal_endpoint: &'a Url,
    /// Stable per-user identifier — typically the user's ULID lower-cased.
    /// Validated against the canonical embedded-provider local-id profile.
    pub local_id: &'a str,
    /// Optional `alsoKnownAs` entries (e.g. the user's `@handle@host`).
    pub also_known_as: &'a [String],
    /// `versionTime` for the inception entry. Soland requires RFC3339.
    pub version_time: DateTime<Utc>,
    pub root_seed: &'a [u8; SECRET_KEY_LENGTH],
    pub next_root_public_key_multibase: &'a str,
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
    prepare_principal_inception_with_portability(input, false)
}

/// Prepare a principal inception that irrevocably opts into method-native
/// same-SCID relocation. Portability cannot be introduced by a later entry.
pub fn prepare_portable_principal_inception(
    input: &PrincipalInceptionInput<'_>,
) -> Result<PreparedPrincipalInception, WebvhInceptionError> {
    prepare_principal_inception_with_portability(input, true)
}

fn prepare_principal_inception_with_portability(
    input: &PrincipalInceptionInput<'_>,
    portable: bool,
) -> Result<PreparedPrincipalInception, WebvhInceptionError> {
    let (method_authority, https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let root_signing = SigningKey::from_bytes(input.root_seed);
    let root_public_key_multibase =
        encode_ed25519_pubkey_multibase(&root_signing.verifying_key().to_bytes());
    validate_principal_key_separation(
        &root_public_key_multibase,
        input.next_root_public_key_multibase,
    )?;
    let next_root_key_hash = webvh_next_key_hash(input.next_root_public_key_multibase)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let version_time = input
        .version_time
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let document_skeleton =
        principal_document_value(&placeholder_did, input.also_known_as, &service_endpoint)?;
    validate_principal_did_document_profile(
        &placeholder_did,
        &document_skeleton,
        &[
            root_public_key_multibase.as_str(),
            input.next_root_public_key_multibase,
        ],
    )?;
    let mut entry_skeleton = json!({
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
    if portable
        && let Some(parameters) = entry_skeleton
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
    {
        parameters.insert("portable".to_owned(), Value::Bool(true));
    }

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
    verify_constructed_webvh_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
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
    let inception_portable = entries[0]
        .pointer("/parameters/portable")
        .and_then(Value::as_bool)
        == Some(true);
    let mut previous_state_id: Option<&str> = None;

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
        let state_id = entry
            .pointer("/state/id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} is missing its state id"
                ))
            })?;
        let state_did = DidFullId::new(state_id.to_owned())
            .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
        if state_did.method() != "webvh" || state_id.split(':').nth(2) != Some(scid) {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "principal history entry {sequence} state id changes method or SCID"
            )));
        }
        if let Some(previous_state_id) = previous_state_id
            && state_id != previous_state_id
        {
            let links_predecessor = entry
                .pointer("/state/alsoKnownAs")
                .and_then(Value::as_array)
                .is_some_and(|aliases| {
                    aliases
                        .iter()
                        .any(|alias| alias.as_str() == Some(previous_state_id))
                });
            if !inception_portable || !links_predecessor {
                return Err(WebvhInceptionError::InvalidProof(format!(
                    "principal history entry {sequence} has an unauthorized portable rename"
                )));
            }
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
        verify_constructed_webvh_proof(entry).map_err(WebvhInceptionError::InvalidProof)?;
        previous_version_id = Some(version_id);
        previous_state_id = Some(state_id);
    }

    if previous_state_id != Some(did) {
        return Err(WebvhInceptionError::InvalidProof(
            "principal history head id does not match current DID".to_owned(),
        ));
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
    let did = DidFullId::new(input.did.to_owned())
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
    verify_constructed_webvh_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
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

/// Build a controller-signed n+1 successor that moves a portable WebVH DID to
/// a new host/path without changing its SCID (and therefore without changing
/// its Arkret core id).
pub fn prepare_webvh_relocation(
    input: &WebvhRelocationInput<'_>,
) -> Result<PreparedWebvhRelocation, WebvhInceptionError> {
    let current_did = DidFullId::new(input.current_did.to_owned())
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    let target_did = DidFullId::new(input.target_did.to_owned())
        .map_err(|error| WebvhInceptionError::InvalidDid(error.to_string()))?;
    if current_did.method() != "webvh" || target_did.method() != "webvh" {
        return Err(WebvhInceptionError::InvalidDid(
            "portable relocation requires did:webvh predecessor and successor".to_owned(),
        ));
    }
    let current_scid = input.current_did.split(':').nth(2).unwrap_or_default();
    let target_scid = input.target_did.split(':').nth(2).unwrap_or_default();
    if current_scid.is_empty() || current_scid != target_scid {
        return Err(WebvhInceptionError::InvalidDid(
            "portable relocation must preserve the exact WebVH SCID".to_owned(),
        ));
    }
    if input.current_did == input.target_did {
        return Err(WebvhInceptionError::InvalidDid(
            "portable relocation must change the WebVH host or path".to_owned(),
        ));
    }
    if input
        .previous_entries
        .first()
        .and_then(|entry| entry.pointer("/parameters/portable"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(WebvhInceptionError::InvalidProof(
            "portable relocation requires portable=true at inception".to_owned(),
        ));
    }
    if input.state.get("id").and_then(Value::as_str) != Some(input.target_did) {
        return Err(WebvhInceptionError::InvalidDid(
            "relocation successor state id must equal target_did".to_owned(),
        ));
    }
    let links_predecessor = input
        .state
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .is_some_and(|aliases| {
            aliases
                .iter()
                .any(|alias| alias.as_str() == Some(input.current_did))
        });
    if !links_predecessor {
        return Err(WebvhInceptionError::InvalidDid(
            "relocation successor alsoKnownAs must contain the direct predecessor DID".to_owned(),
        ));
    }

    let (previous_entry, activated_roots) =
        validate_principal_rotation_history(input.current_did, input.previous_entries)?;
    let previous_version_id = previous_entry
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous WebVH entry is missing versionId".to_owned(),
            )
        })?;
    let previous_sequence = previous_version_id
        .split_once('-')
        .and_then(|(sequence, _)| sequence.parse::<u64>().ok())
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous WebVH entry has malformed versionId".to_owned(),
            )
        })?;
    let sequence = previous_sequence.checked_add(1).ok_or_else(|| {
        WebvhInceptionError::InvalidProof("WebVH sequence cannot advance".to_owned())
    })?;
    let previous_parameters = previous_entry
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous WebVH entry is missing parameters".to_owned(),
            )
        })?;
    let current_signing = SigningKey::from_bytes(input.current_update_seed);
    let current_update_public_key_multibase =
        encode_ed25519_pubkey_multibase(&current_signing.verifying_key().to_bytes());
    let current_commitment = webvh_next_key_hash(&current_update_public_key_multibase)?;
    let previous_next_hashes = previous_parameters
        .get("nextKeyHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "previous WebVH entry is missing nextKeyHashes".to_owned(),
            )
        })?;
    if !previous_next_hashes
        .iter()
        .any(|hash| hash.as_str() == Some(current_commitment.as_str()))
    {
        return Err(WebvhInceptionError::InvalidProof(
            "relocation update key was not precommitted by the previous entry".to_owned(),
        ));
    }
    if activated_roots.contains(&current_update_public_key_multibase)
        || activated_roots.contains(input.next_update_public_key_multibase)
        || current_update_public_key_multibase == input.next_update_public_key_multibase
    {
        return Err(WebvhInceptionError::InvalidProof(
            "relocation attempts to reuse an activated WebVH update key".to_owned(),
        ));
    }
    let next_update_key_hash = webvh_next_key_hash(input.next_update_public_key_multibase)?;
    let version_time = input
        .version_time
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut log_entry = json!({
        "versionId": previous_version_id,
        "versionTime": version_time,
        "parameters": {
            "scid": current_scid,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [current_update_public_key_multibase],
            "nextKeyHashes": [next_update_key_hash],
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
    let proof = build_proof(
        &log_entry,
        &current_signing,
        &current_update_public_key_multibase,
    )?;
    if let Value::Object(properties) = &mut log_entry {
        properties.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    verify_constructed_webvh_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
    let previous_event_digest = Hash::new(
        arkret_canonical::canonical::canonical_sha256(previous_entry)
            .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?,
    )
    .map_err(|error| WebvhInceptionError::Canonical(error.to_string()))?;
    let submit_body = did_submit_body(
        input.current_did,
        sequence,
        Some(previous_event_digest),
        log_entry.clone(),
    )?;
    let current_update_verification_method =
        did_key_verification_method(&current_update_public_key_multibase);
    Ok(PreparedWebvhRelocation {
        predecessor_did: input.current_did.to_owned(),
        did: input.target_did.to_owned(),
        version_time,
        previous_version_id: previous_version_id.to_owned(),
        version_id,
        log_entry,
        submit_body,
        current_update_public_key_multibase,
        current_update_verification_method,
        next_update_public_key_multibase: input.next_update_public_key_multibase.to_owned(),
        next_update_key_hash,
    })
}

/// Inputs for a service's own `did:webvh` self-mint.
///
/// A service DID is the identity of the service itself and carries no
/// device authorization authority. The resulting DID document therefore omits the
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
/// service-shaped DID document with no device-authorization-authority service
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
        *input.registration_key.service_kind(),
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
        ServiceKind::PrincipalServer,
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
    service_kind: ServiceKind,
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
        service_kind,
    );
    let entry_skeleton = json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "portable": true,
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
    verify_constructed_webvh_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
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
    )?;
    DateTime::parse_from_rfc3339(input.version_time).map_err(|_| {
        WebvhInceptionError::InvalidProof("version_time must be RFC3339".to_owned())
    })?;

    let (method_authority, _https_authority) = authority_pair(input.principal_endpoint)?;
    let local_id = normalize_local_id(input.local_id).ok_or(WebvhInceptionError::InvalidLocalId)?;
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, &local_id);
    let service_endpoint = trimmed_endpoint(input.principal_endpoint);
    let document_skeleton =
        principal_document_value(&placeholder_did, input.also_known_as, &service_endpoint)?;
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
    verify_constructed_webvh_proof(&log_entry).map_err(WebvhInceptionError::InvalidProof)?;
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
    service_kind: ServiceKind,
) -> Value {
    let mut verification_methods = vec![json!({
        "id": did_key_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": did_public_key_multibase,
    })];
    let authentication = vec![did_key_id.to_owned()];
    let mut assertion_methods = vec![did_key_id.to_owned()];
    if service_kind == ServiceKind::PrincipalServer {
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
                "serviceKind": service_kind,
                "serviceEndpoint": service_endpoint,
            }
        ],
    })
}

fn principal_document_value(
    did: &str,
    also_known_as: &[String],
    service_endpoint: &str,
) -> Result<Value, WebvhInceptionError> {
    Ok(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": also_known_as,
        "service": [{
            "id": format!("{did}#soland"),
            "type": "ArkretPrincipalServer",
            "serviceEndpoint": service_endpoint,
        }],
    }))
}

/// Validate the two mutually exclusive principal DID-document profiles and
/// ensure no current or caller-known future root key is exposed as a DID Core
/// verification method.
pub fn validate_principal_did_document_profile(
    did: &str,
    state: &Value,
    forbidden_root_keys: &[&str],
) -> Result<(), WebvhInceptionError> {
    let object = state.as_object().ok_or_else(|| {
        WebvhInceptionError::InvalidProof("principal DID document must be an object".to_owned())
    })?;
    if object.get("id").and_then(Value::as_str) != Some(did) {
        return Err(WebvhInceptionError::InvalidProof(
            "principal DID document id mismatch".to_owned(),
        ));
    }
    if [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "capabilityDelegation",
    ]
    .iter()
    .any(|field| object.contains_key(*field))
    {
        return Err(WebvhInceptionError::InvalidProof(
            "principal DID document is an identity anchor and must not carry device or business authority keys"
                .to_owned(),
        ));
    }
    if forbidden_root_keys
        .iter()
        .any(|key| serde_json::to_string(state).is_ok_and(|document| document.contains(*key)))
    {
        return Err(WebvhInceptionError::InvalidProof(
            "identity root keys must not appear in the principal DID document".to_owned(),
        ));
    }
    let services = object
        .get("service")
        .and_then(Value::as_array)
        .filter(|services| services.len() == 1)
        .ok_or_else(|| {
            WebvhInceptionError::InvalidProof(
                "principal DID document must declare exactly one Principal Server service"
                    .to_owned(),
            )
        })?;
    let service = &services[0];
    let expected_service_id = format!("{did}#soland");
    if service.get("id").and_then(Value::as_str) != Some(expected_service_id.as_str())
        || service.get("type").and_then(Value::as_str) != Some("ArkretPrincipalServer")
        || service
            .get("serviceEndpoint")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(WebvhInceptionError::InvalidProof(
            "principal DID document Principal Server service is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_principal_key_separation(
    root_public_key_multibase: &str,
    next_root_public_key_multibase: &str,
) -> Result<(), WebvhInceptionError> {
    let named_keys = [
        ("root", root_public_key_multibase),
        ("next root", next_root_public_key_multibase),
    ];
    for (name, key) in &named_keys {
        if !valid_multibase_key(key) {
            return Err(WebvhInceptionError::InvalidProof(format!(
                "{name} key must be an Ed25519 public multikey"
            )));
        }
    }
    if root_public_key_multibase == next_root_public_key_multibase {
        return Err(WebvhInceptionError::InvalidProof(
            "root and next root keys must be distinct".to_owned(),
        ));
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
    let typed_did = DidFullId::new(did.to_owned())
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

/// Self-check one constructed or caller-supplied method-native proof.
///
/// Complete history and witness verification remains centralized in
/// `arkret-identity`; this narrow check prevents a public builder or inception
/// validator from returning an object whose own controller signature is
/// invalid.
fn verify_constructed_webvh_proof(entry: &Value) -> Result<(), String> {
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
    let signature_bytes = arkret_canonical::decode_ed25519_signature_multibase(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .map_err(|error| format!("invalid ed25519 proofValue: {error}"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let mut proof_config = Value::Object(proof.clone());
    if let Value::Object(properties) = &mut proof_config {
        properties.remove("proofValue");
    }
    let mut document = entry.clone();
    if let Value::Object(properties) = &mut document {
        properties.remove("proof");
    }
    let proof_config = canonical_bytes(&proof_config).map_err(|error| error.to_string())?;
    let document = canonical_bytes(&document).map_err(|error| error.to_string())?;
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&proof_config));
    payload.extend_from_slice(&arkret_canonical::canonical::sha256_bytes(&document));
    public_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "webvh log proof signature is invalid".to_owned())
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

/// Derive the embedded provider authority. Returns (method_authority,
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

/// Apply the embedded-provider local-id profile so the local_id we send is
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
mod historical_verification_tests {
    use chrono::{Duration, TimeZone as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::*;

    struct HistoryFixture {
        did: DidFullId,
        first_time: DateTime<Utc>,
        second_time: DateTime<Utc>,
        first_key: String,
        second_key: String,
        first_assertion_key: String,
        second_assertion_key: String,
        entries: Vec<Value>,
        second_seed: [u8; SECRET_KEY_LENGTH],
    }

    fn history_fixture() -> HistoryFixture {
        let endpoint = Url::parse("https://history.example/").unwrap();
        let first_time = Utc.with_ymd_and_hms(2026, 8, 9, 10, 0, 0).unwrap();
        let second_time = first_time + Duration::hours(1);
        let mut rng = ChaChaRng::seed_from_u64(0x4849_5354);
        let third_seed = [0x33; SECRET_KEY_LENGTH];
        let third_key = encode_ed25519_pubkey_multibase(
            &SigningKey::from_bytes(&third_seed)
                .verifying_key()
                .to_bytes(),
        );
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: first_time,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let did = inception.did.clone();
        let first_key = inception.update_public_key_multibase.clone();
        let second_key = inception.next_update_public_key_multibase.clone();
        let second_seed = inception.next_update_key_seed;
        let first_assertion_key = inception.did_public_key_multibase.clone();
        let second_assertion_seed = [0x44; SECRET_KEY_LENGTH];
        let second_assertion_key = encode_ed25519_pubkey_multibase(
            &SigningKey::from_bytes(&second_assertion_seed)
                .verifying_key()
                .to_bytes(),
        );
        let mut second_state = inception.log_entry["state"].clone();
        second_state["verificationMethod"][0]["publicKeyMultibase"] =
            Value::String(second_assertion_key.clone());
        let previous_version_id = inception.version_id.clone();
        let scid = inception.log_entry["parameters"]["scid"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut rotation = json!({
            "versionId": previous_version_id,
            "versionTime": second_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "parameters": {
                "scid": scid,
                "method": WEBVH_METHOD_VERSION,
                "updateKeys": [second_key],
                "nextKeyHashes": [webvh_next_key_hash(&third_key).unwrap()],
            },
            "state": second_state,
        });
        let version_hash = sha256_multihash_base58btc(
            &canonical_bytes(&strip_for_hash(&rotation, &previous_version_id)).unwrap(),
        );
        rotation["versionId"] = Value::String(format!("2-{version_hash}"));
        let signing = SigningKey::from_bytes(&second_seed);
        rotation["proof"] =
            Value::Array(vec![build_proof(&rotation, &signing, &second_key).unwrap()]);
        HistoryFixture {
            did: DidFullId::new(did).unwrap(),
            first_time,
            second_time,
            first_key,
            second_key,
            first_assertion_key,
            second_assertion_key,
            entries: vec![inception.log_entry.clone(), rotation],
            second_seed,
        }
    }

    fn registration_fixture() -> (
        PreparedPrincipalInception,
        [u8; SECRET_KEY_LENGTH],
        DateTime<Utc>,
    ) {
        let root_seed = [0x51; SECRET_KEY_LENGTH];
        let next_seed = [0x52; SECRET_KEY_LENGTH];
        let next_root_public_key_multibase = encode_ed25519_pubkey_multibase(
            &SigningKey::from_bytes(&next_seed)
                .verifying_key()
                .to_bytes(),
        );
        let created_at = Utc.with_ymd_and_hms(2026, 8, 11, 2, 0, 0).unwrap();
        let prepared = prepare_principal_inception(&PrincipalInceptionInput {
            principal_endpoint: &Url::parse("https://registration.example/").unwrap(),
            local_id: "alice",
            also_known_as: &[],
            version_time: created_at,
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root_public_key_multibase,
        })
        .unwrap();
        (prepared, root_seed, created_at)
    }

    #[test]
    fn frozen_registration_evidence_rejects_mutation_and_omission() {
        let (prepared, root_seed, created_at) = registration_fixture();
        let draft =
            sign_registration_did_evidence_draft(&prepared.submit_body, created_at, &root_seed)
                .unwrap();
        verify_registration_did_evidence_draft(&prepared.submit_body, &draft).unwrap();

        let mut mutated = draft.clone();
        mutated.method_evidence.document_digest =
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(verify_registration_did_evidence_draft(&prepared.submit_body, &mutated).is_err());

        let mut invalid_signature = draft.clone();
        invalid_signature.control_proof.jws = Base64UrlString::new("AA".to_owned()).unwrap();
        assert!(
            verify_registration_did_evidence_draft(&prepared.submit_body, &invalid_signature)
                .is_err()
        );

        let mut omitted = serde_json::to_value(&draft).unwrap();
        omitted.as_object_mut().unwrap().remove("method_evidence");
        assert!(serde_json::from_value::<RegistrationDidEvidenceDraft>(omitted).is_err());
        assert!(
            draft
                .clone()
                .accept(created_at - Duration::milliseconds(1))
                .is_err()
        );
    }

    #[test]
    fn selects_the_key_effective_at_the_exact_issued_at_boundary() {
        let fixture = history_fixture();
        let before_rotation = validate_webvh_history_at(
            &fixture.did,
            &fixture.entries,
            fixture.second_time - Duration::milliseconds(1),
        )
        .unwrap();
        assert_eq!(
            before_rotation.active_update_key_multibase,
            fixture.first_key
        );
        assert_eq!(
            before_rotation
                .document
                .pointer("/verificationMethod/0/publicKeyMultibase")
                .and_then(Value::as_str),
            Some(fixture.first_assertion_key.as_str())
        );

        let at_rotation =
            validate_webvh_history_at(&fixture.did, &fixture.entries, fixture.second_time).unwrap();
        assert_eq!(at_rotation.active_update_key_multibase, fixture.second_key);
        assert_eq!(
            at_rotation
                .document
                .pointer("/verificationMethod/0/publicKeyMultibase")
                .and_then(Value::as_str),
            Some(fixture.second_assertion_key.as_str())
        );
        assert_eq!(at_rotation.version_time, fixture.second_time);
    }

    #[test]
    fn rejects_a_forked_or_reordered_history() {
        let mut fixture = history_fixture();
        fixture.entries[1]["versionId"] = Value::String("2-zfork".to_owned());
        let error = validate_webvh_history_at(&fixture.did, &fixture.entries, fixture.second_time)
            .unwrap_err();
        assert!(error.to_string().contains("versionId hash is invalid"));

        let mut fixture = history_fixture();
        fixture.entries[1]["versionTime"] = Value::String(
            fixture
                .first_time
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        let error = validate_webvh_history_at(&fixture.did, &fixture.entries, fixture.second_time)
            .unwrap_err();
        assert!(
            error.to_string().contains("versionId hash is invalid")
                || error.to_string().contains("fork or reorder")
        );
    }

    #[test]
    fn rejects_a_cryptographically_valid_deactivated_history_point() {
        let mut fixture = history_fixture();
        let previous_version_id = fixture.entries[0]["versionId"].as_str().unwrap().to_owned();
        let entry = &mut fixture.entries[1];
        entry["parameters"]["deactivated"] = Value::Bool(true);
        entry.as_object_mut().unwrap().remove("proof");
        let version_hash = sha256_multihash_base58btc(
            &canonical_bytes(&strip_for_hash(entry, &previous_version_id)).unwrap(),
        );
        entry["versionId"] = Value::String(format!("2-{version_hash}"));
        let signing = SigningKey::from_bytes(&fixture.second_seed);
        let proof = build_proof(entry, &signing, &fixture.second_key).unwrap();
        entry["proof"] = Value::Array(vec![proof]);

        let error = validate_webvh_history_at(&fixture.did, &fixture.entries, fixture.second_time)
            .unwrap_err();
        assert!(error.to_string().contains("deactivated"));
    }
}
