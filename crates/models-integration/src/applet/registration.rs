use std::collections::BTreeMap;

use arkret_models_identity::did_document::DidDocument;
use arkret_wire::{
    Did, Error, Hash, MoveSigner, Proof, Result, XExtensionMap, canonical, proof_kind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::namespace_match::namespace_patterns_overlap;
use crate::{AppletPackageE2eePolicy, DelegationPolicy, Widget};

/// Which namespace bucket a claim lives in. The wire model
/// (`applet-schema.md` §1.namespaces) groups claims into exactly
/// `actors` / `realms` / `handles`; the bucket — not a separate `kind`
/// field — determines the segment separator set used for pattern
/// matching (§2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletNamespaceDomain {
    /// Actor / DID namespace. Separator: `:` only; `#fragment` is ignored.
    Actors,
    /// Realm / portal namespace. Separators: `:` and `/`.
    Realms,
    /// Handle namespace. Separators: `:` and `/`.
    Handles,
}

impl AppletNamespaceDomain {
    /// Segment separators for this domain per `applet-schema.md` §2.
    pub(super) fn separators(self) -> &'static [u8] {
        match self {
            AppletNamespaceDomain::Actors => b":",
            AppletNamespaceDomain::Realms | AppletNamespaceDomain::Handles => b":/",
        }
    }
}

/// Overlap between two exclusive namespace claims in the same domain
/// (`applet-schema.md` §4.1). Surfaced in
/// `InstallPlan::namespace_conflicts` and by
/// [`AppletWireNamespaces::conflicts_with`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletNamespaceConflict {
    pub domain: AppletNamespaceDomain,
    pub pattern: String,
    pub conflicting_pattern: String,
}

// ─── wire-format `ak.applet.registration` (spec `applet-schema.md` §1) ─────

/// A single namespace claim entry. Wire shape per `applet-schema.md`
/// §2: an `{ exclusive, pattern }` object, NOT a bare pattern string.
/// `exclusive` claims reject any later registrant whose pattern overlaps
/// (see [`AppletWireNamespaces::conflicts_with`]); non-exclusive claims
/// may coexist.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppletNamespaceEntry {
    #[serde(default)]
    pub exclusive: bool,
    pub pattern: String,
}

impl AppletNamespaceEntry {
    /// An exclusive claim over `pattern`.
    pub fn exclusive(pattern: impl Into<String>) -> Self {
        Self {
            exclusive: true,
            pattern: pattern.into(),
        }
    }

    /// A shared (non-exclusive) claim over `pattern`.
    pub fn shared(pattern: impl Into<String>) -> Self {
        Self {
            exclusive: false,
            pattern: pattern.into(),
        }
    }
}

/// Per-domain namespaces an Applet claims on registration. Wire shape
/// per `applet-schema.md` §1.namespaces / §2: each domain holds an array
/// of `{ exclusive, pattern }` entries (S-13: was a bare `Vec<String>`,
/// which could not express exclusivity and so could not round-trip the
/// spec's object-form namespace entries).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletWireNamespaces {
    #[serde(default)]
    pub actors: Vec<AppletNamespaceEntry>,
    #[serde(default)]
    pub realms: Vec<AppletNamespaceEntry>,
    #[serde(default)]
    pub handles: Vec<AppletNamespaceEntry>,
}

impl AppletWireNamespaces {
    /// Find exclusive-claim overlaps between `self` and `other`, per
    /// domain (`applet-schema.md` §4.1). Two entries conflict iff they
    /// sit in the same domain, at least one is `exclusive`, and their
    /// patterns overlap.
    pub fn conflicts_with(&self, other: &AppletWireNamespaces) -> Vec<AppletNamespaceConflict> {
        let mut conflicts = Vec::new();
        for (domain, mine, theirs) in [
            (AppletNamespaceDomain::Actors, &self.actors, &other.actors),
            (AppletNamespaceDomain::Realms, &self.realms, &other.realms),
            (
                AppletNamespaceDomain::Handles,
                &self.handles,
                &other.handles,
            ),
        ] {
            for a in mine {
                for b in theirs {
                    if (a.exclusive || b.exclusive)
                        && namespace_patterns_overlap(domain, &a.pattern, &b.pattern)
                    {
                        conflicts.push(AppletNamespaceConflict {
                            domain,
                            pattern: a.pattern.clone(),
                            conflicting_pattern: b.pattern.clone(),
                        });
                    }
                }
            }
        }
        conflicts
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookAuthType {
    HttpMessageSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookSignatureAlg {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

impl WebhookSignatureAlg {
    /// Wire name used for serialization and canonical epoch-transcript
    /// ordering (`AppletRegistrationEpochTranscript` in the `arkret` umbrella).
    pub fn as_wire_name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::MlDsa65 => "ML-DSA-65",
        }
    }
}

/// Optional inbound-webhook auth metadata. Wire shape mirrors
/// `applet-package.schema.json#/$defs/webhook_auth`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebhookAuth {
    #[serde(rename = "type")]
    pub r#type: WebhookAuthType,
    pub key_ref: String,
    pub accepted_algs: Vec<WebhookSignatureAlg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_header: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

impl WebhookAuth {
    pub fn http_message_signature(
        key_ref: impl Into<String>,
        accepted_algs: Vec<WebhookSignatureAlg>,
    ) -> Self {
        Self {
            r#type: WebhookAuthType::HttpMessageSignature,
            key_ref: key_ref.into(),
            accepted_algs,
            signature_header: None,
            extra: XExtensionMap::default(),
        }
    }
}

/// HTTP method of a single supported Applet API endpoint
/// (`applet-package.schema.json#/$defs/endpoint_entry.method`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AppletEndpointMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
    Delete,
}

/// Auth requirement of a single supported Applet API endpoint
/// (`applet-package.schema.json#/$defs/endpoint_entry.auth`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletEndpointAuth {
    None,
    WebhookSignature,
    Bearer,
    Mtls,
}

/// One supported Applet API endpoint and its auth requirement
/// (`applet-package.schema.json#/$defs/endpoint_entry`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletEndpointEntry {
    pub method: AppletEndpointMethod,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AppletEndpointAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `x_`-prefixed protocol extension members
    /// (`patternProperties ^x_[a-z][a-z0-9_]{0,63}$`).
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Supported Applet API endpoints and their auth requirements
/// (`applet-package.schema.json#/$defs/endpoint_policy`). Replaces the former
/// untyped `Value` so the manifest's endpoint surface is checked at compile
/// time. The spec requires `endpoints` `minItems: 1`; that cardinality is
/// enforced at schema-validation time, while the type permits an empty list
/// during registration assembly (consistent with the rest of the wire models).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletEndpointPolicy {
    #[serde(default)]
    pub endpoints: Vec<AppletEndpointEntry>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Service-side resource hints derived into the registration manifest
/// (`applet-package.schema.json#/$defs/limits`). All members are optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transaction_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<u64>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Ghost Actor support and accountability template
/// (`applet-package.schema.json#/$defs/ghost_policy`). `enabled` is required;
/// it carries no `default` in the schema, so it is a non-`Option` field that
/// the producer MUST set explicitly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletGhostPolicy {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_template: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletAcceptedSigningKeyEvidence {
    pub key_ref: String,
    pub public_key_digest: Hash,
}

/// Method-specific resolution evidence captured with an Applet registration
/// epoch. Versioned methods carry at least one stable version selector;
/// unversioned methods carry neither selector and require a fresh canonical
/// resolution whenever the epoch is verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletDidMethodVersionEvidence {
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_time: Option<DateTime<Utc>>,
    pub unversioned_refetch: bool,
}

impl AppletDidMethodVersionEvidence {
    pub fn versioned(
        method: impl Into<String>,
        version_id: Option<String>,
        version_time: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let evidence = Self {
            method: method.into(),
            version_id,
            version_time,
            unversioned_refetch: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn unversioned(method: impl Into<String>) -> Result<Self> {
        let evidence = Self {
            method: method.into(),
            version_id: None,
            version_time: None,
            unversioned_refetch: true,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.method.starts_with("did:")
            || self.method.len() <= 4
            || !self.method[4..]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(Error::Protocol(
                "applet registration epoch DID method is invalid".to_owned(),
            ));
        }
        if self.unversioned_refetch {
            if self.version_id.is_some() || self.version_time.is_some() {
                return Err(Error::Protocol(
                    "unversioned DID evidence cannot carry version selectors".to_owned(),
                ));
            }
        } else if self.version_id.as_deref().is_none_or(str::is_empty)
            && self.version_time.is_none()
        {
            return Err(Error::Protocol(
                "versioned DID evidence requires version_id or version_time".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Security-relevant registration fields included in the epoch transcript.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRegistrationEpochDerivedRegistration {
    pub kind: String,
    pub applet_id: String,
    pub service_id: Did,
    pub controller_id: Did,
    pub base_url: String,
    pub bot_actor_id: Did,
    pub protocols: Vec<String>,
    pub namespaces: AppletWireNamespaces,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    pub requested_scopes: Vec<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletRegistrationEpochDidDocument {
    pub service_id: Did,
    pub document_digest: Hash,
    pub method_version: AppletDidMethodVersionEvidence,
}

/// Wire-format `ak.applet.registration` Event content per spec
/// `applet-schema.md` §1 (authoritative `applet_registration_payload`).
///
/// This is the on-the-wire shape every external Applet implementation
/// sends. Build it directly via [`WireAppletRegistration::new`] or derive
/// it from an [`AppletPackage`] with [`AppletPackage::to_registration`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireAppletRegistration {
    pub applet_id: String,
    pub service_id: Did,
    pub controller_id: Did,
    pub base_url: String,
    pub bot_actor_id: Did,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub namespaces: AppletWireNamespaces,
    #[serde(default)]
    pub receive_events: bool,
    #[serde(default)]
    pub receive_ephemeral: bool,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    /// Canonical security epoch hash (`sha256:<hex>`) over the derived
    /// registration plus DID Document / signing-key / endpoint / auth
    /// evidence. **Required** per `applet-schema.md` §1 and the
    /// authoritative `applet_registration_payload`; delegated-agent
    /// grants bind this epoch (`applet-integration.md` §11). Direct wire
    /// builders supply the value; package producers compute it with
    /// `AppletRegistrationEpochTranscript` or
    /// [`AppletPackage::seal_registration_epoch`].
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_auth: Option<WebhookAuth>,
    /// Optional manifest snapshot (claimed profiles, limits, policies,
    /// widget) per `applet_registration_payload.manifest`. Populated by
    /// `AppletPackage::to_registration`; never a substitute for the
    /// top-level required fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl WireAppletRegistration {
    pub const KIND: &'static str = "ak.applet.registration";

    /// Build an unsigned registration. Caller MUST attach `proof` via
    /// [`sign_registration`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: impl Into<String>,
        service_id: Did,
        controller_id: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        protocols: Vec<String>,
        namespaces: AppletWireNamespaces,
        registration_epoch: Hash,
    ) -> Self {
        Self {
            applet_id: applet_id.into(),
            service_id,
            controller_id,
            base_url: base_url.into(),
            bot_actor_id,
            protocols,
            namespaces,
            receive_events: false,
            receive_ephemeral: false,
            rate_limited: false,
            requested_scopes: Vec::new(),
            registration_epoch,
            webhook_auth: None,
            manifest: None,
            created_at: Utc::now(),
            proof: None,
        }
    }

    /// Canonical-JSON SHA256 of the registration **with `proof` set to
    /// `None`**. This is what the controller signs.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut unsigned = self.clone();
        unsigned.proof = None;
        let hash = canonical::canonical_sha256(&unsigned)?;
        Hash::new(hash).map_err(Into::into)
    }
}

/// Sign a [`WireAppletRegistration`] in-place: compute the canonical
/// digest (with `proof` removed), sign it with the supplied
/// [`MoveSigner`], and stamp `reg.proof`.
pub fn sign_registration<S: MoveSigner + ?Sized>(
    reg: &mut WireAppletRegistration,
    signer: &S,
    verification_method: &str,
) -> Result<()> {
    let mut unsigned = reg.clone();
    unsigned.proof = None;
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned)?;
    let payload_digest = Hash::new(canonical::sha256_digest(&canonical_bytes))?;
    let sig = signer.sign_payload(&canonical_bytes)?;
    reg.proof = Some(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: sig.alg,
        verification_method: verification_method.to_owned(),
        event_digest: payload_digest,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: sig.jws,
    });
    Ok(())
}

pub fn applet_signing_key_material_digest(public_key_material: &str) -> Result<Hash> {
    if let Ok(value) = serde_json::from_str::<Value>(public_key_material) {
        return Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into);
    }
    Hash::new(canonical::sha256_digest(public_key_material.as_bytes())).map_err(Into::into)
}

pub fn normalize_applet_signing_key_ref(service_id: &Did, key_ref: &str) -> String {
    if key_ref.starts_with("did:") {
        key_ref.to_owned()
    } else if key_ref.starts_with('#') {
        format!("{}{}", service_id.as_str(), key_ref)
    } else {
        format!("{}#{}", service_id.as_str(), key_ref)
    }
}
/// Captured DID-document and signing-key evidence for an Applet registration
/// epoch. Reducers expand this snapshot when checking delegated Applet grants
/// and fail closed if the service DID document or accepted signing key set no
/// longer matches the install-time epoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRegistrationEpochEvidence {
    pub service_id: Did,
    pub did_document_digest: Hash,
    pub method_version_evidence: AppletDidMethodVersionEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_signing_keys: Vec<AppletAcceptedSigningKeyEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppletEpochEvidenceError {
    ServiceIdMismatch,
    DidDocumentDigestMismatch,
    SigningKeySetEmpty,
    SigningKeySetMismatch,
    SigningKeyMissing(String),
    DidDocumentDigestFailed(String),
    SigningKeyDigestFailed(String),
}

impl std::fmt::Display for AppletEpochEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceIdMismatch => write!(f, "service DID does not match DID document"),
            Self::DidDocumentDigestMismatch => write!(f, "DID document digest mismatch"),
            Self::SigningKeySetEmpty => write!(f, "accepted signing key set is empty"),
            Self::SigningKeySetMismatch => write!(f, "accepted signing key set mismatch"),
            Self::SigningKeyMissing(key_ref) => {
                write!(
                    f,
                    "accepted signing key is missing from DID document: {key_ref}"
                )
            }
            Self::DidDocumentDigestFailed(error) => {
                write!(f, "DID document digest failed: {error}")
            }
            Self::SigningKeyDigestFailed(error) => {
                write!(f, "signing key digest failed: {error}")
            }
        }
    }
}

impl std::error::Error for AppletEpochEvidenceError {}

impl AppletRegistrationEpochEvidence {
    pub fn new(
        service_id: Did,
        did_document_digest: Hash,
        method_version_evidence: AppletDidMethodVersionEvidence,
        accepted_signing_keys: Vec<AppletAcceptedSigningKeyEvidence>,
    ) -> Self {
        Self {
            service_id,
            did_document_digest,
            method_version_evidence,
            accepted_signing_keys,
        }
    }

    pub fn from_did_document(
        document: &DidDocument,
        method_version_evidence: AppletDidMethodVersionEvidence,
    ) -> Result<Self> {
        method_version_evidence.validate()?;
        let did_document_digest = applet_did_document_digest(document)?;
        let mut accepted_signing_keys = Vec::with_capacity(document.verification_methods.len());
        for (key_ref, public_key_material) in &document.verification_methods {
            accepted_signing_keys.push(AppletAcceptedSigningKeyEvidence {
                key_ref: normalize_applet_signing_key_ref(&document.id, key_ref),
                public_key_digest: applet_signing_key_material_digest(public_key_material)?,
            });
        }
        if accepted_signing_keys.is_empty() {
            return Err(Error::Protocol(
                "applet registration_epoch evidence has no signing keys".to_owned(),
            ));
        }
        Ok(Self {
            service_id: document.id.clone(),
            did_document_digest,
            method_version_evidence,
            accepted_signing_keys,
        })
    }

    pub fn validate_against_did_document(
        &self,
        document: &DidDocument,
    ) -> std::result::Result<(), AppletEpochEvidenceError> {
        if self.service_id != document.id {
            return Err(AppletEpochEvidenceError::ServiceIdMismatch);
        }
        let actual_document_digest = applet_did_document_digest(document).map_err(|error| {
            AppletEpochEvidenceError::DidDocumentDigestFailed(error.to_string())
        })?;
        if self.did_document_digest != actual_document_digest {
            return Err(AppletEpochEvidenceError::DidDocumentDigestMismatch);
        }
        if self.accepted_signing_keys.is_empty() {
            return Err(AppletEpochEvidenceError::SigningKeySetEmpty);
        }
        if self.method_version_evidence.validate().is_err() {
            return Err(AppletEpochEvidenceError::DidDocumentDigestFailed(
                "invalid DID method version evidence".to_owned(),
            ));
        }

        let mut captured = BTreeMap::new();
        for key in &self.accepted_signing_keys {
            if captured
                .insert(key.key_ref.clone(), key.public_key_digest.clone())
                .is_some()
            {
                return Err(AppletEpochEvidenceError::SigningKeySetMismatch);
            }
        }
        let mut current = BTreeMap::new();
        for (key_ref, public_key_material) in &document.verification_methods {
            let normalized = normalize_applet_signing_key_ref(&self.service_id, key_ref);
            let digest =
                applet_signing_key_material_digest(public_key_material).map_err(|error| {
                    AppletEpochEvidenceError::SigningKeyDigestFailed(error.to_string())
                })?;
            current.insert(normalized, digest);
        }
        for key_ref in captured.keys() {
            if !current.contains_key(key_ref) {
                return Err(AppletEpochEvidenceError::SigningKeyMissing(key_ref.clone()));
            }
        }
        if captured != current {
            return Err(AppletEpochEvidenceError::SigningKeySetMismatch);
        }
        Ok(())
    }

    pub fn contains_signing_key(&self, verification_method: &str) -> bool {
        let key_ref = normalize_applet_signing_key_ref(&self.service_id, verification_method);
        self.accepted_signing_keys
            .iter()
            .any(|key| key.key_ref == key_ref)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRegistrationEpochSecurityPolicy {
    pub claimed_profiles: Vec<String>,
    pub limits: AppletLimits,
    pub ghost_policy: AppletGhostPolicy,
    pub delegation_policy: DelegationPolicy,
    pub e2ee_policy: AppletPackageE2eePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget: Option<Widget>,
}

/// Closed normalized transcript hashed to derive `registration_epoch`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletRegistrationEpochTranscript {
    pub schema: String,
    pub derived_registration: AppletRegistrationEpochDerivedRegistration,
    pub service_did_document: AppletRegistrationEpochDidDocument,
    pub accepted_signing_keys: Vec<AppletAcceptedSigningKeyEvidence>,
    pub endpoint_policy: AppletEndpointPolicy,
    pub webhook_auth: WebhookAuth,
    pub security_policy: AppletRegistrationEpochSecurityPolicy,
}

impl AppletRegistrationEpochTranscript {
    pub const SCHEMA: &'static str = "ak.schema.applet_registration_epoch_transcript.v1";
    pub const DOMAIN_SEPARATOR: &'static [u8] = b"arkret-applet-registration-epoch-v1\n";

    pub fn from_package(
        package: &AppletPackage,
        evidence: &AppletRegistrationEpochEvidence,
    ) -> Result<Self> {
        if package.service_id != evidence.service_id {
            return Err(Error::Protocol(
                "applet registration epoch evidence service_id mismatch".to_owned(),
            ));
        }
        let mut transcript = Self {
            schema: Self::SCHEMA.to_owned(),
            derived_registration: AppletRegistrationEpochDerivedRegistration {
                kind: WireAppletRegistration::KIND.to_owned(),
                applet_id: package.applet_id.clone(),
                service_id: package.service_id.clone(),
                controller_id: package.controller_id.clone(),
                base_url: package.base_url.clone(),
                bot_actor_id: package.bot_actor_id.clone(),
                protocols: package.protocols.clone(),
                namespaces: package.namespaces.clone(),
                receive_events: package.receive_events,
                receive_ephemeral: package.receive_ephemeral,
                rate_limited: package.rate_limited,
                requested_scopes: package.requested_scopes.clone(),
                created_at: package.created_at,
            },
            service_did_document: AppletRegistrationEpochDidDocument {
                service_id: evidence.service_id.clone(),
                document_digest: evidence.did_document_digest.clone(),
                method_version: evidence.method_version_evidence.clone(),
            },
            accepted_signing_keys: evidence.accepted_signing_keys.clone(),
            endpoint_policy: package.endpoint_policy.clone(),
            webhook_auth: package.webhook_auth.clone(),
            security_policy: AppletRegistrationEpochSecurityPolicy {
                claimed_profiles: package.claimed_profiles.clone(),
                limits: package.limits.clone(),
                ghost_policy: package.ghost_policy.clone(),
                delegation_policy: package.delegation_policy.clone(),
                e2ee_policy: package.e2ee_policy.clone(),
                widget: package.widget.clone(),
            },
        };
        transcript.normalize()?;
        transcript.validate_normalized()?;
        Ok(transcript)
    }

    pub fn normalize(&mut self) -> Result<()> {
        sort_unique_strings("protocols", &mut self.derived_registration.protocols)?;
        sort_namespace_entries(
            "namespaces.actors",
            &mut self.derived_registration.namespaces.actors,
        )?;
        sort_namespace_entries(
            "namespaces.realms",
            &mut self.derived_registration.namespaces.realms,
        )?;
        sort_namespace_entries(
            "namespaces.handles",
            &mut self.derived_registration.namespaces.handles,
        )?;
        sort_unique_strings(
            "requested_scopes",
            &mut self.derived_registration.requested_scopes,
        )?;
        sort_unique_strings(
            "claimed_profiles",
            &mut self.security_policy.claimed_profiles,
        )?;
        self.accepted_signing_keys
            .sort_by(|left, right| left.key_ref.as_bytes().cmp(right.key_ref.as_bytes()));
        reject_duplicate_adjacent_by(
            "accepted_signing_keys",
            &self.accepted_signing_keys,
            |left, right| left.key_ref == right.key_ref,
        )?;
        self.webhook_auth.accepted_algs.sort_by(|left, right| {
            left.as_wire_name()
                .as_bytes()
                .cmp(right.as_wire_name().as_bytes())
        });
        reject_duplicate_adjacent_by(
            "webhook_auth.accepted_algs",
            &self.webhook_auth.accepted_algs,
            |left, right| left == right,
        )?;
        self.endpoint_policy.endpoints.sort_by(|left, right| {
            (left.method, left.path.as_bytes(), left.auth).cmp(&(
                right.method,
                right.path.as_bytes(),
                right.auth,
            ))
        });
        reject_duplicate_adjacent_by(
            "endpoint_policy.endpoints",
            &self.endpoint_policy.endpoints,
            |left, right| {
                left.method == right.method && left.path == right.path && left.auth == right.auth
            },
        )
    }

    pub fn validate_normalized(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(
                "applet registration epoch transcript schema mismatch".to_owned(),
            ));
        }
        if self.derived_registration.kind != WireAppletRegistration::KIND {
            return Err(Error::Protocol(
                "applet registration epoch transcript kind mismatch".to_owned(),
            ));
        }
        if self.derived_registration.service_id != self.service_did_document.service_id {
            return Err(Error::Protocol(
                "applet registration epoch transcript service_id mismatch".to_owned(),
            ));
        }
        self.service_did_document.method_version.validate()?;
        let expected_method = did_method_name(&self.service_did_document.service_id)?;
        if self.service_did_document.method_version.method != expected_method {
            return Err(Error::Protocol(
                "applet registration epoch DID method evidence mismatch".to_owned(),
            ));
        }
        let service_key_prefix = format!("{}#", self.service_did_document.service_id);
        if !self.webhook_auth.key_ref.starts_with(&service_key_prefix)
            || self
                .accepted_signing_keys
                .iter()
                .any(|key| !key.key_ref.starts_with(&service_key_prefix))
        {
            return Err(Error::Protocol(
                "applet registration epoch signing key is outside service DID".to_owned(),
            ));
        }
        if !self
            .accepted_signing_keys
            .iter()
            .any(|key| key.key_ref == self.webhook_auth.key_ref)
        {
            return Err(Error::Protocol(
                "applet registration epoch webhook key is not accepted".to_owned(),
            ));
        }
        validate_strictly_sorted_strings("protocols", &self.derived_registration.protocols)?;
        validate_namespace_entries(
            "namespaces.actors",
            &self.derived_registration.namespaces.actors,
        )?;
        validate_namespace_entries(
            "namespaces.realms",
            &self.derived_registration.namespaces.realms,
        )?;
        validate_namespace_entries(
            "namespaces.handles",
            &self.derived_registration.namespaces.handles,
        )?;
        validate_strictly_sorted_strings(
            "requested_scopes",
            &self.derived_registration.requested_scopes,
        )?;
        validate_strictly_sorted_strings(
            "claimed_profiles",
            &self.security_policy.claimed_profiles,
        )?;
        validate_strictly_sorted_by(
            "accepted_signing_keys",
            &self.accepted_signing_keys,
            |left, right| left.key_ref.as_bytes().cmp(right.key_ref.as_bytes()),
        )?;
        validate_strictly_sorted_by(
            "webhook_auth.accepted_algs",
            &self.webhook_auth.accepted_algs,
            |left, right| {
                left.as_wire_name()
                    .as_bytes()
                    .cmp(right.as_wire_name().as_bytes())
            },
        )?;
        validate_strictly_sorted_by(
            "endpoint_policy.endpoints",
            &self.endpoint_policy.endpoints,
            |left, right| {
                (left.method, left.path.as_bytes(), left.auth).cmp(&(
                    right.method,
                    right.path.as_bytes(),
                    right.auth,
                ))
            },
        )?;
        if self.accepted_signing_keys.is_empty()
            || self.endpoint_policy.endpoints.is_empty()
            || self.webhook_auth.accepted_algs.is_empty()
            || self.security_policy.claimed_profiles.is_empty()
        {
            return Err(Error::Protocol(
                "applet registration epoch transcript contains an empty required set".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        self.validate_normalized()?;
        Ok(canonical::canonical_json_bytes(self)?)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let canonical_bytes = self.canonical_json_bytes()?;
        let mut bytes = Vec::with_capacity(Self::DOMAIN_SEPARATOR.len() + canonical_bytes.len());
        bytes.extend_from_slice(Self::DOMAIN_SEPARATOR);
        bytes.extend_from_slice(&canonical_bytes);
        Ok(bytes)
    }

    pub fn registration_epoch(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(&self.signing_bytes()?)).map_err(Into::into)
    }
}

fn sort_unique_strings(context: &str, values: &mut [String]) -> Result<()> {
    values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    reject_duplicate_adjacent_by(context, values, |left, right| left == right)
}

fn sort_namespace_entries(context: &str, values: &mut [AppletNamespaceEntry]) -> Result<()> {
    values.sort_by(|left, right| {
        (left.pattern.as_bytes(), left.exclusive).cmp(&(right.pattern.as_bytes(), right.exclusive))
    });
    reject_duplicate_adjacent_by(context, values, |left, right| left.pattern == right.pattern)
}

fn validate_namespace_entries(context: &str, values: &[AppletNamespaceEntry]) -> Result<()> {
    validate_strictly_sorted_by(context, values, |left, right| {
        (left.pattern.as_bytes(), left.exclusive).cmp(&(right.pattern.as_bytes(), right.exclusive))
    })
}

fn validate_strictly_sorted_strings(context: &str, values: &[String]) -> Result<()> {
    validate_strictly_sorted_by(context, values, |left, right| {
        left.as_bytes().cmp(right.as_bytes())
    })
}

fn validate_strictly_sorted_by<T>(
    context: &str,
    values: &[T],
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<()> {
    if values
        .windows(2)
        .any(|pair| compare(&pair[0], &pair[1]) != std::cmp::Ordering::Less)
    {
        return Err(Error::Protocol(format!(
            "applet registration epoch {context} is unsorted or contains duplicates"
        )));
    }
    Ok(())
}

fn reject_duplicate_adjacent_by<T>(
    context: &str,
    values: &[T],
    equal: impl Fn(&T, &T) -> bool,
) -> Result<()> {
    if values.windows(2).any(|pair| equal(&pair[0], &pair[1])) {
        return Err(Error::Protocol(format!(
            "applet registration epoch {context} contains duplicate entries"
        )));
    }
    Ok(())
}

fn did_method_name(did: &Did) -> Result<&str> {
    let value = did.as_str();
    let method_end = value[4..]
        .find(':')
        .map(|offset| offset + 4)
        .ok_or_else(|| Error::Protocol("DID method delimiter is missing".to_owned()))?;
    Ok(&value[..method_end])
}

pub fn applet_did_document_digest(document: &DidDocument) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(document)?).map_err(Into::into)
}

// ─── S-13 (2026-06-04): Applet Package + install aggregate objects ────────
//
// Spec `applet-schema.md` §1a/§1b + `applet-integration.md` §4a/§4b. The
// Package is a controller-signed *distribution* object: it is NOT Realm
// history and NOT a grant. The Principal Server / authz service derives a
// canonical `ak.applet.registration` and capability grants during
// `ak.self.applet.command.install`.

/// Controller-signed installable Applet package (`ak.schema.applet_package.v1`).
///
/// Build it unsigned via [`AppletPackage::new`], [`seal`](Self::seal) to
/// stamp `package_digest`, then [`sign`](Self::sign) with the controller
/// signer. [`to_registration`](Self::to_registration) performs the
/// spec §1a Package→registration derivation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletPackage {
    /// Always `ak.schema.applet_package.v1`.
    pub schema: String,
    /// Distribution identifier only — never a grant subject.
    pub package_id: String,
    /// DID or `ak:applet:<uuidv7>`.
    pub applet_id: String,
    pub service_id: Did,
    pub controller_id: Did,
    pub base_url: String,
    /// Visible bot actor DID; MUST NOT carry a `#fragment`.
    pub bot_actor_id: Did,
    /// MUST contain at least `ak.profile.applet_service.v1`.
    pub claimed_profiles: Vec<String>,
    pub protocols: Vec<String>,
    pub namespaces: AppletWireNamespaces,
    /// Capability action request list for approval UI only, never a grant.
    pub requested_scopes: Vec<String>,
    /// Supported Applet API endpoints + auth requirements
    /// (`applet-package.schema.json#/$defs/endpoint_policy`).
    /// Renamed `endpoint_set` → `endpoint_policy` (2026-06-10, hard_reject;
    /// `normative-language.md` §7 forbids `*_set` wire suffixes).
    pub endpoint_policy: AppletEndpointPolicy,
    /// HTTP message signature key ref / accepted algorithms.
    pub webhook_auth: WebhookAuth,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    /// Max transaction events / payload bytes / rate-limit hint
    /// (`applet-package.schema.json#/$defs/limits`).
    pub limits: AppletLimits,
    /// Ghost Actor support + accountability template
    /// (`applet-package.schema.json#/$defs/ghost_policy`).
    pub ghost_policy: AppletGhostPolicy,
    /// Delegated native-user acting request; defaults to disabled.
    pub delegation_policy: DelegationPolicy,
    /// MLS join request; defaults to disabled.
    pub e2ee_policy: AppletPackageE2eePolicy,
    /// Widget origin / CSP / token scope / consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget: Option<Widget>,
    /// Captured DID document + signing-key evidence covered by
    /// `registration_epoch`.
    #[serde(skip_serializing)]
    pub registration_epoch_evidence: Option<AppletRegistrationEpochEvidence>,
    /// Canonical package hash (excludes `package_digest` + `proof`).
    /// `None` until [`seal`](Self::seal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_digest: Option<Hash>,
    /// Canonical security epoch hash. New packages start with the all-zero
    /// sentinel and MUST call [`seal_registration_epoch`](Self::seal_registration_epoch)
    /// after all security-relevant fields and evidence are finalized.
    pub registration_epoch: Hash,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    /// Controller DID detached proof. `None` until [`sign`](Self::sign).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl AppletPackage {
    pub const SCHEMA: &'static str = "ak.schema.applet_package.v1";
    /// The base profile every Applet package MUST claim.
    pub const BASE_PROFILE: &'static str = "ak.profile.applet_service.v1";

    /// Build an unsigned, unsealed package. Caller MUST
    /// [`seal`](Self::seal) then [`sign`](Self::sign) before publishing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: impl Into<String>,
        applet_id: impl Into<String>,
        service_id: Did,
        controller_id: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        protocols: Vec<String>,
        namespaces: AppletWireNamespaces,
    ) -> Self {
        let webhook_key_ref = format!("{}#applet-webhook", service_id.as_str());
        Self {
            schema: Self::SCHEMA.to_owned(),
            package_id: package_id.into(),
            applet_id: applet_id.into(),
            service_id,
            controller_id,
            base_url: base_url.into(),
            bot_actor_id,
            claimed_profiles: vec![Self::BASE_PROFILE.to_owned()],
            protocols,
            namespaces,
            requested_scopes: Vec::new(),
            endpoint_policy: AppletEndpointPolicy::default(),
            webhook_auth: WebhookAuth::http_message_signature(
                webhook_key_ref,
                vec![WebhookSignatureAlg::EdDsa],
            ),
            receive_events: false,
            receive_ephemeral: false,
            rate_limited: true,
            limits: AppletLimits::default(),
            ghost_policy: AppletGhostPolicy::default(),
            delegation_policy: DelegationPolicy::default(),
            e2ee_policy: AppletPackageE2eePolicy {
                enabled: false,
                mls_join_requested: Some(false),
                extensions: XExtensionMap::default(),
            },
            widget: None,
            registration_epoch_evidence: None,
            package_digest: None,
            registration_epoch: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .expect("the registration epoch sentinel is a valid SHA-256 hash"),
            created_at: Utc::now(),
            expires_at: None,
            proof: None,
        }
    }

    /// Build the normalized closed transcript for the package's current
    /// security-relevant fields.
    pub fn registration_epoch_transcript(
        &self,
        evidence: &AppletRegistrationEpochEvidence,
    ) -> Result<AppletRegistrationEpochTranscript> {
        AppletRegistrationEpochTranscript::from_package(self, evidence)
    }

    /// Recompute the registration epoch using the v1 domain-separated
    /// transcript algorithm.
    pub fn compute_registration_epoch(
        &self,
        evidence: &AppletRegistrationEpochEvidence,
    ) -> Result<Hash> {
        self.registration_epoch_transcript(evidence)?
            .registration_epoch()
    }

    /// Capture local evidence and stamp the recomputed registration epoch.
    /// Call this after changing any package field covered by the transcript
    /// and before [`seal`](Self::seal).
    pub fn seal_registration_epoch(
        &mut self,
        evidence: AppletRegistrationEpochEvidence,
    ) -> Result<()> {
        self.registration_epoch = self.compute_registration_epoch(&evidence)?;
        self.registration_epoch_evidence = Some(evidence);
        self.package_digest = None;
        self.proof = None;
        Ok(())
    }

    /// Canonical SHA256 over the package with `package_digest` **and**
    /// `proof` cleared, so the digest never depends on itself or the
    /// signature.
    pub fn compute_package_digest(&self) -> Result<Hash> {
        let mut bare = self.clone();
        bare.package_digest = None;
        bare.proof = None;
        Hash::new(canonical::canonical_sha256(&bare)?).map_err(Into::into)
    }

    /// Compute and stamp `package_digest`.
    pub fn seal(&mut self) -> Result<()> {
        let evidence = self.registration_epoch_evidence.as_ref().ok_or_else(|| {
            Error::Protocol("applet package registration_epoch_evidence is missing".to_owned())
        })?;
        if self.compute_registration_epoch(evidence)? != self.registration_epoch {
            return Err(Error::Protocol(
                "applet package registration_epoch does not match its transcript".to_owned(),
            ));
        }
        self.package_digest = Some(self.compute_package_digest()?);
        Ok(())
    }

    /// Sign the canonical package (with `proof` removed) using the
    /// controller signer and stamp `proof`. Call [`seal`](Self::seal)
    /// first so the digest is part of the signed bytes.
    pub fn sign<S: MoveSigner + ?Sized>(
        &mut self,
        signer: &S,
        verification_method: &str,
    ) -> Result<()> {
        let mut unsigned = self.clone();
        unsigned.proof = None;
        let canonical_bytes = canonical::canonical_json_bytes(&unsigned)?;
        let payload_digest = Hash::new(canonical::sha256_digest(&canonical_bytes))?;
        let sig = signer.sign_payload(&canonical_bytes)?;
        self.proof = Some(Proof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: sig.alg,
            verification_method: verification_method.to_owned(),
            event_digest: payload_digest,
            created_at: Utc::now(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: sig.jws,
        });
        Ok(())
    }

    /// Validate the sealed, signed package against the spec §1a required
    /// fields. Rejects a missing base profile, empty protocol /
    /// requested-scope lists, and an unsealed or unsigned package.
    pub fn validate(&self) -> Result<()> {
        self.validate_wire()?;
        let evidence = self.registration_epoch_evidence.as_ref().ok_or_else(|| {
            Error::Protocol("applet package registration_epoch_evidence is missing".to_owned())
        })?;
        self.validate_with_epoch_evidence(evidence)
    }

    pub fn validate_wire(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol("applet package schema mismatch".to_owned()));
        }
        if self.package_id.is_empty() || self.applet_id.is_empty() || self.base_url.is_empty() {
            return Err(Error::Protocol(
                "applet package missing required fields".to_owned(),
            ));
        }
        if !self
            .claimed_profiles
            .iter()
            .any(|profile| profile == Self::BASE_PROFILE)
        {
            return Err(Error::Protocol(
                "applet package MUST claim ak.profile.applet_service.v1".to_owned(),
            ));
        }
        if self.protocols.is_empty() {
            return Err(Error::Protocol(
                "applet package protocols are empty".to_owned(),
            ));
        }
        if self.requested_scopes.is_empty() {
            return Err(Error::Protocol(
                "applet package requested_scopes are empty".to_owned(),
            ));
        }
        validate_applet_extension_fields("endpoint_policy", &self.endpoint_policy.extra)?;
        for endpoint in &self.endpoint_policy.endpoints {
            validate_applet_extension_fields("endpoint_policy.endpoints", &endpoint.extra)?;
        }
        validate_applet_extension_fields("limits", &self.limits.extra)?;
        validate_applet_extension_fields("ghost_policy", &self.ghost_policy.extra)?;
        validate_applet_extension_fields("delegation_policy", &self.delegation_policy.extra)?;
        validate_applet_extension_fields("e2ee_policy", &self.e2ee_policy.extensions)?;
        let Some(package_digest) = &self.package_digest else {
            return Err(Error::Protocol("applet package is not sealed".to_owned()));
        };
        if package_digest != &self.compute_package_digest()? {
            return Err(Error::Protocol(
                "applet package digest does not match its canonical content".to_owned(),
            ));
        }
        if self.proof.is_none() {
            return Err(Error::Protocol("applet package is not signed".to_owned()));
        }
        Ok(())
    }

    pub fn validate_with_epoch_evidence(
        &self,
        evidence: &AppletRegistrationEpochEvidence,
    ) -> Result<()> {
        self.validate_wire()?;
        if evidence.service_id != self.service_id {
            return Err(Error::Protocol(
                "applet package registration_epoch_evidence service_id mismatch".to_owned(),
            ));
        }
        if evidence.accepted_signing_keys.is_empty() {
            return Err(Error::Protocol(
                "applet package registration_epoch_evidence signing keys are empty".to_owned(),
            ));
        }
        let recomputed = self.compute_registration_epoch(evidence)?;
        if recomputed != self.registration_epoch {
            return Err(Error::Protocol(
                "applet package registration_epoch does not match its transcript".to_owned(),
            ));
        }
        Ok(())
    }

    /// Manifest snapshot folded into the derived registration's
    /// `manifest` slot (spec §1a derivation row `manifest`).
    pub fn manifest_snapshot(&self) -> BTreeMap<String, Value> {
        let mut manifest = serde_json::Map::new();
        manifest.insert(
            "claimed_profiles".to_owned(),
            Value::Array(
                self.claimed_profiles
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        manifest.insert(
            "limits".to_owned(),
            serde_json::to_value(&self.limits).unwrap_or(Value::Null),
        );
        manifest.insert(
            "ghost_policy".to_owned(),
            serde_json::to_value(&self.ghost_policy).unwrap_or(Value::Null),
        );
        manifest.insert(
            "delegation_policy".to_owned(),
            serde_json::to_value(&self.delegation_policy).unwrap_or(Value::Null),
        );
        manifest.insert(
            "e2ee_policy".to_owned(),
            serde_json::to_value(&self.e2ee_policy).unwrap_or(Value::Null),
        );
        if let Some(widget) = &self.widget {
            manifest.insert(
                "widget".to_owned(),
                serde_json::to_value(widget).unwrap_or(Value::Null),
            );
        }
        if let Some(evidence) = &self.registration_epoch_evidence
            && let Ok(value) = serde_json::to_value(evidence)
        {
            manifest.insert("registration_epoch_evidence".to_owned(), value);
        }
        manifest.into_iter().collect()
    }

    /// Derive the canonical `ak.applet.registration` payload per the
    /// spec §1a mapping table. The package `proof` is carried over; the
    /// authz service still re-verifies / re-signs the derived
    /// registration before fan-out.
    pub fn to_registration(&self) -> Result<WireAppletRegistration> {
        self.validate()?;
        let mut reg = WireAppletRegistration::new(
            self.applet_id.clone(),
            self.service_id.clone(),
            self.controller_id.clone(),
            self.base_url.clone(),
            self.bot_actor_id.clone(),
            self.protocols.clone(),
            self.namespaces.clone(),
            self.registration_epoch.clone(),
        );
        reg.receive_events = self.receive_events;
        reg.receive_ephemeral = self.receive_ephemeral;
        reg.rate_limited = self.rate_limited;
        reg.requested_scopes = self.requested_scopes.clone();
        reg.webhook_auth = Some(self.webhook_auth.clone());
        reg.manifest = Some(self.manifest_snapshot());
        reg.created_at = self.created_at;
        reg.proof = self.proof.clone();
        Ok(reg)
    }
}

fn validate_applet_extension_fields(context: &str, fields: &BTreeMap<String, Value>) -> Result<()> {
    for name in fields.keys() {
        let Some(suffix) = name.strip_prefix("x_") else {
            return Err(Error::Protocol(format!(
                "{context} contains non-extension field {name}"
            )));
        };
        if suffix.is_empty()
            || suffix.len() > 64
            || !suffix.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
        {
            return Err(Error::Protocol(format!(
                "{context} contains invalid extension field {name}"
            )));
        }
    }
    Ok(())
}
