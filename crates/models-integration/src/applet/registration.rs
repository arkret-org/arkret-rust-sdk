use std::collections::BTreeMap;

use arkret_wire::{
    Did, Error, Hash, MoveSigner, Proof, Result, XExtensionMap, canonical, proof_kind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::namespace_match::namespace_patterns_overlap;

/// Which namespace bucket a claim lives in. The wire model
/// (`applet-schema.md` §1.namespaces) groups claims into exactly
/// `actors` / `realms` / `handles`; the bucket — not a separate `kind`
/// field — determines the segment separator set used for pattern
/// matching (§2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WebhookAuthType {
    HttpMessageSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    /// ordering (`AppletRegistrationEpochTranscript` in `arkret-core`).
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

#[cfg(feature = "salvo-oapi")]
impl salvo::oapi::ToSchema for WebhookAuth {
    fn to_schema(
        components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        use salvo::oapi::Object;

        Object::new()
            .property("type", WebhookAuthType::to_schema(components))
            .required("type")
            .property("key_ref", String::to_schema(components))
            .required("key_ref")
            .property(
                "accepted_algs",
                Vec::<WebhookSignatureAlg>::to_schema(components),
            )
            .required("accepted_algs")
            .property("signature_header", String::to_schema(components))
            .into()
    }
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletEndpointEntry {
    pub method: AppletEndpointMethod,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AppletEndpointAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `x_`-prefixed protocol extension members
    /// (`patternProperties ^x_[a-z][a-z0-9_]{0,63}$`).
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletEndpointPolicy {
    #[serde(default)]
    pub endpoints: Vec<AppletEndpointEntry>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Service-side resource hints derived into the registration manifest
/// (`applet-package.schema.json#/$defs/limits`). All members are optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transaction_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_minute: Option<u64>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

/// Ghost Actor support and accountability template
/// (`applet-package.schema.json#/$defs/ghost_policy`). `enabled` is required;
/// it carries no `default` in the schema, so it is a non-`Option` field that
/// the producer MUST set explicitly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletGhostPolicy {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_template: Option<String>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AppletAcceptedSigningKeyEvidence {
    pub key_ref: String,
    pub public_key_digest: Hash,
}

/// Method-specific resolution evidence captured with an Applet registration
/// epoch. Versioned methods carry at least one stable version selector;
/// unversioned methods carry neither selector and require a fresh canonical
/// resolution whenever the epoch is verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
/// it from an `AppletPackage` (in `arkret-core`) with
/// `AppletPackage::to_registration`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    /// `AppletPackage::seal_registration_epoch` (both in `arkret-core`).
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_auth: Option<WebhookAuth>,
    /// Optional manifest snapshot (claimed profiles, limits, policies,
    /// widget) per `applet_registration_payload.manifest`. Populated by
    /// `AppletPackage::to_registration`; never a substitute for the
    /// top-level required fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<BTreeMap<String, Value>>,
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
