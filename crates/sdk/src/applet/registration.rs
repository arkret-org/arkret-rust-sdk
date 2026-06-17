use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::namespace_match::namespace_patterns_overlap;
use crate::{Did, Error, Proof, Result, canonical};

/// Which namespace bucket a claim lives in. The wire model
/// (`applet-schema.md` §1.namespaces) groups claims into exactly
/// `actors` / `realms` / `handles`; the bucket — not a separate `kind`
/// field — determines the segment separator set used for pattern
/// matching (§2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
/// [`InstallPlan::namespace_conflicts`] and by
/// [`AppletWireNamespaces::conflicts_with`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletNamespaceConflict {
    pub domain: AppletNamespaceDomain,
    pub pattern: String,
    pub conflicting_pattern: String,
}

// ─── wire-format `ck.applet.registration` (spec `applet-schema.md` §1) ─────

/// A single namespace claim entry. Wire shape per `applet-schema.md`
/// §2: an `{ exclusive, pattern }` object, NOT a bare pattern string.
/// `exclusive` claims reject any later registrant whose pattern overlaps
/// (see [`AppletWireNamespaces::conflicts_with`]); non-exclusive claims
/// may coexist.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WebhookAuthType {
    HttpMessageSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum WebhookSignatureAlg {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
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
    pub extra: BTreeMap<String, Value>,
}

#[cfg(feature = "salvo")]
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
            extra: BTreeMap::new(),
        }
    }
}

/// Wire-format `ck.applet.registration` Event content per spec
/// `applet-schema.md` §1 (authoritative `applet_registration_payload`).
///
/// This is the on-the-wire shape every external Applet implementation
/// sends. Build it directly via [`WireAppletRegistration::new`] or derive
/// it from an [`AppletPackage`] with [`AppletPackage::to_registration`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct WireAppletRegistration {
    /// Always `"ck.applet.registration"`. Reducer rejects other values.
    pub kind: String,
    pub applet_id: String,
    pub service_did: Did,
    pub controller_did: Did,
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
    /// grants bind this epoch (`applet-integration.md` §11). The SDK
    /// cannot synthesize the full evidence digest, so the caller MUST
    /// supply it.
    pub registration_epoch: crate::Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_auth: Option<WebhookAuth>,
    /// Optional manifest snapshot (claimed profiles, limits, policies,
    /// widget) per `applet_registration_payload.manifest`. Populated by
    /// [`AppletPackage::to_registration`]; never a substitute for the
    /// top-level required fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Value>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl WireAppletRegistration {
    pub const KIND: &'static str = "ck.applet.registration";

    /// Build an unsigned registration. Caller MUST attach `proof` via
    /// [`sign_registration`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applet_id: impl Into<String>,
        service_did: Did,
        controller_did: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        protocols: Vec<String>,
        namespaces: AppletWireNamespaces,
        registration_epoch: crate::Hash,
    ) -> Self {
        Self {
            kind: Self::KIND.to_owned(),
            applet_id: applet_id.into(),
            service_did,
            controller_did,
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
    pub fn payload_digest(&self) -> Result<crate::Hash> {
        let mut unsigned = self.clone();
        unsigned.proof = None;
        let hash = canonical::canonical_sha256(&unsigned)?;
        crate::Hash::new(hash).map_err(Into::into)
    }
}

/// Sign a [`WireAppletRegistration`] in-place: compute the canonical
/// digest (with `proof` removed), sign it with the supplied
/// [`cokret_core::MoveSigner`], and stamp `reg.proof`.
pub fn sign_registration<S: cokret_core::MoveSigner + ?Sized>(
    reg: &mut WireAppletRegistration,
    signer: &S,
    verification_method: &str,
) -> Result<()> {
    let mut unsigned = reg.clone();
    unsigned.proof = None;
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned)?;
    let payload_digest = crate::Hash::new(canonical::sha256_digest(&canonical_bytes))?;
    let sig = signer.sign_payload(&canonical_bytes)?;
    reg.proof = Some(Proof {
        kind: cokret_core::proof_kind::DETACHED_JWS.to_owned(),
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

// ─── S-13 (2026-06-04): Applet Package + install aggregate objects ────────
//
// Spec `applet-schema.md` §1a/§1b + `applet-integration.md` §4a/§4b. The
// Package is a controller-signed *distribution* object: it is NOT Realm
// history and NOT a grant. The Principal Server / authz service derives a
// canonical `ck.applet.registration` and capability grants during
// `ck.self.applet.command.install`.

/// Controller-signed installable Applet package (`ck.schema.applet_package.v1`).
///
/// Build it unsigned via [`AppletPackage::new`], [`seal`](Self::seal) to
/// stamp `package_digest`, then [`sign`](Self::sign) with the controller
/// signer. [`to_registration`](Self::to_registration) performs the
/// spec §1a Package→registration derivation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletPackage {
    /// Always `ck.schema.applet_package.v1`.
    pub schema: String,
    /// Distribution identifier only — never a grant subject.
    pub package_id: String,
    /// DID or `ck:applet:<uuidv7>`.
    pub applet_id: String,
    pub service_did: Did,
    pub controller_did: Did,
    pub base_url: String,
    /// Visible bot actor DID; MUST NOT carry a `#fragment`.
    pub bot_actor_id: Did,
    /// MUST contain at least `ck.profile.applet_service.v1`.
    pub claimed_profiles: Vec<String>,
    pub protocols: Vec<String>,
    pub namespaces: AppletWireNamespaces,
    /// Capability action request list for approval UI only, never a grant.
    pub requested_scopes: Vec<String>,
    /// Supported Applet API endpoints + auth requirements (open shape).
    /// Renamed `endpoint_set` → `endpoint_policy` (2026-06-10, hard_reject;
    /// `normative-language.md` §7 forbids `*_set` wire suffixes).
    pub endpoint_policy: Value,
    /// HTTP message signature key ref / accepted algorithms.
    pub webhook_auth: WebhookAuth,
    pub receive_events: bool,
    pub receive_ephemeral: bool,
    pub rate_limited: bool,
    /// Max transaction events / payload bytes / rate-limit hint.
    pub limits: Value,
    /// Ghost Actor support + accountability template.
    pub ghost_policy: Value,
    /// Delegated native-user acting request; defaults to disabled.
    pub delegation_policy: Value,
    /// MLS join request; defaults to disabled.
    pub e2ee_policy: Value,
    /// Widget origin / CSP / token scope / consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget: Option<Value>,
    /// Canonical package hash (excludes `package_digest` + `proof`).
    /// `None` until [`seal`](Self::seal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_digest: Option<crate::Hash>,
    /// Canonical security epoch hash; copied verbatim to the derived
    /// registration.
    pub registration_epoch: crate::Hash,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Controller DID detached proof. `None` until [`sign`](Self::sign).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl AppletPackage {
    pub const SCHEMA: &'static str = "ck.schema.applet_package.v1";
    /// The base profile every Applet package MUST claim.
    pub const BASE_PROFILE: &'static str = "ck.profile.applet_service.v1";

    /// Build an unsigned, unsealed package. Caller MUST
    /// [`seal`](Self::seal) then [`sign`](Self::sign) before publishing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: impl Into<String>,
        applet_id: impl Into<String>,
        service_did: Did,
        controller_did: Did,
        base_url: impl Into<String>,
        bot_actor_id: Did,
        protocols: Vec<String>,
        namespaces: AppletWireNamespaces,
        registration_epoch: crate::Hash,
    ) -> Self {
        let webhook_key_ref = format!("{}#applet-webhook", controller_did.as_str());
        Self {
            schema: Self::SCHEMA.to_owned(),
            package_id: package_id.into(),
            applet_id: applet_id.into(),
            service_did,
            controller_did,
            base_url: base_url.into(),
            bot_actor_id,
            claimed_profiles: vec![Self::BASE_PROFILE.to_owned()],
            protocols,
            namespaces,
            requested_scopes: Vec::new(),
            endpoint_policy: Value::Object(Default::default()),
            webhook_auth: WebhookAuth::http_message_signature(
                webhook_key_ref,
                vec![WebhookSignatureAlg::EdDsa],
            ),
            receive_events: false,
            receive_ephemeral: false,
            rate_limited: true,
            limits: Value::Object(Default::default()),
            ghost_policy: Value::Object(Default::default()),
            delegation_policy: Value::Object(Default::default()),
            e2ee_policy: Value::Object(Default::default()),
            widget: None,
            package_digest: None,
            registration_epoch,
            created_at: Utc::now(),
            expires_at: None,
            proof: None,
        }
    }

    /// Canonical SHA256 over the package with `package_digest` **and**
    /// `proof` cleared, so the digest never depends on itself or the
    /// signature.
    pub fn compute_package_digest(&self) -> Result<crate::Hash> {
        let mut bare = self.clone();
        bare.package_digest = None;
        bare.proof = None;
        crate::Hash::new(canonical::canonical_sha256(&bare)?).map_err(Into::into)
    }

    /// Compute and stamp `package_digest`.
    pub fn seal(&mut self) -> Result<()> {
        self.package_digest = Some(self.compute_package_digest()?);
        Ok(())
    }

    /// Sign the canonical package (with `proof` removed) using the
    /// controller signer and stamp `proof`. Call [`seal`](Self::seal)
    /// first so the digest is part of the signed bytes.
    pub fn sign<S: cokret_core::MoveSigner + ?Sized>(
        &mut self,
        signer: &S,
        verification_method: &str,
    ) -> Result<()> {
        let mut unsigned = self.clone();
        unsigned.proof = None;
        let canonical_bytes = canonical::canonical_json_bytes(&unsigned)?;
        let payload_digest = crate::Hash::new(canonical::sha256_digest(&canonical_bytes))?;
        let sig = signer.sign_payload(&canonical_bytes)?;
        self.proof = Some(Proof {
            kind: cokret_core::proof_kind::DETACHED_JWS.to_owned(),
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

    /// Validate the sealed, signed package against the spec §1a required
    /// fields. Rejects a missing base profile, empty protocol /
    /// requested-scope lists, and an unsealed or unsigned package.
    pub fn validate(&self) -> Result<()> {
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
                "applet package MUST claim ck.profile.applet_service.v1".to_owned(),
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
        if self.package_digest.is_none() {
            return Err(Error::Protocol("applet package is not sealed".to_owned()));
        }
        if self.proof.is_none() {
            return Err(Error::Protocol("applet package is not signed".to_owned()));
        }
        Ok(())
    }

    /// Manifest snapshot folded into the derived registration's
    /// `manifest` slot (spec §1a derivation row `manifest`).
    pub fn manifest_snapshot(&self) -> Value {
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
        manifest.insert("limits".to_owned(), self.limits.clone());
        manifest.insert("ghost_policy".to_owned(), self.ghost_policy.clone());
        manifest.insert(
            "delegation_policy".to_owned(),
            self.delegation_policy.clone(),
        );
        manifest.insert("e2ee_policy".to_owned(), self.e2ee_policy.clone());
        if let Some(widget) = &self.widget {
            manifest.insert("widget".to_owned(), widget.clone());
        }
        Value::Object(manifest)
    }

    /// Derive the canonical `ck.applet.registration` payload per the
    /// spec §1a mapping table. The package `proof` is carried over; the
    /// authz service still re-verifies / re-signs the derived
    /// registration before fan-out.
    pub fn to_registration(&self) -> Result<WireAppletRegistration> {
        self.validate()?;
        let mut reg = WireAppletRegistration::new(
            self.applet_id.clone(),
            self.service_did.clone(),
            self.controller_did.clone(),
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
