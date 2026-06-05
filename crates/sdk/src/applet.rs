//! Applet wire objects: registration, package, install aggregate
//! operations, namespace claims/matching, bridge-error events and
//! portal / bridge-mapping helpers (spec `applet-schema.md` +
//! `applet-integration.md`).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::model::AppletTransactionResBody;
use crate::{
    Did, Error, Event, RealmId, Result, canonical,
    model::{AppletActorResBody, AppletRealmResBody, AppletTransactionReqBody},
};

/// Which namespace bucket a claim lives in. The wire model
/// (`applet-schema.md` §1.namespaces) groups claims into exactly
/// `actors` / `realms` / `handles`; the bucket — not a separate `kind`
/// field — determines the segment separator set used for pattern
/// matching (§2). Replaces the legacy `AppletNamespaceKind`.
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
    fn separators(self) -> &'static [u8] {
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
pub struct AppletNamespaceEntry {
    #[serde(default)]
    pub exclusive: bool,
    pub pattern: String,
}

impl AppletNamespaceEntry {
    /// An exclusive claim over `pattern`.
    pub fn exclusive(pattern: impl Into<String>) -> Self {
        Self { exclusive: true, pattern: pattern.into() }
    }

    /// A shared (non-exclusive) claim over `pattern`.
    pub fn shared(pattern: impl Into<String>) -> Self {
        Self { exclusive: false, pattern: pattern.into() }
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
            (AppletNamespaceDomain::Handles, &self.handles, &other.handles),
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

/// Optional inbound-webhook auth metadata. Open-shape (`Value`) so
/// receivers can round-trip future extensions; today the spec leaves
/// the inner shape Applet-defined.
pub type WebhookAuth = Value;

/// Wire-format `ck.applet.registration` Event content per spec
/// `applet-schema.md` §1 (authoritative `applet_registration_payload`).
///
/// This is the on-the-wire shape every external Applet implementation
/// sends. Build it directly via [`WireAppletRegistration::new`] or derive
/// it from an [`AppletPackage`] with [`AppletPackage::to_registration`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    pub proof: Option<crate::model::Proof>,
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
    reg.proof = Some(crate::model::Proof {
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
// `ck.self.applet.install`.

/// Controller-signed installable Applet package (`ck.schema.applet_package.v1`).
///
/// Build it unsigned via [`AppletPackage::new`], [`seal`](Self::seal) to
/// stamp `package_digest`, then [`sign`](Self::sign) with the controller
/// signer. [`to_registration`](Self::to_registration) performs the
/// spec §1a Package→registration derivation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Capability action request list —审批 UI only, never a grant.
    pub requested_scopes: Vec<String>,
    /// Supported Applet API endpoints + auth requirements (open shape).
    pub endpoint_set: Value,
    /// HTTP message signature key ref / accepted algorithms (open shape).
    pub webhook_auth: Value,
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
    pub proof: Option<crate::model::Proof>,
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
            endpoint_set: Value::Object(Default::default()),
            webhook_auth: Value::Object(Default::default()),
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
        self.proof = Some(crate::model::Proof {
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
            return Err(Error::Protocol("applet package missing required fields".to_owned()));
        }
        if !self.claimed_profiles.iter().any(|profile| profile == Self::BASE_PROFILE) {
            return Err(Error::Protocol(
                "applet package MUST claim ck.profile.applet_service.v1".to_owned(),
            ));
        }
        if self.protocols.is_empty() {
            return Err(Error::Protocol("applet package protocols are empty".to_owned()));
        }
        if self.requested_scopes.is_empty() {
            return Err(Error::Protocol("applet package requested_scopes are empty".to_owned()));
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
            Value::Array(self.claimed_profiles.iter().cloned().map(Value::String).collect()),
        );
        manifest.insert("limits".to_owned(), self.limits.clone());
        manifest.insert("ghost_policy".to_owned(), self.ghost_policy.clone());
        manifest.insert("delegation_policy".to_owned(), self.delegation_policy.clone());
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

/// Single install target. `kind="realm"` is a Realm-wide grant;
/// `kind="circle"` is bounded to one Circle. A single install operation
/// MUST target exactly one scope (spec §1b / §4b).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveScope {
    Realm { realm_id: RealmId },
    Circle { realm_id: RealmId, circle_id: crate::CircleId },
}

impl EffectiveScope {
    /// The Realm both variants are anchored in.
    pub fn realm_id(&self) -> &RealmId {
        match self {
            EffectiveScope::Realm { realm_id } | EffectiveScope::Circle { realm_id, .. } => {
                realm_id
            }
        }
    }
}

/// Admin approval intent attached to an install preview (spec §1b). Not
/// a grant; the commit step intersects it with package requested scopes
/// and Realm/Circle policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    #[serde(default)]
    pub approve_actions: Vec<String>,
    #[serde(default)]
    pub allow_ghost_actors: bool,
    #[serde(default)]
    pub allow_delegated_native_actors: bool,
    #[serde(default)]
    pub allow_e2ee_join: bool,
    #[serde(default)]
    pub allow_widget: bool,
}

/// `POST /_cokret/self/applets/install/preview` request body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallPreviewRequest {
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub approval_request: ApprovalRequest,
}

/// Approved capability scope (commit input). `actions` × `realm_ids`
/// under optional `constraints`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovedScope {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub realm_ids: Vec<RealmId>,
    #[serde(default)]
    pub constraints: Vec<Value>,
}

/// Read-only `InstallPlan` returned by install preview (spec §1b). The
/// recomputed `plan_digest` is the anti-tamper anchor the commit step
/// re-derives and compares (`applet_install_plan_mismatch`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallPlan {
    pub plan_id: String,
    pub applet_id: String,
    pub package_digest: crate::Hash,
    pub registration_epoch: crate::Hash,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default)]
    pub approved_scopes: Vec<ApprovedScope>,
    #[serde(default)]
    pub denied_scopes: Vec<String>,
    #[serde(default)]
    pub events_to_submit: Vec<Value>,
    #[serde(default)]
    pub capability_constraints: Vec<Value>,
    #[serde(default)]
    pub namespace_conflicts: Vec<AppletNamespaceConflict>,
    pub e2ee_effect: Value,
    pub widget_effect: Value,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// `None` until [`seal`](Self::seal); canonical digest excludes
    /// itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<crate::Hash>,
}

impl InstallPlan {
    /// Canonical SHA256 over the plan with `plan_digest` cleared.
    pub fn compute_plan_digest(&self) -> Result<crate::Hash> {
        let mut bare = self.clone();
        bare.plan_digest = None;
        crate::Hash::new(canonical::canonical_sha256(&bare)?).map_err(Into::into)
    }

    /// Compute and stamp `plan_digest`.
    pub fn seal(&mut self) -> Result<()> {
        self.plan_digest = Some(self.compute_plan_digest()?);
        Ok(())
    }
}

/// Bot / ghost membership policy carried into the install commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorPolicy {
    pub bot_membership: String,
    pub ghost_actor_mode: String,
}

/// E2EE policy at install commit time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallE2eePolicy {
    #[serde(default)]
    pub allow_mls_join: bool,
}

/// Widget policy at install commit time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WidgetPolicy {
    #[serde(default)]
    pub allow_widget: bool,
}

/// `POST /_cokret/self/applets/install` request body. MUST carry the
/// preview `plan_digest`; the server fails closed on a mismatch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallCommitRequest {
    pub plan_digest: crate::Hash,
    pub applet_package: AppletPackage,
    pub effective_scope: EffectiveScope,
    #[serde(default)]
    pub approved_scopes: Vec<ApprovedScope>,
    pub actor_policy: ActorPolicy,
    #[serde(default)]
    pub e2ee_policy: InstallE2eePolicy,
    #[serde(default)]
    pub widget_policy: WidgetPolicy,
}

/// Install commit response (spec §1b). Carries the fan-out event refs
/// (`ck.applet.registration`, `ck.capability.grant`, membership, E2EE
/// authorization, widget policy).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallCommitResponse {
    pub ok: bool,
    pub install_id: String,
    pub applet_id: String,
    pub registration_event_ref: String,
    pub registration_epoch: crate::Hash,
    pub bot_actor_id: Did,
    #[serde(default)]
    pub capability_grant_refs: Vec<String>,
    #[serde(default)]
    pub membership_event_refs: Vec<String>,
    #[serde(default)]
    pub e2ee_authorization_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_policy_ref: Option<String>,
    pub effective_status: String,
    #[serde(default)]
    pub rejected: Vec<Value>,
}

/// `POST /_cokret/self/applets/{applet_id}/revoke` request body. Revoke
/// targets the active install bound to `applet_id` + `effective_scope` +
/// `registration_epoch` (spec §4b): all active grants, widget scoped
/// token, delegated session and (where required) bot/ghost membership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstallRevokeRequest {
    pub effective_scope: EffectiveScope,
    pub registration_epoch: crate::Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─── S-11 / S-13: ck.applet.bridge_error builder ──────────────────────────

/// Who MAY see a `ck.applet.bridge_error` Event. Spec `applet-schema.md`
/// §7 makes `visibility_scope` a **required** enum; clients MUST restrict
/// display accordingly and MUST NOT leak bridge-internal detail to
/// unrelated members. Serializes as snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorVisibility {
    /// Realm administrators only.
    RealmAdmins,
    /// The Applet controller only.
    AppletController,
    /// All Realm members.
    RealmMembers,
}

/// Build a `ck.applet.bridge_error` Event per spec `applet-schema.md` §7
/// (authoritative `applet_bridge_error_payload`).
///
/// External Applets MUST emit this Event rather than silently dropping
/// upstream-network failures. The payload MUST bind `realm_id`,
/// `failed_transaction_ref`, `retriable` and `visibility_scope`; missing
/// any required field is rejected as `schema_violation`. The builder
/// takes all required fields up front so a bridge error can never be
/// built without them.
///
/// S-13 (2026-06-04): replaces the prior `severity` / `target_ref` shape
/// — the spec landed `error_class` / `retriable` / `visibility_scope` /
/// `failed_transaction_ref` instead.
#[derive(Clone, Debug)]
pub struct AppletBridgeErrorBuilder {
    realm_id: RealmId,
    applet_id: String,
    actor_id: Did,
    failed_transaction_ref: String,
    error_class: String,
    error_code: String,
    retriable: bool,
    visibility_scope: AppletBridgeErrorVisibility,
    message: Option<String>,
    external_ref: Option<Value>,
    retry_after_ms: Option<u64>,
    extra: serde_json::Map<String, Value>,
}

impl AppletBridgeErrorBuilder {
    /// `applet_id` is the typed `ck:applet:<uuidv7>` (or DID); `actor_id`
    /// is the bot / system DID emitting the error. `failed_transaction_ref`
    /// points at the failed transaction / source Event (e.g. a push
    /// `event_id`) and MUST NOT inline unauthorized external plaintext.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm_id: RealmId,
        applet_id: impl Into<String>,
        actor_id: Did,
        failed_transaction_ref: impl Into<String>,
        error_class: impl Into<String>,
        error_code: impl Into<String>,
        retriable: bool,
        visibility_scope: AppletBridgeErrorVisibility,
    ) -> Self {
        Self {
            realm_id,
            applet_id: applet_id.into(),
            actor_id,
            failed_transaction_ref: failed_transaction_ref.into(),
            error_class: error_class.into(),
            error_code: error_code.into(),
            retriable,
            visibility_scope,
            message: None,
            external_ref: None,
            retry_after_ms: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Human-readable summary. MUST NOT leak unauthorized external
    /// plaintext.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// External network reference (protocol / network id). MUST NOT
    /// contain unauthorized external plaintext.
    pub fn with_external_ref(mut self, external_ref: Value) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    /// Suggested retry delay; only meaningful when `retriable == true`.
    pub fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn build(self, actor_seq: u64, hlc: crate::Hlc) -> Result<Event> {
        let mut content = serde_json::Map::new();
        content.insert("applet_id".to_owned(), Value::String(self.applet_id.clone()));
        content.insert("realm_id".to_owned(), Value::String(self.realm_id.as_str().to_owned()));
        content.insert(
            "failed_transaction_ref".to_owned(),
            Value::String(self.failed_transaction_ref.clone()),
        );
        content.insert("error_class".to_owned(), Value::String(self.error_class.clone()));
        content.insert("error_code".to_owned(), Value::String(self.error_code.clone()));
        content.insert("retriable".to_owned(), Value::Bool(self.retriable));
        content.insert(
            "visibility_scope".to_owned(),
            serde_json::to_value(self.visibility_scope).expect("visibility_scope is a closed enum"),
        );
        if let Some(message) = &self.message {
            content.insert("message".to_owned(), Value::String(message.clone()));
        }
        if let Some(external_ref) = &self.external_ref {
            content.insert("external_ref".to_owned(), external_ref.clone());
        }
        if self.retriable {
            if let Some(retry_after_ms) = self.retry_after_ms {
                content.insert("retry_after_ms".to_owned(), Value::from(retry_after_ms));
            }
        }
        for (k, v) in &self.extra {
            content.insert(k.clone(), v.clone());
        }

        let mut event = Event::new(
            "ck.applet.bridge_error",
            self.realm_id,
            self.actor_id,
            actor_seq,
            hlc,
            Value::Object(content),
        )?;
        event.applet_id = Some(self.applet_id);
        if let Some(external_ref) = self.external_ref {
            event.external_ref = Some(external_ref);
        }
        Ok(event)
    }
}

/// Framework-neutral applet endpoint route declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) struct AppletEndpointRoute {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Route set expected from applet service framework adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) struct AppletEndpointRouteSet {
    pub routes: Vec<AppletEndpointRoute>,
}

#[cfg(test)]
impl AppletEndpointRouteSet {
    /// Standard applet service routes from the Cokret service binding.
    pub fn cokret_default() -> Self {
        Self {
            routes: vec![
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/ping".to_owned(),
                    description: "applet liveness and public metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/describe".to_owned(),
                    description: "applet capabilities and namespace metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "POST".to_owned(),
                    path: "/_cokret/edge/applet/transactions".to_owned(),
                    description: "receive applet transaction".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/actors/{actor_id}".to_owned(),
                    description: "query applet actor".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/realms/{realm_id_or_alias}".to_owned(),
                    description: "query applet realm".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/protocols/{protocol}".to_owned(),
                    description: "query protocol metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/third_party/users".to_owned(),
                    description: "query third-party user".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/third_party/locations".to_owned(),
                    description: "query third-party location".to_owned(),
                },
            ],
        }
    }
}

/// Applet service transaction with an explicit idempotency key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletServiceTransaction {
    pub idempotency_key: String,
    pub request: AppletTransactionReqBody,
}

/// Result of recording an idempotent transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) enum AppletServiceTransactionRecord {
    New(AppletTransactionResBody),
    Duplicate(AppletTransactionResBody),
}

/// In-memory idempotent applet service transaction store.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct AppletServiceTransactionStore {
    transactions: BTreeMap<String, (String, AppletTransactionResBody)>,
}

#[cfg(test)]
impl AppletServiceTransactionStore {
    /// Create an empty transaction store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transaction or return the prior response for an exact duplicate.
    pub fn record(
        &mut self,
        transaction: &AppletServiceTransaction,
        response: AppletTransactionResBody,
    ) -> Result<AppletServiceTransactionRecord> {
        let digest = canonical::canonical_sha256(&transaction.request)?;
        if let Some((existing_digest, existing_response)) =
            self.transactions.get(&transaction.idempotency_key)
        {
            if existing_digest == &digest {
                return Ok(AppletServiceTransactionRecord::Duplicate(existing_response.clone()));
            }
            return Err(Error::IdempotencyConflict(transaction.idempotency_key.clone()));
        }

        self.transactions.insert(transaction.idempotency_key.clone(), (digest, response.clone()));
        Ok(AppletServiceTransactionRecord::New(response))
    }
}

/// Virtual actor controlled by an applet service.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualActor {
    pub actor_id: Did,
    pub service_did: Did,
    pub localpart: String,
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<Did>,
}

/// Applet service intent for acting as a virtual actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletServiceIntent {
    pub service_did: Did,
    pub actor_id: Did,
    pub idempotency_prefix: String,
}

impl AppletServiceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_did: Did, actor_id: Did) -> Self {
        Self { service_did, actor_id, idempotency_prefix: "applet_txn".to_owned() }
    }

    /// Build an idempotent transaction envelope for events produced by this intent.
    pub fn transaction(
        &self,
        idempotency_key: impl AsRef<str>,
        events: Vec<Event>,
    ) -> AppletServiceTransaction {
        AppletServiceTransaction {
            idempotency_key: format!("{}:{}", self.idempotency_prefix, idempotency_key.as_ref()),
            request: AppletTransactionReqBody {
                source_service_did: self.service_did.clone(),
                events,
                ephemeral: Value::Null,
            },
        }
    }
}

/// Third-party lookup kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyLookupKind {
    User,
    Location,
}

/// Third-party user or location lookup request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyLookupReqBody {
    pub kind: ThirdPartyLookupKind,
    pub protocol: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

/// Third-party lookup response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThirdPartyLookupResBody {
    User(AppletActorResBody),
    Location(AppletRealmResBody),
}

/// Bridge mapping from a remote user to a Cokret virtual actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteUserMapping {
    pub protocol: String,
    pub remote_user_id: String,
    pub actor_id: Did,
    pub ghost_actor: Option<Did>,
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

/// Bridge mapping from a remote location to a Cokret Realm.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteRealmMapping {
    pub protocol: String,
    pub remote_realm_id: String,
    pub realm_id: RealmId,
    pub portal_id: Option<String>,
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

/// In-memory bridge mapping storage.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct BridgeMappingStore {
    users: BTreeMap<String, RemoteUserMapping>,
    realms: BTreeMap<String, RemoteRealmMapping>,
}

#[cfg(test)]
impl BridgeMappingStore {
    /// Create an empty mapping store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store or replace a remote user mapping.
    pub fn upsert_user(&mut self, mapping: RemoteUserMapping) {
        self.users.insert(remote_key(&mapping.protocol, &mapping.remote_user_id), mapping);
    }

    /// Store or replace a remote location mapping.
    pub fn upsert_realm(&mut self, mapping: RemoteRealmMapping) {
        self.realms.insert(remote_key(&mapping.protocol, &mapping.remote_realm_id), mapping);
    }

    /// Resolve a remote user mapping.
    pub fn user(&self, protocol: &str, remote_user_id: &str) -> Option<&RemoteUserMapping> {
        self.users.get(&remote_key(protocol, remote_user_id))
    }

    /// Resolve a remote location mapping.
    pub fn realm(&self, protocol: &str, remote_realm_id: &str) -> Option<&RemoteRealmMapping> {
        self.realms.get(&remote_key(protocol, remote_realm_id))
    }
}

/// Accountability metadata for a ghost actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GhostActorAccountability {
    pub ghost_actor: Did,
    pub service_did: Did,
    pub accountable_principal_ids: Vec<Did>,
    pub reason: String,
}

/// Mapping between an applet portal and a bridged remote location.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortalRealmMapping {
    pub portal_id: String,
    pub realm_id: RealmId,
    pub protocol: String,
    pub remote_realm_id: String,
}

/// Portal mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalMode {
    Native,
    Bridge,
}

/// Applet portal Realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPortal {
    pub portal_id: String,
    pub realm_id: RealmId,
    pub mode: PortalMode,
    pub applets: BTreeSet<String>,
    pub ghost_actor: Option<Did>,
}

/// Applet portal manager.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct AppletPortalManager {
    portals: BTreeMap<String, AppletPortal>,
}

#[cfg(test)]
impl AppletPortalManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a portal.
    pub fn create_portal(&mut self, realm_id: RealmId) -> AppletPortal {
        let portal = AppletPortal {
            portal_id: format!("portal_{}", uuid::Uuid::now_v7()),
            realm_id,
            mode: PortalMode::Native,
            applets: BTreeSet::new(),
            ghost_actor: None,
        };
        self.portals.insert(portal.portal_id.clone(), portal.clone());
        portal
    }

    /// Install an applet into a portal.
    pub fn install_applet(&mut self, portal_id: &str, applet_id: impl Into<String>) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.applets.insert(applet_id.into());
        Ok(())
    }

    /// Enable bridge mode.
    pub fn enable_bridge(&mut self, portal_id: &str) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.mode = PortalMode::Bridge;
        Ok(())
    }

    /// Set ghost actor.
    pub fn set_ghost_actor(&mut self, portal_id: &str, actor: Did) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.ghost_actor = Some(actor);
        Ok(())
    }

    /// Get a portal.
    pub fn portal(&self, portal_id: &str) -> Option<&AppletPortal> {
        self.portals.get(portal_id)
    }
}

/// Strip the DID `#fragment` for actor-domain matching (`applet-schema.md`
/// §2: `#fragment` does not participate). Other domains keep `#` literal.
fn strip_fragment(domain: AppletNamespaceDomain, value: &str) -> &str {
    if matches!(domain, AppletNamespaceDomain::Actors) {
        value.split('#').next().unwrap_or(value)
    } else {
        value
    }
}

/// Conservative overlap test between two exclusive namespace patterns.
/// Conflict detection MUST NOT miss a real overlap, so this errs toward
/// over-reporting: it strips a trailing `*` / `**` and tests prefix
/// containment after fragment normalization.
fn namespace_patterns_overlap(domain: AppletNamespaceDomain, left: &str, right: &str) -> bool {
    let left = strip_fragment(domain, left);
    let right = strip_fragment(domain, right);
    if left == right {
        return true;
    }
    let left_prefix = left.trim_end_matches('*');
    let right_prefix = right.trim_end_matches('*');
    left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix)
}

/// Test whether `candidate` matches an applet namespace `pattern` in
/// `domain`.
///
/// Grammar (spec `applet-schema.md` §2):
/// - `*` matches exactly one segment: one or more chars that are not a
///   separator for `domain` (actor: `:`; realm / handle: `:` and `/`). It
///   never crosses a separator and never matches an empty segment.
/// - `**` matches one or more path-like segments: one or more chars that
///   may include `/` but never `:`. It never matches empty.
/// - Literal `*` is escaped as `\*`.
/// - For the actor domain a DID `#fragment` is ignored on both sides.
/// - An empty pattern matches only an empty candidate.
pub fn namespace_pattern_matches(
    domain: AppletNamespaceDomain,
    pattern: &str,
    candidate: &str,
) -> bool {
    let pattern = strip_fragment(domain, pattern);
    let candidate = strip_fragment(domain, candidate);
    namespace_pattern_match_bytes(domain.separators(), pattern.as_bytes(), candidate.as_bytes())
}

fn namespace_pattern_match_bytes(separators: &[u8], pattern: &[u8], candidate: &[u8]) -> bool {
    let is_sep = |byte: u8| separators.contains(&byte);
    let mut pi = 0;
    let mut ci = 0;

    while pi < pattern.len() {
        match pattern[pi] {
            b'\\' if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' => {
                // Escaped literal `*`.
                if ci >= candidate.len() || candidate[ci] != b'*' {
                    return false;
                }
                pi += 2;
                ci += 1;
            }
            b'*' => {
                if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' {
                    // `**`: one or more chars, may cross `/` but never `:`.
                    let rest = &pattern[pi + 2..];
                    if ci >= candidate.len() || candidate[ci] == b':' {
                        return false;
                    }
                    let mut split = ci + 1;
                    loop {
                        if namespace_pattern_match_bytes(separators, rest, &candidate[split..]) {
                            return true;
                        }
                        if split >= candidate.len() || candidate[split] == b':' {
                            return false;
                        }
                        split += 1;
                    }
                } else {
                    // `*`: one or more non-separator chars.
                    let rest = &pattern[pi + 1..];
                    if ci >= candidate.len() || is_sep(candidate[ci]) {
                        return false;
                    }
                    let mut split = ci + 1;
                    loop {
                        if namespace_pattern_match_bytes(separators, rest, &candidate[split..]) {
                            return true;
                        }
                        if split >= candidate.len() || is_sep(candidate[split]) {
                            return false;
                        }
                        split += 1;
                    }
                }
            }
            byte => {
                if ci >= candidate.len() || candidate[ci] != byte {
                    return false;
                }
                pi += 1;
                ci += 1;
            }
        }
    }

    ci == candidate.len()
}

#[cfg(test)]
fn remote_key(protocol: &str, remote_id: &str) -> String {
    format!("{protocol}:{remote_id}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn applet_portal_manages_space_bridge_and_ghost_actor() {
        let mut manager = AppletPortalManager::new();
        let portal = manager
            .create_portal(RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap());
        manager.install_applet(&portal.portal_id, "todo").unwrap();
        manager.enable_bridge(&portal.portal_id).unwrap();
        manager.set_ghost_actor(&portal.portal_id, did("ghost")).unwrap();

        let portal = manager.portal(&portal.portal_id).unwrap();
        assert_eq!(portal.mode, PortalMode::Bridge);
        assert!(portal.applets.contains("todo"));
        assert!(portal.ghost_actor.is_some());
    }

    #[test]
    fn applet_wire_namespaces_detect_exclusive_conflicts() {
        let a = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive("did:web:slack-bridge.example:ghost:*")],
            ..Default::default()
        };
        // Exclusive vs overlapping concrete claim in the same domain conflicts.
        let b = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive("did:web:slack-bridge.example:ghost:u1")],
            ..Default::default()
        };
        let conflicts = a.conflicts_with(&b);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].domain, Actors);

        // Two non-exclusive claims may coexist.
        let c = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::shared("did:web:slack-bridge.example:ghost:*")],
            ..Default::default()
        };
        let d = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::shared("did:web:slack-bridge.example:ghost:u1")],
            ..Default::default()
        };
        assert!(c.conflicts_with(&d).is_empty());

        // Claims in different domain buckets never conflict.
        let realm_only = AppletWireNamespaces {
            realms: vec![AppletNamespaceEntry::exclusive("slack:team:*")],
            ..Default::default()
        };
        assert!(a.conflicts_with(&realm_only).is_empty());
    }

    #[test]
    fn applet_service_transactions_are_idempotent() {
        let intent = AppletServiceIntent::new(did("svc"), did("ghost"));
        let transaction = intent.transaction("k1", Vec::new());
        let response =
            AppletTransactionResBody { ok: true, rejected: Vec::new(), retry_after_ms: None };
        let mut store = AppletServiceTransactionStore::new();

        assert!(matches!(
            store.record(&transaction, response.clone()).unwrap(),
            AppletServiceTransactionRecord::New(_)
        ));
        assert!(matches!(
            store.record(&transaction, response).unwrap(),
            AppletServiceTransactionRecord::Duplicate(_)
        ));

        let mut changed = transaction.clone();
        changed.request.ephemeral = json!({"changed": true});
        assert!(matches!(
            store.record(
                &changed,
                AppletTransactionResBody { ok: true, rejected: Vec::new(), retry_after_ms: None },
            ),
            Err(Error::IdempotencyConflict(_))
        ));
    }

    #[test]
    fn applet_endpoint_routes_and_bridge_mappings_cover_queries() {
        assert_eq!(AppletEndpointRouteSet::cokret_default().routes.len(), 8);

        let mut mappings = BridgeMappingStore::new();
        mappings.upsert_user(RemoteUserMapping {
            protocol: "slack".to_owned(),
            remote_user_id: "U1".to_owned(),
            actor_id: did("u1"),
            ghost_actor: Some(did("ghost")),
            display_name: Some("User One".to_owned()),
            external_ref: json!({"team": "T1"}),
        });
        mappings.upsert_realm(RemoteRealmMapping {
            protocol: "slack".to_owned(),
            remote_realm_id: "C1".to_owned(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-f949e0272316").unwrap(),
            portal_id: Some("portal".to_owned()),
            title: Some("general".to_owned()),
            external_ref: Value::Null,
        });

        assert_eq!(mappings.user("slack", "U1").unwrap().display_name, Some("User One".to_owned()));
        assert!(mappings.realm("slack", "C1").is_some());
    }

    use AppletNamespaceDomain::{Actors, Realms};

    #[test]
    fn namespace_pattern_single_star_matches_one_segment() {
        assert!(namespace_pattern_matches(
            Actors,
            "did:web:slack-bridge.example:ghost:*",
            "did:web:slack-bridge.example:ghost:u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_different_host() {
        assert!(!namespace_pattern_matches(
            Actors,
            "did:web:slack-bridge.example:ghost:*",
            "did:web:other.example:ghost:u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_missing_prefix() {
        assert!(!namespace_pattern_matches(
            Actors,
            "did:web:slack-bridge.example:ghost:*",
            "did:web:slack-bridge.example:bot"
        ));
    }

    #[test]
    fn namespace_pattern_actor_ignores_fragment() {
        // `#fragment` does not participate in actor-domain matching.
        assert!(namespace_pattern_matches(
            Actors,
            "did:web:slack-bridge.example:ghost:*",
            "did:web:slack-bridge.example:ghost:u123#key-1"
        ));
    }

    #[test]
    fn namespace_pattern_multiple_single_stars_match_segments() {
        assert!(namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_does_not_cross_separator() {
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn namespace_pattern_double_star_crosses_slash_only() {
        // `**` matches one or more `/`-separated segments...
        assert!(namespace_pattern_matches(
            Realms,
            "slack.acme.example/**",
            "slack.acme.example/team/a/b"
        ));
        // ...but never crosses `:`.
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:**",
            "slack:team:T123:channel:C456"
        ));
        // ...and never matches an empty segment.
        assert!(!namespace_pattern_matches(Realms, "slack.acme.example/**", "slack.acme.example/"));
    }

    #[test]
    fn namespace_pattern_escaped_star_matches_literal() {
        assert!(namespace_pattern_matches(Realms, "literal\\*pattern", "literal*pattern"));
    }

    #[test]
    fn namespace_pattern_escaped_star_rejects_non_star() {
        assert!(!namespace_pattern_matches(Realms, "literal\\*pattern", "literalXpattern"));
    }

    #[test]
    fn namespace_pattern_empty_pattern_rejects_non_empty_candidate() {
        assert!(!namespace_pattern_matches(Actors, "", "did:web:anything.example"));
    }

    // ─── S-4 (savfox SDK gap) tests ──────────────────────────────────

    fn sample_epoch() -> crate::Hash {
        crate::Hash::new(format!("sha256:{}", "bb".repeat(32))).unwrap()
    }

    fn sample_wire_registration() -> WireAppletRegistration {
        WireAppletRegistration::new(
            "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["ck.applet.v1".to_owned()],
            AppletWireNamespaces {
                actors: vec![AppletNamespaceEntry::exclusive(
                    "did:web:slackbridge.example#ghost-*",
                )],
                realms: vec![],
                handles: vec![],
            },
            sample_epoch(),
        )
    }

    #[test]
    fn wire_registration_round_trips_through_json() {
        let reg = sample_wire_registration();
        let value = serde_json::to_value(&reg).unwrap();
        assert_eq!(value["kind"], "ck.applet.registration");
        assert_eq!(value["applet_id"], reg.applet_id);
        assert_eq!(value["service_did"], reg.service_did.as_str());
        assert_eq!(value["controller_did"], reg.controller_did.as_str());
        assert_eq!(value["base_url"], reg.base_url);
        assert_eq!(value["bot_actor_id"], reg.bot_actor_id.as_str());
        let back: WireAppletRegistration = serde_json::from_value(value).unwrap();
        assert_eq!(back.applet_id, reg.applet_id);
        assert_eq!(back.namespaces.actors, reg.namespaces.actors);
    }

    #[test]
    fn wire_registration_payload_digest_is_stable_and_excludes_proof() {
        let reg = sample_wire_registration();
        let digest_before = reg.payload_digest().unwrap();

        let mut with_proof = reg;
        with_proof.proof = Some(crate::model::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            event_digest: digest_before.clone(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "header..sig".to_owned(),
        });
        let digest_after = with_proof.payload_digest().unwrap();
        assert_eq!(
            digest_before, digest_after,
            "payload_digest MUST exclude `proof` so re-signing is idempotent"
        );
    }

    // ─── S-11 (savfox SDK gap) tests ─────────────────────────────────

    fn realm() -> crate::RealmId {
        crate::RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn hlc() -> crate::Hlc {
        crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    #[test]
    fn applet_bridge_error_builder_emits_canonical_kind_and_payload() {
        let event = AppletBridgeErrorBuilder::new(
            realm(),
            "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("bot"),
            "ck:event:01904100-0000-7000-8000-deadbeefdead",
            "external_network",
            "external_rate_limited",
            true,
            AppletBridgeErrorVisibility::RealmAdmins,
        )
        .with_message("external network rejected the message")
        .with_external_ref(serde_json::json!({"slack_response_code": 429}))
        .with_retry_after_ms(1000)
        .build(1, hlc())
        .unwrap();
        assert_eq!(event.kind, "ck.applet.bridge_error");
        assert_eq!(event.content["realm_id"], realm().as_str());
        assert_eq!(
            event.content["failed_transaction_ref"],
            "ck:event:01904100-0000-7000-8000-deadbeefdead"
        );
        assert_eq!(event.content["error_class"], "external_network");
        assert_eq!(event.content["error_code"], "external_rate_limited");
        assert_eq!(event.content["retriable"], true);
        assert_eq!(event.content["visibility_scope"], "realm_admins");
        assert_eq!(event.content["message"], "external network rejected the message");
        assert_eq!(event.content["retry_after_ms"], 1000);
        assert_eq!(
            event.applet_id.as_deref(),
            Some("ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa")
        );
        assert_eq!(event.external_ref.as_ref().unwrap()["slack_response_code"], 429);
    }

    #[test]
    fn wire_registration_serializes_registration_epoch() {
        let reg = sample_wire_registration();
        let value = serde_json::to_value(&reg).unwrap();
        assert_eq!(value["registration_epoch"], reg.registration_epoch.as_str());
        // namespace entries are object-form `{ exclusive, pattern }`.
        assert_eq!(value["namespaces"]["actors"][0]["exclusive"], true);
        assert_eq!(
            value["namespaces"]["actors"][0]["pattern"],
            "did:web:slackbridge.example#ghost-*"
        );
    }

    #[test]
    fn applet_package_derives_registration_and_round_trips() {
        let mut package = AppletPackage::new(
            "applet_pkg_todo",
            "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["slack".to_owned()],
            AppletWireNamespaces {
                actors: vec![AppletNamespaceEntry::exclusive(
                    "did:web:slackbridge.example:ghost:*",
                )],
                realms: vec![],
                handles: vec![],
            },
            sample_epoch(),
        );
        package.requested_scopes = vec!["ck.message.create".to_owned()];
        package.webhook_auth = json!({"type": "http_message_signature"});

        // Unsealed / unsigned package fails validation and derivation.
        assert!(package.validate().is_err());
        package.seal().unwrap();
        package.proof = Some(crate::model::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            event_digest: package.package_digest.clone().unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "header..sig".to_owned(),
        });
        package.validate().unwrap();

        let reg = package.to_registration().unwrap();
        assert_eq!(reg.applet_id, package.applet_id);
        assert_eq!(reg.registration_epoch, package.registration_epoch);
        assert_eq!(reg.requested_scopes, package.requested_scopes);
        assert_eq!(reg.namespaces, package.namespaces);
        assert!(reg.manifest.is_some());

        // Package digest excludes itself and proof.
        let recomputed = package.compute_package_digest().unwrap();
        assert_eq!(recomputed, package.package_digest.clone().unwrap());

        let back: AppletPackage =
            serde_json::from_value(serde_json::to_value(&package).unwrap()).unwrap();
        assert_eq!(back, package);
    }

    #[test]
    fn applet_package_missing_base_profile_is_rejected() {
        let mut package = AppletPackage::new(
            "applet_pkg_todo",
            "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["slack".to_owned()],
            AppletWireNamespaces::default(),
            sample_epoch(),
        );
        package.claimed_profiles = vec!["ck.profile.applet_bridge.v1".to_owned()];
        package.requested_scopes = vec!["ck.message.create".to_owned()];
        package.seal().unwrap();
        assert!(package.validate().is_err());
    }

    #[test]
    fn install_plan_digest_excludes_itself_and_effective_scope_round_trips() {
        let mut plan = InstallPlan {
            plan_id: "plan_1".to_owned(),
            applet_id: "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
            package_digest: sample_epoch(),
            registration_epoch: sample_epoch(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            requested_scopes: vec!["ck.message.create".to_owned()],
            approved_scopes: vec![],
            denied_scopes: vec![],
            events_to_submit: vec![],
            capability_constraints: vec![],
            namespace_conflicts: vec![],
            e2ee_effect: json!({"allow_mls_join": false}),
            widget_effect: json!({"allow_widget": false}),
            warnings: vec![],
            plan_digest: None,
        };
        let before = plan.compute_plan_digest().unwrap();
        plan.seal().unwrap();
        assert_eq!(plan.plan_digest.clone().unwrap(), before);

        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["effective_scope"]["kind"], "realm");
        let back: InstallPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back.effective_scope.realm_id(), &realm());
    }

    #[test]
    fn sign_registration_attaches_proof_with_matching_digest() {
        use std::collections::BTreeMap;

        use cokret_core::{
            Did as CoreDid, Hash as CoreHash, MoveSignature, MoveSigner, Result as CoreResult,
            UnsignedMove, canonical, move_event::Move,
        };

        struct StubSigner {
            did: CoreDid,
            kid: String,
        }

        impl MoveSigner for StubSigner {
            fn sign_move(&self, _: &UnsignedMove) -> CoreResult<Move> {
                unreachable!()
            }
            fn signer_did(&self) -> &CoreDid {
                &self.did
            }
            fn verification_method_id(&self) -> &str {
                &self.kid
            }
            fn sign_payload(&self, canonical_bytes: &[u8]) -> CoreResult<MoveSignature> {
                let payload_digest = CoreHash::new(canonical::sha256_digest(canonical_bytes))?;
                Ok(MoveSignature {
                    alg: "EdDSA".to_owned(),
                    verification_method: self.kid.clone(),
                    payload_digest: payload_digest.clone(),
                    created_at: Utc::now(),
                    jws: format!("stub..{}", payload_digest.as_str()),
                })
            }
        }

        let signer =
            StubSigner { did: did("alice"), kid: "did:web:alice.example#key-1".to_owned() };
        let mut reg = sample_wire_registration();
        sign_registration(&mut reg, &signer, "did:web:alice.example#key-1").unwrap();

        let proof = reg.proof.as_ref().expect("proof must be attached");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(proof.verification_method, "did:web:alice.example#key-1");
        assert_eq!(proof.event_digest, reg.payload_digest().unwrap());

        // Silence any unused warnings on the BTreeMap import — kept for symmetry.
        let _ = BTreeMap::<String, ()>::new();
        let _ = json!({});
    }
}
