//! Applet schema, OpenAPI binding and portal helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::model::AppletTransactionResBody;
use crate::{
    Did, Error, Event, Result, SpaceId, canonical,
    model::{AppletActorResBody, AppletRealmResBody, AppletTransactionReqBody},
};

/// Applet permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPermission {
    pub resource: String,
    pub actions: BTreeSet<String>,
}

/// OpenAPI binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiBinding {
    pub base_url: String,
    pub operations: BTreeMap<String, String>,
}

/// Applet schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletSchema {
    pub applet_id: String,
    pub name: String,
    pub version: String,
    pub permissions: Vec<AppletPermission>,
    pub openapi: Option<OpenApiBinding>,
    pub schema: Value,
}

impl AppletSchema {
    /// Validate required fields.
    pub fn validate(&self) -> Result<()> {
        if self.applet_id.is_empty() || self.name.is_empty() || self.version.is_empty() {
            return Err(Error::Protocol("applet schema missing required fields".to_owned()));
        }
        Ok(())
    }

    /// Check permission.
    pub fn allows(&self, resource: &str, action: &str) -> bool {
        self.permissions.iter().any(|permission| {
            permission.resource == resource && permission.actions.contains(action)
        })
    }
}

/// Namespace domain declared by an applet or applet service.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletNamespaceKind {
    Actor,
    Space,
    Handle,
    Protocol,
    Command,
}

/// Namespace declaration for applet ownership and bridge routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletNamespaceDeclaration {
    pub kind: AppletNamespaceKind,
    pub pattern: String,
    #[serde(default)]
    pub exclusive: bool,
}

impl AppletNamespaceDeclaration {
    /// Create an exclusive namespace declaration.
    pub fn exclusive(kind: AppletNamespaceKind, pattern: impl Into<String>) -> Self {
        Self { kind, pattern: pattern.into(), exclusive: true }
    }

    /// Return whether two declarations conflict.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.kind == other.kind
            && (self.exclusive || other.exclusive)
            && namespace_patterns_overlap(&self.pattern, &other.pattern)
    }

    /// True iff `candidate` matches this declaration's pattern.
    pub fn matches(&self, candidate: &str) -> bool {
        namespace_pattern_matches(&self.pattern, candidate)
    }
}

/// Namespace conflict detected during applet registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletNamespaceConflict {
    pub kind: AppletNamespaceKind,
    pub pattern: String,
    pub conflicting_applet_id: String,
    pub conflicting_pattern: String,
}

/// Signed applet registration with namespace declarations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedAppletRegistration {
    pub registration_id: String,
    pub applet_id: String,
    pub service_did: Did,
    pub schema: AppletSchema,
    #[serde(default)]
    pub namespaces: Vec<AppletNamespaceDeclaration>,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

impl SignedAppletRegistration {
    /// Build a new signed registration model.
    pub fn new(
        applet_id: impl Into<String>,
        service_did: Did,
        schema: AppletSchema,
        namespaces: Vec<AppletNamespaceDeclaration>,
        signature: impl Into<String>,
    ) -> Self {
        let applet_id = applet_id.into();
        Self {
            registration_id: format!("applet_reg_{}", uuid::Uuid::now_v7()),
            applet_id,
            service_did,
            schema,
            namespaces,
            signature: signature.into(),
            created_at: Utc::now(),
        }
    }

    /// Validate required registration fields.
    pub fn validate(&self) -> Result<()> {
        self.schema.validate()?;
        if self.applet_id != self.schema.applet_id {
            return Err(Error::Protocol("applet registration id mismatch".to_owned()));
        }
        if self.signature.is_empty() {
            return Err(Error::Protocol("applet registration missing signature".to_owned()));
        }
        for namespace in &self.namespaces {
            if namespace.pattern.is_empty() {
                return Err(Error::Protocol("applet namespace pattern is empty".to_owned()));
            }
        }
        Ok(())
    }
}

// ─── S-4 (savfox SDK gap): wire-format `ck.applet.registration` ────────────
//
// Spec `applet-schema.md` §1. Distinct from [`SignedAppletRegistration`]
// (SDK-internal). Co-exists so existing callers don't break; new
// integrations (savfox bridge, ghost-actor controllers) MUST use this.

/// Per-domain namespaces an Applet claims on registration. Wire shape
/// per `applet-schema.md` §1.namespaces.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletWireNamespaces {
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default)]
    pub realms: Vec<String>,
    #[serde(default)]
    pub handles: Vec<String>,
}

/// Optional inbound-webhook auth metadata. Open-shape (`Value`) so
/// receivers can round-trip future extensions; today the spec leaves
/// the inner shape Applet-defined.
pub type WebhookAuth = Value;

/// Wire-format `ck.applet.registration` Event content per spec
/// `applet-schema.md` §1.
///
/// Distinct from [`SignedAppletRegistration`] — that one is an
/// SDK-internal model used by the in-process applet registry; this is
/// the on-the-wire shape every external Applet implementation sends.
/// See [`crate::KNOWN_GAPS`] for migration notes.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_auth: Option<WebhookAuth>,
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
            webhook_auth: None,
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
        payload_digest,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: sig.jws,
    });
    Ok(())
}

// ─── S-11 (savfox SDK gap): ck.applet.bridge_error builder ────────────────

/// Severity hint for [`AppletBridgeErrorBuilder`]. Spec
/// `applet-integration.md` §14 keeps the slot opaque, so we expose a
/// closed enum that serializes as snake_case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletBridgeErrorSeverity {
    /// Recoverable upstream blip; retry SHOULD succeed.
    Warning,
    /// Single-attempt failure; downstream MAY surface.
    Error,
    /// Repeated / unrecoverable failure; downstream MUST surface.
    Fatal,
}

/// Build a `ck.applet.bridge_error` Event Envelope per spec
/// `applet-integration.md` §14 + `applet-schema.md` §7.
///
/// External Applets MUST emit this Event rather than silently dropping
/// upstream-network failures (savfox's current tracing-only path
/// fails-closed in production).
#[derive(Clone, Debug)]
pub struct AppletBridgeErrorBuilder {
    realm_id: crate::RealmId,
    applet_id: String,
    actor_id: Did,
    target_ref: Option<String>,
    code: String,
    message: String,
    severity: AppletBridgeErrorSeverity,
    external_ref: Option<Value>,
    extra: serde_json::Map<String, Value>,
}

impl AppletBridgeErrorBuilder {
    /// `applet_id` is the typed `ck:applet:<uuidv7>`; `actor_id` is
    /// the bot / system DID emitting the error.
    pub fn new(
        realm_id: crate::RealmId,
        applet_id: impl Into<String>,
        actor_id: Did,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            realm_id,
            applet_id: applet_id.into(),
            actor_id,
            target_ref: None,
            code: code.into(),
            message: message.into(),
            severity: AppletBridgeErrorSeverity::Error,
            external_ref: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Typed reference to the Object the failure relates to (e.g.
    /// `ck:event:...`, `ck:morph:...`).
    pub fn with_target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    pub fn with_severity(mut self, severity: AppletBridgeErrorSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_external_ref(mut self, external_ref: Value) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn build(self, actor_seq: u64, hlc: crate::Hlc) -> Result<Event> {
        let mut content = serde_json::Map::new();
        content.insert("applet_id".to_owned(), Value::String(self.applet_id.clone()));
        content.insert("code".to_owned(), Value::String(self.code.clone()));
        content.insert("message".to_owned(), Value::String(self.message.clone()));
        content.insert(
            "severity".to_owned(),
            serde_json::to_value(self.severity).expect("severity is a closed enum"),
        );
        if let Some(target_ref) = &self.target_ref {
            content.insert("target_ref".to_owned(), Value::String(target_ref.clone()));
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

/// Applet registry.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct AppletRegistry {
    applets: BTreeMap<String, AppletSchema>,
    signed_registrations: BTreeMap<String, SignedAppletRegistration>,
    namespaces: Vec<(String, AppletNamespaceDeclaration)>,
}

#[cfg(test)]
impl AppletRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and register an applet schema from JSON.
    pub fn register_from_value(&mut self, value: Value) -> Result<AppletSchema> {
        let schema: AppletSchema = serde_json::from_value(value)?;
        schema.validate()?;
        self.applets.insert(schema.applet_id.clone(), schema.clone());
        Ok(schema)
    }

    /// Register an applet schema.
    pub fn register(&mut self, schema: AppletSchema) -> Result<()> {
        schema.validate()?;
        self.applets.insert(schema.applet_id.clone(), schema);
        Ok(())
    }

    /// Get an applet.
    pub fn get(&self, applet_id: &str) -> Option<&AppletSchema> {
        self.applets.get(applet_id)
    }

    /// Register a signed applet and reject conflicting exclusive namespaces.
    pub fn register_signed(&mut self, registration: SignedAppletRegistration) -> Result<()> {
        registration.validate()?;
        let conflicts = self.namespace_conflicts(&registration.namespaces);
        if !conflicts.is_empty() {
            return Err(Error::Protocol("applet namespace conflict".to_owned()));
        }

        self.register(registration.schema.clone())?;
        for namespace in &registration.namespaces {
            self.namespaces.push((registration.applet_id.clone(), namespace.clone()));
        }
        self.signed_registrations.insert(registration.registration_id.clone(), registration);
        Ok(())
    }

    /// Find namespace conflicts for a proposed registration.
    pub fn namespace_conflicts(
        &self,
        namespaces: &[AppletNamespaceDeclaration],
    ) -> Vec<AppletNamespaceConflict> {
        namespaces
            .iter()
            .flat_map(|candidate| {
                self.namespaces.iter().filter_map(move |(applet_id, existing)| {
                    if candidate.conflicts_with(existing) {
                        Some(AppletNamespaceConflict {
                            kind: candidate.kind.clone(),
                            pattern: candidate.pattern.clone(),
                            conflicting_applet_id: applet_id.clone(),
                            conflicting_pattern: existing.pattern.clone(),
                        })
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

/// Applet endpoint registration model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) struct AppletEndpointRegistration {
    pub registration_id: String,
    pub service_did: Did,
    pub bot_localpart: String,
    #[serde(default)]
    pub namespaces: Vec<AppletNamespaceDeclaration>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub receive_ephemeral: bool,
    #[serde(default)]
    pub rate_limited: bool,
}

#[cfg(test)]
impl AppletEndpointRegistration {
    /// Create a registration with a generated id.
    pub fn new(service_did: Did, bot_localpart: impl Into<String>) -> Self {
        Self {
            registration_id: format!("applet_ep_{}", uuid::Uuid::now_v7()),
            service_did,
            bot_localpart: bot_localpart.into(),
            namespaces: Vec::new(),
            protocols: Vec::new(),
            receive_ephemeral: false,
            rate_limited: true,
        }
    }

    /// Validate required fields.
    pub fn validate(&self) -> Result<()> {
        if self.bot_localpart.is_empty() {
            return Err(Error::Protocol("applet endpoint bot localpart is empty".to_owned()));
        }
        Ok(())
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

/// Bridge mapping from a remote location to a Cokret space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteSpaceMapping {
    pub protocol: String,
    pub remote_space_id: String,
    pub space_id: SpaceId,
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
    spaces: BTreeMap<String, RemoteSpaceMapping>,
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

    /// Store or replace a remote space mapping.
    pub fn upsert_space(&mut self, mapping: RemoteSpaceMapping) {
        self.spaces.insert(remote_key(&mapping.protocol, &mapping.remote_space_id), mapping);
    }

    /// Resolve a remote user mapping.
    pub fn user(&self, protocol: &str, remote_user_id: &str) -> Option<&RemoteUserMapping> {
        self.users.get(&remote_key(protocol, remote_user_id))
    }

    /// Resolve a remote space mapping.
    pub fn space(&self, protocol: &str, remote_space_id: &str) -> Option<&RemoteSpaceMapping> {
        self.spaces.get(&remote_key(protocol, remote_space_id))
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

/// Mapping between an applet portal and a bridged remote space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortalSpaceMapping {
    pub portal_id: String,
    pub space_id: SpaceId,
    pub protocol: String,
    pub remote_space_id: String,
}

/// Portal mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalMode {
    Native,
    Bridge,
}

/// Applet portal space.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPortal {
    pub portal_id: String,
    pub space_id: SpaceId,
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
    pub fn create_portal(&mut self, space_id: SpaceId) -> AppletPortal {
        let portal = AppletPortal {
            portal_id: format!("portal_{}", uuid::Uuid::now_v7()),
            space_id,
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

fn namespace_patterns_overlap(left: &str, right: &str) -> bool {
    if left == right || left == "*" || right == "*" {
        return true;
    }
    let left_prefix = left.strip_suffix('*').unwrap_or(left);
    let right_prefix = right.strip_suffix('*').unwrap_or(right);
    left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix)
}

/// Test whether a candidate string matches an applet namespace pattern.
///
/// Grammar (spec applet-schema.md §2):
/// - `*` matches one path-like segment (i.e. one or more consecutive
///   non-separator chars, where separators are `:`, `/`, `#`). Empty matches
///   are not allowed.
/// - `**` matches multiple segments — any chars, including separators. May
///   match the empty string when consumed at the end of the pattern.
/// - Literal `*` is escaped as `\*`.
/// - All other characters match literally.
///
/// An empty pattern never matches a non-empty candidate; an empty pattern
/// matches only an empty candidate.
pub fn namespace_pattern_matches(pattern: &str, candidate: &str) -> bool {
    namespace_pattern_match_bytes(pattern.as_bytes(), candidate.as_bytes())
}

fn is_namespace_separator(byte: u8) -> bool {
    matches!(byte, b':' | b'/' | b'#')
}

fn namespace_pattern_match_bytes(pattern: &[u8], candidate: &[u8]) -> bool {
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
                // Detect `**` vs `*`.
                if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' {
                    // `**`: any chars, including separators, possibly empty.
                    let rest = &pattern[pi + 2..];
                    if rest.is_empty() {
                        // Trailing `**` consumes everything remaining.
                        return true;
                    }
                    // Try every possible split point for the remainder of
                    // the candidate.
                    for split in ci..=candidate.len() {
                        if namespace_pattern_match_bytes(rest, &candidate[split..]) {
                            return true;
                        }
                    }
                    return false;
                } else {
                    // `*`: one or more non-separator chars.
                    let rest = &pattern[pi + 1..];
                    let mut split = ci + 1;
                    // Must consume at least one non-separator char.
                    if split > candidate.len() || is_namespace_separator(candidate[ci]) {
                        return false;
                    }
                    // Greedy/backtracking walk: extend the consumed span as
                    // long as we stay on non-separator chars.
                    loop {
                        if namespace_pattern_match_bytes(rest, &candidate[split..]) {
                            return true;
                        }
                        if split >= candidate.len() || is_namespace_separator(candidate[split]) {
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
    fn applet_registry_parses_openapi_schema_and_permissions() {
        let mut registry = AppletRegistry::new();
        let schema = registry
            .register_from_value(json!({
                "applet_id": "todo",
                "name": "Todo",
                "version": "1.0.0",
                "permissions": [{"resource": "task", "actions": ["read", "write"]}],
                "openapi": {
                    "base_url": "https://api.example",
                    "operations": {"createTask": "POST /tasks"}
                },
                "schema": {"type": "object"}
            }))
            .unwrap();

        assert!(schema.allows("task", "write"));
        assert_eq!(schema.openapi.unwrap().operations["createTask"], "POST /tasks");
        assert!(registry.get("todo").is_some());
    }

    #[test]
    fn applet_portal_manages_space_bridge_and_ghost_actor() {
        let mut manager = AppletPortalManager::new();
        let portal = manager
            .create_portal(SpaceId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap());
        manager.install_applet(&portal.portal_id, "todo").unwrap();
        manager.enable_bridge(&portal.portal_id).unwrap();
        manager.set_ghost_actor(&portal.portal_id, did("ghost")).unwrap();

        let portal = manager.portal(&portal.portal_id).unwrap();
        assert_eq!(portal.mode, PortalMode::Bridge);
        assert!(portal.applets.contains("todo"));
        assert!(portal.ghost_actor.is_some());
    }

    #[test]
    fn signed_applet_registration_rejects_namespace_conflicts() {
        let mut registry = AppletRegistry::new();
        let schema = AppletSchema {
            applet_id: "todo".to_owned(),
            name: "Todo".to_owned(),
            version: "1.0.0".to_owned(),
            permissions: Vec::new(),
            openapi: None,
            schema: json!({"type": "object"}),
        };
        let registration = SignedAppletRegistration::new(
            "todo",
            did("svc"),
            schema.clone(),
            vec![AppletNamespaceDeclaration::exclusive(AppletNamespaceKind::Command, "!todo*")],
            "sig",
        );
        registry.register_signed(registration).unwrap();

        let conflict = SignedAppletRegistration::new(
            "todo2",
            did("svc2"),
            AppletSchema { applet_id: "todo2".to_owned(), ..schema },
            vec![AppletNamespaceDeclaration::exclusive(AppletNamespaceKind::Command, "!todo add")],
            "sig",
        );
        assert!(registry.namespace_conflicts(&conflict.namespaces).len() == 1);
        assert!(registry.register_signed(conflict).is_err());
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
        let registration = AppletEndpointRegistration::new(did("svc"), "bridge");
        registration.validate().unwrap();
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
        mappings.upsert_space(RemoteSpaceMapping {
            protocol: "slack".to_owned(),
            remote_space_id: "C1".to_owned(),
            space_id: SpaceId::new("ck:space:01904100-0000-7000-8000-f949e0272316").unwrap(),
            portal_id: Some("portal".to_owned()),
            title: Some("general".to_owned()),
            external_ref: Value::Null,
        });

        assert_eq!(mappings.user("slack", "U1").unwrap().display_name, Some("User One".to_owned()));
        assert!(mappings.space("slack", "C1").is_some());
    }

    #[test]
    fn namespace_pattern_single_star_matches_one_segment() {
        assert!(namespace_pattern_matches(
            "did:web:slack-bridge.example#ghost-*",
            "did:web:slack-bridge.example#ghost-u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_different_host() {
        assert!(!namespace_pattern_matches(
            "did:web:slack-bridge.example#ghost-*",
            "did:web:other.example#ghost-u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_missing_prefix() {
        assert!(!namespace_pattern_matches(
            "did:web:slack-bridge.example#ghost-*",
            "did:web:slack-bridge.example#bot"
        ));
    }

    #[test]
    fn namespace_pattern_multiple_single_stars_match_segments() {
        assert!(namespace_pattern_matches(
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_does_not_cross_separator() {
        assert!(!namespace_pattern_matches(
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn namespace_pattern_double_star_matches_multiple_segments() {
        assert!(namespace_pattern_matches(
            "slack:team:**",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn namespace_pattern_escaped_star_matches_literal() {
        assert!(namespace_pattern_matches("literal\\*pattern", "literal*pattern"));
    }

    #[test]
    fn namespace_pattern_escaped_star_rejects_non_star() {
        assert!(!namespace_pattern_matches("literal\\*pattern", "literalXpattern"));
    }

    #[test]
    fn namespace_pattern_empty_pattern_rejects_non_empty_candidate() {
        assert!(!namespace_pattern_matches("", "did:web:anything.example"));
    }

    #[test]
    fn namespace_declaration_matches_uses_pattern() {
        let decl = AppletNamespaceDeclaration::exclusive(
            AppletNamespaceKind::Actor,
            "did:web:slack-bridge.example#ghost-*",
        );
        assert!(decl.matches("did:web:slack-bridge.example#ghost-u123"));
        assert!(!decl.matches("did:web:slack-bridge.example#bot"));
    }

    // ─── S-4 (savfox SDK gap) tests ──────────────────────────────────

    fn sample_wire_registration() -> WireAppletRegistration {
        WireAppletRegistration::new(
            "ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["cx.applet.v1".to_owned()],
            AppletWireNamespaces {
                actors: vec!["did:web:slackbridge.example#ghost-*".to_owned()],
                realms: vec![],
                handles: vec![],
            },
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
            payload_digest: digest_before.clone(),
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
            "upstream_rate_limited",
            "Slack returned 429",
        )
        .with_severity(AppletBridgeErrorSeverity::Warning)
        .with_target_ref("ck:event:01904100-0000-7000-8000-deadbeefdead")
        .with_external_ref(serde_json::json!({"slack_response_code": 429}))
        .build(1, hlc())
        .unwrap();
        assert_eq!(event.kind, "ck.applet.bridge_error");
        assert_eq!(event.content["code"], "upstream_rate_limited");
        assert_eq!(event.content["message"], "Slack returned 429");
        assert_eq!(event.content["severity"], "warning");
        assert_eq!(event.content["target_ref"], "ck:event:01904100-0000-7000-8000-deadbeefdead");
        assert_eq!(
            event.applet_id.as_deref(),
            Some("ck:applet:01904100-0000-7000-8000-aaaaaaaaaaaa")
        );
        assert_eq!(event.external_ref.as_ref().unwrap()["slack_response_code"], 429);
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
        assert_eq!(proof.payload_digest, reg.payload_digest().unwrap());

        // Silence any unused warnings on the BTreeMap import — kept for symmetry.
        let _ = BTreeMap::<String, ()>::new();
        let _ = json!({});
    }
}
