//! User profile management.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, Error, Result, SpaceId};

/// User profile state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// User DID.
    pub user_id: Did,
    /// Display name.
    pub display_name: Option<String>,
    /// Avatar URL or media reference.
    pub avatar_url: Option<String>,
    /// Bio/description.
    pub bio: Option<String>,
    /// Monotonic profile version.
    pub version: u64,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

impl UserProfile {
    /// Create an empty profile at version 0.
    pub fn new(user_id: Did) -> Self {
        Self {
            user_id,
            display_name: None,
            avatar_url: None,
            bio: None,
            version: 0,
            updated_at: Utc::now(),
        }
    }
}

/// External device approval mode for sovereign deployments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDeviceApprovalMode {
    Allow,
    RequireApproval,
    Deny,
}

/// Data classification level used by sovereign deployment policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Sovereign deployment policy primitives for profiles and spaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignDeploymentPolicy {
    pub deployment_id: String,
    pub owner: Did,
    pub home_domain: String,
    #[serde(default)]
    pub closed_federation: bool,
    #[serde(default)]
    pub federation_allowlist: BTreeSet<String>,
    #[serde(default)]
    pub resolver_pins: BTreeMap<String, String>,
    pub external_device_approval: ExternalDeviceApprovalMode,
    #[serde(default)]
    pub data_classification: BTreeMap<String, DataClassification>,
    pub created_at: DateTime<Utc>,
}

impl SovereignDeploymentPolicy {
    /// Create a closed-federation policy owned by a DID.
    pub fn closed(owner: Did, home_domain: impl Into<String>) -> Self {
        Self {
            deployment_id: format!("deploy_{}", ulid::Ulid::new()),
            owner,
            home_domain: home_domain.into(),
            closed_federation: true,
            federation_allowlist: BTreeSet::new(),
            resolver_pins: BTreeMap::new(),
            external_device_approval: ExternalDeviceApprovalMode::RequireApproval,
            data_classification: BTreeMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Add a federated domain to the allowlist.
    pub fn allow_domain(&mut self, domain: impl Into<String>) {
        self.federation_allowlist.insert(domain.into());
    }

    /// Check whether a federated domain is allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        !self.closed_federation || self.federation_allowlist.contains(domain)
    }

    /// Pin a DID resolver endpoint or trust root.
    pub fn pin_resolver(&mut self, did_method: impl Into<String>, resolver_ref: impl Into<String>) {
        self.resolver_pins.insert(did_method.into(), resolver_ref.into());
    }

    /// Classify a data subject reference.
    pub fn classify(&mut self, subject_ref: impl Into<String>, classification: DataClassification) {
        self.data_classification.insert(subject_ref.into(), classification);
    }
}

/// Space export manifest used for validation before import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceExportManifest {
    pub export_id: String,
    pub space_id: SpaceId,
    pub exported_by: Did,
    pub source_service_did: Did,
    pub event_count: u64,
    pub state_digest: String,
    pub created_at: DateTime<Utc>,
}

/// Result of validating an import manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceImportValidation {
    pub accepted: bool,
    pub errors: Vec<String>,
}

/// Service replacement contract for sovereign deployments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceReplacementPlan {
    pub old_service_did: Did,
    pub new_service_did: Did,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
    #[serde(default)]
    pub preserve_service_history: bool,
}

impl ServiceReplacementPlan {
    /// Validate a service replacement contract.
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        if self.old_service_did == self.new_service_did {
            return Err(Error::Protocol("replacement service must change".to_owned()));
        }
        if self.effective_at < now {
            return Err(Error::Protocol("replacement effective time is in the past".to_owned()));
        }
        if self.reason.trim().is_empty() {
            return Err(Error::Protocol("replacement reason is empty".to_owned()));
        }
        Ok(())
    }
}

/// Validate a space import manifest against expected local constraints.
pub fn validate_space_import(
    manifest: &SpaceExportManifest,
    expected_space_id: Option<&SpaceId>,
    allowed_source_services: &BTreeSet<Did>,
) -> SpaceImportValidation {
    let mut errors = Vec::new();
    if let Some(expected_space_id) = expected_space_id
        && &manifest.space_id != expected_space_id
    {
        errors.push("space id mismatch".to_owned());
    }
    if manifest.event_count == 0 {
        errors.push("export contains no events".to_owned());
    }
    if !manifest.state_digest.starts_with("sha256:") {
        errors.push("state hash is not a sha256 digest".to_owned());
    }
    if !allowed_source_services.is_empty()
        && !allowed_source_services.contains(&manifest.source_service_did)
    {
        errors.push("source service is not allowed".to_owned());
    }

    SpaceImportValidation { accepted: errors.is_empty(), errors }
}

/// Optional TSP trust binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TspTrustBinding {
    pub subject: Did,
    pub tsp_endpoint: String,
    pub trust_anchor: String,
    pub binding_proof: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl TspTrustBinding {
    /// Check whether the binding is active.
    pub fn is_active(&self, at: DateTime<Utc>) -> bool {
        !self.binding_proof.is_empty()
            && self.expires_at.map(|expires_at| expires_at > at).unwrap_or(true)
    }
}

/// Pairwise control message kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairwiseControlMessageKind {
    DeviceApprovalRequest,
    DeviceApprovalDecision,
    ResolverPinUpdate,
    TrustBindingUpdate,
    KillSwitch,
    Custom(String),
}

/// Pairwise control message hook payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairwiseControlMessage {
    pub message_id: String,
    pub sender: Did,
    pub recipient: Did,
    pub kind: PairwiseControlMessageKind,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// In-memory profile manager with version history.
#[derive(Clone, Debug, Default)]
pub struct ProfileManager {
    profiles: BTreeMap<Did, UserProfile>,
    history: BTreeMap<Did, Vec<UserProfile>>,
}

impl ProfileManager {
    /// Create an empty profile manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current profile.
    pub fn profile(&self, user_id: &Did) -> Option<&UserProfile> {
        self.profiles.get(user_id)
    }

    /// Get profile version history.
    pub fn history(&self, user_id: &Did) -> Vec<&UserProfile> {
        self.history.get(user_id).map(|history| history.iter().collect()).unwrap_or_default()
    }

    /// Replace profile fields and increment version.
    pub fn update_profile(
        &mut self,
        user_id: Did,
        display_name: Option<String>,
        avatar_url: Option<String>,
        bio: Option<String>,
    ) -> UserProfile {
        let mut profile =
            self.profiles.remove(&user_id).unwrap_or_else(|| UserProfile::new(user_id.clone()));
        profile.display_name = display_name;
        profile.avatar_url = avatar_url;
        profile.bio = bio;
        profile.version += 1;
        profile.updated_at = Utc::now();
        self.profiles.insert(user_id.clone(), profile.clone());
        self.history.entry(user_id).or_default().push(profile.clone());
        profile
    }

    /// Update display name only.
    pub fn set_display_name(
        &mut self,
        user_id: Did,
        display_name: impl Into<String>,
    ) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(user_id, Some(display_name.into()), current.avatar_url, current.bio)
    }

    /// Update avatar URL only.
    pub fn set_avatar_url(&mut self, user_id: Did, avatar_url: impl Into<String>) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(user_id, current.display_name, Some(avatar_url.into()), current.bio)
    }

    /// Update bio only.
    pub fn set_bio(&mut self, user_id: Did, bio: impl Into<String>) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(user_id, current.display_name, current.avatar_url, Some(bio.into()))
    }

    /// Get a specific profile version.
    pub fn profile_version(&self, user_id: &Did, version: u64) -> Result<&UserProfile> {
        self.history
            .get(user_id)
            .and_then(|history| history.iter().find(|profile| profile.version == version))
            .ok_or_else(|| Error::Protocol("profile version not found".to_owned()))
    }
}

// ─── S-9 (savfox SDK gap): cx.profile.create / cx.profile.update builder ──

/// Operation kind discriminant for [`ProfileCreateBuilder::build`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEventKind {
    /// `cx.profile.create` — first appearance of an actor profile.
    Create,
    /// `cx.profile.update` — subsequent revisions.
    Update,
}

impl ProfileEventKind {
    /// Wire string for `Event::kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileEventKind::Create => "cx.profile.create",
            ProfileEventKind::Update => "cx.profile.update",
        }
    }
}

/// Build a `cx.profile.create` / `cx.profile.update` Event Envelope
/// payload. Ghost-actor profiles (spec §9) MUST carry `actor_kind =
/// "ghost"`, `managed_by_applet`, and `accountability` blocks; this
/// builder stamps those slots so callers no longer drift between
/// applets.
#[derive(Clone, Debug)]
pub struct ProfileCreateBuilder {
    realm_id: crate::RealmId,
    actor_id: Did,
    display_name: Option<String>,
    avatar_url: Option<String>,
    bio: Option<String>,
    actor_kind: Option<String>,
    managed_by_applet: Option<String>,
    accountable_to: Option<Did>,
    external_ref: Option<serde_json::Value>,
    kind: ProfileEventKind,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl ProfileCreateBuilder {
    /// Construct a new builder for a `cx.profile.create` Envelope.
    /// Switch to `cx.profile.update` via [`Self::for_update`].
    pub fn new(realm_id: crate::RealmId, actor_id: Did) -> Self {
        Self {
            realm_id,
            actor_id,
            display_name: None,
            avatar_url: None,
            bio: None,
            actor_kind: None,
            managed_by_applet: None,
            accountable_to: None,
            external_ref: None,
            kind: ProfileEventKind::Create,
            extra: serde_json::Map::new(),
        }
    }

    pub fn for_update(mut self) -> Self {
        self.kind = ProfileEventKind::Update;
        self
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn with_avatar_url(mut self, avatar_url: impl Into<String>) -> Self {
        self.avatar_url = Some(avatar_url.into());
        self
    }

    pub fn with_bio(mut self, bio: impl Into<String>) -> Self {
        self.bio = Some(bio.into());
        self
    }

    /// Stamp this profile as an Applet-managed ghost actor. Sets
    /// `actor_kind = "ghost"`, `managed_by_applet = <applet_id>`, and
    /// `accountability.accountable_to = <accountable_to>` per spec §9.
    pub fn with_ghost_kind(mut self, applet_id: impl Into<String>, accountable_to: Did) -> Self {
        self.actor_kind = Some("ghost".to_owned());
        self.managed_by_applet = Some(applet_id.into());
        self.accountable_to = Some(accountable_to);
        self
    }

    /// Attach the bridge-side external reference (e.g. `{"slack_user_id":
    /// "U12345"}`) so receivers can dedupe across bridges.
    pub fn with_external_ref(mut self, external_ref: serde_json::Value) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    /// Open-shape: stash future / spec-deferred keys into the
    /// payload's content object. Use sparingly — keyed fields should
    /// land in spec-mirroring methods above instead.
    pub fn with_extra(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Build the unsigned `Event` Envelope. Caller is responsible for
    /// `actor_seq` + `hlc` + (re-)signing via
    /// [`contrix_signatures::sign_event`].
    pub fn build(self, actor_seq: u64, hlc: crate::Hlc) -> Result<crate::Event> {
        let mut content = serde_json::Map::new();
        content.insert("actor_id".to_owned(), serde_json::Value::String(self.actor_id.to_string()));
        if let Some(display_name) = &self.display_name {
            content
                .insert("display_name".to_owned(), serde_json::Value::String(display_name.clone()));
        }
        if let Some(avatar_url) = &self.avatar_url {
            content.insert("avatar_url".to_owned(), serde_json::Value::String(avatar_url.clone()));
        }
        if let Some(bio) = &self.bio {
            content.insert("bio".to_owned(), serde_json::Value::String(bio.clone()));
        }
        if let Some(actor_kind) = &self.actor_kind {
            content.insert("actor_kind".to_owned(), serde_json::Value::String(actor_kind.clone()));
        }
        if let Some(applet_id) = &self.managed_by_applet {
            content.insert(
                "managed_by_applet".to_owned(),
                serde_json::Value::String(applet_id.clone()),
            );
        }
        if let Some(accountable_to) = &self.accountable_to {
            let mut accountability = serde_json::Map::new();
            accountability.insert(
                "accountable_to".to_owned(),
                serde_json::Value::String(accountable_to.to_string()),
            );
            content.insert("accountability".to_owned(), serde_json::Value::Object(accountability));
        }
        for (k, v) in &self.extra {
            content.insert(k.clone(), v.clone());
        }

        let mut event = crate::Event::new(
            self.kind.as_str(),
            self.realm_id,
            self.actor_id,
            actor_seq,
            hlc,
            serde_json::Value::Object(content),
        )?;
        // S-7: stash external_ref on the top-level slot, not in `content`.
        if let Some(external_ref) = self.external_ref {
            event.external_ref = Some(external_ref);
        }
        Ok(event)
    }
}

#[cfg(test)]
mod profile_builder_tests {
    use super::*;

    fn realm() -> crate::RealmId {
        crate::RealmId::new("cx:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn applet_owner() -> Did {
        Did::new("did:web:owner.example").unwrap()
    }

    fn hlc() -> crate::Hlc {
        crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    #[test]
    fn profile_create_builder_stamps_kind_and_actor_id() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .with_display_name("Alice")
            .build(1, hlc())
            .unwrap();
        assert_eq!(event.kind, "cx.profile.create");
        assert_eq!(event.content["actor_id"], "did:web:alice.example");
        assert_eq!(event.content["display_name"], "Alice");
    }

    #[test]
    fn profile_update_switches_event_kind() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .for_update()
            .with_display_name("Alice 2")
            .build(2, hlc())
            .unwrap();
        assert_eq!(event.kind, "cx.profile.update");
    }

    #[test]
    fn profile_ghost_kind_stamps_required_fields() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .with_ghost_kind("cx:applet:01904100-0000-7000-8000-aaaaaaaaaaaa", applet_owner())
            .with_external_ref(serde_json::json!({"slack_user_id": "U12345"}))
            .build(1, hlc())
            .unwrap();
        assert_eq!(event.content["actor_kind"], "ghost");
        assert_eq!(
            event.content["managed_by_applet"],
            "cx:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"
        );
        assert_eq!(event.content["accountability"]["accountable_to"], "did:web:owner.example");
        assert_eq!(event.external_ref.as_ref().unwrap()["slack_user_id"], "U12345");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn profiles_manage_display_avatar_bio_and_versions() {
        let alice = did("alice");
        let mut manager = ProfileManager::new();

        let v1 = manager.set_display_name(alice.clone(), "Alice");
        assert_eq!(v1.version, 1);
        assert_eq!(v1.display_name, Some("Alice".to_owned()));

        let v2 = manager.set_avatar_url(alice.clone(), "cx:blob:avatar");
        assert_eq!(v2.version, 2);
        assert_eq!(v2.display_name, Some("Alice".to_owned()));
        assert_eq!(v2.avatar_url, Some("cx:blob:avatar".to_owned()));

        let v3 = manager.set_bio(alice.clone(), "Builder");
        assert_eq!(v3.version, 3);
        assert_eq!(manager.profile(&alice).unwrap().bio, Some("Builder".to_owned()));
        assert_eq!(manager.history(&alice).len(), 3);
        assert_eq!(
            manager.profile_version(&alice, 1).unwrap().display_name,
            Some("Alice".to_owned())
        );
    }

    #[test]
    fn sovereign_policy_validates_domains_resolver_pins_and_imports() {
        let alice = did("alice");
        let service = did("svc");
        let mut policy = SovereignDeploymentPolicy::closed(alice.clone(), "example.com");
        assert!(!policy.is_domain_allowed("remote.example"));
        policy.allow_domain("remote.example");
        policy.pin_resolver("web", "https://resolver.example");
        policy.classify("space:private", DataClassification::Restricted);
        assert!(policy.is_domain_allowed("remote.example"));
        assert_eq!(policy.resolver_pins["web"], "https://resolver.example");

        let manifest = SpaceExportManifest {
            export_id: "export1".to_owned(),
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            exported_by: alice,
            source_service_did: service.clone(),
            event_count: 10,
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            created_at: Utc::now(),
        };
        let validation =
            validate_space_import(&manifest, Some(&manifest.space_id), &BTreeSet::from([service]));
        assert!(validation.accepted);
    }

    #[test]
    fn service_replacement_tsp_and_pairwise_control_models_validate() {
        let old_service = did("old");
        let new_service = did("new");
        let plan = ServiceReplacementPlan {
            old_service_did: old_service.clone(),
            new_service_did: new_service.clone(),
            reason: "rotate service".to_owned(),
            effective_at: Utc::now() + chrono::Duration::hours(1),
            preserve_service_history: true,
        };
        plan.validate(Utc::now()).unwrap();

        let binding = TspTrustBinding {
            subject: old_service.clone(),
            tsp_endpoint: "https://tsp.example".to_owned(),
            trust_anchor: "anchor".to_owned(),
            binding_proof: "proof".to_owned(),
            created_at: Utc::now(),
            expires_at: None,
        };
        assert!(binding.is_active(Utc::now()));

        let message = PairwiseControlMessage {
            message_id: "ctrl1".to_owned(),
            sender: old_service,
            recipient: new_service,
            kind: PairwiseControlMessageKind::ResolverPinUpdate,
            payload: serde_json::json!({"method": "web"}),
            created_at: Utc::now(),
            expires_at: None,
        };
        assert_eq!(message.kind, PairwiseControlMessageKind::ResolverPinUpdate);
    }
}
