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
    pub state_hash: String,
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
    if !manifest.state_hash.starts_with("sha256:") {
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
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap(),
            exported_by: alice,
            source_service_did: service.clone(),
            event_count: 10,
            state_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
