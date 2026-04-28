//! User profile management.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, Error, Result};

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
}
