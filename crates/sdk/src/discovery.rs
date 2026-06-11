//! User discovery, public directories and URL previews.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::search::{RealmSearchEntry, RealmSearchIndex, RealmSearchQuery};
use crate::{Did, RealmId};

/// Public user directory entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryUser {
    /// User DID.
    pub user_id: Did,
    /// Display name.
    pub display_name: Option<String>,
    /// User handle.
    pub handle: Option<String>,
    /// Bio/description.
    pub bio: Option<String>,
    /// Whether user is discoverable.
    pub discoverable: bool,
}

impl DirectoryUser {
    /// Create a discoverable user entry.
    pub fn new(user_id: Did) -> Self {
        Self {
            user_id,
            display_name: None,
            handle: None,
            bio: None,
            discoverable: true,
        }
    }
}

/// Directory service for users and public realms.
#[derive(Clone, Debug, Default)]
pub struct DirectoryService {
    users: BTreeMap<Did, DirectoryUser>,
    realms: RealmSearchIndex,
    categories: BTreeMap<String, BTreeSet<RealmId>>,
}

impl DirectoryService {
    /// Create an empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a user profile.
    pub fn upsert_user(&mut self, user: DirectoryUser) {
        self.users.insert(user.user_id.clone(), user);
    }

    /// Search discoverable users by DID, handle, display name or bio.
    pub fn search_users(&self, query: &str) -> Vec<&DirectoryUser> {
        let query = query.to_lowercase();
        self.users
            .values()
            .filter(|user| user.discoverable)
            .filter(|user| user_text(user).contains(&query))
            .collect()
    }

    /// Get a discoverable user profile.
    pub fn user_profile(&self, user_id: &Did) -> Option<&DirectoryUser> {
        self.users.get(user_id).filter(|user| user.discoverable)
    }

    /// Publish a public Realm entry.
    pub fn publish_realm(&mut self, mut entry: RealmSearchEntry) {
        entry.public = true;
        if let Some(category) = &entry.category {
            self.categories
                .entry(category.clone())
                .or_default()
                .insert(entry.realm_id.clone());
        }
        self.realms.upsert(entry);
    }

    /// Search realms through the directory index.
    pub fn search_realms(&self, query: RealmSearchQuery) -> Vec<&RealmSearchEntry> {
        self.realms.search(query)
    }

    /// List public realms.
    pub fn public_realms(&self) -> Vec<&RealmSearchEntry> {
        self.realms.search(RealmSearchQuery {
            public_only: true,
            ..RealmSearchQuery::default()
        })
    }

    /// List realms in a category.
    pub fn realms_in_category(&self, category: &str) -> Vec<&RealmSearchEntry> {
        self.categories
            .get(category)
            .map(|realm_ids| {
                realm_ids
                    .iter()
                    .filter_map(|realm_id| self.realms.get(realm_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Recommend public realms based on desired tags and existing memberships.
    pub fn recommend_realms(
        &self,
        preferred_tags: BTreeSet<String>,
        already_joined: BTreeSet<RealmId>,
        limit: usize,
    ) -> Vec<&RealmSearchEntry> {
        let mut results: Vec<_> = self
            .public_realms()
            .into_iter()
            .filter(|entry| !already_joined.contains(&entry.realm_id))
            .map(|entry| {
                let score = entry
                    .tags
                    .iter()
                    .filter(|tag| preferred_tags.contains(*tag))
                    .count();
                (score, entry)
            })
            .filter(|(score, _)| *score > 0)
            .collect();
        results.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.name.cmp(&right.name))
        });
        results
            .into_iter()
            .take(limit)
            .map(|(_, entry)| entry)
            .collect()
    }
}

/// OpenGraph URL preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenGraphPreview {
    /// URL.
    pub url: String,
    /// Title.
    pub title: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Image URL.
    pub image: Option<String>,
    /// Site name.
    pub site_name: Option<String>,
    /// Cache timestamp.
    pub fetched_at: DateTime<Utc>,
}

/// In-memory URL preview cache.
#[derive(Clone, Debug, Default)]
pub struct UrlPreviewCache {
    previews: BTreeMap<String, OpenGraphPreview>,
}

impl UrlPreviewCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse OpenGraph metadata from an HTML document and store it.
    pub fn parse_and_store(&mut self, url: impl Into<String>, html: &str) -> OpenGraphPreview {
        let url = url.into();
        let preview = OpenGraphPreview {
            title: meta_content(html, "og:title").or_else(|| title_tag(html)),
            description: meta_content(html, "og:description")
                .or_else(|| meta_content(html, "description")),
            image: meta_content(html, "og:image"),
            site_name: meta_content(html, "og:site_name"),
            fetched_at: Utc::now(),
            url: url.clone(),
        };
        self.previews.insert(url, preview.clone());
        preview
    }

    /// Get cached preview.
    pub fn get(&self, url: &str) -> Option<&OpenGraphPreview> {
        self.previews.get(url)
    }

    /// Clear one cached preview.
    pub fn clear(&mut self, url: &str) -> bool {
        self.previews.remove(url).is_some()
    }
}

fn user_text(user: &DirectoryUser) -> String {
    format!(
        "{} {} {} {}",
        user.user_id.as_str(),
        user.display_name.as_deref().unwrap_or_default(),
        user.handle.as_deref().unwrap_or_default(),
        user.bio.as_deref().unwrap_or_default()
    )
    .to_lowercase()
}

fn meta_content(html: &str, name: &str) -> Option<String> {
    for tag in html.split('<').filter(|part| part.starts_with("meta ")) {
        let tag = tag.split('>').next().unwrap_or(tag);
        let property_matches = attr_value(tag, "property").as_deref() == Some(name);
        let name_matches = attr_value(tag, "name").as_deref() == Some(name);
        if property_matches || name_matches {
            return attr_value(tag, "content");
        }
    }
    None
}

fn title_tag(html: &str) -> Option<String> {
    let start = html.find("<title>")? + "<title>".len();
    let end = html[start..].find("</title>")? + start;
    Some(html[start..end].trim().to_owned())
}

fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn directory_searches_users_public_realms_categories_and_recommendations() {
        let alice = did("alice");
        let mut directory = DirectoryService::new();
        let mut user = DirectoryUser::new(alice.clone());
        user.display_name = Some("Alice Example".to_owned());
        user.handle = Some("alice".to_owned());
        directory.upsert_user(user);

        assert_eq!(directory.search_users("alice").len(), 1);
        assert!(directory.user_profile(&alice).is_some());

        let mut entry = RealmSearchEntry::new(
            RealmId::new("ck:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            "Rust SDK",
        );
        entry.tags.insert("rust".to_owned());
        entry.category = Some("engineering".to_owned());
        directory.publish_realm(entry);

        assert_eq!(directory.public_realms().len(), 1);
        assert_eq!(directory.realms_in_category("engineering").len(), 1);
        assert_eq!(
            directory
                .recommend_realms(BTreeSet::from(["rust".to_owned()]), BTreeSet::new(), 5)
                .len(),
            1
        );
    }

    #[test]
    fn url_preview_parses_open_graph_and_caches() {
        let html = r#"
            <html>
              <head>
                <title>Fallback</title>
                <meta property="og:title" content="Cokret">
                <meta property="og:description" content="SDK docs">
                <meta property="og:image" content="https://example.com/og.png">
              </head>
            </html>
        "#;
        let mut cache = UrlPreviewCache::new();
        let preview = cache.parse_and_store("https://example.com", html);

        assert_eq!(preview.title, Some("Cokret".to_owned()));
        assert_eq!(preview.description, Some("SDK docs".to_owned()));
        assert!(cache.get("https://example.com").is_some());
        assert!(cache.clear("https://example.com"));
    }
}
