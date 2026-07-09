//! Realm search indexes and filters.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Did, RealmId};

/// Searchable Realm directory entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct RealmSearchEntry {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Display name/title.
    pub name: String,
    /// Description/summary.
    pub description: Option<String>,
    /// Tags/labels.
    pub tags: BTreeSet<String>,
    /// Known members.
    pub members: BTreeSet<Did>,
    /// Whether the Realm is publicly listed.
    pub public: bool,
    /// Optional category.
    pub category: Option<String>,
}

impl RealmSearchEntry {
    /// Create a searchable Realm entry.
    pub fn new(realm_id: RealmId, name: impl Into<String>) -> Self {
        Self {
            realm_id,
            name: name.into(),
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
        }
    }
}

/// Realm search query.
#[derive(Clone, Debug, Default)]
pub struct RealmSearchQuery {
    /// Name/description text query.
    pub text: Option<String>,
    /// Required tags.
    pub tags: BTreeSet<String>,
    /// Required members.
    pub members: BTreeSet<Did>,
    /// Restrict to public realms.
    pub public_only: bool,
    /// Maximum results.
    pub limit: Option<usize>,
}

/// In-memory Realm search index.
#[derive(Clone, Debug, Default)]
pub struct RealmSearchIndex {
    entries: BTreeMap<RealmId, RealmSearchEntry>,
}

impl RealmSearchIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a Realm entry.
    pub fn upsert(&mut self, entry: RealmSearchEntry) {
        self.entries.insert(entry.realm_id.clone(), entry);
    }

    /// Get an entry.
    pub fn get(&self, realm_id: &RealmId) -> Option<&RealmSearchEntry> {
        self.entries.get(realm_id)
    }

    /// Search by name or description.
    pub fn search_by_text(&self, query: &str) -> Vec<&RealmSearchEntry> {
        let query = query.to_lowercase();
        self.entries
            .values()
            .filter(|entry| realm_text(entry).contains(&query))
            .collect()
    }

    /// Search by tag.
    pub fn search_by_tag(&self, tag: &str) -> Vec<&RealmSearchEntry> {
        self.entries
            .values()
            .filter(|entry| entry.tags.contains(tag))
            .collect()
    }

    /// Search by member.
    pub fn search_by_member(&self, member: &Did) -> Vec<&RealmSearchEntry> {
        self.entries
            .values()
            .filter(|entry| entry.members.contains(member))
            .collect()
    }

    /// Run a combined query.
    pub fn search(&self, query: RealmSearchQuery) -> Vec<&RealmSearchEntry> {
        let mut scored: Vec<_> = self
            .entries
            .values()
            .filter(|entry| !query.public_only || entry.public)
            .filter(|entry| {
                query
                    .text
                    .as_ref()
                    .map(|text| realm_text(entry).contains(&text.to_lowercase()))
                    .unwrap_or(true)
            })
            .filter(|entry| query.tags.iter().all(|tag| entry.tags.contains(tag)))
            .filter(|entry| {
                query
                    .members
                    .iter()
                    .all(|member| entry.members.contains(member))
            })
            .map(|entry| (realm_score(entry, &query), entry))
            .collect();

        scored.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.name.cmp(&right.name))
        });

        let mut results: Vec<_> = scored.into_iter().map(|(_, entry)| entry).collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }
}

fn realm_text(entry: &RealmSearchEntry) -> String {
    format!(
        "{} {} {}",
        entry.name,
        entry.description.as_deref().unwrap_or_default(),
        entry.tags.iter().cloned().collect::<Vec<_>>().join(" ")
    )
    .to_lowercase()
}

fn realm_score(entry: &RealmSearchEntry, query: &RealmSearchQuery) -> usize {
    let mut score = 0;
    if let Some(text) = &query.text {
        let text = text.to_lowercase();
        if entry.name.to_lowercase().contains(&text) {
            score += 10;
        }
        if entry
            .description
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(&text)
        {
            score += 4;
        }
    }
    score += query
        .tags
        .iter()
        .filter(|tag| entry.tags.contains(*tag))
        .count()
        * 3;
    score += query
        .members
        .iter()
        .filter(|member| entry.members.contains(*member))
        .count()
        * 2;
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn search_finds_realms_by_text_tags_and_members() {
        let alice = did("alice");
        let mut index = RealmSearchIndex::new();
        let mut entry = RealmSearchEntry::new(
            RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            "Rust SDK",
        );
        entry.description = Some("Arkret development".to_owned());
        entry.tags.insert("rust".to_owned());
        entry.members.insert(alice.clone());
        entry.public = true;
        index.upsert(entry);

        assert_eq!(index.search_by_text("sdk").len(), 1);
        assert_eq!(index.search_by_tag("rust").len(), 1);
        assert_eq!(index.search_by_member(&alice).len(), 1);

        let mut tags = BTreeSet::new();
        tags.insert("rust".to_owned());
        let results = index.search(RealmSearchQuery {
            text: Some("arkret".to_owned()),
            tags,
            members: BTreeSet::from([alice]),
            public_only: true,
            limit: Some(1),
        });
        assert_eq!(results.len(), 1);
    }
}
