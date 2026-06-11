//! In-memory reaction bookkeeping helpers.
//!
//! Rich text parsing (markdown, mentions, link previews) is owned by the
//! `cokret-html` crate; this module only keeps the reaction aggregation
//! helpers that used to live next to it.

use std::collections::BTreeMap;

use crate::Did;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Reaction entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    /// Target event or object ID.
    pub target_id: String,
    /// Reacting user.
    pub user_id: Did,
    /// Canonical shortcode, for example `:thumbsup:`.
    pub shortcode: String,
    /// Renderable emoji or fallback text.
    pub emoji: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Aggregated reactions for a target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReactionSummary {
    /// Counts by shortcode.
    pub counts: BTreeMap<String, usize>,
}

/// In-memory reaction manager.
#[derive(Clone, Debug, Default)]
pub struct ReactionManager {
    reactions: BTreeMap<(String, Did, String), Reaction>,
}

impl ReactionManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a user reaction.
    pub fn add_reaction(
        &mut self,
        target_id: impl Into<String>,
        user_id: Did,
        shortcode: impl Into<String>,
    ) -> Reaction {
        let target_id = target_id.into();
        let shortcode = normalize_shortcode(&shortcode.into());
        let reaction = Reaction {
            target_id: target_id.clone(),
            user_id: user_id.clone(),
            emoji: emoji_shortcode_value(&shortcode),
            shortcode: shortcode.clone(),
            created_at: Utc::now(),
        };
        self.reactions.insert((target_id, user_id, shortcode), reaction.clone());
        reaction
    }

    /// Remove a user reaction.
    pub fn remove_reaction(&mut self, target_id: &str, user_id: &Did, shortcode: &str) -> bool {
        self.reactions
            .remove(&(target_id.to_owned(), user_id.clone(), normalize_shortcode(shortcode)))
            .is_some()
    }

    /// Aggregate reactions by shortcode for a target.
    pub fn aggregate(&self, target_id: &str) -> ReactionSummary {
        let mut summary = ReactionSummary::default();
        for reaction in self.reactions.values().filter(|reaction| reaction.target_id == target_id) {
            *summary.counts.entry(reaction.shortcode.clone()).or_default() += 1;
        }
        summary
    }
}

fn normalize_shortcode(shortcode: &str) -> String {
    let trimmed = shortcode.trim();
    if trimmed.starts_with(':') && trimmed.ends_with(':') {
        trimmed.to_owned()
    } else {
        format!(":{trimmed}:")
    }
}

fn emoji_shortcode_value(shortcode: &str) -> String {
    match shortcode {
        ":thumbsup:" | ":+1:" => "+1",
        ":heart:" => "<3",
        ":laugh:" => "laugh",
        _ => shortcode.trim_matches(':'),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn reactions_add_remove_and_aggregate_shortcodes() {
        let mut manager = ReactionManager::new();
        let alice = did("alice");
        let bob = did("bob");

        manager.add_reaction("event1", alice.clone(), "thumbsup");
        manager.add_reaction("event1", bob, ":thumbsup:");
        assert_eq!(manager.aggregate("event1").counts[":thumbsup:"], 2);

        assert!(manager.remove_reaction("event1", &alice, "thumbsup"));
        assert_eq!(manager.aggregate("event1").counts[":thumbsup:"], 1);
    }
}
