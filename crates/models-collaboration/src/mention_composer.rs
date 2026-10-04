//! Local draft semantics from strand-and-message section 9.4.1 and sidecar 8.1.
//! These types are not wire carriers and do not grant delivery or read access.

use arkret_wire::AccountId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMentionComposerScope {
    Realm,
    Circle,
    Direct,
    Sidecar,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AgentMentionSendChoice {
    #[default]
    PrivateDefault,
    Shared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMentionRoute {
    Shared,
    Direct,
    Sidecar,
    BlockedMixedPrivateTargets,
}

pub fn agent_mention_route(
    scope: AgentMentionComposerScope,
    choice: AgentMentionSendChoice,
    has_owned_agent: bool,
    has_outside_private_target: bool,
    has_audience_mention: bool,
) -> AgentMentionRoute {
    use AgentMentionComposerScope as Scope;
    use AgentMentionRoute as Route;
    match scope {
        Scope::Direct => Route::Direct,
        Scope::Circle => Route::Shared,
        Scope::Realm if choice == AgentMentionSendChoice::Shared || !has_owned_agent => {
            Route::Shared
        }
        Scope::Realm | Scope::Sidecar => {
            if has_outside_private_target || has_audience_mention {
                Route::BlockedMixedPrivateTargets
            } else {
                Route::Sidecar
            }
        }
    }
}

/// A selected visual token, never an address reconstructed from its label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MentionDraftBinding {
    pub subject_account_id: AccountId,
    pub start: usize,
    pub end: usize,
    pub token: String,
}

impl MentionDraftBinding {
    pub fn new(
        subject_account_id: AccountId,
        start: usize,
        end: usize,
        token: String,
        draft: &str,
    ) -> Option<Self> {
        let binding = Self {
            subject_account_id,
            start,
            end,
            token,
        };
        binding.is_visible_in(draft).then_some(binding)
    }

    pub fn is_visible_in(&self, draft: &str) -> bool {
        draft.get(self.start..self.end) == Some(self.token.as_str())
            && self.token.starts_with('@')
            && self.token.len() > 1
            && draft[..self.start].chars().next_back().is_none_or(|ch| {
                ch.is_whitespace() || matches!(ch, '(' | '[' | '{' | '<' | '"' | '\'')
            })
            && draft[self.end..].chars().next().is_none_or(|ch| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        ')' | ']' | '}' | '>' | '"' | '\'' | ',' | '.' | ';' | '!' | '?'
                    )
            })
    }

    /// Preserve untouched tokens across edits outside their ranges. Once an
    /// edit intersects this token, an equal string elsewhere cannot revive it.
    pub fn rebase(&mut self, old: &str, new: &str) -> bool {
        if !self.is_visible_in(old) {
            return false;
        }
        if old == new {
            return true;
        }
        let prefix = old
            .chars()
            .zip(new.chars())
            .take_while(|(a, b)| a == b)
            .map(|(ch, _)| ch.len_utf8())
            .sum::<usize>();
        let suffix = old[prefix..]
            .chars()
            .rev()
            .zip(new[prefix..].chars().rev())
            .take_while(|(a, b)| a == b)
            .map(|(ch, _)| ch.len_utf8())
            .sum::<usize>();
        let old_end = old.len() - suffix;
        let new_end = new.len() - suffix;
        if old_end <= self.start {
            self.start = self.start - old_end + new_end;
            self.end = self.end - old_end + new_end;
        } else if prefix < self.end {
            return false;
        }
        self.is_visible_in(new)
    }
}

/// Holder-private presentation is never reused as the shared token. Callers
/// supply only currently authorized public label material and distinguish a
/// verified slug from a name-only/unresolved suffix in their visible badge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentMentionLabels {
    pub local: String,
    pub shared: String,
}

impl AgentMentionLabels {
    pub fn new(
        public_holder: &str,
        private_holder: Option<&str>,
        owned: bool,
        suffix: &str,
    ) -> Self {
        let holder = if owned { "me" } else { public_holder };
        let local_holder = if owned {
            "me"
        } else {
            private_holder.unwrap_or(public_holder)
        };
        Self {
            local: format!("{local_holder}/{suffix}"),
            shared: format!("{holder}/{suffix}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidCoreId;

    use super::*;

    fn account(station: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    #[test]
    fn edits_never_rebind_or_revive_same_named_tokens() {
        let mut binding = MentionDraftBinding::new(
            account("ak:did_core:web:one.example"),
            4,
            15,
            "@me/summary".into(),
            "询 @me/summary",
        )
        .unwrap();
        assert!(binding.rebase("询 @me/summary", "前 询 @me/summary"));
        assert_eq!(binding.start, 8);
        assert!(!binding.rebase("前 询 @me/summary", "前 询 @me/summary-extra @me/summary"));
        let elsewhere = account("ak:did_core:web:two.example");
        assert_ne!(binding.subject_account_id, elsewhere);
        assert!(
            MentionDraftBinding::new(elsewhere, 0, 11, "@me/summary".into(), "@me/summary-extra")
                .is_none()
        );
    }

    #[test]
    fn holder_private_name_does_not_enter_shared_token() {
        let labels = AgentMentionLabels::new(
            "alice:example.com",
            Some("Private colleague note"),
            false,
            "summary",
        );
        assert_eq!(labels.local, "Private colleague note/summary");
        assert_eq!(labels.shared, "alice:example.com/summary");
        assert!(!labels.shared.contains("Private colleague note"));
    }

    #[test]
    fn mixed_private_targets_require_an_explicit_shared_choice() {
        assert_eq!(
            agent_mention_route(
                AgentMentionComposerScope::Realm,
                AgentMentionSendChoice::PrivateDefault,
                true,
                true,
                false
            ),
            AgentMentionRoute::BlockedMixedPrivateTargets
        );
        assert_eq!(
            agent_mention_route(
                AgentMentionComposerScope::Realm,
                AgentMentionSendChoice::Shared,
                true,
                true,
                true
            ),
            AgentMentionRoute::Shared
        );
        assert_eq!(
            agent_mention_route(
                AgentMentionComposerScope::Sidecar,
                AgentMentionSendChoice::Shared,
                true,
                true,
                false
            ),
            AgentMentionRoute::BlockedMixedPrivateTargets
        );
    }
}
