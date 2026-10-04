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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMentionRoute {
    Shared,
    Direct,
    Sidecar,
    BlockedMixedPrivateTargets,
}

/// Verified Realm mode determines the route; a display choice grants no publication.
pub fn agent_mention_route_with_modes(
    scope: AgentMentionComposerScope,
    modes: &[Option<crate::agent_interaction::AgentInteractionMode>],
    outside: bool,
    audience: bool,
) -> AgentMentionRoute {
    use AgentMentionComposerScope as Scope;
    use AgentMentionRoute as Route;

    use crate::agent_interaction::AgentInteractionMode as Mode;
    if scope == Scope::Direct {
        return Route::Direct;
    }
    if scope == Scope::Sidecar {
        return if outside || audience {
            Route::BlockedMixedPrivateTargets
        } else {
            Route::Sidecar
        };
    }
    if modes.iter().any(Option::is_none) {
        return Route::BlockedMixedPrivateTargets;
    }
    let private = modes.contains(&Some(Mode::Private));
    let public = modes.contains(&Some(Mode::Public));
    if !private {
        return Route::Shared;
    }
    if scope == Scope::Circle || public || outside || audience {
        Route::BlockedMixedPrivateTargets
    } else {
        Route::Sidecar
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
    fn realm_modes_circle_and_private_scopes_keep_their_boundaries() {
        use AgentMentionComposerScope::{Circle, Direct, Realm, Sidecar};
        use AgentMentionRoute::{
            BlockedMixedPrivateTargets as Blocked, Direct as DirectRoute, Shared,
            Sidecar as PrivateRoute,
        };

        use crate::agent_interaction::AgentInteractionMode::{Private, Public};
        for (scope, modes, outside, audience, expected) in [
            (Realm, vec![Some(Public)], false, false, Shared),
            (Realm, vec![Some(Private)], false, false, PrivateRoute),
            (
                Realm,
                vec![Some(Public), Some(Private)],
                false,
                false,
                Blocked,
            ),
            (Realm, vec![Some(Private)], true, false, Blocked),
            (Realm, vec![Some(Private)], false, true, Blocked),
            (Realm, vec![None], false, false, Blocked),
            (Circle, vec![Some(Private)], false, false, Blocked),
            (Circle, vec![Some(Public)], false, false, Shared),
            (Sidecar, vec![Some(Public)], false, false, PrivateRoute),
            (Sidecar, vec![None], false, false, PrivateRoute),
            (Direct, vec![None], false, false, DirectRoute),
        ] {
            assert_eq!(
                agent_mention_route_with_modes(scope, &modes, outside, audience),
                expected
            );
        }
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
}
