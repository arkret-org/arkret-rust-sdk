//! Shared v1 push rule core.
//!
//! This module contains the protocol-level watch-state gate shared by
//! clients, servers, and local notification evaluators. Higher-level crates
//! may wrap the result with transport, diagnostics, DND, or UI state, but the
//! `(watch_level, event)` decision should converge here.

use serde::{Deserialize, Serialize};

/// Receiver-level watch state. Mirrors `cx.flow.watch.set`'s `level` field
/// wire encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchLevel {
    /// Pre-engine deny rule. Never deliver, even for direct mentions.
    Muted,
    /// Only deliver when the receiver is explicitly mentioned or assigned.
    #[default]
    MentionsOnly,
    /// Deliver when the receiver participated in the surrounding flow/thread.
    Participating,
    /// Deliver every event in the watched scope.
    All,
}

impl WatchLevel {
    /// Parse the canonical wire form.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "muted" => Some(Self::Muted),
            "mentions_only" => Some(Self::MentionsOnly),
            "participating" => Some(Self::Participating),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Canonical wire string for this level.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Muted => "muted",
            Self::MentionsOnly => "mentions_only",
            Self::Participating => "participating",
            Self::All => "all",
        }
    }
}

/// Minimal event metadata required to make a v1 core decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventContext {
    /// Whether the event explicitly mentions the receiver.
    ///
    /// This is the receiver-side result after direct mention matching or
    /// authorized `audience_mention` expansion. The shared push payload must
    /// not carry the audience name, recipient count, watcher list, or sender
    /// visible expansion diagnostics.
    pub mentions_actor: bool,
    /// Whether the event is addressed or assigned to the receiver.
    pub assigned_to_actor: bool,
    /// Whether this event replies to a thread the receiver authored.
    pub reply_to_self: bool,
    /// Whether the receiver already participated in the surrounding thread.
    pub participating_thread_update: bool,
    /// Whether the event payload is end-to-end encrypted.
    pub is_e2ee: bool,
    /// True when the local device already decrypted the event.
    pub local_decrypted: bool,
}

impl EventContext {
    /// `mentions_only` directs delivery on direct addressing.
    pub fn directed(&self) -> bool {
        self.mentions_actor || self.assigned_to_actor
    }

    /// `participating` directs delivery on any receiver involvement.
    pub fn participated(&self) -> bool {
        self.directed() || self.reply_to_self || self.participating_thread_update
    }
}

/// Decision returned by [`evaluate_watch_level`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShouldNotify {
    /// Deliver a visible notification.
    Notify,
    /// Skip delivery entirely.
    DontNotify,
    /// E2EE event: wake the client so it can decrypt and re-evaluate locally.
    BlindWakeup,
}

impl ShouldNotify {
    /// True when the transport should deliver something to the device.
    pub fn delivers(self) -> bool {
        matches!(self, Self::Notify | Self::BlindWakeup)
    }

    /// True when the decision should produce a visible UI banner.
    pub fn visible(self) -> bool {
        matches!(self, Self::Notify)
    }
}

/// Stable wire reason codes returned alongside [`ShouldNotify`].
pub mod reason_code {
    /// Receiver explicitly muted the flow.
    pub const MUTED: &str = "muted";
    /// `mentions_only` and the event is not directed at the receiver.
    pub const NOT_MENTIONED: &str = "not_mentioned";
    /// `participating` and the receiver has not participated in the thread.
    pub const NOT_PARTICIPATING: &str = "not_participating";
    /// Watch level allows delivery.
    pub const WATCH_ALLOWS: &str = "watch_allows";
    /// E2EE event must be evaluated after local decryption.
    pub const BLIND_WAKEUP_REQUIRED: &str = "blind_wakeup_required";
}

/// Evaluate the receiver's watch level against an event.
pub fn evaluate_watch_level(level: WatchLevel, ctx: &EventContext) -> (ShouldNotify, &'static str) {
    if matches!(level, WatchLevel::Muted) {
        return (ShouldNotify::DontNotify, reason_code::MUTED);
    }

    if ctx.is_e2ee && !ctx.local_decrypted {
        return (ShouldNotify::BlindWakeup, reason_code::BLIND_WAKEUP_REQUIRED);
    }

    match level {
        WatchLevel::Muted => unreachable!("handled above"),
        WatchLevel::All => (ShouldNotify::Notify, reason_code::WATCH_ALLOWS),
        WatchLevel::MentionsOnly => {
            if ctx.directed() {
                (ShouldNotify::Notify, reason_code::WATCH_ALLOWS)
            } else {
                (ShouldNotify::DontNotify, reason_code::NOT_MENTIONED)
            }
        }
        WatchLevel::Participating => {
            if ctx.participated() {
                (ShouldNotify::Notify, reason_code::WATCH_ALLOWS)
            } else {
                (ShouldNotify::DontNotify, reason_code::NOT_PARTICIPATING)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EventContext {
        EventContext::default()
    }

    #[test]
    fn watch_level_wire_roundtrip() {
        for level in [
            WatchLevel::Muted,
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
        ] {
            assert_eq!(WatchLevel::from_wire(level.as_wire()), Some(level));
        }
        assert!(WatchLevel::from_wire("none").is_none());
    }

    #[test]
    fn muted_short_circuits() {
        let mut c = ctx();
        c.mentions_actor = true;
        c.is_e2ee = true;

        let (decision, reason) = evaluate_watch_level(WatchLevel::Muted, &c);

        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::MUTED);
    }

    #[test]
    fn mentions_only_filters_non_directed_events() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &ctx());

        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::NOT_MENTIONED);

        let mut c = ctx();
        c.assigned_to_actor = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);
    }

    #[test]
    fn participating_filters_non_participants() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::Participating, &ctx());

        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::NOT_PARTICIPATING);

        let mut c = ctx();
        c.participating_thread_update = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::Participating, &c);
        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);
    }

    #[test]
    fn all_passes_plain_events() {
        let (decision, reason) = evaluate_watch_level(WatchLevel::All, &ctx());

        assert_eq!(decision, ShouldNotify::Notify);
        assert_eq!(reason, reason_code::WATCH_ALLOWS);
    }

    #[test]
    fn e2ee_requires_blind_wakeup_until_decrypted() {
        for level in [WatchLevel::MentionsOnly, WatchLevel::Participating, WatchLevel::All] {
            let mut c = ctx();
            c.is_e2ee = true;

            let (decision, reason) = evaluate_watch_level(level, &c);

            assert_eq!(decision, ShouldNotify::BlindWakeup);
            assert_eq!(reason, reason_code::BLIND_WAKEUP_REQUIRED);
            assert!(decision.delivers());
            assert!(!decision.visible());
        }

        let mut c = ctx();
        c.is_e2ee = true;
        c.local_decrypted = true;
        let (decision, reason) = evaluate_watch_level(WatchLevel::MentionsOnly, &c);
        assert_eq!(decision, ShouldNotify::DontNotify);
        assert_eq!(reason, reason_code::NOT_MENTIONED);
    }
}
