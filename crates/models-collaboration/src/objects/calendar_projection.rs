//! Shared Calendar schedule and RSVP read models.
//!
//! `calendar-event.md` §9 makes these client-local derived models: they are
//! computed from the authorized Event set plus the schedule revision frontier,
//! and the Calendar profile deliberately does not add a remote Calendar API.
//! They live here so a server projection, a client and the conformance runner
//! all classify heads the same way instead of each inventing a rule.
//!
//! Nothing here picks a winner among concurrent responses. The spec forbids
//! resolving them by HLC, `created_at`, `event_id` or arrival order, so a
//! conflict stays a conflict until the responder writes a later RSVP that
//! observes both heads.

use std::collections::BTreeSet;

use arkret_wire::Hash;
use serde::{Deserialize, Serialize};

use crate::objects::productivity::RsvpResponse;

/// Whether the Calendar schedule itself has converged.
///
/// Only `Settled` may expand occurrences, author an RSVP or derive an exact
/// schedule notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleResolutionState {
    /// One head, or several heads whose canonical schedule bytes are identical.
    /// Equal-valued heads are all retained; identity is not collapsed.
    Settled,
    /// Two or more heads carry different schedule values.
    Conflict,
    /// The reader cannot decrypt the schedule, so it cannot compare heads.
    EncryptedUnresolved,
}

/// Canonical schedule revision frontier for one Calendar Strand.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarScheduleProjection {
    /// Every current schedule revision head, sorted and deduplicated. An RSVP
    /// entry basis is drawn from exactly this set.
    pub schedule_revision_heads: Vec<Hash>,
    pub resolution_state: ScheduleResolutionState,
}

impl CalendarScheduleProjection {
    /// Builds the frontier from the accepted schedule revision heads.
    ///
    /// `head_schedule_bytes` is the canonical schedule bytes each head carries,
    /// or `None` when the reader cannot decrypt it. A reader that cannot
    /// compare even one head reports `EncryptedUnresolved` rather than guessing
    /// that the heads agree.
    pub fn from_heads(heads: &[(Hash, Option<Vec<u8>>)]) -> Self {
        let mut schedule_revision_heads: Vec<Hash> =
            heads.iter().map(|(digest, _)| digest.clone()).collect();
        schedule_revision_heads.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        schedule_revision_heads.dedup_by(|left, right| left.as_str() == right.as_str());

        let resolution_state = if heads.iter().any(|(_, bytes)| bytes.is_none()) {
            ScheduleResolutionState::EncryptedUnresolved
        } else {
            let distinct: BTreeSet<&Vec<u8>> = heads
                .iter()
                .filter_map(|(_, bytes)| bytes.as_ref())
                .collect();
            if distinct.len() > 1 {
                ScheduleResolutionState::Conflict
            } else {
                ScheduleResolutionState::Settled
            }
        };
        Self {
            schedule_revision_heads,
            resolution_state,
        }
    }

    pub fn is_settled(&self) -> bool {
        self.resolution_state == ScheduleResolutionState::Settled
    }
}

/// Basis axis: how the head relates to the current schedule revision frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpBasisClass {
    /// Answered against the current schedule.
    Current,
    /// Still counts, but a significant field changed since, so the UI must ask
    /// the responder to confirm.
    EffectiveNeedsReconfirmation,
    /// An identity-affecting edit moved the occurrence key. The head is kept
    /// for audit and never migrated to the new key.
    StaleOrphaned,
    /// A basis ref cannot be resolved, is invisible, or is not on the target
    /// Strand's schedule revision DAG.
    UnresolvedBasis,
}

/// Response axis: whether the response value could be read at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpResponseClass {
    Resolved,
    /// Decryption authenticated but the plaintext is not a valid response, or
    /// authentication failed outright.
    InvalidResponse,
    /// No key. The head is listed, and no status is fabricated for it.
    EncryptedUnresolved,
}

impl RsvpBasisClass {
    /// Only the first two classes may contribute to the effective response.
    pub fn participates(self) -> bool {
        matches!(self, Self::Current | Self::EffectiveNeedsReconfirmation)
    }
}

impl RsvpResponseClass {
    pub fn participates(self) -> bool {
        self == Self::Resolved
    }
}

/// One classified `mv_register` head.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarRsvpHead {
    pub source_event_digest: Hash,
    /// Schedule revision frontier this responder signed into the entry.
    pub schedule_basis_refs: Vec<Hash>,
    /// Present only when the response axis resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RsvpResponse>,
    pub basis_class: RsvpBasisClass,
    pub response_class: RsvpResponseClass,
}

impl CalendarRsvpHead {
    pub fn participates(&self) -> bool {
        self.basis_class.participates() && self.response_class.participates()
    }

    /// Classifies the basis axis.
    ///
    /// `known_schedule_revisions` is the schedule revision DAG this reader has
    /// actually seen — a basis ref outside it is unresolvable, not stale. What
    /// changed since the head was written arrives as the two flags rather than
    /// being derived here, because deciding significance needs the schedule
    /// plaintext, which a reader of an encrypted Realm does not have.
    ///
    /// `identity_affecting_changed` says whether `start`, `timezone`, `all_day`
    /// or `recurrence` moved since this head was written; that is what turns an
    /// instance head into an orphan, because the occurrence key itself changed.
    pub fn classify_basis(
        schedule_basis_refs: &[Hash],
        known_schedule_revisions: &[Hash],
        is_instance_head: bool,
        identity_affecting_changed: bool,
        significant_changed: bool,
    ) -> RsvpBasisClass {
        let known: BTreeSet<&str> = known_schedule_revisions.iter().map(Hash::as_str).collect();
        // A basis ref outside the known DAG is not evidence of anything, so the
        // head is set aside rather than counted as current.
        if schedule_basis_refs.is_empty()
            || schedule_basis_refs
                .iter()
                .any(|basis| !known.contains(basis.as_str()))
        {
            return RsvpBasisClass::UnresolvedBasis;
        }
        if identity_affecting_changed {
            // Series heads have no occurrence in their subject, so they cannot
            // be orphaned by a key change; they only need reconfirming.
            return if is_instance_head {
                RsvpBasisClass::StaleOrphaned
            } else {
                RsvpBasisClass::EffectiveNeedsReconfirmation
            };
        }
        if significant_changed {
            return RsvpBasisClass::EffectiveNeedsReconfirmation;
        }
        RsvpBasisClass::Current
    }
}

/// Whether the responder currently has one answer or several.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsvpResolutionState {
    Settled,
    /// Concurrent heads whose full `(basis, response)` differ. Only the
    /// responder can resolve it, by answering again while observing both.
    Conflict,
}

/// Converged RSVP read model for one responder and one occurrence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarRsvpProjection {
    pub instance_heads: Vec<CalendarRsvpHead>,
    pub series_heads: Vec<CalendarRsvpHead>,
}

impl CalendarRsvpProjection {
    /// Heads that decide the answer shown to the user.
    ///
    /// Instance heads override the series fallback and the two sets are never
    /// unioned: merging them would display a fallback next to an override as if
    /// the responder had answered twice.
    pub fn effective_heads(&self) -> Vec<&CalendarRsvpHead> {
        let instance: Vec<&CalendarRsvpHead> = self
            .instance_heads
            .iter()
            .filter(|head| head.participates())
            .collect();
        if !instance.is_empty() {
            return instance;
        }
        self.series_heads
            .iter()
            .filter(|head| head.participates())
            .collect()
    }

    /// `Conflict` when the effective heads disagree on the full
    /// `(schedule_basis_refs, response)` tuple.
    ///
    /// Two heads whose plaintext is identical are not a conflict even though
    /// their ciphertexts differ: randomized encryption makes byte inequality
    /// meaningless as a signal about what the user answered.
    pub fn resolution_state(&self) -> RsvpResolutionState {
        let heads = self.effective_heads();
        // Compare the full (basis, response) tuple. Serializing the response
        // keeps the comparison on the decrypted value rather than on ciphertext
        // identity, which randomized encryption makes meaningless.
        let distinct: BTreeSet<(Vec<&str>, Option<String>)> = heads
            .iter()
            .map(|head| {
                (
                    head.schedule_basis_refs
                        .iter()
                        .map(Hash::as_str)
                        .collect::<Vec<_>>(),
                    head.response
                        .as_ref()
                        .and_then(|response| serde_json::to_string(response).ok()),
                )
            })
            .collect();
        if distinct.len() > 1 {
            RsvpResolutionState::Conflict
        } else {
            RsvpResolutionState::Settled
        }
    }

    /// The single response to display, or `None` when there is none or the
    /// responder has an unresolved conflict.
    pub fn effective_response(&self) -> Option<&RsvpResponse> {
        if self.resolution_state() == RsvpResolutionState::Conflict {
            return None;
        }
        self.effective_heads()
            .first()
            .and_then(|head| head.response.as_ref())
    }

    /// Heads excluded from the effective response, so a UI can explain why a
    /// response does not count instead of silently dropping it.
    pub fn excluded_heads(&self) -> Vec<&CalendarRsvpHead> {
        self.instance_heads
            .iter()
            .chain(self.series_heads.iter())
            .filter(|head| !head.participates())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::productivity::RsvpStatus;

    fn digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn head(digest_byte: u8, basis: Vec<Hash>, status: RsvpStatus) -> CalendarRsvpHead {
        CalendarRsvpHead {
            source_event_digest: digest(digest_byte),
            schedule_basis_refs: basis,
            response: Some(RsvpResponse {
                status,
                comment: None,
            }),
            basis_class: RsvpBasisClass::Current,
            response_class: RsvpResponseClass::Resolved,
        }
    }

    #[test]
    fn equal_valued_concurrent_schedule_heads_are_settled_and_all_retained() {
        let projection = CalendarScheduleProjection::from_heads(&[
            (digest(1), Some(b"same".to_vec())),
            (digest(2), Some(b"same".to_vec())),
        ]);
        assert_eq!(
            projection.resolution_state,
            ScheduleResolutionState::Settled
        );
        // Identity is not collapsed just because the values agree.
        assert_eq!(projection.schedule_revision_heads.len(), 2);
    }

    #[test]
    fn differing_schedule_heads_conflict_and_undecryptable_heads_are_unresolved() {
        let conflict = CalendarScheduleProjection::from_heads(&[
            (digest(1), Some(b"a".to_vec())),
            (digest(2), Some(b"b".to_vec())),
        ]);
        assert_eq!(conflict.resolution_state, ScheduleResolutionState::Conflict);

        let blind = CalendarScheduleProjection::from_heads(&[
            (digest(1), Some(b"a".to_vec())),
            (digest(2), None),
        ]);
        assert_eq!(
            blind.resolution_state,
            ScheduleResolutionState::EncryptedUnresolved
        );
    }

    #[test]
    fn basis_outside_the_known_frontier_is_unresolved_not_current() {
        assert_eq!(
            CalendarRsvpHead::classify_basis(&[digest(9)], &[digest(1)], false, false, false,),
            RsvpBasisClass::UnresolvedBasis
        );
        assert_eq!(
            CalendarRsvpHead::classify_basis(&[], &[digest(1)], false, false, false,),
            RsvpBasisClass::UnresolvedBasis
        );
    }

    #[test]
    fn identity_affecting_edits_orphan_instance_heads_but_only_reconfirm_series() {
        let known = [digest(1), digest(2)];
        assert_eq!(
            CalendarRsvpHead::classify_basis(&[digest(2)], &known, true, true, false,),
            RsvpBasisClass::StaleOrphaned
        );
        assert_eq!(
            CalendarRsvpHead::classify_basis(&[digest(2)], &known, false, true, false,),
            RsvpBasisClass::EffectiveNeedsReconfirmation
        );
        assert_eq!(
            CalendarRsvpHead::classify_basis(&[digest(2)], &known, true, false, true,),
            RsvpBasisClass::EffectiveNeedsReconfirmation
        );
    }

    #[test]
    fn instance_heads_override_series_and_the_two_are_never_unioned() {
        let projection = CalendarRsvpProjection {
            instance_heads: vec![head(1, vec![digest(1)], RsvpStatus::Declined)],
            series_heads: vec![head(2, vec![digest(1)], RsvpStatus::Accepted)],
        };
        assert_eq!(projection.effective_heads().len(), 1);
        assert_eq!(
            projection.effective_response().unwrap().status,
            RsvpStatus::Declined
        );
        // Different statuses across the two tiers are a fallback plus an
        // override, not a conflict.
        assert_eq!(projection.resolution_state(), RsvpResolutionState::Settled);
    }

    #[test]
    fn series_is_the_fallback_when_no_instance_head_participates() {
        let mut stale = head(1, vec![digest(1)], RsvpStatus::Declined);
        stale.basis_class = RsvpBasisClass::StaleOrphaned;
        let projection = CalendarRsvpProjection {
            instance_heads: vec![stale],
            series_heads: vec![head(2, vec![digest(1)], RsvpStatus::Accepted)],
        };
        assert_eq!(
            projection.effective_response().unwrap().status,
            RsvpStatus::Accepted
        );
        assert_eq!(projection.excluded_heads().len(), 1);
    }

    #[test]
    fn concurrent_differing_heads_conflict_and_identical_ones_do_not() {
        let conflict = CalendarRsvpProjection {
            instance_heads: vec![
                head(1, vec![digest(1)], RsvpStatus::Accepted),
                head(2, vec![digest(1)], RsvpStatus::Declined),
            ],
            series_heads: Vec::new(),
        };
        assert_eq!(conflict.resolution_state(), RsvpResolutionState::Conflict);
        // A conflict has no single answer to show; the responder resolves it.
        assert!(conflict.effective_response().is_none());

        // Same basis and same plaintext: distinct canonical heads, but the user
        // answered the same thing, so this is not a conflict.
        let agreeing = CalendarRsvpProjection {
            instance_heads: vec![
                head(1, vec![digest(1)], RsvpStatus::Accepted),
                head(2, vec![digest(1)], RsvpStatus::Accepted),
            ],
            series_heads: Vec::new(),
        };
        assert_eq!(agreeing.resolution_state(), RsvpResolutionState::Settled);
        assert_eq!(
            agreeing.effective_response().unwrap().status,
            RsvpStatus::Accepted
        );
    }

    #[test]
    fn missing_key_heads_are_listed_but_never_fabricate_a_status() {
        let mut blind = head(1, vec![digest(1)], RsvpStatus::Accepted);
        blind.response = None;
        blind.response_class = RsvpResponseClass::EncryptedUnresolved;
        let projection = CalendarRsvpProjection {
            instance_heads: vec![blind],
            series_heads: Vec::new(),
        };
        assert!(projection.effective_heads().is_empty());
        assert!(projection.effective_response().is_none());
        assert_eq!(projection.excluded_heads().len(), 1);
    }
}
