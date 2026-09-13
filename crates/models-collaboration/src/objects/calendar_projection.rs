//! Shared Calendar schedule and RSVP read models.
//!
//! `calendar-event.md` §9 makes these client-local derived models: they are
//! computed from the authorized Event set plus the deterministic schedule and
//! RSVP winners. The Calendar profile deliberately does not add a remote
//! Calendar API. They live here so a server projection, a client and the
//! conformance runner classify a winner's domain status the same way.

use std::collections::BTreeSet;

use arkret_wire::Hash;
use serde::{Deserialize, Serialize};

use crate::objects::productivity::RsvpResponse;

/// Whether the deterministic Calendar schedule winner can be consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleResolutionState {
    Available,
    /// The reader cannot decrypt the deterministic schedule winner.
    EncryptedUnresolved,
}

/// Canonical schedule revision winner for one Calendar Strand.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarScheduleProjection {
    /// Exact source digest of the deterministic current schedule value.
    pub schedule_revision_source: Hash,
    pub resolution_state: ScheduleResolutionState,
}

impl CalendarScheduleProjection {
    /// Builds the projection from the already verified causal-register winner.
    pub fn from_winner(schedule_revision_source: Hash, schedule_bytes: Option<Vec<u8>>) -> Self {
        let resolution_state = if schedule_bytes.is_none() {
            ScheduleResolutionState::EncryptedUnresolved
        } else {
            ScheduleResolutionState::Available
        };
        Self {
            schedule_revision_source,
            resolution_state,
        }
    }

    pub fn is_available(&self) -> bool {
        self.resolution_state == ScheduleResolutionState::Available
    }
}

/// Basis axis: how the RSVP winner relates to the current schedule revision.
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
    ResponseInvalid,
    /// No key. The winner is listed, and no status is fabricated for it.
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

/// One classified causal-register winner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarRsvpWinner {
    pub source_event_digest: Hash,
    /// Schedule revision frontier this responder signed into the entry.
    pub schedule_basis_refs: Vec<Hash>,
    /// Present only when the response axis resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RsvpResponse>,
    pub basis_class: RsvpBasisClass,
    pub response_class: RsvpResponseClass,
}

impl CalendarRsvpWinner {
    pub fn participates(&self) -> bool {
        self.basis_class.participates() && self.response_class.participates()
    }

    /// Classifies the basis axis.
    ///
    /// `known_schedule_revisions` is the schedule revision DAG this reader has
    /// actually seen — a basis ref outside it is unresolvable, not stale. What
    /// changed since the winner was written arrives as the two flags rather than
    /// being derived here, because deciding significance needs the schedule
    /// plaintext, which a reader of an encrypted Realm does not have.
    ///
    /// `identity_affecting_changed` says whether `start`, `timezone`, `all_day`
    /// or `recurrence` moved since this head was written; that is what turns an
    /// instance winner into an orphan, because the occurrence key itself changed.
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
            // Series winners have no occurrence in their subject, so they cannot
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

/// Converged RSVP read model for one responder and one occurrence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalendarRsvpProjection {
    pub instance_winner: Option<CalendarRsvpWinner>,
    pub series_winner: Option<CalendarRsvpWinner>,
}

impl CalendarRsvpProjection {
    /// Instance winner overrides the series fallback; they are never unioned.
    pub fn effective_winner(&self) -> Option<&CalendarRsvpWinner> {
        self.instance_winner
            .as_ref()
            .filter(|winner| winner.participates())
            .or_else(|| {
                self.series_winner
                    .as_ref()
                    .filter(|winner| winner.participates())
            })
    }

    /// The single response to display, or `None` when the winner is excluded.
    pub fn effective_response(&self) -> Option<&RsvpResponse> {
        self.effective_winner()
            .and_then(|winner| winner.response.as_ref())
    }

    /// Winners excluded from the effective response, so a UI can explain why a
    /// response does not count instead of silently dropping it.
    pub fn excluded_winners(&self) -> Vec<&CalendarRsvpWinner> {
        self.instance_winner
            .iter()
            .chain(self.series_winner.iter())
            .filter(|winner| !winner.participates())
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

    fn winner(digest_byte: u8, basis: Vec<Hash>, status: RsvpStatus) -> CalendarRsvpWinner {
        CalendarRsvpWinner {
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
    fn readable_schedule_winner_is_available() {
        let projection =
            CalendarScheduleProjection::from_winner(digest(2), Some(b"schedule".to_vec()));
        assert_eq!(
            projection.resolution_state,
            ScheduleResolutionState::Available
        );
        assert_eq!(projection.schedule_revision_source, digest(2));
    }

    #[test]
    fn unreadable_schedule_winner_is_unresolved() {
        let blind = CalendarScheduleProjection::from_winner(digest(2), None);
        assert_eq!(
            blind.resolution_state,
            ScheduleResolutionState::EncryptedUnresolved
        );
    }

    #[test]
    fn basis_outside_the_known_frontier_is_unresolved_not_current() {
        assert_eq!(
            CalendarRsvpWinner::classify_basis(&[digest(9)], &[digest(1)], false, false, false,),
            RsvpBasisClass::UnresolvedBasis
        );
        assert_eq!(
            CalendarRsvpWinner::classify_basis(&[], &[digest(1)], false, false, false,),
            RsvpBasisClass::UnresolvedBasis
        );
    }

    #[test]
    fn identity_affecting_edits_orphan_instance_winners_but_only_reconfirm_series() {
        let known = [digest(1), digest(2)];
        assert_eq!(
            CalendarRsvpWinner::classify_basis(&[digest(2)], &known, true, true, false,),
            RsvpBasisClass::StaleOrphaned
        );
        assert_eq!(
            CalendarRsvpWinner::classify_basis(&[digest(2)], &known, false, true, false,),
            RsvpBasisClass::EffectiveNeedsReconfirmation
        );
        assert_eq!(
            CalendarRsvpWinner::classify_basis(&[digest(2)], &known, true, false, true,),
            RsvpBasisClass::EffectiveNeedsReconfirmation
        );
    }

    #[test]
    fn instance_winner_overrides_series_and_the_two_are_never_unioned() {
        let projection = CalendarRsvpProjection {
            instance_winner: Some(winner(1, vec![digest(1)], RsvpStatus::Declined)),
            series_winner: Some(winner(2, vec![digest(1)], RsvpStatus::Accepted)),
        };
        assert_eq!(
            projection.effective_winner().unwrap().source_event_digest,
            digest(1)
        );
        assert_eq!(
            projection.effective_response().unwrap().status,
            RsvpStatus::Declined
        );
    }

    #[test]
    fn series_is_the_fallback_when_instance_winner_does_not_participate() {
        let mut stale = winner(1, vec![digest(1)], RsvpStatus::Declined);
        stale.basis_class = RsvpBasisClass::StaleOrphaned;
        let projection = CalendarRsvpProjection {
            instance_winner: Some(stale),
            series_winner: Some(winner(2, vec![digest(1)], RsvpStatus::Accepted)),
        };
        assert_eq!(
            projection.effective_response().unwrap().status,
            RsvpStatus::Accepted
        );
        assert_eq!(projection.excluded_winners().len(), 1);
    }

    #[test]
    fn deterministic_winner_is_the_only_rsvp_value() {
        let projection = CalendarRsvpProjection {
            instance_winner: Some(winner(2, vec![digest(1)], RsvpStatus::Declined)),
            series_winner: None,
        };
        assert_eq!(
            projection.effective_response().unwrap().status,
            RsvpStatus::Declined
        );
    }

    #[test]
    fn missing_key_winner_is_listed_but_never_fabricates_a_status() {
        let mut blind = winner(1, vec![digest(1)], RsvpStatus::Accepted);
        blind.response = None;
        blind.response_class = RsvpResponseClass::EncryptedUnresolved;
        let projection = CalendarRsvpProjection {
            instance_winner: Some(blind),
            series_winner: None,
        };
        assert!(projection.effective_winner().is_none());
        assert!(projection.effective_response().is_none());
        assert_eq!(projection.excluded_winners().len(), 1);
    }
}
