//! Local history-visibility decisions over an authority-committed stream.
//!
//! This module decides whether an already-authorized reader may read a commit
//! at a given stream position. It does not define key export, secret sharing,
//! backfill recovery, or any network protocol.

use arkret_wire::HistoryAccess;

/// Current facts required to read from one independent commit stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderStanding {
    pub membership_active: bool,
    pub scope_readable: bool,
    /// First stream position made visible by the reader's current membership.
    pub join_position: u64,
}

/// Whether `event_position` is inside the policy window.
pub const fn position_visible(
    access: HistoryAccess,
    event_position: u64,
    join_position: u64,
) -> bool {
    match access {
        HistoryAccess::AllHistoryForCurrentMembers => true,
        HistoryAccess::SinceJoin => event_position >= join_position,
    }
}

/// Decide visibility using only the target stream's committed positions.
///
/// Positions from Realm, Circle, and Sidecar streams are never compared with
/// one another; callers must obtain both positions from the same stream.
pub const fn readable(
    access: HistoryAccess,
    event_position: u64,
    reader: ReaderStanding,
) -> bool {
    reader.membership_active
        && reader.scope_readable
        && position_visible(access, event_position, reader.join_position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_join_uses_the_same_stream_position_floor() {
        let reader = ReaderStanding {
            membership_active: true,
            scope_readable: true,
            join_position: 7,
        };
        assert!(!readable(HistoryAccess::SinceJoin, 6, reader));
        assert!(readable(HistoryAccess::SinceJoin, 7, reader));
    }

    #[test]
    fn all_history_still_requires_current_standing() {
        let reader = ReaderStanding {
            membership_active: false,
            scope_readable: true,
            join_position: 9,
        };
        assert!(!readable(
            HistoryAccess::AllHistoryForCurrentMembers,
            0,
            reader
        ));
    }
}
