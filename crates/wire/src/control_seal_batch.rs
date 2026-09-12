//! Successor Seal batch admission, event-auth-state-resolution section 4.3.

use std::collections::BTreeSet;

use crate::EventKind;

/// Incremental non-anchor Control Move batch admission shared by authors and receivers.
/// Registered atomic anchor units use their separate full-unit validator.
#[derive(Default)]
pub struct ControlSealBatch {
    event_count: usize,
    cells: BTreeSet<String>,
}

impl ControlSealBatch {
    /// Rejection leaves the admitted batch unchanged; the author may retain
    /// the candidate for a successor batch with a freshly verified basis.
    pub fn try_insert<'a>(
        &mut self,
        kind: &EventKind,
        cells: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), &'static str> {
        if !kind.has_security_writes() {
            return Err("Event has no registered security write");
        }
        let cells = cells
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if !self.cells.is_disjoint(&cells) {
            return Err("non-anchor Control Moves in one Seal must write disjoint cells");
        }
        self.cells.extend(cells);
        self.event_count += 1;
        Ok(())
    }
}
