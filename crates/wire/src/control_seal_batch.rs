//! Ordinary Seal batch admission, event-auth-state-resolution section 4.3.

use std::collections::BTreeSet;

use crate::EventKind;

/// Incremental ordinary batch admission shared by authors and receivers.
/// Registered atomic anchor units use their separate full-unit validator.
#[derive(Default)]
pub struct ControlSealBatch {
    event_count: usize,
    barrier: bool,
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
        let class = kind
            .descriptor()
            .and_then(|d| d.concurrency_class)
            .ok_or("Control Move has no registered concurrency class")?;
        self.insert_class(class, cells)
    }

    fn insert_class<'a>(
        &mut self,
        class: &str,
        cells: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), &'static str> {
        let barrier = match class {
            "security_barrier" => true,
            "exclusive" | "merge_safe" => false,
            _ => return Err("unknown Control Move concurrency class"),
        };
        if self.event_count > 0 && (self.barrier || barrier) {
            return Err("security barrier must be the sole ordinary control transaction in a Seal");
        }
        let cells = cells
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if !self.cells.is_disjoint(&cells) {
            return Err("ordinary Control Moves in one Seal must write disjoint cells");
        }
        self.cells.extend(cells);
        self.barrier |= barrier;
        self.event_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_and_ordinary_writes_never_mix_in_either_order() {
        for classes in [
            ["security_barrier", "merge_safe"],
            ["merge_safe", "security_barrier"],
            ["security_barrier", "security_barrier"],
        ] {
            let mut batch = ControlSealBatch::default();
            batch.insert_class(classes[0], ["a"]).unwrap();
            assert!(batch.insert_class(classes[1], ["b"]).is_err());
        }
    }

    #[test]
    fn hot_cell_rejection_does_not_poison_unrelated_batch_candidates() {
        let mut batch = ControlSealBatch::default();
        batch.insert_class("exclusive", ["hot"]).unwrap();
        for _ in 0..1000 {
            assert!(batch.insert_class("exclusive", ["hot"]).is_err());
        }
        batch.insert_class("merge_safe", ["unrelated"]).unwrap();
        assert_eq!(batch.event_count, 2);
    }
}
