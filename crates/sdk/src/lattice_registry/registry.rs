use std::collections::BTreeMap;

use super::types::LatticeKind;

/// Canonical-cell-family registry. Holds one `Box<dyn LatticeKind>` per
/// registered `cell_family` string; lookup is `O(log n)` over a
/// `BTreeMap`. The inverted `event_kind → cell_family` index is built
/// from each impl's [`LatticeKind::event_kinds`] declaration.
#[derive(Default)]
pub struct LatticeRegistry {
    families: BTreeMap<&'static str, Box<dyn LatticeKind>>,
    event_kind_index: BTreeMap<&'static str, &'static str>,
}

impl LatticeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cell-family impl. Subsequent inserts on the same
    /// family id replace the existing impl (last-write-wins).
    pub fn register<K>(&mut self, kind: K)
    where
        K: LatticeKind + 'static,
    {
        let family = kind.cell_family();
        for ek in kind.event_kinds() {
            self.event_kind_index.insert(*ek, family);
        }
        self.families.insert(family, Box::new(kind));
    }

    pub fn lookup(&self, cell_family: &str) -> Option<&dyn LatticeKind> {
        self.families.get(cell_family).map(|boxed| boxed.as_ref())
    }

    pub fn lookup_for_event_kind(&self, event_kind: &str) -> Option<&dyn LatticeKind> {
        let family = self.event_kind_index.get(event_kind)?;
        self.lookup(family)
    }

    pub fn event_kind_mappings(&self) -> usize {
        self.event_kind_index.len()
    }

    pub fn len(&self) -> usize {
        self.families.len()
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}
