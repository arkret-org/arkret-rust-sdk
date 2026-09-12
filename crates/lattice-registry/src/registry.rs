use std::collections::BTreeMap;

use super::types::CellFamilyAdapter;

/// Canonical cell-family registry. Holds one adapter per
/// registered `cell_family` string; lookup is `O(log n)` over a
/// `BTreeMap`. The inverted `event_kind → cell_family` index is built
/// from the generated Event descriptor `cell_writes`; one Event may map to
/// multiple cell families.
#[derive(Default)]
pub struct CellFamilyRegistry {
    families: BTreeMap<&'static str, Box<dyn CellFamilyAdapter>>,
    event_kind_index: BTreeMap<&'static str, Vec<&'static str>>,
}

impl CellFamilyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cell-family impl. Subsequent inserts on the same
    /// family id replace the existing impl (last-write-wins).
    pub fn register<K>(&mut self, kind: K)
    where
        K: CellFamilyAdapter + 'static,
    {
        let family = kind.cell_family();
        for descriptor in arkret_wire::EVENT_KIND_DESCRIPTORS {
            if descriptor.cell_writes.iter().any(|write| {
                write
                    .cell_family
                    .is_some_and(|cell_family| cell_family.as_str() == family)
            }) {
                let families = self.event_kind_index.entry(descriptor.kind).or_default();
                if !families.contains(&family) {
                    families.push(family);
                    families.sort_unstable();
                }
            }
        }
        self.families.insert(family, Box::new(kind));
    }

    pub fn lookup(&self, cell_family: &str) -> Option<&dyn CellFamilyAdapter> {
        self.families.get(cell_family).map(|boxed| boxed.as_ref())
    }

    pub fn lookups_for_event_kind(
        &self,
        event_kind: &str,
    ) -> impl Iterator<Item = &dyn CellFamilyAdapter> {
        self.event_kind_index
            .get(event_kind)
            .into_iter()
            .flatten()
            .filter_map(|family| self.lookup(family))
    }

    /// Every registered cell family, in canonical order.
    ///
    /// Coverage checks compare this against the generated spec binding list;
    /// counting registrations is not coverage, because one missing family and
    /// one stray family cancel out.
    pub fn families(&self) -> impl ExactSizeIterator<Item = &'static str> + '_ {
        self.families.keys().copied()
    }

    /// Every registered `(event_kind, cell_family)` mapping, in canonical order.
    pub fn event_kind_bindings(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.event_kind_index
            .iter()
            .flat_map(|(event_kind, families)| {
                families.iter().map(move |family| (*event_kind, *family))
            })
    }

    pub fn len(&self) -> usize {
        self.families.len()
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}
