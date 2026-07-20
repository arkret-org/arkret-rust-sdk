//! Closed selector used by capability and widget token scopes.
//!
//! The selector shapes relocated to `arkret-wire` (`resource_selector`) so the
//! integration applet surface can also reach them within the frozen layering.
//! Re-exported here for path stability. `ObjectRef` keeps its collaboration
//! alias (`crate::ObjectRef`, identical `= String`).

pub use arkret_wire::resource_selector::{
    ResourceMatchScope, ResourceSelectorKind, WireResourceSelector,
};
