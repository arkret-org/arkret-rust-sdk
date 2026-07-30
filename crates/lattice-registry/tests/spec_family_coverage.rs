//! Coverage gate for the hand-written typed lattice registry.
//!
//! `SPEC_LATTICE_BINDINGS` is generated from `event-kind-registry.json`;
//! `default_lattice_registry()` is the hand-written companion supplying subject
//! derivation and event-kind dispatch. The two lists are NOT expected to be
//! equal — most families need no custom typed adapter — so a set-equality gate
//! would be wrong. What is unambiguous in either reading is the stray
//! direction: a hand-written adapter claiming a `cell_family` the generated
//! spec bindings never declare can only be a stale or misspelled family id, and
//! every Move routed to it is routed to nothing real.
//!
//! The reverse direction (which spec families genuinely require a typed
//! adapter, and why several adapters' `lattice()` / `bottom_policy()` disagree
//! with the generated bindings) is still an open protocol question — see O48 in
//! the cleanup report. Do not turn this into a set-equality assertion without
//! first settling which list is authoritative for which purpose.

use std::collections::BTreeSet;

use arkret_lattice_registry::{default_lattice_registry, lattice_bindings_for_sdk_registry};

#[test]
fn typed_registry_declares_no_family_the_spec_bindings_do_not_know() {
    let declared: BTreeSet<&'static str> = lattice_bindings_for_sdk_registry()
        .into_iter()
        .map(|(family, ..)| family)
        .collect();
    let stray: Vec<&'static str> = default_lattice_registry()
        .families()
        .filter(|family| !declared.contains(family))
        .collect();

    assert!(
        stray.is_empty(),
        "default_lattice_registry() registers cell famil(ies) {stray:?} that the generated \
         event-kind registry bindings do not declare; a Move routed to such a family reaches \
         an adapter no peer implementation shares"
    );
}

#[test]
fn typed_registry_routes_no_event_kind_to_the_actor_private_namespace() {
    // `try_build_sdk_cell_registry` rejects an actor-private family reaching
    // the shared registry. The typed registry feeds the same dispatch path, so
    // the same boundary has to hold here.
    let leaked: Vec<(&'static str, &'static str)> = default_lattice_registry()
        .event_kind_bindings()
        .filter(|(_, family)| family.starts_with("ak.private."))
        .collect();

    assert!(
        leaked.is_empty(),
        "event kind(s) {leaked:?} dispatch to an actor-private cell family through the \
         shared typed registry"
    );
}
