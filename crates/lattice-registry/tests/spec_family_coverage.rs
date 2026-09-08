//! Coverage gate for the hand-written typed lattice registry.
//!
//! `SPEC_LATTICE_BINDINGS` is generated from `event-kind-registry.json`;
//! `default_lattice_registry()` is the hand-written companion supplying subject
//! derivation and event-kind dispatch. Most spec families need no custom typed
//! adapter, so the family sets are intentionally unequal. Every adapter that
//! does exist must nevertheless expose exactly the generated lattice and bottom
//! binding for its family.
//!
//! Today the adapters read the generated table directly, so this gate is the
//! guard against that being undone: an adapter that hard-codes an algebra or a
//! bottom mode again fails here on the first divergence rather than shipping a
//! second, drifting source of truth.

use std::collections::{BTreeMap, BTreeSet};

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
fn every_typed_adapter_matches_its_generated_lattice_binding() {
    let generated: BTreeMap<_, _> = lattice_bindings_for_sdk_registry()
        .into_iter()
        .map(|(family, lattice, bottom)| (family, (lattice, bottom)))
        .collect();
    let typed = default_lattice_registry();

    for family in typed.families() {
        let adapter = typed
            .lookup(family)
            .expect("enumerated adapter must remain registered");
        let (expected_lattice, expected_bottom) = generated
            .get(family)
            .unwrap_or_else(|| panic!("typed adapter {family} has no generated binding"));
        assert_eq!(
            adapter.lattice(),
            *expected_lattice,
            "typed adapter {family} drifted from the generated lattice"
        );
        assert_eq!(
            adapter.bottom_policy(),
            *expected_bottom,
            "typed adapter {family} drifted from the generated bottom policy"
        );
    }
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
