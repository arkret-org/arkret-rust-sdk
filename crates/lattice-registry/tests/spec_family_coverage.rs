//! Coverage gate for the hand-written typed cell-family registry.
//!
//! `SPEC_STATE_MODEL_BINDINGS` is generated from `event-kind-registry.json`;
//! `default_cell_family_registry()` is the hand-written companion supplying subject
//! derivation and event-kind dispatch. Most spec families need no custom typed
//! adapter, so the family sets are intentionally unequal. Every adapter that
//! does exist must nevertheless expose exactly the generated state model and bottom
//! binding for its family.
//!
//! Today the adapters read the generated table directly, so this gate is the
//! guard against that being undone: an adapter that hard-codes an algebra or a
//! bottom mode again fails here on the first divergence rather than shipping a
//! second, drifting source of truth.

use std::collections::{BTreeMap, BTreeSet};

use arkret_lattice_registry::{
    default_cell_family_registry, state_model_bindings_for_sdk_registry,
};

#[test]
fn typed_registry_declares_no_family_the_spec_bindings_do_not_know() {
    let declared: BTreeSet<&'static str> = state_model_bindings_for_sdk_registry()
        .into_iter()
        .map(|(family, ..)| family)
        .collect();
    let stray: Vec<&'static str> = default_cell_family_registry()
        .families()
        .filter(|family| !declared.contains(family))
        .collect();

    assert!(
        stray.is_empty(),
        "default_cell_family_registry() registers cell famil(ies) {stray:?} that the generated \
         event-kind registry bindings do not declare; a Move routed to such a family reaches \
         an adapter no peer implementation shares"
    );
}

#[test]
fn every_typed_adapter_matches_its_generated_state_model_binding() {
    let generated: BTreeMap<_, _> = state_model_bindings_for_sdk_registry()
        .into_iter()
        .map(|(family, execution, state_model, value_shape)| {
            (family, (execution, state_model, value_shape))
        })
        .collect();
    let typed = default_cell_family_registry();

    for family in typed.families() {
        let adapter = typed
            .lookup(family)
            .expect("enumerated adapter must remain registered");
        let (expected_execution, expected_state_model, expected_value_shape) = generated
            .get(family)
            .unwrap_or_else(|| panic!("typed adapter {family} has no generated binding"));
        assert_eq!(
            adapter.state_model(),
            *expected_state_model,
            "typed adapter {family} drifted from the generated state model"
        );
        assert_eq!(
            adapter.execution(),
            *expected_execution,
            "typed adapter {family} drifted from the generated execution plane"
        );
        assert_eq!(
            adapter.value_shape(),
            *expected_value_shape,
            "typed adapter {family} drifted from the generated value shape"
        );
    }
}

#[test]
fn typed_registry_routes_no_event_kind_to_the_actor_private_namespace() {
    // `try_build_sdk_state_registry` rejects an actor-private family reaching
    // the shared registry. The typed registry feeds the same dispatch path, so
    // the same boundary has to hold here.
    let leaked: Vec<(&'static str, &'static str)> = default_cell_family_registry()
        .event_kind_bindings()
        .filter(|(_, family)| family.starts_with("ak.private."))
        .collect();

    assert!(
        leaked.is_empty(),
        "event kind(s) {leaked:?} dispatch to an actor-private cell family through the \
         shared typed registry"
    );
}
