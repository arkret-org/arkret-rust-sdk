//! The generated creator MLS Genesis bootstrap machine is the only source of
//! its state and transition labels. These checks pin the two properties the
//! generator cannot state in its own output: descriptor lookup is index-aligned
//! with the enum, and the closed arrow set agrees with the closed state set.

use arkret_wire::{
    MLS_CREATOR_BOOTSTRAP_STATES, MLS_CREATOR_BOOTSTRAP_TRANSITIONS, MlsCreatorBootstrapState,
    MlsCreatorBootstrapStateKind, MlsCreatorBootstrapTransition,
};

#[test]
fn state_descriptors_are_index_aligned_and_ordinal_ordered() {
    assert_eq!(
        MlsCreatorBootstrapState::ALL.len(),
        MLS_CREATOR_BOOTSTRAP_STATES.len()
    );
    for (index, state) in MlsCreatorBootstrapState::ALL.iter().copied().enumerate() {
        let descriptor = state.descriptor();
        assert_eq!(descriptor.state, state);
        assert_eq!(descriptor.ordinal as usize, index + 1);
        assert_eq!(
            MlsCreatorBootstrapState::from_wire(state.as_str()),
            Some(state)
        );
        let terminal = descriptor.kind != MlsCreatorBootstrapStateKind::Progress;
        assert_eq!(
            terminal && descriptor.kind != MlsCreatorBootstrapStateKind::TerminalAttempt,
            state.allowed_exits().is_empty(),
            "{state} exits disagree with its lifecycle class"
        );
    }
}

#[test]
fn every_transition_matches_a_declared_exit() {
    assert_eq!(
        MlsCreatorBootstrapTransition::ALL.len(),
        MLS_CREATOR_BOOTSTRAP_TRANSITIONS.len()
    );
    let mut creating = 0;
    for (index, transition) in MlsCreatorBootstrapTransition::ALL
        .iter()
        .copied()
        .enumerate()
    {
        let descriptor = transition.descriptor();
        assert_eq!(descriptor.transition, transition);
        assert_eq!(&MLS_CREATOR_BOOTSTRAP_TRANSITIONS[index], descriptor);
        assert_eq!(
            MlsCreatorBootstrapTransition::from_wire(transition.as_str()),
            Some(transition)
        );
        match transition.from_state() {
            None => creating += 1,
            Some(from) => assert!(
                from.allowed_exits().contains(&transition.to_state()),
                "{transition} is not a declared exit of {from}"
            ),
        }
    }
    assert_eq!(creating, 1, "exactly one arrow creates the durable record");
}

#[test]
fn state_labels_round_trip_through_serde() {
    for state in MlsCreatorBootstrapState::ALL.iter().copied() {
        let encoded = serde_json::to_value(state).unwrap();
        assert_eq!(encoded, serde_json::json!(state.as_str()));
        assert_eq!(
            serde_json::from_value::<MlsCreatorBootstrapState>(encoded).unwrap(),
            state
        );
    }
    assert!(
        serde_json::from_value::<MlsCreatorBootstrapState>(serde_json::json!("ready_")).is_err()
    );
}
