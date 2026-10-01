use arkret_canonical::DigestSuite;
use arkret_models_collaboration::exact_current_results::CanonicalEventDot;
use arkret_models_collaboration::objects::productivity::{
    PinAddPayload, PinAssertionEntry, PinAssertionPayload, PinCurrentValue,
};
use arkret_wire::{EventId, PinScope, RealmId};

fn entry(byte: u8, index: u16) -> PinAssertionEntry {
    PinAssertionEntry {
        tag_id: CanonicalEventDot::new(
            EventId::from_digest(DigestSuite::Sha256, [byte; 32]),
            index,
        )
        .unwrap(),
        value: PinAssertionPayload::Add(PinAddPayload {
            pin_scope: PinScope::Realm {
                id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            },
            target_ref: "ak:message:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9".into(),
            rank: "a0".into(),
            note: None,
        }),
    }
}

#[test]
fn pin_current_rejects_invalid_append_without_mutating_the_held_set() {
    let first = entry(0x21, 0);
    let mut current = PinCurrentValue::new(vec![first.clone()]).unwrap();
    let before = current.clone();
    let mut bad_rank = entry(0x42, 0);
    let PinAssertionPayload::Add(payload) = &mut bad_rank.value else {
        unreachable!()
    };
    payload.rank = "!".into();
    let mut other_home = entry(0x43, 0);
    let PinAssertionPayload::Add(payload) = &mut other_home.value else {
        unreachable!()
    };
    payload.pin_scope = PinScope::Realm {
        id: RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x44; 32])),
    };
    for invalid in [first, bad_rank, other_home, entry(0x45, 1)] {
        assert!(current.add_assertion(invalid).is_err());
        assert_eq!(current, before);
    }
    current.add_assertion(entry(0x42, 0)).unwrap();
    let json = serde_json::to_value(&current).unwrap();
    assert_eq!(
        serde_json::from_value::<PinCurrentValue>(json).unwrap(),
        current
    );
    let mut reversed = current.assertions().to_vec();
    reversed.reverse();
    assert!(PinCurrentValue::new(reversed).is_err());
}
