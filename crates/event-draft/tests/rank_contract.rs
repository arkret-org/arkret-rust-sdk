use arkret_event_draft::{container_rebalance_assignments, rank_between, rank_exhausted};

#[test]
fn rank_helpers_generate_between_and_rebalance_assignments() {
    let first = rank_between(None, None).unwrap();
    let second = rank_between(Some(&first), None).unwrap();
    assert!(first < second);
    assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(second.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(rank_exhausted(None, Some("0")).unwrap());

    let assignments = container_rebalance_assignments(&[
        "ak:morph:01904100-0000-7000-8000-8b4aa2ca29ef".to_owned(),
        "ak:morph:01904100-0000-7000-8000-d5864c129df4".to_owned(),
        "ak:morph:01904100-0000-7000-8000-6057e4215f24".to_owned(),
    ])
    .unwrap();
    assert_eq!(assignments.len(), 3);
    assert!(assignments[0].rank < assignments[1].rank);
    assert!(assignments[1].rank < assignments[2].rank);
    assert!(assignments.iter().all(|assignment| {
        assignment
            .rank
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    }));
}
