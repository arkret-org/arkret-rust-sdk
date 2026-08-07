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
        "ak:morph:AcRp8AmaNRAqSq4CvFtzDkuXfxw3v4PB0rlS-l_n-GX0".to_owned(),
        "ak:morph:AeR2rlO-50fCroo1gGAX8G-gwf2Dzu8cZ_rlauOIPMlw".to_owned(),
        "ak:morph:AUyvkgYc0QHSVhrplS2jCafDjCkDg7uxB2iSZ9VPjajc".to_owned(),
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
