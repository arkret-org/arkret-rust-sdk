use arkret_event_draft::{rank_between, rank_exhausted};

#[test]
fn rank_helpers_generate_between_and_detect_exhaustion() {
    let first = rank_between(None, None).unwrap();
    let second = rank_between(Some(&first), None).unwrap();
    assert!(first < second);
    assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(second.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(rank_exhausted(None, Some("0")).unwrap());
}
