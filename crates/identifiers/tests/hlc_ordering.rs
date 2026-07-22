use arkret_identifiers::Hlc;

#[test]
fn hlc_sorts_by_structured_parts() {
    let mut hlcs = [
        "01970e589d21-0004-bbbbbbbb",
        "01970e589d20-0009-ffffffff",
        "01970e589d21-0003-ffffffff",
        "01970e589d21-0004-a13f9c2e",
    ]
    .map(|value| Hlc::new(value).unwrap());
    hlcs.sort();
    let actual = hlcs.map(|value| value.to_string());
    assert_eq!(
        actual,
        [
            "01970e589d20-0009-ffffffff",
            "01970e589d21-0003-ffffffff",
            "01970e589d21-0004-a13f9c2e",
            "01970e589d21-0004-bbbbbbbb",
        ]
    );
}
