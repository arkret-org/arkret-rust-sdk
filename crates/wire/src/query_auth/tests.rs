use super::*;

#[test]
fn detects_case_and_percent_encoded_names_without_substring_false_positives() {
    assert!(contains_query_auth_material("foo=1&Access_Token=secret"));
    assert!(contains_query_auth_material("sign%61ture=secret"));
    assert!(!contains_query_auth_material(
        "oauth=metadata&tokenized=true"
    ));
}
