use arkret_wire::{NonEmptyString, validate_bounded_non_typed_identifier};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct Scoped {
    #[serde(deserialize_with = "arkret_wire::deserialize_bounded_non_typed_identifier")]
    value: String,
    #[serde(
        default,
        deserialize_with = "arkret_wire::deserialize_optional_bounded_non_typed_identifier"
    )]
    optional: Option<NonEmptyString>,
}

#[derive(Debug, Deserialize)]
struct Focus {
    #[serde(deserialize_with = "arkret_wire::deserialize_focus_identifier")]
    value: String,
}

#[test]
fn scoped_handles_count_unicode_codepoints_and_preserve_every_literal() {
    for literal in [
        " ".to_owned(),
        " a ".to_owned(),
        "🦀".repeat(256),
        "e\u{301}".repeat(128),
    ] {
        let parsed: Scoped =
            serde_json::from_value(json!({"value":literal,"optional":literal})).unwrap();
        assert_eq!(parsed.value, literal);
        assert_eq!(parsed.optional.unwrap().as_str(), literal);
    }
    for invalid in [
        String::new(),
        "ak:unregistered:any".to_owned(),
        "🦀".repeat(257),
    ] {
        assert!(serde_json::from_value::<Scoped>(json!({"value":invalid})).is_err());
        assert!(
            serde_json::from_value::<Scoped>(json!({"value":"valid","optional":invalid})).is_err()
        );
    }
    assert!(serde_json::from_value::<Scoped>(json!({"value":"valid","optional":null})).is_err());
    assert!(validate_bounded_non_typed_identifier("é", 1).is_ok());
    assert!(validate_bounded_non_typed_identifier("e\u{301}", 1).is_err());
}

#[test]
fn stricter_focus_and_secret_profiles_are_composed_without_global_narrowing() {
    let literal = "🦀".repeat(64);
    let focus: Focus = serde_json::from_value(json!({"value":literal})).unwrap();
    assert_eq!(focus.value, literal);
    assert!(serde_json::from_value::<Focus>(json!({"value":"🦀".repeat(65)})).is_err());
    for valid in ["a_1.2-3".to_owned(), "a".repeat(256)] {
        assert!(arkret_wire::validate_secret_storage_identifier(&valid).is_ok());
    }
    for invalid in [
        "é".to_owned(),
        " ".to_owned(),
        "a".repeat(257),
        "ak:secret".to_owned(),
    ] {
        assert!(arkret_wire::validate_secret_storage_identifier(&invalid).is_err());
    }
    assert!(NonEmptyString::new("ak:unrelated".to_owned()).is_ok());
    assert!(NonEmptyString::new("🦀".repeat(257)).is_ok());
}
