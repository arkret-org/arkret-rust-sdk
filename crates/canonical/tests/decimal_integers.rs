use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Wide {
    #[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]
    value: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct NonnegativeSigned {
    #[serde(with = "arkret_canonical::serde_helpers::nonnegative_int64_decimal")]
    value: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct OptionalWide {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_uint64_decimal"
    )]
    value: Option<u64>,
}

#[test]
fn full_width_json_preserves_every_integer_bit() {
    for value in [0, 1, 9_007_199_254_740_991, 9_007_199_254_740_992, u64::MAX] {
        let wire = serde_json::to_value(Wide { value }).unwrap();
        assert_eq!(wire["value"], value.to_string());
        assert_eq!(serde_json::from_value::<Wide>(wire).unwrap().value, value);
    }
}

#[test]
fn json_accepts_one_canonical_decimal_spelling() {
    for text in [
        "",
        "00",
        "01",
        "+1",
        "-1",
        "1.0",
        "1e3",
        " 1",
        "1 ",
        "18446744073709551616",
    ] {
        assert!(
            serde_json::from_value::<Wide>(serde_json::json!({"value":text})).is_err(),
            "{text}"
        );
    }
    for value in [
        serde_json::json!(0),
        serde_json::json!(u64::MAX),
        serde_json::Value::Null,
    ] {
        assert!(serde_json::from_value::<Wide>(serde_json::json!({"value":value})).is_err());
    }
    let maximum = i64::MAX as u64;
    assert!(
        serde_json::from_value::<NonnegativeSigned>(
            serde_json::json!({"value":maximum.to_string()})
        )
        .is_ok()
    );
    assert!(serde_json::to_value(NonnegativeSigned { value: maximum + 1 }).is_err());
    assert!(
        serde_json::from_value::<NonnegativeSigned>(
            serde_json::json!({"value":(maximum+1).to_string()})
        )
        .is_err()
    );
}

#[test]
fn optional_decimal_preserves_absence_and_rejects_explicit_null() {
    assert_eq!(
        serde_json::from_str::<OptionalWide>("{}").unwrap().value,
        None
    );
    assert_eq!(
        serde_json::to_string(&OptionalWide { value: None }).unwrap(),
        "{}"
    );
    assert!(serde_json::from_str::<OptionalWide>(r#"{"value":null}"#).is_err());
    assert_eq!(
        serde_json::from_str::<OptionalWide>(r#"{"value":"0"}"#)
            .unwrap()
            .value,
        Some(0)
    );
}
