mod error_code;
mod reason_code;
mod status;

pub use error_code::*;
pub use reason_code::*;
pub use status::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip_and_have_http_statuses() {
        for code in ErrorCode::ALL {
            let wire = code.as_str();
            assert_eq!(ErrorCode::from_wire(wire), Some(*code));
            assert_eq!(error_code_http_status(wire), Some(code.http_status()));
            assert!((100..=599).contains(&code.http_status()));
        }
    }

    #[test]
    fn unknown_reason_code_round_trips_without_a_descriptor() {
        let unknown = ReasonCode::from_wire("vendor_custom_reason");
        assert_eq!(unknown.as_str(), "vendor_custom_reason");
        assert!(unknown.descriptor().is_none());
    }

    #[test]
    fn unknown_reason_code_rejects_invalid_wire_syntax() {
        for invalid in ["", "Uppercase", "contains-hyphen", " leading_space"] {
            let wire = serde_json::to_string(invalid).expect("serialize fixture");
            assert!(
                serde_json::from_str::<ReasonCode>(&wire).is_err(),
                "{invalid:?}"
            );
        }
        let overlong = format!("a{}", "b".repeat(64));
        let wire = serde_json::to_string(&overlong).expect("serialize fixture");
        assert!(serde_json::from_str::<ReasonCode>(&wire).is_err());
    }
}
