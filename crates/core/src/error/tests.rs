use std::path::PathBuf;

use super::*;

fn local_spec_artifacts_dir() -> Option<PathBuf> {
    if let Some(dir) = crate::schema::default_spec_artifacts_dir() {
        return Some(dir);
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts");
    candidate.is_dir().then_some(candidate)
}

fn generated_error_codes() -> Vec<&'static str> {
    ErrorCode::ALL.iter().map(|code| code.as_str()).collect()
}

fn registry_reason_codes() -> Vec<String> {
    if let Some(artifacts_dir) = local_spec_artifacts_dir() {
        let registry_path = artifacts_dir
            .join("registry")
            .join("error-code-registry.json");
        if let Ok(text) = std::fs::read_to_string(&registry_path) {
            let registry: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|error| {
                panic!("failed to parse {}: {error}", registry_path.display())
            });
            return registry
                .get("reason_codes")
                .and_then(serde_json::Value::as_array)
                .expect("live error-code-registry missing reason_codes")
                .iter()
                .map(|entry| {
                    entry
                        .get("code")
                        .and_then(serde_json::Value::as_str)
                        .expect("live reason-code entry missing code")
                        .to_owned()
                })
                .collect();
        }
    }
    crate::schema::embedded_error_code_reason_codes()
        .expect("embedded error-code-registry reason codes must load")
}

#[test]
fn generated_error_codes_match_embedded_registry() {
    let embedded = crate::schema::embedded_error_code_codes()
        .expect("embedded error-code-registry codes must load");
    assert_eq!(generated_error_codes(), embedded);
}

#[test]
fn generated_error_codes_match_live_registry_when_available() {
    let Some(artifacts_dir) = local_spec_artifacts_dir() else {
        return;
    };
    let registry_path = artifacts_dir
        .join("registry")
        .join("error-code-registry.json");
    let text = std::fs::read_to_string(&registry_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", registry_path.display()));
    let registry: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", registry_path.display()));
    let live: Vec<&str> = registry
        .get("codes")
        .and_then(serde_json::Value::as_array)
        .expect("live error-code-registry missing codes array")
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(serde_json::Value::as_str)
                .expect("live error-code-registry code entry missing code")
        })
        .collect();
    assert_eq!(generated_error_codes(), live);
}

#[test]
fn error_code_enum_round_trips_and_has_status() {
    for code in ErrorCode::ALL {
        let wire = code.as_str();
        assert_eq!(ErrorCode::from_wire(wire), Some(*code));
        assert_eq!(error_code_http_status(wire), Some(code.http_status()));
        assert!((100..=599).contains(&code.http_status()));
    }
}

#[test]
fn unknown_error_code_is_preserved_by_problem_details() {
    let details = ProblemDetails::new("vendor_remote_error", "remote failure");
    assert_eq!(details.error_code(), None);
    assert_eq!(details.code, "vendor_remote_error");
}

#[test]
fn generated_reason_codes_match_registry_and_round_trip_unknown() {
    let generated: Vec<&str> = REASON_CODE_DESCRIPTORS
        .iter()
        .map(|descriptor| descriptor.code)
        .collect();
    assert_eq!(generated, registry_reason_codes());

    let unknown = ReasonCode::from_wire("vendor_custom_reason");
    assert_eq!(unknown.as_str(), "vendor_custom_reason");
    assert!(unknown.descriptor().is_none());
}
