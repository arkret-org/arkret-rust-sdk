use std::path::PathBuf;

use super::*;

fn local_spec_artifacts_dir() -> Option<PathBuf> {
    if let Some(dir) = crate::schema::default_spec_artifacts_dir() {
        return Some(dir);
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("cokret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts");
    candidate.is_dir().then_some(candidate)
}

#[test]
fn every_known_error_code_has_http_status() {
    for code in KNOWN_ERROR_CODES {
        assert!(
            error_code_http_status(code).is_some(),
            "known error code {code:?} has no HTTP status mapping",
        );
    }
}

#[test]
fn known_error_codes_match_embedded_registry() {
    let embedded = crate::schema::embedded_error_code_codes()
        .expect("embedded error-code-registry codes must load");
    assert_eq!(KNOWN_ERROR_CODES, embedded.as_slice());
}

#[test]
fn known_error_codes_match_live_registry_when_available() {
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
    let live: Vec<String> = registry
        .get("codes")
        .and_then(serde_json::Value::as_array)
        .expect("live error-code-registry missing codes array")
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(serde_json::Value::as_str)
                .expect("live error-code-registry code entry missing code")
                .to_owned()
        })
        .collect();
    assert_eq!(KNOWN_ERROR_CODES, live.as_slice());
}

/// `ErrorCode::ALL` MUST contain one variant per entry in
/// `KNOWN_ERROR_CODES`.
#[test]
fn error_code_enum_matches_registry() {
    assert_eq!(ErrorCode::ALL.len(), KNOWN_ERROR_CODES.len());
    for code in ErrorCode::ALL {
        let wire = code.as_str();
        assert!(
            is_known_error_code(wire),
            "ErrorCode::{:?} → {wire:?} missing from KNOWN_ERROR_CODES",
            code
        );
        assert_eq!(
            ErrorCode::from_wire(wire),
            Some(code),
            "round-trip mismatch for ErrorCode::{:?}",
            code,
        );
    }
    for wire in KNOWN_ERROR_CODES {
        assert!(
            ErrorCode::from_wire(wire).is_some(),
            "registry wire {wire:?} has no ErrorCode variant",
        );
    }
}

/// Every variant MUST resolve to an HTTP status via
/// `error_code_http_status`. Catches drift between the registry
/// table and the HTTP-status `match` arm.
#[test]
fn every_variant_has_http_status() {
    for code in ErrorCode::ALL {
        let status = code.http_status();
        assert!(
            (100..=599).contains(&status),
            "ErrorCode::{:?} returned status {status}",
            code,
        );
    }
}

/// Guard against the manual-mirror drift fixed in SDK-01-001: every
/// hand-maintained `REASON_*` constant MUST exist as a declared identifier
/// in the embedded `error-code-registry.json` snapshot. This pins the
/// previously-missing `federation_trust_domain_mismatch` /
/// `invalid_ack_token` and catches any future reason code added as a
/// constant without a matching registry entry (or vice versa).
///
/// The spec registry files identifiers across two arrays: canonical error
/// codes under `codes` and finer sub-reasons under `reason_codes`. Several
/// curated constants (the Reaction and direct-conversation sub-reasons) are
/// registered by the spec under `codes`, so the cross-check resolves
/// against the union of both arrays rather than `reason_codes` alone.
#[test]
fn reason_constants_are_declared_in_embedded_registry() {
    let registry = crate::schema::embedded_error_code_identifiers()
        .expect("embedded error-code-registry identifiers must load");

    // The two reason codes restored in SDK-01-001 must be present.
    assert!(
        registry.contains(REASON_FEDERATION_TRUST_DOMAIN_MISMATCH),
        "federation_trust_domain_mismatch missing from embedded registry",
    );
    assert!(
        registry.contains(REASON_INVALID_ACK_TOKEN),
        "invalid_ack_token missing from embedded registry",
    );

    // Every curated reason-code set MUST be a registry subset; a constant
    // absent from the snapshot signals manual-mirror drift.
    let curated = [
        KNOWN_REASON_CODES_ROUND_C45,
        KNOWN_REASON_CODES_AUTHZ_GOVERNANCE,
        KNOWN_REASON_CODES_CKP_0007,
        KNOWN_REASON_CODES_AGENT_PARTICIPATION,
        KNOWN_REASON_CODES_ROUND_C44,
        KNOWN_REASON_CODES_REACTION,
        KNOWN_REASON_CODES_CONTACT_DIRECT_CONVERSATION,
        KNOWN_REASON_CODES_AUDIT_RELEASE,
    ];
    for reason in curated.iter().flat_map(|set| set.iter()) {
        assert!(
            registry.contains(*reason),
            "REASON constant {reason:?} not present in embedded \
             error-code-registry.json (codes or reason_codes)",
        );
    }
}
