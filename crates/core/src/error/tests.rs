use super::*;

#[test]
fn every_known_error_code_has_http_status() {
    for code in KNOWN_ERROR_CODES {
        assert!(
            error_code_http_status(code).is_some(),
            "known error code {code:?} has no HTTP status mapping",
        );
    }
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
            Some(*code),
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
        KNOWN_REASON_CODES_CKP_0007,
        KNOWN_REASON_CODES_ROUND_C44,
        KNOWN_REASON_CODES_REACTION,
        KNOWN_REASON_CODES_CONTACT_DIRECT_CONVERSATION,
    ];
    for reason in curated.iter().flat_map(|set| set.iter()) {
        assert!(
            registry.contains(*reason),
            "REASON constant {reason:?} not present in embedded \
             error-code-registry.json (codes or reason_codes)",
        );
    }
}
