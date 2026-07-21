//! Executable consumer for the spec fixture
//! `fixtures/cursor-negative-fixture.json`
//! (`ak.vector.encoding.reject_invalid_cursor.core.v1`).
//!
//! Every case is a plausible-looking `ak:cursor:` token that the issuing
//! service MUST reject before advancing any server-side state
//! (conformance-vectors.md §1.16). The positive opaqueness contract lives in
//! `ak.vector.encoding.cursor_opaque.core.v1`; this suite pins the rejection
//! surface of [`arkret_core::cursor::Cursor::decode`] to the spec vectors so
//! the SDK's self-authored negative tests can no longer drift from the
//! published rejection semantics.

use arkret_core::cursor::Cursor;
use arkret_core::schema::embedded_json_artifact;

const FIXTURE_PATH: &str = "fixtures/cursor-negative-fixture.json";
const VECTOR_ID: &str = "ak.vector.encoding.reject_invalid_cursor.core.v1";

#[test]
fn cursor_negative_fixture_cases_all_reject() {
    let fixture =
        embedded_json_artifact(FIXTURE_PATH).expect("embedded cursor-negative fixture must load");
    let vectors = fixture["vectors"]
        .as_array()
        .expect("fixture vectors must be an array");
    assert_eq!(vectors.len(), 1, "fixture carries exactly one vector");
    let vector = &vectors[0];
    assert_eq!(vector["vector_id"].as_str(), Some(VECTOR_ID));

    let cases = vector["cases"].as_array().expect("vector cases");
    assert_eq!(cases.len(), 16, "case inventory pinned to the spec fixture");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let token = case["input_cursor"].as_str().expect("case input_cursor");
        let reason = case["expected_reason_code"]
            .as_str()
            .expect("case expected_reason_code");

        let err = Cursor::decode(token)
            .expect_err(&format!("case {name}: decoder must reject this token"));

        // The fixture keeps two rejection classes apart: `cursor_expired`
        // (structurally valid, past its `expires_at`) versus everything else
        // (`invalid_cursor`, surfaced under top-level `invalid_param`).
        if reason == "cursor_expired" {
            assert!(
                err.to_string().contains("expired"),
                "case {name}: expiry must reject as the expiry class, got: {err}"
            );
        } else {
            assert_eq!(
                reason, "invalid_cursor",
                "case {name}: unexpected reason_code in fixture"
            );
        }
    }
}

/// Guard: the case list itself is pinned so a silently shrunk fixture cannot
/// pass as full coverage.
#[test]
fn cursor_negative_fixture_case_inventory_is_pinned() {
    let fixture =
        embedded_json_artifact(FIXTURE_PATH).expect("embedded cursor-negative fixture must load");
    let names: Vec<String> = fixture["vectors"][0]["cases"]
        .as_array()
        .expect("vector cases")
        .iter()
        .map(|case| case["name"].as_str().expect("case name").to_owned())
        .collect();
    assert_eq!(
        names,
        [
            "oversized_token",
            "invalid_base64url",
            "malformed_json",
            "duplicate_json_key",
            "non_nfc_string",
            "inline_positions_rejected",
            "unknown_public_field_rejected",
            "unsupported_version",
            "handle_too_short",
            "non_canonical_timestamp",
            "negative_ttl",
            "stream_ttl_exceeds_cap",
            "barrier_ttl_exceeds_cap",
            "expired",
            "missing_millisecond_fraction",
            "retired_t_x_fields_rejected",
        ]
    );
}
