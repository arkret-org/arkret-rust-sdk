//! Executable consumer for the spec fixture `fixtures/sync-fixture.json`
//! (`ck.vector_group.sync.v1` client-sync projection + cursor recovery
//! vectors).
//!
//! The SDK-implementable subset drives [`arkret_core::cursor::Cursor`] over the
//! fixture's cursor tokens: a live `next_cursor` must decode to a valid stream
//! cursor with the pinned handle/purpose/expiry, and the expired
//! recovery-path cursors (`cursor_gap_recovery.after`,
//! `expired_cursor_not_reused.stale_cursor`) must fail closed exactly as the
//! fixture's `cursor_expired` expectation requires — the client MUST discard
//! them rather than reuse them.
//!
//! The projection halves (`collection_projection`,
//! `strand_discussion_timeline` entries, `snapshot_frontier_recovery`,
//! `snapshot_inclusion_challenge`, `e2ee_decryption_pending`) are server
//! sync-pipeline / snapshot-reducer semantics and stay owned by the soland
//! suite; they are consumed here only through the cursor surface plus a pinned
//! frontier-shape assertion, so this consumer does not paper over server-side
//! behaviour it cannot execute.

use arkret_core::cursor::Cursor;
use arkret_core::schema::embedded_json_artifact;
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/sync-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded sync fixture must load")
}

#[test]
fn sync_fixture_profile_is_pinned() {
    let fixture = fixture();
    assert_eq!(
        fixture["profile"].as_str(),
        Some("ck.vector_group.sync.v1"),
        "sync fixture profile drifted"
    );
    // Guard: pin the case keys so a silently reshaped fixture is caught.
    for key in [
        "collection_projection",
        "strand_discussion_timeline",
        "cursor_gap_recovery",
        "expired_cursor_not_reused",
        "snapshot_frontier_recovery",
        "snapshot_inclusion_challenge",
        "e2ee_decryption_pending",
    ] {
        assert!(
            fixture.get(key).is_some(),
            "sync fixture missing expected case {key}"
        );
    }
}

#[test]
fn next_cursor_is_a_well_formed_opaque_stream_cursor() {
    // The timeline continuation `next_cursor` is a valid `ck:cursor:` token,
    // but its `t`/`x` are pinned to a fixed future test clock (2026-12-30), so
    // `Cursor::decode` — which enforces wall-clock TTL bounds and rejects a
    // `t` beyond the clock-skew tolerance — cannot accept it at an arbitrary
    // real clock. `Cursor` exposes no injectable clock, so this consumer pins
    // the opaqueness contract instead: the token is a `ck:cursor:` prefixed,
    // Base64URL body whose decoded payload is a v1 stream cursor carrying the
    // pinned opaque handle. The wall-clock TTL path is exercised by the
    // expired-cursor test below.
    let fixture = fixture();
    let token = fixture["strand_discussion_timeline"]["next_cursor"]
        .as_str()
        .expect("strand_discussion_timeline.next_cursor");

    let body = token
        .strip_prefix("ak:cursor:")
        .expect("next_cursor must use the ck:cursor: transport prefix");
    let json =
        arkret_core::base64url::base64url_decode(body).expect("next_cursor body must be Base64URL");
    let payload: Value = serde_json::from_slice(&json).expect("cursor payload must be JSON");
    assert_eq!(payload["v"].as_str(), Some("1"), "v1 cursor");
    assert_eq!(
        payload["purpose"].as_str(),
        Some("stream"),
        "timeline continuation cursor is a stream cursor"
    );
    assert_eq!(
        payload["h"].as_str(),
        Some("b3BhcXVlLXN0cmVhbS1oYW5kbGU"),
        "opaque server handle is carried verbatim"
    );
}

#[test]
fn expired_recovery_cursors_fail_closed_at_decode() {
    let fixture = fixture();

    // Both the gap-recovery `after` and the stale cursor share the same
    // past-expiry (`x` = 2026-01-01) token; the fixture promises
    // `cursor_expired` and forbids reuse. `Cursor::decode` enforces TTL
    // expiry at decode, so both must reject.
    let gap_after = fixture["cursor_gap_recovery"]["request"]["after"]
        .as_str()
        .expect("cursor_gap_recovery.request.after");
    let gap_err = Cursor::decode(gap_after).expect_err("expired gap cursor must reject");
    assert!(
        gap_err.to_string().contains("expired"),
        "gap-recovery cursor must reject as the expiry class, got: {gap_err}"
    );
    assert_eq!(
        fixture["cursor_gap_recovery"]["expected_error"]["code"].as_str(),
        Some("cursor_expired"),
        "fixture pins the cursor_expired recovery code"
    );

    let stale = fixture["expired_cursor_not_reused"]["stale_cursor"]
        .as_str()
        .expect("expired_cursor_not_reused.stale_cursor");
    let stale_err = Cursor::decode(stale).expect_err("stale cursor must reject");
    assert!(
        stale_err.to_string().contains("expired"),
        "stale cursor must reject as the expiry class, got: {stale_err}"
    );

    // The fixture forbids reusing the failed cursor as any `after`/`before`
    // start; the SDK enforces this structurally by refusing to decode it into
    // a usable cursor at all (fail-closed).
    let expected = &fixture["expired_cursor_not_reused"]["expected"];
    assert_eq!(
        expected["discard_local_cursor"].as_bool(),
        Some(true),
        "fixture requires discarding the failed cursor"
    );
    assert_eq!(
        expected["stale_cursor_reused"].as_bool(),
        Some(false),
        "fixture forbids reusing the stale cursor"
    );
    assert!(
        fixture["expired_cursor_not_reused"]["trigger_errors"]
            .as_array()
            .expect("trigger_errors array")
            .iter()
            .any(|error| error.as_str() == Some("cursor_expired")),
        "fixture lists cursor_expired as a trigger"
    );
}

#[test]
fn snapshot_frontier_recovery_shape_is_pinned() {
    // Frontier recovery is a server snapshot-reducer flow; consume it here by
    // pinning the frontier commitment shape the SDK's snapshot verification
    // consumes downstream (event-set commitment + state digest present).
    let fixture = fixture();
    let recovery = &fixture["snapshot_frontier_recovery"];
    assert!(
        recovery["state_digest"].as_str().is_some(),
        "frontier recovery must carry a state_digest"
    );
    assert!(
        recovery["event_set_commitment"].is_object()
            || recovery["event_set_commitment"].is_string(),
        "frontier recovery must carry an event_set_commitment"
    );
}
