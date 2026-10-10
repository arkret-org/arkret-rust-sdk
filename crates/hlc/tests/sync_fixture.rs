//! Executable consumer for the spec fixture `fixtures/client-sync-fixture.json`
//! (`ak.vector.sync.client_account_stream.v1`).
//!
//! The fixture states the own-Station account aggregate stream contract as
//! decision tables: which per-stream tails a client accepts, in which order a
//! durable checkpoint may advance, which reconnect outcomes resume and which
//! reset, and what actually cancels a recipient delivery. Each test below
//! re-derives the decision from the case data with the rule the specification
//! states and asserts it against the fixture's own `expected`, so a fixture
//! whose data stops matching its verdict fails here rather than being read as
//! documentation.
//!
//! The server-side halves — minting cursors, producing baseline segments,
//! authorizing streams — stay owned by the service suite. This consumer keeps
//! the client-side invariants plus the `ak:cursor:` opaqueness contract that
//! [`arkret_hlc::Cursor`] enforces.

use arkret_hlc::Cursor;
use arkret_schema_conformance::spec_json_artifact;
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/client-sync-fixture.json";

fn fixture() -> Value {
    spec_json_artifact(FIXTURE_PATH).expect("client sync fixture must load")
}

#[test]
fn account_stale_fixture_has_an_exact_typed_continuation_without_installation() {
    let fixture = fixture();
    let case = cases(&fixture, "reconnect")
        .iter()
        .find(|case| name(case) == "revision_stale_keeps_the_cursor_and_continues_backfill")
        .expect("independent stale-prefix recovery case");
    let problem: arkret_wire::Problem =
        serde_json::from_value(case["response_problem"].clone()).unwrap();
    let details = problem.account_revision_stale_details().unwrap().unwrap();
    details
        .validate_after(case["stored_cursor"].as_str().unwrap())
        .unwrap();
    assert!(details.validate_after("ak:cursor:replaced").is_err());
    for field in [
        "baseline_redone",
        "discard_old_cursor",
        "checkpoint_advanced_on_error",
        "delivery_acks_invalidated",
        "mls_private_state_deleted",
    ] {
        assert_eq!(case[field], false, "{field}");
    }
    assert_eq!(case["fresh_process_readback"], true);
    assert_eq!(
        case["expected_client_action"],
        "follow_the_response_continuation_cursor"
    );
}

fn cases<'a>(fixture: &'a Value, key: &str) -> &'a Vec<Value> {
    fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("client sync fixture case list {key}"))
}

fn name(case: &Value) -> &str {
    case["name"].as_str().expect("every case is named")
}

fn expected(case: &Value) -> &str {
    case["expected"]
        .as_str()
        .unwrap_or_else(|| panic!("case {} carries an expected verdict", name(case)))
}

/// Read an optional boolean flag, treating an absent flag as "not asserted".
fn flag(case: &Value, key: &str) -> Option<bool> {
    case.get(key).map(|value| {
        value
            .as_bool()
            .unwrap_or_else(|| panic!("{}.{key} must be a boolean", name(case)))
    })
}

#[test]
fn client_sync_fixture_surface_is_pinned() {
    let fixture = fixture();
    assert_eq!(fixture["suite"].as_str(), Some("client_sync"));
    assert_eq!(fixture["runner"]["kind"].as_str(), Some("named_suite"));
    assert_eq!(
        fixture["runner"]["entrypoint"].as_str(),
        Some("ak.suite.sync.client_account_stream.v1")
    );
    assert!(
        fixture["covers_vectors"]
            .as_array()
            .expect("covers_vectors")
            .iter()
            .any(|vector| vector.as_str() == Some("ak.vector.sync.client_account_stream.v1")),
        "the fixture must stay bound to its registered vector"
    );
    for key in [
        "subscription",
        "stream_tails",
        "checkpoint_ordering",
        "reconnect",
        "delivery_cancellation",
    ] {
        assert!(
            fixture.get(key).is_some(),
            "client sync fixture missing case group {key}"
        );
    }

    // Guard the deletions: snapshot frontier recovery, inclusion challenge and
    // state digest are gone from the protocol, so a fixture that reintroduces
    // any of them must fail here instead of quietly regrowing a consumer.
    let text = serde_json::to_string(&fixture).expect("fixture reserializes");
    for removed in ["frontier", "inclusion", "state_digest", "seal", "lattice"] {
        assert!(
            !text.contains(removed),
            "client sync fixture reintroduced the removed concept {removed}"
        );
    }
}

#[test]
fn the_account_stream_carries_no_global_or_realm_position() {
    // Realm, Circle and Sidecar each keep an independent commit stream. The
    // account aggregate only orders delivery of frames, so neither a global
    // chain position nor a per-Realm position exists to be compared.
    let fixture = fixture();
    let subscription = &fixture["subscription"];
    assert_eq!(
        subscription["operation_id"].as_str(),
        Some("ak.self.account.stream.subscribe.v1")
    );
    assert_eq!(
        subscription["global_position_exists"].as_bool(),
        Some(false)
    );
    assert_eq!(subscription["realm_position_exists"].as_bool(), Some(false));

    let classes: Vec<&str> = subscription["stream_classes"]
        .as_array()
        .expect("stream_classes")
        .iter()
        .map(|class| class.as_str().expect("stream class is a string"))
        .collect();
    assert_eq!(
        classes,
        ["authority_committed", "account_private", "delivery"],
        "the subscribed stream classes are pinned"
    );
}

/// One commit stream is continuous when every delivered commit advances its
/// own `stream_position` by exactly one and names the commit it follows. The
/// first delivered commit of a tail names no predecessor.
fn tail_is_continuous(commits: &[Value]) -> bool {
    let mut previous: Option<(u64, &str)> = None;
    for commit in commits {
        let position = commit["stream_position"]
            .as_u64()
            .expect("stream_position is an unsigned integer");
        let commit_id = commit["commit_id"].as_str().expect("commit_id");
        let previous_ref = commit["previous_commit_ref"].as_str();
        match previous {
            None => {
                if previous_ref.is_some() {
                    return false;
                }
            }
            Some((previous_position, previous_id)) => {
                if position != previous_position + 1 || previous_ref != Some(previous_id) {
                    return false;
                }
            }
        }
        previous = Some((position, commit_id));
    }
    true
}

#[test]
fn a_stream_tail_is_accepted_exactly_when_it_is_continuous() {
    let fixture = fixture();
    let mut kinds = Vec::new();
    for case in cases(&fixture, "stream_tails") {
        let commits = case["commits"].as_array().expect("commits");
        let continuous = tail_is_continuous(commits);
        let verdict = if continuous { "accepted" } else { "rejected" };
        assert_eq!(
            verdict,
            expected(case),
            "{}: continuity and verdict disagree",
            name(case)
        );

        let stream_ref = &case["stream_ref"];
        assert!(
            stream_ref["realm_id"].is_string(),
            "{}: every commit stream is anchored in a Realm",
            name(case)
        );
        kinds.push(stream_ref["kind"].as_str().expect("stream kind").to_owned());

        if continuous {
            continue;
        }
        // An unexplained position jump stops that one stream. It never resets a
        // sibling stream and never invalidates the delivery queue.
        assert_eq!(
            case["expected_client_action"].as_str(),
            Some("stop_this_stream_and_refetch_snapshot"),
            "{}: a broken tail refetches its own snapshot",
            name(case)
        );
        assert_eq!(flag(case, "other_streams_reset"), Some(false));
        assert_eq!(flag(case, "to_device_acks_reset"), Some(false));
    }

    for kind in ["realm", "circle", "sidecar"] {
        assert!(
            kinds.iter().any(|seen| seen == kind),
            "the fixture must exercise the independent {kind} stream"
        );
    }
}

#[test]
fn a_durable_checkpoint_never_outruns_the_installed_projection() {
    let fixture = fixture();
    let mut ordering_cases = 0;
    let mut merge_cases = 0;
    let mut undurable_cases = Vec::new();

    for case in cases(&fixture, "checkpoint_ordering") {
        let steps = case["steps"].as_array().expect("steps");
        let position_of = |action: &str| {
            steps
                .iter()
                .position(|step| step["action"].as_str() == Some(action))
        };
        let install = position_of("install_typed_current_result");
        let advance = position_of("advance_durable_cursor");

        if let Some(install) = install {
            let durable = steps[install]["durable"]
                .as_bool()
                .expect("projection installation states whether its cut is durable");
            if !durable {
                undurable_cases.push(name(case));
                assert_eq!(
                    expected(case),
                    "rejected",
                    "{}: an undurable projection cannot establish a new checkpoint",
                    name(case)
                );
                assert!(
                    advance.is_none(),
                    "{}: a failed projection installation must preserve the old checkpoint",
                    name(case)
                );
                continue;
            }
        }

        if let (Some(install), Some(advance)) = (install, advance) {
            ordering_cases += 1;
            let verdict = if install < advance {
                "accepted"
            } else {
                "rejected"
            };
            assert_eq!(
                verdict,
                expected(case),
                "{}: a checkpoint that precedes its projection loses the delta after a crash",
                name(case)
            );
            continue;
        }

        // The remaining case is the merge rule: an incremental delivered ahead
        // of the baseline survives, because the baseline section was cut at an
        // older stream position and must not overwrite the newer delta.
        merge_cases += 1;
        let delivered = steps
            .iter()
            .find(|step| step["action"].as_str() == Some("deliver_incremental"))
            .and_then(|step| step["stream_position"].as_u64())
            .expect("merge case delivers an incremental at a stream position");
        let baseline_cut = steps
            .iter()
            .find(|step| step["action"].as_str() == Some("deliver_baseline_section_complete"))
            .and_then(|step| step["as_of_stream_position"].as_u64())
            .expect("merge case completes a baseline section at a cut position");
        assert!(
            baseline_cut < delivered,
            "{}: the merge rule only bites when the baseline cut is older",
            name(case)
        );
        assert_eq!(expected(case), "accepted");
    }

    assert!(
        ordering_cases >= 2 && merge_cases >= 1,
        "both the ordering rule and the merge rule must stay covered"
    );
    for case in [
        "sidecar_missing_tail_does_not_install_newer_current_or_checkpoint",
        "sidecar_projection_transaction_failure_preserves_prior_cut",
    ] {
        assert!(
            undurable_cases.contains(&case),
            "the undurable checkpoint case {case} must stay covered"
        );
    }
}

#[test]
fn foreign_cursor_and_local_tamper_keep_distinct_recovery_cases() {
    let fixture = fixture();
    let reconnect = cases(&fixture, "reconnect");
    for (case_name, origin) in [
        (
            "cursor_integrity_invalid_redoes_only_that_surface_baseline",
            "local_unknown_tampered_handle",
        ),
        (
            "foreign_station_cursor_redoes_only_that_surface_baseline",
            "distinct_station_valid_issued_binding",
        ),
    ] {
        let matches: Vec<_> = reconnect
            .iter()
            .filter(|case| name(case) == case_name)
            .collect();
        assert_eq!(matches.len(), 1);
        let case = matches[0];
        assert_eq!(case["cursor_origin"], origin);
        assert_eq!(case["server_outcome"], "cursor_integrity_invalid");
        assert_eq!(flag(case, "server_state_advanced"), Some(false));
        assert_eq!(flag(case, "local_verified_commits_deleted"), Some(false));
        assert_eq!(flag(case, "mls_private_state_deleted"), Some(false));
        assert_eq!(flag(case, "delivery_acks_invalidated"), Some(false));
        assert_eq!(flag(case, "fresh_process_readback"), Some(true));
    }
}

/// Cursor expiry and integrity refusals discard the stored cursor and redo that
/// one surface baseline; everything else continues from the cursor it has.
fn reconnect_verdict(server_outcome: &str) -> &'static str {
    match server_outcome {
        "cursor_expired" | "cursor_integrity_invalid" => "reset",
        "accepted" | "revision_stale" | "stream_tail_missing" => "resume",
        other => panic!("unregistered reconnect outcome {other}"),
    }
}

#[test]
fn a_reconnect_resets_only_the_surface_whose_cursor_failed() {
    let fixture = fixture();
    for case in cases(&fixture, "reconnect") {
        let outcome = case["server_outcome"].as_str().expect("server_outcome");
        assert_eq!(
            reconnect_verdict(outcome),
            expected(case),
            "{}: reconnect verdict does not follow its server outcome",
            name(case)
        );

        match expected(case) {
            "reset" => {
                assert_eq!(
                    flag(case, "baseline_redone"),
                    Some(true),
                    "{}: a discarded cursor redoes its surface baseline",
                    name(case)
                );
                assert_eq!(
                    flag(case, "discard_old_cursor"),
                    Some(true),
                    "{}: the failed cursor must never be reused",
                    name(case)
                );
            }
            "resume" => {
                assert_ne!(
                    flag(case, "baseline_redone"),
                    Some(true),
                    "{}: a resumable reconnect must not redo a baseline",
                    name(case)
                );
                assert_ne!(
                    flag(case, "discard_old_cursor"),
                    Some(true),
                    "{}: a resumable reconnect keeps its cursor",
                    name(case)
                );
            }
            other => panic!("unregistered reconnect verdict {other}"),
        }

        // Neither branch is allowed to widen: locally verified Commits, MLS
        // private state and issued delivery ACKs survive every reconnect.
        for preserved in [
            "local_verified_commits_deleted",
            "mls_private_state_deleted",
            "delivery_acks_invalidated",
            "other_streams_reset",
            "to_device_acks_reset",
        ] {
            assert_ne!(
                flag(case, preserved),
                Some(true),
                "{}: a reconnect must not set {preserved}",
                name(case)
            );
        }

        if outcome == "stream_tail_missing" {
            let affected = case["affected_stream_ref"]["kind"]
                .as_str()
                .expect("the missing tail names its stream");
            let recovered: Vec<&str> = case["recovered_streams"]
                .as_array()
                .expect("recovered_streams")
                .iter()
                .map(|stream| stream.as_str().expect("stream kind is a string"))
                .collect();
            assert_eq!(
                recovered,
                [affected],
                "{}: only the missing tail is recovered",
                name(case)
            );
        }
    }
}

#[test]
fn only_an_explicit_ack_after_durable_processing_cancels_a_delivery() {
    let fixture = fixture();
    let mut message_ids = std::collections::BTreeSet::new();

    for case in cases(&fixture, "delivery_cancellation") {
        let action = case["action"].as_str().expect("action");
        let durably_processed = case["durably_processed"]
            .as_bool()
            .expect("durably_processed");
        // Endpoint queue capacity is an admission precondition (client-sync
        // §10.1): a full endpoint atomically rejects the new delivery with
        // `quota_exceeded`, evicts nothing and consumes no idempotency identity.
        let at_full_capacity = action == "enqueue_new_delivery_at_full_capacity";
        let cancelled = action.starts_with("ack") && durably_processed;
        let verdict = if at_full_capacity {
            "rejected_quota_exceeded_with_old_delivery_still_queued"
        } else if cancelled {
            "removed_from_recipient_queue"
        } else {
            "still_queued"
        };
        assert_eq!(
            verdict,
            expected(case),
            "{}: only an explicit ACK after durable processing cancels a delivery",
            name(case)
        );
        if at_full_capacity {
            assert_eq!(
                flag(case, "request_idempotency_written"),
                Some(false),
                "{}: a capacity rejection must not consume the request idempotency identity",
                name(case)
            );
        }

        let message_id = case["device_message_id"]
            .as_str()
            .expect("device_message_id");
        assert!(
            message_ids.insert(message_id.to_owned()),
            "{}: each case owns its own delivery",
            name(case)
        );
        // The backfill path shares the one recipient queue and the one ACK
        // token; it never mints a second copy of the delivery.
        assert_ne!(flag(case, "second_copy_created"), Some(true));
    }
}

#[test]
fn stored_cursor_labels_are_opaque_and_never_decode_as_live_cursors() {
    // Every cursor in the fixture is a stable label for a stored client-side
    // position, not an issued token. `Cursor::decode` is the only path from a
    // token to a position and it fails closed on all of them, which is exactly
    // the contract: a client persists its cursor as opaque bytes and never
    // parses ordering out of it.
    let fixture = fixture();
    let mut checked = 0;

    for case in cases(&fixture, "reconnect") {
        let token = case["stored_cursor"].as_str().expect("stored_cursor");
        assert!(
            token.starts_with("ak:cursor:"),
            "{}: a stored cursor keeps the transport prefix",
            name(case)
        );
        Cursor::decode(token).expect_err("a fixture label must not decode as a live cursor");
        checked += 1;
    }

    for case in cases(&fixture, "checkpoint_ordering") {
        for step in case["steps"].as_array().expect("steps") {
            let Some(token) = step.get("cursor").and_then(Value::as_str) else {
                continue;
            };
            assert!(token.starts_with("ak:cursor:"));
            Cursor::decode(token).expect_err("a fixture label must not decode as a live cursor");
            checked += 1;
        }
    }

    assert!(checked >= 7, "every fixture cursor must be exercised");
}
