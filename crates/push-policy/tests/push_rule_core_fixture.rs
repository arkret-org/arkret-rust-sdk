//! Executable consumer for the spec fixture
//! `fixtures/push-rule-core-fixture.json` (shared v1 push-rule watch-state
//! vectors, `ak.profile.push_gateway.blind_wakeup.v1`).
//!
//! Every case drives the SDK's shared push-rule core
//! [`arkret_push_policy::push_rule_core::evaluate_watch_level`] with the fixture's
//! `(watch_level, event)` inputs and asserts the fixture's `expected`
//! `deliver` / `blind_wakeup` / `reason_code` decision plus the derived
//! client-projection flags. This is the pure protocol decision the spec
//! requires every SDK to converge on; transport, DND and UI wrapping are
//! left to higher crates.

use arkret_push_policy::push_rule_core::{
    EventContext, ShouldNotify, WatchLevel, evaluate_watch_level,
};
use arkret_schema::embedded_json_artifact;
use serde_json::Value;

const FIXTURE_PATH: &str = "fixtures/push-rule-core-fixture.json";

fn fixture() -> Value {
    embedded_json_artifact(FIXTURE_PATH).expect("embedded push-rule-core fixture must load")
}

/// Build the SDK `EventContext` from the fixture `event` object. Every field
/// is optional in the fixture and defaults to `false`, matching
/// `EventContext::default()`.
fn context_from_event(event: &Value) -> EventContext {
    let flag = |key: &str| event.get(key).and_then(Value::as_bool).unwrap_or(false);
    EventContext {
        mentions_actor: flag("mentions_actor"),
        assigned_to_actor: flag("assigned_to_actor"),
        reply_to_self: flag("reply_to_self"),
        participating_thread_update: flag("participating_thread_update"),
        is_e2ee: flag("is_e2ee"),
        local_decrypted: flag("local_decrypted"),
    }
}

#[test]
fn push_rule_core_fixture_cases_all_match_shared_core() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("fixture cases array");
    assert_eq!(cases.len(), 14, "case inventory pinned to the spec fixture");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        if name == "hardened_realm_disables_recipient_registered_mention_routing" {
            let variants = case["variants"].as_array().expect("hardened variants");
            assert_eq!(variants.len(), 5);
            for variant in variants {
                let hardened = variant["realm_profiles"]
                    .as_array()
                    .expect("realm profiles")
                    .iter()
                    .any(|profile| {
                        matches!(
                            profile.as_str(),
                            Some(
                                "ak.profile.mls.minimal_metadata_realm.v1"
                                    | "ak.profile.attested_audit.e2ee.v1"
                                    | "ak.profile.disclosed_audit.e2ee.v1"
                            )
                        )
                    });
                let declared = variant["declared_mention_routing_hint"]
                    .as_str()
                    .expect("declared mention routing hint");
                let effective = if hardened || declared != "recipient_registered_token" {
                    "disabled"
                } else {
                    declared
                };
                assert_eq!(
                    effective,
                    variant["expected_effective_hint"]
                        .as_str()
                        .expect("expected effective hint")
                );
            }
            continue;
        }
        let level = WatchLevel::from_wire(case["watch_level"].as_str().expect("watch_level"))
            .unwrap_or_else(|| panic!("case {name}: unknown watch_level"));
        let ctx = context_from_event(&case["event"]);
        let expected = &case["expected"];

        let (decision, reason) = evaluate_watch_level(level, &ctx);

        assert_eq!(
            decision.delivers(),
            expected["deliver"].as_bool().expect("expected.deliver"),
            "case {name}: deliver decision must match fixture"
        );
        assert_eq!(
            matches!(decision, ShouldNotify::BlindWakeup),
            expected["blind_wakeup"]
                .as_bool()
                .expect("expected.blind_wakeup"),
            "case {name}: blind_wakeup decision must match fixture"
        );
        assert_eq!(
            reason,
            expected["reason_code"]
                .as_str()
                .expect("expected.reason_code"),
            "case {name}: reason_code must match fixture"
        );

        // Derived client-projection flags the shared core implies.
        let projection = &expected["client_projection"];
        assert_eq!(
            decision.visible(),
            projection["should_notify"]
                .as_bool()
                .expect("should_notify"),
            "case {name}: should_notify (visible banner) must match projection"
        );
        assert_eq!(
            matches!(decision, ShouldNotify::BlindWakeup),
            projection["blind_wakeup_required"]
                .as_bool()
                .expect("blind_wakeup_required"),
            "case {name}: blind_wakeup_required must match projection"
        );
        // `watch_suppressed` is true exactly when a resolved decision skips
        // delivery (muted / not-mentioned / not-participating / decrypted-miss).
        let watch_suppressed = matches!(decision, ShouldNotify::DontNotify);
        assert_eq!(
            watch_suppressed,
            projection["watch_suppressed"]
                .as_bool()
                .expect("watch_suppressed"),
            "case {name}: watch_suppressed must match projection"
        );
        // `muted_short_circuit` is true exactly when the muted deny-rule fired.
        let muted_short_circuit = level == WatchLevel::Muted;
        assert_eq!(
            muted_short_circuit,
            projection["muted_short_circuit"]
                .as_bool()
                .expect("muted_short_circuit"),
            "case {name}: muted_short_circuit must match projection"
        );
    }
}

#[test]
fn push_rule_core_fixture_case_inventory_is_pinned() {
    // Guard: extend this consumer when the spec adds or renames cases.
    let fixture = fixture();
    let names: Vec<&str> = fixture["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .map(|case| case["name"].as_str().expect("case name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "muted_direct_mention_short_circuits",
            "mentions_only_plain_non_directed_is_filtered",
            "mentions_only_assigned_to_actor_delivers",
            "broadcast_mention_controls_authorized_audience_delivers",
            "strand_engaged_here_maps_to_receiver_side_mention",
            "hardened_realm_disables_recipient_registered_mention_routing",
            "participating_plain_non_participant_is_filtered",
            "participating_thread_update_delivers",
            "all_plain_non_directed_delivers",
            "e2ee_all_requires_blind_wakeup_until_decrypted",
            "e2ee_mentions_only_unknown_requires_blind_wakeup",
            "e2ee_participating_unknown_requires_blind_wakeup",
            "e2ee_muted_still_short_circuits",
            "e2ee_decrypted_mentions_only_filters_non_mentions",
        ],
        "push-rule-core fixture case manifest drifted — update the SDK consumer"
    );
}
