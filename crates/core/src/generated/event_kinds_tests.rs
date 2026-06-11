//! Drift test for the generated `event_kinds` module.
//!
//! Re-reads `event-kind-registry.json` and asserts the committed `EventKind`
//! enum is in lockstep with it: every active `ck.*` kind has a variant, the
//! count matches, and unknown kinds fall through to the forward-compat
//! `Unknown` catch-all. If the generator was not re-run after a registry
//! change, this test fails — same contract as the profile-constants drift test.

use serde_json::Value;

use super::event_kinds::{EVENT_KIND_COUNT, EventKind};
use crate::schema::default_spec_artifacts_dir;

fn registry_active_kinds() -> Option<Vec<String>> {
    let path = default_spec_artifacts_dir()?
        .join("registry")
        .join("event-kind-registry.json");
    if !path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&path).expect("read event-kind-registry.json");
    let json: Value = serde_json::from_str(&raw).expect("parse event-kind-registry.json");
    let Some(Value::Array(entries)) = json.get("event_kinds") else {
        panic!("event-kind-registry.json missing 'event_kinds' array");
    };
    let kinds = entries
        .iter()
        .filter(|e| e.get("status").and_then(Value::as_str) == Some("active"))
        .filter_map(|e| {
            e.get("event_kind")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    Some(kinds)
}

#[test]
fn event_kind_enum_matches_registry() {
    let Some(kinds) = registry_active_kinds() else {
        // Spec artifacts not present in this build context — skip.
        return;
    };
    assert_eq!(
        EVENT_KIND_COUNT,
        kinds.len(),
        "EVENT_KIND_COUNT is stale; re-run tools/generate-sdk-event-kinds.ps1"
    );
    for kind in &kinds {
        let parsed = EventKind::from_wire(kind);
        assert!(
            parsed.is_standard(),
            "registry kind {kind:?} has no EventKind variant; re-run the generator"
        );
        assert_eq!(parsed.as_str(), kind, "round-trip mismatch for {kind:?}");
    }
}

#[test]
fn event_kind_unknown_is_forward_compatible() {
    let kind = EventKind::from_wire("ck.not.a.real.kind");
    assert!(!kind.is_standard());
    assert_eq!(kind, EventKind::Unknown("ck.not.a.real.kind".to_owned()));
    assert_eq!(kind.as_str(), "ck.not.a.real.kind");
    assert!(EventKind::try_new("ck.not.a.real.kind").is_none());
}
