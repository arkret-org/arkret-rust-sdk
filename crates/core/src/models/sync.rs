//! Account-subscribe frame shim.
//!
//! The `ak.self.account.stream.subscribe` NDJSON frame family migrated to
//! `arkret-models-collaboration` (`sync_frames::account_subscribe`,
//! re-exported below). The registered schema-fixture parity test stays
//! here with the embedded spec artifacts.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeRealms,
};

#[cfg(test)]
mod account_subscribe_fixture_tests {
    use super::*;

    #[test]
    fn account_subscribe_fixture_cases_match_typed_wire_model() {
        let fixture = crate::schema::embedded_json_artifact("fixtures/sync-fixture.json").unwrap();
        for case in fixture["account_subscribe_schema_cases"]
            .as_array()
            .unwrap()
        {
            let line = serde_json::to_string(&case["instance"]).unwrap();
            let accepted = AccountSubscribeFrame::from_ndjson_line(&line).is_ok();
            assert_eq!(
                accepted,
                case["expect_valid"].as_bool().unwrap(),
                "fixture case {} drifted",
                case["name"]
            );
        }
    }
}
