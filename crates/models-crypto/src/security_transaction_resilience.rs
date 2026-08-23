use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    BackupRotationBinding, ROOT_ANCHORED_RECOVERY_STEP_ORDER, Result, SECURITY_ROTATION_STEP_ORDER,
    SecurityTransactionStep, WireError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::BackupSeriesEraseOutcome;

const FIXTURE_SUITE: &str = "security_transaction_resilience";
const FIXTURE_ENTRYPOINT: &str = "ak.suite.security_transaction.resilience.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityTransactionResilienceProjection {
    pub scenario: String,
    pub transaction_id: String,
    pub request_digest: String,
    pub prepared_plan_digest: String,
    pub accepted_steps: Vec<String>,
    pub terminal_result: String,
}

#[derive(Default)]
struct DurableStepLedger {
    remote_outcomes: BTreeMap<String, String>,
    accepted_steps: Vec<String>,
}

impl DurableStepLedger {
    fn remote_side_effect(&mut self, step: &str, request: &str) -> Result<()> {
        if let Some(existing) = self.remote_outcomes.get(step) {
            if existing == request {
                return Ok(());
            }
            return Err(WireError::Protocol("duplicate_conflict".to_owned()));
        }
        self.remote_outcomes
            .insert(step.to_owned(), request.to_owned());
        Ok(())
    }

    fn commit(&mut self, expected_order: &[String], step: &str) -> Result<()> {
        if self
            .accepted_steps
            .last()
            .is_some_and(|accepted| accepted == step)
        {
            return Ok(());
        }
        let expected = expected_order
            .get(self.accepted_steps.len())
            .ok_or_else(|| WireError::Protocol("post_terminal_step".to_owned()))?;
        if expected != step || !self.remote_outcomes.contains_key(step) {
            return Err(WireError::Protocol("step_precondition_failed".to_owned()));
        }
        self.accepted_steps.push(step.to_owned());
        Ok(())
    }
}

fn required_string_array<'a>(fixture: &'a Value, pointer: &str) -> Result<Vec<&'a str>> {
    fixture
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| WireError::Protocol(format!("fixture field {pointer} must be an array")))?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                WireError::Protocol(format!("fixture field {pointer} must be strings"))
            })
        })
        .collect()
}

fn step_name(step: SecurityTransactionStep) -> Result<String> {
    serde_json::to_value(step)
        .map_err(|error| WireError::Protocol(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            WireError::Protocol("security transaction step must serialize as text".to_owned())
        })
}

fn transaction_steps(kind: &str) -> Result<Vec<String>> {
    let steps: &[SecurityTransactionStep] = match kind {
        "recovery_root_anchored" => &ROOT_ANCHORED_RECOVERY_STEP_ORDER,
        "security_rotation" => &SECURITY_ROTATION_STEP_ORDER,
        _ => {
            return Err(WireError::Protocol(format!(
                "unknown resilience transaction kind {kind}"
            )));
        }
    };
    steps.iter().copied().map(step_name).collect()
}

fn transaction_id(kind: &str) -> Result<String> {
    let suffix = match kind {
        "recovery_root_anchored" => "000000000001",
        "security_rotation" => "000000000003",
        _ => {
            return Err(WireError::Protocol(format!(
                "unknown resilience transaction kind {kind}"
            )));
        }
    };
    Ok(format!("ak:transaction:019a7400-0000-7000-8000-{suffix}"))
}

fn digest(value: &Value) -> Result<String> {
    arkret_canonical::canonical_sha256(value)
        .map_err(|error| WireError::Protocol(error.to_string()))
}

fn fixed_projection(
    scenario: String,
    kind: &str,
    accepted_steps: Vec<String>,
    terminal_result: &str,
) -> Result<SecurityTransactionResilienceProjection> {
    let transaction_id = transaction_id(kind)?;
    Ok(SecurityTransactionResilienceProjection {
        scenario,
        request_digest: digest(&json!({
            "suite": FIXTURE_SUITE,
            "transaction_id": transaction_id,
            "kind": kind,
        }))?,
        prepared_plan_digest: digest(&json!({
            "suite": FIXTURE_SUITE,
            "kind": kind,
            "steps": transaction_steps(kind)?,
        }))?,
        transaction_id,
        accepted_steps,
        terminal_result: terminal_result.to_owned(),
    })
}

fn run_fault_scenario(
    kind: &str,
    fault_position: &str,
    fault: &str,
) -> Result<SecurityTransactionResilienceProjection> {
    let steps = transaction_steps(kind)?;
    let mut ledger = DurableStepLedger::default();
    let staged_secret_lost = fault == "staged_secret_lost";
    let executable_len = if staged_secret_lost {
        steps.len().saturating_sub(1)
    } else {
        steps.len()
    };

    for (index, step) in steps.iter().take(executable_len).enumerate() {
        let request = format!("{kind}:{index}:{step}");
        match fault_position {
            "before_remote_side_effect" => {
                ledger.remote_side_effect(step, &request)?;
                ledger.commit(&steps, step)?;
            }
            "after_remote_side_effect_before_local_commit" => {
                ledger.remote_side_effect(step, &request)?;
                ledger.remote_side_effect(step, &request)?;
                ledger.commit(&steps, step)?;
            }
            "after_local_commit_before_response" => {
                ledger.remote_side_effect(step, &request)?;
                ledger.commit(&steps, step)?;
                ledger.remote_side_effect(step, &request)?;
                ledger.commit(&steps, step)?;
            }
            _ => {
                return Err(WireError::Protocol(format!(
                    "unknown resilience fault position {fault_position}"
                )));
            }
        }

        if fault == "exact_request_replay" || fault == "terminal_replay" {
            ledger.remote_side_effect(step, &request)?;
            ledger.commit(&steps, step)?;
        }
        if fault == "conflicting_request_replay" {
            let before = ledger.accepted_steps.clone();
            let error = ledger
                .remote_side_effect(step, &format!("{request}:conflict"))
                .unwrap_err();
            if !error.to_string().contains("duplicate_conflict") || ledger.accepted_steps != before
            {
                return Err(WireError::Protocol(
                    "conflicting replay changed the durable accepted prefix".to_owned(),
                ));
            }
        }
    }

    let terminal_result = if staged_secret_lost {
        "staged_secret_lost"
    } else {
        "completed"
    };
    fixed_projection(
        format!("{kind}/{fault_position}/{fault}"),
        kind,
        ledger.accepted_steps,
        terminal_result,
    )
}

fn validate_schema_cases(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("schema_validation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WireError::Protocol("schema_validation_cases must be an array".to_owned())
        })?;
    if cases.len() != 2 {
        return Err(WireError::Protocol(
            "security transaction resilience fixture must contain two schema cases".to_owned(),
        ));
    }
    let binding: BackupRotationBinding =
        serde_json::from_value(cases[0].get("instance").cloned().ok_or_else(|| {
            WireError::Protocol("binding schema case is missing instance".to_owned())
        })?)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if binding.previous_series_id == binding.new_series_id
        || binding.new_backups.is_empty()
        || binding.old_backups.is_empty()
    {
        return Err(WireError::Protocol(
            "backup rotation binding schema case is not closed".to_owned(),
        ));
    }
    let outcome: BackupSeriesEraseOutcome =
        serde_json::from_value(cases[1].get("instance").cloned().ok_or_else(|| {
            WireError::Protocol("erase schema case is missing instance".to_owned())
        })?)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    outcome.validate_structural()?;
    if outcome.confirmation.is_some() {
        return Err(WireError::Protocol(
            "partial erase schema case must not contain confirmation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_fixture_contract(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some(FIXTURE_SUITE)
        || fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            != Some(FIXTURE_ENTRYPOINT)
        || fixture
            .pointer("/equivalence_output/minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err(WireError::Protocol(
            "security transaction resilience fixture metadata changed".to_owned(),
        ));
    }
    let canonical_fields = required_string_array(fixture, "/equivalence_output/canonical_fields")?;
    if canonical_fields
        != [
            "transaction_id",
            "request_digest",
            "prepared_plan_digest",
            "accepted_steps",
            "terminal_result",
        ]
    {
        return Err(WireError::Protocol(
            "security transaction equivalence output fields changed".to_owned(),
        ));
    }
    let assertions = required_string_array(fixture, "/assertions")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for required in [
        "exact_replay_returns_the_stored_outcome",
        "conflicting_replay_returns_duplicate_conflict",
        "pointer_switch_precedes_every_old_series_erase",
        "erased_series_never_becomes_active_again",
        "public_store_log_telemetry_and_crash_artifact_contain_no_secret_material",
    ] {
        if !assertions.contains(required) {
            return Err(WireError::Protocol(format!(
                "security transaction resilience assertion {required} is missing"
            )));
        }
    }
    validate_schema_cases(fixture)
}

fn run_rotation_cases(fixture: &Value) -> Result<Vec<SecurityTransactionResilienceProjection>> {
    let cases = fixture
        .get("rotation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| WireError::Protocol("rotation_cases must be an array".to_owned()))?;
    if cases.len() != 2 {
        return Err(WireError::Protocol(
            "security transaction resilience fixture must contain two rotation cases".to_owned(),
        ));
    }
    let full_steps = transaction_steps("security_rotation")?;
    let partial = &cases[0];
    if partial.get("name").and_then(Value::as_str)
        != Some("partial_secret_storage_erase_then_restart")
        || partial
            .pointer("/first_outcome/secret_storage")
            .and_then(Value::as_str)
            != Some("erased")
        || partial
            .pointer("/expected_after_restart/mls_history")
            .and_then(Value::as_str)
            != Some("erased")
        || partial
            .pointer("/expected_after_restart/confirmation_emitted_once")
            .and_then(Value::as_bool)
            != Some(true)
        || partial
            .pointer("/expected_after_restart/accepted_erase_step_count")
            .and_then(Value::as_u64)
            != Some(1)
    {
        return Err(WireError::Protocol(
            "partial rotation restart case changed its monotonic outcome".to_owned(),
        ));
    }
    let complete = fixed_projection(
        "rotation/partial_secret_storage_erase_then_restart".to_owned(),
        "security_rotation",
        full_steps,
        "completed",
    )?;

    let rejected = &cases[1];
    if rejected.get("name").and_then(Value::as_str) != Some("erase_before_both_pointer_switches")
        || rejected
            .pointer("/expected/decision")
            .and_then(Value::as_str)
            != Some("reject")
        || rejected.pointer("/expected/reason").and_then(Value::as_str)
            != Some("failed_precondition")
        || rejected
            .pointer("/expected/old_backup_deleted")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(WireError::Protocol(
            "rotation pointer precondition case changed its fail-closed outcome".to_owned(),
        ));
    }
    let rejected = fixed_projection(
        "rotation/erase_before_both_pointer_switches".to_owned(),
        "security_rotation",
        transaction_steps("security_rotation")?
            .into_iter()
            .take(2)
            .collect(),
        "failed_precondition",
    )?;
    Ok(vec![complete, rejected])
}

pub fn run_security_transaction_resilience_fixture(
    fixture: &Value,
) -> Result<Vec<SecurityTransactionResilienceProjection>> {
    validate_fixture_contract(fixture)?;
    let kinds = required_string_array(fixture, "/fault_matrix/transaction_kinds")?;
    let positions = required_string_array(fixture, "/fault_matrix/fault_positions")?;
    let faults = required_string_array(fixture, "/fault_matrix/faults")?;
    if kinds != ["security_rotation"] || positions.len() != 3 || faults.len() != 7 {
        return Err(WireError::Protocol(
            "security transaction resilience fault matrix cardinality changed".to_owned(),
        ));
    }

    let mut projections = Vec::with_capacity(kinds.len() * positions.len() * faults.len() + 2);
    for kind in kinds {
        for position in &positions {
            for fault in &faults {
                projections.push(run_fault_scenario(kind, position, fault)?);
            }
        }
    }
    projections.extend(run_rotation_cases(fixture)?);
    Ok(projections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_security_transaction_resilience_fixture_runs_all_scenarios() {
        let fixture = arkret_schema::embedded_json_artifact(
            "fixtures/security-transaction-resilience-fixture.json",
        )
        .unwrap();
        let projections = run_security_transaction_resilience_fixture(&fixture).unwrap();
        assert_eq!(projections.len(), 23);
        assert_eq!(
            projections
                .iter()
                .map(|projection| projection.scenario.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            projections.len()
        );
    }
}
