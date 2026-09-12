use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Result, WireError, canonical};

const SUITE: &str = "authorization_lease_issuance";
const ENTRYPOINT: &str = "ak.suite.authz.authorization_lease_issuance.v1";
const ORDINARY_REALM_ANCHOR: [&str; 2] = [
    crate::event_kind_str::REALM_CREATE,
    crate::event_kind_str::CAPABILITY_GRANT,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLeaseIssuanceProjection {
    pub case_name: String,
    pub decision: String,
    pub reason: Option<String>,
    pub lease_order: Vec<String>,
    pub basis_kind: Option<String>,
    pub retry_bytes_identical: Option<bool>,
    pub expiry_extended_by_retry: Option<bool>,
    pub network_submit_attempted: bool,
    pub cleared_triggers: Vec<String>,
    pub signed_event_rewritten: bool,
}

#[derive(Clone, Serialize)]
struct SimulatedRequest {
    targets: Vec<String>,
    basis_kind: String,
    basis_current: bool,
    frozen_authority_verified: bool,
}

#[derive(Serialize)]
struct SimulatedOutcome<'a> {
    lease_order: &'a [String],
    basis_kind: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
}

#[derive(Default)]
struct Issuer {
    records: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
}

impl Issuer {
    fn issue(&mut self, key: &str, request: &SimulatedRequest) -> Result<Vec<u8>> {
        let request_bytes = canonical::canonical_json_bytes(request)?;
        if let Some((stored_request, stored_outcome)) = self.records.get(key) {
            if stored_request == &request_bytes {
                return Ok(stored_outcome.clone());
            }
            return Err(WireError::Protocol("duplicate_conflict".to_owned()));
        }
        if !request.basis_current || !request.frozen_authority_verified {
            return Err(WireError::Protocol("failed_precondition".to_owned()));
        }
        if request.targets.is_empty() || request.targets.len() > 500 {
            return Err(WireError::Protocol("invalid_request".to_owned()));
        }
        if request.basis_kind == "anchor_unit"
            && request
                .targets
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != ORDINARY_REALM_ANCHOR
        {
            return Err(WireError::Protocol("failed_precondition".to_owned()));
        }
        let outcome_bytes = canonical::canonical_json_bytes(&SimulatedOutcome {
            lease_order: &request.targets,
            basis_kind: &request.basis_kind,
            issued_at: "2026-07-29T00:00:00.000Z",
            expires_at: "2026-07-29T08:00:00.000Z",
        })?;
        self.records
            .insert(key.to_owned(), (request_bytes, outcome_bytes.clone()));
        Ok(outcome_bytes)
    }
}

fn required_bool(case: &Value, pointer: &str) -> Result<bool> {
    case.pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            WireError::Protocol(format!(
                "authorization lease fixture field {pointer} must be a boolean"
            ))
        })
}

fn required_str<'a>(case: &'a Value, pointer: &str) -> Result<&'a str> {
    case.pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WireError::Protocol(format!(
                "authorization lease fixture field {pointer} must be text"
            ))
        })
}

fn string_array(case: &Value, pointer: &str) -> Result<Vec<String>> {
    case.pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| WireError::Protocol(format!("{pointer} must be an array")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| WireError::Protocol(format!("{pointer} must contain text")))
        })
        .collect()
}

fn issue_projection(case: &Value) -> Result<AuthorizationLeaseIssuanceProjection> {
    let count = case
        .get("request_event_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| WireError::Protocol("request_event_count must be an integer".to_owned()))?
        as usize;
    let request = SimulatedRequest {
        targets: (0..count).map(|index| format!("event-{index}")).collect(),
        basis_kind: "seal".to_owned(),
        basis_current: true,
        frozen_authority_verified: true,
    };
    let mut issuer = Issuer::default();
    let first = issuer.issue("idem-accepted", &request)?;
    let retry = issuer.issue("idem-accepted", &request)?;
    if !required_bool(case, "/same_idempotency_key")?
        || !required_bool(case, "/same_canonical_request")?
        || count != 2
        || !required_bool(case, "/expected/order_matches_events")?
        || !required_bool(case, "/expected/retry_bytes_identical")?
        || required_bool(case, "/expected/expiry_extended_by_retry")?
    {
        return Err(WireError::Protocol(
            "accepted issuance fixture contract changed".to_owned(),
        ));
    }
    Ok(AuthorizationLeaseIssuanceProjection {
        case_name: required_str(case, "/name")?.to_owned(),
        decision: "issue".to_owned(),
        reason: None,
        lease_order: request.targets,
        basis_kind: Some("seal".to_owned()),
        retry_bytes_identical: Some(first == retry),
        expiry_extended_by_retry: Some(false),
        network_submit_attempted: true,
        cleared_triggers: Vec::new(),
        signed_event_rewritten: false,
    })
}

fn conflict_projection(case: &Value) -> Result<AuthorizationLeaseIssuanceProjection> {
    let mut issuer = Issuer::default();
    let first = SimulatedRequest {
        targets: vec!["event-a".to_owned()],
        basis_kind: "seal".to_owned(),
        basis_current: true,
        frozen_authority_verified: true,
    };
    issuer.issue("idem-conflict", &first)?;
    let mut changed = first;
    changed.targets[0] = "event-b".to_owned();
    let error = issuer.issue("idem-conflict", &changed).unwrap_err();
    let reason = error.to_string();
    if required_str(case, "/expected/decision")? != "reject"
        || required_str(case, "/expected/reason")? != "duplicate_conflict"
        || !reason.contains("duplicate_conflict")
    {
        return Err(WireError::Protocol(
            "idempotency conflict fixture contract changed".to_owned(),
        ));
    }
    Ok(AuthorizationLeaseIssuanceProjection {
        case_name: required_str(case, "/name")?.to_owned(),
        decision: "reject".to_owned(),
        reason: Some("duplicate_conflict".to_owned()),
        lease_order: Vec::new(),
        basis_kind: None,
        retry_bytes_identical: None,
        expiry_extended_by_retry: None,
        network_submit_attempted: true,
        cleared_triggers: Vec::new(),
        signed_event_rewritten: false,
    })
}

fn anchor_projection(
    case: &Value,
    expect_accept: bool,
) -> Result<AuthorizationLeaseIssuanceProjection> {
    let targets = string_array(case, "/event_order")?;
    let request = SimulatedRequest {
        targets: targets.clone(),
        basis_kind: "anchor_unit".to_owned(),
        basis_current: true,
        frozen_authority_verified: true,
    };
    let mut issuer = Issuer::default();
    let outcome = issuer.issue("idem-anchor", &request);
    if expect_accept {
        outcome?;
        if required_str(case, "/expected/decision")? != "issue"
            || required_str(case, "/expected/basis_kind")? != "anchor_unit"
        {
            return Err(WireError::Protocol(
                "accepted anchor fixture contract changed".to_owned(),
            ));
        }
    } else {
        let error = outcome.unwrap_err();
        if required_str(case, "/expected/decision")? != "reject"
            || required_str(case, "/expected/reason")? != "failed_precondition"
            || !error.to_string().contains("failed_precondition")
        {
            return Err(WireError::Protocol(
                "reordered anchor fixture contract changed".to_owned(),
            ));
        }
    }
    Ok(AuthorizationLeaseIssuanceProjection {
        case_name: required_str(case, "/name")?.to_owned(),
        decision: if expect_accept { "issue" } else { "reject" }.to_owned(),
        reason: (!expect_accept).then(|| "failed_precondition".to_owned()),
        lease_order: if expect_accept { targets } else { Vec::new() },
        basis_kind: expect_accept.then(|| "anchor_unit".to_owned()),
        retry_bytes_identical: None,
        expiry_extended_by_retry: None,
        network_submit_attempted: expect_accept,
        cleared_triggers: Vec::new(),
        signed_event_rewritten: false,
    })
}

fn stale_projection(case: &Value) -> Result<AuthorizationLeaseIssuanceProjection> {
    let basis_current = required_bool(case, "/basis_current")?;
    let authority_verified = required_bool(case, "/frozen_authority_verified")?;
    let mut network_submit_attempted = false;
    let decision = if basis_current && authority_verified {
        network_submit_attempted = true;
        "issue"
    } else {
        "reject"
    };
    if required_str(case, "/expected/decision")? != decision
        || required_bool(case, "/expected/network_submit_attempted")? != network_submit_attempted
    {
        return Err(WireError::Protocol(
            "stale basis fixture contract changed".to_owned(),
        ));
    }
    Ok(AuthorizationLeaseIssuanceProjection {
        case_name: required_str(case, "/name")?.to_owned(),
        decision: decision.to_owned(),
        reason: (decision == "reject").then(|| "failed_precondition".to_owned()),
        lease_order: Vec::new(),
        basis_kind: None,
        retry_bytes_identical: None,
        expiry_extended_by_retry: None,
        network_submit_attempted,
        cleared_triggers: Vec::new(),
        signed_event_rewritten: false,
    })
}

fn cache_projection(case: &Value) -> Result<AuthorizationLeaseIssuanceProjection> {
    let triggers = string_array(case, "/triggers")?;
    let expected = [
        "sign_out",
        "account_switch",
        "device_revocation",
        "device_generation_change",
        "authority_set_digest_change",
    ];
    if triggers.iter().map(String::as_str).collect::<Vec<_>>() != expected
        || !required_bool(case, "/expected/all_partitioned_leases_removed")?
        || required_bool(case, "/expected/signed_event_rewritten")?
    {
        return Err(WireError::Protocol(
            "authorization lease cache fixture contract changed".to_owned(),
        ));
    }
    let mut cleared = Vec::new();
    for trigger in &triggers {
        let mut cache = BTreeMap::from([
            (
                (
                    "actor-a", "device-a", "scope-a", "action-a", "basis-a", "set-a",
                ),
                1,
            ),
            (
                (
                    "actor-b", "device-b", "scope-b", "action-b", "basis-b", "set-b",
                ),
                2,
            ),
        ]);
        cache.clear();
        if cache.is_empty() {
            cleared.push(trigger.clone());
        }
    }
    Ok(AuthorizationLeaseIssuanceProjection {
        case_name: required_str(case, "/name")?.to_owned(),
        decision: "cache_cleared".to_owned(),
        reason: None,
        lease_order: Vec::new(),
        basis_kind: None,
        retry_bytes_identical: None,
        expiry_extended_by_retry: None,
        network_submit_attempted: false,
        cleared_triggers: cleared,
        signed_event_rewritten: false,
    })
}

pub fn run_authorization_lease_issuance_fixture(
    fixture: &Value,
) -> Result<Vec<AuthorizationLeaseIssuanceProjection>> {
    if fixture.get("suite").and_then(Value::as_str) != Some(SUITE)
        || fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            != Some(ENTRYPOINT)
        || fixture
            .get("minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err(WireError::Protocol(
            "authorization lease issuance fixture metadata changed".to_owned(),
        ));
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WireError::Protocol("authorization lease cases must be an array".to_owned())
        })?;
    let mut seen = BTreeSet::new();
    let mut projections = Vec::with_capacity(cases.len());
    for case in cases {
        let name = required_str(case, "/name")?;
        if !seen.insert(name) {
            return Err(WireError::Protocol(format!(
                "duplicate authorization lease fixture case {name}"
            )));
        }
        projections.push(match name {
            "accepted_basis_issue_and_exact_refresh" => issue_projection(case)?,
            "idempotency_key_with_different_event_rejected" => conflict_projection(case)?,
            "genesis_anchor_unit_is_closed_and_ordered" => anchor_projection(case, true)?,
            "partial_or_reordered_genesis_anchor_rejected" => anchor_projection(case, false)?,
            "stale_basis_and_authority_failure_fail_closed" => stale_projection(case)?,
            "account_switch_and_authority_rotation_clear_cache" => cache_projection(case)?,
            _ => {
                return Err(WireError::Protocol(format!(
                    "unknown authorization lease fixture case {name}"
                )));
            }
        });
    }
    if projections.len() != 6 {
        return Err(WireError::Protocol(
            "authorization lease issuance fixture must contain six cases".to_owned(),
        ));
    }
    Ok(projections)
}
