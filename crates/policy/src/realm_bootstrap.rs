//! Ordinary Realm bootstrap batch validation.
//!
//! `ak.realm.create` is not an independently committable Event.  The wire
//! unit is the ordered batch `create -> founding grant -> closed followups`.
//! Keeping that shape here prevents clients and servers from growing separate
//! kind allowlists or interpreting genesis authority differently.

use std::collections::BTreeSet;

use arkret_wire::{Event, EventKind};

/// The only actions carried by an ordinary Realm founding grant.
pub const REALM_FOUNDING_GRANT_ACTIONS: [&str; 4] = [
    "ak.realm.admin",
    "ak.capability.grant",
    "ak.capability.revoke",
    "ak.realm_key.share",
];

/// Closed set of initial Realm facets that may follow the founding grant.
pub fn is_realm_bootstrap_followup_kind(kind: &str) -> bool {
    matches!(
        kind,
        EventKind::MEMBER_STATE
            | EventKind::REALM_HISTORY_VISIBILITY
            | EventKind::REALM_HISTORY_SHARING_POLICY
            | EventKind::REALM_POLICY_COMPONENTS
            | EventKind::REALM_DISCOVERY
            | EventKind::REALM_JOIN_RULE
            | EventKind::REALM_DELIVERY_BINDING_POLICY
            | EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmBootstrapValidationError {
    NotOrdinaryRealmBootstrap,
    RealmFoundingGrantMissing,
    InvalidRealmFoundingGrant,
    OutOfOrderBootstrap,
    EffectsPayloadMismatch,
    PlaneCrossWrite,
}

impl RealmBootstrapValidationError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::NotOrdinaryRealmBootstrap => "not_ordinary_realm_bootstrap",
            Self::RealmFoundingGrantMissing => "realm_founding_grant_missing",
            Self::InvalidRealmFoundingGrant => "invalid_realm_founding_grant",
            Self::OutOfOrderBootstrap => "out_of_order_bootstrap",
            Self::EffectsPayloadMismatch => "effects_payload_mismatch",
            Self::PlaneCrossWrite => "plane_cross_write",
        }
    }
}

impl std::fmt::Display for RealmBootstrapValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for RealmBootstrapValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRealmBootstrap {
    pub realm_id: String,
    pub actor_id: String,
}

/// Validate the complete ordinary (non-PCR) Realm genesis transaction.
///
/// Envelope schema/proof validation remains the caller's responsibility. This
/// function owns the cross-Event shape and genesis-authority invariants.
pub fn validate_realm_bootstrap_unit(
    events: &[Event],
) -> Result<ValidatedRealmBootstrap, RealmBootstrapValidationError> {
    let Some(create) = events.first() else {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    };
    if create.kind.as_str() != EventKind::REALM_CREATE {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    // PCR bootstrap is a distinct, exactly-two-Event protocol unit.
    if events
        .get(1)
        .is_some_and(|event| event.kind.as_str() == EventKind::DEVICE_AUTHORIZE)
    {
        return Err(RealmBootstrapValidationError::NotOrdinaryRealmBootstrap);
    }
    let actor_id = create.actor_id.as_str();
    let realm_id = create.realm_id.as_str();
    if create
        .payload
        .get("object")
        .and_then(|object| object.get("created_by"))
        .and_then(serde_json::Value::as_str)
        != Some(actor_id)
    {
        return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
    }
    let Some(founding) = events.get(1) else {
        return Err(RealmBootstrapValidationError::RealmFoundingGrantMissing);
    };
    if founding.kind.as_str() != EventKind::CAPABILITY_GRANT {
        return Err(RealmBootstrapValidationError::RealmFoundingGrantMissing);
    }
    if founding.actor_id.as_str() != actor_id || founding.realm_id.as_str() != realm_id {
        return Err(RealmBootstrapValidationError::InvalidRealmFoundingGrant);
    }
    validate_founding_grant_payload(&founding.payload, realm_id, actor_id)?;

    for followup in &events[2..] {
        if followup.actor_id.as_str() != actor_id
            || followup.realm_id.as_str() != realm_id
            || !is_realm_bootstrap_followup_kind(followup.kind.as_str())
        {
            return Err(RealmBootstrapValidationError::OutOfOrderBootstrap);
        }
        let descriptor = followup.kind.descriptor();
        if descriptor.is_some_and(|descriptor| {
            descriptor.reducer_input && descriptor.lattice == Some("cas_register")
        }) {
            arkret_schema::validate_single_target_set_event_contract_in_context(
                followup,
                arkret_schema::EventCellContractContext::OrdinaryRealmBootstrap,
            )
            .map_err(|error| match error.reason_code() {
                "plane_cross_write" => RealmBootstrapValidationError::PlaneCrossWrite,
                _ => RealmBootstrapValidationError::EffectsPayloadMismatch,
            })?;
        }
    }
    Ok(ValidatedRealmBootstrap {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
    })
}

fn validate_founding_grant_payload(
    object: &std::collections::BTreeMap<String, serde_json::Value>,
    realm_id: &str,
    actor_id: &str,
) -> Result<(), RealmBootstrapValidationError> {
    let invalid = RealmBootstrapValidationError::InvalidRealmFoundingGrant;
    if object.keys().any(|key| key != "grant_id" && key != "grant") {
        return Err(invalid);
    }
    let grant_id = object
        .get("grant_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("ak:grant:"))
        .ok_or(invalid)?;
    let grant = object
        .get("grant")
        .and_then(serde_json::Value::as_object)
        .ok_or(invalid)?;
    const ALLOWED_GRANT_FIELDS: &[&str] = &[
        "id",
        "schema",
        "realm_id",
        "issuer",
        "subject",
        "actions",
        "resources",
        "capability_action_registry_digest",
        "issued_at",
        "proofs",
    ];
    if grant
        .keys()
        .any(|key| !ALLOWED_GRANT_FIELDS.contains(&key.as_str()))
        || grant.get("id").and_then(serde_json::Value::as_str) != Some(grant_id)
        || grant.get("schema").and_then(serde_json::Value::as_str)
            != Some("ak.schema.capability.v1")
        || grant.get("realm_id").and_then(serde_json::Value::as_str) != Some(realm_id)
        || grant.get("issuer").and_then(serde_json::Value::as_str) != Some(actor_id)
        || grant.get("subject").and_then(serde_json::Value::as_str) != Some(actor_id)
    {
        return Err(invalid);
    }
    let actions = grant
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or(invalid)?;
    let actual_actions = actions
        .iter()
        .map(|action| action.as_str().ok_or(invalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_actions = REALM_FOUNDING_GRANT_ACTIONS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_actions != expected_actions || actions.len() != expected_actions.len() {
        return Err(invalid);
    }
    let registry_digest = grant
        .get("capability_action_registry_digest")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| arkret_wire::Hash::new(value.to_owned()).ok())
        .ok_or(invalid)?;
    let expected_registry_digest =
        crate::current_capability_action_registry_digest().map_err(|_| invalid)?;
    if registry_digest != expected_registry_digest {
        return Err(invalid);
    }
    let resources = grant
        .get("resources")
        .and_then(serde_json::Value::as_array)
        .filter(|resources| resources.len() == 1)
        .ok_or(invalid)?;
    let resource = resources[0].as_object().ok_or(invalid)?;
    if resource.len() != 3
        || resource.get("kind").and_then(serde_json::Value::as_str) != Some("realm")
        || resource.get("realm_id").and_then(serde_json::Value::as_str) != Some(realm_id)
        || resource
            .get("match_scope")
            .and_then(serde_json::Value::as_str)
            != Some("realm_wide")
    {
        return Err(invalid);
    }
    if !grant
        .get("issued_at")
        .is_some_and(serde_json::Value::is_string)
        || !grant.get("proofs").is_some_and(serde_json::Value::is_array)
    {
        return Err(invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, Hlc, RealmId};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:01964120-0000-7000-8000-000000000000";
    const ACTOR: &str = "did:web:founder.example";

    fn event(kind: &str, payload: serde_json::Value) -> Event {
        Event::new_at(
            kind,
            RealmId::new(REALM).unwrap(),
            Did::new(ACTOR).unwrap(),
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            payload,
            chrono::Utc::now(),
        )
        .unwrap()
    }

    fn create() -> Event {
        event(
            EventKind::REALM_CREATE,
            json!({"object": {"created_by": ACTOR}}),
        )
    }

    fn founding(subject: &str) -> Event {
        let registry_digest = crate::current_capability_action_registry_digest().unwrap();
        event(
            EventKind::CAPABILITY_GRANT,
            json!({
                "grant_id": "ak:grant:01964120-0000-7000-8000-000000000001",
                "grant": {
                    "id": "ak:grant:01964120-0000-7000-8000-000000000001",
                    "schema": "ak.schema.capability.v1",
                    "realm_id": REALM,
                    "issuer": ACTOR,
                    "subject": subject,
                    "actions": REALM_FOUNDING_GRANT_ACTIONS,
                    "capability_action_registry_digest": registry_digest,
                    "resources": [{
                        "kind": "realm",
                        "realm_id": REALM,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-20T00:00:00.000Z",
                    "proofs": []
                }
            }),
        )
    }

    fn history_sharing_followup() -> Event {
        let value = json!({"version": 1});
        let mut event = event(
            EventKind::REALM_HISTORY_SHARING_POLICY,
            json!({"value": value}),
        );
        event.effects = serde_json::from_value(json!([{
            "cell": "ak:cell:ak.component.realm.history_sharing_policy.v1:null",
            "op": {"kind": "set", "value": value}
        }]))
        .unwrap();
        event
    }

    #[test]
    fn accepts_closed_founding_grant_and_history_sharing_followup() {
        let events = vec![create(), founding(ACTOR), history_sharing_followup()];
        let result = validate_realm_bootstrap_unit(&events);
        assert!(result.is_ok(), "unexpected bootstrap rejection: {result:?}");
    }

    #[test]
    fn rejects_missing_founding_grant() {
        let events = vec![
            create(),
            event(
                EventKind::REALM_POLICY_COMPONENTS,
                json!({"value": {"policy_revision": 1}}),
            ),
        ];
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::RealmFoundingGrantMissing)
        );
    }

    #[test]
    fn rejects_widened_or_third_party_founding_grant() {
        let events = vec![create(), founding("did:web:other.example")];
        assert_eq!(
            validate_realm_bootstrap_unit(&events),
            Err(RealmBootstrapValidationError::InvalidRealmFoundingGrant)
        );
    }

    #[test]
    fn rejects_founding_grant_without_registry_basis() {
        let mut founding = founding(ACTOR);
        founding
            .payload
            .get_mut("grant")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("capability_action_registry_digest");
        assert_eq!(
            validate_realm_bootstrap_unit(&[create(), founding]),
            Err(RealmBootstrapValidationError::InvalidRealmFoundingGrant)
        );
    }

    #[test]
    fn rejects_founding_grant_with_unknown_registry_basis() {
        let mut founding = founding(ACTOR);
        founding
            .payload
            .get_mut("grant")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "capability_action_registry_digest".to_owned(),
                serde_json::json!(format!("sha256:{}", "0".repeat(64))),
            );
        assert_eq!(
            validate_realm_bootstrap_unit(&[create(), founding]),
            Err(RealmBootstrapValidationError::InvalidRealmFoundingGrant)
        );
    }
}
