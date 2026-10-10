//! Frozen accepted installation dependencies for ordinary Applet admission.

use arkret_wire::{Event, EventKind, Hash, Result, WireError, canonical};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::exact_current_results::ExactCurrentResultsReadOutcome;

/// The formal Applet committed Event carrier. The retained account-device root
/// is the regular closed two-member sibling, not authority-forward evidence.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq)]
pub struct AppletCommittedEvent {
    pub commit: arkret_wire::RealmCommit,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
    pub producer_device_evidence: Option<arkret_models_identity::AccountDeviceSignerEvidence>,
}

/// Exact decoder for `applet-edge-operations.schema.json#/$defs/applet_committed_event`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppletCommittedEventCarrier {
    commit: arkret_wire::RealmCommit,
    event: Event,
    #[serde(default, deserialize_with = "deserialize_device_evidence")]
    producer_device_evidence: Option<arkret_models_identity::AccountDeviceSignerEvidence>,
}

fn deserialize_device_evidence<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<arkret_models_identity::AccountDeviceSignerEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    arkret_models_identity::AccountDeviceSignerEvidence::deserialize(deserializer).map(Some)
}

impl AppletCommittedEvent {
    /// Check shape and immutable byte-local bindings. A consumer separately
    /// authenticates the original Event, covering Commit and method-native
    /// Station evidence at `commit.committed_at`, never its current read time.
    pub fn validate_structural(&self) -> Result<()> {
        arkret_wire::CommittedEventFullView {
            commit: self.commit.clone(),
            event: self.event.clone(),
        }
        .validate_shape()?;
        let producer = self.event.human_device_producer()?;
        match (producer, self.producer_device_evidence.as_ref()) {
            (Some(producer), Some(evidence)) => {
                if evidence.service_resolution.service_kind != "station" {
                    return Err(WireError::Protocol("Applet device evidence origin must be a Station".into()));
                }
                evidence.validate_binding(&producer.account_id, &producer.device_id)
            },
            (None, None) => Ok(()),
            _ => Err(WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::SchemaViolation,
                message: "Applet producer_device_evidence is required exactly for an Account Device producer".into(),
            }),
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.validate_structural()
    }
}

impl<'de> Deserialize<'de> for AppletCommittedEvent {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let carrier = AppletCommittedEventCarrier::deserialize(deserializer)?;
        let value = Self {
            commit: carrier.commit,
            event: carrier.event,
            producer_device_evidence: carrier.producer_device_evidence,
        };
        value
            .validate_structural()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl Serialize for AppletCommittedEvent {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate_structural()
            .map_err(serde::ser::Error::custom)?;
        let mut carrier = serializer.serialize_struct(
            "AppletCommittedEvent",
            if self.producer_device_evidence.is_some() {
                3
            } else {
                2
            },
        )?;
        carrier.serialize_field("commit", &self.commit)?;
        carrier.serialize_field("event", &self.event)?;
        if let Some(evidence) = &self.producer_device_evidence {
            carrier.serialize_field("producer_device_evidence", evidence)?;
        }
        carrier.end()
    }
}

/// The accepted administrator Events are the portable installation authority.
/// Their producer bytes remain unchanged from the signed authoring request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallationAuthority {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub capability_grant_event: Event,
}

impl AppletInstallationAuthority {
    pub fn canonical_sha256_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    /// Shape and content binding only; the consumer must authenticate both
    /// accepted Events before using the registration's Station as authority.
    pub fn validate_structural(&self) -> Result<()> {
        let registration = &self.registration_event;
        let grant = &self.capability_grant_event;
        if registration.kind != EventKind::AppletRegistration
            || grant.kind != EventKind::CapabilityGrant
            || registration.applet_id.is_some()
            || grant.applet_id.is_some()
            || registration.executed_by.is_some()
            || grant.executed_by.is_some()
            || registration.scope_ref != grant.scope_ref
            || registration.realm_id != grant.realm_id
            || registration.actor_id.route_service_id() != grant.actor_id.route_service_id()
        {
            return Err(WireError::Protocol(
                "Applet installation authority coordinates mismatch".to_owned(),
            ));
        }
        for event in [registration, grant] {
            let suite = event.event_id.event_digest().digest_suite()?;
            event.validate_for_accepted_structural()?;
            event.verify_event_id_matches_content_with_digest_suite(suite)?;
            event.validate_proof_bindings_with_digest_suite(suite)?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialRequestBody {
    pub effective_scope: arkret_wire::ScopeRef,
    pub grant_ids: Vec<arkret_wire::GrantId>,
}

impl AppletAuthorityMaterialRequestBody {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.effective_scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        ) || !(1..=64).contains(&self.grant_ids.len())
            || self
                .grant_ids
                .iter()
                .enumerate()
                .any(|(index, id)| self.grant_ids[..index].contains(id))
        {
            return Err(WireError::Protocol(
                "Applet authority material request requires a Realm/Circle scope and 1..64 unique grant IDs".into(),
            ));
        }
        Ok(())
    }
}
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletAuthorityMaterialOutcome {
    pub applet_id: arkret_wire::AppletId,
    pub effective_scope: arkret_wire::ScopeRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration: AppletCommittedEvent,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub grant_events: Vec<AppletCommittedEvent>,
    /// Present same-cut responses retain Realm, generation and covering head.
    /// The authority-material schema forbids absence and empty result arrays.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    #[serde(
        deserialize_with = "deserialize_present_current_results",
        serialize_with = "serialize_present_current_results"
    )]
    pub current_results: Vec<ExactCurrentResultsReadOutcome>,
}

impl AppletAuthorityMaterialOutcome {
    /// Schema shape only: accepted Event proofs and current cut authority must
    /// still be authenticated by the consumer before using these materials.
    pub fn validate_structural(&self) -> Result<()> {
        if !matches!(
            self.effective_scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        ) || self.grant_events.is_empty()
        {
            return Err(WireError::Protocol(
                "Applet authority material requires a Realm/Circle scope and grant Events".into(),
            ));
        }
        self.registration.validate_structural()?;
        for grant in &self.grant_events {
            grant.validate_structural()?;
        }
        validate_present_current_results_for_scope(&self.effective_scope, &self.current_results)
    }
}

fn validate_present_current_results_for_scope(
    scope: &arkret_wire::ScopeRef,
    results: &[ExactCurrentResultsReadOutcome],
) -> Result<()> {
    validate_present_current_results(results)?;
    let realm = scope
        .realm_id_opt()
        .ok_or_else(|| WireError::Protocol("Applet material scope has no Realm".into()))?;
    let mut generation = None;
    let grant_stream = arkret_wire::CommitStreamRef::from_scope(scope, None)?;
    let mut heads: Vec<&arkret_wire::CommitStreamHead> = Vec::new();
    for result in results {
        let ExactCurrentResultsReadOutcome::Present {
            realm_id,
            governance_generation,
            effective_stream_head,
            entry,
        } = result
        else {
            unreachable!("present results validated above")
        };
        if realm_id != realm
            || generation.is_some_and(|expected| expected != *governance_generation)
        {
            return Err(WireError::Protocol(
                "Applet material current results differ from the scope Realm or governing cut"
                    .into(),
            ));
        }
        generation = Some(*governance_generation);
        entry.validate_covering_head(realm, effective_stream_head)?;
        if heads.iter().any(|head| {
            head.stream_ref == effective_stream_head.stream_ref && *head != effective_stream_head
        }) {
            return Err(WireError::Protocol(
                "Applet material results use different heads for one source stream".into(),
            ));
        }
        heads.push(effective_stream_head);
        if let crate::exact_current_results::ExactCurrentResultEntry::CapabilityGrant(grant) = entry
            && (grant.value.id != grant.selector.grant_id
                || grant.value.realm_id.as_ref() != Some(realm)
                || grant.source_stream_ref != grant_stream)
        {
            return Err(WireError::Protocol(
                "Applet material grant selector, Realm or stream differs from its value or scope"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_present_current_results(results: &[ExactCurrentResultsReadOutcome]) -> Result<()> {
    if results.is_empty()
        || results
            .iter()
            .any(|result| !matches!(result, ExactCurrentResultsReadOutcome::Present { .. }))
    {
        return Err(WireError::Protocol(
            "Applet authority material requires nonempty present current results".into(),
        ));
    }
    Ok(())
}

fn deserialize_present_current_results<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ExactCurrentResultsReadOutcome>, D::Error>
where
    D: Deserializer<'de>,
{
    let results = Vec::<ExactCurrentResultsReadOutcome>::deserialize(deserializer)?;
    validate_present_current_results(&results).map_err(serde::de::Error::custom)?;
    Ok(results)
}

fn serialize_present_current_results<S>(
    results: &[ExactCurrentResultsReadOutcome],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    validate_present_current_results(results).map_err(serde::ser::Error::custom)?;
    results.serialize(serializer)
}

#[cfg(test)]
mod authority_material_current_tests {
    use serde_json::{Value, json};

    use super::*;

    fn formal_outcome(status: &str) -> Value {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("fixtures/exact-current-results-read-fixture.json"))
                .unwrap(),
        )
        .unwrap();
        fixture["valid_outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["value"]["status"] == status)
            .unwrap()["value"]
            .clone()
    }

    fn decode(
        value: &Value,
    ) -> std::result::Result<Vec<ExactCurrentResultsReadOutcome>, serde_json::Error> {
        let input = serde_json::to_string(value).unwrap();
        deserialize_present_current_results(&mut serde_json::Deserializer::from_str(&input))
    }

    #[test]
    fn present_current_material_preserves_the_formal_same_cut_envelope() {
        let value = json!([formal_outcome("present")]);
        let results = decode(&value).unwrap();
        assert!(matches!(
            results[0],
            ExactCurrentResultsReadOutcome::Present { .. }
        ));
        let mut bytes = Vec::new();
        serialize_present_current_results(&results, &mut serde_json::Serializer::new(&mut bytes))
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
    }

    #[test]
    fn absence_empty_and_missing_current_cut_are_rejected() {
        assert!(decode(&json!([])).is_err());
        assert!(decode(&json!([formal_outcome("never_written")])).is_err());
        let present = formal_outcome("present");
        // The previous DTO accepted this bare entry and discarded its cut.
        assert!(decode(&json!([present["entry"]])).is_err());
        for field in ["realm_id", "governance_generation", "effective_stream_head"] {
            let mut missing = present.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(decode(&json!([missing])).is_err(), "{field}");
        }
    }

    #[test]
    fn in_memory_absence_cannot_be_serialized_as_authority_material() {
        let absence: ExactCurrentResultsReadOutcome =
            serde_json::from_value(formal_outcome("never_written")).unwrap();
        let mut bytes = Vec::new();
        assert!(
            serialize_present_current_results(
                &[absence],
                &mut serde_json::Serializer::new(&mut bytes)
            )
            .is_err()
        );
    }

    #[test]
    fn request_limits_unique_ids_and_effective_scope() {
        let present = formal_outcome("present");
        let realm = serde_json::from_value(present["realm_id"].clone()).unwrap();
        let scope = arkret_wire::ScopeRef::Realm { realm_id: realm };
        let grant = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let mut request = AppletAuthorityMaterialRequestBody {
            effective_scope: scope,
            grant_ids: vec![grant.clone()],
        };
        request.validate().unwrap();
        request.grant_ids.clear();
        assert!(request.validate().is_err());
        request.grant_ids = vec![grant.clone(), grant];
        assert!(request.validate().is_err());
        request.grant_ids = (0..65)
            .map(|index| {
                arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [index; 32],
                ))
            })
            .collect();
        assert!(request.validate().is_err());
        request.grant_ids.pop();
        request.validate().unwrap();
        request.effective_scope = arkret_wire::ScopeRef::RealmGenesis;
        assert!(request.validate().is_err());
    }

    #[test]
    fn scope_and_current_cut_bindings_fail_closed() {
        let present = formal_outcome("present");
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: serde_json::from_value(present["realm_id"].clone()).unwrap(),
        };
        let results = decode(&json!([present])).unwrap();
        validate_present_current_results_for_scope(&scope, &results).unwrap();
        let mut other_cut = present.clone();
        other_cut["effective_stream_head"]["stream_position"] = json!(
            present["effective_stream_head"]["stream_position"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([present, other_cut])).unwrap()
            )
            .is_err()
        );
        let mut future = present.clone();
        future["entry"]["revision"]["stream_position"] = json!(
            future["effective_stream_head"]["stream_position"]
                .as_u64()
                .unwrap()
                + 1
        );
        assert!(
            validate_present_current_results_for_scope(&scope, &decode(&json!([future])).unwrap())
                .is_err()
        );
        let mut other_head = present.clone();
        other_head["effective_stream_head"]["stream_ref"]["realm_id"] =
            json!(arkret_wire::RealmId::from_event_id(
                &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32])
            ));
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([other_head])).unwrap()
            )
            .is_err()
        );
        let mut other_realm = present.clone();
        other_realm["realm_id"] = json!(arkret_wire::RealmId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32])
        ));
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([other_realm])).unwrap()
            )
            .is_err()
        );
        let mut other_generation = present.clone();
        other_generation["governance_generation"] =
            json!(present["governance_generation"].as_u64().unwrap() + 1);
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([present, other_generation])).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn grant_material_requires_the_exact_scope_stream_without_owned_agent_gate() {
        let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("fixtures/agent-participation-fixture.json")).unwrap(),
        )
        .unwrap();
        let payload: Value = serde_json::from_str(
            fixture["owned_agent_authority_contract"]["schema_cases"][0]["canonical_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut grant = payload["grant"].clone();
        let grant_id = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [81; 32],
        ));
        grant["id"] = json!(grant_id);
        grant["authority_depth"] = json!(0);
        grant["issuer_authority_refs"] = json!([{
            "kind":"realm_root", "realm_id":grant["realm_id"], "authority_generation":0,
            "authority_event_ref":arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [80; 32])
        }]);
        grant["authority_root_refs"] = grant["issuer_authority_refs"].clone();
        grant["subject"] = json!(arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:applet.example").unwrap()
        ));
        grant["status"] = json!("active");
        // This validator binds material coordinates, not the separate owned
        // Agent read authority. The accepted Service-parent reader authenticates
        // original roots and source Events independently.
        let realm: arkret_wire::RealmId =
            serde_json::from_value(grant["realm_id"].clone()).unwrap();
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let commit = arkret_wire::RealmCommitId::from_digest([82; 32]);
        let value = json!({
            "status":"present", "realm_id":realm, "governance_generation":0,
            "effective_stream_head":{"stream_ref":stream, "commit_id":commit,"stream_position":9},
            "entry":{"selector":{"kind":"capability_grant","grant_id":grant_id},
                "source_stream_ref":stream,"revision":{"commit_id":commit,"stream_position":9},"value":grant}
        });
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        validate_present_current_results_for_scope(&scope, &decode(&json!([value])).unwrap())
            .unwrap();
        let circle_scope = arkret_wire::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [83; 32],
            )),
        };
        assert!(
            validate_present_current_results_for_scope(
                &circle_scope,
                &decode(&json!([value])).unwrap()
            )
            .is_err()
        );
        let mut circle_value = value.clone();
        let circle_stream = arkret_wire::CommitStreamRef::from_scope(&circle_scope, None).unwrap();
        circle_value["entry"]["source_stream_ref"] = json!(circle_stream);
        circle_value["effective_stream_head"]["stream_ref"] = json!(circle_stream);
        validate_present_current_results_for_scope(
            &circle_scope,
            &decode(&json!([circle_value.clone()])).unwrap(),
        )
        .unwrap();
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([circle_value])).unwrap()
            )
            .is_err()
        );
        let mut wrong_id = value;
        wrong_id["entry"]["value"]["id"] = json!(arkret_wire::GrantId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [84; 32],)
        ));
        assert!(
            validate_present_current_results_for_scope(
                &scope,
                &decode(&json!([wrong_id])).unwrap()
            )
            .is_err()
        );
    }
}
