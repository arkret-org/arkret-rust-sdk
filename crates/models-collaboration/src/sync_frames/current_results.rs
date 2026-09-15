//! Server-adjudicated current values. No client lattice replay is involved.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use arkret_schema::ProtocolSchemaRegistry;
pub use arkret_schema::generated::current_result_schemas::MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES;
use arkret_wire::{
    ActorId, CellId, CellRef, EventId, RealmId, Result, ScopeRef, StrandId, WireError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ENTRY_SCHEMA: &str = "ak.internal.current_result_entry";
const COVERAGE_SCHEMA: &str = "ak.internal.current_result_coverage";
const CURRENT_SCHEMA_URL: &str = "https://arkret.org/v1/schemas/account-current-result.schema.json";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn error(message: impl Into<String>) -> WireError {
    WireError::Protocol(message.into())
}

struct CurrentRegistry {
    schemas: ProtocolSchemaRegistry,
    families: BTreeMap<String, CurrentFamilyDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CurrentFamilyDescriptor {
    pub cell_family: String,
    pub state_model: String,
    pub value_schema_ref: Option<String>,
    pub target_class: String,
    pub target_derivation: String,
    pub projection_omitted_fields: Vec<String>,
    pub result_projection: String,
    pub delivery: String,
    pub materialized_id_from_subject: bool,
    pub singleton: bool,
}

pub fn current_family_descriptor(family: &str) -> Result<Option<&'static CurrentFamilyDescriptor>> {
    Ok(current_registry()?.families.get(family))
}

pub fn current_family_descriptors() -> Result<impl Iterator<Item = &'static CurrentFamilyDescriptor>>
{
    Ok(current_registry()?.families.values())
}

fn registry() -> Result<&'static ProtocolSchemaRegistry> {
    Ok(&current_registry()?.schemas)
}

fn current_registry() -> Result<&'static CurrentRegistry> {
    static REGISTRY: OnceLock<std::result::Result<CurrentRegistry, String>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let bundle: Value = serde_json::from_str(
                arkret_schema::generated::current_result_schemas::CURRENT_RESULT_SCHEMA_BUNDLE,
            )
            .map_err(|e| e.to_string())?;
            let mut registry = ProtocolSchemaRegistry::new();
            for document in bundle["documents"]
                .as_array()
                .ok_or("Missing schema documents")?
            {
                registry
                    .register_reference_document(document.clone())
                    .map_err(|e| e.to_string())?;
                if document["$id"] == CURRENT_SCHEMA_URL {
                    registry
                        .register_fragment(ENTRY_SCHEMA, document.clone(), "#/$defs/entry")
                        .map_err(|e| e.to_string())?;
                    registry
                        .register_fragment(COVERAGE_SCHEMA, document.clone(), "#/$defs/coverage")
                        .map_err(|e| e.to_string())?;
                }
            }
            let families: Vec<CurrentFamilyDescriptor> =
                serde_json::from_value(bundle["families"].clone()).map_err(|e| e.to_string())?;
            Ok(CurrentRegistry {
                schemas: registry,
                families: families
                    .into_iter()
                    .map(|row| (row.cell_family.clone(), row))
                    .collect(),
            })
        })
        .as_ref()
        .map_err(|e| error(e.clone()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSelector {
    pub scope_ref: ScopeRef,
    pub cell_id: CellRef,
}

impl CurrentSelector {
    pub fn canonical_key(&self) -> Result<String> {
        String::from_utf8(arkret_canonical::canonical_json_bytes(self)?)
            .map_err(|e| error(e.to_string()))
    }

    pub fn family(&self) -> Result<String> {
        Ok(CellId::from_ref(&self.cell_id)?.component().to_owned())
    }

    pub fn validate_for_realm(&self, expected: &RealmId) -> Result<()> {
        match &self.scope_ref {
            ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. }
                if realm_id == expected =>
            {
                Ok(())
            }
            _ => Err(error("Current selector is outside its enclosing Realm")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentTarget {
    Realm,
    Strand { strand_id: StrandId },
    Member { actor_id: ActorId },
    Event { event_id: EventId },
}

/// A complete value validated against its exact registered cell family.
/// It cannot be constructed by deserializing an untyped JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentValue {
    family: String,
    value: Value,
}

impl Serialize for CurrentValue {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl CurrentValue {
    pub fn as_json(&self) -> &Value {
        &self.value
    }
    pub fn family(&self) -> &str {
        &self.family
    }

    fn decode<T: serde::de::DeserializeOwned>(&self, family: &str) -> Result<T> {
        if self.family != family {
            return Err(error("Current value accessor family mismatch"));
        }
        serde_json::from_value(self.value.clone()).map_err(|e| error(e.to_string()))
    }

    pub fn as_strand(&self) -> Result<crate::objects::strand::Strand> {
        self.decode("ak.component.strand.object.v1")
    }

    pub fn as_realm_genesis(&self) -> Result<crate::events_payloads::realm::RealmGenesis> {
        self.decode("ak.component.realm.genesis.v1")
    }

    /// Validate a non-causal value using the same entry boundary as a received result.
    /// Causal-register families must use [`Self::try_new_with_source`].
    pub fn try_new(
        selector: &CurrentSelector,
        target: &CurrentTarget,
        value: Value,
    ) -> Result<Self> {
        Self::try_new_with_source(selector, target, value, None)
    }

    /// Validate a value and its optional causal-register winner source using
    /// the same entry boundary as a received result.
    pub fn try_new_with_source(
        selector: &CurrentSelector,
        target: &CurrentTarget,
        value: Value,
        source: Option<CurrentValueSource>,
    ) -> Result<Self> {
        let mut result = serde_json::json!({"status":"value","value":value});
        if let Some(source) = source {
            result
                .as_object_mut()
                .expect("Current result literal is an object")
                .insert(
                    "source".to_owned(),
                    serde_json::to_value(source)
                        .map_err(|serde_error| error(serde_error.to_string()))?,
                );
        }
        let raw = serde_json::json!({"selector":selector,"target":target,"revision":0,
            "result":result});
        match CurrentResultEntry::try_from_json(raw)?.result {
            CurrentOutcome::Value { value, .. } => Ok(value),
            _ => Err(error("Current value requires a scalar result")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentValueSource {
    pub event_id: EventId,
    pub depth: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentUnavailableReason {
    DependencyMissing,
    LimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CurrentOutcome {
    Value {
        value: CurrentValue,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<CurrentValueSource>,
    },
    Removed,
    Unavailable {
        reason: CurrentUnavailableReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CurrentResultEntry {
    selector: CurrentSelector,
    target: CurrentTarget,
    revision: u64,
    result: CurrentOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    selector: CurrentSelector,
    target: CurrentTarget,
    revision: u64,
    result: ResultWire,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ResultWire {
    Value {
        value: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<CurrentValueSource>,
    },
    Removed,
    Unavailable {
        reason: CurrentUnavailableReason,
    },
}

impl<'de> Deserialize<'de> for CurrentResultEntry {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = EntryWire::deserialize(deserializer)?;
        Self::from_wire(raw).map_err(serde::de::Error::custom)
    }
}

impl CurrentResultEntry {
    pub fn selector(&self) -> &CurrentSelector {
        &self.selector
    }
    pub fn target(&self) -> &CurrentTarget {
        &self.target
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn result(&self) -> &CurrentOutcome {
        &self.result
    }

    pub fn try_from_json(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|e| error(e.to_string()))
    }

    pub fn try_new(
        selector: CurrentSelector,
        target: CurrentTarget,
        revision: u64,
        result: CurrentOutcome,
    ) -> Result<Self> {
        Self::try_from_json(
            serde_json::json!({"selector":selector,"target":target,"revision":revision,"result":result}),
        )
    }

    fn from_wire(raw: EntryWire) -> Result<Self> {
        let value = serde_json::json!({"selector":raw.selector,"target":raw.target,"revision":raw.revision,"result":raw.result});
        if arkret_canonical::canonical_json_bytes(&value)
            .map_err(|e| error(e.to_string()))?
            .len()
            > MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES
        {
            return Err(error(
                "current entry exceeds its fixed canonical byte limit",
            ));
        }
        registry()?
            .validate_value(ENTRY_SCHEMA, &value)
            .map_err(|e| error(e.to_string()))?;
        let family = raw.selector.family()?;
        validate_target_binding(&raw.selector, &raw.target, &family, &raw.result)?;
        let result = match raw.result {
            ResultWire::Value { value, source } => {
                let causal = current_family_descriptor(&family)?
                    .is_some_and(|descriptor| descriptor.state_model == "causal_register");
                // A confirmed empty value has no writing identity, so the
                // register-shaped baseline singleton publishes a null value with
                // no source. A written null still carries one, which is exactly
                // what keeps "written null" and "never written" distinguishable
                // on the wire.
                let source_required = causal && !value.is_null();
                if (source.is_some() && !causal) || (source.is_none() && source_required) {
                    return Err(error(
                        "only a written causal-register current value carries a source, and no other state model may carry one",
                    ));
                }
                if source
                    .as_ref()
                    .is_some_and(|source| source.depth > MAX_SAFE_INTEGER)
                {
                    return Err(error("Current source depth exceeds the safe integer range"));
                }
                CurrentOutcome::Value {
                    value: CurrentValue { family, value },
                    source,
                }
            }
            ResultWire::Removed => CurrentOutcome::Removed,
            ResultWire::Unavailable { reason } => CurrentOutcome::Unavailable { reason },
        };
        Ok(Self {
            selector: raw.selector,
            target: raw.target,
            revision: raw.revision,
            result,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentEntries {
    pub entries: Vec<CurrentResultEntry>,
}

impl CurrentEntries {
    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > 100 {
            return Err(error("Current entries exceed 100 items"));
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert(entry.selector.canonical_key()?) {
                return Err(error("Duplicate current selector in one frame"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentMemberCoverage {
    All,
    Selected { actor_ids: Vec<ActorId> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCoverage {
    pub realm: bool,
    pub strand_ids: Vec<StrandId>,
    pub members: CurrentMemberCoverage,
    pub event_ids: Vec<EventId>,
}

impl CurrentCoverage {
    pub fn validate(&self) -> Result<()> {
        registry()?
            .validate_value(COVERAGE_SCHEMA, &serde_json::to_value(self)?)
            .map_err(|e| error(e.to_string()))?;
        if self
            .strand_ids
            .windows(2)
            .any(|p| p[0].token_bytes() >= p[1].token_bytes())
            || self
                .event_ids
                .windows(2)
                .any(|p| p[0].token_bytes() >= p[1].token_bytes())
        {
            return Err(error(
                "Coverage identifiers must be sorted by decoded token",
            ));
        }
        if let CurrentMemberCoverage::Selected { actor_ids } = &self.members {
            let keys = actor_ids
                .iter()
                .map(arkret_canonical::canonical_json_bytes)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if keys.windows(2).any(|p| p[0] >= p[1]) {
                return Err(error("Coverage ActorIds must be sorted"));
            }
        }
        Ok(())
    }

    pub fn covers(&self, _selector: &CurrentSelector, target: &CurrentTarget) -> bool {
        match target {
            CurrentTarget::Realm => self.realm,
            CurrentTarget::Strand { strand_id } => self.strand_ids.contains(strand_id),
            CurrentTarget::Event { event_id } => self.event_ids.contains(event_id),
            CurrentTarget::Member { actor_id } => match &self.members {
                CurrentMemberCoverage::All => true,
                CurrentMemberCoverage::Selected { actor_ids } => actor_ids.contains(actor_id),
            },
        }
    }
}

pub(crate) fn validate_current_revision(revision: u64) -> Result<()> {
    if revision > MAX_SAFE_INTEGER {
        return Err(error("Current revision exceeds the safe integer range"));
    }
    Ok(())
}

fn validate_target_binding(
    selector: &CurrentSelector,
    target: &CurrentTarget,
    family: &str,
    result: &ResultWire,
) -> Result<()> {
    if family == "ak.component.mls.epoch.v1" {
        if let ResultWire::Value { value, .. } = result {
            if !value.is_null() {
                let head: arkret_models_crypto::MlsEpochHead =
                    serde_json::from_value(value.clone())?;
                head.validate()?;
                if head.effective_scope != selector.scope_ref {
                    return Err(error("MLS current head scope differs from selector"));
                }
            }
        }
    }
    let cell = CellId::from_ref(&selector.cell_id)?;
    // Tuple/hash subjects deliberately use the Station's accepted source index.
    if matches!(
        family,
        "ak.component.strand.object.v1"
            | "ak.component.strand.lifecycle.v1"
            | "ak.component.strand.stage.v1"
    ) {
        if !matches!(target, CurrentTarget::Strand { strand_id } if strand_id.as_str() == cell.subject())
        {
            return Err(error(
                "Current Strand target does not match the cell subject",
            ));
        }
    }
    if family == "ak.component.strand.position.v1" {
        let matches_position_subject = match target {
            CurrentTarget::Strand { strand_id } => cell
                .strand_position_target()
                .is_ok_and(|subject_strand| subject_strand == *strand_id),
            _ => false,
        };
        if !matches_position_subject {
            return Err(error(
                "Current Strand target does not match the position cell subject",
            ));
        }
    }
    if family == "ak.component.strand.object.v1" {
        if let ResultWire::Value { value, .. } = result {
            let CurrentTarget::Strand { strand_id } = target else {
                return Err(error("Strand value target mismatch"));
            };
            if value["id"].as_str() != Some(strand_id.as_str()) {
                return Err(error("Strand value id differs from target"));
            }
            match &selector.scope_ref {
                ScopeRef::Realm { realm_id }
                    if value["realm_id"].as_str() == Some(realm_id.as_str())
                        && value.get("scope_circle_id").is_none() => {}
                ScopeRef::Circle {
                    realm_id,
                    circle_id,
                } if value["realm_id"].as_str() == Some(realm_id.as_str())
                    && value["scope_circle_id"].as_str() == Some(circle_id.as_str()) => {}
                _ => return Err(error("Strand value scope differs from selector")),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    const STRAND_ENTRY: &str = r####"{"selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD"},"cell_id":"ak:cell:ak.component.strand.object.v1:ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS"},"target":{"kind":"strand","strand_id":"ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS"},"revision":8,"result":{"status":"value","value":{"id":"ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS","schema":"ak.schema.strand.v1","realm_id":"ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD","schema_refs":["ak.schema.calendar_event.v1"],"metadata":{"title":"Weekly sync","fields":{"calendar":{"start":"2026-06-22T09:00:00","end":"2026-06-22T10:00:00","timezone":"America/Los_Angeles","tzdb_version":"2025a","all_day":false,"status":"confirmed"}}},"tracks":{"synthesis":{"enabled":true,"is_primary":true}},"created_by":{"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:webvh:z6mkfixturestationexample"}},"created_at":"2026-06-01T00:00:00.000Z"},"source":{"event_id":"ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml","depth":4}}}"####;

    #[test]
    fn atomic_entry_budget_is_checked_before_family_schema_validation() {
        assert_eq!(MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES, 7_340_032);
        let oversized = scalar(Value::String(
            "x".repeat(MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES),
        ));
        let error = CurrentResultEntry::try_from_json(oversized).unwrap_err();
        assert!(error.to_string().contains("fixed canonical byte limit"));
    }

    fn scalar(value: Value) -> Value {
        json!({"selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},"cell_id":"ak:cell:ak.component.realm.freeze.v1:null"},"target":{"kind":"realm"},"revision":7,"result":{"status":"value","value":value}})
    }

    #[test]
    fn exact_family_values_accept_initial_null_and_reject_arbitrary_json() {
        for value in [json!(false), Value::Null] {
            let entry = CurrentResultEntry::try_from_json(scalar(value)).unwrap();
            assert_eq!(entry.revision(), 7);
        }
        assert!(CurrentResultEntry::try_from_json(scalar(json!({"arbitrary":"json"}))).is_err());
        let mut wrong = scalar(json!(false));
        wrong["target"] = json!({"kind":"member","actor_id":{"unexpected":true}});
        assert!(CurrentResultEntry::try_from_json(wrong).is_err());
    }

    #[test]
    fn materialized_causal_value_validates_source_target_scope_and_complete_value() {
        let wire: Value = serde_json::from_str(STRAND_ENTRY).unwrap();
        let entry = CurrentResultEntry::try_from_json(wire.clone()).unwrap();
        let CurrentOutcome::Value { value, source } = entry.result() else {
            panic!("expected value");
        };
        assert_eq!(source.as_ref().unwrap().depth, 4);
        assert!(value.as_strand().unwrap().id.is_some());
        assert!(value.as_realm_genesis().is_err());
        let mut patch = wire.clone();
        patch["result"]["value"] = json!({"patch":{}});
        assert!(CurrentResultEntry::try_from_json(patch).is_err());
        let mut missing_source = wire.clone();
        missing_source["result"]
            .as_object_mut()
            .unwrap()
            .remove("source");
        assert!(CurrentResultEntry::try_from_json(missing_source).is_err());
        let mut wrong = wire;
        wrong["selector"]["cell_id"] = json!(
            "ak:cell:ak.component.strand.object.v1:ak:strand:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"
        );
        assert!(CurrentResultEntry::try_from_json(wrong).is_err());
    }

    #[test]
    fn causal_current_value_constructor_requires_and_preserves_winner_source() {
        let wire: Value = serde_json::from_str(STRAND_ENTRY).unwrap();
        let selector: CurrentSelector = serde_json::from_value(wire["selector"].clone()).unwrap();
        let target: CurrentTarget = serde_json::from_value(wire["target"].clone()).unwrap();
        let value = wire["result"]["value"].clone();
        let source: CurrentValueSource =
            serde_json::from_value(wire["result"]["source"].clone()).unwrap();

        assert!(CurrentValue::try_new(&selector, &target, value.clone()).is_err());
        let current =
            CurrentValue::try_new_with_source(&selector, &target, value, Some(source.clone()))
                .unwrap();
        assert_eq!(current.family(), "ak.component.strand.object.v1");

        let roundtrip = serde_json::json!({
            "selector": selector,
            "target": target,
            "revision": 0,
            "result": {"status":"value","value":current,"source":source}
        });
        assert!(CurrentResultEntry::try_from_json(roundtrip).is_ok());
    }

    #[test]
    fn strand_position_target_binds_to_typed_board_strand_pair() {
        let strand_id = "ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS";
        let mut wire = scalar(
            json!({"list_space_id":"ak:space:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS","rank":"U"}),
        );
        wire["selector"]["cell_id"] = json!(format!(
            "ak:cell:ak.component.strand.position.v1:ak:space:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI:{strand_id}"
        ));
        wire["target"] = json!({"kind":"strand","strand_id":strand_id});
        wire["result"]["source"] = json!({
            "event_id":"ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml",
            "depth":2
        });
        assert!(CurrentResultEntry::try_from_json(wire.clone()).is_ok());

        wire["target"]["strand_id"] =
            json!("ak:strand:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml");
        assert!(CurrentResultEntry::try_from_json(wire.clone()).is_err());

        wire["target"]["strand_id"] = json!(strand_id);
        wire["selector"]["cell_id"] = json!(format!(
            "ak:cell:ak.component.strand.position.v1:ak:space:bad:{strand_id}"
        ));
        assert!(CurrentResultEntry::try_from_json(wire).is_err());
    }

    #[test]
    fn genesis_epoch_is_zero_zero_and_successors_are_exact() {
        let mut wire = scalar(json!(false));
        wire["selector"]["cell_id"] = json!("ak:cell:ak.component.mls.epoch.v1:null");
        let scope: ScopeRef =
            serde_json::from_value(wire["selector"]["scope_ref"].clone()).unwrap();
        let source = EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
        for (previous, next, valid) in [(0, 0, true), (0, 1, true), (7, 7, false), (7, 3, false)] {
            wire["result"] = json!({"status":"value","value":{
                "transition_ref":source,"transition_event_digest":source.event_digest(),
                "mls_transition_digest":source.event_digest(),"effective_scope":scope,
                "mls_group_id":scope.canonical_mls_group_id().unwrap(),
                "previous_epoch":previous,"next_epoch":next,"content_scheme":"mls_rfc9420"
            }});
            assert_eq!(
                CurrentResultEntry::try_from_json(wire.clone()).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn stable_failure_and_special_channel_are_closed() {
        let mut wire = scalar(json!(false));
        wire["result"] = json!({"status":"unavailable","reason":"temporarily_unavailable"});
        assert!(CurrentResultEntry::try_from_json(wire.clone()).is_err());
        wire["result"] = json!({"status":"unavailable","reason":"dependency_missing"});
        assert!(CurrentResultEntry::try_from_json(wire).is_ok());
        let mut notifications = scalar(json!([]));
        notifications["selector"]["cell_id"] =
            json!("ak:cell:ak.component.device.list_update.v1:null");
        assert!(CurrentResultEntry::try_from_json(notifications).is_err());
    }

    #[test]
    fn one_frame_cannot_repeat_a_selector_and_baseline_is_explicit() {
        for family in [
            "ak.component.realm.genesis.v1",
            "ak.component.realm.policy.v1",
            "ak.component.realm.policy_bundle.v1",
            "ak.component.realm.set_default_strand.v1",
        ] {
            assert!(
                current_family_descriptor(family)
                    .unwrap()
                    .unwrap()
                    .singleton
            );
        }
        assert!(
            !current_family_descriptor("ak.component.strand.object.v1")
                .unwrap()
                .unwrap()
                .singleton
        );
        let entry = CurrentResultEntry::try_from_json(scalar(json!(false))).unwrap();
        assert!(
            CurrentEntries {
                entries: vec![entry.clone(), entry]
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_value::<super::super::account_sync::RealmSyncEntry>(
                json!({"state":{"events":[]}})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<super::super::demand_sync::RealmDetailBaseline>(
                json!({"snapshot_cursor":"ak:cursor:abc","complete":true})
            )
            .is_err()
        );
        let registry = current_registry().unwrap();
        assert_eq!(registry.families.len(), 108);
        assert_eq!(
            current_family_descriptor("ak.component.device.list_update.v1")
                .unwrap()
                .unwrap()
                .delivery,
            "dedicated_channel"
        );
    }
}
