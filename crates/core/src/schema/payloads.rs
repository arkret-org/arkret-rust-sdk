use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadSchemaRule {
    pub event_kind: String,
    pub payload_schema_id: String,
    pub required_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadValidatorCatalog {
    pub rules: BTreeMap<String, EventPayloadSchemaRule>,
}

impl EventPayloadValidatorCatalog {
    pub fn validate_payload(&self, event_kind: &str, payload: &Value) -> Result<()> {
        let Some(rule) = self.rules.get(event_kind) else {
            return Ok(());
        };
        let object = payload.as_object().ok_or_else(|| {
            Error::Protocol(format!("event kind '{event_kind}' payload must be a JSON object"))
        })?;
        for field in &rule.required_fields {
            if !object.contains_key(field) {
                return Err(Error::Protocol(format!(
                    "event kind '{event_kind}' payload requires field '{field}'"
                )));
            }
        }
        Ok(())
    }
}

pub fn event_payload_validator_catalog() -> EventPayloadValidatorCatalog {
    let rules = [
        ("cx.flow.create", FLOW_SCHEMA, &["object"][..]),
        ("cx.flow.update", FLOW_SCHEMA, &["patch"][..]),
        (
            "cx.flow.move",
            FLOW_SCHEMA,
            &["board_place_id", "flow_id", "target_place_id", "rank"][..],
        ),
        ("cx.flow.reorder", FLOW_SCHEMA, &["board_place_id", "flow_id", "place_id", "rank"][..]),
        ("cx.message.create", EVENT_SCHEMA, &["flow_id", "track"][..]),
        ("cx.member.state", EVENT_SCHEMA, &["membership"][..]),
        (
            "cx.capability.grant",
            CAPABILITY_SCHEMA,
            &["grant_id", "subject", "actions", "resources"][..],
        ),
    ]
    .into_iter()
    .map(|(event_kind, payload_schema_id, required_fields)| {
        (
            event_kind.to_owned(),
            EventPayloadSchemaRule {
                event_kind: event_kind.to_owned(),
                payload_schema_id: payload_schema_id.to_owned(),
                required_fields: required_fields.iter().map(|field| (*field).to_owned()).collect(),
            },
        )
    })
    .collect();
    EventPayloadValidatorCatalog { rules }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaBreakingChange {
    RemovedSchema,
    NewRequiredField,
    TypeNarrowed,
    AdditionalPropertiesClosed,
    SecurityExtensionTrustWidened,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEvolutionPlan {
    pub from_version: String,
    pub to_version: String,
    pub affected_schemas: Vec<String>,
    pub breaking_changes: BTreeSet<SchemaBreakingChange>,
}

impl SchemaEvolutionPlan {
    pub fn validate_release_candidate(&self) -> Result<()> {
        if self.from_version.trim().is_empty() || self.to_version.trim().is_empty() {
            return Err(Error::Protocol("schema evolution versions must be present".to_owned()));
        }
        if self.affected_schemas.is_empty() {
            return Err(Error::Protocol("schema evolution must name affected schemas".to_owned()));
        }
        if !self.breaking_changes.is_empty() {
            return Err(Error::Protocol(format!(
                "schema evolution contains breaking changes: {:?}",
                self.breaking_changes
            )));
        }
        Ok(())
    }
}

pub fn generated_validators() -> Result<BTreeMap<String, GeneratedSchemaValidator>> {
    let registry = schema_registry_from_default_spec_artifacts()?
        .unwrap_or_else(ProtocolSchemaRegistry::default);
    registry
        .schema_ids()
        .map(|schema_id| Ok((schema_id.to_owned(), registry.generated_validator(schema_id)?)))
        .collect()
}
