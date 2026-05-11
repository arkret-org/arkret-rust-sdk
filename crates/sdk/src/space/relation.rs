use super::*;

/// Input for creating a relation operation.
#[derive(Clone, Debug)]
pub struct RelationOperationInput {
    pub relation_kind: RelationKind,
    pub from_ref: Option<String>,
    pub to_ref: Option<String>,
    pub from_entity_id: Option<EntityId>,
    pub from_actor_id: Option<Did>,
    pub from_space_id: Option<SpaceId>,
    pub to_entity_id: Option<EntityId>,
    pub to_actor_id: Option<Did>,
    pub to_space_id: Option<SpaceId>,
    pub fields: BTreeMap<String, Value>,
}

impl RelationOperationInput {
    pub fn new(relation_kind: RelationKind) -> Self {
        Self {
            relation_kind,
            from_ref: None,
            to_ref: None,
            from_entity_id: None,
            from_actor_id: None,
            from_space_id: None,
            to_entity_id: None,
            to_actor_id: None,
            to_space_id: None,
            fields: BTreeMap::new(),
        }
    }
}

/// Relation operations within a space.
impl Space {
    /// Create a relation creation operation.
    pub fn create_relation_operation(&self, input: RelationOperationInput) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let relation_id = RelationId::new(generate_id("cx:relation:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": relation_id.as_str(),
            "relation_kind": serde_json::to_value(input.relation_kind)?,
        });

        if let Some(from_entity_id) = &input.from_entity_id {
            payload["from_entity_id"] = json!(from_entity_id.as_str());
        }
        if let Some(from_ref) = &input.from_ref {
            payload["from_ref"] = json!(from_ref);
        }
        if let Some(from_actor_id) = &input.from_actor_id {
            payload["from_actor_id"] = json!(from_actor_id.as_str());
        }
        if let Some(from_space_id) = &input.from_space_id {
            payload["from_space_id"] = json!(from_space_id.as_str());
        }
        if let Some(to_entity_id) = &input.to_entity_id {
            payload["to_entity_id"] = json!(to_entity_id.as_str());
        }
        if let Some(to_ref) = &input.to_ref {
            payload["to_ref"] = json!(to_ref);
        }
        if let Some(to_actor_id) = &input.to_actor_id {
            payload["to_actor_id"] = json!(to_actor_id.as_str());
        }
        if let Some(to_space_id) = &input.to_space_id {
            payload["to_space_id"] = json!(to_space_id.as_str());
        }
        if !input.fields.is_empty() {
            payload["fields"] = json!(input.fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "relation.create", payload))
    }

    /// Create a relation delete operation.
    pub fn delete_relation_operation(&self, relation_id: RelationId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "id": relation_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "relation.delete", payload))
    }
}
