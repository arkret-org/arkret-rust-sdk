use super::*;

/// Input for creating a relation operation.
#[derive(Clone, Debug)]
pub struct RelationOperationInput {
    pub relation_kind: RelationKind,
    pub from_ref: String,
    pub to_ref: String,
    pub fields: BTreeMap<String, Value>,
}

impl RelationOperationInput {
    pub fn new(
        relation_kind: RelationKind,
        from_ref: impl Into<String>,
        to_ref: impl Into<String>,
    ) -> Self {
        Self {
            relation_kind,
            from_ref: from_ref.into(),
            to_ref: to_ref.into(),
            fields: BTreeMap::new(),
        }
    }
}

/// Relation operations within a space.
impl Realm {
    /// Create a relation creation operation.
    pub fn create_relation_operation(&self, input: RelationOperationInput) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let relation_id = RelationId::new(generate_id("ck:relation:"))?;
        let operation_id = OperationId::new(generate_id("ck:operation:"))?;

        let mut relation = json!({
            "id": relation_id.as_str(),
            "schema": crate::RELATION_SCHEMA,
            "space_id": self.space_id.as_str(),
            "relation_kind": serde_json::to_value(input.relation_kind)?,
            "from_ref": input.from_ref,
            "to_ref": input.to_ref,
        });
        if !input.fields.is_empty() {
            relation["fields"] = json!(input.fields);
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            OP_RELATION_CREATE,
            json!({ "relation": relation }),
        ))
    }

    /// Create a relation delete operation.
    pub fn delete_relation_operation(&self, relation_id: RelationId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let payload = json!({ "relation_id": relation_id.as_str() });

        Ok(Operation::create(operation_id, self.realm_id()?, OP_RELATION_TOMBSTONE, payload))
    }
}
