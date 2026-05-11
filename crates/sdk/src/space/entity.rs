use super::*;

/// Legacy subject compatibility operations within a space.
/// Entity operations within a space.
impl Space {
    /// Create an entity creation operation.
    pub fn create_entity_operation(
        &self,
        entity_type: EntityType,
        title: Option<String>,
        content: Option<Value>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let entity_id = EntityId::new(generate_id("cx:entity:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": entity_id.as_str(),
            "entity_type": serde_json::to_value(entity_type)?,
        });

        if let Some(title) = &title {
            payload["title"] = json!(title);
        }
        if let Some(content) = &content {
            payload["content"] = content.clone();
        }
        if !fields.is_empty() {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.create", payload))
    }

    /// Create an entity update operation.
    pub fn update_entity_operation(
        &self,
        entity_id: EntityId,
        title: Option<String>,
        content: Option<Value>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "id": entity_id.as_str(),
        });

        if let Some(title) = &title {
            payload["title"] = json!(title);
        }
        if let Some(content) = &content {
            payload["content"] = content.clone();
        }
        if let Some(fields) = &fields {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.update", payload))
    }

    /// Create an entity delete operation.
    pub fn delete_entity_operation(&self, entity_id: EntityId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let payload = json!({
            "id": entity_id.as_str(),
        });

        Ok(Operation::create(operation_id, self.space_id.clone(), "entity.delete", payload))
    }
}
