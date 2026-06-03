use super::*;

/// Morph operations within a space.
impl Space {
    /// Create a Morph creation operation.
    pub fn create_morph_operation(
        &self,
        morph_type: impl Into<String>,
        title: Option<String>,
        summary: Option<String>,
        content: Option<Value>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let morph_id = MorphId::new(generate_id("ck:morph:"))?;
        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let now = Utc::now();

        let mut metadata = serde_json::Map::new();
        if let Some(title) = title {
            metadata.insert("title".to_owned(), json!(title));
        }
        if let Some(summary) = summary {
            metadata.insert("summary".to_owned(), json!(summary));
        }

        let mut object = json!({
            "id": morph_id.as_str(),
            "schema": crate::MORPH_SCHEMA,
            "space_id": self.space_id.as_str(),
            "morph_type": morph_type.into(),
            "created_by": session_meta.user_id.as_str(),
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "fields": fields,
        });

        if !metadata.is_empty() {
            object["metadata"] = Value::Object(metadata);
        }
        if let Some(content) = content {
            object["content"] = content;
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            OP_MORPH_CREATE,
            json!({ "object": object }),
        ))
    }

    /// Create a Morph update operation.
    pub fn update_morph_operation(
        &self,
        morph_id: MorphId,
        title: Option<String>,
        summary: Option<String>,
        content: Option<Value>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut patch = serde_json::Map::new();

        if let Some(title) = title {
            patch.insert("metadata.title".to_owned(), json!(title));
        }
        if let Some(summary) = summary {
            patch.insert("metadata.summary".to_owned(), json!(summary));
        }
        if let Some(content) = content {
            patch.insert("content".to_owned(), content);
        }
        if let Some(fields) = fields {
            patch.insert("fields".to_owned(), json!(fields));
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            OP_MORPH_UPDATE,
            json!({
                "morph_id": morph_id.as_str(),
                "patch": Value::Object(patch),
            }),
        ))
    }

    /// Create a Morph archive operation.
    pub fn archive_morph_operation(&self, morph_id: MorphId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            OP_MORPH_ARCHIVE,
            json!({ "morph_id": morph_id.as_str() }),
        ))
    }
}
