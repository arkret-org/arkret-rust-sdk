use super::*;

/// Optional flow metadata accepted by [`Space::create_flow_operation_with_metadata`].
///
/// All fields default to "unset" so callers can struct-update the variant
/// they need without naming the rest:
///
/// ```ignore
/// space.create_flow_operation_with_metadata(
///     "Refactor",
///     FlowKind::Discussion,
///     None,
///     None,
///     fields,
///     FlowCreateMetadata { semantic_kind: Some("work_item".into()), ..Default::default() },
/// )?;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowCreateMetadata {
    pub primary_track: Option<String>,
    pub tracks: Vec<String>,
    pub semantic_kind: Option<String>,
}

/// Optional flow metadata accepted by [`Space::update_flow_operation_with_metadata`].
///
/// Identical shape to [`FlowCreateMetadata`] but `tracks` is `Option`:
/// `None` means "leave unchanged", `Some(vec![])` means "clear tracks".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowUpdateMetadata {
    pub primary_track: Option<String>,
    pub tracks: Option<Vec<String>>,
    pub semantic_kind: Option<String>,
}

/// Flow operations within a space.
impl Space {
    /// Create a flow creation operation.
    pub fn create_flow_operation(
        &self,
        title: impl Into<String>,
        flow_kind: FlowKind,
        brief: Option<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_flow_operation_with_metadata(
            title,
            flow_kind,
            brief,
            summary,
            fields,
            FlowCreateMetadata::default(),
        )
    }

    /// Create a flow creation operation with flow metadata.
    pub fn create_flow_operation_with_metadata(
        &self,
        title: impl Into<String>,
        flow_kind: FlowKind,
        brief: Option<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
        metadata: FlowCreateMetadata,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let flow_id = FlowId::new(generate_id("cx:flow:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;

        let mut payload = json!({
            "flow_id": flow_id.as_str(),
            "title": title.into(),
            "flow_kind": serde_json::to_value(flow_kind)?,
        });

        if let Some(brief) = brief {
            payload["brief"] = json!(brief);
        }
        if let Some(summary) = summary {
            payload["summary"] = json!(summary);
        }
        if let Some(primary_track) = metadata.primary_track {
            payload["primary_track"] = json!(primary_track);
        }
        if !metadata.tracks.is_empty() {
            payload["tracks"] = json!(metadata.tracks);
        }
        if let Some(semantic_kind) = metadata.semantic_kind {
            payload["semantic_kind"] = json!(semantic_kind);
        }
        if !fields.is_empty() {
            payload["fields"] = json!(fields);
        }

        Ok(Operation::create(operation_id, self.space_id.clone(), "flow", payload))
    }

    /// Create a flow update operation.
    pub fn update_flow_operation(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        brief: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_flow_operation_with_metadata(
            flow_id,
            title,
            brief,
            summary,
            fields,
            FlowUpdateMetadata::default(),
        )
    }

    /// Create a flow update operation with extended metadata.
    pub fn update_flow_operation_with_metadata(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        brief: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
        metadata: FlowUpdateMetadata,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({ "flow_id": flow_id.as_str() });

        if let Some(title) = title {
            payload["title"] = json!(title);
        }
        if let Some(brief) = brief {
            payload["brief"] = json!(brief);
        }
        if let Some(summary) = summary {
            payload["summary"] = json!(summary);
        }
        if let Some(primary_track) = metadata.primary_track {
            payload["primary_track"] = json!(primary_track);
        }
        if let Some(tracks) = metadata.tracks {
            payload["tracks"] = json!(tracks);
        }
        if let Some(semantic_kind) = metadata.semantic_kind {
            payload["semantic_kind"] = json!(semantic_kind);
        }
        if let Some(fields) = fields {
            payload["fields"] = json!(fields);
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a flow archive operation.
    pub fn archive_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, OperationType::Delete, "archived")
    }

    /// Create a flow restore operation.
    pub fn restore_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, OperationType::Update, "active")
    }

    fn flow_lifecycle_operation(
        &self,
        flow_id: FlowId,
        operation_type: OperationType,
        state: &str,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.space_id.clone(),
            "flow",
            json!({
                "flow_id": flow_id.as_str(),
                "state": state,
            }),
        );
        operation.operation_type = operation_type;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create an operation linking a flow to a surface object.
    pub fn link_flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: impl Into<String>,
        surface_role: Option<String>,
        primary: bool,
    ) -> Result<Operation> {
        self.flow_surface_operation(
            flow_id,
            surface_ref.into(),
            surface_role,
            primary,
            OperationType::Link,
        )
    }

    /// Create an operation unlinking a flow surface object.
    pub fn unlink_flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: impl Into<String>,
        surface_role: Option<String>,
    ) -> Result<Operation> {
        self.flow_surface_operation(
            flow_id,
            surface_ref.into(),
            surface_role,
            false,
            OperationType::Unlink,
        )
    }

    fn flow_surface_operation(
        &self,
        flow_id: FlowId,
        surface_ref: String,
        surface_role: Option<String>,
        primary: bool,
        operation_type: OperationType,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "flow_id": flow_id.as_str(),
            "surface_ref": surface_ref,
        });
        if let Some(surface_role) = surface_role {
            payload["surface_role"] = json!(surface_role);
        }
        if operation_type == OperationType::Link {
            payload["primary"] = json!(primary);
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = operation_type;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a flow move operation.
    pub fn move_flow_operation(
        &self,
        flow_id: FlowId,
        parent_id: FlowId,
        rank: i64,
    ) -> Result<Operation> {
        self.flow_mutation_operation(
            flow_id,
            json!({
                "parent_id": parent_id,
                "rank": rank,
            }),
        )
    }

    /// Create a flow reorder operation.
    pub fn reorder_flow_operation(&self, flow_id: FlowId, rank: i64) -> Result<Operation> {
        self.flow_mutation_operation(flow_id, json!({ "rank": rank }))
    }

    /// Create a flow convert operation.
    pub fn convert_flow_operation(
        &self,
        flow_id: FlowId,
        target_kind: String,
    ) -> Result<Operation> {
        self.flow_mutation_operation(flow_id, json!({ "target_kind": target_kind }))
    }

    fn flow_mutation_operation(
        &self,
        flow_id: FlowId,
        additional_payload: Value,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({ "flow_id": flow_id.as_str() });
        if let Value::Object(map) = additional_payload {
            for (key, value) in map {
                payload[key] = value;
            }
        }

        let mut operation = Operation::create(operation_id, self.space_id.clone(), "flow", payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }
}
