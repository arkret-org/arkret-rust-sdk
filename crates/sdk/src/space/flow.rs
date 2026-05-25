use super::*;

/// Optional Flow create metadata accepted by [`Space::create_flow_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowCreateMetadata {
    pub body: Option<Value>,
    pub encrypted_payload: Option<Value>,
    pub tracks: BTreeMap<String, crate::FlowTrackConfig>,
    /// CXP-0007 — optional Circle that defines this Flow's encryption scope.
    pub scope_circle_id: Option<contrix_core::CircleId>,
}

/// Optional Flow patch metadata accepted by [`Space::update_flow_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowUpdateMetadata {
    pub body: Option<Value>,
    pub encrypted_payload: Option<Value>,
    pub tracks: Option<BTreeMap<String, crate::FlowTrackConfig>>,
}

impl Space {
    /// Create a spec-shaped `cx.flow.create` operation.
    pub fn create_flow_operation(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_flow_operation_with_metadata(
            title,
            summary,
            fields,
            FlowCreateMetadata::default(),
        )
    }

    /// Create a spec-shaped `cx.flow.create` operation with extended Flow fields.
    pub fn create_flow_operation_with_metadata(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
        metadata: FlowCreateMetadata,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let flow_id = FlowId::new(generate_id("cx:flow:"))?;
        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let now = Utc::now();
        let tracks =
            if metadata.tracks.is_empty() { default_flow_tracks() } else { metadata.tracks };

        let mut object = json!({
            "id": flow_id.as_str(),
            "schema": crate::FLOW_SCHEMA,
            "space_id": self.space_id.as_str(),
            "title": title.into(),
            "tracks": tracks,
            "created_by": session_meta.user_id.as_str(),
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });

        if let Some(summary) = summary {
            object["summary"] = json!(summary);
        }
        if let Some(body) = metadata.body {
            object["body"] = body;
        }
        if let Some(encrypted_payload) = metadata.encrypted_payload {
            object["encrypted_payload"] = encrypted_payload;
        }
        if let Some(scope_circle_id) = metadata.scope_circle_id {
            object["scope_circle_id"] = json!(scope_circle_id.as_str());
        }
        if !fields.is_empty() {
            object["fields"] = json!(fields);
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_FLOW_CREATE,
            json!({ "object": object }),
        ))
    }

    /// Create a spec-shaped `cx.flow.update` operation.
    pub fn update_flow_operation(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_flow_operation_with_metadata(
            flow_id,
            title,
            summary,
            fields,
            FlowUpdateMetadata::default(),
        )
    }

    /// Create a spec-shaped `cx.flow.update` operation with extended Flow fields.
    pub fn update_flow_operation_with_metadata(
        &self,
        flow_id: FlowId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
        metadata: FlowUpdateMetadata,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut patch = serde_json::Map::new();

        if let Some(title) = title {
            patch.insert("title".to_owned(), json!(title));
        }
        if let Some(summary) = summary {
            patch.insert("summary".to_owned(), json!(summary));
        }
        if let Some(fields) = fields {
            patch.insert("fields".to_owned(), json!(fields));
        }
        if let Some(body) = metadata.body {
            patch.insert("body".to_owned(), body);
            patch.insert("encrypted_payload".to_owned(), Value::Null);
        }
        if let Some(encrypted_payload) = metadata.encrypted_payload {
            patch.insert("encrypted_payload".to_owned(), encrypted_payload);
            patch.insert("body".to_owned(), Value::Null);
        }
        if let Some(tracks) = metadata.tracks {
            patch.insert("tracks".to_owned(), json!(tracks));
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_FLOW_UPDATE,
            json!({
                "flow_id": flow_id.as_str(),
                "patch": Value::Object(patch),
            }),
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a Flow archive operation.
    pub fn archive_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, crate::OP_FLOW_ARCHIVE, OperationType::Delete)
    }

    /// Create a Flow restore operation.
    pub fn restore_flow_operation(&self, flow_id: FlowId) -> Result<Operation> {
        self.flow_lifecycle_operation(flow_id, crate::OP_FLOW_RESTORE, OperationType::Update)
    }

    fn flow_lifecycle_operation(
        &self,
        flow_id: FlowId,
        kind: &str,
        operation_type: OperationType,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            kind,
            json!({ "flow_id": flow_id.as_str() }),
        );
        operation.operation_type = operation_type;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `cx.flow.move` operation.
    pub fn move_flow_operation(
        &self,
        flow_id: FlowId,
        board_place_id: SpaceId,
        target_place_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.flow_position_operation(
            crate::OP_FLOW_MOVE,
            flow_id,
            board_place_id,
            ("target_place_id", target_place_id),
            rank,
            expected_position,
        )
    }

    /// Create a `cx.flow.reorder` operation.
    pub fn reorder_flow_operation(
        &self,
        flow_id: FlowId,
        board_place_id: SpaceId,
        place_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.flow_position_operation(
            crate::OP_FLOW_REORDER,
            flow_id,
            board_place_id,
            ("place_id", place_id),
            rank,
            expected_position,
        )
    }

    fn flow_position_operation(
        &self,
        kind: &str,
        flow_id: FlowId,
        board_place_id: SpaceId,
        place_field: (&str, SpaceId),
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("cx:operation:"))?;
        let mut payload = json!({
            "flow_id": flow_id.as_str(),
            "board_place_id": board_place_id.as_str(),
            "rank": rank.into(),
        });
        payload[place_field.0] = json!(place_field.1.as_str());
        if let Some(expected_position) = expected_position {
            payload["expected_position"] = expected_position;
        }

        let mut operation = Operation::create(operation_id, self.realm_id()?, kind, payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(flow_id.as_str().to_owned());
        Ok(operation)
    }
}

fn default_flow_tracks() -> BTreeMap<String, crate::FlowTrackConfig> {
    let mut tracks = BTreeMap::new();
    tracks.insert(crate::FLOW_TRACK_NAME_SYNTHESIS.to_owned(), crate::FlowTrackConfig::synthesis());
    tracks
}
