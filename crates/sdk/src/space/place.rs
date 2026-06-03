use super::*;

/// Optional Place create metadata accepted by [`Space::create_place_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PlaceCreateMetadata {
    pub parent_space_id: Option<String>,
    pub summary: Option<String>,
    pub rank: Option<String>,
    pub schema_refs: Vec<String>,
    pub fields: BTreeMap<String, Value>,
    pub labels: Vec<String>,
}

/// Optional Place patch metadata accepted by [`Space::update_place_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PlaceUpdateMetadata {
    pub kind: Option<String>,
    pub summary: Option<String>,
    pub rank: Option<String>,
    pub schema_refs: Option<Vec<String>>,
    pub fields: Option<BTreeMap<String, Value>>,
    pub labels: Option<Vec<String>>,
}

impl Space {
    /// Create a spec-shaped `ck.space.create` operation.
    pub fn create_place_operation(
        &self,
        kind: impl Into<String>,
        title: impl Into<String>,
        parent_space_id: Option<String>,
        rank: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_place_operation_with_metadata(
            kind,
            title,
            PlaceCreateMetadata { parent_space_id, rank, fields, ..Default::default() },
        )
    }

    /// Create a spec-shaped `ck.space.create` operation with extended Place fields.
    pub fn create_place_operation_with_metadata(
        &self,
        kind: impl Into<String>,
        title: impl Into<String>,
        metadata: PlaceCreateMetadata,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let place_id = SpaceId::new(generate_id("ck:space:"))?;
        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let now = Utc::now();
        let mut object = json!({
            "id": place_id.as_str(),
            "schema": crate::SPACE_SCHEMA,
            "space_id": self.space_id.as_str(),
            "kind": kind.into(),
            "title": title.into(),
            "created_by": session_meta.user_id.as_str(),
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });

        if let Some(parent_space_id) = metadata.parent_space_id {
            object["parent_space_id"] = json!(parent_space_id);
        }
        if let Some(summary) = metadata.summary {
            object["summary"] = json!(summary);
        }
        if let Some(rank) = metadata.rank {
            object["rank"] = json!(rank);
        }
        if !metadata.schema_refs.is_empty() {
            object["schema_refs"] = json!(metadata.schema_refs);
        }
        if !metadata.fields.is_empty() {
            object["fields"] = json!(metadata.fields);
        }
        if !metadata.labels.is_empty() {
            object["labels"] = json!(metadata.labels);
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_SPACE_CREATE,
            json!({ "object": object }),
        );
        operation.object_id = Some(place_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a spec-shaped `ck.space.update` operation.
    pub fn update_place_operation(
        &self,
        place_id: SpaceId,
        title: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_place_operation_with_metadata(
            place_id,
            title,
            PlaceUpdateMetadata { fields, ..Default::default() },
        )
    }

    /// Create a spec-shaped `ck.space.update` operation with extended Place fields.
    pub fn update_place_operation_with_metadata(
        &self,
        place_id: SpaceId,
        title: Option<String>,
        metadata: PlaceUpdateMetadata,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut patch = serde_json::Map::new();
        if let Some(title) = title {
            patch.insert("title".to_owned(), json!(title));
        }
        if let Some(kind) = metadata.kind {
            patch.insert("kind".to_owned(), json!(kind));
        }
        if let Some(summary) = metadata.summary {
            patch.insert("summary".to_owned(), json!(summary));
        }
        if let Some(rank) = metadata.rank {
            patch.insert("rank".to_owned(), json!(rank));
        }
        if let Some(schema_refs) = metadata.schema_refs {
            patch.insert("schema_refs".to_owned(), json!(schema_refs));
        }
        if let Some(fields) = metadata.fields {
            patch.insert("fields".to_owned(), json!(fields));
        }
        if let Some(labels) = metadata.labels {
            patch.insert("labels".to_owned(), json!(labels));
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_SPACE_UPDATE,
            json!({
                "space_id": place_id.as_str(),
                "patch": Value::Object(patch),
            }),
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(place_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ck.space.parent` operation.
    pub fn set_place_parent_operation(
        &self,
        place_id: SpaceId,
        parent_space_id: impl Into<String>,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_SPACE_PARENT,
            json!({
                "space_id": place_id.as_str(),
                "parent_space_id": parent_space_id.into(),
            }),
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(place_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ck.space.archive` operation.
    pub fn archive_place_operation(&self, place_id: SpaceId) -> Result<Operation> {
        self.place_lifecycle_operation(place_id, crate::OP_SPACE_ARCHIVE, OperationType::Update)
    }

    /// Create a `ck.space.restore` operation (`archived -> active`).
    /// Reducer rejects with `place_not_archived` when current state is not archived.
    pub fn restore_place_operation(&self, place_id: SpaceId) -> Result<Operation> {
        self.place_lifecycle_operation(place_id, crate::OP_SPACE_RESTORE, OperationType::Update)
    }

    /// Create a `ck.space.tombstone` operation.
    pub fn tombstone_place_operation(&self, place_id: SpaceId) -> Result<Operation> {
        self.place_lifecycle_operation(place_id, crate::OP_SPACE_TOMBSTONE, OperationType::Delete)
    }

    fn place_lifecycle_operation(
        &self,
        place_id: SpaceId,
        kind: &str,
        operation_type: OperationType,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            kind,
            json!({ "space_id": place_id.as_str() }),
        );
        operation.operation_type = operation_type;
        operation.object_id = Some(place_id.as_str().to_owned());
        Ok(operation)
    }
}
