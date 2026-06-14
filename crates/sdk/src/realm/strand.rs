use super::*;

/// Optional Strand create metadata accepted by [`Space::create_strand_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StrandCreateMetadata {
    pub content: Option<Value>,
    pub encrypted_content: Option<Value>,
    pub encrypted_metadata: Option<Value>,
    pub tracks: BTreeMap<String, crate::StrandTrackConfig>,
    /// CKP-0007 — optional Circle that defines this Strand's encryption scope.
    pub scope_circle_id: Option<cokret_core::CircleId>,
}

/// Optional Strand patch metadata accepted by [`Space::update_strand_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StrandUpdateMetadata {
    pub content: Option<Value>,
    pub encrypted_content: Option<Value>,
    pub encrypted_metadata: Option<Value>,
    pub tracks: Option<BTreeMap<String, crate::StrandTrackConfig>>,
}

impl Realm {
    /// Create a spec-shaped `ck.strand.create` operation.
    pub fn create_strand_operation(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_strand_operation_with_metadata(
            title,
            summary,
            fields,
            StrandCreateMetadata::default(),
        )
    }

    /// Create a spec-shaped `ck.strand.create` operation with extended Strand fields.
    pub fn create_strand_operation_with_metadata(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
        metadata: StrandCreateMetadata,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let strand_id = StrandId::new(generate_id("ck:strand:"))?;
        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let now = Utc::now();
        let tracks = if metadata.tracks.is_empty() {
            default_strand_tracks()
        } else {
            metadata.tracks
        };

        let mut strand_metadata = serde_json::Map::new();
        strand_metadata.insert("title".to_owned(), json!(title.into()));
        if let Some(summary) = summary {
            strand_metadata.insert("summary".to_owned(), json!(summary));
        }
        if !fields.is_empty() {
            strand_metadata.insert("fields".to_owned(), json!(fields));
        }

        let mut object = json!({
            "id": strand_id.as_str(),
            "schema": crate::STRAND_SCHEMA,
            "realm_id": self.realm_id.as_str(),
            "metadata": Value::Object(strand_metadata),
            "tracks": tracks,
            "created_by": session_meta.user_id.as_str(),
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });

        if let Some(content) = metadata.content {
            object["content"] = content;
        }
        if let Some(encrypted_content) = metadata.encrypted_content {
            object["encrypted_content"] = encrypted_content;
        }
        if let Some(encrypted_metadata) = metadata.encrypted_metadata {
            object["encrypted_metadata"] = encrypted_metadata;
        }
        if let Some(scope_circle_id) = metadata.scope_circle_id {
            object["scope_circle_id"] = json!(scope_circle_id.as_str());
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_STRAND_CREATE,
            json!({ "object": object }),
        ))
    }

    /// Create a spec-shaped `ck.strand.update` operation.
    pub fn update_strand_operation(
        &self,
        strand_id: StrandId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_strand_operation_with_metadata(
            strand_id,
            title,
            summary,
            fields,
            StrandUpdateMetadata::default(),
        )
    }

    /// Create a spec-shaped `ck.strand.update` operation with extended Strand fields.
    pub fn update_strand_operation_with_metadata(
        &self,
        strand_id: StrandId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
        metadata: StrandUpdateMetadata,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut patch = serde_json::Map::new();
        let mut metadata_patch = serde_json::Map::new();

        if let Some(title) = title {
            metadata_patch.insert("title".to_owned(), json!(title));
        }
        if let Some(summary) = summary {
            metadata_patch.insert("summary".to_owned(), json!(summary));
        }
        if let Some(fields) = fields {
            metadata_patch.insert("fields".to_owned(), json!(fields));
        }
        if !metadata_patch.is_empty() {
            patch.insert("metadata".to_owned(), Value::Object(metadata_patch));
        }
        if let Some(content) = metadata.content {
            patch.insert("content".to_owned(), content);
            patch.insert("encrypted_content".to_owned(), Value::Null);
        }
        if let Some(encrypted_content) = metadata.encrypted_content {
            patch.insert("encrypted_content".to_owned(), encrypted_content);
            patch.insert("content".to_owned(), Value::Null);
        }
        if let Some(encrypted_metadata) = metadata.encrypted_metadata {
            patch.insert("encrypted_metadata".to_owned(), encrypted_metadata);
            patch.insert("metadata".to_owned(), Value::Null);
        }
        if let Some(tracks) = metadata.tracks {
            patch.insert("tracks".to_owned(), json!(tracks));
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::OP_STRAND_UPDATE,
            json!({
                "target_ref": strand_id.as_str(),
                "patch": Value::Object(patch),
            }),
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a Strand archive operation.
    pub fn archive_strand_operation(&self, strand_id: StrandId) -> Result<Operation> {
        self.strand_lifecycle_operation(strand_id, crate::OP_STRAND_ARCHIVE, OperationType::Delete)
    }

    /// Create a Strand restore operation.
    pub fn restore_strand_operation(&self, strand_id: StrandId) -> Result<Operation> {
        self.strand_lifecycle_operation(strand_id, crate::OP_STRAND_RESTORE, OperationType::Update)
    }

    fn strand_lifecycle_operation(
        &self,
        strand_id: StrandId,
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
            json!({ "target_ref": strand_id.as_str() }),
        );
        operation.operation_type = operation_type;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ck.strand.move` operation.
    pub fn move_strand_operation(
        &self,
        strand_id: StrandId,
        board_space_id: SpaceId,
        target_space_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.strand_position_operation(
            crate::OP_STRAND_MOVE,
            strand_id,
            board_space_id,
            ("target_space_id", target_space_id),
            rank,
            expected_position,
        )
    }

    /// Create a `ck.strand.reorder` operation.
    pub fn reorder_strand_operation(
        &self,
        strand_id: StrandId,
        board_space_id: SpaceId,
        space_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.strand_position_operation(
            crate::OP_STRAND_REORDER,
            strand_id,
            board_space_id,
            ("space_id", space_id),
            rank,
            expected_position,
        )
    }

    fn strand_position_operation(
        &self,
        kind: &str,
        strand_id: StrandId,
        board_space_id: SpaceId,
        space_field: (&str, SpaceId),
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ck:operation:"))?;
        let mut payload = json!({
            "strand_id": strand_id.as_str(),
            "board_space_id": board_space_id.as_str(),
            "rank": rank.into(),
        });
        payload[space_field.0] = json!(space_field.1.as_str());
        if let Some(expected_position) = expected_position {
            payload["expected_position"] = expected_position;
        }

        let mut operation = Operation::create(operation_id, self.realm_id()?, kind, payload);
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }
}

fn default_strand_tracks() -> BTreeMap<String, crate::StrandTrackConfig> {
    let mut tracks = BTreeMap::new();
    tracks.insert(
        crate::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
        crate::StrandTrackConfig::synthesis(),
    );
    tracks
}
