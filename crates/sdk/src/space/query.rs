use super::*;

/// Advanced entity and relation operations.
impl Space {
    /// Query entities from local resolved state with filters, sorting and limit.
    pub fn query_entities(&self, query: EntityQuery) -> Vec<Entity> {
        let mut entities: Vec<Entity> = self
            .state
            .entities
            .values()
            .filter(|entity| {
                (query.entity_types.is_empty() || query.entity_types.contains(&entity.entity_type))
                    && query.filters.iter().all(|filter| entity_matches_filter(entity, filter))
            })
            .cloned()
            .collect();

        entities.sort_by(|left, right| compare_entities(left, right, &query.order_by));

        if let Some(limit) = query.limit {
            entities.truncate(limit);
        }
        entities
    }

    /// Full-text search over entity title, content and fields.
    pub fn search_entities(&self, query: &str) -> Vec<Entity> {
        let needle = query.to_lowercase();
        self.state
            .entities
            .values()
            .filter(|entity| entity_search_text(entity).contains(&needle))
            .cloned()
            .collect()
    }

    /// Aggregate entities by type and selected field keys.
    pub fn aggregate_entities(&self, field_keys: &[impl AsRef<str>]) -> EntityAggregation {
        let mut aggregation =
            EntityAggregation { total: self.state.entities.len(), ..EntityAggregation::default() };

        for entity in self.state.entities.values() {
            *aggregation.by_type.entry(entity_type_key(&entity.entity_type)).or_default() += 1;

            for field_key in field_keys {
                let field_key = field_key.as_ref();
                if let Some(value) = entity_field_value(entity, field_key) {
                    let value_key = scalar_value_key(&value);
                    *aggregation
                        .by_field
                        .entry(field_key.to_owned())
                        .or_default()
                        .entry(value_key)
                        .or_default() += 1;
                }
            }
        }

        aggregation
    }

    /// Traverse outgoing entity relations from a start entity.
    pub fn traverse_relations(
        &self,
        start: &EntityId,
        relation_kind: Option<RelationKind>,
        traversal: GraphTraversal,
        max_depth: Option<usize>,
    ) -> Vec<EntityId> {
        let mut visited = HashSet::from([start.clone()]);
        let mut output = Vec::new();
        let max_depth = max_depth.unwrap_or(usize::MAX);

        match traversal {
            GraphTraversal::BreadthFirst => {
                let mut queue = VecDeque::from([(start.clone(), 0usize)]);
                while let Some((current, depth)) = queue.pop_front() {
                    if depth >= max_depth {
                        continue;
                    }
                    for next in self.relation_neighbors(&current, relation_kind.as_ref()) {
                        if visited.insert(next.clone()) {
                            output.push(next.clone());
                            queue.push_back((next, depth + 1));
                        }
                    }
                }
            }
            GraphTraversal::DepthFirst => {
                let mut stack = vec![(start.clone(), 0usize)];
                while let Some((current, depth)) = stack.pop() {
                    if depth >= max_depth {
                        continue;
                    }
                    let mut neighbors = self.relation_neighbors(&current, relation_kind.as_ref());
                    neighbors.reverse();
                    for next in neighbors {
                        if visited.insert(next.clone()) {
                            output.push(next.clone());
                            stack.push((next, depth + 1));
                        }
                    }
                }
            }
        }

        output
    }

    /// Find the shortest outgoing relation path between two entities.
    pub fn shortest_relation_path(
        &self,
        start: &EntityId,
        target: &EntityId,
        relation_kind: Option<RelationKind>,
    ) -> Option<Vec<EntityId>> {
        if start == target {
            return Some(vec![start.clone()]);
        }

        let mut visited = HashSet::from([start.clone()]);
        let mut queue = VecDeque::from([(start.clone(), vec![start.clone()])]);

        while let Some((current, path)) = queue.pop_front() {
            for next in self.relation_neighbors(&current, relation_kind.as_ref()) {
                if !visited.insert(next.clone()) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(next.clone());
                if &next == target {
                    return Some(next_path);
                }
                queue.push_back((next, next_path));
            }
        }

        None
    }

    /// Detect whether the directed relation graph contains a cycle.
    pub fn relation_graph_has_cycle(&self, relation_kind: Option<RelationKind>) -> bool {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();

        for entity in self.state.entities.values() {
            if self.relation_cycle_visit(
                &entity.id,
                relation_kind.as_ref(),
                &mut visiting,
                &mut visited,
            ) {
                return true;
            }
        }

        false
    }

    /// Reconstruct version history for an entity from processed state events.
    pub fn entity_versions(&self, entity_id: &EntityId) -> Vec<EntityVersion> {
        let mut versions = Vec::new();
        let mut title = None;
        let mut content = None;
        let mut fields = BTreeMap::new();
        let mut state = None;
        let mut version = None;

        for event in &self.state.state_events {
            if event.content.get("id").and_then(Value::as_str) != Some(entity_id.as_str()) {
                continue;
            }

            match event.kind.as_str() {
                OP_ENTITY_CREATE => {
                    version = Some(0);
                    title = event.content.get("title").and_then(Value::as_str).map(str::to_owned);
                    content = event.content.get("content").cloned();
                    fields = event
                        .content
                        .get("fields")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or_default();
                    state = Some(ObjectState::Active);
                }
                OP_ENTITY_UPDATE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    if let Some(next_title) = event.content.get("title").and_then(Value::as_str) {
                        title = Some(next_title.to_owned());
                    }
                    if let Some(next_content) = event.content.get("content") {
                        content = Some(next_content.clone());
                    }
                    if let Some(next_fields) = event
                        .content
                        .get("fields")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                    {
                        fields = next_fields;
                    }
                    if let Some(next_state) = event.content.get("state").and_then(Value::as_str) {
                        state = parse_object_state(next_state);
                    }
                }
                OP_ENTITY_DELETE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    state = Some(ObjectState::Deleted);
                }
                OP_ENTITY_REDACT => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    content = None;
                    state = Some(ObjectState::Redacted);
                }
                _ => continue,
            }

            versions.push(EntityVersion {
                entity_id: entity_id.clone(),
                version: version.expect("version set by entity event"),
                event_id: event.event_id.clone(),
                updated_at: event.created_at,
                title: title.clone(),
                content: content.clone(),
                fields: fields.clone(),
                state: state.clone(),
            });
        }

        versions
    }

    /// Compare two historical versions of an entity.
    pub fn compare_entity_versions(
        &self,
        entity_id: &EntityId,
        from_version: u64,
        to_version: u64,
    ) -> Option<EntityVersionDiff> {
        let versions = self.entity_versions(entity_id);
        let from = versions.iter().find(|version| version.version == from_version)?;
        let to = versions.iter().find(|version| version.version == to_version)?;

        let from_keys: HashSet<_> = from.fields.keys().cloned().collect();
        let to_keys: HashSet<_> = to.fields.keys().cloned().collect();
        let mut added_fields: Vec<_> = to_keys.difference(&from_keys).cloned().collect();
        let mut removed_fields: Vec<_> = from_keys.difference(&to_keys).cloned().collect();
        let mut changed_fields: Vec<_> = from_keys
            .intersection(&to_keys)
            .filter(|key| from.fields.get(*key) != to.fields.get(*key))
            .cloned()
            .collect();
        added_fields.sort();
        removed_fields.sort();
        changed_fields.sort();

        Some(EntityVersionDiff {
            title_changed: from.title != to.title,
            content_changed: from.content != to.content,
            added_fields,
            removed_fields,
            changed_fields,
        })
    }

    /// Create an update operation that rolls an entity back to a previous version.
    pub fn rollback_entity_operation(
        &self,
        entity_id: EntityId,
        target_version: u64,
    ) -> Result<Operation> {
        let version = self
            .entity_versions(&entity_id)
            .into_iter()
            .find(|version| version.version == target_version)
            .ok_or_else(|| crate::Error::Protocol("entity version not found".to_owned()))?;
        let mut operation = self.update_entity_operation(
            entity_id,
            version.title,
            version.content,
            Some(version.fields),
        )?;
        operation.payload["rollback_to_version"] = json!(target_version);
        Ok(operation)
    }

    /// Create entity operations in batch.
    pub fn batch_create_entity_operations(
        &self,
        items: Vec<BatchCreateEntity>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.create_entity_operation(
                    item.entity_type,
                    item.title,
                    item.content,
                    item.fields,
                )
            })
            .collect()
    }

    /// Create entity update operations in batch.
    pub fn batch_update_entity_operations(
        &self,
        items: Vec<BatchUpdateEntity>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.update_entity_operation(item.entity_id, item.title, item.content, item.fields)
            })
            .collect()
    }

    /// Create entity delete operations in batch.
    pub fn batch_delete_entity_operations(
        &self,
        entity_ids: Vec<EntityId>,
    ) -> Result<Vec<Operation>> {
        entity_ids.into_iter().map(|entity_id| self.delete_entity_operation(entity_id)).collect()
    }

    fn relation_neighbors(
        &self,
        entity_id: &EntityId,
        relation_kind: Option<&RelationKind>,
    ) -> Vec<EntityId> {
        self.state
            .relations
            .values()
            .filter(|relation| relation_is_active(relation))
            .filter(|relation| {
                relation_kind.map(|kind| &relation.relation_kind == kind).unwrap_or(true)
            })
            .filter(|relation| relation.from_entity_id.as_ref() == Some(entity_id))
            .filter_map(|relation| relation.to_entity_id.clone())
            .collect()
    }

    fn relation_cycle_visit(
        &self,
        entity_id: &EntityId,
        relation_kind: Option<&RelationKind>,
        visiting: &mut HashSet<EntityId>,
        visited: &mut HashSet<EntityId>,
    ) -> bool {
        if visited.contains(entity_id) {
            return false;
        }
        if !visiting.insert(entity_id.clone()) {
            return true;
        }

        for next in self.relation_neighbors(entity_id, relation_kind) {
            if self.relation_cycle_visit(&next, relation_kind, visiting, visited) {
                return true;
            }
        }

        visiting.remove(entity_id);
        visited.insert(entity_id.clone());
        false
    }
}
