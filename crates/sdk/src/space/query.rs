use super::*;

/// Advanced Morph and relation operations.
impl Space {
    /// Query Morph objects from local resolved state with filters, sorting and limit.
    pub fn query_morphs(&self, query: MorphQuery) -> Vec<Morph> {
        let mut morphs: Vec<Morph> = self
            .state
            .morphs
            .values()
            .filter(|morph| {
                (query.morph_types.is_empty() || query.morph_types.contains(&morph.morph_type))
                    && query.filters.iter().all(|filter| morph_matches_filter(morph, filter))
            })
            .cloned()
            .collect();

        morphs.sort_by(|left, right| compare_morphs(left, right, &query.order_by));

        if let Some(limit) = query.limit {
            morphs.truncate(limit);
        }
        morphs
    }

    /// Full-text search over Morph title, summary, content and fields.
    pub fn search_morphs(&self, query: &str) -> Vec<Morph> {
        let needle = query.to_lowercase();
        self.state
            .morphs
            .values()
            .filter(|morph| morph_search_text(morph).contains(&needle))
            .cloned()
            .collect()
    }

    /// Aggregate Morph objects by type and selected field keys.
    pub fn aggregate_morphs(&self, field_keys: &[impl AsRef<str>]) -> MorphAggregation {
        let mut aggregation =
            MorphAggregation { total: self.state.morphs.len(), ..MorphAggregation::default() };

        for morph in self.state.morphs.values() {
            *aggregation.by_type.entry(morph.morph_type.clone()).or_default() += 1;

            for field_key in field_keys {
                let field_key = field_key.as_ref();
                if let Some(value) = morph_field_value(morph, field_key) {
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

    /// Traverse outgoing relations from a typed object reference.
    pub fn traverse_relation_refs(
        &self,
        start_ref: &str,
        relation_kind: Option<RelationKind>,
        traversal: GraphTraversal,
        max_depth: Option<usize>,
    ) -> Vec<String> {
        let mut visited = std::collections::HashSet::from([start_ref.to_owned()]);
        let mut output = Vec::new();
        let max_depth = max_depth.unwrap_or(usize::MAX);

        match traversal {
            GraphTraversal::BreadthFirst => {
                let mut queue = std::collections::VecDeque::from([(start_ref.to_owned(), 0usize)]);
                while let Some((current, depth)) = queue.pop_front() {
                    if depth >= max_depth {
                        continue;
                    }
                    for next in self.relation_ref_neighbors(&current, relation_kind.as_ref()) {
                        if visited.insert(next.clone()) {
                            output.push(next.clone());
                            queue.push_back((next, depth + 1));
                        }
                    }
                }
            }
            GraphTraversal::DepthFirst => {
                let mut stack = vec![(start_ref.to_owned(), 0usize)];
                while let Some((current, depth)) = stack.pop() {
                    if depth >= max_depth {
                        continue;
                    }
                    let mut neighbors = self.relation_ref_neighbors(&current, relation_kind.as_ref());
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

    /// Find the shortest outgoing relation path between two typed object refs.
    pub fn shortest_relation_ref_path(
        &self,
        start_ref: &str,
        target_ref: &str,
        relation_kind: Option<RelationKind>,
    ) -> Option<Vec<String>> {
        if start_ref == target_ref {
            return Some(vec![start_ref.to_owned()]);
        }

        let mut visited = std::collections::HashSet::from([start_ref.to_owned()]);
        let mut queue =
            std::collections::VecDeque::from([(start_ref.to_owned(), vec![start_ref.to_owned()])]);

        while let Some((current, path)) = queue.pop_front() {
            for next in self.relation_ref_neighbors(&current, relation_kind.as_ref()) {
                if !visited.insert(next.clone()) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(next.clone());
                if next == target_ref {
                    return Some(next_path);
                }
                queue.push_back((next, next_path));
            }
        }

        None
    }

    /// Detect whether the directed relation graph contains a cycle.
    pub fn relation_ref_graph_has_cycle(&self, relation_kind: Option<RelationKind>) -> bool {
        let mut visiting = std::collections::HashSet::new();
        let mut visited = std::collections::HashSet::new();

        for morph in self.state.morphs.values() {
            if self.relation_ref_cycle_visit(
                morph.id.as_str(),
                relation_kind.as_ref(),
                &mut visiting,
                &mut visited,
            ) {
                return true;
            }
        }

        false
    }

    /// Reconstruct version history for a Morph from processed state events.
    pub fn morph_versions(&self, morph_id: &MorphId) -> Vec<MorphVersion> {
        let mut versions = Vec::new();
        let mut title = None;
        let mut content = None;
        let mut fields = BTreeMap::new();
        let mut state = None;
        let mut version = None;

        for event in &self.state.state_events {
            let object = event.content.get("object").unwrap_or(&event.content);
            let target_id = object
                .get("id")
                .or_else(|| event.content.get("morph_id"))
                .and_then(Value::as_str);
            if target_id != Some(morph_id.as_str()) {
                continue;
            }

            match event.kind.as_str() {
                OP_MORPH_CREATE => {
                    version = Some(0);
                    title = object.get("title").and_then(Value::as_str).map(str::to_owned);
                    content = object.get("content").cloned();
                    fields = object
                        .get("fields")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or_default();
                    state = Some(ObjectState::Active);
                }
                OP_MORPH_UPDATE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    let patch = event.content.get("patch").and_then(Value::as_object);
                    if let Some(next_title) = event
                        .content
                        .get("title")
                        .or_else(|| patch.and_then(|patch| patch.get("title")))
                        .and_then(Value::as_str)
                    {
                        title = Some(next_title.to_owned());
                    }
                    if let Some(next_content) =
                        event.content.get("content").or_else(|| patch.and_then(|p| p.get("content")))
                    {
                        content = Some(next_content.clone());
                    }
                    if let Some(next_fields) = event
                        .content
                        .get("fields")
                        .or_else(|| patch.and_then(|p| p.get("fields")))
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                    {
                        fields = next_fields;
                    }
                    if let Some(next_state) = event
                        .content
                        .get("state")
                        .or_else(|| patch.and_then(|p| p.get("state")))
                        .and_then(Value::as_str)
                    {
                        state = parse_object_state(next_state);
                    }
                }
                OP_MORPH_ARCHIVE => {
                    let Some(next_version) = version.map(|value| value + 1) else {
                        continue;
                    };
                    version = Some(next_version);
                    state = Some(ObjectState::Archived);
                }
                _ => continue,
            }

            versions.push(MorphVersion {
                morph_id: morph_id.clone(),
                version: version.expect("version set by morph event"),
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

    /// Compare two historical versions of a Morph.
    pub fn compare_morph_versions(
        &self,
        morph_id: &MorphId,
        from_version: u64,
        to_version: u64,
    ) -> Option<MorphVersionDiff> {
        let versions = self.morph_versions(morph_id);
        let from = versions.iter().find(|version| version.version == from_version)?;
        let to = versions.iter().find(|version| version.version == to_version)?;

        let from_keys: std::collections::HashSet<_> = from.fields.keys().cloned().collect();
        let to_keys: std::collections::HashSet<_> = to.fields.keys().cloned().collect();
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

        Some(MorphVersionDiff {
            title_changed: from.title != to.title,
            content_changed: from.content != to.content,
            added_fields,
            removed_fields,
            changed_fields,
        })
    }

    /// Create an update operation that rolls a Morph back to a previous version.
    pub fn rollback_morph_operation(
        &self,
        morph_id: MorphId,
        target_version: u64,
    ) -> Result<Operation> {
        let version = self
            .morph_versions(&morph_id)
            .into_iter()
            .find(|version| version.version == target_version)
            .ok_or_else(|| crate::Error::Protocol("morph version not found".to_owned()))?;
        let mut operation = self.update_morph_operation(
            morph_id,
            version.title,
            None,
            version.content,
            Some(version.fields),
        )?;
        operation.payload["rollback_to_version"] = json!(target_version);
        Ok(operation)
    }

    /// Create Morph operations in batch.
    pub fn batch_create_morph_operations(
        &self,
        items: Vec<BatchCreateMorph>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.create_morph_operation(
                    item.morph_type,
                    item.title,
                    item.summary,
                    item.content,
                    item.fields,
                )
            })
            .collect()
    }

    /// Create Morph update operations in batch.
    pub fn batch_update_morph_operations(
        &self,
        items: Vec<BatchUpdateMorph>,
    ) -> Result<Vec<Operation>> {
        items
            .into_iter()
            .map(|item| {
                self.update_morph_operation(
                    item.morph_id,
                    item.title,
                    item.summary,
                    item.content,
                    item.fields,
                )
            })
            .collect()
    }

    /// Create Morph archive operations in batch.
    pub fn batch_archive_morph_operations(
        &self,
        morph_ids: Vec<MorphId>,
    ) -> Result<Vec<Operation>> {
        morph_ids.into_iter().map(|morph_id| self.archive_morph_operation(morph_id)).collect()
    }

    fn relation_ref_neighbors(
        &self,
        object_ref: &str,
        relation_kind: Option<&RelationKind>,
    ) -> Vec<String> {
        self.state
            .relations
            .values()
            .filter(|relation| relation_is_active(relation))
            .filter(|relation| {
                relation_kind.map(|kind| &relation.relation_kind == kind).unwrap_or(true)
            })
            .filter(|relation| relation.from_ref == object_ref)
            .map(|relation| relation.to_ref.clone())
            .collect()
    }

    fn relation_ref_cycle_visit(
        &self,
        object_ref: &str,
        relation_kind: Option<&RelationKind>,
        visiting: &mut std::collections::HashSet<String>,
        visited: &mut std::collections::HashSet<String>,
    ) -> bool {
        if visited.contains(object_ref) {
            return false;
        }
        if !visiting.insert(object_ref.to_owned()) {
            return true;
        }

        for next in self.relation_ref_neighbors(object_ref, relation_kind) {
            if self.relation_ref_cycle_visit(&next, relation_kind, visiting, visited) {
                return true;
            }
        }

        visiting.remove(object_ref);
        visited.insert(object_ref.to_owned());
        false
    }
}
