use arkret_wire::EventKind;

use super::*;

mod events;
mod helpers;
mod objects;

/// Current reducer state of a Realm.
#[derive(Clone, Debug)]
pub struct RealmState {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Reducer profile used for this state.
    pub reducer_profile: String,
    /// Current strands by ID
    pub subjects: BTreeMap<String, Strand>,
    /// Current Morph objects by ID.
    pub morphs: BTreeMap<String, Morph>,
    /// Current Space (container) objects by ID.
    pub spaces: BTreeMap<String, Space>,
    /// Canonical placement projection keyed by (Board, Strand), valued by List.
    pub(super) strand_positions: BTreeMap<(String, String), String>,
    /// Current relations by ID
    pub relations: BTreeMap<String, Relation>,
    /// Generic resolved state events keyed by `kind|subject` (spec Phase 1).
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    /// Message timeline state keyed by message id.
    pub messages: BTreeMap<String, ResolvedMessage>,
    /// Reaction OR-Set keyed by `(message_id, actor, reaction_key)`.
    pub reactions: BTreeMap<String, ResolvedReaction>,
    /// Deterministic conflict decisions recorded during reduction.
    pub conflict_records: Vec<ConflictRecord>,
    /// Causal frontier (most recent event IDs)
    pub frontier: Vec<EventId>,
    /// Realm state events.
    pub state_events: Vec<Event>,
    pub(super) processed_events: BTreeMap<EventId, Event>,
    pub(super) redacted_events: BTreeSet<EventId>,
    pub(super) tombstone_event_id: Option<EventId>,
}

impl RealmState {
    /// Create a new empty Realm state.
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            reducer_profile: CORE_REDUCER_PROFILE.to_owned(),
            subjects: BTreeMap::new(),
            morphs: BTreeMap::new(),
            spaces: BTreeMap::new(),
            strand_positions: BTreeMap::new(),
            relations: BTreeMap::new(),
            resolved_state: BTreeMap::new(),
            messages: BTreeMap::new(),
            reactions: BTreeMap::new(),
            conflict_records: Vec::new(),
            frontier: Vec::new(),
            state_events: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: None,
        }
    }

    /// Apply a sequence of events to the state.
    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        let mut event_index = self.processed_events.clone();
        for event in events {
            event_index.insert(event.event_id.clone(), event.clone());
        }

        let mut sorted_events: Vec<&Event> = events.iter().collect();
        sorted_events.sort_by(|a, b| {
            let depth_a = Self::causal_depth_from_index(a, &event_index);
            let depth_b = Self::causal_depth_from_index(b, &event_index);
            depth_a
                .cmp(&depth_b)
                .then_with(|| a.hlc.cmp(&b.hlc))
                .then_with(|| a.actor_id.cmp(&b.actor_id))
                .then_with(|| a.actor_seq.cmp(&b.actor_seq))
                .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
        });

        // Apply events in order
        for event in sorted_events {
            self.apply_event(event)?;
        }

        Ok(())
    }

    /// Apply a single event to the state.
    pub(super) fn apply_event(&mut self, event: &Event) -> Result<()> {
        if self.processed_events.contains_key(&event.event_id) {
            return Ok(());
        }

        // Check causal dependencies
        for prev_ref in &event.prev_refs {
            if !self.is_processed(prev_ref) {
                return Err(WireError::Protocol(format!(
                    "missing causal dependency: {}",
                    prev_ref
                )));
            }
        }

        if self.tombstone_event_id.is_some() && !Self::is_maintenance_event(event) {
            return Err(WireError::Protocol("realm is destroyed".to_owned()));
        }

        // Process event content
        self.process_event_content(event)?;

        let mut stored_event = event.clone();
        if self.redacted_events.contains(&stored_event.event_id) {
            // Preserve envelope fields required for chain validation per
            // event-auth-state-resolution.md §10; clear payload + unsigned.
            stored_event.payload = BTreeMap::new();
            stored_event.unsigned.clear();
        }
        self.state_events.push(stored_event.clone());
        self.processed_events
            .insert(stored_event.event_id.clone(), stored_event);

        // Update frontier
        self.update_frontier(event);

        Ok(())
    }

    /// Process the content of an event and update state.
    pub(super) fn process_event_content(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::StrandCreate => self.create_strand(event)?,
            EventKind::StrandUpdate => self.update_strand(event)?,
            EventKind::StrandArchive => self.archive_strand(event)?,
            EventKind::StrandRestore => self.restore_strand(event)?,
            EventKind::StrandMove | EventKind::StrandReorder => self.touch_strand(event)?,
            EventKind::StrandTracksUpdate => self.update_strand_tracks(event)?,

            EventKind::MorphCreate => self.create_morph(event)?,
            EventKind::MorphUpdate => self.update_morph(event)?,
            EventKind::MorphArchive => self.archive_morph(event)?,
            EventKind::MorphRestore => self.restore_morph(event)?,

            EventKind::SpaceCreate => self.create_space(event)?,
            EventKind::SpaceUpdate => self.update_space(event)?,
            EventKind::SpaceParent => self.set_space_parent(event)?,
            EventKind::SpaceArchive => self.archive_space(event)?,
            EventKind::SpaceRestore => self.restore_space(event)?,
            EventKind::SpaceTombstone => self.tombstone_space(event)?,

            // Relation lifecycle
            EventKind::RelationCreate => self.create_relation(event)?,
            EventKind::RelationTombstone => self.delete_relation(event)?,
            EventKind::ContainerMoveItem => self.move_relation(event)?,

            // View operations
            EventKind::ViewCreate => self.create_view(event)?,
            EventKind::ViewUpdate => self.update_view(event)?,
            EventKind::ViewReconcile => self.reconcile_view(event)?,

            // Realm lifecycle - generic state reduction. Container-level
            // (`ak.space.*`) lifecycle is covered by the typed arms above.
            EventKind::RealmCreate
            | EventKind::RealmOrganization
            | EventKind::RealmLink
            | EventKind::RealmInheritancePolicy
            | EventKind::RealmJoinRule
            | EventKind::RealmHistoryAccess
            | EventKind::RealmDiscovery
            | EventKind::RealmArchive
            | EventKind::RealmFreeze
            | EventKind::RealmDestroy => self.reduce_realm_lifecycle_event(event)?,

            // Member / capability / invite / policy / read-marker state
            EventKind::MemberState
            | EventKind::CapabilityGrant
            | EventKind::CapabilityRevoke
            | EventKind::RealmPolicy
            | EventKind::PolicySet
            | EventKind::InviteCreate
            | EventKind::InviteCancel
            | EventKind::InviteAccept
            | EventKind::ReadCursorAdvance
            // Account lifecycle (account-lifecycle.md §3 +
            // event-auth-state-resolution.md). The cell subject is the
            // account DID; the latest event wins per HLC ordering.
            // Moderation reports / franks (moderation.md §3).
            // Reports are state events keyed by `(target_ref, reporter)`;
            // franks bind a per-message receipt for E2EE accountability.
            | EventKind::SelfModerationReport
            | EventKind::ModerationFrankingProof => self.reduce_generic_state_event(event)?,

            // Message timeline
            EventKind::MessageCreate => self.create_message(event)?,
            EventKind::MessageRevise => self.revise_message(event)?,
            EventKind::MessageRedact => self.redact_message(event)?,

            // Reactions
            EventKind::ReactionAdd | EventKind::ReactionRemove => self.reduce_reaction(event)?,

            // Realm upgrade
            EventKind::RealmUpgrade => self.upgrade_realm(event)?,

            // Cross-object redaction. Also flips Strand / Morph subject state
            // to Redacted per spec common-fields.md §5.1 when the registered
            // object-target member `payload.target_ref` names a `ak:strand:` /
            // `ak:morph:` typed-id. State-machine guard rejects an
            // already-terminal source with `<kind>_already_terminal`.
            // Space is excluded — spec note "Space has no redacted state" routes
            // Space removal through `ak.space.tombstone` only.
            EventKind::Redaction => self.redact_object_for_event(event)?,

            _ => {
                // Unknown event types do not affect the local reducer state.
            }
        }

        Ok(())
    }

    /// Update the causal frontier.
    pub(super) fn update_frontier(&mut self, event: &Event) {
        let prev_refs: BTreeSet<EventId> = event.prev_refs.iter().cloned().collect();
        self.frontier
            .retain(|frontier_event| !prev_refs.contains(frontier_event));
        if !self.frontier.contains(&event.event_id) {
            self.frontier.push(event.event_id.clone());
        }
        self.frontier.sort();
    }

    /// Check if an event has been processed.
    pub(super) fn is_processed(&self, event_id: &EventId) -> bool {
        self.processed_events.contains_key(event_id)
    }

    pub(super) fn causal_depth_from_index(
        event: &Event,
        index: &BTreeMap<EventId, Event>,
    ) -> usize {
        fn walk(
            event_id: &EventId,
            index: &BTreeMap<EventId, Event>,
            visiting: &mut BTreeSet<EventId>,
        ) -> usize {
            if !visiting.insert(event_id.clone()) {
                return 0;
            }
            let depth = index
                .get(event_id)
                .map(|event| {
                    event
                        .prev_refs
                        .iter()
                        .map(|prev_ref| 1 + walk(prev_ref, index, visiting))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            visiting.remove(event_id);
            depth
        }

        event
            .prev_refs
            .iter()
            .map(|prev_ref| 1 + walk(prev_ref, index, &mut BTreeSet::new()))
            .max()
            .unwrap_or(0)
    }

    pub(super) fn is_maintenance_event(event: &Event) -> bool {
        matches!(
            event.kind.as_str(),
            arkret_wire::event_kind_str::MESSAGE_REDACT
                | arkret_wire::event_kind_str::REALM_UPGRADE
                | arkret_wire::event_kind_str::REALM_DESTROY
                | arkret_wire::event_kind_str::REDACTION
        )
    }
}
