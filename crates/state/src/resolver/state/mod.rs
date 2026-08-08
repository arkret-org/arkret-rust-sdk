use arkret_wire::EventKind;

use super::snapshot::{StateHashInput, state_digest_payload, state_merkle_root};
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
    /// True when one or more events were marked `soft_failed` because
    /// their authorization refs were not yet materialized at apply time.
    /// Per `event-auth-state-resolution.md` §6.2, the projection MUST be
    /// treated as `read_only` while this is set: callers MUST NOT submit
    /// new writes that depend on unverified auth state.
    pub auth_incomplete: bool,
    /// Event IDs that landed but could not be auth-validated due to a
    /// missing `refs[role=authorized_by]` chain link. They live here, not in
    /// `state_events`, until the missing dependency is materialized.
    pub soft_failed: Vec<EventId>,
    pub(super) processed_events: BTreeMap<EventId, Event>,
    pub(super) redacted_events: BTreeSet<EventId>,
    pub(super) tombstone_event_id: Option<EventId>,
}

impl RealmState {
    /// Create a new empty Realm state.
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            reducer_profile: REDUCER_SNAPSHOT_PROFILE.to_owned(),
            subjects: BTreeMap::new(),
            morphs: BTreeMap::new(),
            spaces: BTreeMap::new(),
            relations: BTreeMap::new(),
            resolved_state: BTreeMap::new(),
            messages: BTreeMap::new(),
            reactions: BTreeMap::new(),
            conflict_records: Vec::new(),
            frontier: Vec::new(),
            state_events: Vec::new(),
            auth_incomplete: false,
            soft_failed: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: None,
        }
    }

    /// Returns `true` when the projection MUST refuse new writes because at
    /// least one applied event is `soft_failed` due to missing authorization refs.
    pub fn is_read_only(&self) -> bool {
        self.auth_incomplete
    }

    /// Mark an event as `soft_failed` and flip the projection into the
    /// read-only `auth_incomplete` mode (event-auth-state-resolution.md §6.2).
    ///
    /// Callers SHOULD invoke this when an inbound event references
    /// `refs[role=authorized_by]` that have not yet been pulled. Once the missing
    /// dependency materialises, callers may invoke
    /// [`RealmState::clear_soft_failed`] to retry reduction.
    pub fn mark_soft_failed(&mut self, event_id: EventId) {
        if !self.soft_failed.iter().any(|id| id == &event_id) {
            self.soft_failed.push(event_id);
        }
        self.auth_incomplete = true;
    }

    /// Drop a soft-failed event marker once its authorization refs have been
    /// resolved. Clears `auth_incomplete` only when the soft-failed list
    /// becomes empty.
    pub fn clear_soft_failed(&mut self, event_id: &EventId) {
        self.soft_failed.retain(|id| id != event_id);
        if self.soft_failed.is_empty() {
            self.auth_incomplete = false;
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
                .then_with(|| a.actor_id.as_str().cmp(b.actor_id.as_str()))
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
                return Err(Error::Protocol(format!(
                    "missing causal dependency: {}",
                    prev_ref
                )));
            }
        }

        if self.tombstone_event_id.is_some() && !Self::is_maintenance_event(event) {
            return Err(Error::Protocol("realm is destroyed".to_owned()));
        }

        // Check for redaction
        if let Some(redacted_ref) = &event.redacts {
            self.redact_event(redacted_ref)?;
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
            | EventKind::RealmHistoryVisibility
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
            | EventKind::AccountStatus
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

            // Generic redaction. Round 11 (2026-05-16): also flips Strand /
            // Morph subject state to Redacted per spec common-fields.md
            // §5.1 when the event content carries an `object_ref` pointing
            // to a `ak:strand:` / `ak:morph:` typed-id. State-machine guard
            // rejects already-terminal source with `<kind>_already_terminal`.
            // Space is excluded — spec note "Space has no redacted state" routes
            // Space removal through `ak.space.tombstone` only.
            EventKind::Redaction => {
                self.redact_object_for_event(event)?;
                if let Some(redacted_ref) = &event.redacts {
                    self.redact_event(redacted_ref)?;
                }
            }

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
            "ak.message.redact"
                | "ak.realm.redact"
                | "ak.realm.export"
                | "ak.realm.legal_hold"
                | "ak.realm.migration_proof"
                | "ak.realm.upgrade"
                | "ak.realm.destroy"
                | "ak.redaction"
        ) || event.redacts.is_some()
    }

    /// Create a state snapshot at the current point. Fails when the manifest
    /// Merkle root cannot be computed (fail-closed: no placeholder manifest).
    pub fn snapshot(&self) -> Result<StateSnapshot> {
        let mut snapshot = StateSnapshot {
            realm_id: self.realm_id.clone(),
            reducer_profile: self.reducer_profile.clone(),
            frontier: self.frontier.clone(),
            subjects: self.subjects.clone(),
            morphs: self.morphs.clone(),
            spaces: self.spaces.clone(),
            relations: self.relations.clone(),
            resolved_state: self.resolved_state.clone(),
            messages: self.messages.clone(),
            reactions: self.reactions.clone(),
            state_digest: self.compute_state_digest(),
            snapshot_timestamp: chrono::Utc::now(),
            tombstone_event_id: self.tombstone_event_id.clone(),
            manifest: None,
        };
        snapshot.manifest = Some(snapshot.manifest()?);
        Ok(snapshot)
    }

    pub fn effective_capability(&self, capability_id: &str) -> Option<&ResolvedStateEvent> {
        self.resolved_state
            .get(&format!("ak.capability|{}", capability_id))
            .filter(|event| matches!(event.kind.as_str(), "ak.capability.grant"))
    }

    pub fn capability_allows(&self, capability_id: &str, action: &str) -> bool {
        self.effective_capability(capability_id)
            .and_then(|event| event.content.get("actions"))
            .and_then(Value::as_array)
            .is_some_and(|actions| {
                actions.iter().any(|candidate| {
                    candidate.as_str() == Some(action) || candidate.as_str() == Some("*")
                })
            })
    }

    /// Compute state hash for verification.
    pub fn compute_state_digest(&self) -> String {
        canonical_sha256(&state_digest_payload(StateHashInput {
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            frontier: &self.frontier,
            subjects: &self.subjects,
            morphs: &self.morphs,
            spaces: &self.spaces,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
        .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)))
    }

    pub fn state_merkle_root(&self) -> Result<String> {
        state_merkle_root(&state_digest_payload(StateHashInput {
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            frontier: &self.frontier,
            subjects: &self.subjects,
            morphs: &self.morphs,
            spaces: &self.spaces,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        }))
    }

    pub(super) fn from_snapshot(snapshot: StateSnapshot) -> Self {
        Self {
            realm_id: snapshot.realm_id,
            reducer_profile: snapshot.reducer_profile,
            subjects: snapshot.subjects,
            morphs: snapshot.morphs,
            spaces: snapshot.spaces,
            relations: snapshot.relations,
            resolved_state: snapshot.resolved_state,
            messages: snapshot.messages,
            reactions: snapshot.reactions,
            conflict_records: Vec::new(),
            frontier: snapshot.frontier,
            state_events: Vec::new(),
            auth_incomplete: false,
            soft_failed: Vec::new(),
            processed_events: BTreeMap::new(),
            redacted_events: BTreeSet::new(),
            tombstone_event_id: snapshot.tombstone_event_id,
        }
    }

    pub fn restore_snapshot_or_replay(
        snapshot: Option<StateSnapshot>,
        realm_id: RealmId,
        repo_events: &[Event],
    ) -> Result<SnapshotRestore> {
        if let Some(snapshot) = snapshot {
            match snapshot.verify() {
                Ok(()) => {
                    return Ok(SnapshotRestore {
                        state: Self::from_snapshot(snapshot),
                        source: SnapshotRestoreSource::Snapshot,
                        snapshot_error: None,
                    });
                }
                Err(err) => {
                    let mut state = Self::new(realm_id);
                    state.apply_events(repo_events)?;
                    return Ok(SnapshotRestore {
                        state,
                        source: SnapshotRestoreSource::RepoReplay,
                        snapshot_error: Some(err.to_string()),
                    });
                }
            }
        }

        let mut state = Self::new(realm_id);
        state.apply_events(repo_events)?;
        Ok(SnapshotRestore {
            state,
            source: SnapshotRestoreSource::RepoReplay,
            snapshot_error: None,
        })
    }
}
