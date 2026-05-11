use super::*;

/// Sliding Sync list configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlidingWindow {
    /// Inclusive start index.
    pub start: usize,
    /// Exclusive end index.
    pub end: usize,
}

impl SlidingWindow {
    /// Create a new window.
    pub fn new(start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(Error::Protocol("sliding sync window start is after end".to_owned()));
        }
        Ok(Self { start, end })
    }

    /// Number of items covered by this window.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Sliding Sync state for a space list.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SlidingSync {
    all_spaces: Vec<SpaceId>,
    subscribed_spaces: BTreeSet<SpaceId>,
    windows: Vec<SlidingWindow>,
    batch_size: Option<u32>,
    timeline_filter: Option<TimelineFilter>,
}

impl SlidingSync {
    /// Create an empty Sliding Sync state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the known ordered space list.
    pub fn set_space_list(&mut self, spaces: Vec<SpaceId>) {
        self.all_spaces = spaces;
    }

    /// Replace the active windows.
    pub fn set_windows(&mut self, windows: Vec<SlidingWindow>) {
        self.windows = windows;
    }

    /// Set timeline batch size.
    pub fn set_batch_size(&mut self, batch_size: Option<u32>) {
        self.batch_size = batch_size;
    }

    /// Set timeline filter for generated subscriptions.
    pub fn set_timeline_filter(&mut self, timeline_filter: Option<TimelineFilter>) {
        self.timeline_filter = timeline_filter;
    }

    /// Apply incremental insertions/removals to the ordered space list.
    pub fn apply_delta(&mut self, removals: &[SpaceId], insertions: Vec<(usize, SpaceId)>) {
        let removal_set: BTreeSet<_> = removals.iter().cloned().collect();
        self.all_spaces.retain(|space_id| !removal_set.contains(space_id));

        for (index, space_id) in insertions {
            let index = index.min(self.all_spaces.len());
            self.all_spaces.insert(index, space_id);
        }
    }

    /// Spaces currently visible through all windows.
    pub fn visible_spaces(&self) -> Vec<SpaceId> {
        let mut visible = BTreeSet::new();
        for window in &self.windows {
            for space_id in self.all_spaces.iter().skip(window.start).take(window.len()) {
                visible.insert(space_id.clone());
            }
        }
        visible.into_iter().collect()
    }

    /// Build protocol subscriptions for the current visible spaces.
    pub fn subscription_config(&mut self) -> SubscriptionConfig {
        let visible = self.visible_spaces();
        self.subscribed_spaces = visible.iter().cloned().collect();

        SubscriptionConfig {
            subscriptions: visible
                .into_iter()
                .map(|space_id| SpaceSubscription {
                    space_id,
                    timeline_filter: self.timeline_filter.clone(),
                    required_state: Vec::new(),
                })
                .collect(),
            batch_size: self.batch_size,
            timeline_filter: None,
        }
    }

    /// True if a space is part of the current visible subscription set.
    pub fn is_subscribed(&self, space_id: &SpaceId) -> bool {
        self.subscribed_spaces.contains(space_id)
    }

    /// Export sliding-window state for persistence.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Restore sliding-window state from a previous snapshot.
    pub fn from_snapshot(snapshot: Self) -> Self {
        snapshot
    }
}

/// Sort order for the space list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceListSort {
    /// Most recent activity first.
    #[default]
    Recency,
    /// Name ascending.
    Name,
    /// Unread count descending.
    Unread,
    /// Favorites first, then recency.
    Favorite,
}

/// Filter for space list projections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListFilter {
    /// Membership buckets to include. Empty means all buckets.
    #[serde(default)]
    pub memberships: BTreeSet<MembershipBucket>,
    /// Favorite flag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// Include only spaces with unread notifications.
    #[serde(default)]
    pub unread_only: bool,
    /// Optional category filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl SpaceListFilter {
    fn matches(&self, entry: &SpaceListEntry) -> bool {
        (self.memberships.is_empty() || self.memberships.contains(&entry.membership))
            && self.favorite.map(|favorite| entry.favorite == favorite).unwrap_or(true)
            && (!self.unread_only || entry.unread_count > 0 || entry.highlight_count > 0)
            && self
                .category
                .as_ref()
                .map(|category| entry.category.as_ref() == Some(category))
                .unwrap_or(true)
    }
}

/// One item in a space list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListEntry {
    /// Space ID.
    pub space_id: SpaceId,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Membership bucket.
    pub membership: MembershipBucket,
    /// Last event ID used for recency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    /// Last deterministic timeline position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<TimelineOrderKey>,
    /// Notification count.
    pub unread_count: u64,
    /// Highlight count.
    pub highlight_count: u64,
    /// User favorite flag.
    pub favorite: bool,
    /// Optional category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl SpaceListEntry {
    /// Create a list entry with default joined membership.
    pub fn joined(space_id: SpaceId) -> Self {
        Self {
            space_id,
            name: None,
            membership: MembershipBucket::Joined,
            last_event_id: None,
            last_activity: None,
            unread_count: 0,
            highlight_count: 0,
            favorite: false,
            category: None,
        }
    }
}

/// Incremental space list change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceListChange {
    /// New visible entry.
    Inserted { index: usize, entry: SpaceListEntry },
    /// Existing visible entry changed in place.
    Updated { index: usize, entry: SpaceListEntry },
    /// Entry disappeared from the visible projection.
    Removed { old_index: usize, space_id: SpaceId },
    /// Existing entry moved after sorting/filtering.
    Moved { old_index: usize, new_index: usize, space_id: SpaceId },
}

/// Result of applying one space-list mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListUpdate {
    /// Ordered visible space IDs after the mutation.
    #[serde(default)]
    pub ordered: Vec<SpaceId>,
    /// Incremental changes suitable for UI bindings.
    #[serde(default)]
    pub changes: Vec<SpaceListChange>,
}

/// Serializable space-list state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceListSnapshot {
    /// Entries by space.
    #[serde(default)]
    pub entries: BTreeMap<SpaceId, SpaceListEntry>,
    /// Visible ordered projection.
    #[serde(default)]
    pub ordered: Vec<SpaceId>,
    /// Current sort.
    pub sort: SpaceListSort,
    /// Current filter.
    pub filter: SpaceListFilter,
}

/// Space list service with deterministic sorting, filtering and deltas.
#[derive(Clone, Debug, Default)]
pub struct SpaceListService {
    entries: BTreeMap<SpaceId, SpaceListEntry>,
    ordered: Vec<SpaceId>,
    sort: SpaceListSort,
    filter: SpaceListFilter,
}

impl SpaceListService {
    /// Create an empty list service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore service state from a snapshot.
    pub fn from_snapshot(snapshot: SpaceListSnapshot) -> Self {
        Self {
            entries: snapshot.entries,
            ordered: snapshot.ordered,
            sort: snapshot.sort,
            filter: snapshot.filter,
        }
    }

    /// Export list state for persistence by the embedding application.
    pub fn snapshot(&self) -> SpaceListSnapshot {
        SpaceListSnapshot {
            entries: self.entries.clone(),
            ordered: self.ordered.clone(),
            sort: self.sort,
            filter: self.filter.clone(),
        }
    }

    /// Current ordered visible entries.
    pub fn entries(&self) -> Vec<&SpaceListEntry> {
        self.ordered.iter().filter_map(|space_id| self.entries.get(space_id)).collect()
    }

    /// Set sort mode and return the resulting delta.
    pub fn set_sort(&mut self, sort: SpaceListSort) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.sort = sort;
        self.rebuild_update(previous)
    }

    /// Set filter and return the resulting delta.
    pub fn set_filter(&mut self, filter: SpaceListFilter) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.filter = filter;
        self.rebuild_update(previous)
    }

    /// Insert or update one entry.
    pub fn upsert(&mut self, entry: SpaceListEntry) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.entries.insert(entry.space_id.clone(), entry);
        self.rebuild_update(previous)
    }

    /// Remove one entry.
    pub fn remove(&mut self, space_id: &SpaceId) -> SpaceListUpdate {
        let previous = self.visible_entries();
        self.entries.remove(space_id);
        self.rebuild_update(previous)
    }

    /// Apply a processed sync update to list metadata.
    pub fn apply_space_update(
        &mut self,
        update: &SpaceUpdate,
        membership: MembershipBucket,
    ) -> SpaceListUpdate {
        let mut entry = self
            .entries
            .get(&update.space_id)
            .cloned()
            .unwrap_or_else(|| SpaceListEntry::joined(update.space_id.clone()));
        entry.membership = membership;
        if let Some(name) = update
            .summary
            .get("name")
            .or_else(|| update.summary.get("title"))
            .and_then(Value::as_str)
        {
            entry.name = Some(name.to_owned());
        }
        if let Some(favorite) = update.summary.get("favorite").and_then(Value::as_bool) {
            entry.favorite = favorite;
        }
        if let Some(category) = update.summary.get("category").and_then(Value::as_str) {
            entry.category = Some(category.to_owned());
        }
        if let Some(unread_count) = update.summary.get("unread_count").and_then(Value::as_u64) {
            entry.unread_count = unread_count;
        }
        if let Some(highlight_count) = update.summary.get("highlight_count").and_then(Value::as_u64)
        {
            entry.highlight_count = highlight_count;
        }
        if let Some(timeline) = &update.timeline
            && let Some(event) = timeline
                .events
                .last()
                .and_then(|value| serde_json::from_value::<Event>(value.clone()).ok())
        {
            entry.last_event_id = Some(event.event_id.clone());
            entry.last_activity =
                Some(TimelineOrderKey::from_event(&event, event.prev_refs.len() as u64));
        }
        self.upsert(entry)
    }

    fn rebuild_update(&mut self, previous: Vec<SpaceListEntry>) -> SpaceListUpdate {
        let current = self.rebuild_order();
        let changes = diff_space_lists(&previous, &current);
        SpaceListUpdate {
            ordered: current.iter().map(|entry| entry.space_id.clone()).collect(),
            changes,
        }
    }

    fn rebuild_order(&mut self) -> Vec<SpaceListEntry> {
        let mut entries = self.visible_entries();
        entries.sort_by(|left, right| compare_space_entries(left, right, self.sort));
        self.ordered = entries.iter().map(|entry| entry.space_id.clone()).collect();
        entries
    }

    fn visible_entries(&self) -> Vec<SpaceListEntry> {
        self.entries.values().filter(|entry| self.filter.matches(entry)).cloned().collect()
    }
}

fn compare_space_entries(
    left: &SpaceListEntry,
    right: &SpaceListEntry,
    sort: SpaceListSort,
) -> std::cmp::Ordering {
    let name_order = left.name.cmp(&right.name).then_with(|| left.space_id.cmp(&right.space_id));
    match sort {
        SpaceListSort::Recency => right.last_activity.cmp(&left.last_activity).then(name_order),
        SpaceListSort::Name => name_order,
        SpaceListSort::Unread => right
            .highlight_count
            .cmp(&left.highlight_count)
            .then_with(|| right.unread_count.cmp(&left.unread_count))
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
        SpaceListSort::Favorite => right
            .favorite
            .cmp(&left.favorite)
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
    }
}

fn diff_space_lists(
    previous: &[SpaceListEntry],
    current: &[SpaceListEntry],
) -> Vec<SpaceListChange> {
    let previous_index: BTreeMap<_, _> = previous
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.space_id.clone(), (index, entry)))
        .collect();
    let current_index: BTreeMap<_, _> = current
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.space_id.clone(), (index, entry)))
        .collect();
    let mut changes = Vec::new();

    for (space_id, (old_index, _)) in &previous_index {
        if !current_index.contains_key(space_id) {
            changes.push(SpaceListChange::Removed {
                old_index: *old_index,
                space_id: space_id.clone(),
            });
        }
    }
    for (space_id, (new_index, entry)) in &current_index {
        match previous_index.get(space_id) {
            None => changes
                .push(SpaceListChange::Inserted { index: *new_index, entry: (*entry).clone() }),
            Some((old_index, previous_entry)) if *old_index != *new_index => {
                changes.push(SpaceListChange::Moved {
                    old_index: *old_index,
                    new_index: *new_index,
                    space_id: space_id.clone(),
                });
                if *previous_entry != *entry {
                    changes.push(SpaceListChange::Updated {
                        index: *new_index,
                        entry: (*entry).clone(),
                    });
                }
            }
            Some((_, previous_entry)) if *previous_entry != *entry => {
                changes
                    .push(SpaceListChange::Updated { index: *new_index, entry: (*entry).clone() });
            }
            _ => {}
        }
    }
    changes
}
