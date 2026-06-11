use super::*;

/// Processed sync response cache and dispatcher.
#[derive(Clone, Debug, Default)]
pub struct SyncResponseProcessor {
    realms: BTreeMap<RealmId, ProcessedRealm>,
    limited_timelines: BTreeMap<RealmId, LimitedTimelineState>,
    to_device: VecDeque<ToDeviceMessage>,
    to_device_acks: BTreeMap<String, ToDeviceAck>,
    changed_device_lists: BTreeSet<String>,
    left_device_lists: BTreeSet<String>,
    presence: BTreeMap<String, PresenceEvent>,
    account_data: BTreeMap<String, AccountData>,
    notifications: BTreeMap<String, NotificationDelta>,
    last_token: Option<String>,
}

impl SyncResponseProcessor {
    /// Create an empty response processor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a full sync response into a delta and update local
    /// caches. `response` is the wire-shape [`SyncOutcome`]; per-event
    /// classes are projected out of the loose `Value` shape via the
    /// `project_typed_*` helpers so the wire layer doesn't have to
    /// commit to typed shapes that real servers may not emit.
    pub fn process(&mut self, response: SyncOutcome) -> Result<SyncUpdates> {
        self.last_token = Some(response.cursor);

        let mut realm_updates = Vec::new();
        for (raw_realm_id, raw_sync_realm) in response.realms {
            let realm_id = RealmId::new(raw_realm_id)?;
            let sync_realm: SyncRealm = serde_json::from_value(raw_sync_realm).unwrap_or_default();
            let processed = self.realms.entry(realm_id.clone()).or_default();
            if let Some(timeline) = &sync_realm.timeline {
                processed.timeline_events += timeline.events.len();
                processed.last_timeline = Some(timeline.clone());
                processed.last_limited = timeline.limited;
                processed.last_prev_cursor = timeline.prev_cursor.clone();
                if timeline.limited {
                    let limited = LimitedTimelineState::from_timeline(realm_id.clone(), timeline);
                    processed.limited_timeline_count += 1;
                    processed.pending_gap = limited.gap.clone();
                    self.limited_timelines.insert(realm_id.clone(), limited);
                }
            }
            processed.state_events += sync_realm.state.len();
            processed.summary = sync_realm.summary.clone();
            processed.notification_count = sync_realm.unread.notification_count;
            processed.highlight_count = sync_realm.unread.highlight_count;

            realm_updates.push(RealmUpdate {
                realm_id,
                timeline: sync_realm.timeline,
                state: sync_realm.state,
                summary: sync_realm.summary,
            });
        }

        let to_device: Vec<ToDeviceMessage> = project_typed_vec(response.to_device);
        let device_lists: DeviceListChanges =
            serde_json::from_value(response.device_lists).unwrap_or_default();
        let presence: Vec<PresenceEvent> = project_typed_vec(response.presence);
        let account_data: Vec<AccountData> = project_typed_vec(response.account_data);
        let notifications: Vec<NotificationDelta> =
            project_typed_vec_from_value(response.notifications);

        for message in &to_device {
            self.to_device.push_back(message.clone());
        }
        for user_id in &device_lists.changed {
            self.changed_device_lists.insert(user_id.clone());
        }
        for user_id in &device_lists.left {
            self.left_device_lists.insert(user_id.clone());
        }
        for event in &presence {
            self.presence.insert(event.user_id.clone(), event.clone());
        }
        for item in &account_data {
            self.account_data
                .insert(item.data_type.clone(), item.clone());
        }
        for notification in &notifications {
            self.notifications
                .insert(notification.id.clone(), notification.clone());
        }

        Ok(SyncUpdates {
            realm_updates,
            to_device,
            device_lists,
            presence,
            account_data,
            notifications,
            partial: response.partial,
        })
    }

    /// Get cached data for a processed Realm.
    pub fn realm(&self, realm_id: &RealmId) -> Option<&ProcessedRealm> {
        self.realms.get(realm_id)
    }

    /// Drain queued to-device messages in receive order.
    pub fn drain_to_device(&mut self) -> Vec<ToDeviceMessage> {
        self.to_device.drain(..).collect()
    }

    /// Acknowledge a to-device message by ID for the local device.
    pub fn acknowledge_to_device(
        &mut self,
        message_id: impl Into<String>,
        device_id: DeviceId,
        status: ToDeviceAckStatus,
    ) -> ToDeviceAck {
        let message_id = message_id.into();
        let ack = ToDeviceAck {
            message_id: message_id.clone(),
            device_id,
            status,
            acknowledged_at: Utc::now(),
        };
        self.to_device_acks.insert(message_id, ack.clone());
        ack
    }

    /// Get an acknowledgement for one to-device message.
    pub fn to_device_ack(&self, message_id: &str) -> Option<&ToDeviceAck> {
        self.to_device_acks.get(message_id)
    }

    /// Pending limited timeline sections that need backfill.
    pub fn limited_timelines(&self) -> Vec<&LimitedTimelineState> {
        self.limited_timelines.values().collect()
    }

    /// Last successfully processed sync token.
    pub fn last_token(&self) -> Option<&str> {
        self.last_token.as_deref()
    }

    /// Latest known presence for a user.
    pub fn presence(&self, user_id: &str) -> Option<&PresenceEvent> {
        self.presence.get(user_id)
    }

    /// Latest account data by type.
    pub fn account_data(&self, data_type: &str) -> Option<&AccountData> {
        self.account_data.get(data_type)
    }

    /// Latest notification by ID.
    pub fn notification(&self, id: &str) -> Option<&NotificationDelta> {
        self.notifications.get(id)
    }

    /// Merged device list changes seen so far.
    pub fn device_lists(&self) -> DeviceListChanges {
        DeviceListChanges {
            changed: self.changed_device_lists.iter().cloned().collect(),
            left: self.left_device_lists.iter().cloned().collect(),
        }
    }

    /// Clear all cached processor state.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Cached state for one processed Realm.
#[derive(Clone, Debug, Default)]
pub struct ProcessedRealm {
    /// Last timeline section received for this Realm.
    pub last_timeline: Option<SyncTimeline>,
    /// Total timeline events processed.
    pub timeline_events: usize,
    /// Total state events processed.
    pub state_events: usize,
    /// Last summary object.
    pub summary: Value,
    /// Current notification count.
    pub notification_count: u64,
    /// Current highlight count.
    pub highlight_count: u64,
    /// Last timeline section had `limited: true`.
    pub last_limited: bool,
    /// Last older-direction cursor from timeline pagination.
    pub last_prev_cursor: Option<String>,
    /// Number of limited timeline sections processed.
    pub limited_timeline_count: usize,
    /// Pending gap created by the latest limited timeline.
    pub pending_gap: Option<crate::sync::SyncGap>,
}
