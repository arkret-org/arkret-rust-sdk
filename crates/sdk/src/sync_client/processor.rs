use super::*;

/// Processed sync response cache and dispatcher.
#[derive(Clone, Debug, Default)]
pub struct SyncResponseProcessor {
    spaces: BTreeMap<SpaceId, ProcessedSpace>,
    limited_timelines: BTreeMap<SpaceId, LimitedTimelineState>,
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

    /// Process a full sync response into a delta and update local caches.
    pub fn process(&mut self, response: SyncResponse) -> Result<SyncUpdates> {
        self.last_token = Some(response.next_batch);

        let mut space_updates = Vec::new();
        for (raw_space_id, sync_space) in response.spaces {
            let space_id = SpaceId::new(raw_space_id)?;
            let processed = self.spaces.entry(space_id.clone()).or_default();
            if let Some(timeline) = &sync_space.timeline {
                processed.timeline_events += timeline.events.len();
                processed.last_timeline = Some(timeline.clone());
                processed.last_limited = timeline.limited;
                processed.last_prev_batch = timeline.prev_batch.clone();
                if timeline.limited {
                    let limited = LimitedTimelineState::from_timeline(space_id.clone(), timeline);
                    processed.limited_timeline_count += 1;
                    processed.pending_gap = limited.gap.clone();
                    self.limited_timelines.insert(space_id.clone(), limited);
                }
            }
            processed.state_events += sync_space.state.len();
            processed.summary = sync_space.summary.clone();
            processed.notification_count = sync_space.unread.notification_count;
            processed.highlight_count = sync_space.unread.highlight_count;

            space_updates.push(SpaceUpdate {
                space_id,
                timeline: sync_space.timeline,
                state: sync_space.state,
                summary: sync_space.summary,
            });
        }

        for message in &response.to_device {
            self.to_device.push_back(message.clone());
        }
        for user_id in &response.device_lists.changed {
            self.changed_device_lists.insert(user_id.clone());
        }
        for user_id in &response.device_lists.left {
            self.left_device_lists.insert(user_id.clone());
        }
        for event in &response.presence {
            self.presence.insert(event.user_id.clone(), event.clone());
        }
        for item in &response.account_data {
            self.account_data.insert(item.data_type.clone(), item.clone());
        }
        for notification in &response.notifications {
            self.notifications.insert(notification.id.clone(), notification.clone());
        }

        Ok(SyncUpdates {
            space_updates,
            to_device: response.to_device,
            device_lists: response.device_lists,
            presence: response.presence,
            account_data: response.account_data,
            notifications: response.notifications,
            partial: response.partial,
        })
    }

    /// Get cached data for a processed space.
    pub fn space(&self, space_id: &SpaceId) -> Option<&ProcessedSpace> {
        self.spaces.get(space_id)
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

/// Cached state for one processed space.
#[derive(Clone, Debug, Default)]
pub struct ProcessedSpace {
    /// Last timeline section received for this space.
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
    /// Last previous-batch token from timeline pagination.
    pub last_prev_batch: Option<String>,
    /// Number of limited timeline sections processed.
    pub limited_timeline_count: usize,
    /// Pending gap created by the latest limited timeline.
    pub pending_gap: Option<crate::sync::SyncGap>,
}

