use super::*;

/// Outbound send queue operation kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueItemKind {
    /// New message/event.
    Message,
    /// Message edit targeting an existing event.
    Edit { target_event_id: EventId },
    /// Redaction targeting an existing event.
    Redaction { target_event_id: EventId },
    /// Reaction add/remove targeting an existing event.
    Reaction { target_event_id: EventId, reaction_key: String, add: bool },
    /// Custom event kind.
    Custom { kind: String },
}

impl SendQueueItemKind {
    fn event_kind(&self) -> String {
        match self {
            Self::Message => "cx.message.create".to_owned(),
            Self::Edit { .. } => "cx.message.revise".to_owned(),
            Self::Redaction { .. } => "cx.message.redact".to_owned(),
            Self::Reaction { add, .. } if *add => "cx.reaction.add".to_owned(),
            Self::Reaction { .. } => "cx.reaction.remove".to_owned(),
            Self::Custom { kind } => kind.clone(),
        }
    }
}

/// Send queue item lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueStatus {
    /// Waiting for connectivity or dependencies.
    Queued,
    /// Currently being sent.
    Sending,
    /// Server accepted the transaction.
    Sent,
    /// Send failed and may be retried after `next_retry_at`.
    Failed,
    /// User or dependency cancellation.
    Cancelled,
}

/// Local echo projected before a queued item is sent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalEcho {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Stable local item ID for UI reconciliation.
    pub item_id: String,
    /// Space receiving the item.
    pub space_id: SpaceId,
    /// Event kind represented by the echo.
    pub event_kind: String,
    /// Echo content.
    pub content: Value,
    /// Local creation time.
    pub created_at: DateTime<Utc>,
    /// Current queue status.
    pub status: SendQueueStatus,
}

/// One queued outbound event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendQueueItem {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Target space.
    pub space_id: SpaceId,
    /// Operation kind.
    pub kind: SendQueueItemKind,
    /// Event content.
    pub content: Value,
    /// Canonical hash of the idempotent payload.
    pub payload_hash: String,
    /// Other transaction IDs that must be sent first.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Lifecycle status.
    pub status: SendQueueStatus,
    /// Number of send attempts.
    pub attempts: u32,
    /// Next retry time after a transient failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Server event ID once sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_event_id: Option<EventId>,
    /// Queue insertion order.
    pub sequence: u64,
    /// Local enqueue time.
    pub enqueued_at: DateTime<Utc>,
    /// Last lifecycle update time.
    pub updated_at: DateTime<Utc>,
    /// Local echo for UI consumers.
    pub local_echo: LocalEcho,
}

/// Serializable send queue state.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SendQueueSnapshot {
    /// Items in queue order.
    #[serde(default)]
    pub items: Vec<SendQueueItem>,
    /// Next insertion sequence.
    pub next_sequence: u64,
}

/// In-memory send queue with idempotent transaction semantics.
#[derive(Clone, Debug, Default)]
pub struct SendQueue {
    items: BTreeMap<String, SendQueueItem>,
    order: VecDeque<String>,
    next_sequence: u64,
}

impl SendQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a queue from a serialized snapshot.
    pub fn from_snapshot(snapshot: SendQueueSnapshot) -> Result<Self> {
        let mut queue = Self { next_sequence: snapshot.next_sequence, ..Self::default() };
        for item in snapshot.items {
            if queue.items.contains_key(&item.transaction_id) {
                return Err(Error::IdempotencyConflict(item.transaction_id));
            }
            queue.order.push_back(item.transaction_id.clone());
            queue.items.insert(item.transaction_id.clone(), item);
        }
        Ok(queue)
    }

    /// Export queue state for persistence by the embedding application.
    pub fn snapshot(&self) -> SendQueueSnapshot {
        SendQueueSnapshot {
            items: self
                .order
                .iter()
                .filter_map(|transaction_id| self.items.get(transaction_id).cloned())
                .collect(),
            next_sequence: self.next_sequence,
        }
    }

    /// Number of queued items in all states.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Enqueue a new message.
    pub fn enqueue_message(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        content: Value,
    ) -> Result<SendQueueItem> {
        self.enqueue(transaction_id, space_id, SendQueueItemKind::Message, content, Vec::new())
    }

    /// Enqueue a message edit.
    pub fn enqueue_edit(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Edit { target_event_id },
            content,
            depends_on,
        )
    }

    /// Enqueue a redaction.
    pub fn enqueue_redaction(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        reason: Option<String>,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        let content =
            reason.map(|reason| serde_json::json!({ "reason": reason })).unwrap_or(Value::Null);
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Redaction { target_event_id },
            content,
            depends_on,
        )
    }

    /// Enqueue a reaction add/remove.
    pub fn enqueue_reaction(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        target_event_id: EventId,
        reaction_key: String,
        add: bool,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            space_id,
            SendQueueItemKind::Reaction { target_event_id, reaction_key, add },
            Value::Null,
            depends_on,
        )
    }

    /// Enqueue an arbitrary outbound event.
    pub fn enqueue(
        &mut self,
        transaction_id: Option<String>,
        space_id: SpaceId,
        kind: SendQueueItemKind,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        let payload_hash = queue_payload_hash(&space_id, &kind, &content, &depends_on)?;
        let transaction_id = transaction_id
            .unwrap_or_else(|| format!("txn_{}", payload_hash.trim_start_matches("sha256:")));

        if let Some(existing) = self.items.get(&transaction_id) {
            if existing.payload_hash == payload_hash {
                return Ok(existing.clone());
            }
            return Err(Error::IdempotencyConflict(transaction_id));
        }

        let now = Utc::now();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event_kind = kind.event_kind();
        let local_echo = LocalEcho {
            transaction_id: transaction_id.clone(),
            item_id: format!("local:{}", transaction_id),
            space_id: space_id.clone(),
            event_kind,
            content: content.clone(),
            created_at: now,
            status: SendQueueStatus::Queued,
        };
        let item = SendQueueItem {
            transaction_id: transaction_id.clone(),
            space_id,
            kind,
            content,
            payload_hash,
            depends_on,
            status: SendQueueStatus::Queued,
            attempts: 0,
            next_retry_at: None,
            remote_event_id: None,
            sequence,
            enqueued_at: now,
            updated_at: now,
            local_echo,
        };
        self.order.push_back(transaction_id.clone());
        self.items.insert(transaction_id, item.clone());
        Ok(item)
    }

    /// Items ready to send now, in dependency-safe order.
    pub fn ready_batch(&self, now: DateTime<Utc>, limit: usize) -> Vec<SendQueueItem> {
        self.order
            .iter()
            .filter_map(|transaction_id| self.items.get(transaction_id))
            .filter(|item| self.is_ready(item, now))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get one queue item.
    pub fn get(&self, transaction_id: &str) -> Option<&SendQueueItem> {
        self.items.get(transaction_id)
    }

    /// Mark an item as actively sending.
    pub fn mark_sending(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Sending;
        item.attempts = item.attempts.saturating_add(1);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Mark an item as accepted by the server.
    pub fn mark_sent(&mut self, transaction_id: &str, remote_event_id: EventId) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Sent;
        item.remote_event_id = Some(remote_event_id);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Mark an item as failed and schedule retry.
    pub fn mark_failed(&mut self, transaction_id: &str, retry_after: Duration) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Failed;
        item.next_retry_at =
            Some(Utc::now() + chrono::Duration::from_std(retry_after).unwrap_or_default());
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Cancel an item, optionally cascading to dependent queued items.
    pub fn cancel(&mut self, transaction_id: &str, cascade: bool) -> Result<()> {
        self.cancel_one(transaction_id)?;
        if cascade {
            let dependents: Vec<_> = self
                .items
                .values()
                .filter(|item| {
                    item.depends_on.iter().any(|dependency| dependency == transaction_id)
                })
                .map(|item| item.transaction_id.clone())
                .collect();
            for dependent in dependents {
                self.cancel(&dependent, true)?;
            }
        }
        Ok(())
    }

    fn is_ready(&self, item: &SendQueueItem, now: DateTime<Utc>) -> bool {
        if !matches!(item.status, SendQueueStatus::Queued | SendQueueStatus::Failed) {
            return false;
        }
        if item.next_retry_at.map(|retry_at| retry_at > now).unwrap_or(false) {
            return false;
        }
        item.depends_on.iter().all(|dependency| {
            self.items
                .get(dependency)
                .map(|dependency| dependency.status == SendQueueStatus::Sent)
                .unwrap_or(false)
        })
    }

    fn item_mut(&mut self, transaction_id: &str) -> Result<&mut SendQueueItem> {
        self.items.get_mut(transaction_id).ok_or_else(|| {
            Error::Protocol(format!("send queue transaction not found: {}", transaction_id))
        })
    }

    fn cancel_one(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Cancelled;
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }
}

fn queue_payload_hash(
    space_id: &SpaceId,
    kind: &SendQueueItemKind,
    content: &Value,
    depends_on: &[String],
) -> Result<String> {
    canonical::canonical_sha256(&serde_json::json!({
        "space_id": space_id,
        "kind": kind,
        "content": content,
        "depends_on": depends_on,
    }))
}
