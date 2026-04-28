//! Event handler registry and built-in handler collectors.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock, Weak},
};

use serde_json::Value;

use crate::{MemberChange, Presence, ReadReceipt, Result, TypingNotification};

/// Event delivered to registered handlers.
#[derive(Clone, Debug)]
pub enum ClientEvent {
    Presence(Presence),
    Typing(TypingNotification),
    Receipt(ReadReceipt),
    Membership(MemberChange),
    Custom { kind: String, payload: Value },
}

type HandlerCallback = Arc<dyn Fn(&ClientEvent) -> Result<()> + Send + Sync>;

#[derive(Clone)]
struct HandlerEntry {
    id: u64,
    name: String,
    callback: HandlerCallback,
}

#[derive(Default)]
struct HandlerState {
    next_id: u64,
    handlers: BTreeMap<u64, HandlerEntry>,
    errors: Vec<String>,
}

/// Event handler registry.
#[derive(Clone, Default)]
pub struct EventHandlerRegistry {
    state: Arc<RwLock<HandlerState>>,
}

impl EventHandlerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler and return a guard that unregisters on drop.
    pub fn register<F>(&self, name: impl Into<String>, handler: F) -> HandlerGuard
    where
        F: Fn(&ClientEvent) -> Result<()> + Send + Sync + 'static,
    {
        let mut state = self.state.write().unwrap();
        state.next_id += 1;
        let id = state.next_id;
        state
            .handlers
            .insert(id, HandlerEntry { id, name: name.into(), callback: Arc::new(handler) });
        HandlerGuard { id, state: Arc::downgrade(&self.state), active: true }
    }

    /// Unregister a handler by ID.
    pub fn unregister(&self, id: u64) -> bool {
        self.state.write().unwrap().handlers.remove(&id).is_some()
    }

    /// Process an event synchronously and collect errors.
    pub fn process_event(&self, event: &ClientEvent) -> Vec<String> {
        let handlers: Vec<_> = self.state.read().unwrap().handlers.values().cloned().collect();
        let mut errors = Vec::new();
        for handler in handlers {
            if let Err(error) = (handler.callback)(event) {
                let message = format!("handler {}({}) failed: {}", handler.name, handler.id, error);
                errors.push(message.clone());
                self.state.write().unwrap().errors.push(message);
            }
        }
        errors
    }

    /// Async-compatible processing entry point.
    pub async fn process_event_async(&self, event: ClientEvent) -> Vec<String> {
        self.process_event(&event)
    }

    /// Number of registered handlers.
    pub fn active_handlers(&self) -> usize {
        self.state.read().unwrap().handlers.len()
    }

    /// Collected handler errors.
    pub fn errors(&self) -> Vec<String> {
        self.state.read().unwrap().errors.clone()
    }

    /// Detect leaked handlers by returning active handler names.
    pub fn leaked_handlers(&self) -> Vec<String> {
        self.state.read().unwrap().handlers.values().map(|entry| entry.name.clone()).collect()
    }

    /// Register the built-in handler collector.
    pub fn register_builtins(&self, builtins: Arc<RwLock<BuiltInEventHandlers>>) -> HandlerGuard {
        self.register("builtins", move |event| {
            builtins.write().unwrap().handle(event.clone());
            Ok(())
        })
    }
}

/// Guard for a registered handler.
pub struct HandlerGuard {
    id: u64,
    state: Weak<RwLock<HandlerState>>,
    active: bool,
}

impl HandlerGuard {
    /// Handler ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Explicitly unregister.
    pub fn unregister(mut self) -> bool {
        self.active = false;
        self.state
            .upgrade()
            .map(|state| state.write().unwrap().handlers.remove(&self.id).is_some())
            .unwrap_or(false)
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(state) = self.state.upgrade() {
            state.write().unwrap().handlers.remove(&self.id);
        }
    }
}

/// Built-in event collectors.
#[derive(Clone, Debug, Default)]
pub struct BuiltInEventHandlers {
    pub presence: Vec<Presence>,
    pub typing: Vec<TypingNotification>,
    pub receipts: Vec<ReadReceipt>,
    pub membership: Vec<MemberChange>,
}

impl BuiltInEventHandlers {
    /// Handle one event.
    pub fn handle(&mut self, event: ClientEvent) {
        match event {
            ClientEvent::Presence(event) => self.presence.push(event),
            ClientEvent::Typing(event) => self.typing.push(event),
            ClientEvent::Receipt(event) => self.receipts.push(event),
            ClientEvent::Membership(event) => self.membership.push(event),
            ClientEvent::Custom { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;

    use super::*;
    use crate::{Did, PresenceStatus};

    #[test]
    fn event_handlers_register_process_unregister_and_guard_cleanup() {
        let registry = EventHandlerRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = calls.clone();
        let guard = registry.register("counter", move |_| {
            calls_for_handler.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        registry
            .process_event(&ClientEvent::Custom { kind: "test".to_owned(), payload: Value::Null });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(registry.active_handlers(), 1);

        drop(guard);
        assert_eq!(registry.active_handlers(), 0);
    }

    #[test]
    fn event_handlers_collect_errors_and_detect_leaks() {
        let registry = EventHandlerRegistry::new();
        let _guard =
            registry.register("failing", |_| Err(crate::Error::Protocol("boom".to_owned())));

        let errors = registry
            .process_event(&ClientEvent::Custom { kind: "test".to_owned(), payload: Value::Null });
        assert_eq!(errors.len(), 1);
        assert_eq!(registry.leaked_handlers(), vec!["failing".to_owned()]);
    }

    #[tokio::test]
    async fn event_handlers_support_async_entrypoint() {
        let registry = EventHandlerRegistry::new();
        let _guard = registry.register("ok", |_| Ok(()));
        let errors = registry
            .process_event_async(ClientEvent::Custom {
                kind: "async".to_owned(),
                payload: Value::Null,
            })
            .await;
        assert!(errors.is_empty());
    }

    #[test]
    fn builtins_collect_presence_typing_receipt_and_membership() {
        let registry = EventHandlerRegistry::new();
        let builtins = Arc::new(RwLock::new(BuiltInEventHandlers::default()));
        let _guard = registry.register_builtins(builtins.clone());
        let user_id = Did::new("did:web:alice.example").unwrap();

        registry.process_event(&ClientEvent::Presence(Presence {
            user_id,
            status: PresenceStatus::Online,
            last_active: Some(Utc::now()),
            active_device: None,
            status_msg: None,
        }));

        assert_eq!(builtins.read().unwrap().presence.len(), 1);
    }
}
