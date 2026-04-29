//! Event handler registry and built-in handler collectors.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
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

impl ClientEvent {
    /// Return the typed kind used by handler filters.
    pub fn kind(&self) -> ClientEventKind {
        match self {
            Self::Presence(_) => ClientEventKind::Presence,
            Self::Typing(_) => ClientEventKind::Typing,
            Self::Receipt(_) => ClientEventKind::Receipt,
            Self::Membership(_) => ClientEventKind::Membership,
            Self::Custom { kind, .. } => ClientEventKind::CustomKind(kind.clone()),
        }
    }
}

/// Typed event kind for handler registration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientEventKind {
    Presence,
    Typing,
    Receipt,
    Membership,
    Custom,
    CustomKind(String),
}

/// Handler filter over typed client events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEventFilter {
    All,
    Kinds(BTreeSet<ClientEventKind>),
}

impl ClientEventFilter {
    /// Match all events.
    pub fn all() -> Self {
        Self::All
    }

    /// Match a fixed set of event kinds.
    pub fn kinds(kinds: impl IntoIterator<Item = ClientEventKind>) -> Self {
        Self::Kinds(kinds.into_iter().collect())
    }

    /// Match one custom event kind.
    pub fn custom_kind(kind: impl Into<String>) -> Self {
        Self::Kinds(BTreeSet::from([ClientEventKind::CustomKind(kind.into())]))
    }

    /// Check whether the filter accepts an event.
    pub fn matches(&self, event: &ClientEvent) -> bool {
        match self {
            Self::All => true,
            Self::Kinds(kinds) => match event {
                ClientEvent::Custom { kind, .. } => {
                    kinds.contains(&ClientEventKind::Custom)
                        || kinds.contains(&ClientEventKind::CustomKind(kind.clone()))
                }
                _ => kinds.contains(&event.kind()),
            },
        }
    }
}

impl Default for ClientEventFilter {
    fn default() -> Self {
        Self::All
    }
}

type HandlerCallback = Arc<dyn Fn(&ClientEvent) -> Result<()> + Send + Sync>;

#[derive(Clone)]
struct HandlerEntry {
    id: u64,
    name: String,
    filter: ClientEventFilter,
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
        self.register_filtered(name, ClientEventFilter::All, handler)
    }

    /// Register a handler with a typed event filter.
    pub fn register_filtered<F>(
        &self,
        name: impl Into<String>,
        filter: ClientEventFilter,
        handler: F,
    ) -> HandlerGuard
    where
        F: Fn(&ClientEvent) -> Result<()> + Send + Sync + 'static,
    {
        let mut state = self.state.write().unwrap();
        state.next_id += 1;
        let id = state.next_id;
        state.handlers.insert(
            id,
            HandlerEntry { id, name: name.into(), filter, callback: Arc::new(handler) },
        );
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
            if !handler.filter.matches(event) {
                continue;
            }
            if let Err(error) = (handler.callback)(event) {
                let message = format!("handler {}({}) failed: {}", handler.name, handler.id, error);
                errors.push(message.clone());
                self.state.write().unwrap().errors.push(message);
            }
        }
        errors
    }

    /// Async-compatible processing entry point.
    #[allow(clippy::unused_async)]
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

type EventPreprocessor = Arc<dyn Fn(ClientEvent) -> Result<Option<ClientEvent>> + Send + Sync>;
type EventFilterCallback = Arc<dyn Fn(&ClientEvent) -> Result<bool> + Send + Sync>;

/// Ordered preprocessor and filter pipeline for bot events.
#[derive(Clone, Default)]
pub struct EventPipeline {
    preprocessors: Arc<RwLock<Vec<EventPreprocessor>>>,
    filters: Arc<RwLock<Vec<EventFilterCallback>>>,
}

impl EventPipeline {
    /// Create an empty event pipeline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an event preprocessor. Returning `None` drops the event.
    pub fn add_preprocessor<F>(&self, preprocessor: F)
    where
        F: Fn(ClientEvent) -> Result<Option<ClientEvent>> + Send + Sync + 'static,
    {
        self.preprocessors.write().unwrap().push(Arc::new(preprocessor));
    }

    /// Add an event filter. Returning `false` drops the event.
    pub fn add_filter<F>(&self, filter: F)
    where
        F: Fn(&ClientEvent) -> Result<bool> + Send + Sync + 'static,
    {
        self.filters.write().unwrap().push(Arc::new(filter));
    }

    /// Run one event through the pipeline.
    pub fn process(&self, event: ClientEvent) -> Result<Option<ClientEvent>> {
        let mut current = Some(event);

        let preprocessors = self.preprocessors.read().unwrap().clone();
        for preprocessor in preprocessors {
            let Some(event) = current.take() else {
                return Ok(None);
            };
            current = preprocessor(event)?;
        }

        let Some(event) = current else {
            return Ok(None);
        };

        let filters = self.filters.read().unwrap().clone();
        for filter in filters {
            if !filter(&event)? {
                return Ok(None);
            }
        }

        Ok(Some(event))
    }
}

/// Parsed bot command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotCommand {
    pub prefix: String,
    pub name: String,
    pub args: Vec<String>,
    pub raw: String,
}

/// Prefix-based bot command parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotCommandParser {
    prefixes: Vec<String>,
}

impl BotCommandParser {
    /// Create a parser for one command prefix.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefixes: vec![prefix.into()] }
    }

    /// Create a parser that accepts multiple prefixes.
    pub fn with_prefixes(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { prefixes: prefixes.into_iter().map(Into::into).collect() }
    }

    /// Parse a text command.
    pub fn parse(&self, input: &str) -> Option<BotCommand> {
        let trimmed = input.trim_start();
        let prefix = self.prefixes.iter().find(|prefix| trimmed.starts_with(prefix.as_str()))?;
        let command_text = trimmed[prefix.len()..].trim();
        if command_text.is_empty() {
            return None;
        }

        let mut parts = command_text.split_whitespace();
        let name = parts.next()?.to_ascii_lowercase();
        let args = parts.map(str::to_owned).collect();
        Some(BotCommand { prefix: prefix.clone(), name, args, raw: trimmed.to_owned() })
    }

    /// Parse a command from a custom message event payload.
    pub fn parse_event(&self, event: &ClientEvent) -> Option<BotCommand> {
        let ClientEvent::Custom { payload, .. } = event else {
            return None;
        };
        let text = payload
            .get("body")
            .or_else(|| payload.get("text"))
            .or_else(|| payload.get("content").and_then(|content| content.get("body")))
            .and_then(Value::as_str)?;
        self.parse(text)
    }
}

/// Shutdown handle for a bot runtime loop.
#[derive(Clone, Default)]
pub struct BotRuntimeShutdown {
    stop: Arc<AtomicBool>,
}

impl BotRuntimeShutdown {
    /// Request graceful shutdown.
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Check whether shutdown was requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Processing counters from a bot runtime run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BotRuntimeReport {
    pub processed: usize,
    pub dropped: usize,
    pub errors: Vec<String>,
}

/// Minimal bot runtime wiring a pipeline to an event registry.
#[derive(Clone, Default)]
pub struct BotRuntime {
    registry: EventHandlerRegistry,
    pipeline: EventPipeline,
    shutdown: BotRuntimeShutdown,
}

impl BotRuntime {
    /// Create a runtime from an event registry and pipeline.
    pub fn new(registry: EventHandlerRegistry, pipeline: EventPipeline) -> Self {
        Self { registry, pipeline, shutdown: BotRuntimeShutdown::default() }
    }

    /// Get a graceful shutdown handle.
    pub fn shutdown_handle(&self) -> BotRuntimeShutdown {
        self.shutdown.clone()
    }

    /// Process a single event through the pipeline and registry.
    pub fn process_event(&self, event: ClientEvent) -> BotRuntimeReport {
        if self.shutdown.is_shutdown_requested() {
            return BotRuntimeReport { dropped: 1, ..BotRuntimeReport::default() };
        }

        match self.pipeline.process(event) {
            Ok(Some(event)) => BotRuntimeReport {
                processed: 1,
                errors: self.registry.process_event(&event),
                ..BotRuntimeReport::default()
            },
            Ok(None) => BotRuntimeReport { dropped: 1, ..BotRuntimeReport::default() },
            Err(error) => BotRuntimeReport {
                dropped: 1,
                errors: vec![error.to_string()],
                ..BotRuntimeReport::default()
            },
        }
    }

    /// Run a pull-based event loop until no event remains or shutdown is requested.
    pub fn run_until_idle<F>(&self, mut next_event: F) -> BotRuntimeReport
    where
        F: FnMut() -> Option<ClientEvent>,
    {
        let mut report = BotRuntimeReport::default();
        while !self.shutdown.is_shutdown_requested() {
            let Some(event) = next_event() else {
                break;
            };
            let current = self.process_event(event);
            report.processed += current.processed;
            report.dropped += current.dropped;
            report.errors.extend(current.errors);
        }
        report
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

    #[test]
    fn event_handlers_support_typed_filters() {
        let registry = EventHandlerRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = calls.clone();
        let _guard = registry.register_filtered(
            "custom-command",
            ClientEventFilter::custom_kind("message"),
            move |_| {
                calls_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        registry.process_event(&ClientEvent::Presence(Presence {
            user_id: Did::new("did:web:alice.example").unwrap(),
            status: PresenceStatus::Online,
            last_active: Some(Utc::now()),
            active_device: None,
            status_msg: None,
        }));
        registry.process_event(&ClientEvent::Custom {
            kind: "message".to_owned(),
            payload: serde_json::json!({"body": "!ping"}),
        });

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bot_command_parser_extracts_commands_from_text_and_events() {
        let parser = BotCommandParser::new("!");
        let command = parser.parse(" !Echo hello world").unwrap();
        assert_eq!(command.name, "echo");
        assert_eq!(command.args, vec!["hello".to_owned(), "world".to_owned()]);

        let event = ClientEvent::Custom {
            kind: "message".to_owned(),
            payload: serde_json::json!({"content": {"body": "!help"}}),
        };
        assert_eq!(parser.parse_event(&event).unwrap().name, "help");
    }

    #[test]
    fn bot_runtime_runs_pipeline_and_stops_gracefully() {
        let registry = EventHandlerRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = calls.clone();
        let _guard = registry.register("counter", move |_| {
            calls_for_handler.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let pipeline = EventPipeline::new();
        pipeline.add_filter(|event| {
            Ok(!matches!(
                event,
                ClientEvent::Custom { kind, .. } if kind == "drop"
            ))
        });
        pipeline.add_preprocessor(|event| match event {
            ClientEvent::Custom { kind, payload } if kind == "upper" => Ok(Some(ClientEvent::Custom {
                kind,
                payload: serde_json::json!({"body": payload["body"].as_str().unwrap_or("").to_uppercase()}),
            })),
            event => Ok(Some(event)),
        });
        let runtime = BotRuntime::new(registry, pipeline);
        let shutdown = runtime.shutdown_handle();
        let mut events = vec![
            ClientEvent::Custom { kind: "drop".to_owned(), payload: Value::Null },
            ClientEvent::Custom {
                kind: "upper".to_owned(),
                payload: serde_json::json!({"body": "ok"}),
            },
        ]
        .into_iter();

        let report = runtime.run_until_idle(|| events.next());
        assert_eq!(report.processed, 1);
        assert_eq!(report.dropped, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        shutdown.request_shutdown();
        let report = runtime.process_event(ClientEvent::Custom {
            kind: "message".to_owned(),
            payload: Value::Null,
        });
        assert_eq!(report.dropped, 1);
    }
}
