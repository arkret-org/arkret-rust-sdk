//! Applet service transaction envelope.
//!
//! The envelope embeds [`AppletTransactionRequestBody`], which carries wire
//! `Event`s alongside an optional `SignalEnvelope` batch.

use arkret_wire::{DidCoreId, Event};
use serde::{Deserialize, Serialize};

use crate::http_bodies::AppletTransactionRequestBody;

/// Applet service transaction with an explicit idempotency key.
///
/// Deduplication of these deliveries lives in one place:
/// `arkret_server::IdempotencyWindow`, keyed by the spec 5-tuple
/// `arkret_server::IdempotencyIdentity` (`applet-integration.md`
/// §7.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletServiceTransaction {
    pub idempotency_key: String,
    pub request: AppletTransactionRequestBody,
}

/// Applet service intent for acting as a virtual actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletServiceIntent {
    pub service_id: DidCoreId,
    pub actor_id: DidCoreId,
    pub idempotency_prefix: String,
}

impl AppletServiceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_id: DidCoreId, actor_id: DidCoreId) -> Self {
        Self {
            service_id,
            actor_id,
            idempotency_prefix: "applet_txn".to_owned(),
        }
    }

    /// Build an idempotent transaction envelope for events produced by this intent.
    pub fn transaction(
        &self,
        idempotency_key: impl AsRef<str>,
        events: Vec<Event>,
    ) -> AppletServiceTransaction {
        AppletServiceTransaction {
            idempotency_key: format!("{}:{}", self.idempotency_prefix, idempotency_key.as_ref()),
            request: AppletTransactionRequestBody {
                source_service_id: self.service_id.clone(),
                events,
                signals: None,
            },
        }
    }
}
