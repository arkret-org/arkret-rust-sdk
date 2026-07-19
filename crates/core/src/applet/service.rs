//! Applet service transaction envelope retained by `arkret-core`.
//!
//! The framework-neutral route declarations migrated to
//! `arkret-models-integration` (re-exported via the parent module). The
//! transaction envelope stays: it embeds
//! [`AppletTransactionRequestBody`], whose `ephemeral` member is the
//! collaboration-owned `EphemeralEnvelope`.

use serde::{Deserialize, Serialize};

use crate::models::AppletTransactionRequestBody;
use crate::{Did, Event};

/// Applet service transaction with an explicit idempotency key.
///
/// Deduplication of these deliveries lives in one place:
/// [`arkret_server::IdempotencyWindow`], keyed by the spec 5-tuple
/// [`arkret_server::IdempotencyIdentity`] (`applet-integration.md`
/// §7.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletServiceTransaction {
    pub idempotency_key: String,
    pub request: AppletTransactionRequestBody,
}

/// Applet service intent for acting as a virtual actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletServiceIntent {
    pub service_id: Did,
    pub actor_id: Did,
    pub idempotency_prefix: String,
}

impl AppletServiceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_id: Did, actor_id: Did) -> Self {
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
                ephemeral: None,
            },
        }
    }
}
