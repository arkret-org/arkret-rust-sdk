//! Original participant confirmation of an accepted Direct Conversation founding unit.

use std::collections::BTreeSet;

use arkret_wire::{ActorId, EventId, Hash, RealmId, Result, StrandId, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::objects::direct_conversation::DirectConversationAuthorizationBasis;

impl DirectConversationBoundPayload {
    pub fn validate_shape(&self) -> Result<()> {
        if self.unordered_participant_ids.len() != 2
            || self
                .unordered_participant_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != 2
        {
            return Err(WireError::Protocol(
                "Direct Conversation binding requires exactly two distinct participants".into(),
            ));
        }
        self.authorization_basis.validate_shape()
    }
}

impl DirectConversationBindingCurrentValue {
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.binding.validate_shape()
    }

    pub fn references(&self, event_id: &EventId) -> bool {
        &self.binding_event_ref == event_id
    }
}

include!("generated/direct_conversation_contracts.rs");
