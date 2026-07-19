//! Membership / invite payload facade retained by `arkret-core`.
//!
//! The payload wire types migrated to `arkret-models-collaboration`
//! (re-exported below). The schema-catalog decode path stays here (it
//! needs `arkret-schema`) as [`InviteCreatePayloadWireExt`], so
//! `InviteCreatePayload::from_wire_value` keeps working for callers that
//! glob-import `arkret_core::models`.

pub use arkret_models_collaboration::governance::membership_invite::*;
use serde_json::Value;

use crate::{Error, Result, events, schema};

/// Schema-catalog-backed decode extension for [`InviteCreatePayload`].
pub trait InviteCreatePayloadWireExt: Sized {
    /// Validate an inbound `ak.invite.create` payload against the event
    /// payload schema catalog, enforce the closed key set, and decode.
    fn from_wire_value(value: &Value) -> Result<Self>;
}

impl InviteCreatePayloadWireExt for InviteCreatePayload {
    fn from_wire_value(value: &Value) -> Result<Self> {
        schema::event_payload_validator_catalog()?
            .validate_payload(events::kinds::EventKind::InviteCreate.as_str(), value)
            .map_err(|err| Error::Protocol(format!("invite create payload schema: {err}")))?;
        validate_invite_create_wire_keys(value)?;
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|err| Error::Protocol(format!("invite create payload decode: {err}")))?;
        payload.invite_delivery_target.validate()?;
        Ok(payload)
    }
}
