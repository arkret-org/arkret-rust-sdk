//! `ServiceDescribe.supported_bindings` entry for
//! `ak.profile.binding.websocket.v1` (`zh/sync/websocket-binding.md` §2).
//!
//! The descriptor is closed and complete: every const-valued member is typed
//! as a one-variant enum, so an unknown `kind`, a partial `operations` list, a
//! non-canonical `wss` URL or a missing limit fails at parse or validation
//! time. §2 requires a client that hits any of those to **ignore the binding
//! and stay on canonical HTTP**, never to guess an endpoint — that is what
//! [`select_websocket_binding`] does.

use arkret_wire::websocket_binding::{
    WEBSOCKET_BINDING_KIND, WEBSOCKET_HARD_MAX_FRAME_BYTES, WebSocketOperationId,
    validate_websocket_base_url,
};
use arkret_wire::{ProfileId, Result, WireError};
use serde::{Deserialize, Serialize};

use crate::service_description::{ServiceDescribe, SupportedBinding};

/// `kind` discriminator of this binding entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketBindingKind {
    #[default]
    Websocket,
}

/// `extension_profile_required`; the only accepted value is the profile id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketBindingProfile {
    #[default]
    #[serde(rename = "ak.profile.binding.websocket.v1")]
    BindingWebsocketV1,
}

/// `subprotocol`; the client MUST request and the server MUST select it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketBindingSubprotocol {
    #[default]
    #[serde(rename = "arkret.v1")]
    ArkretV1,
}

/// `authentication`; the only registered scheme for this binding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketBindingAuthentication {
    #[default]
    ChallengeDpopSessionV1,
}

/// Closed `supported_bindings` entry for the WebSocket profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketBindingDescriptor {
    pub kind: WebSocketBindingKind,
    pub base_url: String,
    pub operations: Vec<WebSocketOperationId>,
    pub extension_profile_required: WebSocketBindingProfile,
    pub subprotocol: WebSocketBindingSubprotocol,
    pub authentication: WebSocketBindingAuthentication,
    pub max_frame_bytes: u32,
    pub max_channels: u32,
}

impl WebSocketBindingDescriptor {
    /// Build the descriptor a service advertises once its conformance run is
    /// green. Every const member is filled in from the profile constants.
    pub fn new(base_url: impl Into<String>, max_frame_bytes: u32, max_channels: u32) -> Self {
        Self {
            kind: WebSocketBindingKind::Websocket,
            base_url: base_url.into(),
            operations: WebSocketOperationId::ALL.to_vec(),
            extension_profile_required: WebSocketBindingProfile::BindingWebsocketV1,
            subprotocol: WebSocketBindingSubprotocol::ArkretV1,
            authentication: WebSocketBindingAuthentication::ChallengeDpopSessionV1,
            max_frame_bytes,
            max_channels,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_websocket_base_url(&self.base_url)?;
        for expected in WebSocketOperationId::ALL {
            if !self.operations.contains(expected) {
                return Err(WireError::Protocol(format!(
                    "a websocket binding that omits {expected} is not \
                     {}",
                    ProfileId::BINDING_WEBSOCKET_V1
                )));
            }
        }
        if self.operations.len() != WebSocketOperationId::ALL.len() {
            return Err(WireError::Protocol(
                "the websocket binding operations list must be the three covered operations"
                    .to_owned(),
            ));
        }
        if self.max_frame_bytes < 1024
            || self.max_frame_bytes as usize > WEBSOCKET_HARD_MAX_FRAME_BYTES
        {
            return Err(WireError::Protocol(format!(
                "websocket max_frame_bytes must be 1024..={WEBSOCKET_HARD_MAX_FRAME_BYTES}"
            )));
        }
        if self.max_channels == 0 || self.max_channels > 256 {
            return Err(WireError::Protocol(
                "websocket max_channels must be 1..=256".to_owned(),
            ));
        }
        Ok(())
    }

    /// Erase back into the loosely-typed discovery entry.
    pub fn to_supported_binding(&self) -> Result<SupportedBinding> {
        self.validate()?;
        let mut binding =
            SupportedBinding::new(WEBSOCKET_BINDING_KIND).with_base_url(self.base_url.clone());
        binding.extra.insert(
            "operations".to_owned(),
            serde_json::to_value(&self.operations)?,
        );
        binding.extra.insert(
            "extension_profile_required".to_owned(),
            serde_json::to_value(self.extension_profile_required)?,
        );
        binding.extra.insert(
            "subprotocol".to_owned(),
            serde_json::to_value(self.subprotocol)?,
        );
        binding.extra.insert(
            "authentication".to_owned(),
            serde_json::to_value(self.authentication)?,
        );
        binding.extra.insert(
            "max_frame_bytes".to_owned(),
            serde_json::to_value(self.max_frame_bytes)?,
        );
        binding.extra.insert(
            "max_channels".to_owned(),
            serde_json::to_value(self.max_channels)?,
        );
        Ok(binding)
    }

    /// Reparse a discovery entry into the closed descriptor.
    pub fn from_supported_binding(binding: &SupportedBinding) -> Result<Self> {
        let descriptor: Self = serde_json::from_value(serde_json::to_value(binding)?)?;
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// The WebSocket binding a client may use, or `None` to stay on canonical
/// HTTP/JSON + bounded NDJSON.
///
/// An entry that does not parse, does not validate, or that this build's own
/// frame limit cannot honour is skipped silently: §2 makes an unusable
/// descriptor a fallback condition, not an error.
pub fn select_websocket_binding(
    description: &ServiceDescribe,
    client_max_frame_bytes: u32,
) -> Option<WebSocketBindingDescriptor> {
    description
        .supported_bindings
        .iter()
        .filter(|binding| binding.kind == WEBSOCKET_BINDING_KIND)
        .find_map(|binding| {
            let descriptor = WebSocketBindingDescriptor::from_supported_binding(binding).ok()?;
            (descriptor.max_frame_bytes <= client_max_frame_bytes).then_some(descriptor)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> WebSocketBindingDescriptor {
        WebSocketBindingDescriptor::new("wss://server.example/_arkret/ws", 2048, 16)
    }

    #[test]
    fn the_closed_descriptor_round_trips_through_discovery() {
        let original = descriptor();
        let binding = original.to_supported_binding().unwrap();
        assert_eq!(
            WebSocketBindingDescriptor::from_supported_binding(&binding).unwrap(),
            original
        );
    }

    #[test]
    fn a_partial_operation_list_is_not_this_profile() {
        let mut partial = descriptor();
        partial
            .operations
            .retain(|operation| *operation != WebSocketOperationId::SignalStreamSubscribe);
        partial.validate().unwrap_err();
    }

    #[test]
    fn a_noncanonical_url_is_rejected() {
        for base_url in [
            "ws://server.example/_arkret/ws",
            "wss://server.example:443/_arkret/ws",
            "wss://SERVER.example/_arkret/ws",
            "wss://server.example/_arkret/../ws",
            "wss://server.example/_arkret/ws?grant=secret",
        ] {
            WebSocketBindingDescriptor::new(base_url, 2048, 16)
                .validate()
                .expect_err(&format!("{base_url} must not be advertised"));
        }
    }

    #[test]
    fn a_descriptor_missing_a_required_member_never_parses() {
        let mut binding = descriptor().to_supported_binding().unwrap();
        for removed in [
            "subprotocol",
            "authentication",
            "max_frame_bytes",
            "max_channels",
        ] {
            let mut incomplete = binding.clone();
            incomplete.extra.remove(removed);
            WebSocketBindingDescriptor::from_supported_binding(&incomplete).expect_err(&format!(
                "a descriptor without {removed} is not this profile"
            ));
        }
        binding.extra.insert("unknown".to_owned(), true.into());
        WebSocketBindingDescriptor::from_supported_binding(&binding)
            .expect_err("the descriptor is closed");
    }
}
