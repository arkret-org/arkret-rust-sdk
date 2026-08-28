//! Typed helpers for the WebSocket member of
//! `ServiceDescribe.transport_bindings`.

use arkret_wire::websocket_binding::{
    WEBSOCKET_HARD_MAX_FRAME_BYTES, WebSocketOperationId, validate_websocket_base_url,
};
use arkret_wire::{
    BindingKind, OPERATION_BUNDLES, OperationBundleDescriptor, Result, ServiceOperationId,
    WireError,
};
use serde::{Deserialize, Serialize};

use crate::service_description::{ServiceDescribe, TransportBinding};

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketBindingProfile {
    #[default]
    #[serde(rename = "ak.profile.binding.websocket.v1")]
    BindingWebsocketV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketBindingSubprotocol {
    #[default]
    #[serde(rename = "arkret.v1")]
    ArkretV1,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketBindingAuthentication {
    #[default]
    ChallengeDpopSessionV1,
}

/// Validate one canonical typed WebSocket transport declaration.
pub fn validate_websocket_transport(binding: &TransportBinding) -> Result<()> {
    let TransportBinding::Websocket {
        base_url,
        max_frame_bytes,
        max_channels,
        ..
    } = binding
    else {
        return Err(WireError::Protocol(
            "expected a websocket transport binding".to_owned(),
        ));
    };

    validate_websocket_base_url(base_url)?;
    if *max_frame_bytes < 1024 || *max_frame_bytes as usize > WEBSOCKET_HARD_MAX_FRAME_BYTES {
        return Err(WireError::Protocol(format!(
            "websocket max_frame_bytes must be 1024..={WEBSOCKET_HARD_MAX_FRAME_BYTES}"
        )));
    }
    if *max_channels == 0 || *max_channels > 256 {
        return Err(WireError::Protocol(
            "websocket max_channels must be 1..=256".to_owned(),
        ));
    }
    Ok(())
}

/// Whether the advertised bundle closure makes every profile operation
/// reachable over the WebSocket binding.
///
/// `websocket-binding.md` 2 moves operation reachability out of the transport
/// descriptor and onto `ServiceDescribe.supported_operation_bundles`: the
/// descriptor is a closed object with no `operations[]`, so the only way to
/// learn whether all three streaming operations are callable over WebSocket is
/// to expand the advertised bundles. A describe that advertises the transport
/// without the bundle is a partial claim and MUST fall back to HTTP.
pub fn websocket_operations_reachable(description: &ServiceDescribe) -> bool {
    let advertised: Vec<&OperationBundleDescriptor> = OPERATION_BUNDLES
        .iter()
        .filter(|bundle| {
            description
                .supported_operation_bundles
                .iter()
                .any(|id| id == bundle.operation_bundle_id)
        })
        .collect();
    WebSocketOperationId::ALL.iter().all(|operation| {
        let Some(operation_id) = ServiceOperationId::from_wire(operation.as_str()) else {
            return false;
        };
        advertised
            .iter()
            .any(|bundle| bundle.contains(operation_id, BindingKind::Websocket))
    })
}

/// Select a usable canonical WebSocket transport, otherwise remain on HTTP.
pub fn select_websocket_binding(
    description: &ServiceDescribe,
    client_max_frame_bytes: u32,
) -> Option<&TransportBinding> {
    if !websocket_operations_reachable(description) {
        return None;
    }
    description.transport_bindings.iter().find(|binding| {
        let TransportBinding::Websocket {
            max_frame_bytes, ..
        } = binding
        else {
            return false;
        };
        *max_frame_bytes <= client_max_frame_bytes && validate_websocket_transport(binding).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(base_url: &str) -> TransportBinding {
        TransportBinding::Websocket {
            base_url: base_url.to_owned(),
            extension_profile_required: WebSocketBindingProfile::BindingWebsocketV1,
            subprotocol: WebSocketBindingSubprotocol::ArkretV1,
            authentication: WebSocketBindingAuthentication::ChallengeDpopSessionV1,
            max_frame_bytes: 2048,
            max_channels: 16,
        }
    }

    #[test]
    fn canonical_transport_validates() {
        validate_websocket_transport(&binding("wss://server.example/_arkret/ws")).unwrap();
    }

    #[test]
    fn noncanonical_urls_are_rejected() {
        for base_url in [
            "ws://server.example/_arkret/ws",
            "wss://server.example:443/_arkret/ws",
            "wss://SERVER.example/_arkret/ws",
            "wss://server.example/_arkret/../ws",
            "wss://server.example/_arkret/ws?grant=secret",
        ] {
            validate_websocket_transport(&binding(base_url))
                .expect_err(&format!("{base_url} must not be advertised"));
        }
    }
}
