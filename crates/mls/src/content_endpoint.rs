//! Original endpoint lookup from independently accepted historical leaf
//! bindings. No private MLS provider or member-held state is required.

use arkret_models_crypto::MlsEndpointIdentity;
use arkret_wire::{MlsWelcomeRecipientEndpoint, ScopeRef};

use crate::{MlsError as Error, MlsVerifiedLeafBinding, Result};

/// Resolve one exact original endpoint from a complete, verified epoch roster.
/// The caller authenticates the original with its native Event key separately;
/// that key may differ from the MLS leaf key returned here. This pure lookup
/// does not confer native authority, membership or content-read permission.
pub fn content_endpoint_from_verified_roster<'a>(
    scope: &ScopeRef,
    bindings: impl IntoIterator<Item = &'a MlsVerifiedLeafBinding>,
    event: &arkret_wire::Event,
) -> Result<arkret_models_crypto::ContentEndpoint> {
    if event.scope_ref != *scope {
        return Err(Error::Protocol(
            "content original belongs to another scope".into(),
        ));
    }
    let method = &event
        .producer_proof
        .as_ref()
        .ok_or_else(|| Error::Protocol("content original omits producer proof".into()))?
        .verification_method;
    let device = method
        .as_str()
        .split_once('#')
        .filter(|(_, fragment)| fragment.starts_with("ak:device:"))
        .map(|(_, fragment)| arkret_wire::DeviceId::new(fragment.to_owned()))
        .transpose()?;
    let mut matches = bindings.into_iter().filter(|binding| {
        if &binding.actor_id != event.actual_signer() {
            return false;
        }
        match (&binding.endpoint, &device) {
            (MlsEndpointIdentity::HumanDevice { device_id, .. }, Some(device)) => {
                device_id == device
            }
            (
                MlsEndpointIdentity::AgentRuntime {
                    verification_method,
                    ..
                },
                None,
            ) => verification_method == method,
            _ => false,
        }
    });
    let binding = matches
        .next()
        .ok_or_else(|| Error::Protocol("original producer has no accepted leaf".into()))?;
    if matches.next().is_some() {
        return Err(Error::Protocol(
            "original producer has ambiguous accepted leaves".into(),
        ));
    }
    let (endpoint, authorization_event_ref) = match &binding.endpoint {
        MlsEndpointIdentity::HumanDevice { device_id, .. } => (
            MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            },
            binding.device_authorize_event_id.clone().ok_or_else(|| {
                Error::Protocol("original Device leaf omits authorization".into())
            })?,
        ),
        MlsEndpointIdentity::AgentRuntime {
            verification_method,
            agent_key_authorize_event_id,
            ..
        } => (
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: verification_method.clone(),
            },
            agent_key_authorize_event_id.clone(),
        ),
    };
    Ok(arkret_models_crypto::ContentEndpoint {
        actor_id: binding.actor_id.clone(),
        endpoint,
        authorization_event_ref,
        signature_key_base64url: binding.signature_key.as_str().to_owned(),
    })
}
