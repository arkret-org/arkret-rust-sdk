//! Host-local endpoint evidence retained with the immutable creator pin.

use arkret_models_identity::signer_key_operations::{
    CurrentSignerKeyQuerySender, ResolvedSignerKey, SignerKeyQuerySelector, SignerKeyResolution,
};

use super::*;

/// An authenticated own-Station current-admission answer. The host must check
/// its live session and original runtime public key before committing the pin.
/// A historical answer or a controller's Device key cannot fill this slot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsCreatorBootstrapAgentAuthority {
    #[serde(deserialize_with = "deserialize_current_agent")]
    outcome: SignerKeyResolution,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    verified_at: chrono::DateTime<chrono::Utc>,
}

fn deserialize_current_agent<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<SignerKeyResolution, D::Error> {
    let value = SignerKeyResolution::deserialize(deserializer)?;
    if !matches!(
        &value,
        SignerKeyResolution::CurrentResolved {
            selector: SignerKeyQuerySelector::CurrentAdmission {
                sender: CurrentSignerKeyQuerySender::Agent { .. }
            },
            ..
        }
    ) {
        return Err(serde::de::Error::custom(
            "creator Agent authority must retain a current resolved answer",
        ));
    }
    Ok(value)
}

impl MlsCreatorBootstrapAgentAuthority {
    pub fn from_current_signer_query(
        intent: &MlsCreatorBootstrapIntent,
        outcome: SignerKeyResolution,
        verified_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self> {
        let value = Self {
            outcome,
            verified_at: arkret_canonical::normalize_timestamp_canonical(verified_at),
        };
        value.validate_binding(intent)?;
        Ok(value)
    }

    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        intent.validate()?;
        self.outcome.validate(intent.effective_scope().realm_id())?;
        let SignerKeyResolution::CurrentResolved {
            selector:
                SignerKeyQuerySelector::CurrentAdmission {
                    sender:
                        CurrentSignerKeyQuerySender::Agent {
                            actor,
                            verification_method,
                        },
                },
            key,
        } = &self.outcome
        else {
            return Err(WireError::Protocol(
                "creator requires a resolved current Agent endpoint".into(),
            ));
        };
        if actor != intent.owner_actor_id()
            || verification_method != intent.creator_signer_method()
            || intent.creator_endpoint()
                != &(arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method: verification_method.clone(),
                })
            || !matches!(
                &key.authorization_ref.stream_ref,
                arkret_wire::CommitStreamRef::Realm { .. }
            )
        {
            return Err(WireError::Protocol(
                "creator Agent evidence changed its exact Actor or runtime method".into(),
            ));
        }
        Ok(())
    }

    pub fn key(&self) -> &ResolvedSignerKey {
        match &self.outcome {
            SignerKeyResolution::CurrentResolved { key, .. } => key,
            _ => unreachable!("validated Agent authority always retains a current resolved key"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep schema-mapped wire variants inline; transport and runtime containers own allocation policy."
)]
pub enum MlsCreatorBootstrapEndpointAuthority {
    Device(MlsCreatorBootstrapDeviceAuthority),
    Agent(MlsCreatorBootstrapAgentAuthority),
}

impl MlsCreatorBootstrapEndpointAuthority {
    pub fn validate_binding(&self, intent: &MlsCreatorBootstrapIntent) -> Result<()> {
        match self {
            Self::Device(value) => value.validate_binding(intent),
            Self::Agent(value) => value.validate_binding(intent),
        }
    }

    pub fn authorization_event_ref(&self) -> &EventId {
        match self {
            Self::Device(value) => &value.projection.device_authorize_event_id,
            Self::Agent(value) => &value.key().authorization_ref.event_id,
        }
    }

    pub fn verified_at(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::Device(value) => value.verified_at,
            Self::Agent(value) => value.verified_at,
        }
    }
}
