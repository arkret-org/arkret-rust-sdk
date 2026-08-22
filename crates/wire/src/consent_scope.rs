//! Contact consent-scope wire primitives.
//!
//! `ConsentScope` is a closed protocol vocabulary shared by the contact/directory
//! operation DTOs (`arkret-models-discovery`) and the account consent-cell
//! bodies (`arkret-models-collaboration`). It lives here in `arkret-wire` so
//! both model domains reach it within their allowed layering edges.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::WireError;

/// Counterpart for `spec/v1/artifacts/schemas/consent-operations.schema.json#/$defs/consent_scope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentScope {
    Invite,
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
    Any,
}

impl ConsentScope {
    pub const ALL: &'static [Self] = &[
        Self::Invite,
        Self::DirectMessage,
        Self::VoiceCall,
        Self::VideoCall,
        Self::Presence,
        Self::Any,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invite => "invite",
            Self::DirectMessage => "direct_message",
            Self::VoiceCall => "voice_call",
            Self::VideoCall => "video_call",
            Self::Presence => "presence",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ConsentScope {
    type Err = WireError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "invite" => Ok(Self::Invite),
            "direct_message" => Ok(Self::DirectMessage),
            "voice_call" => Ok(Self::VoiceCall),
            "video_call" => Ok(Self::VideoCall),
            "presence" => Ok(Self::Presence),
            "any" => Ok(Self::Any),
            _ => Err(WireError::Protocol(format!(
                "unsupported consent_scope: {value}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConsentScope;

    #[test]
    fn consent_scope_is_closed_and_round_trips() {
        for scope in ConsentScope::ALL {
            let wire = scope.as_str();
            assert_eq!(wire.parse::<ConsentScope>().unwrap(), *scope);
            assert_eq!(serde_json::to_value(scope).unwrap(), wire);
        }
        assert!("messaging".parse::<ConsentScope>().is_err());
        assert!(serde_json::from_str::<ConsentScope>(r#""dm""#).is_err());
    }
}
