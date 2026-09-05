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

/// The section 4 enum minus `invite`.
///
/// Two closed carriers narrow to exactly this set:
/// `consent-operations.schema.json#/$defs/consent_request_request_body` pins
/// `consent_scope` away from `invite`, and so does the `consent_request` branch
/// of `holder-quarantine.schema.json#/$defs/quarantine_entry`. An invite-scoped
/// request belongs to invite delivery, so it has no representation here rather
/// than being remapped at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentRequestScope {
    DirectMessage,
    VoiceCall,
    VideoCall,
    Presence,
    Any,
}

impl ConsentRequestScope {
    pub const ALL: &'static [Self] = &[
        Self::DirectMessage,
        Self::VoiceCall,
        Self::VideoCall,
        Self::Presence,
        Self::Any,
    ];

    /// Registered default of `consent_request_request_body.consent_scope`.
    pub const DEFAULT: Self = Self::DirectMessage;

    #[must_use]
    pub const fn as_consent_scope(self) -> ConsentScope {
        match self {
            Self::DirectMessage => ConsentScope::DirectMessage,
            Self::VoiceCall => ConsentScope::VoiceCall,
            Self::VideoCall => ConsentScope::VideoCall,
            Self::Presence => ConsentScope::Presence,
            Self::Any => ConsentScope::Any,
        }
    }

    /// Narrow a section 4 scope. `invite` has no consent-request carrier and is
    /// rejected instead of silently becoming another scope.
    #[must_use]
    pub const fn from_consent_scope(scope: ConsentScope) -> Option<Self> {
        match scope {
            ConsentScope::Invite => None,
            ConsentScope::DirectMessage => Some(Self::DirectMessage),
            ConsentScope::VoiceCall => Some(Self::VoiceCall),
            ConsentScope::VideoCall => Some(Self::VideoCall),
            ConsentScope::Presence => Some(Self::Presence),
            ConsentScope::Any => Some(Self::Any),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.as_consent_scope().as_str()
    }
}

impl fmt::Display for ConsentRequestScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ConsentRequestScope {
    type Err = WireError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_consent_scope(value.parse()?).ok_or_else(|| {
            WireError::Protocol(
                "consent request consent_scope must be the section 4 enum without invite"
                    .to_owned(),
            )
        })
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
    use super::{ConsentRequestScope, ConsentScope};

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

    #[test]
    fn consent_request_scope_is_section_four_without_invite() {
        assert_eq!(ConsentRequestScope::ALL.len(), ConsentScope::ALL.len() - 1);
        for scope in ConsentRequestScope::ALL {
            let wire = scope.as_str();
            assert_eq!(wire.parse::<ConsentRequestScope>().unwrap(), *scope);
            assert_eq!(serde_json::to_value(scope).unwrap(), wire);
            assert_eq!(
                ConsentRequestScope::from_consent_scope(scope.as_consent_scope()),
                Some(*scope)
            );
        }
        assert_eq!(
            ConsentRequestScope::from_consent_scope(ConsentScope::Invite),
            None
        );
        assert!("invite".parse::<ConsentRequestScope>().is_err());
        assert!(serde_json::from_str::<ConsentRequestScope>(r#""invite""#).is_err());
        assert_eq!(
            ConsentRequestScope::DEFAULT.as_consent_scope(),
            ConsentScope::DirectMessage
        );
    }
}
