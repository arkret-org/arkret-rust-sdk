//! Consent event payloads.

use arkret_wire::ConsentScope;

use crate::internal_prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentPeer {
    Actor { actor_id: ActorId },
}

/// Exact compare-and-swap precondition signed by the holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentExpectedCurrent {
    NeverWritten,
    Present { revision: CurrentRevision },
}

impl<'de> Deserialize<'de> for ConsentExpectedCurrent {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            state: String,
            #[serde(
                default,
                deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
            )]
            revision: Option<CurrentRevision>,
        }
        let wire = Wire::deserialize(deserializer)?;
        match (wire.state.as_str(), wire.revision) {
            ("never_written", None) => Ok(Self::NeverWritten),
            ("present", Some(revision)) => Ok(Self::Present { revision }),
            _ => Err(serde::de::Error::custom(
                "Consent expected_current requires an exact closed state branch",
            )),
        }
    }
}

include!("generated/consent_contracts.rs");

pub fn validate_permissions(permissions: &[ConsentPermission]) -> Result<()> {
    if permissions.len() > 4
        || permissions
            .windows(2)
            .any(|pair| pair[0].consent_scope >= pair[1].consent_scope)
    {
        return Err(WireError::Protocol(
            "Consent permissions require unique scopes in canonical order".into(),
        ));
    }
    Ok(())
}

impl ConsentReplacePayload {
    pub fn validate(&self) -> Result<()> {
        self.validate_minimal()
    }

    pub fn validate_minimal(&self) -> Result<()> {
        validate_permissions(&self.permissions)
    }
}
