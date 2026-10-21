//! Consent event payloads.

use arkret_wire::ConsentScope;

use crate::internal_prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentPeer {
    Actor { actor_id: ActorId },
}

include!("generated/consent_contracts.rs");

impl ConsentPeer {
    pub fn actor_id(&self) -> &ActorId {
        let Self::Actor { actor_id } = self;
        actor_id
    }
}
pub fn validate_scope_order(scopes: impl IntoIterator<Item = ConsentScope>) -> Result<()> {
    let mut previous = None;
    for scope in scopes {
        if previous.is_some_and(|prior| prior >= scope) {
            return Err(WireError::Protocol(
                "consent permissions require unique scopes in canonical order".into(),
            ));
        }
        previous = Some(scope);
    }
    Ok(())
}
pub fn validate_permissions(permissions: &[ConsentPermission]) -> Result<()> {
    if permissions.len() > 4 {
        return Err(WireError::Protocol(
            "consent permits at most four concrete scopes".into(),
        ));
    }
    validate_scope_order(
        permissions
            .iter()
            .map(|permission| permission.consent_scope),
    )?;
    for permission in permissions {
        if let (Some(start), Some(end)) = (permission.not_before, permission.expires_at) {
            if start >= end {
                return Err(WireError::Protocol(
                    "consent permission window is empty".into(),
                ));
            }
        }
    }
    Ok(())
}
impl ConsentReplacePayload {
    pub fn validate(&self) -> Result<()> {
        validate_permissions(&self.permissions)
    }
}
impl ConsentPermission {
    pub fn permits(&self, now: DateTime<Utc>) -> bool {
        self.not_before.is_none_or(|start| start <= now)
            && self.expires_at.is_none_or(|end| now < end)
            && self.constraints.as_ref().is_none_or(Vec::is_empty)
    }
}

impl ConsentReplacePayload {
    /// Compare one facade decision against the exact signed previous value.
    pub fn validate_scope_diff(
        &self,
        previous: &[ConsentPermission],
        scope: ConsentScope,
        retain_scope: bool,
    ) -> Result<()> {
        self.validate()?;
        validate_permissions(previous)?;
        let before = previous.iter().find(|p| p.consent_scope == scope);
        let after = self.permissions.iter().find(|p| p.consent_scope == scope);
        if after.is_some() != retain_scope || (!retain_scope && before.is_none()) {
            return Err(WireError::Protocol(
                "Consent facade decision differs from its correlated scope".into(),
            ));
        }
        let others = |permissions: &[ConsentPermission]| {
            permissions
                .iter()
                .filter(|p| p.consent_scope != scope)
                .cloned()
                .collect::<Vec<_>>()
        };
        if arkret_canonical::canonical_json_bytes(&others(previous))?
            != arkret_canonical::canonical_json_bytes(&others(&self.permissions))?
        {
            return Err(WireError::Protocol(
                "Consent facade replacement changes another scope".into(),
            ));
        }
        Ok(())
    }
}
