//! Capability event payloads.

use arkret_wire::{ActorId, CurrentRevision};

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantCreateBody {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer_id: ActorId,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    pub issuer_authority_refs: Vec<IssuerAuthorityRef>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
}

impl CapabilityGrantCreateBody {
    /// Structural checks only. Ownership, current rights and management gates
    /// must still be decided by the accepting Station in its transaction.
    pub fn validate_owned_agent_shape(&self) -> Result<()> {
        use crate::governance::grant_constraint::GrantConstraintKind;
        let owned = self.issuer_authority_refs.iter().find_map(|reference| {
            if let IssuerAuthorityRef::OwnedAgent {
                realm_id,
                controller_account_id,
                ..
            } = reference
            {
                Some((realm_id, controller_account_id))
            } else {
                None
            }
        });
        let Some((realm, controller)) = owned else {
            return Ok(());
        };
        let terminal = self.constraints.iter().any(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                && constraint.constraint_subkind.is_none()
                && constraint.max_authority_depth == Some(0)
                && constraint.authority_regrant_allowed == Some(false)
        });
        if self.issuer_authority_refs.len() != 1
            || self.realm_id.as_ref() != Some(realm)
            || self.issuer_id.as_account_id() != Some(controller)
            || !matches!(&self.subject, CapabilitySubject::Actor(actor) if actor.as_account_id().is_some())
            || !terminal
        {
            return Err(WireError::Protocol(
                "invalid terminal owned Agent authority source".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantPayload {
    /// Genesis body omits the id. The reducer retypes the accepted EventId
    /// into a GrantId and inserts it into the projected CapabilityGrant.
    pub grant: CapabilityGrantCreateBody,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokePayload {
    pub grant_id: GrantId,
    pub expected_revision: CurrentRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for
/// `event-payload.schema.json#/$defs/capability_relinquish_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRelinquishPayload {
    pub grant_id: GrantId,
    pub expected_revision: CurrentRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
