//! Frozen accepted installation dependencies for ordinary Applet admission.

use arkret_wire::{Event, EventKind, Hash, Result, WireError, canonical};
use serde::{Deserialize, Serialize};

/// The accepted administrator Events are the portable installation authority.
/// Their producer bytes remain unchanged from the signed authoring request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletInstallationAuthority {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub capability_grant_event: Event,
}

impl AppletInstallationAuthority {
    pub fn canonical_sha256_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    /// Shape and content binding only; the consumer must authenticate both
    /// accepted Events before using the registration's Station as authority.
    pub fn validate_structural(&self) -> Result<()> {
        let registration = &self.registration_event;
        let grant = &self.capability_grant_event;
        if registration.kind != EventKind::AppletRegistration
            || grant.kind != EventKind::CapabilityGrant
            || registration.applet_id.is_some()
            || grant.applet_id.is_some()
            || registration.executed_by.is_some()
            || grant.executed_by.is_some()
            || registration.scope_ref != grant.scope_ref
            || registration.realm_id != grant.realm_id
            || registration.actor_id.route_service_id() != grant.actor_id.route_service_id()
        {
            return Err(WireError::Protocol(
                "Applet installation authority coordinates mismatch".to_owned(),
            ));
        }
        for event in [registration, grant] {
            let suite = event.event_id.event_digest().digest_suite()?;
            event.validate_for_accepted_structural()?;
            event.verify_event_id_matches_content_with_digest_suite(suite)?;
            event.validate_station_admission_binding(suite)?;
        }
        Ok(())
    }
}
