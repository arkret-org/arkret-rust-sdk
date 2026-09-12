//! Exact committed installation input delivered to a managed Actor producer.
//!
//! These are closed wire results, not opaque proof of authorization. A runtime
//! must authenticate its installing Station and match its retained original
//! identity material before installing authoring state.

use arkret_canonical::DigestSuite;
use arkret_models_integration::applet::GhostActorProvisionRequestBody;
use arkret_models_integration::{
    AppletInstallRequestBody, AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
};
use arkret_wire::{ActorId, AppletId, AuthContext, DidCoreId, RealmId, Result, WireError};
use serde::{Deserialize, Serialize};

use crate::event_sync::RealmActorFrontierView;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppletManagedActorCommittedRequest {
    Install(Box<AppletInstallRequestBody>),
    Ghost(Box<GhostActorProvisionRequestBody>),
}

impl AppletManagedActorCommittedRequest {
    pub fn authoring_request(&self) -> &AppletManagedActorAuthoringRequest {
        match self {
            Self::Install(request) => request.authoring_request(),
            Self::Ghost(request) => &request.authoring_request,
        }
    }

    pub fn managed_actor_bundle(&self) -> Option<&AppletManagedActorAuthoringBundle> {
        match self {
            Self::Install(request) => request.managed_actor_bundle(),
            Self::Ghost(request) => Some(&request.managed_actor_bundle),
        }
    }

    pub fn realm_id(&self) -> Result<&RealmId> {
        match self {
            Self::Install(request) => request
                .authoring_request()
                .basis
                .install()
                .and_then(|basis| basis.effective_scope.realm_id_opt())
                .ok_or_else(|| invalid("committed install request has no exact Realm scope")),
            Self::Ghost(request) => request
                .authoring_basis()
                .map(|basis| &basis.realm_id)
                .ok_or_else(|| invalid("committed Ghost request has the wrong purpose")),
        }
    }

    pub fn managed_actor_id(&self) -> &ActorId {
        match self {
            Self::Install(request) => match request.as_ref() {
                AppletInstallRequestBody::Create(create) => {
                    &create.managed_actor_bundle.pcr_genesis_event.actor_id
                }
                AppletInstallRequestBody::Reuse(reuse) => {
                    &reuse.reuse_existing_managed_actor.actor_id
                }
            },
            Self::Ghost(request) => &request.managed_actor_bundle.pcr_genesis_event.actor_id,
        }
    }

    pub fn applet_id(&self) -> &AppletId {
        match &self.authoring_request().basis {
            arkret_models_integration::AppletManagedActorAuthoringBasis::InstallBot(basis) => {
                &basis.applet_id
            }
            arkret_models_integration::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => {
                &basis.applet_id
            }
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletManagedActorAuthoringResult {
    pub committed_request: AppletManagedActorCommittedRequest,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub digest_suite: DigestSuite,
    pub auth_context: AuthContext,
    pub accepted_actor_frontier: RealmActorFrontierView,
}

impl AppletManagedActorAuthoringResult {
    /// Check internal coordinate bindings only. The caller separately verifies
    /// delivery authentication and exact retained request/identity equality.
    /// No preview expiry is re-evaluated for this already committed result.
    pub fn validate_bindings(&self) -> Result<()> {
        let request = self.committed_request.authoring_request();
        request.validate_bindings()?;
        if let Some(bundle) = self.committed_request.managed_actor_bundle() {
            bundle.validate_bindings(request)?;
        }
        let actor = self.committed_request.managed_actor_id();
        let account = actor.as_account_id().ok_or_else(|| {
            invalid("managed Actor completion requires a complete Account identity")
        })?;
        if &account.station_id != request.basis.target_station_id()
            || &self.accepted_actor_frontier.realm_id != self.committed_request.realm_id()?
            || &self.accepted_actor_frontier.actor_id != actor
        {
            return Err(invalid(
                "managed Actor completion frontier or Account mismatch",
            ));
        }
        self.auth_context.validate()?;
        self.accepted_actor_frontier
            .validate_with_suite(self.digest_suite)?;
        Ok(())
    }

    pub fn validate_delivery_binding(
        &self,
        applet_id: &AppletId,
        source_id: &DidCoreId,
        destination_id: &DidCoreId,
    ) -> Result<()> {
        self.validate_bindings()?;
        let basis = &self.committed_request.authoring_request().basis;
        if self.committed_request.applet_id() != applet_id
            || basis.target_station_id() != source_id
            || basis.service_id() != destination_id
        {
            return Err(invalid(
                "managed Actor completion delivery binding mismatch",
            ));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}
