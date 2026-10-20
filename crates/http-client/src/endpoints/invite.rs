//! Third-party (3PID) invite private-material lifecycle endpoints
//! (`sync/third-party-invites.md` §7).
//!
//! The four operations here are the whole standard chain between minting the
//! private token and delivering it: provision, acceptance attestation,
//! activation and status. The verification service keeps the token, salt,
//! pepper, per-invite ephemeral key and delivery target; none of them ever
//! crosses one of these responses.

use arkret_models_collaboration::governance::invite_addressing::{
    INVITE_LOCATOR_ISSUE_PATH, INVITE_LOCATOR_RESOLVE_PATH, INVITE_LOCATOR_REVOKE_PATH,
    INVITE_LOCATOR_ROTATE_PATH, InviteDeliveryOutcome, InviteLocatorIssueOutcome,
    InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody, InviteLocatorRevokeOutcome,
    InviteLocatorRevokeRequestBody, InviteLocatorRotateRequestBody, PrincipalLocator,
    SelfInviteDispatchRequestBody,
};
use arkret_models_collaboration::governance::third_party_invite::{
    ThirdPartyInviteAcceptanceAttestationOutcome, ThirdPartyInviteAcceptanceAttestationRequestBody,
    ThirdPartyInviteActivationOutcome, ThirdPartyInviteActivationRequestBody,
    ThirdPartyInviteProvisionOutcome, ThirdPartyInviteProvisionRequestBody,
    ThirdPartyInviteProvisioningStatusOutcome, ThirdPartyInviteProvisioningStatusRequestBody,
};

use crate::{Client, Result};

impl Client {
    /// Resolve public introduction evidence without forwarding session credentials.
    pub async fn resolve_invite_locator(
        &self,
        request: &InviteLocatorResolveRequestBody,
    ) -> Result<PrincipalLocator> {
        request.validate_minimal()?;
        let builder = self.canonical_json_body(
            self.public_request(reqwest::Method::POST, INVITE_LOCATOR_RESOLVE_PATH)?,
            request,
        )?;
        let locator: PrincipalLocator = self.send_json(builder).await?;
        locator.validate_minimal()?;
        Ok(locator)
    }

    pub async fn issue_invite_locator(
        &self,
        request: &InviteLocatorIssueRequestBody,
    ) -> Result<InviteLocatorIssueOutcome> {
        request.validate_minimal()?;
        self.post(INVITE_LOCATOR_ISSUE_PATH, request).await
    }

    pub async fn rotate_invite_locator(
        &self,
        request: &InviteLocatorRotateRequestBody,
    ) -> Result<InviteLocatorIssueOutcome> {
        request.validate_minimal()?;
        self.post(INVITE_LOCATOR_ROTATE_PATH, request).await
    }

    /// Revoke one owned locator; retries retain the first revocation timestamp.
    pub async fn revoke_invite_locator(
        &self,
        request: &InviteLocatorRevokeRequestBody,
    ) -> Result<InviteLocatorRevokeOutcome> {
        request.validate_minimal()?;
        let outcome: InviteLocatorRevokeOutcome =
            self.post(INVITE_LOCATOR_REVOKE_PATH, request).await?;
        if outcome.locator_id != request.locator_id {
            return Err(crate::Error::Protocol(
                "revocation answers another invite locator".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Dispatch an already accepted Event by its immutable identifier.
    pub async fn dispatch_invite(
        &self,
        request: &SelfInviteDispatchRequestBody,
    ) -> Result<InviteDeliveryOutcome> {
        request.validate_minimal()?;
        self.post("/_arkret/self/invites/dispatch", request).await
    }

    /// `POST /_arkret/open/third-party-invites/provision`
    /// (`ak.open.third_party_invite.command.provision.v1`).
    ///
    /// The inviter signs the request; the service mints and keeps the private
    /// material and returns only the public `third_party_invite` object plus the
    /// opaque provisioning handle. Success is not invite permission and does not
    /// create a pending Realm Invite.
    pub async fn third_party_invite_provision(
        &self,
        request: &ThirdPartyInviteProvisionRequestBody,
    ) -> Result<ThirdPartyInviteProvisionOutcome> {
        request.validate_for_service(&request.verification_id)?;
        let outcome: ThirdPartyInviteProvisionOutcome = self
            .post("/_arkret/open/third-party-invites/provision", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/self/third-party-invites/acceptance-attestation`
    /// (`ak.self.third_party_invite.read.acceptance_attestation.v1`).
    ///
    /// The authenticated inviter asks its own Station for the purpose-scoped
    /// acceptance attestation of one exact invite it authored. The caller must
    /// pass the returned object to activation unchanged: editing any member, or
    /// recomputing `invite_digest` locally, makes it unusable.
    pub async fn third_party_invite_acceptance_attestation(
        &self,
        request: &ThirdPartyInviteAcceptanceAttestationRequestBody,
    ) -> Result<ThirdPartyInviteAcceptanceAttestationOutcome> {
        let outcome: ThirdPartyInviteAcceptanceAttestationOutcome = self
            .post(
                "/_arkret/self/third-party-invites/acceptance-attestation",
                request,
            )
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/open/third-party-invites/activate`
    /// (`ak.open.third_party_invite.command.activate.v1`).
    ///
    /// Binds one provisioning record to exactly one accepted
    /// `ak.invite.third_party`. A byte-identical retry, a concurrent duplicate
    /// and a retry after a restart all return the same first `activated_at`.
    pub async fn third_party_invite_activate(
        &self,
        request: &ThirdPartyInviteActivationRequestBody,
    ) -> Result<ThirdPartyInviteActivationOutcome> {
        request.validate()?;
        let outcome: ThirdPartyInviteActivationOutcome = self
            .post("/_arkret/open/third-party-invites/activate", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/open/third-party-invites/status`
    /// (`ak.open.third_party_invite.read.provisioning_status.v1`).
    ///
    /// The recovery entry point after a lost provisioning or activation
    /// response: read the lifecycle position first, then decide whether to retry
    /// provisioning or activation. Never re-provision to "repair" a record that
    /// is already activated.
    pub async fn third_party_invite_provisioning_status(
        &self,
        request: &ThirdPartyInviteProvisioningStatusRequestBody,
    ) -> Result<ThirdPartyInviteProvisioningStatusOutcome> {
        let outcome: ThirdPartyInviteProvisioningStatusOutcome = self
            .post("/_arkret/open/third-party-invites/status", request)
            .await?;
        outcome.validate()?;
        if outcome.provisioning_id != request.provisioning_id {
            return Err(crate::Error::Protocol(
                "provisioning status answers another provisioning record".to_owned(),
            ));
        }
        Ok(outcome)
    }
}
