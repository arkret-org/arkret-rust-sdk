use arkret_models_collaboration::governance::invite_addressing::{
    INVITE_LOCATOR_ISSUE_PATH, INVITE_LOCATOR_RESOLVE_PATH, INVITE_LOCATOR_REVOKE_PATH,
    INVITE_LOCATOR_ROTATE_PATH, InviteDeliveryResponseBody, InviteLocatorIssueRequestBody,
    InviteLocatorIssueResponseBody, InviteLocatorResolveRequestBody,
    InviteLocatorRevokeRequestBody, InviteLocatorRevokeResponseBody,
    InviteLocatorRotateRequestBody, PrincipalLocator, SelfInviteDispatchRequestBody,
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
    ) -> Result<InviteLocatorIssueResponseBody> {
        request.validate_minimal()?;
        self.post(INVITE_LOCATOR_ISSUE_PATH, request).await
    }

    pub async fn rotate_invite_locator(
        &self,
        request: &InviteLocatorRotateRequestBody,
    ) -> Result<InviteLocatorIssueResponseBody> {
        request.validate_minimal()?;
        self.post(INVITE_LOCATOR_ROTATE_PATH, request).await
    }

    /// Revoke one owned locator; retries retain the first revocation timestamp.
    pub async fn revoke_invite_locator(
        &self,
        request: &InviteLocatorRevokeRequestBody,
    ) -> Result<InviteLocatorRevokeResponseBody> {
        request.validate_minimal()?;
        let outcome: InviteLocatorRevokeResponseBody =
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
    ) -> Result<InviteDeliveryResponseBody> {
        request.validate_minimal()?;
        self.post("/_arkret/self/invites/dispatch", request).await
    }
}
