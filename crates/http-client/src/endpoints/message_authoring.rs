//! Message submission through the Realm governance authority.

use arkret_identity::VerifiedSubmission;
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
};
use arkret_models_collaboration::message_authoring::MessageSubmitRequestBody;
use arkret_wire::AuthoritySubmitResponseBody;

use crate::{Client, ClientRequestOptions, Error, Result};

impl Client {
    /// Submit a fully producer-authored `ak.message.create` Event. Finality is
    /// the governance Station's returned RealmCommit.
    pub async fn self_message_submit(
        &self,
        request: &VerifiedSubmission<MessageSubmitRequestBody>,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitResponseBody> {
        request.validate()?;
        match self
            .submit_to_realm_authority(
                &request.rebind(SelfAuthoritySubmitRequestBody::Event(
                    request.submission.clone(),
                ))?,
                options,
            )
            .await?
        {
            SelfAuthoritySubmitResponseBody::Ordinary(outcome) => Ok(outcome),
            _ => Err(Error::Protocol(
                "message Event submission returned an aggregate outcome".to_owned(),
            )),
        }
    }
}
