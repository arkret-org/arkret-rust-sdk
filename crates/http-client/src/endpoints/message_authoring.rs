//! Message submission through the Realm governance authority.

use arkret_identity::VerifiedSubmission;
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::message_authoring::MessageSubmitRequestBody;
use arkret_wire::AuthoritySubmitOutcome;

use crate::{Client, ClientRequestOptions, Error, Result};

impl Client {
    /// Submit a fully producer-authored `ak.message.create` Event. Finality is
    /// the governance Station's returned RealmCommit.
    pub async fn self_message_submit(
        &self,
        request: &VerifiedSubmission<MessageSubmitRequestBody>,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        request.validate()?;
        match self
            .submit_to_realm_authority(
                &request.rebind(SelfAuthoritySubmitRequest::Event(
                    request.submission.clone(),
                ))?,
                options,
            )
            .await?
        {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(Error::Protocol(
                "message Event submission returned an aggregate outcome".to_owned(),
            )),
        }
    }
}
