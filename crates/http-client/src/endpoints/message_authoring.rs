//! Message submission through the Realm governance authority.

use arkret_models_collaboration::message_authoring::MessageSubmitRequestBody;
use arkret_wire::{AuthoritySubmitOutcome, AuthoritySubmitRequest};

use crate::{Client, ClientRequestOptions, Result};

impl Client {
    /// Submit a fully producer-authored `ak.message.create` Event. Finality is
    /// the governance Station's returned RealmCommit.
    pub async fn self_message_submit(
        &self,
        request: &MessageSubmitRequestBody,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        request.validate()?;
        self.submit_to_realm_authority(
            &AuthoritySubmitRequest::Event(request.submission.clone()),
            options,
        )
        .await
    }
}
