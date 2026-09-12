use arkret_models_collaboration::message_authoring::{
    MessagePrepareOutcome, MessagePrepareRequestBody,
};

use crate::{Client, Result};

impl Client {
    /// Encryption is already complete. Verify local target/signer/frontier,
    /// sign the returned Event, then use the ordinary Event submit operation.
    pub async fn self_message_prepare(
        &self,
        request: &MessagePrepareRequestBody,
    ) -> Result<MessagePrepareOutcome> {
        request.validate()?;
        let outcome: MessagePrepareOutcome = self
            .post_protocol_replay_safe("/_arkret/self/messages/prepare", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Produce the exact signed submission for durable local storage before
    /// `events_submit`. A failed/uncertain submit reuses this value; it must
    /// never invoke preparation, encryption or the signer again.
    pub async fn prepare_message_submission<F>(
        &self,
        request: &MessagePrepareRequestBody,
        scope: &arkret_wire::ScopeRef,
        signer_context: &arkret_wire::AuthContext,
        direct_binding: Option<&arkret_wire::EventId>,
        known_frontier: Option<&arkret_models_collaboration::event_sync::RealmActorFrontierView>,
        sign: F,
    ) -> Result<arkret_wire::EventInitialSubmission>
    where
        F: FnOnce(&mut arkret_wire::AuthoredEvent) -> arkret_wire::Result<()>,
    {
        let outcome = self.self_message_prepare(request).await?;
        let mut event = outcome.verify_for_signing(
            request,
            scope,
            signer_context,
            direct_binding,
            known_frontier,
            chrono::Utc::now(),
        )?;
        let before = event.event().digest_payload()?;
        sign(&mut event)?;
        if event.event().digest_payload()? != before || !event.event().unsigned.is_empty() {
            return Err(arkret_wire::WireError::Protocol(
                "message signer changed prepared non-proof fields".into(),
            )
            .into());
        }
        let suite = outcome.draft.event_digest.digest_suite()?;
        event
            .event()
            .validate_proof_bindings_with_digest_suite(suite)?;
        event.event().validate_for_submit_structural()?;
        Ok(arkret_wire::EventInitialSubmission::online(
            event.event().clone(),
        ))
    }
}
