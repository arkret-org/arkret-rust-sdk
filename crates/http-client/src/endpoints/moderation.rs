//! Moderation endpoint methods on [`Client`].

use arkret_models_collaboration::events_payloads::moderation::{
    FrankingSealObservationOutcome, FrankingSealObservationRequest,
};
use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequestBody,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<ModerationReportOutcome> {
        request.validate(digest_suite)?;
        let expected_report_id = request.report_id(digest_suite)?;
        let outcome: ModerationReportOutcome = self
            .post("/_arkret/self/moderation/report", request)
            .await?;
        if outcome.report_id != expected_report_id {
            return Err(crate::Error::Protocol(
                "moderation report outcome report_id does not match the signed Event".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Fetch and verify the first signed data-plane Seal observation for a
    /// durable moderation franking proof Event.
    pub async fn moderation_franking_seal_observation(
        &self,
        request: &FrankingSealObservationRequest,
    ) -> Result<FrankingSealObservationOutcome> {
        let outcome: FrankingSealObservationOutcome = self
            .post(
                "/_arkret/self/moderation/franking/seal-observation",
                request,
            )
            .await?;
        outcome.validate_binding(request)?;
        Ok(outcome)
    }
}
