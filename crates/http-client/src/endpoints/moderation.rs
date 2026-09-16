//! Moderation endpoint methods on [`Client`].

use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};

use crate::{Client, Result};

impl Client {
    pub async fn moderation_report(
        &self,
        request: &ModerationReportRequestBody,
    ) -> Result<ModerationReportOutcome> {
        request.validate()?;
        let expected_report_id = request.report_id()?;
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
}
