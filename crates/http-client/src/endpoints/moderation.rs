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
        self.post("/_arkret/self/moderation/report", request).await
    }
}
