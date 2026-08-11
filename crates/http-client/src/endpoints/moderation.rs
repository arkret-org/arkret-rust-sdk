//! Moderation endpoint methods on [`Client`].

use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};
use arkret_models_collaboration::governance::realm_governance::{
    RealmModerationPolicyDocument, RealmModerationPolicyReplaceRequestBody,
};
use arkret_wire::RealmId;

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

    /// Replace a Realm moderation policy with the caller's complete signed
    /// Control Move. The typed request is validated locally and serialized as
    /// canonical JSON before the PUT is sent.
    pub async fn realm_moderation_policy_replace(
        &self,
        realm_id: &RealmId,
        request: &RealmModerationPolicyReplaceRequestBody,
    ) -> Result<RealmModerationPolicyDocument> {
        request.validate(realm_id)?;
        self.put(
            &format!("/_arkret/self/realms/{realm_id}/moderation-policy"),
            request,
        )
        .await
    }
}
