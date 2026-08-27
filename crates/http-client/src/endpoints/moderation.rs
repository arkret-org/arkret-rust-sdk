//! Moderation endpoint methods on [`Client`].

use arkret_models_collaboration::events_payloads::moderation::{
    FrankingSealObservationOutcome, FrankingSealObservationRequest,
};
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
        let expected_root = outcome
            .covering_seal
            .data_event_set_root
            .as_ref()
            .ok_or_else(|| {
                crate::Error::Protocol(
                    "franking covering Seal has no data_event_set_root".to_owned(),
                )
            })?;
        let suite_name = expected_root
            .as_str()
            .split_once(':')
            .map(|(suite, _)| suite)
            .ok_or_else(|| crate::Error::Protocol("invalid data Event set root".to_owned()))?;
        let digest_suite = arkret_canonical::digest_suite(suite_name)
            .map_err(|error| crate::Error::Protocol(error.to_string()))?;
        let proof = arkret_state::EventDigestSetInclusionProof {
            leaf_digest: outcome.data_event_inclusion_proof.leaf_digest.clone(),
            leaf_index: outcome.data_event_inclusion_proof.leaf_index,
            leaf_count: outcome.data_event_inclusion_proof.leaf_count,
            audit_path: outcome.data_event_inclusion_proof.audit_path.clone(),
        };
        if !arkret_state::verify_event_digest_set_inclusion_proof(
            &proof,
            expected_root,
            digest_suite,
        )
        .map_err(|error| crate::Error::Protocol(error.to_string()))?
        {
            return Err(crate::Error::Protocol(
                "franking data Event inclusion proof is invalid".to_owned(),
            ));
        }
        let proof_event_digest = arkret_wire::Hash::new(
            outcome
                .proof_event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| crate::Error::Protocol(error.to_string()))?,
        )
        .map_err(|error| crate::Error::Protocol(error.to_string()))?;
        if proof_event_digest != outcome.data_event_inclusion_proof.leaf_digest {
            return Err(crate::Error::Protocol(
                "franking inclusion leaf does not match the durable proof Event".to_owned(),
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
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<RealmModerationPolicyDocument> {
        request.validate(realm_id, digest_suite)?;
        self.put(
            &format!("/_arkret/self/realms/{realm_id}/moderation-policy"),
            request,
        )
        .await
    }
}
