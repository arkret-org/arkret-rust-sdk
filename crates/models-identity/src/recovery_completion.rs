//! The sole typed Recovery-completion issuance request and response owner.
//!
//! The Station supplies C over its existing authenticated internal channel.
//! Fresh handoff/DPoP and current accepted-device eligibility are independently
//! authenticated by the issuer; the original recovery grant remains historical.

use arkret_models_crypto::RecoveryReceipt;
use arkret_wire::{AccountId, DidCoreId, Hash, RecoveryCompletionAttestation, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::account::InitialSessionGrantIntent;

fn sha256<T: Serialize>(value: &T) -> Result<Hash> {
    Hash::new(arkret_canonical::canonical::canonical_sha256(value)?).map_err(Into::into)
}

impl RecoveryCompletionGrantRequestBody {
    /// R is already signed before this digest is computed; the new PoP signs
    /// this intent, after which the complete request digest is computed.
    pub fn session_intent_digest(
        receipt: &RecoveryReceipt,
        initial_session: &InitialSessionGrantIntent,
    ) -> Result<Hash> {
        sha256(
            &serde_json::json!({"receipt_digest": receipt.receipt_digest()?, "initial_session": initial_session}),
        )
    }

    pub fn new(
        terminal_receipt: RecoveryReceipt,
        initial_session: InitialSessionGrantIntent,
        accepted_device_possession_proof: arkret_wire::AcceptedDeviceIssuePossessionProof,
    ) -> Result<Self> {
        let canonical_request_digest = sha256(&serde_json::json!({
            "terminal_receipt": terminal_receipt, "initial_session": initial_session,
            "accepted_device_possession_proof": accepted_device_possession_proof,
        }))?;
        let request = Self {
            terminal_receipt,
            initial_session,
            accepted_device_possession_proof,
            canonical_request_digest,
        };
        request.validate_structural()?;
        Ok(request)
    }

    pub fn expected_canonical_request_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| WireError::Protocol("completion request must be an object".into()))?
            .remove("canonical_request_digest");
        sha256(&value)
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.terminal_receipt.validate()?;
        self.initial_session.validate()?;
        let proof = &self.accepted_device_possession_proof;
        proof.validate_purpose(
            arkret_wire::AcceptedDeviceIssuePossessionPurpose::RecoveryCompletionGrantIssue,
        )?;
        if proof.account_id != self.terminal_receipt.account_id
            || proof.device_id != self.terminal_receipt.new_device_id
            || self.initial_session.device_id != proof.device_id
            || self.initial_session.audience_id != proof.audience_id
            || proof.holder_jkt
                != self
                    .initial_session
                    .session_public_key
                    .thumbprint_sha256()?
            || proof.session_intent_digest
                != Self::session_intent_digest(&self.terminal_receipt, &self.initial_session)?
            || self.canonical_request_digest != self.expected_canonical_request_digest()?
        {
            return Err(WireError::Protocol(
                "completion request changed its receipt/new holder/accepted-device intent".into(),
            ));
        }
        Ok(())
    }

    /// Current authentication inputs come from the fresh verified handoff and
    /// DPoP, never from decoding this request or the historical recovery grant.
    /// Caller also checks current accepted replacement eligibility at the same
    /// issuer cut and verifies the identity-key signature before issuance.
    pub fn validate_first_issue(
        &self,
        completion: &RecoveryCompletionAttestation,
        account_subject: &Hash,
        handoff_digest: &Hash,
        authenticated_holder_jkt: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate_structural()?;
        self.validate_completion(completion)?;
        let proof = &self.accepted_device_possession_proof;
        if proof.account_subject != *account_subject
            || proof.account_handoff_grant_digest != *handoff_digest
            || proof.holder_jkt != authenticated_holder_jkt
            || now < proof.issued_at
            || now >= proof.expires_at
        {
            return Err(WireError::Protocol("completion first-issue proof is not bound to the fresh authenticated holder/window".into()));
        }
        Ok(())
    }

    pub fn validate_completion(&self, completion: &RecoveryCompletionAttestation) -> Result<()> {
        completion.validate_structural()?;
        let receipt = &self.terminal_receipt;
        if completion.transaction_id != receipt.transaction_id
            || completion.account_id != receipt.account_id
            || completion.recovery_session_id != receipt.recovery_session_id
            || completion.terminal_receipt_id != receipt.receipt_id
            || completion.terminal_receipt_digest != receipt.receipt_digest()?
            || completion.replacement_device_id != receipt.new_device_id
            || completion.new_model_generation_ref != receipt.new_model_generation_ref
            || completion.completed_at < receipt.completed_at
            || completion.reanchor_event_ref.event_id
                != receipt.recovery_unit.events[0].event.event_id
            || completion.device_authorization_event_ref.event_id
                != receipt.recovery_unit.events[1].event.event_id
            || completion.reanchor_event_ref.stream_ref
                != (arkret_wire::CommitStreamRef::Realm {
                    realm_id: receipt.recovery_unit.events[0].event.realm_id.clone(),
                })
        {
            return Err(WireError::Protocol(
                "completion issuance received another native Station closure".into(),
            ));
        }
        Ok(())
    }

    /// Durable business identity, independent of caller request_id. The issuer
    /// freezes the first accepted whole request/full-signed-R/outcome atomically
    /// under these bytes; changing request_id cannot create another issuance.
    pub fn operation_identity(&self, issuer_id: &DidCoreId) -> Result<Vec<u8>> {
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "issuer_id": issuer_id, "operation": "ak.gate.account.command.issue_recovery_completion_grant.v1",
            "account_id": self.terminal_receipt.account_id, "transaction_id": self.terminal_receipt.transaction_id,
        })).map_err(Into::into)
    }

    /// Once an issuer outcome exists, old PoP time/handoff are verified history.
    /// A fresh transport handoff may differ; the account/holder/current device
    /// still must be authenticated, and revoked/expired/superseded successors
    /// remain terminal in the issuer ledger rather than being reissued.
    pub fn validate_exact_replay(
        &self,
        stored: &Self,
        account_id: &AccountId,
        holder_jkt: &str,
    ) -> Result<()> {
        if arkret_canonical::canonical_json_bytes(self)?
            != arkret_canonical::canonical_json_bytes(stored)?
            || self.terminal_receipt.account_id != *account_id
            || self.accepted_device_possession_proof.holder_jkt != holder_jkt
        {
            return Err(WireError::Protocol(
                "completion replay changed the accepted request or current holder".into(),
            ));
        }
        Ok(())
    }
}

include!("generated/recovery_completion_contracts.rs");

#[cfg(test)]
mod tests;
