//! Durable security transaction and recovery-authority endpoint methods.

use arkret_identity::VerifiedSubmission;
use arkret_models_crypto::{
    SecurityTransaction, SecurityTransactionContinueRequestBody,
    SecurityTransactionCreateRequestBody,
};
use arkret_models_identity::{
    IssueRecoveryCompletionGrantResponseBody, RecoveryCompletionGrantRequestBody,
};
use arkret_wire::TransactionId;

use crate::{Client, Error, Result, reject_path_segment};

impl Client {
    pub async fn create_security_transaction(
        &self,
        request: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
    ) -> Result<SecurityTransaction> {
        let outcome: SecurityTransaction = self
            .post("/_arkret/self/security-transactions", request)
            .await?;
        outcome.validate_structural()?;
        let request_bytes = arkret_canonical::canonical::canonical_json_bytes(request)?;
        match (&**request, &outcome) {
            (
                SecurityTransactionCreateRequestBody::Recovery(sent),
                SecurityTransaction::Recovery(accepted),
            ) => accepted.validate_for_request(sent)?,
            (
                SecurityTransactionCreateRequestBody::SecurityRotation(_),
                SecurityTransaction::SecurityRotation(accepted),
            ) => {
                arkret_canonical::canonical::verify_digest(
                    &request_bytes,
                    accepted.request_digest.as_str(),
                )?;
            }
            _ => {
                return Err(Error::Protocol(
                    "security transaction create response changed kind".into(),
                ));
            }
        }
        let request_transaction_id = request.transaction_id();
        if outcome.transaction_id() != request_transaction_id {
            return Err(Error::Protocol(
                "security transaction create response changed transaction_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn get_security_transaction(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<SecurityTransaction> {
        reject_path_segment(transaction_id.as_str())?;
        let path = format!(
            "/_arkret/self/security-transactions/{}",
            transaction_id.as_str()
        );
        let outcome: SecurityTransaction = self.get(&path).await?;
        outcome.validate_structural()?;
        if outcome.transaction_id() != transaction_id {
            return Err(Error::Protocol(
                "security transaction resource response changed transaction_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn continue_security_transaction(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequestBody,
    ) -> Result<SecurityTransaction> {
        reject_path_segment(transaction_id.as_str())?;
        let path = format!(
            "/_arkret/self/security-transactions/{}/continue",
            transaction_id.as_str()
        );
        let outcome: SecurityTransaction = self.post(&path, request).await?;
        outcome.validate_structural()?;
        if !matches!(&outcome, SecurityTransaction::SecurityRotation(_))
            || outcome.transaction_id() != transaction_id
        {
            return Err(Error::Protocol(
                "security transaction continue response changed transaction_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn issue_recovery_completion_grant(
        &self,
        request: &RecoveryCompletionGrantRequestBody,
    ) -> Result<IssueRecoveryCompletionGrantResponseBody> {
        request.validate_structural()?;
        let outcome: IssueRecoveryCompletionGrantResponseBody = self
            .post(
                "/_arkret/gate/account/recovery-session-grants/issue",
                request,
            )
            .await?;
        if outcome.transaction_id != request.terminal_receipt.transaction_id
            || outcome.issued_session.account_id != request.terminal_receipt.account_id
            || outcome.issued_session.device_id.as_ref()
                != Some(&request.terminal_receipt.new_device_id)
            || outcome.issued_session.session_public_key
                != request.initial_session.session_public_key
            || outcome.issued_session.audience_id != request.initial_session.audience_id
        {
            return Err(Error::Protocol(
                "recovery completion grant response changed transaction binding".to_owned(),
            ));
        }
        Ok(outcome)
    }
}
