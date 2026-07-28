//! Durable security transaction and recovery-authority endpoint methods.

use arkret_wire::{
    AuthorizeRecoveryDeviceOutcome, AuthorizeRecoveryDeviceRequest,
    PromoteRecoverySessionGrantOutcome, PromoteRecoverySessionGrantRequest,
    RecoveryAuthorityTicket, RecoveryAuthorityTicketIssueRequest, SecurityTransaction,
    SecurityTransactionContinueRequest, SecurityTransactionCreateRequest, TransactionId,
};

use crate::{Client, Error, Result, reject_path_segment};

impl Client {
    pub async fn create_security_transaction(
        &self,
        request: &SecurityTransactionCreateRequest,
    ) -> Result<SecurityTransaction> {
        let outcome: SecurityTransaction = self
            .post("/_arkret/self/security-transactions", request)
            .await?;
        outcome.validate_structural()?;
        let request_bytes = arkret_canonical::canonical::canonical_json_bytes(request)?;
        arkret_canonical::canonical::verify_digest(
            &request_bytes,
            outcome.request_digest.as_str(),
        )?;
        let request_transaction_id = match request {
            SecurityTransactionCreateRequest::Recovery(request) => &request.transaction_id,
            SecurityTransactionCreateRequest::SecurityRotation(request) => &request.transaction_id,
        };
        if &outcome.transaction_id != request_transaction_id {
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
        if &outcome.transaction_id != transaction_id {
            return Err(Error::Protocol(
                "security transaction resource response changed transaction_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn continue_security_transaction(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequest,
    ) -> Result<SecurityTransaction> {
        reject_path_segment(transaction_id.as_str())?;
        let path = format!(
            "/_arkret/self/security-transactions/{}/continue",
            transaction_id.as_str()
        );
        let outcome: SecurityTransaction = self.post(&path, request).await?;
        outcome.validate_structural()?;
        if &outcome.transaction_id != transaction_id {
            return Err(Error::Protocol(
                "security transaction continue response changed transaction_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn issue_recovery_authority_ticket(
        &self,
        request: &RecoveryAuthorityTicketIssueRequest,
    ) -> Result<RecoveryAuthorityTicket> {
        let ticket: RecoveryAuthorityTicket = self
            .post("/_arkret/self/recovery-authority-tickets", request)
            .await?;
        ticket.validate_structural()?;
        if ticket.transaction_id != request.transaction_id
            || ticket.transaction_request_digest != request.transaction_request_digest
            || ticket.prepared_plan_digest != request.prepared_plan_digest
            || ticket.ticket_id != request.authority_ticket_id
        {
            return Err(Error::Protocol(
                "recovery authority ticket response changed transaction binding".to_owned(),
            ));
        }
        Ok(ticket)
    }

    pub async fn authorize_recovery_device(
        &self,
        request: &AuthorizeRecoveryDeviceRequest,
    ) -> Result<AuthorizeRecoveryDeviceOutcome> {
        let outcome: AuthorizeRecoveryDeviceOutcome = self
            .post(
                "/_arkret/gate/account/recovery-device-authorizations",
                request,
            )
            .await?;
        if outcome.ticket_id != request.ticket.ticket_id
            || outcome.transaction_id != request.ticket.transaction_id
            || outcome.authorize_event_id != request.ticket.authorize_event_id
        {
            return Err(Error::Protocol(
                "recovery device authorization response changed ticket binding".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn promote_recovery_session_grant(
        &self,
        request: &PromoteRecoverySessionGrantRequest,
    ) -> Result<PromoteRecoverySessionGrantOutcome> {
        let outcome: PromoteRecoverySessionGrantOutcome = self
            .post(
                "/_arkret/gate/account/recovery-session-grants/promote",
                request,
            )
            .await?;
        if outcome.transaction_id != request.transaction_id
            || outcome.consumed_grant_id != request.old_grant_id
        {
            return Err(Error::Protocol(
                "recovery grant promotion response changed transaction or grant binding".to_owned(),
            ));
        }
        Ok(outcome)
    }
}
