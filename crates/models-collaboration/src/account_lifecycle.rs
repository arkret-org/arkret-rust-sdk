//! Account lifecycle authorization proof, Account Authority status
//! publication/resolution relay carriers, and the session/applet revoke DTOs.
//!
//! The signed status record and its replication receipt live in
//! [`crate::account_status`]; this module owns the request/outcome carriers
//! that move those objects between an Account Authority and a replica, plus the
//! account-lifecycle proof that authorizes the revoke commands.

// The account lifecycle proof and its applet selector are defined in
// arkret-models-identity because `account-operations.schema.json` is the
// identity/account domain and `AppletRevokeRequestBody` (arkret-models-integration)
// binds the same proof; that crate cannot reach this one. They are surfaced here
// so the session-revoke request body and its authorization proof stay reachable
// through one module path.
pub use arkret_models_identity::account::{
    ACCOUNT_LIFECYCLE_PROOF_MAX_LIFETIME_SECONDS, ACCOUNT_LIFECYCLE_PROOF_SCHEMA,
    AccountLifecycleProof, AccountLifecycleProofKind, SessionGrantAppletSelector,
};
use arkret_wire::{
    AccountId, AppletId, Cursor, DeviceId, DidCoreId, Hash, Result, ScopeRef, SessionGrantId,
    WireError,
};
use serde::{Deserialize, Serialize};

use crate::account_status::{AccountStatusReceipt, AccountStatusRecord};

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_publication (first
// branch).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusInitialPublication {
    pub record: AccountStatusRecord,
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_publication (second
// branch).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusReceiptedPublication {
    pub record: AccountStatusRecord,
    pub account_status_receipts: Vec<AccountStatusReceipt>,
}

/// Maximum receipts a downstream fanout publication may carry.
pub const ACCOUNT_STATUS_PUBLICATION_MAX_RECEIPTS: usize = 32;

/// Initial publication carries the record alone; downstream fanout carries the
/// byte-identical record plus the prior receiver receipts. No receiver rebuilds
/// or re-signs the record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccountStatusPublication {
    Receipted(AccountStatusReceiptedPublication),
    Initial(AccountStatusInitialPublication),
}

impl AccountStatusPublication {
    pub fn record(&self) -> &AccountStatusRecord {
        match self {
            Self::Receipted(publication) => &publication.record,
            Self::Initial(publication) => &publication.record,
        }
    }

    pub fn receipts(&self) -> &[AccountStatusReceipt] {
        match self {
            Self::Receipted(publication) => &publication.account_status_receipts,
            Self::Initial(_) => &[],
        }
    }
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_publication_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusPublicationRequestBody {
    pub publication: AccountStatusPublication,
}

impl AccountStatusPublicationRequestBody {
    pub fn validate_shape(&self) -> Result<()> {
        let record = self.publication.record();
        record.validate_shape()?;
        let receipts = self.publication.receipts();
        if matches!(self.publication, AccountStatusPublication::Receipted(_))
            && (receipts.is_empty() || receipts.len() > ACCOUNT_STATUS_PUBLICATION_MAX_RECEIPTS)
        {
            return Err(WireError::Protocol(
                "receipted account status publication carries 1..=32 receipts".to_owned(),
            ));
        }
        for (index, receipt) in receipts.iter().enumerate() {
            receipt.validate_for_record(record)?;
            if receipts[..index].contains(receipt) {
                return Err(WireError::Protocol(
                    "account status publication receipts must be unique".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// `accepted` and `duplicate` are terminal for this receiver; a
/// `dependency_missing` outcome performs zero writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatusPublicationStatus {
    Accepted,
    Duplicate,
    DependencyMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatusPropagationState {
    NotRequired,
    Scheduled,
    Complete,
    Incomplete,
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_publication_outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusPublicationOutcome {
    pub status: AccountStatusPublicationStatus,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub status_seq: u64,
    pub account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_account_status_record_id: Option<arkret_wire::AccountStatusRecordId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_status_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_status_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_cursor: Option<Cursor>,
    pub propagation_state: AccountStatusPropagationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_destination_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<AccountStatusReceipt>,
}

impl AccountStatusPublicationOutcome {
    pub fn validate_for_request(
        &self,
        request: &AccountStatusPublicationRequestBody,
    ) -> Result<()> {
        request.validate_shape()?;
        let record = request.publication.record();
        if self.account_status_record_id != record.account_status_record_id
            || self.status_seq != record.status_seq
            || self.account_id != record.account_id
        {
            return Err(WireError::Protocol(
                "account status publication outcome does not name the submitted record".to_owned(),
            ));
        }
        if (self.status == AccountStatusPublicationStatus::DependencyMissing)
            != self.required_status_seq.is_some()
        {
            return Err(WireError::Protocol(
                "required_status_seq is present exactly for dependency_missing".to_owned(),
            ));
        }
        if let Some(receipt) = self.receipt.as_ref() {
            receipt.validate_for_record(record)?;
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_resolve_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusResolveRequestBody {
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub from_status_seq: u64,
    pub limit: u16,
}

impl AccountStatusResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        if self.from_status_seq == 0 || !(1..=128).contains(&self.limit) {
            return Err(WireError::Protocol(
                "account status resolve bounds are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_status_resolve_outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusResolveOutcome {
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub records: Vec<AccountStatusRecord>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_status_seq: Option<u64>,
}

impl AccountStatusResolveOutcome {
    pub fn validate_for_request(&self, request: &AccountStatusResolveRequestBody) -> Result<()> {
        request.validate()?;
        if self.account_authority_id != request.account_authority_id
            || self.account_id != request.account_id
            || self.records.len() > usize::from(request.limit)
        {
            return Err(WireError::Protocol(
                "account status resolve binding mismatch".to_owned(),
            ));
        }
        for (offset, record) in self.records.iter().enumerate() {
            record.validate_shape()?;
            if record.account_authority_id != self.account_authority_id
                || record.account_id != self.account_id
                || record.status_seq != request.from_status_seq + offset as u64
            {
                return Err(WireError::Protocol(
                    "account status resolve range is not contiguous".to_owned(),
                ));
            }
        }
        let expected_next = self.records.last().map(|record| record.status_seq + 1);
        if self.has_more != self.next_status_seq.is_some()
            || self
                .next_status_seq
                .is_some_and(|next| Some(next) != expected_next)
        {
            return Err(WireError::Protocol(
                "account status resolve continuation is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/session_revoke_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session_grant_id: Option<SessionGrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_sessions: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_epoch: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}

impl SessionRevokeRequestBody {
    /// The schema pins `all_sessions` to `true`, makes the three targets
    /// mutually exclusive, makes `applet_id` exclusive with every target, and
    /// binds `applet_id`, `effective_scope` and `registration_epoch` together
    /// (with `service_id` and `capability_grant_refs` depending on all three).
    pub fn validate_shape(&self) -> Result<()> {
        if self.all_sessions == Some(false) {
            return Err(WireError::Protocol(
                "session revoke all_sessions is pinned to true when present".to_owned(),
            ));
        }
        let targets = usize::from(self.target_session_grant_id.is_some())
            + usize::from(self.target_device_id.is_some())
            + usize::from(self.all_sessions.is_some())
            + usize::from(self.applet_id.is_some());
        if targets > 1 {
            return Err(WireError::Protocol(
                "session revoke selects at most one of session grant, device, all sessions or applet"
                    .to_owned(),
            ));
        }
        let applet_group = self.applet_id.is_some();
        if self.effective_scope.is_some() != applet_group
            || self.registration_epoch.is_some() != applet_group
        {
            return Err(WireError::Protocol(
                "session revoke applet_id, effective_scope and registration_epoch are one group"
                    .to_owned(),
            ));
        }
        if !applet_group && (self.service_id.is_some() || !self.capability_grant_refs.is_empty()) {
            return Err(WireError::Protocol(
                "session revoke service_id and capability_grant_refs require the applet group"
                    .to_owned(),
            ));
        }
        if let Some(proof) = self.proof.as_ref() {
            proof.validate_shape()?;
        }
        Ok(())
    }

    pub fn applet_selector(&self) -> Option<SessionGrantAppletSelector> {
        Some(SessionGrantAppletSelector {
            applet_id: self.applet_id.clone()?,
            effective_scope: self.effective_scope.clone()?,
            registration_epoch: self.registration_epoch.clone()?,
            service_id: self.service_id.clone(),
            capability_grant_refs: self.capability_grant_refs.clone(),
        })
    }
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/session_revoke_outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeOutcome {
    pub revoked_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_session_grant_ids: Vec<SessionGrantId>,
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::account::AccountLifecycleProofKind;
    use serde_json::json;

    use super::*;

    fn proof_value() -> serde_json::Value {
        json!({
            "proof_kind": "did_bound_signature",
            "challenge": "0123456789abcdef",
            "request_canonical_digest": format!("sha256:{}", "a".repeat(64)),
            "audience_id": "ak:did_core:web:station.example",
            "issued_at": "2026-08-09T00:00:00.000Z",
            "expires_at": "2026-08-09T00:10:00.000Z",
            "signature": "c2ln"
        })
    }

    #[test]
    fn account_lifecycle_proof_round_trips_and_is_closed() {
        let value = proof_value();
        let parsed: AccountLifecycleProof =
            serde_json::from_value(value.clone()).expect("closed proof");
        assert_eq!(
            parsed.proof_kind,
            AccountLifecycleProofKind::DidBoundSignature
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        parsed.validate_shape().expect("proof shape");

        let mut unknown = value.clone();
        unknown.as_object_mut().unwrap().insert(
            "account_id".to_owned(),
            serde_json::Value::String("ak:account:x".to_owned()),
        );
        assert!(serde_json::from_value::<AccountLifecycleProof>(unknown).is_err());

        for required in [
            "proof_kind",
            "challenge",
            "request_canonical_digest",
            "audience_id",
            "issued_at",
            "expires_at",
            "signature",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<AccountLifecycleProof>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }

    #[test]
    fn account_lifecycle_proof_lifetime_ceiling_is_enforced() {
        let mut value = proof_value();
        value.as_object_mut().unwrap().insert(
            "expires_at".to_owned(),
            serde_json::Value::String("2026-08-09T00:16:00.000Z".to_owned()),
        );
        let parsed: AccountLifecycleProof = serde_json::from_value(value).expect("closed proof");
        assert!(parsed.validate_shape().is_err());
    }

    #[test]
    fn session_revoke_request_body_targets_are_mutually_exclusive() {
        let both = json!({
            "target_session_grant_id": SessionGrantId::from_issuance_digest([5; 32]),
            "all_sessions": true
        });
        let parsed: SessionRevokeRequestBody =
            serde_json::from_value(both).expect("closed revoke body");
        assert!(parsed.validate_shape().is_err());

        let single: SessionRevokeRequestBody =
            serde_json::from_value(json!({"all_sessions": true})).expect("closed revoke body");
        single.validate_shape().expect("single target");

        let false_all: SessionRevokeRequestBody =
            serde_json::from_value(json!({"all_sessions": false})).expect("closed revoke body");
        assert!(false_all.validate_shape().is_err());
    }

    #[test]
    fn session_revoke_request_body_applet_group_is_atomic() {
        let partial: SessionRevokeRequestBody = serde_json::from_value(json!({
            "applet_id": "ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d"
        }))
        .expect("closed revoke body");
        assert!(partial.validate_shape().is_err());
    }

    #[test]
    fn session_revoke_request_body_rejects_unknown_members() {
        assert!(
            serde_json::from_value::<SessionRevokeRequestBody>(json!({"revoke_everything": true}))
                .is_err()
        );
    }

    #[test]
    fn session_revoke_outcome_round_trips() {
        let value = json!({"revoked_count": 2});
        let parsed: SessionRevokeOutcome =
            serde_json::from_value(value.clone()).expect("closed outcome");
        assert_eq!(parsed.revoked_count, 2);
        assert!(parsed.revoked_session_grant_ids.is_empty());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        assert!(
            serde_json::from_value::<SessionRevokeOutcome>(json!({})).is_err(),
            "revoked_count must not become optional"
        );
    }

    #[test]
    fn account_status_publication_selects_the_receipted_branch_first() {
        let initial = json!({"record": {"schema": "ak.schema.account_operations.v1"}});
        assert!(serde_json::from_value::<AccountStatusPublication>(initial).is_err());
    }
}
