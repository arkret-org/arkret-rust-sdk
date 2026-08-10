//! Historical Account Authority verification for signed registration receipts.

use arkret_models_identity::{AccountBindingReceipt, DidDocument, IdentityLogListOutcome};
use arkret_wire::{DidCoreId, DidFullId, Hash};

use crate::{
    BindingVerifyError, DidVerificationRelationship, verify_jws_with_document_relationship,
};

/// Resolver failure is distinct from a cryptographically invalid history: a
/// caller may retry an unavailable authority, but must never retry through a
/// fork, revoked key or invalid signature as if it were a network problem.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("authority DID history unavailable: {message}")]
pub struct AuthorityHistoryUnavailable {
    pub message: String,
}

/// Supplies a complete method-native history. Implementations must finish all
/// pages themselves; returning a partial page is rejected by the verifier.
pub trait AuthorityDidHistoryResolver {
    fn resolve_complete_history(
        &self,
        did: &DidFullId,
    ) -> Result<IdentityLogListOutcome, AuthorityHistoryUnavailable>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityHistoryVerificationError {
    #[error(transparent)]
    Unavailable(#[from] AuthorityHistoryUnavailable),
    #[error("authority history response belongs to a different DID or method")]
    AuthorityMismatch,
    #[error("authority DID method does not expose a native verifiable history")]
    NativeHistoryUnavailable,
    #[error("authority history response is paginated or otherwise incomplete")]
    IncompleteHistory,
    #[error("authority DID history contains a fork or non-contiguous chain: {0}")]
    Fork(String),
    #[error("authority DID was deactivated at receipt issuance")]
    Deactivated,
    #[error("authority history has no version effective at receipt issuance")]
    NoVersionAtIssuance,
    #[error("authority DID history is invalid: {0}")]
    InvalidHistory(String),
    #[error("account binding receipt shape is invalid: {0}")]
    InvalidReceipt(String),
    #[error("receipt verification method was not an assertion method at issuance: {0}")]
    KeyNotAuthorized(#[source] BindingVerifyError),
    #[error("account binding receipt detached JWS is invalid: {0}")]
    InvalidSignature(#[source] BindingVerifyError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAccountBindingReceipt {
    pub authority_id: DidCoreId,
    pub authority_version_id: String,
    pub authority_log_head_digest: Hash,
    pub authority_document: DidDocument,
}

/// Resolve the Account Authority's complete history, select its state at the
/// receipt's `issued_at`, require the named key in `assertionMethod`, and verify
/// the detached JWS over the exact receipt transcript.
pub fn verify_account_binding_receipt_at_issuance(
    receipt: &AccountBindingReceipt,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedAccountBindingReceipt, AuthorityHistoryVerificationError> {
    receipt
        .validate_shape()
        .map_err(|error| AuthorityHistoryVerificationError::InvalidReceipt(error.to_string()))?;
    let authority_full_id = crate::verification_method_did(
        receipt.proof.verification_method.as_str(),
    )
    .map_err(|error| AuthorityHistoryVerificationError::InvalidReceipt(error.to_string()))?;
    let projected_authority = arkret_wire::project_full_id_to_core_id(&authority_full_id)
        .map_err(|error| AuthorityHistoryVerificationError::InvalidReceipt(error.to_string()))?;
    if projected_authority.as_str() != receipt.account_authority_id.as_str() {
        return Err(AuthorityHistoryVerificationError::AuthorityMismatch);
    }
    let history = resolver.resolve_complete_history(&authority_full_id)?;
    if history.did != authority_full_id || history.method != "did:webvh" {
        return Err(AuthorityHistoryVerificationError::AuthorityMismatch);
    }
    if history.native_history == Some(false) {
        return Err(AuthorityHistoryVerificationError::NativeHistoryUnavailable);
    }
    if history.has_more || history.next_cursor.is_some() {
        return Err(AuthorityHistoryVerificationError::IncompleteHistory);
    }

    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &authority_full_id,
        &history.entries,
        receipt.issued_at,
    )
    .map_err(|error| classify_history_error(error.to_string()))?;
    let authority_document: DidDocument = serde_json::from_value(point.document)
        .map_err(|error| AuthorityHistoryVerificationError::InvalidHistory(error.to_string()))?;
    let binding_bytes = receipt
        .canonical_proof_binding_bytes()
        .map_err(|error| AuthorityHistoryVerificationError::InvalidReceipt(error.to_string()))?;
    verify_jws_with_document_relationship(
        &binding_bytes,
        &receipt.proof.jws,
        &receipt.proof.verification_method,
        &authority_full_id,
        &authority_document,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(classify_receipt_proof_error)?;

    let authority_log_head_digest = Hash::new(
        arkret_canonical::canonical_sha256(
            history
                .entries
                .iter()
                .find(|entry| {
                    entry.get("versionId").and_then(serde_json::Value::as_str)
                        == Some(point.version_id.as_str())
                })
                .expect("validated history point came from one returned entry"),
        )
        .map_err(|error| AuthorityHistoryVerificationError::InvalidHistory(error.to_string()))?,
    )
    .map_err(|error| AuthorityHistoryVerificationError::InvalidHistory(error.to_string()))?;
    Ok(VerifiedAccountBindingReceipt {
        authority_id: receipt.account_authority_id.clone(),
        authority_version_id: point.version_id,
        authority_log_head_digest,
        authority_document,
    })
}

fn classify_history_error(message: String) -> AuthorityHistoryVerificationError {
    if message.contains("fork or reorder")
        || message.contains("non-contiguous")
        || message.contains("versionId hash is invalid")
        || message.contains("not precommitted by its predecessor")
        || message.contains("reuses an activated root")
    {
        AuthorityHistoryVerificationError::Fork(message)
    } else if message.contains("deactivated") {
        AuthorityHistoryVerificationError::Deactivated
    } else if message.contains("no entry effective") {
        AuthorityHistoryVerificationError::NoVersionAtIssuance
    } else {
        AuthorityHistoryVerificationError::InvalidHistory(message)
    }
}

fn classify_receipt_proof_error(error: BindingVerifyError) -> AuthorityHistoryVerificationError {
    match error {
        BindingVerifyError::Proof { .. } => {
            AuthorityHistoryVerificationError::InvalidSignature(error)
        }
        _ => AuthorityHistoryVerificationError::KeyNotAuthorized(error),
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::{
        AccountBindingKind, AccountBindingState, IdentityCreationOperationStatus,
        IdentityLogListOutcome,
    };
    use arkret_signatures::webvh::{ServiceInceptionInput, prepare_service_inception};
    use arkret_wire::{DidUrl, PayloadProof};
    use chrono::{TimeZone as _, Utc};
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;
    use url::Url;

    use super::*;

    #[derive(Clone)]
    struct FrozenResolver {
        outcome: IdentityLogListOutcome,
    }

    impl AuthorityDidHistoryResolver for FrozenResolver {
        fn resolve_complete_history(
            &self,
            _did: &DidFullId,
        ) -> Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
            Ok(self.outcome.clone())
        }
    }

    struct UnavailableResolver;

    impl AuthorityDidHistoryResolver for UnavailableResolver {
        fn resolve_complete_history(
            &self,
            _did: &DidFullId,
        ) -> Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
            Err(AuthorityHistoryUnavailable {
                message: "fixture transport unavailable".to_owned(),
            })
        }
    }

    fn receipt_fixture() -> (AccountBindingReceipt, IdentityLogListOutcome) {
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 9, 12, 0, 0).unwrap();
        let endpoint = Url::parse("https://account-authority.example/").unwrap();
        let mut rng = ChaChaRng::seed_from_u64(0x4155_5448);
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: issued_at,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let authority_full_id = DidFullId::new(inception.did.clone()).unwrap();
        let authority_id = arkret_wire::project_full_id_to_core_id(&authority_full_id).unwrap();
        let principal_full_id = DidFullId::new("did:webvh:zprincipal:principal.example").unwrap();
        let verification_method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let mut receipt = AccountBindingReceipt {
            binding_state: AccountBindingState::Bound,
            binding_kind: AccountBindingKind::IdentityCreation,
            account_authority_id: authority_id,
            account_subject: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            principal_id: DidCoreId::new("ak:did_core:webvh:zprincipal").unwrap(),
            full_id: principal_full_id,
            did_version_id: "1-fixture".to_owned(),
            control_key_digest: Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap(),
            identity_creation_lease_id: Some("identity-creation-lease-fixture".to_owned()),
            lease_fence: Some(1),
            operation_status: IdentityCreationOperationStatus::Accepted,
            operation_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            head_event_digest: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
            issued_at,
            proof: PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method,
                payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
                created_at: issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "placeholder".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.canonical_payload_digest().unwrap();
        let binding = receipt.canonical_proof_binding_bytes().unwrap();
        receipt.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &binding,
            &SigningKey::from_bytes(&inception.did_key_seed),
        )
        .unwrap();
        let history = IdentityLogListOutcome {
            did: authority_full_id,
            method: "did:webvh".to_owned(),
            native_history: Some(true),
            entries: vec![inception.log_entry.clone()],
            next_cursor: None,
            has_more: false,
        };
        (receipt, history)
    }

    #[test]
    fn verifies_the_receipt_with_the_authority_key_at_issuance() {
        let (receipt, history) = receipt_fixture();
        let verified = verify_account_binding_receipt_at_issuance(
            &receipt,
            &FrozenResolver { outcome: history },
        )
        .unwrap();
        assert_eq!(verified.authority_id, receipt.account_authority_id);
    }

    #[test]
    fn distinguishes_unavailable_history_from_invalid_receipt_signature() {
        let (mut receipt, history) = receipt_fixture();
        let unavailable =
            verify_account_binding_receipt_at_issuance(&receipt, &UnavailableResolver).unwrap_err();
        assert!(matches!(
            unavailable,
            AuthorityHistoryVerificationError::Unavailable(_)
        ));

        let last = receipt.proof.jws.pop().unwrap();
        receipt.proof.jws.push(if last == 'A' { 'B' } else { 'A' });
        let invalid = verify_account_binding_receipt_at_issuance(
            &receipt,
            &FrozenResolver { outcome: history },
        )
        .unwrap_err();
        assert!(matches!(
            invalid,
            AuthorityHistoryVerificationError::InvalidSignature(_)
        ));
    }

    #[test]
    fn classifies_a_mutated_authority_chain_as_a_fork() {
        let (receipt, mut history) = receipt_fixture();
        history.entries[0]["versionId"] = serde_json::Value::String("1-zfork".to_owned());
        let error = verify_account_binding_receipt_at_issuance(
            &receipt,
            &FrozenResolver { outcome: history },
        )
        .unwrap_err();
        assert!(matches!(error, AuthorityHistoryVerificationError::Fork(_)));
    }
}
