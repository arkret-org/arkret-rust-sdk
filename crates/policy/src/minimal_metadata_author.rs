//! Minimal-metadata content author credential validator (spec 2026-07-10,
//! encryption-and-audit.md §2.10.3).
//!
//! For a `ak.profile.mls.minimal_metadata_realm.v1` Realm, the ONLY trust
//! anchor for content authorship is the RFC 9420 BasicCredential LeafNode
//! that is active at the encrypted envelope's `(group_id, epoch,
//! group_state_ref)`: the credential identity must equal
//! `utf8(Event.actor_id)` byte-for-byte, exactly one active leaf may match,
//! and the Event proof's resolved public key must equal that leaf's
//! `signature_key` byte-for-byte. A principal-scoped `keys/query` directory
//! fallback is forbidden — this module is deliberately pure: it takes an
//! already-authenticated historical group-state view and never accepts a
//! directory client or resolver callback, so a caller cannot accidentally
//! wire a network fallback through it.
use arkret_wire::{Did, DidCoreId, DidUrl, MlsGroupId, project_did_to_core_id};

/// Credential carried by an active leaf in an [`AuthorGroupStateView`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorLeafCredential {
    /// RFC 9420 BasicCredential; `identity` is the raw credential content.
    Basic { identity: Vec<u8> },
    /// Any non-basic credential type. Never matches an author claim — the
    /// minimal-metadata trust anchor is defined over BasicCredential only.
    Other { credential_type: String },
}

/// One leaf that is active (present in the ratchet tree) at the view's epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorLeaf {
    pub leaf_index: u32,
    pub credential: AuthorLeafCredential,
    /// The leaf's MLS `signature_key` bytes.
    pub signature_key: Vec<u8>,
    /// Exact RFC 9420 TLS serialization of the active LeafNode.
    pub leaf_node_canonical_bytes: Vec<u8>,
}

/// An already-authenticated historical MLS group-state view.
///
/// The caller is responsible for having verified (out of band, e.g. against
/// its accepted genesis / winning-commit log) that `group_state_ref` is the
/// winning group state for `epoch` and that `active_leaves` is the complete
/// leaf set of that state — removed leaves MUST NOT appear here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorGroupStateView {
    pub group_id: MlsGroupId,
    pub epoch: u64,
    /// The winning `group_state_ref` for `epoch`, as verified by the caller.
    pub group_state_ref: String,
    pub active_leaves: Vec<AuthorLeaf>,
}

/// The `(envelope, Event, proof)` author claim to validate against a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinimalMetadataAuthorClaim<'a> {
    /// `encrypted_content.group_id` from the envelope.
    pub group_id: &'a str,
    /// `encrypted_content.epoch` from the envelope.
    pub epoch: u64,
    /// `encrypted_content.key_ref.group_state_ref` from the envelope.
    pub group_state_ref: &'a str,
    /// `Event.actor_id`, the realm-scoped pairwise Core DidCoreId. The raw leaf
    /// credential identity is this DidCoreId, never the resolvable did:key.
    pub actor_id: &'a DidCoreId,
    /// Event proof verification method. Its controller MUST be a did:key
    /// DID whose active adapter projection equals `actor_id`.
    pub proof_verification_method: &'a DidUrl,
    /// The proof's resolved public key, raw bytes (e.g. Ed25519 32 bytes via
    /// `arkret_signatures::proof::PublicKeyMaterial::ed25519_bytes`).
    pub proof_public_key: &'a [u8],
}

/// Which invariant failed. Diagnostic only — every variant maps to the single
/// canonical wire reason [`arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinimalMetadataAuthorViolation {
    /// Envelope `group_id` does not equal the view's group id.
    GroupIdMismatch,
    /// Envelope `epoch` does not equal the view's epoch.
    EpochMismatch,
    /// Envelope `group_state_ref` is not the winning group state for the
    /// epoch (rollback / non-winning fork).
    GroupStateRefNotWinning,
    /// The proof method is not a did:key URL, or its DID controller does
    /// not project byte-for-byte to the Event Core DidCoreId.
    ProofVerificationMethodMismatch,
    /// No active leaf carries a BasicCredential equal to `utf8(actor_id)`
    /// (covers removed leaves and never-member actors).
    NoActiveLeafForActor,
    /// More than one active leaf claims the actor's identity.
    DuplicateActiveLeafIdentity,
    /// The unique matching leaf's `signature_key` does not equal the proof's
    /// resolved public key.
    SignatureKeyMismatch,
}

impl MinimalMetadataAuthorViolation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroupIdMismatch => "group_id_mismatch",
            Self::EpochMismatch => "epoch_mismatch",
            Self::GroupStateRefNotWinning => "group_state_ref_not_winning",
            Self::ProofVerificationMethodMismatch => "proof_verification_method_mismatch",
            Self::NoActiveLeafForActor => "no_active_leaf_for_actor",
            Self::DuplicateActiveLeafIdentity => "duplicate_active_leaf_identity",
            Self::SignatureKeyMismatch => "signature_key_mismatch",
        }
    }
}

/// Validation failure. All variants share the canonical wire reason code so
/// receivers reject uniformly as
/// `failed_precondition + minimal_metadata_author_credential_invalid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "{}: {}",
    arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID,
    .violation.as_str()
)]
pub struct MinimalMetadataAuthorError {
    pub violation: MinimalMetadataAuthorViolation,
}

impl MinimalMetadataAuthorError {
    /// The canonical `failed_precondition` sub-reason for every failure mode.
    pub const fn reason_code(&self) -> &'static str {
        arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID
    }
}

/// The accepted author binding: which active leaf authenticated the claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAuthorLeaf {
    pub leaf_index: u32,
}

/// Validate a minimal-metadata content author claim against an
/// already-authenticated historical group-state view.
///
/// Accepts iff the envelope coordinates match the view exactly and the view
/// contains exactly one active BasicCredential leaf whose identity equals
/// `utf8(actor_id)` and whose `signature_key` equals the proof key. Every
/// failure carries [`arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID`]; the
/// caller MUST fail closed and MUST NOT fall back to a principal-scoped
/// directory query.
pub fn verify_minimal_metadata_author(
    view: &AuthorGroupStateView,
    claim: &MinimalMetadataAuthorClaim<'_>,
) -> Result<VerifiedAuthorLeaf, MinimalMetadataAuthorError> {
    let reject = |violation| Err(MinimalMetadataAuthorError { violation });

    if claim.group_id.as_bytes() != view.group_id.as_bytes() {
        return reject(MinimalMetadataAuthorViolation::GroupIdMismatch);
    }
    if claim.epoch != view.epoch {
        return reject(MinimalMetadataAuthorViolation::EpochMismatch);
    }
    if claim.group_state_ref.as_bytes() != view.group_state_ref.as_bytes() {
        return reject(MinimalMetadataAuthorViolation::GroupStateRefNotWinning);
    }

    let Some((controller, _)) = claim.proof_verification_method.as_str().split_once('#') else {
        return reject(MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch);
    };
    if !controller.starts_with("did:key:") {
        return reject(MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch);
    }
    let Ok(controller) = Did::new(controller.to_owned()) else {
        return reject(MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch);
    };
    let Ok(projected) = project_did_to_core_id(&controller) else {
        return reject(MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch);
    };
    if projected != *claim.actor_id {
        return reject(MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch);
    }

    let actor_identity = claim.actor_id.as_str().as_bytes();
    let mut matching = view.active_leaves.iter().filter(|leaf| {
        matches!(
            &leaf.credential,
            AuthorLeafCredential::Basic { identity } if identity.as_slice() == actor_identity
        )
    });
    let Some(leaf) = matching.next() else {
        return reject(MinimalMetadataAuthorViolation::NoActiveLeafForActor);
    };
    if matching.next().is_some() {
        return reject(MinimalMetadataAuthorViolation::DuplicateActiveLeafIdentity);
    }
    if leaf.signature_key.as_slice() != claim.proof_public_key {
        return reject(MinimalMetadataAuthorViolation::SignatureKeyMismatch);
    }
    Ok(VerifiedAuthorLeaf {
        leaf_index: leaf.leaf_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> DidCoreId {
        project_did_to_core_id(&Did::new("did:key:z6MkpairwiseAlice").unwrap()).unwrap()
    }

    fn key(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn basic_leaf(index: u32, identity: &str, signature_key: Vec<u8>) -> AuthorLeaf {
        AuthorLeaf {
            leaf_index: index,
            credential: AuthorLeafCredential::Basic {
                identity: identity.as_bytes().to_vec(),
            },
            signature_key,
            leaf_node_canonical_bytes: Vec::new(),
        }
    }

    fn view(leaves: Vec<AuthorLeaf>) -> AuthorGroupStateView {
        AuthorGroupStateView {
            group_id: MlsGroupId::new("QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4").unwrap(),
            epoch: 7,
            group_state_ref: "ak:event:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9".to_owned(),
            active_leaves: leaves,
        }
    }

    fn claim<'a>(actor: &'a DidCoreId, proof_key: &'a [u8]) -> MinimalMetadataAuthorClaim<'a> {
        static PROOF_METHOD: std::sync::LazyLock<DidUrl> = std::sync::LazyLock::new(|| {
            DidUrl::new("did:key:z6MkpairwiseAlice#z6MkpairwiseAlice").unwrap()
        });
        MinimalMetadataAuthorClaim {
            group_id: "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4",
            epoch: 7,
            group_state_ref: "ak:event:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9",
            actor_id: actor,
            proof_verification_method: &PROOF_METHOD,
            proof_public_key: proof_key,
        }
    }

    #[test]
    fn active_unique_leaf_is_accepted() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![
            basic_leaf(0, "ak:did_core:key:z6MkpairwiseBob", key(0xB0)),
            basic_leaf(3, actor.as_str(), proof_key.clone()),
        ]);

        let verified = verify_minimal_metadata_author(&view, &claim(&actor, &proof_key)).unwrap();
        assert_eq!(verified.leaf_index, 3);
    }

    #[test]
    fn duplicate_active_leaf_identity_is_rejected() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![
            basic_leaf(1, actor.as_str(), proof_key.clone()),
            basic_leaf(4, actor.as_str(), key(0xC4)),
        ]);

        let err = verify_minimal_metadata_author(&view, &claim(&actor, &proof_key)).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::DuplicateActiveLeafIdentity
        );
        assert_eq!(
            err.reason_code(),
            arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID
        );
    }

    #[test]
    fn removed_leaf_is_rejected_as_no_active_leaf() {
        // A removed leaf is simply absent from the active leaf set.
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![basic_leaf(
            0,
            "ak:did_core:key:z6MkpairwiseBob",
            key(0xB0),
        )]);

        let err = verify_minimal_metadata_author(&view, &claim(&actor, &proof_key)).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::NoActiveLeafForActor
        );
    }

    #[test]
    fn non_winning_group_state_ref_is_rejected() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![basic_leaf(3, actor.as_str(), proof_key.clone())]);
        let mut rollback = claim(&actor, &proof_key);
        rollback.group_state_ref = "ak:event:AXXyHtC0MgQ7on9ZHrO_NaIHvB0Lz6pk0TlTNxj6Wyp1";

        let err = verify_minimal_metadata_author(&view, &rollback).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::GroupStateRefNotWinning
        );
    }

    #[test]
    fn epoch_rollback_is_rejected() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![basic_leaf(3, actor.as_str(), proof_key.clone())]);
        let mut rollback = claim(&actor, &proof_key);
        rollback.epoch = 6;

        let err = verify_minimal_metadata_author(&view, &rollback).unwrap_err();
        assert_eq!(err.violation, MinimalMetadataAuthorViolation::EpochMismatch);
    }

    #[test]
    fn group_id_mismatch_is_rejected() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![basic_leaf(3, actor.as_str(), proof_key.clone())]);
        let mut wrong_group = claim(&actor, &proof_key);
        wrong_group.group_id = "mnoZ_saVPf3fDTNZYVjrFGJxJwRL6QkkU1EzZRYPzm4";

        let err = verify_minimal_metadata_author(&view, &wrong_group).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::GroupIdMismatch
        );
    }

    #[test]
    fn signature_key_mismatch_is_rejected() {
        let actor = actor();
        let leaf_key = key(0xA1);
        let other_proof_key = key(0xE7);
        let view = view(vec![basic_leaf(3, actor.as_str(), leaf_key)]);

        let err =
            verify_minimal_metadata_author(&view, &claim(&actor, &other_proof_key)).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::SignatureKeyMismatch
        );
    }

    #[test]
    fn proof_did_must_project_to_event_actor_core_id() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![basic_leaf(3, actor.as_str(), proof_key.clone())]);
        let wrong_method = DidUrl::new("did:key:z6MkpairwiseMallory#z6MkpairwiseAlice").unwrap();
        let mut mismatched = claim(&actor, &proof_key);
        mismatched.proof_verification_method = &wrong_method;

        let err = verify_minimal_metadata_author(&view, &mismatched).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::ProofVerificationMethodMismatch
        );
    }

    #[test]
    fn non_basic_credential_never_matches() {
        let actor = actor();
        let proof_key = key(0xA1);
        let view = view(vec![AuthorLeaf {
            leaf_index: 3,
            credential: AuthorLeafCredential::Other {
                credential_type: "x509".to_owned(),
            },
            signature_key: proof_key.clone(),
            leaf_node_canonical_bytes: vec![0xA1],
        }]);

        let err = verify_minimal_metadata_author(&view, &claim(&actor, &proof_key)).unwrap_err();
        assert_eq!(
            err.violation,
            MinimalMetadataAuthorViolation::NoActiveLeafForActor
        );
    }

    #[test]
    fn error_display_carries_canonical_reason() {
        let err = MinimalMetadataAuthorError {
            violation: MinimalMetadataAuthorViolation::SignatureKeyMismatch,
        };
        let text = err.to_string();
        assert!(text.contains("minimal_metadata_author_credential_invalid"));
        assert!(text.contains("signature_key_mismatch"));
    }
}
