//! Accepted MLS activation and admissible content.

/// Reducer-pure validator for the content shape a scope admits.
///
/// A write into a scope whose `ak.mls.genesis` is already accepted MUST carry
/// RFC 9420 application ciphertext (wire reason
/// [`arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED`]). An encrypted write
/// into a scope with no accepted MLS activation is refused as a generic
/// `failed_precondition` without a reason code (visibility-policy vector
/// `ak.vector.e2ee.ciphertext_write_before_activation_rejected.v1`).
pub fn validate_scope_mls_activation(
    scope_mls_group_id: Option<&str>,
    write_is_encrypted: bool,
) -> Result<(), MlsActivationError> {
    match (scope_mls_group_id, write_is_encrypted) {
        (Some(_), false) => Err(MlsActivationError::MlsActivationRequired),
        (None, true) => Err(MlsActivationError::MlsScopeInactive),
        _ => Ok(()),
    }
}

/// Reducer-pure validator: an accepted MLS activation is irreversible. A second
/// `ak.mls.genesis` for the same scope, or any transition that would clear the
/// committed `mls_group_id`, is rejected with wire reason
/// [`arkret_wire::ReasonCode::MLS_ACTIVATION_IRREVERSIBLE`].
pub fn validate_mls_activation_is_irreversible(
    previous_mls_group_id: Option<&str>,
    next_mls_group_id: Option<&str>,
) -> Result<(), MlsActivationError> {
    match (previous_mls_group_id, next_mls_group_id) {
        (None, _) => Ok(()),
        (Some(previous), Some(next)) if previous == next => Ok(()),
        _ => Err(MlsActivationError::MlsActivationIrreversible),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MlsActivationError {
    /// Plaintext write into a scope whose `ak.mls.genesis` is accepted.
    #[error(
        "reason=mls_activation_required: content write into an activated scope is not MLS-backed"
    )]
    MlsActivationRequired,
    /// Encrypted write into a scope without an accepted MLS activation. It is
    /// a generic `failed_precondition` and carries no reason code.
    #[error("encrypted write into a scope without an accepted MLS activation")]
    MlsScopeInactive,
    /// An attempt to re-run or undo an accepted MLS activation.
    #[error(
        "reason=mls_activation_irreversible: an accepted MLS activation cannot be replaced or cleared"
    )]
    MlsActivationIrreversible,
}
