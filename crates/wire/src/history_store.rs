//! Device-local history-only store record classes.
//!
//! `zh/governance/history-visibility.md` §7 splits every history secret a
//! device holds into exactly two record classes, and both live here rather
//! than inside one consumer because three layers need the same shapes: the
//! exporter-AEAD open path (`arkret-mls`) produces the Event binding, the
//! bounded ledger (`arkret-state`) admits and evicts them, and the private
//! history-key surface (`arkret-models-collaboration`) attributes received
//! material to its origin.
//!
//! * `external_candidate` — [`HistoryCandidateMaterialKey`] / [`HistoryCandidateMaterialRecord`],
//!   the closed `history-key.schema.json#/$defs/history_candidate_material_key` and
//!   `#/$defs/history_candidate_material_record` shapes. Every secret that arrives through a
//!   history response, an organization-recovery archive or a portable backup is one of these and
//!   stays one forever.
//! * `local_authoritative` — [`LocalAuthoritativeHistorySecret`], the separate record class the
//!   schema description of `history_candidate_material_record` names but deliberately gives no wire
//!   `$def`: it is device-local and MUST NOT be transmitted.
//!
//! `event_local_binding` — [`EventCandidateBinding`] — is the third state and
//! the only thing an AEAD success may record. There is no epoch-level
//! `verified` state and no promotion between the classes
//! (`history-visibility.md:140`, `:416`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, WireError};
use crate::event_envelope::HistoryEffectiveScope;
use crate::generated::{HISTORY_STORE_LIMITS, MLS_CIPHERSUITES};
use crate::organization_recovery::{validate_base64url_bounded, validate_canonical_mls_group_id};
use crate::{EventId, Hash};

/// Maximum characters of a `verified_sender_domain` or a
/// `source_sender_domain`, from
/// `history-key.schema.json#/$defs/event_candidate_binding` and
/// `#/$defs/history_candidate_origin_attribution`.
pub const MAX_HISTORY_SENDER_DOMAIN_CHARS: usize = 512;

/// Maximum characters of a device-local durable MLS post-state handle.
///
/// The handle never leaves the device, so its only requirement is that a
/// bounded, non-empty string identifies exactly one durable local record.
pub const MAX_LOCAL_MLS_STATE_REF_CHARS: usize = 512;

/// Counterpart for
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/history_candidate_material_key`.
///
/// Global received-material identity. Origin is deliberately absent: equal
/// bytes at the same scope/group/epoch deduplicate to one resident material
/// instance (`history-visibility.md:409-412`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCandidateMaterialKey {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub candidate_digest: Hash,
}

impl HistoryCandidateMaterialKey {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_mls_group_id(&self.effective_scope, &self.mls_group_id)
    }

    /// `(effective_scope, mls_group_id, epoch)` — the quota key every
    /// `history_store` limit except `max_origin_attributions_per_candidate` is
    /// counted under.
    pub fn is_same_scope_group_epoch(&self, other: &Self) -> bool {
        self.effective_scope == other.effective_scope
            && self.mls_group_id == other.mls_group_id
            && self.epoch == other.epoch
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/history_candidate_material_record`.
///
/// Device-local resident received bytes. `material_received_sequence` is
/// assigned once when this byte instance becomes resident and is immutable;
/// adding origin attribution never refreshes it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCandidateMaterialRecord {
    pub material_key: HistoryCandidateMaterialKey,
    pub secret_b64u: String,
    pub material_received_sequence: u64,
}

impl HistoryCandidateMaterialRecord {
    pub fn validate(&self) -> Result<()> {
        self.material_key.validate()?;
        validate_base64url_bounded(&self.secret_b64u, 1, usize::MAX, "secret_b64u")
    }
}

/// Device-local `local_authoritative` history-secret record class.
///
/// `history-visibility.md:416` and `key-management.md:864-866`: a secret is
/// `local_authoritative` only when **this** endpoint exported it from an MLS
/// epoch state it fully verified and actually applied, and durably retained
/// that post-state. It uses a separate accounting class from received
/// candidate material, consumes no received slot and is never evicted
/// (`history-recovery-scalability-registry.json#/history_store/material_quota_rule`).
///
/// The protocol gives this class no wire `$def` on purpose: it is device-local
/// and MUST NOT be transmitted. The only projection allowed to leave the
/// device is the packed [`crate::history_secret::HistorySecretRange`] inside a
/// portable key backup, and on another endpoint that material comes back as an
/// ordinary `external_candidate` with `portable_backup` attribution
/// (`history-visibility.md:417-418`).
///
/// The three transition fields are the exact `ak.component.mls.epoch.v1`
/// winner-tuple members (`event-kind-registry.json#/.../effective_epoch_cell_rule`,
/// `history-visibility.md:501-503`): `transition_ref` is the Genesis/Commit
/// EventId, `transition_event_digest` is the outer signed Event digest, and
/// `mls_transition_digest` is the MLS transition content digest. Binding all
/// three plus `local_state_ref` is what makes "the exact verified and durable
/// post-state this secret was exported from" checkable rather than asserted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAuthoritativeHistorySecret {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub mls_ciphersuite: String,
    pub local_state_ref: String,
    pub transition_ref: EventId,
    pub transition_event_digest: Hash,
    pub mls_transition_digest: Hash,
    pub secret_b64u: String,
}

impl LocalAuthoritativeHistorySecret {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_mls_group_id(&self.effective_scope, &self.mls_group_id)?;
        if !MLS_CIPHERSUITES
            .iter()
            .any(|suite| suite.canonical_id == self.mls_ciphersuite)
        {
            return Err(WireError::Protocol(
                "local-authoritative history secret names an unregistered MLS ciphersuite"
                    .to_owned(),
            ));
        }
        if !(1..=MAX_LOCAL_MLS_STATE_REF_CHARS).contains(&self.local_state_ref.chars().count()) {
            return Err(WireError::Protocol(format!(
                "local-authoritative history secret local_state_ref must contain 1..={MAX_LOCAL_MLS_STATE_REF_CHARS} characters"
            )));
        }
        validate_base64url_bounded(&self.secret_b64u, 1, usize::MAX, "secret_b64u")
    }

    /// The `(effective_scope, mls_group_id, epoch)` coordinate this secret is
    /// authoritative for.
    pub fn is_same_scope_group_epoch(
        &self,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> bool {
        self.effective_scope == *effective_scope
            && self.mls_group_id == mls_group_id
            && self.epoch == epoch
    }
}

/// Counterpart for the `event_binding_key` member of
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/event_candidate_binding`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCandidateBindingKey {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub event_id: EventId,
    pub event_digest: Hash,
    pub verified_sender_domain: String,
}

impl EventCandidateBindingKey {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_mls_group_id(&self.effective_scope, &self.mls_group_id)?;
        if !(1..=MAX_HISTORY_SENDER_DOMAIN_CHARS)
            .contains(&self.verified_sender_domain.chars().count())
        {
            return Err(WireError::Protocol(format!(
                "history verified_sender_domain must contain 1..={MAX_HISTORY_SENDER_DOMAIN_CHARS} characters"
            )));
        }
        Ok(())
    }

    /// The material key the named candidate digest occupies under this
    /// binding's scope/group/epoch.
    pub fn material_key(&self, candidate_digest: Hash) -> HistoryCandidateMaterialKey {
        HistoryCandidateMaterialKey {
            effective_scope: self.effective_scope.clone(),
            mls_group_id: self.mls_group_id.clone(),
            epoch: self.epoch,
            candidate_digest,
        }
    }
}

/// The two-valued AEAD result an `event_local_binding` may record. Neither
/// value promotes a candidate or an epoch (`history-visibility.md:437-440`).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCandidateBindingOutcome {
    Success,
    Failure,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/history-key.schema.json#/$defs/event_candidate_binding`.
///
/// Keyed by `(event_binding_key, candidate_digest, outcome)`. It contains no
/// origin, must not be used to infer one, and never pins candidate bytes.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCandidateBinding {
    pub event_binding_key: EventCandidateBindingKey,
    pub candidate_digest: Hash,
    pub outcome: EventCandidateBindingOutcome,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub first_observed_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl EventCandidateBinding {
    /// Build the binding an AEAD attempt against one exact candidate produces.
    /// `expires_at` is the registry lifetime and is never extended.
    pub fn new(
        event_binding_key: EventCandidateBindingKey,
        candidate_digest: Hash,
        outcome: EventCandidateBindingOutcome,
        first_observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let expires_at = first_observed_at
            .checked_add_signed(chrono::Duration::seconds(
                HISTORY_STORE_LIMITS.event_candidate_binding_ttl_seconds,
            ))
            .ok_or_else(|| {
                WireError::Protocol("history Event candidate binding expiry overflows".to_owned())
            })?;
        let binding = Self {
            event_binding_key,
            candidate_digest,
            outcome,
            first_observed_at,
            expires_at,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<()> {
        self.event_binding_key.validate()?;
        if self
            .expires_at
            .signed_duration_since(self.first_observed_at)
            != chrono::Duration::seconds(HISTORY_STORE_LIMITS.event_candidate_binding_ttl_seconds)
        {
            return Err(WireError::Protocol(format!(
                "history Event candidate binding expiry must equal first_observed_at plus {} seconds",
                HISTORY_STORE_LIMITS.event_candidate_binding_ttl_seconds
            )));
        }
        Ok(())
    }
}
