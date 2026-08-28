//! Private history-key recovery and direct governance-traversal wire objects.

use std::fmt;

use arkret_models_identity::{AgentLifecycleStatus, AgentSignerEvidence};
use arkret_wire::{
    Base64UrlString, CircleId, DeviceId, DidCoreId, DidUrl, EventId, Hash, HistoryAccess,
    HistoryEffectiveScope, OrganizationRecoveryArchive, PayloadProof, RealmId, Result, SealBasis,
    SignerEvidenceRef, WireError,
};
pub use arkret_wire::{
    EpochRange, EventCandidateBinding, EventCandidateBindingKey, EventCandidateBindingOutcome,
    HistoryCandidateMaterialKey, HistoryCandidateMaterialRecord, HistorySecretRange,
    LocalAuthoritativeHistorySecret, validate_canonical_ranges,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

macro_rules! history_id {
    ($name:ident, $prefix:literal, $validate:expr) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$validate(&value) {
                    return Err(WireError::Protocol(format!(
                        "invalid {}",
                        stringify!($name)
                    )));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

fn uuid_v7_suffix(value: &str, prefix: &str) -> bool {
    let Some(value) = value.strip_prefix(prefix) else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

history_id!(HistoryRequestId, "ak:history_request:", |value: &str| {
    uuid_v7_suffix(value, "ak:history_request:")
});
history_id!(HistoryResponseId, "ak:history_response:", |value: &str| {
    uuid_v7_suffix(value, "ak:history_response:")
});

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationIncarnation {
    Realm {
        realm_membership_incarnation_ref: EventId,
    },
    Circle {
        realm_membership_incarnation_ref: EventId,
        circle_membership_incarnation_ref: EventId,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorProfile {
    OrdinaryHuman,
    NativeAgent,
    MinimalMetadata,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequesterEndpointAuthorization {
    OrdinaryHuman {
        requester_device_id: DeviceId,
        requester_device_authorize_event_id: EventId,
        requester_device_generation_ref: u64,
    },
    NativeAgent {
        requester_agent_id: DidCoreId,
        requester_agent_verification_method: DidUrl,
        requester_agent_key_authorize_event_id: EventId,
    },
    MinimalMetadata,
}

impl RequesterEndpointAuthorization {
    pub fn validate_for_profile(&self, profile: AuthorProfile) -> Result<()> {
        let matches = matches!(
            (profile, self),
            (
                AuthorProfile::OrdinaryHuman,
                Self::OrdinaryHuman {
                    requester_device_generation_ref: 1..,
                    ..
                }
            ) | (AuthorProfile::NativeAgent, Self::NativeAgent { .. })
                | (AuthorProfile::MinimalMetadata, Self::MinimalMetadata)
        );
        if !matches {
            return Err(WireError::Protocol(
                "requester endpoint authorization does not match requester_author_profile"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSenderQuotaDomain {
    pub source_sender_domain: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSenderOriginRef {
    pub response_id: HistoryResponseId,
    pub source_record_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RrkArchiveQuotaDomain {
    pub holder_principal_id: DidCoreId,
    pub holder_id: DidCoreId,
    pub recovery_key_id: String,
    pub accepted_key_evidence_ref: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RrkArchiveOriginRef {
    pub container_event_ref: EventId,
    pub archive_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableBackupQuotaDomain {
    pub backup_series_id: String,
    pub producer_actor_id: DidCoreId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableBackupOriginRef {
    pub backup_origin_id: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryCandidateOriginDomain {
    ResponseSender,
    RrkArchive,
    PortableBackup,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin_domain", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryCandidateOriginAttribution {
    ResponseSender {
        material_key: HistoryCandidateMaterialKey,
        origin_quota_domain: ResponseSenderQuotaDomain,
        origin_ref: ResponseSenderOriginRef,
        #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
        first_observed_at: DateTime<Utc>,
    },
    RrkArchive {
        material_key: HistoryCandidateMaterialKey,
        origin_quota_domain: RrkArchiveQuotaDomain,
        origin_ref: RrkArchiveOriginRef,
        #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
        first_observed_at: DateTime<Utc>,
    },
    PortableBackup {
        material_key: HistoryCandidateMaterialKey,
        origin_quota_domain: PortableBackupQuotaDomain,
        origin_ref: PortableBackupOriginRef,
        #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
        first_observed_at: DateTime<Utc>,
    },
}

impl HistoryCandidateOriginAttribution {
    /// The received-material instance this row attributes. Origin is
    /// deliberately not part of material identity, so several rows share one
    /// key (`history-visibility.md:409-412`).
    pub fn material_key(&self) -> &HistoryCandidateMaterialKey {
        match self {
            Self::ResponseSender { material_key, .. }
            | Self::RrkArchive { material_key, .. }
            | Self::PortableBackup { material_key, .. } => material_key,
        }
    }

    /// The closed origin-domain discriminator derived from the enum variant.
    pub fn origin_domain(&self) -> HistoryCandidateOriginDomain {
        match self {
            Self::ResponseSender { .. } => HistoryCandidateOriginDomain::ResponseSender,
            Self::RrkArchive { .. } => HistoryCandidateOriginDomain::RrkArchive,
            Self::PortableBackup { .. } => HistoryCandidateOriginDomain::PortableBackup,
        }
    }

    /// RFC 8785 canonical bytes of the stable `origin_quota_domain`. Every
    /// per-domain quota is counted over exactly these bytes, never over the
    /// retrieval-only `origin_ref`.
    pub fn origin_quota_domain_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::ResponseSender {
                origin_quota_domain,
                ..
            } => arkret_wire::canonical::canonical_json_bytes(origin_quota_domain)?,
            Self::RrkArchive {
                origin_quota_domain,
                ..
            } => arkret_wire::canonical::canonical_json_bytes(origin_quota_domain)?,
            Self::PortableBackup {
                origin_quota_domain,
                ..
            } => arkret_wire::canonical::canonical_json_bytes(origin_quota_domain)?,
        })
    }

    /// RFC 8785 canonical bytes of the retrieval-only `origin_ref`. It
    /// completes the ledger row key and never selects quota identity.
    pub fn origin_ref_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::ResponseSender { origin_ref, .. } => {
                arkret_wire::canonical::canonical_json_bytes(origin_ref)?
            }
            Self::RrkArchive { origin_ref, .. } => {
                arkret_wire::canonical::canonical_json_bytes(origin_ref)?
            }
            Self::PortableBackup { origin_ref, .. } => {
                arkret_wire::canonical::canonical_json_bytes(origin_ref)?
            }
        })
    }

    pub fn first_observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::ResponseSender {
                first_observed_at, ..
            }
            | Self::RrkArchive {
                first_observed_at, ..
            }
            | Self::PortableBackup {
                first_observed_at, ..
            } => *first_observed_at,
        }
    }

    pub fn expires_at(&self) -> Result<DateTime<Utc>> {
        self.first_observed_at()
            .checked_add_signed(chrono::Duration::seconds(2_592_000))
            .ok_or_else(|| {
                WireError::Protocol("history candidate origin expiry overflows".to_owned())
            })
    }

    /// Exact ledger-row identity `(material_key, origin_domain, origin_ref)`.
    /// An exact duplicate is a no-op and never refreshes `first_observed_at`.
    pub fn is_same_row(&self, other: &Self) -> Result<bool> {
        Ok(self.material_key() == other.material_key()
            && self.origin_domain() == other.origin_domain()
            && self.origin_ref_bytes()? == other.origin_ref_bytes()?)
    }

    /// Whether two rows share one exact
    /// `(scope, group, epoch, origin_domain, origin_quota_domain)` quota bucket.
    pub fn is_same_quota_bucket(&self, other: &Self) -> Result<bool> {
        Ok(self
            .material_key()
            .is_same_scope_group_epoch(other.material_key())
            && self.origin_domain() == other.origin_domain()
            && self.origin_quota_domain_bytes()? == other.origin_quota_domain_bytes()?)
    }

    /// `(first_observed_at, candidate_digest, origin_domain, JCS(origin_quota_domain),
    /// JCS(origin_ref))` — the canonical tuple an over-cap ledger keeps the
    /// minimum of (`history-visibility.md:433-434`).
    ///
    /// `expires_at` is rendered through the canonical fixed-millisecond
    /// formatter rather than chrono's default: the default trims trailing
    /// subsecond zeros, which would make `…:00Z` sort after `…:00.500Z` and
    /// turn a deterministic rule into a precision-dependent one.
    pub fn canonical_retention_key(&self) -> Result<Vec<u8>> {
        arkret_wire::canonical::canonical_json_bytes(&serde_json::json!([
            arkret_wire::canonical::format_timestamp_canonical(self.first_observed_at()),
            self.material_key().candidate_digest,
            self.origin_domain(),
            serde_json::from_slice::<serde_json::Value>(&self.origin_quota_domain_bytes()?)?,
            serde_json::from_slice::<serde_json::Value>(&self.origin_ref_bytes()?)?,
        ]))
        .map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        let material_key = match self {
            Self::ResponseSender {
                material_key,
                origin_quota_domain,
                ..
            } => {
                validate_sender_domain(&origin_quota_domain.source_sender_domain)?;
                material_key
            }
            Self::RrkArchive {
                material_key,
                origin_quota_domain,
                ..
            } => {
                validate_bounded_chars(
                    &origin_quota_domain.recovery_key_id,
                    1,
                    512,
                    "recovery_key_id",
                )?;
                material_key
            }
            Self::PortableBackup {
                material_key,
                origin_quota_domain,
                origin_ref,
                ..
            } => {
                if !uuid_v7_suffix(&origin_quota_domain.backup_series_id, "ak:backup_series:") {
                    return Err(WireError::Protocol(
                        "history backup series id is invalid".to_owned(),
                    ));
                }
                let backup_id = origin_ref
                    .backup_origin_id
                    .strip_prefix("backup:")
                    .ok_or_else(|| {
                        WireError::Protocol("history backup origin id is invalid".to_owned())
                    })?;
                if !(uuid_v7_suffix(backup_id, "ak:backup:")
                    || backup_id.strip_prefix("sha256:").is_some_and(|hex| {
                        hex.len() == 64
                            && hex
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    }))
                {
                    return Err(WireError::Protocol(
                        "history backup origin id is invalid".to_owned(),
                    ));
                }
                material_key
            }
        };
        material_key.validate()?;
        self.expires_at()?;
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryChunkPlaintextKind {
    #[serde(rename = "ak.history_key.chunk_plaintext")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryChunkPlaintext {
    pub kind: HistoryChunkPlaintextKind,
    pub secret_range: HistorySecretRange,
}

impl HistoryChunkPlaintext {
    pub fn validate(&self) -> Result<()> {
        self.secret_range.validate()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryResponseCapabilityPlaintextKind {
    #[serde(rename = "ak.history_key.response_capability_plaintext")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseCapabilityPlaintext {
    pub kind: HistoryResponseCapabilityPlaintextKind,
    pub response_capability_b64u: String,
}

impl HistoryResponseCapabilityPlaintext {
    pub fn validate(&self) -> Result<()> {
        let decoded = arkret_wire::base64url::base64url_decode(&self.response_capability_b64u)?;
        if decoded.len() != 32
            || arkret_wire::base64url::base64url_encode(&decoded) != self.response_capability_b64u
        {
            return Err(WireError::Protocol(
                "history response capability plaintext is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryResponseCapabilitySealPurpose {
    #[serde(rename = "history_response_capability")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseCapabilitySealContext {
    pub purpose: HistoryResponseCapabilitySealPurpose,
    pub request_digest: Hash,
    pub response_capability_commitment: Hash,
    pub effective_scope: HistoryEffectiveScope,
    pub release_id: DidCoreId,
    pub release_service_binding_ref: EventId,
    pub release_service_resolution_ref: String,
    pub release_service_resolution_sequence: u64,
    pub release_service_resolution_record_digest: Hash,
    pub release_service_route_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl HistoryResponseCapabilitySealContext {
    pub fn validate(&self) -> Result<()> {
        validate_bounded_chars(
            &self.release_service_resolution_ref,
            1,
            2048,
            "release_service_resolution_ref",
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(arkret_wire::canonical::canonical_json_bytes(self)?)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistorySecretChunkSealPurpose {
    #[serde(rename = "history_secret_chunk")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySecretChunkSealContext {
    pub purpose: HistorySecretChunkSealPurpose,
    pub manifest_admission_digest: Hash,
    pub chunk_response_id: HistoryResponseId,
    pub chunk_index: u64,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
}

impl HistorySecretChunkSealContext {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.source_sender_domain)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(arkret_wire::canonical::canonical_json_bytes(self)?)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRecoveryArchivePlaintextKind {
    #[serde(rename = "ak.organization_recovery.archive_plaintext")]
    Value,
}

/// Counterpart for
/// `history-key.schema.json#/$defs/organization_recovery_archive_plaintext`:
/// the only RFC 9180 plaintext of
/// `ak.hpke_surface.organization_recovery_archive.v1`. It carries exactly one
/// epoch's `history_secret` and can never carry active MLS state, counters,
/// policy snapshots, holder claims or a second epoch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchivePlaintext {
    pub kind: OrganizationRecoveryArchivePlaintextKind,
    pub history_secret_b64u: String,
}

impl OrganizationRecoveryArchivePlaintext {
    pub fn validate(&self) -> Result<()> {
        validate_base64url_bounded(&self.history_secret_b64u, 1, 512, "history_secret_b64u")
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAuthorizationTuple {
    pub recovery_key_id: String,
    pub key_agreement_ref: DidUrl,
    pub holder_principal_id: DidCoreId,
    pub holder_id: DidCoreId,
    pub holder_signing_ref: DidUrl,
    pub accepted_key_evidence_ref: EventId,
    pub holder_trusted_basis: SealBasis,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryGovernanceTraversalIntentKind {
    #[serde(rename = "ak.history_governance.traversal_intent")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestExpiringRetentionKind {
    #[serde(rename = "request_expiring")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestExpiringRetention {
    pub kind: RequestExpiringRetentionKind,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveLifetimeRetentionKind {
    #[serde(rename = "archive_lifetime")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveLifetimeRetention {
    pub kind: ArchiveLifetimeRetentionKind,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryGovernanceTraversalIntent {
    MemberHistoryDelivery {
        kind: HistoryGovernanceTraversalIntentKind,
        effective_scope: HistoryEffectiveScope,
        mls_group_id: String,
        trusted_history_base_basis: SealBasis,
        trusted_current_basis: SealBasis,
        target_basis: SealBasis,
        request_digest: Hash,
        requested_ranges: Vec<EpochRange>,
        authorization_incarnation: AuthorizationIncarnation,
        retention: RequestExpiringRetention,
    },
    OrganizationRecoveryArchive {
        kind: HistoryGovernanceTraversalIntentKind,
        effective_scope: HistoryEffectiveScope,
        mls_group_id: String,
        trusted_history_base_basis: SealBasis,
        trusted_current_basis: SealBasis,
        target_basis: SealBasis,
        requested_ranges: [EpochRange; 1],
        archive_authorization_tuple: ArchiveAuthorizationTuple,
        container_event_ref: EventId,
        retention: ArchiveLifetimeRetention,
    },
}

impl HistoryGovernanceTraversalIntent {
    pub fn validate(&self) -> Result<()> {
        let (effective_scope, mls_group_id, history_basis, current_basis, target_basis) = match self
        {
            Self::MemberHistoryDelivery {
                effective_scope,
                mls_group_id,
                trusted_history_base_basis,
                trusted_current_basis,
                target_basis,
                requested_ranges,
                ..
            } => {
                validate_canonical_ranges(requested_ranges, 64)?;
                (
                    effective_scope,
                    mls_group_id,
                    trusted_history_base_basis,
                    trusted_current_basis,
                    target_basis,
                )
            }
            Self::OrganizationRecoveryArchive {
                effective_scope,
                mls_group_id,
                trusted_history_base_basis,
                trusted_current_basis,
                target_basis,
                requested_ranges,
                archive_authorization_tuple,
                ..
            } => {
                requested_ranges[0].validate()?;
                let recovery_key_id_len =
                    archive_authorization_tuple.recovery_key_id.chars().count();
                if !(1..=512).contains(&recovery_key_id_len) {
                    return Err(WireError::Protocol(
                        "archive recovery_key_id must contain 1..=512 characters".to_owned(),
                    ));
                }
                archive_authorization_tuple
                    .holder_trusted_basis
                    .validate_protocol_bounds()?;
                (
                    effective_scope,
                    mls_group_id,
                    trusted_history_base_basis,
                    trusted_current_basis,
                    target_basis,
                )
            }
        };
        if mls_group_id.is_empty() || !is_base64url(mls_group_id) {
            return Err(WireError::Protocol(
                "history traversal mls_group_id is not canonical base64url".to_owned(),
            ));
        }
        if &effective_scope.canonical_mls_group_id()? != mls_group_id {
            return Err(WireError::Protocol(
                "history traversal mls_group_id does not match effective_scope".to_owned(),
            ));
        }
        history_basis.validate_protocol_bounds()?;
        current_basis.validate_protocol_bounds()?;
        target_basis.validate_protocol_bounds()?;
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.validate()?;
        full_object_digest(self, "ak.history-governance-traversal-intent-v1")
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryGovernanceTraversalRetention {
    pub traversal_intent: HistoryGovernanceTraversalIntent,
    pub traversal_intent_digest: Hash,
}

impl HistoryGovernanceTraversalRetention {
    pub fn from_intent(traversal_intent: HistoryGovernanceTraversalIntent) -> Result<Self> {
        let traversal_intent_digest = traversal_intent.canonical_digest()?;
        Ok(Self {
            traversal_intent,
            traversal_intent_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        self.traversal_intent.validate()?;
        let mut preimage = b"ak.history-governance-traversal-intent-v1".to_vec();
        preimage.push(0);
        preimage.extend(arkret_wire::canonical::canonical_json_bytes(
            &self.traversal_intent,
        )?);
        let expected = Hash::new(arkret_wire::canonical::sha256_digest(preimage))?;
        if expected != self.traversal_intent_digest {
            return Err(WireError::Protocol(
                "history traversal intent digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_archive(
        &self,
        archive: &OrganizationRecoveryArchive,
        container_event_ref: &EventId,
    ) -> Result<()> {
        self.validate_digest()?;
        let HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            effective_scope,
            mls_group_id,
            requested_ranges,
            archive_authorization_tuple,
            container_event_ref: intent_container_event_ref,
            ..
        } = &self.traversal_intent
        else {
            return Err(WireError::Protocol(
                "organization recovery archive requires archive-lifetime traversal intent"
                    .to_owned(),
            ));
        };
        let range = &requested_ranges[0];
        if effective_scope != &archive.effective_scope
            || mls_group_id != &archive.mls_group_id
            || range.from_epoch != archive.epoch
            || range.to_epoch != archive.epoch
            || intent_container_event_ref != container_event_ref
            || archive_authorization_tuple.recovery_key_id != archive.recovery_key_id
            || archive_authorization_tuple.key_agreement_ref != archive.key_agreement_ref
            || archive_authorization_tuple.holder_principal_id != archive.holder_principal_id
            || archive_authorization_tuple.holder_id != archive.holder_id
            || archive_authorization_tuple.holder_signing_ref != archive.holder_signing_ref
            || archive_authorization_tuple.accepted_key_evidence_ref
                != archive.accepted_key_evidence_ref
            || archive_authorization_tuple.holder_trusted_basis != archive.holder_trusted_basis
        {
            return Err(WireError::Protocol(
                "archive traversal retention does not bind the exact archive tuple".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelfHistoryTraversalAccess {
    RequestReceipt { request_receipt_digest: Hash },
    ArchiveReplica { archive_replica_digest: Hash },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerHistoryTraversalAccess {
    PendingArchiveReplica {
        pending_archive_replica_digest: Hash,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryKeyRequestKind {
    #[serde(rename = "ak.history_key.request")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestSigningInput {
    pub request_id: HistoryRequestId,
    pub kind: HistoryKeyRequestKind,
    pub effective_scope: HistoryEffectiveScope,
    pub requester_actor_id: DidCoreId,
    pub requester_sender_domain: String,
    pub requester_author_profile: AuthorProfile,
    pub requester_endpoint_authorization: RequesterEndpointAuthorization,
    pub requester_authorization_incarnation: AuthorizationIncarnation,
    pub trusted_history_base_basis: SealBasis,
    pub trusted_current_basis: SealBasis,
    pub requested_ranges: Vec<EpochRange>,
    pub recipient_hpke_public_key: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl HistoryKeyRequestSigningInput {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.requester_sender_domain)?;
        self.requester_endpoint_authorization
            .validate_for_profile(self.requester_author_profile)?;
        self.trusted_history_base_basis.validate_protocol_bounds()?;
        self.trusted_current_basis.validate_protocol_bounds()?;
        validate_canonical_ranges(&self.requested_ranges, 64)?;
        if self.recipient_hpke_public_key.len() != 43
            || !is_base64url(&self.recipient_hpke_public_key)
        {
            return Err(WireError::Protocol(
                "history request recipient HPKE public key is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequest {
    pub request_id: HistoryRequestId,
    pub kind: HistoryKeyRequestKind,
    pub effective_scope: HistoryEffectiveScope,
    pub requester_actor_id: DidCoreId,
    pub requester_sender_domain: String,
    pub requester_author_profile: AuthorProfile,
    pub requester_endpoint_authorization: RequesterEndpointAuthorization,
    pub requester_authorization_incarnation: AuthorizationIncarnation,
    pub trusted_history_base_basis: SealBasis,
    pub trusted_current_basis: SealBasis,
    pub requested_ranges: Vec<EpochRange>,
    pub recipient_hpke_public_key: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub requester_proof: PayloadProof,
}

impl HistoryKeyRequest {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.requester_sender_domain)?;
        self.requester_endpoint_authorization
            .validate_for_profile(self.requester_author_profile)?;
        self.trusted_history_base_basis.validate_protocol_bounds()?;
        self.trusted_current_basis.validate_protocol_bounds()?;
        validate_canonical_ranges(&self.requested_ranges, 64)?;
        if self.recipient_hpke_public_key.len() != 43
            || !is_base64url(&self.recipient_hpke_public_key)
        {
            return Err(WireError::Protocol(
                "history request recipient HPKE public key is invalid".to_owned(),
            ));
        }
        self.validate_proof_binding()?;
        if arkret_wire::canonical::canonical_json_bytes(self)?.len() > 65_536 {
            return Err(WireError::Protocol(
                "history key request exceeds 65536 canonical bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryKeyRequestReceiptKind {
    #[serde(rename = "ak.history_key.request_receipt")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestReceipt {
    pub kind: HistoryKeyRequestReceiptKind,
    pub request_digest: Hash,
    pub response_capability_commitment: Hash,
    pub sealed_response_capability_digest: Hash,
    pub effective_scope: HistoryEffectiveScope,
    pub requester_sender_domain: String,
    pub requester_authorization_incarnation: AuthorizationIncarnation,
    pub trusted_history_base_basis: SealBasis,
    pub trusted_current_basis: SealBasis,
    pub release_id: DidCoreId,
    pub release_service_binding_ref: EventId,
    pub release_service_resolution_ref: String,
    pub release_service_resolution_sequence: u64,
    pub release_service_resolution_record_digest: Hash,
    pub release_service_route_digest: Hash,
    pub history_traversal_retention: HistoryGovernanceTraversalRetention,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub service_proof: PayloadProof,
}

impl HistoryKeyRequestReceipt {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.requester_sender_domain)?;
        self.trusted_history_base_basis.validate_protocol_bounds()?;
        self.trusted_current_basis.validate_protocol_bounds()?;
        if self.accepted_at > self.expires_at {
            return Err(WireError::Protocol(
                "history request receipt is already expired".to_owned(),
            ));
        }
        self.validate_proof_binding()?;
        self.history_traversal_retention.validate_digest()?;
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedHistoryResponseCapability {
    pub enc: String,
    pub ciphertext: String,
}

impl SealedHistoryResponseCapability {
    pub fn validate(&self) -> Result<()> {
        if self.enc.is_empty()
            || self.ciphertext.is_empty()
            || !is_base64url(&self.enc)
            || !is_base64url(&self.ciphertext)
        {
            return Err(WireError::Protocol(
                "sealed history response capability is not canonical base64url".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryKeyRequestAcceptedKind {
    #[serde(rename = "ak.history_key.request_accepted")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestCreateOutcome {
    pub kind: HistoryKeyRequestAcceptedKind,
    pub request: HistoryKeyRequest,
    pub request_receipt: HistoryKeyRequestReceipt,
    pub sealed_history_response_capability: SealedHistoryResponseCapability,
}

impl HistoryKeyRequestCreateOutcome {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.request_receipt.validate()?;
        self.sealed_history_response_capability.validate()?;
        if self.request.effective_scope != self.request_receipt.effective_scope
            || self.request.requester_sender_domain != self.request_receipt.requester_sender_domain
            || self.request.requester_authorization_incarnation
                != self.request_receipt.requester_authorization_incarnation
            || self.request.trusted_history_base_basis
                != self.request_receipt.trusted_history_base_basis
            || self.request.trusted_current_basis != self.request_receipt.trusted_current_basis
            || self.request.expires_at != self.request_receipt.expires_at
        {
            return Err(WireError::Protocol(
                "history key request receipt does not bind the accepted request".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestRecord {
    pub request: HistoryKeyRequest,
    pub request_receipt: HistoryKeyRequestReceipt,
}

impl HistoryKeyRequestRecord {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.request_receipt.validate()?;
        if self.request.effective_scope != self.request_receipt.effective_scope
            || self.request.requester_sender_domain != self.request_receipt.requester_sender_domain
            || self.request.requester_authorization_incarnation
                != self.request_receipt.requester_authorization_incarnation
            || self.request.trusted_history_base_basis
                != self.request_receipt.trusted_history_base_basis
            || self.request.trusted_current_basis != self.request_receipt.trusted_current_basis
        {
            return Err(WireError::Protocol(
                "history request record receipt binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestListOutcome {
    pub requests: Vec<HistoryKeyRequestRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limited: bool,
}

impl HistoryKeyRequestListOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_pagination(self.limited, self.cursor.as_deref())?;
        self.requests
            .iter()
            .try_for_each(HistoryKeyRequestRecord::validate)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestListQuery {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<CircleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u8>,
}

impl HistoryKeyRequestListQuery {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty_optional(&self.cursor, "cursor")?;
        if self.limit.is_some_and(|limit| limit == 0 || limit > 100) {
            return Err(WireError::Protocol(
                "history request list limit must be 1..=100".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryKeyRequestReplicaKind {
    #[serde(rename = "ak.history_key.request_replica")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryKeyRequestReplicaDestinationAuthorization {
    MemberDeliveryBinding {
        delivery_binding_ref: EventId,
        delivery_binding_digest: Hash,
    },
    OrganizationRecoveryHolder {
        holder_principal_id: DidCoreId,
        holder_id: DidCoreId,
        archive_tuple_digest: Hash,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestReplica {
    pub kind: HistoryKeyRequestReplicaKind,
    pub request: HistoryKeyRequest,
    pub request_receipt: HistoryKeyRequestReceipt,
    pub destination_id: DidCoreId,
    pub destination_authorization: HistoryKeyRequestReplicaDestinationAuthorization,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub replicated_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub relay_proof: PayloadProof,
}

impl HistoryKeyRequestReplica {
    pub fn validate(&self) -> Result<()> {
        HistoryKeyRequestRecord {
            request: self.request.clone(),
            request_receipt: self.request_receipt.clone(),
        }
        .validate()?;
        if self.expires_at != self.request.expires_at || self.replicated_at > self.expires_at {
            return Err(WireError::Protocol(
                "history request replica expiry mismatch".to_owned(),
            ));
        }
        if let HistoryKeyRequestReplicaDestinationAuthorization::OrganizationRecoveryHolder {
            holder_id,
            ..
        } = &self.destination_authorization
            && holder_id != &self.destination_id
        {
            return Err(WireError::Protocol(
                "history request replica destination holder service mismatch".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRequestReplicaOutcome {
    pub request_digest: Hash,
    pub destination_id: DidCoreId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub service_proof: PayloadProof,
}

impl HistoryKeyRequestReplicaOutcome {
    pub fn validate(&self) -> Result<()> {
        self.validate_proof_binding()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Member,
    OrganizationRecoveryHolder,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RrkHolderAuthorityObservation {
    pub holder_principal_id: DidCoreId,
    pub holder_id: DidCoreId,
    pub current_holder_signing_ref: DidUrl,
    pub accepted_key_evidence_ref: EventId,
    pub archive_authorization_tuple_digest: Hash,
    pub holder_trusted_basis: SealBasis,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl RrkHolderAuthorityObservation {
    pub fn validate(&self) -> Result<()> {
        self.holder_trusted_basis.validate_protocol_bounds()?;
        require_sha256(
            &self.archive_authorization_tuple_digest,
            "archive_authorization_tuple_digest",
        )?;
        if self.observed_at > self.expires_at {
            return Err(WireError::Protocol(
                "RRK holder authority observation has an invalid validity window".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_archive_tuple(&self, tuple: &ArchiveAuthorizationTuple) -> Result<()> {
        self.validate()?;
        if self.holder_principal_id != tuple.holder_principal_id
            || self.holder_id != tuple.holder_id
            || self.archive_authorization_tuple_digest
                != tuple.archive_authorization_tuple_digest()?
        {
            return Err(WireError::Protocol(
                "RRK holder authority observation does not match its archive tuple".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<Hash> {
        self.validate()?;
        full_object_digest(self, "ak.rrk-holder-authority-observation-v1")
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceAuthorityLocator {
    MemberDeliveryBinding {
        binding_ref: EventId,
        binding_digest: Hash,
    },
    OrganizationRecoveryHolder {
        authority_observation: RrkHolderAuthorityObservation,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceRelayAttestationKind {
    #[serde(rename = "ak.history_key.source_relay_attestation")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRelayAttestation {
    pub kind: SourceRelayAttestationKind,
    pub source_record_digest: Hash,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    pub effective_scope: HistoryEffectiveScope,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
    pub source_kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_author_profile: Option<AuthorProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_authorization_incarnation: Option<AuthorizationIncarnation>,
    pub source_id: DidCoreId,
    pub source_authority_locator: SourceAuthorityLocator,
    pub destination_release_id: DidCoreId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub relayed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub service_proof: PayloadProof,
}

impl SourceRelayAttestation {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.source_sender_domain)?;
        match (
            self.source_kind,
            &self.source_author_profile,
            &self.source_authorization_incarnation,
            &self.source_authority_locator,
        ) {
            (
                SourceKind::Member,
                Some(_),
                Some(_),
                SourceAuthorityLocator::MemberDeliveryBinding { .. },
            ) => {}
            (
                SourceKind::OrganizationRecoveryHolder,
                None,
                None,
                SourceAuthorityLocator::OrganizationRecoveryHolder {
                    authority_observation,
                },
            ) if authority_observation.holder_id == self.source_id
                && authority_observation.holder_principal_id == self.source_actor_id
                && authority_observation.current_holder_signing_ref
                    == self.service_proof.verification_method
                && authority_observation.expires_at == self.expires_at
                && authority_observation.observed_at <= self.relayed_at =>
            {
                authority_observation.validate()?;
            }
            _ => {
                return Err(WireError::Protocol(
                    "history source relay authority branch mismatch".to_owned(),
                ));
            }
        }
        if self.relayed_at > self.expires_at {
            return Err(WireError::Protocol(
                "history source relay is already expired".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeySourceRelay {
    pub response: HistoryKeyResponseSendRequest,
    pub source_relay_attestation: SourceRelayAttestation,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryResponseManifestKind {
    #[serde(rename = "ak.history_key.response_manifest")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseChunkDescriptor {
    pub chunk_response_id: HistoryResponseId,
    pub chunk_index: u64,
    pub covered_epoch_range: EpochRange,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseManifest {
    pub kind: HistoryResponseManifestKind,
    pub chunks: Vec<HistoryResponseChunkDescriptor>,
}

impl HistoryResponseManifest {
    pub fn validate(&self) -> Result<()> {
        if self.chunks.is_empty() {
            return Err(WireError::Protocol(
                "history response manifest requires at least one chunk".to_owned(),
            ));
        }
        for chunk in &self.chunks {
            chunk.covered_epoch_range.validate()?;
        }
        for pair in self.chunks.windows(2) {
            if pair[0].chunk_index >= pair[1].chunk_index {
                return Err(WireError::Protocol(
                    "history response chunks must be sorted and unique by chunk_index".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealedHistoryChunkKind {
    #[serde(rename = "ak.history_key.response_chunk")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedHistoryChunk {
    pub kind: SealedHistoryChunkKind,
    pub manifest_digest: Hash,
    pub manifest_admission_digest: Hash,
    pub chunk_index: u64,
    pub enc: String,
    pub ciphertext: String,
}

impl SealedHistoryChunk {
    pub fn validate(&self) -> Result<()> {
        if self.enc.is_empty()
            || self.enc.len() > 2_048
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > 1_900_000
            || !is_base64url(&self.enc)
            || !is_base64url(&self.ciphertext)
        {
            return Err(WireError::Protocol(
                "sealed history chunk is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoryKeyResponseContent {
    Manifest(HistoryResponseManifest),
    Chunk(SealedHistoryChunk),
}

/// Content-addressed historical signer evidence for a minimal-metadata
/// pairwise actor whose proof key is an exact winning MLS LeafNode key rather
/// than a public Principal DID method.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalMetadataMlsLeafSignerEvidence {
    pub effective_scope: HistoryEffectiveScope,
    pub mls_group_id: String,
    pub epoch: u64,
    pub leaf_index: u64,
    pub pairwise_actor_id: DidCoreId,
    pub source_actor_id: DidCoreId,
    pub verification_method: DidUrl,
    pub response_signing_public_key_b64u: Base64UrlString,
    pub response_signing_public_key_digest: Hash,
    pub identity_link_canonical_bytes_b64u: Base64UrlString,
    pub identity_link_digest: Hash,
    pub identity_link_signer_evidence_ref: SignerEvidenceRef,
    pub identity_link_signer_evidence_digest: Hash,
    pub leaf_node_canonical_bytes_b64u: Base64UrlString,
    pub leaf_node_digest: Hash,
    pub winning_group_state_transition_ref: EventId,
    pub winning_group_state_event_digest: Hash,
    pub winning_mls_transition_digest: Hash,
    pub target_basis: SealBasis,
    pub authorization_incarnation: AuthorizationIncarnation,
}

impl MinimalMetadataMlsLeafSignerEvidence {
    pub fn canonical_sha256_digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    pub fn evidence_ref(&self) -> Result<SignerEvidenceRef> {
        SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            self.canonical_sha256_digest()?.as_ref()
        ))
    }

    pub fn validate(&self) -> Result<()> {
        if self.mls_group_id != self.effective_scope.canonical_mls_group_id()? {
            return Err(WireError::Protocol(
                "minimal-metadata signer evidence MLS group does not match its scope".to_owned(),
            ));
        }
        let method_did = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| {
                WireError::Protocol("history source method lacks fragment".to_owned())
            })?;
        let method_did = arkret_wire::Did::new(method_did.to_owned())?;
        if self.pairwise_actor_id != self.source_actor_id
            || arkret_wire::project_did_to_core_id(&method_did)? != self.source_actor_id
        {
            return Err(WireError::Protocol(
                "minimal-metadata signer evidence actor or method mismatch".to_owned(),
            ));
        }
        let response_key = arkret_wire::base64url::base64url_decode(
            self.response_signing_public_key_b64u.as_str().as_bytes(),
        )?;
        let identity_link_bytes = arkret_wire::base64url::base64url_decode(
            self.identity_link_canonical_bytes_b64u.as_str().as_bytes(),
        )?;
        let leaf_node_bytes = arkret_wire::base64url::base64url_decode(
            self.leaf_node_canonical_bytes_b64u.as_str().as_bytes(),
        )?;
        if response_key.len() != 32
            || identity_link_bytes.is_empty()
            || leaf_node_bytes.is_empty()
            || self.response_signing_public_key_digest
                != Hash::new(arkret_canonical::sha256_digest(&response_key))?
            || self.identity_link_digest
                != Hash::new(arkret_canonical::sha256_digest(&identity_link_bytes))?
            || self.leaf_node_digest
                != Hash::new(arkret_canonical::sha256_digest(&leaf_node_bytes))?
            || !self.leaf_node_digest.as_ref().starts_with("sha256:")
            || !self
                .winning_mls_transition_digest
                .as_ref()
                .starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "minimal-metadata signer evidence has invalid LeafNode or transition digests"
                    .to_owned(),
            ));
        }
        self.target_basis.validate_protocol_bounds()?;
        let identity_link = self.validate_identity_link_binding()?;
        if self.identity_link_signer_evidence_ref.content_digest()?
            != self.identity_link_signer_evidence_digest
            || !self
                .identity_link_signer_evidence_digest
                .as_ref()
                .starts_with("sha256:")
            || identity_link
                .proof
                .verification_method
                .as_str()
                .trim()
                .is_empty()
        {
            return Err(WireError::Protocol(
                "minimal-metadata IdentityLink signer-evidence binding is invalid".to_owned(),
            ));
        }
        if arkret_canonical::canonical_json_bytes(self)?.len() > 1024 * 1024 {
            return Err(WireError::Protocol(
                "minimal-metadata signer evidence exceeds 1 MiB".to_owned(),
            ));
        }
        Ok(())
    }

    /// Parse and validate the exact end-to-end encrypted IdentityLink retained
    /// by the receiver, including its independently signed history response-key
    /// binding. Active LeafNode bytes are a separate local-state input.
    pub fn validate_identity_link_binding(&self) -> Result<crate::objects::profiles::IdentityLink> {
        let identity_link_bytes = arkret_wire::base64url::base64url_decode(
            self.identity_link_canonical_bytes_b64u.as_str().as_bytes(),
        )?;
        let identity_link: crate::objects::profiles::IdentityLink =
            serde_json::from_slice(&identity_link_bytes)?;
        identity_link.validate_minimal()?;
        if arkret_canonical::canonical_json_bytes(&identity_link)? != identity_link_bytes {
            return Err(WireError::Protocol(
                "minimal-metadata signer IdentityLink bytes are not canonical".to_owned(),
            ));
        }
        let expected_realm = match &self.effective_scope {
            HistoryEffectiveScope::Realm { realm_id }
            | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
        };
        if &identity_link.realm_id != expected_realm
            || identity_link.status != crate::objects::profiles::IdentityLinkStatus::Active
            || identity_link.pairwise_actor_id != self.pairwise_actor_id
            || identity_link.mls_group_id.as_deref() != Some(self.mls_group_id.as_str())
            || identity_link.mls_leaf_index != self.leaf_index
            || identity_link.mls_epoch != self.epoch
            || identity_link.response_signing_verification_method != self.verification_method
            || identity_link.response_signing_public_key_b64u
                != self.response_signing_public_key_b64u
            || identity_link.response_signing_public_key_digest
                != self.response_signing_public_key_digest
        {
            return Err(WireError::Protocol(
                "minimal-metadata signer evidence differs from its signed IdentityLink".to_owned(),
            ));
        }
        Ok(identity_link)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySourceAgentObservationInput {
    pub response_id: HistoryResponseId,
    pub effective_scope: HistoryEffectiveScope,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: HistoryKeyResponseContent,
}

impl HistorySourceAgentObservationInput {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.source_sender_domain)?;
        match &self.content {
            HistoryKeyResponseContent::Manifest(manifest) => manifest.validate(),
            HistoryKeyResponseContent::Chunk(chunk) => chunk.validate(),
        }
    }

    pub fn history_source_agent_observation_digest(&self) -> Result<Hash> {
        self.validate()?;
        framed_sha256("ak.history-source-agent-observation-v1", self)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseSigningInput {
    pub response_id: HistoryResponseId,
    pub effective_scope: HistoryEffectiveScope,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
    pub source_signer_evidence_ref: SignerEvidenceRef,
    pub source_signer_evidence_digest: Hash,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: HistoryKeyResponseContent,
}

impl HistoryKeyResponseSigningInput {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.source_sender_domain)?;
        if self.source_signer_evidence_ref.content_digest()? != self.source_signer_evidence_digest {
            return Err(WireError::Protocol(
                "history source signer evidence ref and digest do not match".to_owned(),
            ));
        }
        match &self.content {
            HistoryKeyResponseContent::Manifest(manifest) => manifest.validate(),
            HistoryKeyResponseContent::Chunk(chunk) => chunk.validate(),
        }
    }

    /// Compute the non-cyclic request digest bound by Native Agent current
    /// admission evidence. The signer-evidence coordinates are deliberately
    /// excluded because that evidence contains this digest.
    pub fn history_source_agent_observation_digest(&self) -> Result<Hash> {
        HistorySourceAgentObservationInput {
            response_id: self.response_id.clone(),
            effective_scope: self.effective_scope.clone(),
            source_actor_id: self.source_actor_id.clone(),
            source_sender_domain: self.source_sender_domain.clone(),
            request_digest: self.request_digest.clone(),
            request_receipt_digest: self.request_receipt_digest.clone(),
            expires_at: self.expires_at,
            content: self.content.clone(),
        }
        .history_source_agent_observation_digest()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseSendRequest {
    pub response_id: HistoryResponseId,
    pub effective_scope: HistoryEffectiveScope,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
    pub source_signer_evidence_ref: SignerEvidenceRef,
    pub source_signer_evidence_digest: Hash,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub content: HistoryKeyResponseContent,
    pub source_proof: PayloadProof,
}

impl HistoryKeyResponseSendRequest {
    pub fn validate(&self) -> Result<()> {
        HistoryKeyResponseSigningInput {
            response_id: self.response_id.clone(),
            effective_scope: self.effective_scope.clone(),
            source_actor_id: self.source_actor_id.clone(),
            source_sender_domain: self.source_sender_domain.clone(),
            source_signer_evidence_ref: self.source_signer_evidence_ref.clone(),
            source_signer_evidence_digest: self.source_signer_evidence_digest.clone(),
            request_digest: self.request_digest.clone(),
            request_receipt_digest: self.request_receipt_digest.clone(),
            expires_at: self.expires_at,
            content: self.content.clone(),
        }
        .validate()?;
        self.validate_proof_binding()
    }

    pub fn history_source_agent_observation_digest(&self) -> Result<Hash> {
        HistoryKeyResponseSigningInput {
            response_id: self.response_id.clone(),
            effective_scope: self.effective_scope.clone(),
            source_actor_id: self.source_actor_id.clone(),
            source_sender_domain: self.source_sender_domain.clone(),
            source_signer_evidence_ref: self.source_signer_evidence_ref.clone(),
            source_signer_evidence_digest: self.source_signer_evidence_digest.clone(),
            request_digest: self.request_digest.clone(),
            request_receipt_digest: self.request_receipt_digest.clone(),
            expires_at: self.expires_at,
            content: self.content.clone(),
        }
        .history_source_agent_observation_digest()
    }
}

impl HistoryKeySourceRelay {
    pub fn validate(&self) -> Result<()> {
        self.response.validate()?;
        self.source_relay_attestation.validate()?;
        let attestation = &self.source_relay_attestation;
        if self.response.effective_scope != attestation.effective_scope
            || self.response.source_actor_id != attestation.source_actor_id
            || self.response.source_sender_domain != attestation.source_sender_domain
            || self.response.request_digest != attestation.request_digest
            || self.response.request_receipt_digest != attestation.request_receipt_digest
            || self.response.expires_at != attestation.expires_at
        {
            return Err(WireError::Protocol(
                "history source relay response binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Durable source disposition of one rejected `send` / `relay` attempt.
///
/// `history-visibility.md` 6.2 makes this a closed partition of the operation's
/// error surface so two sources cannot diverge between exact retry, manifest
/// replacement and giving up on a request. The classification is keyed on the
/// registered error code alone; HTTP status classes, `title` and `detail` are
/// never inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySourceSendDisposition {
    /// The rejection is not attributable to the frozen bytes. The attempt stays
    /// unfinished and the exact staged bytes are resent with bounded backoff
    /// until a receipt arrives or the request expires.
    RetrySameAttempt,
    /// These exact bytes are permanently unacceptable. The attempt must move to
    /// `replacement_required` -- never `completed` -- and a fresh manifest for
    /// the same request may be authored within the concurrency ceiling.
    ReplaceManifest,
    /// No attempt from this source can be accepted for this request under the
    /// current authorization or policy. Both retry and replacement stop.
    RequestTerminal,
}

impl HistorySourceSendDisposition {
    /// Codes whose rejection leaves the frozen bytes still acceptable later.
    pub const RETRY_SAME_ATTEMPT: &'static [&'static str] = &[
        "account_locked",
        "account_suspended",
        "auth_expired",
        "dependency_missing",
        "did_proof_required",
        "frontier_unavailable",
        "internal_error",
        "operation_selector_required",
        "rate_limited",
        "service_unavailable",
        "soft_logged_out",
        "temporarily_unavailable",
        "unauthenticated",
    ];

    /// Codes attributable to the exact submitted bytes or the frozen attempt
    /// identity, so only a differently authored manifest can succeed.
    pub const REPLACE_MANIFEST: &'static [&'static str] = &[
        "conflict",
        "duplicate_conflict",
        "failed_precondition",
        "json_invalid",
        "limit_exceeded",
        "param_invalid",
        "param_missing",
        "query_invalid",
        "schema_violation",
        "signature_invalid",
        "state_mismatch",
        "too_large",
    ];

    /// Codes that end this source's participation in the request entirely.
    pub const REQUEST_TERMINAL: &'static [&'static str] = &[
        "account_deactivated",
        "account_erased",
        "capability_denied",
        "history_not_visible",
        "not_implemented",
        "unsupported_event_kind",
        "unsupported_feature",
        "unsupported_operation_version",
        "unsupported_protocol_version",
    ];

    /// Classify one closed error reply.
    ///
    /// An unregistered code is a peer protocol violation; it is classified as
    /// `RetrySameAttempt` because that branch creates no response-id or outbox
    /// churn and is still bounded by request expiry, whereas guessing
    /// replacement would.
    pub fn classify(code: &str) -> Self {
        if Self::REPLACE_MANIFEST.contains(&code) {
            Self::ReplaceManifest
        } else if Self::REQUEST_TERMINAL.contains(&code) {
            Self::RequestTerminal
        } else {
            Self::RetrySameAttempt
        }
    }

    /// Whether the attempt keeps resending the exact staged bytes.
    pub const fn retries_same_bytes(self) -> bool {
        matches!(self, Self::RetrySameAttempt)
    }

    /// Whether a replacement manifest for the same request may be authored.
    pub const fn allows_replacement_manifest(self) -> bool {
        matches!(self, Self::ReplaceManifest)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseSendReceipt {
    pub response_id: HistoryResponseId,
    pub source_record_digest: Hash,
    pub record_digest: Hash,
    pub sequence: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub manifest_admission_digest: Hash,
    pub release_attestation_digest: Option<Hash>,
    pub receipt_digest: Hash,
    pub service_proof: PayloadProof,
}

impl HistoryKeyResponseSendReceipt {
    pub fn validate(&self) -> Result<()> {
        self.validate_proof_binding()?;
        let mut value = serde_json::to_value(self)?;
        let serde_json::Value::Object(map) = &mut value else {
            return Err(WireError::Protocol(
                "history response send receipt must be an object".to_owned(),
            ));
        };
        map.remove("receipt_digest");
        map.remove("service_proof");
        let mut preimage = b"ak.history-response-send-receipt-v1".to_vec();
        preimage.push(0);
        preimage.extend(arkret_wire::canonical::canonical_json_bytes(&value)?);
        let expected = Hash::new(arkret_wire::canonical::sha256_digest(preimage))?;
        if expected != self.receipt_digest {
            return Err(WireError::Protocol(
                "history response send receipt digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryManifestAdmissionKind {
    #[serde(rename = "ak.history_key.manifest_admission")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryManifestAdmissionPass {
    #[serde(rename = "all_manifest_ranges_authorized")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryManifestAdmission {
    pub kind: HistoryManifestAdmissionKind,
    pub manifest_digest: Hash,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    pub traversal_intent_digest: Hash,
    pub authorized_ranges: Vec<EpochRange>,
    pub t0_pass: HistoryManifestAdmissionPass,
    pub manifest_admission_digest: Hash,
}

impl HistoryManifestAdmission {
    pub fn validate(&self) -> Result<()> {
        validate_canonical_ranges(&self.authorized_ranges, 1_024)?;
        let mut value = serde_json::to_value(self)?;
        let serde_json::Value::Object(map) = &mut value else {
            return Err(WireError::Protocol(
                "history manifest admission must be an object".to_owned(),
            ));
        };
        map.remove("manifest_admission_digest");
        let mut preimage = b"ak.history-manifest-admission-v1".to_vec();
        preimage.push(0);
        preimage.extend(arkret_wire::canonical::canonical_json_bytes(&value)?);
        let expected = Hash::new(arkret_wire::canonical::sha256_digest(preimage))?;
        if expected != self.manifest_admission_digest {
            return Err(WireError::Protocol(
                "history manifest admission digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_digest_without_field(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        let serde_json::Value::Object(map) = &mut value else {
            return Err(WireError::Protocol(
                "history manifest admission must be an object".to_owned(),
            ));
        };
        map.remove("manifest_admission_digest");
        framed_sha256("ak.history-manifest-admission-v1", &value)
    }

    pub fn with_computed_digest(mut self) -> Result<Self> {
        self.manifest_admission_digest = self.canonical_digest_without_field()?;
        self.validate()?;
        Ok(self)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealmCurrentGateProjectionKind {
    #[serde(rename = "realm")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCurrentGateProjection {
    pub kind: RealmCurrentGateProjectionKind,
    pub history_access: HistoryAccess,
    pub realm_tombstoned: bool,
    pub recipient_authorization_incarnation: AuthorizationIncarnation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_authorization_incarnation: Option<AuthorizationIncarnation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircleCurrentGateProjectionKind {
    #[serde(rename = "circle")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleCurrentGateProjection {
    pub kind: CircleCurrentGateProjectionKind,
    pub history_access: HistoryAccess,
    pub realm_tombstoned: bool,
    pub circle_tombstoned: bool,
    pub membership_reconcile_required: bool,
    pub recipient_authorization_incarnation: AuthorizationIncarnation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_authorization_incarnation: Option<AuthorizationIncarnation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CurrentGateProjection {
    Realm(RealmCurrentGateProjection),
    Circle(CircleCurrentGateProjection),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealViewLocator {
    pub authority_realm_id: RealmId,
    pub seal_basis: SealBasis,
    pub current_gate_projection: CurrentGateProjection,
    pub authority_sequence: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSealViewLocator {
    pub authority_realm_id: RealmId,
    pub seal_basis: SealBasis,
    pub current_gate_projection: RealmCurrentGateProjection,
    pub authority_sequence: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleSealViewLocator {
    pub authority_realm_id: RealmId,
    pub seal_basis: SealBasis,
    pub current_gate_projection: CircleCurrentGateProjection,
    pub authority_sequence: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusViewLocator {
    pub account_authority_id: DidCoreId,
    pub account_id: String,
    pub account_status_record_id: String,
    pub status_sequence: u64,
    pub record_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrDeviceViewLocator {
    pub principal_control_realm_id: RealmId,
    pub pcr_seal_basis: SealBasis,
    pub device_id: DeviceId,
    pub device_authorize_event_id: EventId,
    pub device_generation_ref: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl PcrDeviceViewLocator {
    pub fn validate(&self) -> Result<()> {
        self.pcr_seal_basis.validate_protocol_bounds()?;
        if self.device_generation_ref == 0 || self.observed_at > self.expires_at {
            return Err(WireError::Protocol(
                "PCR device view locator has an invalid generation or validity window".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvidenceViewLocator {
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub agent_key_authorize_event_id: EventId,
    pub active_lifecycle_event_id: EventId,
    pub control_basis: SealBasis,
    pub agent_signer_evidence_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl AgentEvidenceViewLocator {
    pub fn validate(&self) -> Result<()> {
        self.control_basis.validate_protocol_bounds()?;
        require_sha256(
            &self.agent_signer_evidence_digest,
            "agent_signer_evidence_digest",
        )?;
        if self.observed_at > self.expires_at {
            return Err(WireError::Protocol(
                "Agent evidence view locator has an invalid validity window".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_current_evidence(&self, evidence: &AgentSignerEvidence) -> Result<()> {
        self.validate()?;
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence,
            current_observation,
            ..
        } = evidence
        else {
            return Err(WireError::Protocol(
                "Agent evidence view locator requires current signer evidence".to_owned(),
            ));
        };
        let snapshot = &admission_evidence.agent_authority_snapshot.core;
        let binding = &snapshot.signing_key_binding;
        let lifecycle = &snapshot.agent_lifecycle_witness;
        let expected_basis = SealBasis {
            leaves: vec![snapshot.frontier_seal_id.clone()],
        };
        if lifecycle.status != AgentLifecycleStatus::Active
            || self.agent_id != binding.agent_id
            || self.verification_method != binding.verification_method
            || self.agent_key_authorize_event_id != binding.agent_key_authorize_event_id
            || self.active_lifecycle_event_id != lifecycle.accepted_status_event.event_id
            || self.control_basis != expected_basis
            || self.observed_at != current_observation.evaluated_at
            || self.expires_at != current_observation.expires_at
            || self.agent_signer_evidence_digest != agent_signer_evidence_digest(evidence)?
        {
            return Err(WireError::Protocol(
                "Agent evidence view locator does not match current signer evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn agent_signer_evidence_digest(evidence: &AgentSignerEvidence) -> Result<Hash> {
    if !matches!(evidence, AgentSignerEvidence::CurrentAdmission { .. }) {
        return Err(WireError::Protocol(
            "Agent evidence view digest requires current signer evidence".to_owned(),
        ));
    }
    Ok(Hash::new(arkret_wire::canonical::canonical_sha256(
        evidence,
    )?)?)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCoverageViewLocator {
    pub archive_set_digest: Hash,
    pub covered_range: EpochRange,
    pub archive_count: u32,
    pub tuple_digest: Hash,
}

/// Exact closed row hashed by the organization-recovery archive-set digest.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveSetRow {
    pub epoch: u64,
    pub container_event_ref: EventId,
    pub archive_digest: Hash,
}

/// Verified archive-set input. The tuple digest is validation metadata and is
/// deliberately not part of the canonical row preimage.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationRecoveryArchiveSetMember {
    pub row: OrganizationRecoveryArchiveSetRow,
    pub archive_authorization_tuple_digest: Hash,
}

impl OrganizationRecoveryArchiveSetMember {
    pub fn from_replica(replica: &OrganizationRecoveryArchiveReplica) -> Result<Self> {
        replica.validate()?;
        Self::from_archive(&replica.archive, replica.container_event_ref.clone())
    }

    pub fn from_archive(
        archive: &OrganizationRecoveryArchive,
        container_event_ref: EventId,
    ) -> Result<Self> {
        archive.validate()?;
        let tuple = ArchiveAuthorizationTuple {
            recovery_key_id: archive.recovery_key_id.clone(),
            key_agreement_ref: archive.key_agreement_ref.clone(),
            holder_principal_id: archive.holder_principal_id.clone(),
            holder_id: archive.holder_id.clone(),
            holder_signing_ref: archive.holder_signing_ref.clone(),
            accepted_key_evidence_ref: archive.accepted_key_evidence_ref.clone(),
            holder_trusted_basis: archive.holder_trusted_basis.clone(),
        };
        Ok(Self {
            row: OrganizationRecoveryArchiveSetRow {
                epoch: archive.epoch,
                container_event_ref,
                archive_digest: archive.archive_digest()?,
            },
            archive_authorization_tuple_digest: tuple.archive_authorization_tuple_digest()?,
        })
    }
}

/// Build the exact continuous archive coverage commitment used by T1 release
/// authorization. Rows are sorted canonically by this helper; callers cannot
/// substitute pagination order for the registered digest order.
pub fn organization_recovery_archive_coverage(
    covered_range: EpochRange,
    members: &[OrganizationRecoveryArchiveSetMember],
) -> Result<ArchiveCoverageViewLocator> {
    covered_range.validate()?;
    if members.is_empty() || members.len() > 65_536 {
        return Err(WireError::Protocol(
            "organization recovery archive set must contain 1..=65536 members".to_owned(),
        ));
    }
    let expected_count = covered_range
        .to_epoch
        .checked_sub(covered_range.from_epoch)
        .and_then(|width| width.checked_add(1))
        .ok_or_else(|| {
            WireError::Protocol("organization recovery archive coverage range overflow".to_owned())
        })?;
    if expected_count != members.len() as u64 {
        return Err(WireError::Protocol(
            "organization recovery archive set does not continuously cover the requested range"
                .to_owned(),
        ));
    }
    let tuple_digest = members[0].archive_authorization_tuple_digest.clone();
    require_sha256(&tuple_digest, "archive_authorization_tuple_digest")?;
    if members
        .iter()
        .any(|member| member.archive_authorization_tuple_digest != tuple_digest)
    {
        return Err(WireError::Protocol(
            "organization recovery archive set mixes authorization tuples".to_owned(),
        ));
    }
    let mut rows = members
        .iter()
        .map(|member| member.row.clone())
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.epoch
            .cmp(&right.epoch)
            .then_with(|| {
                left.container_event_ref
                    .as_str()
                    .as_bytes()
                    .cmp(right.container_event_ref.as_str().as_bytes())
            })
            .then_with(|| {
                left.archive_digest
                    .as_str()
                    .as_bytes()
                    .cmp(right.archive_digest.as_str().as_bytes())
            })
    });
    for (offset, row) in rows.iter().enumerate() {
        let expected_epoch = covered_range
            .from_epoch
            .checked_add(offset as u64)
            .ok_or_else(|| {
                WireError::Protocol(
                    "organization recovery archive coverage epoch overflow".to_owned(),
                )
            })?;
        if row.epoch != expected_epoch {
            return Err(WireError::Protocol(
                "organization recovery archive set has a gap or duplicate epoch".to_owned(),
            ));
        }
        if offset > 0 && rows[offset - 1] == *row {
            return Err(WireError::Protocol(
                "organization recovery archive set contains a duplicate row".to_owned(),
            ));
        }
    }
    let archive_set_digest = framed_sha256("ak.organization-recovery-archive-set-v1", &rows)?;
    Ok(ArchiveCoverageViewLocator {
        archive_set_digest,
        covered_range,
        archive_count: rows.len() as u32,
        tuple_digest,
    })
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRelayViewLocator {
    pub relay_id: DidCoreId,
    pub relay_attestation_digest: Hash,
    pub source_authority_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedAuthorityViewVector {
    pub scope_realm: RealmSealViewLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_circle: Option<CircleSealViewLocator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_account_status: Option<AccountStatusViewLocator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_pcr_device: Option<PcrDeviceViewLocator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_agent_control_evidence: Option<AgentEvidenceViewLocator>,
    pub source_relay: SourceRelayViewLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_tuple: Option<ArchiveAuthorizationTuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_coverage: Option<ArchiveCoverageViewLocator>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryReleaseAttestationKind {
    #[serde(rename = "ak.history_key.release_attestation")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryReleaseVerifierProfile {
    #[serde(rename = "ak.history_release_predicates.v1")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryReleaseAttestation {
    pub kind: HistoryReleaseAttestationKind,
    pub source_record_digest: Hash,
    pub response_id: HistoryResponseId,
    pub request_digest: Hash,
    pub request_receipt_digest: Hash,
    pub effective_scope: HistoryEffectiveScope,
    pub manifest_admission_digest: Hash,
    pub t0_pass: HistoryManifestAdmissionPass,
    pub released_range: EpochRange,
    pub recipient_actor_id: DidCoreId,
    pub recipient_sender_domain: String,
    pub recipient_authorization_incarnation: AuthorizationIncarnation,
    pub recipient_author_profile: AuthorProfile,
    pub source_actor_id: DidCoreId,
    pub source_sender_domain: String,
    pub source_kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_author_profile: Option<AuthorProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_authorization_incarnation: Option<AuthorizationIncarnation>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub accepted_authority_views: AcceptedAuthorityViewVector,
    pub verifier_profile_id: HistoryReleaseVerifierProfile,
}

impl HistoryReleaseAttestation {
    pub fn validate(&self) -> Result<()> {
        validate_sender_domain(&self.recipient_sender_domain)?;
        validate_sender_domain(&self.source_sender_domain)?;
        self.released_range.validate()?;
        if self.accepted_at > self.expires_at {
            return Err(WireError::Protocol(
                "history release attestation is expired".to_owned(),
            ));
        }
        let views = &self.accepted_authority_views;
        if let Some(locator) = &views.recipient_pcr_device {
            locator.validate()?;
        }
        if let Some(locator) = &views.recipient_agent_control_evidence {
            locator.validate()?;
        }
        if views.scope_realm.current_gate_projection.realm_tombstoned
            || views.scope_circle.as_ref().is_some_and(|circle| {
                circle.current_gate_projection.realm_tombstoned
                    || circle.current_gate_projection.circle_tombstoned
                    || circle.current_gate_projection.membership_reconcile_required
            })
        {
            return Err(WireError::Protocol(
                "history current gate projection is not active".to_owned(),
            ));
        }
        match self.recipient_author_profile {
            AuthorProfile::OrdinaryHuman
                if views.recipient_account_status.is_some()
                    && views.recipient_pcr_device.is_some()
                    && views.recipient_agent_control_evidence.is_none() => {}
            AuthorProfile::NativeAgent
                if views.recipient_account_status.is_none()
                    && views.recipient_pcr_device.is_none()
                    && views.recipient_agent_control_evidence.is_some() => {}
            AuthorProfile::MinimalMetadata
                if views.recipient_account_status.is_none()
                    && views.recipient_pcr_device.is_none()
                    && views.recipient_agent_control_evidence.is_none() => {}
            _ => {
                return Err(WireError::Protocol(
                    "history recipient authority view mismatch".to_owned(),
                ));
            }
        }
        match self.source_kind {
            SourceKind::Member
                if self.source_author_profile.is_some()
                    && self.source_authorization_incarnation.is_some()
                    && views.archive_tuple.is_none()
                    && views.archive_coverage.is_none() => {}
            SourceKind::OrganizationRecoveryHolder
                if self.source_author_profile.is_none()
                    && self.source_authorization_incarnation.is_none()
                    && views.archive_tuple.is_some()
                    && views.archive_coverage.is_some() => {}
            _ => {
                return Err(WireError::Protocol(
                    "history source authority view mismatch".to_owned(),
                ));
            }
        }
        match self.effective_scope {
            HistoryEffectiveScope::Realm { .. } if views.scope_circle.is_none() => Ok(()),
            HistoryEffectiveScope::Circle { .. } if views.scope_circle.is_some() => Ok(()),
            _ => Err(WireError::Protocol(
                "history scope authority view mismatch".to_owned(),
            )),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseRecord {
    pub sequence: u64,
    pub cursor: String,
    pub record_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_attestation: Option<HistoryReleaseAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_admission: Option<HistoryManifestAdmission>,
    pub release_service_signer_evidence_ref: SignerEvidenceRef,
    pub release_service_signer_evidence_digest: Hash,
    pub service_proof: PayloadProof,
    pub source_record: HistoryKeyResponseSendRequest,
}

impl HistoryKeyResponseRecord {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.cursor, "cursor")?;
        if self.release_service_signer_evidence_ref.content_digest()?
            != self.release_service_signer_evidence_digest
        {
            return Err(WireError::Protocol(
                "history response record release-service signer evidence mismatch".to_owned(),
            ));
        }
        self.source_record.validate()?;
        match (
            &self.source_record.content,
            &self.manifest_admission,
            &self.release_attestation,
        ) {
            (HistoryKeyResponseContent::Manifest(_), Some(admission), None) => {
                admission.validate()?
            }
            (HistoryKeyResponseContent::Chunk(_), None, Some(attestation)) => {
                attestation.validate()?
            }
            _ => {
                return Err(WireError::Protocol(
                    "history response record branch mismatch".to_owned(),
                ));
            }
        }
        let mut value = serde_json::to_value(self)?;
        let serde_json::Value::Object(map) = &mut value else {
            unreachable!()
        };
        map.remove("record_digest");
        map.remove("service_proof");
        let expected = framed_sha256("ak.history-response-record-v1", &value)?;
        if expected != self.record_digest {
            return Err(WireError::Protocol(
                "history response record digest mismatch".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseLostRecord {
    pub sequence: u64,
    pub cursor: String,
    pub response_id: HistoryResponseId,
    pub record_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub lost_at: DateTime<Utc>,
    pub release_service_signer_evidence_ref: SignerEvidenceRef,
    pub release_service_signer_evidence_digest: Hash,
    pub service_proof: PayloadProof,
}

impl HistoryKeyResponseLostRecord {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.cursor, "cursor")?;
        if self.release_service_signer_evidence_ref.content_digest()?
            != self.release_service_signer_evidence_digest
        {
            return Err(WireError::Protocol(
                "history lost record release-service signer evidence mismatch".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryResponsePageEntry {
    Record {
        record: Box<HistoryKeyResponseRecord>,
    },
    Lost {
        lost_record: Box<HistoryKeyResponseLostRecord>,
    },
}

impl HistoryResponsePageEntry {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Record { record } => record.sequence,
            Self::Lost { lost_record } => lost_record.sequence,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseListOutcome {
    pub ack_entries: Vec<HistoryResponsePageEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limited: bool,
}

impl HistoryKeyResponseListOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.ack_entries.is_empty() {
            if self.ack_token.is_some() {
                return Err(WireError::Protocol(
                    "empty history response page must omit ack_token".to_owned(),
                ));
            }
        } else {
            validate_non_empty(
                self.ack_token.as_deref().ok_or_else(|| {
                    WireError::Protocol(
                        "non-empty history response page requires ack_token".to_owned(),
                    )
                })?,
                "ack_token",
            )?;
        }
        validate_pagination(self.limited, self.cursor.as_deref())?;
        for entry in &self.ack_entries {
            match entry {
                HistoryResponsePageEntry::Record { record } => record.validate()?,
                HistoryResponsePageEntry::Lost { lost_record } => lost_record.validate()?,
            }
        }
        for pair in self.ack_entries.windows(2) {
            if pair[0].sequence() >= pair[1].sequence() {
                return Err(WireError::Protocol(
                    "history response entries must be strictly sequence ascending".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u8>,
}

impl HistoryKeyResponseListQuery {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty_optional(&self.after, "after")?;
        if self.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
            return Err(WireError::Protocol(
                "history response list limit must be within 1..=100".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryResponseRecordStatus {
    Installed,
    CryptographicallyRejected,
    SupersededDuplicate,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryResponseLostStatus {
    #[serde(rename = "service_record_lost")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryResponseAckEntry {
    Record {
        sequence: u64,
        response_id: HistoryResponseId,
        record_digest: Hash,
        status: HistoryResponseRecordStatus,
    },
    Lost {
        sequence: u64,
        response_id: HistoryResponseId,
        lost_record_digest: Hash,
        status: HistoryResponseLostStatus,
    },
}

impl HistoryResponseAckEntry {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Record { sequence, .. } | Self::Lost { sequence, .. } => *sequence,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseAckRequest {
    pub ack_token: String,
    pub high_water_cursor: String,
    pub ack_entries: Vec<HistoryResponseAckEntry>,
}

impl HistoryKeyResponseAckRequest {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.ack_token, "ack_token")?;
        validate_non_empty(&self.high_water_cursor, "high_water_cursor")?;
        if self.ack_entries.is_empty() {
            return Err(WireError::Protocol(
                "history ack requires entries".to_owned(),
            ));
        }
        for pair in self.ack_entries.windows(2) {
            if pair[0].sequence() >= pair[1].sequence() {
                return Err(WireError::Protocol(
                    "history ack entries must be strictly sequence ascending".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyResponseAckOutcome {
    pub acked_through_cursor: String,
}

impl HistoryKeyResponseAckOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.acked_through_cursor, "acked_through_cursor")
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveListQuery {
    pub effective_scope: HistoryEffectiveScope,
    pub recovery_key_id: String,
    pub key_agreement_ref: DidUrl,
    pub accepted_key_evidence_ref: EventId,
    pub holder_trusted_basis: SealBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_limit: Option<u32>,
}

impl OrganizationRecoveryArchiveListQuery {
    pub fn validate(&self) -> Result<()> {
        validate_bounded_chars(&self.recovery_key_id, 1, 512, "recovery_key_id")?;
        self.holder_trusted_basis.validate_protocol_bounds()?;
        match (self.from_epoch, self.to_epoch) {
            (None, None) => {}
            (Some(from), Some(to)) if from <= to => {}
            _ => {
                return Err(WireError::Protocol(
                    "archive list epoch range is invalid".to_owned(),
                ));
            }
        }
        validate_non_empty_optional(&self.cursor, "cursor")?;
        if self
            .byte_limit
            .is_some_and(|limit| !(65_536..=1_048_576).contains(&limit))
        {
            return Err(WireError::Protocol(
                "archive list byte_limit is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveListItem {
    pub archive_sequence: u64,
    /// Exact canonical digest of the first archive replica durably accepted by
    /// the holder service. This is the only valid self-traversal access
    /// coordinate for this row.
    pub archive_replica_digest: Hash,
    pub archive: OrganizationRecoveryArchive,
    pub container_event_ref: EventId,
    pub history_traversal_retention: HistoryGovernanceTraversalRetention,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveListOutcome {
    pub items: Vec<OrganizationRecoveryArchiveListItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limited: bool,
}

impl OrganizationRecoveryArchiveListOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_pagination(self.limited, self.cursor.as_deref())?;
        for item in &self.items {
            item.archive.validate()?;
            if item.archive_replica_digest.as_str().is_empty() {
                return Err(WireError::Protocol(
                    "archive item replica digest is empty".to_owned(),
                ));
            }
            item.history_traversal_retention
                .validate_for_archive(&item.archive, &item.container_event_ref)?;
        }
        for pair in self.items.windows(2) {
            if pair[0].archive_sequence >= pair[1].archive_sequence {
                return Err(WireError::Protocol(
                    "archive items are not sequence ascending".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Validate that every typed row is within the exact holder query rather
    /// than merely being well-formed. The holder must perform this binding
    /// before using `archive_replica_digest` as a traversal access coordinate.
    pub fn validate_for_query(&self, query: &OrganizationRecoveryArchiveListQuery) -> Result<()> {
        query.validate()?;
        self.validate()?;
        for item in &self.items {
            let archive = &item.archive;
            if archive.effective_scope != query.effective_scope
                || archive.recovery_key_id != query.recovery_key_id
                || archive.key_agreement_ref != query.key_agreement_ref
                || archive.accepted_key_evidence_ref != query.accepted_key_evidence_ref
                || archive.holder_trusted_basis != query.holder_trusted_basis
                || query.from_epoch.is_some_and(|from| archive.epoch < from)
                || query.to_epoch.is_some_and(|to| archive.epoch > to)
            {
                return Err(WireError::Protocol(
                    "archive item is outside the exact holder query".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRecoveryArchiveReplicaKind {
    #[serde(rename = "ak.organization_recovery.archive_replica")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveReplica {
    pub kind: OrganizationRecoveryArchiveReplicaKind,
    pub archive: OrganizationRecoveryArchive,
    pub container_event_ref: EventId,
    pub history_traversal_retention: HistoryGovernanceTraversalRetention,
    pub source_id: DidCoreId,
    pub holder_id: DidCoreId,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub replicated_at: DateTime<Utc>,
    pub service_proof: PayloadProof,
}

impl OrganizationRecoveryArchiveReplica {
    pub fn validate(&self) -> Result<()> {
        self.archive.validate()?;
        self.history_traversal_retention
            .validate_for_archive(&self.archive, &self.container_event_ref)?;
        if self.holder_id != self.archive.holder_id {
            return Err(WireError::Protocol(
                "archive replica holder service mismatch".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Payload<'a> {
            kind: OrganizationRecoveryArchiveReplicaKind,
            archive: &'a OrganizationRecoveryArchive,
            container_event_ref: &'a EventId,
            history_traversal_retention: &'a HistoryGovernanceTraversalRetention,
            source_id: &'a DidCoreId,
            holder_id: &'a DidCoreId,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            replicated_at: DateTime<Utc>,
        }
        Ok(Hash::new(arkret_wire::canonical::canonical_sha256(
            &Payload {
                kind: self.kind,
                archive: &self.archive,
                container_event_ref: &self.container_event_ref,
                history_traversal_retention: &self.history_traversal_retention,
                source_id: &self.source_id,
                holder_id: &self.holder_id,
                replicated_at: self.replicated_at,
            },
        )?)?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Transcript<'a> {
            context: &'static str,
            payload_digest: Hash,
            kind: OrganizationRecoveryArchiveReplicaKind,
            archive: &'a OrganizationRecoveryArchive,
            container_event_ref: &'a EventId,
            history_traversal_retention: &'a HistoryGovernanceTraversalRetention,
            source_id: &'a DidCoreId,
            holder_id: &'a DidCoreId,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            replicated_at: DateTime<Utc>,
            verification_method: &'a DidUrl,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            created_at: DateTime<Utc>,
        }
        Ok(arkret_wire::canonical::canonical_json_bytes(&Transcript {
            context: arkret_wire::ProofContextId::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_PROOF_V1,
            payload_digest: self.canonical_payload_digest()?,
            kind: self.kind,
            archive: &self.archive,
            container_event_ref: &self.container_event_ref,
            history_traversal_retention: &self.history_traversal_retention,
            source_id: &self.source_id,
            holder_id: &self.holder_id,
            replicated_at: self.replicated_at,
            verification_method: &self.service_proof.verification_method,
            created_at: self.service_proof.created_at,
        })?)
    }

    pub fn validate_proof_binding(&self) -> Result<()> {
        self.service_proof.validate_production()?;
        if self.service_proof.payload_digest != self.canonical_payload_digest()?
            || self.service_proof.domain.is_some()
            || self.service_proof.audience.is_some()
            || self.service_proof.proof_purpose.is_some()
        {
            return Err(WireError::Protocol(
                "archive replica service proof binding mismatch".to_owned(),
            ));
        }
        self.proof_binding_bytes().map(|_| ())
    }

    pub fn build_signed_proof<Build, Sign>(
        verification_method: DidUrl,
        created_at: DateTime<Utc>,
        build: Build,
        sign: Sign,
    ) -> Result<Self>
    where
        Build: Fn(PayloadProof) -> Self,
        Sign: FnOnce(&[u8]) -> Result<String>,
    {
        build_history_proof_carrier(
            "service_proof",
            arkret_wire::ProofContextId::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_PROOF_V1,
            verification_method,
            created_at,
            build,
            sign,
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryArchiveReplicaOutcome {
    pub archive_replica_digest: Hash,
    pub holder_id: DidCoreId,
    pub archive_sequence: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub service_proof: PayloadProof,
}

impl OrganizationRecoveryArchiveReplicaOutcome {
    pub fn validate(&self) -> Result<()> {
        self.validate_proof_binding()
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Payload<'a> {
            archive_replica_digest: &'a Hash,
            holder_id: &'a DidCoreId,
            archive_sequence: u64,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            accepted_at: DateTime<Utc>,
        }
        Ok(Hash::new(arkret_wire::canonical::canonical_sha256(
            &Payload {
                archive_replica_digest: &self.archive_replica_digest,
                holder_id: &self.holder_id,
                archive_sequence: self.archive_sequence,
                accepted_at: self.accepted_at,
            },
        )?)?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Transcript<'a> {
            context: &'static str,
            payload_digest: Hash,
            archive_replica_digest: &'a Hash,
            holder_id: &'a DidCoreId,
            archive_sequence: u64,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            accepted_at: DateTime<Utc>,
            verification_method: &'a DidUrl,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            created_at: DateTime<Utc>,
        }
        Ok(arkret_wire::canonical::canonical_json_bytes(&Transcript {
            context:
                arkret_wire::ProofContextId::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_RECEIPT_PROOF_V1,
            payload_digest: self.canonical_payload_digest()?,
            archive_replica_digest: &self.archive_replica_digest,
            holder_id: &self.holder_id,
            archive_sequence: self.archive_sequence,
            accepted_at: self.accepted_at,
            verification_method: &self.service_proof.verification_method,
            created_at: self.service_proof.created_at,
        })?)
    }

    pub fn validate_proof_binding(&self) -> Result<()> {
        self.service_proof.validate_production()?;
        if self.service_proof.payload_digest != self.canonical_payload_digest()?
            || self.service_proof.domain.is_some()
            || self.service_proof.audience.is_some()
            || self.service_proof.proof_purpose.is_some()
        {
            return Err(WireError::Protocol(
                "archive replica receipt service proof binding mismatch".to_owned(),
            ));
        }
        self.proof_binding_bytes().map(|_| ())
    }

    pub fn build_signed_proof<Build, Sign>(
        verification_method: DidUrl,
        created_at: DateTime<Utc>,
        build: Build,
        sign: Sign,
    ) -> Result<Self>
    where
        Build: Fn(PayloadProof) -> Self,
        Sign: FnOnce(&[u8]) -> Result<String>,
    {
        build_history_proof_carrier(
            "service_proof",
            arkret_wire::ProofContextId::ORGANIZATION_RECOVERY_ARCHIVE_REPLICA_RECEIPT_PROOF_V1,
            verification_method,
            created_at,
            build,
            sign,
        )
    }
}

fn proof_payload_and_binding_bytes(
    value: &impl Serialize,
    proof_field: &str,
    context: &'static str,
    proof: &PayloadProof,
) -> Result<(Hash, Vec<u8>)> {
    proof.validate_production()?;
    if proof.domain.is_some() || proof.audience.is_some() || proof.proof_purpose.is_some() {
        return Err(WireError::Protocol(
            "history proof contains fields outside its registered transcript".to_owned(),
        ));
    }
    let serde_json::Value::Object(mut payload) = serde_json::to_value(value)? else {
        return Err(WireError::Protocol(
            "history proof carrier must be a closed object".to_owned(),
        ));
    };
    if payload.remove(proof_field).is_none() {
        return Err(WireError::Protocol(format!(
            "history proof carrier is missing {proof_field}"
        )));
    }
    let payload_digest = Hash::new(arkret_wire::canonical::canonical_sha256(&payload)?)?;
    if proof.payload_digest != payload_digest {
        return Err(WireError::Protocol(
            "history proof payload digest mismatch".to_owned(),
        ));
    }
    payload.insert(
        "context".to_owned(),
        serde_json::Value::String(context.to_owned()),
    );
    payload.insert(
        "payload_digest".to_owned(),
        serde_json::to_value(&payload_digest)?,
    );
    payload.insert(
        "verification_method".to_owned(),
        serde_json::to_value(&proof.verification_method)?,
    );
    payload.insert(
        "created_at".to_owned(),
        serde_json::Value::String(arkret_wire::canonical::format_timestamp_canonical(
            proof.created_at,
        )),
    );
    Ok((
        payload_digest,
        arkret_wire::canonical::canonical_json_bytes(&payload)?,
    ))
}

fn build_history_proof_carrier<T, Build, Sign>(
    proof_field: &str,
    context: &'static str,
    verification_method: DidUrl,
    created_at: DateTime<Utc>,
    build: Build,
    sign: Sign,
) -> Result<T>
where
    T: Serialize,
    Build: Fn(PayloadProof) -> T,
    Sign: FnOnce(&[u8]) -> Result<String>,
{
    let placeholder = PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))?,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "pending".to_owned(),
    };
    let draft = build(placeholder);
    let serde_json::Value::Object(mut payload) = serde_json::to_value(&draft)? else {
        return Err(WireError::Protocol(
            "history proof carrier must be a closed object".to_owned(),
        ));
    };
    if payload.remove(proof_field).is_none() {
        return Err(WireError::Protocol(format!(
            "history proof carrier is missing {proof_field}"
        )));
    }
    let payload_digest = Hash::new(arkret_wire::canonical::canonical_sha256(&payload)?)?;
    let mut proof = PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "pending".to_owned(),
    };
    let carrier = build(proof.clone());
    let (_, binding_bytes) =
        proof_payload_and_binding_bytes(&carrier, proof_field, context, &proof)?;
    proof.jws = sign(&binding_bytes)?;
    proof.validate_production()?;
    let carrier = build(proof.clone());
    proof_payload_and_binding_bytes(&carrier, proof_field, context, &proof)?;
    Ok(carrier)
}

fn full_object_digest(value: &impl Serialize, domain: &str) -> Result<Hash> {
    framed_sha256(domain, value)
}

fn object_digest_without_field(value: &impl Serialize, field: &str, domain: &str) -> Result<Hash> {
    let serde_json::Value::Object(mut object) = serde_json::to_value(value)? else {
        return Err(WireError::Protocol(
            "history digest carrier must be a closed object".to_owned(),
        ));
    };
    if object.remove(field).is_none() {
        return Err(WireError::Protocol(format!(
            "history digest carrier is missing {field}"
        )));
    }
    framed_sha256(domain, &object)
}

macro_rules! history_proof_binding {
    ($type:ty, $proof:ident, $context:expr) => {
        impl $type {
            pub fn canonical_payload_digest(&self) -> Result<Hash> {
                proof_payload_and_binding_bytes(self, stringify!($proof), $context, &self.$proof)
                    .map(|(digest, _)| digest)
            }

            pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
                proof_payload_and_binding_bytes(self, stringify!($proof), $context, &self.$proof)
                    .map(|(_, bytes)| bytes)
            }

            pub fn validate_proof_binding(&self) -> Result<()> {
                self.proof_binding_bytes().map(|_| ())
            }

            /// Construct the carrier and its detached proof without exposing
            /// or duplicating the registered canonical transcript preimage.
            pub fn build_signed_proof<Build, Sign>(
                verification_method: DidUrl,
                created_at: DateTime<Utc>,
                build: Build,
                sign: Sign,
            ) -> Result<Self>
            where
                Build: Fn(PayloadProof) -> Self,
                Sign: FnOnce(&[u8]) -> Result<String>,
            {
                build_history_proof_carrier(
                    stringify!($proof),
                    $context,
                    verification_method,
                    created_at,
                    build,
                    sign,
                )
            }
        }
    };
}

history_proof_binding!(
    HistoryKeyRequest,
    requester_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_REQUEST_PROOF_V1
);
history_proof_binding!(
    HistoryKeyRequestReceipt,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_REQUEST_RECEIPT_PROOF_V1
);
history_proof_binding!(
    HistoryKeyRequestReplica,
    relay_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_REQUEST_REPLICA_PROOF_V1
);
history_proof_binding!(
    HistoryKeyRequestReplicaOutcome,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_REQUEST_REPLICA_RECEIPT_PROOF_V1
);
history_proof_binding!(
    SourceRelayAttestation,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_SOURCE_RELAY_ATTESTATION_PROOF_V1
);
history_proof_binding!(
    HistoryKeyResponseSendRequest,
    source_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_RESPONSE_PROOF_V1
);
history_proof_binding!(
    HistoryKeyResponseRecord,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_RESPONSE_RECORD_PROOF_V1
);
history_proof_binding!(
    HistoryKeyResponseLostRecord,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_RESPONSE_LOST_RECORD_PROOF_V1
);
history_proof_binding!(
    HistoryKeyResponseSendReceipt,
    service_proof,
    arkret_wire::ProofContextId::HISTORY_KEY_RESPONSE_SEND_RECEIPT_PROOF_V1
);

impl HistoryKeyRequest {
    pub fn request_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-key-request-digest-v1")
    }
}

impl HistoryKeyRequestReceipt {
    pub fn request_receipt_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-key-request-receipt-digest-v1")
    }
}

impl HistoryKeyRequestReplica {
    pub fn request_replica_digest(&self) -> Result<Hash> {
        object_digest_without_field(self, "relay_proof", "ak.history-key-request-replica-v1")
    }
}

impl SealedHistoryResponseCapability {
    pub fn sealed_response_capability_digest(&self) -> Result<Hash> {
        self.validate()?;
        full_object_digest(self, "ak.history-response-sealed-capability-v1")
    }
}

pub fn response_capability_commitment(capability_b64u: &str) -> Result<Hash> {
    let decoded = arkret_wire::base64url::base64url_decode(capability_b64u)?;
    if decoded.len() != 32 || arkret_wire::base64url::base64url_encode(&decoded) != capability_b64u
    {
        return Err(WireError::Protocol(
            "history response capability must be canonical base64url for 32 bytes".to_owned(),
        ));
    }
    #[derive(Serialize)]
    struct Commitment<'a> {
        response_capability_b64u: &'a str,
    }
    framed_sha256(
        "ak.history-response-capability-commitment-v1",
        &Commitment {
            response_capability_b64u: capability_b64u,
        },
    )
}

impl HistoryKeyResponseSendRequest {
    pub fn source_record_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-source-record-v1")
    }

    pub fn manifest_digest(&self) -> Result<Hash> {
        match self.content {
            HistoryKeyResponseContent::Manifest(_) => full_object_digest(
                &HistoryKeyResponseSigningInput {
                    response_id: self.response_id.clone(),
                    effective_scope: self.effective_scope.clone(),
                    source_actor_id: self.source_actor_id.clone(),
                    source_sender_domain: self.source_sender_domain.clone(),
                    source_signer_evidence_ref: self.source_signer_evidence_ref.clone(),
                    source_signer_evidence_digest: self.source_signer_evidence_digest.clone(),
                    request_digest: self.request_digest.clone(),
                    request_receipt_digest: self.request_receipt_digest.clone(),
                    expires_at: self.expires_at,
                    content: self.content.clone(),
                },
                "ak.history-response-manifest-v1",
            ),
            HistoryKeyResponseContent::Chunk(_) => Err(WireError::Protocol(
                "a history response chunk has no manifest digest of its own".to_owned(),
            )),
        }
    }
}

impl SourceAuthorityLocator {
    pub fn source_authority_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-source-authority-locator-v1")
    }
}

impl ArchiveAuthorizationTuple {
    pub fn archive_authorization_tuple_digest(&self) -> Result<Hash> {
        self.holder_trusted_basis.validate_protocol_bounds()?;
        full_object_digest(self, "ak.organization-recovery-archive-tuple-v1")
    }
}

impl SourceRelayAttestation {
    pub fn source_relay_attestation_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-source-relay-attestation-v1")
    }
}

impl HistoryReleaseAttestation {
    pub fn release_attestation_digest(&self) -> Result<Hash> {
        self.validate()?;
        full_object_digest(self, "ak.history-release-attestation-v1")
    }
}

impl AcceptedAuthorityViewVector {
    pub fn canonical_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-accepted-authority-view-vector-v1")
    }
}

impl CurrentGateProjection {
    pub fn canonical_digest(&self) -> Result<Hash> {
        full_object_digest(self, "ak.history-current-gate-projection-v1")
    }
}

impl HistoryKeyResponseRecord {
    pub fn response_record_digest(&self) -> Result<Hash> {
        let serde_json::Value::Object(mut object) = serde_json::to_value(self)? else {
            unreachable!()
        };
        object.remove("record_digest");
        object.remove("service_proof");
        framed_sha256("ak.history-response-record-v1", &object)
    }
}

impl HistoryKeyResponseLostRecord {
    pub fn lost_record_digest(&self) -> Result<Hash> {
        object_digest_without_field(self, "service_proof", "ak.history-response-lost-record-v1")
    }
}

impl HistoryKeyResponseSendReceipt {
    pub fn send_receipt_digest(&self) -> Result<Hash> {
        let serde_json::Value::Object(mut object) = serde_json::to_value(self)? else {
            unreachable!()
        };
        object.remove("receipt_digest");
        object.remove("service_proof");
        framed_sha256("ak.history-response-send-receipt-v1", &object)
    }
}

impl OrganizationRecoveryArchiveReplica {
    pub fn archive_replica_digest(&self) -> Result<Hash> {
        object_digest_without_field(
            self,
            "service_proof",
            "ak.organization-recovery-archive-replica-v1",
        )
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryResponseAckTokenEntryKind {
    Record,
    Lost,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseAckTokenEntry {
    pub sequence: u64,
    pub kind: HistoryResponseAckTokenEntryKind,
    pub response_id: HistoryResponseId,
    pub entry_digest: Hash,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseAckTokenClaims {
    pub release_id: DidCoreId,
    pub request_id: HistoryRequestId,
    pub ordered_ack_entries: Vec<HistoryResponseAckTokenEntry>,
    pub high_water_cursor: String,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub token_expires_at: DateTime<Utc>,
}

impl HistoryResponseAckTokenClaims {
    pub fn validate(&self) -> Result<()> {
        validate_non_empty(&self.high_water_cursor, "high_water_cursor")?;
        if self.ordered_ack_entries.is_empty() {
            return Err(WireError::Protocol(
                "history ack token must bind at least one entry".to_owned(),
            ));
        }
        for pair in self.ordered_ack_entries.windows(2) {
            if pair[0].sequence >= pair[1].sequence {
                return Err(WireError::Protocol(
                    "history ack token entries must be strictly sequence ascending".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn hmac_input_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = b"ak.history-response-ack-token-v1".to_vec();
        bytes.push(0);
        bytes.extend(arkret_wire::canonical::canonical_json_bytes(self)?);
        Ok(bytes)
    }
}

impl HistoryResponsePageEntry {
    pub fn ack_token_entry(&self) -> Result<HistoryResponseAckTokenEntry> {
        match self {
            Self::Record { record } => Ok(HistoryResponseAckTokenEntry {
                sequence: record.sequence,
                kind: HistoryResponseAckTokenEntryKind::Record,
                response_id: record.source_record.response_id.clone(),
                entry_digest: record.record_digest.clone(),
            }),
            Self::Lost { lost_record } => Ok(HistoryResponseAckTokenEntry {
                sequence: lost_record.sequence,
                kind: HistoryResponseAckTokenEntryKind::Lost,
                response_id: lost_record.response_id.clone(),
                entry_digest: lost_record.lost_record_digest()?,
            }),
        }
    }
}

fn validate_sender_domain(value: &str) -> Result<()> {
    if !(1..=512).contains(&value.chars().count()) {
        return Err(WireError::Protocol(
            "history sender domain must contain 1..=512 characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(WireError::Protocol(format!("{field} must not be empty")));
    }
    Ok(())
}

fn validate_non_empty_optional(value: &Option<String>, field: &str) -> Result<()> {
    if let Some(value) = value {
        validate_non_empty(value, field)?;
    }
    Ok(())
}

fn validate_pagination(limited: bool, cursor: Option<&str>) -> Result<()> {
    match (limited, cursor) {
        (true, Some(cursor)) => validate_non_empty(cursor, "cursor"),
        (false, None) => Ok(()),
        _ => Err(WireError::Protocol(
            "cursor must be present exactly when limited is true".to_owned(),
        )),
    }
}

fn validate_bounded_chars(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    if !(min..=max).contains(&value.chars().count()) {
        return Err(WireError::Protocol(format!(
            "{field} must contain {min}..={max} characters"
        )));
    }
    Ok(())
}

fn validate_base64url_bounded(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    if !(min..=max).contains(&value.len()) || !is_base64url(value) {
        return Err(WireError::Protocol(format!(
            "{field} is not canonical base64url"
        )));
    }
    Ok(())
}

fn framed_sha256(domain: &str, value: &impl Serialize) -> Result<Hash> {
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend(arkret_wire::canonical::canonical_json_bytes(value)?);
    Ok(Hash::new(arkret_wire::canonical::sha256_digest(preimage))?)
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn require_sha256(value: &Hash, field: &str) -> Result<()> {
    if !value.as_ref().starts_with("sha256:") {
        return Err(WireError::Protocol(format!("{field} must use sha256")));
    }
    Ok(())
}

#[cfg(test)]
mod history_source_send_disposition_tests {
    use super::HistorySourceSendDisposition;

    #[test]
    fn disposition_lists_are_sorted_and_pairwise_disjoint() {
        let lists = [
            HistorySourceSendDisposition::RETRY_SAME_ATTEMPT,
            HistorySourceSendDisposition::REPLACE_MANIFEST,
            HistorySourceSendDisposition::REQUEST_TERMINAL,
        ];
        for list in lists {
            assert!(
                list.windows(2).all(|pair| pair[0] < pair[1]),
                "disposition list must be sorted and duplicate-free: {list:?}"
            );
        }
        for (index, list) in lists.iter().enumerate() {
            for other in &lists[index + 1..] {
                for code in *list {
                    assert!(
                        !other.contains(code),
                        "{code} appears in two disposition classes"
                    );
                }
            }
        }
    }

    #[test]
    fn unregistered_codes_never_churn_the_outbox() {
        let disposition = HistorySourceSendDisposition::classify("ak_unregistered_experimental");
        assert_eq!(
            disposition,
            HistorySourceSendDisposition::RetrySameAttempt,
            "an unknown code must not be guessed into a manifest replacement"
        );
        assert!(disposition.retries_same_bytes());
        assert!(!disposition.allows_replacement_manifest());
    }

    #[test]
    fn classification_is_keyed_on_the_registered_code() {
        assert_eq!(
            HistorySourceSendDisposition::classify("dependency_missing"),
            HistorySourceSendDisposition::RetrySameAttempt
        );
        assert_eq!(
            HistorySourceSendDisposition::classify("state_mismatch"),
            HistorySourceSendDisposition::ReplaceManifest
        );
        assert_eq!(
            HistorySourceSendDisposition::classify("history_not_visible"),
            HistorySourceSendDisposition::RequestTerminal
        );
    }
}
