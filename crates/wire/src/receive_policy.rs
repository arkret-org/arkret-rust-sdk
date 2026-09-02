use serde::{Deserialize, Serialize};

use crate::{DidCoreId, Result, WireError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteReceiveAction {
    Drop,
    Quarantine,
    Notify,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum UnknownInviteAction {
    Drop,
    Quarantine,
}

/// Holder-selected invite consent gate profile
/// (`consent-model.md` §6.1, carried by `invite_receive_policy.consent_profile`).
///
/// The profile is subject-private: it is never advertised through
/// `ServiceDescribe` and must not be observable by requesters or peer Stations.
/// Under `RequireExplicitConsent` only verified `consent_grant` introduction
/// evidence may notify the holder; every other delivery is silently dropped on
/// the holder Station inside the opaque `deferred` equivalence class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentProfile {
    #[default]
    Default,
    RequireExplicitConsent,
}

impl ConsentProfile {
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    #[must_use]
    pub fn requires_explicit_consent(&self) -> bool {
        matches!(self, Self::RequireExplicitConsent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceivePolicySurface {
    InviteDelivery,
    ContactRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDisclosureLevel {
    Opaque,
    Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveDisclosureMax {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_trust_max: Option<ReceiveDisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_trust_max: Option<ReceiveDisclosureLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_trust_max: Option<ReceiveDisclosureLevel>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NewSourceQuotaOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_sources_per_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_sources_per_retention: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct NewSourceQuotaConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_new_sources_per_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_new_sources_per_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_new_sources_per_retention: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_new_sources_per_retention: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveNewSourceQuota {
    pub window_seconds: u64,
    pub new_sources_per_window: u64,
    pub retention_seconds: u64,
    pub new_sources_per_retention: u64,
}

impl NewSourceQuotaConstraints {
    pub const DEFAULT_WINDOW_SECONDS: u64 = 86_400;
    pub const DEFAULT_NEW_SOURCES_PER_WINDOW: u64 = 3;
    pub const MAX_NEW_SOURCES_PER_WINDOW: u64 = 10;
    pub const DEFAULT_RETENTION_SECONDS: u64 = 2_592_000;
    pub const DEFAULT_NEW_SOURCES_PER_RETENTION: u64 = 30;
    pub const MAX_NEW_SOURCES_PER_RETENTION: u64 = 200;

    pub fn effective(
        &self,
        subject: Option<&NewSourceQuotaOverride>,
    ) -> Result<EffectiveNewSourceQuota> {
        let window_seconds = self.window_seconds.unwrap_or(Self::DEFAULT_WINDOW_SECONDS);
        let default_per_window = self
            .default_new_sources_per_window
            .unwrap_or(Self::DEFAULT_NEW_SOURCES_PER_WINDOW);
        let max_per_window = self
            .max_new_sources_per_window
            .unwrap_or(Self::MAX_NEW_SOURCES_PER_WINDOW);
        let retention_seconds = self
            .retention_seconds
            .unwrap_or(Self::DEFAULT_RETENTION_SECONDS);
        let default_per_retention = self
            .default_new_sources_per_retention
            .unwrap_or(Self::DEFAULT_NEW_SOURCES_PER_RETENTION);
        let max_per_retention = self
            .max_new_sources_per_retention
            .unwrap_or(Self::MAX_NEW_SOURCES_PER_RETENTION);

        if window_seconds == 0
            || default_per_window == 0
            || max_per_window == 0
            || retention_seconds == 0
            || default_per_retention == 0
            || max_per_retention == 0
            || max_per_window < default_per_window
            || max_per_retention < default_per_retention
            || retention_seconds < window_seconds
        {
            return Err(WireError::Protocol(
                "receive policy new_source_quota violates its deployment invariants".to_owned(),
            ));
        }

        Ok(EffectiveNewSourceQuota {
            window_seconds,
            new_sources_per_window: subject
                .and_then(|value| value.new_sources_per_window)
                .unwrap_or(default_per_window)
                .min(max_per_window),
            retention_seconds,
            new_sources_per_retention: subject
                .and_then(|value| value.new_sources_per_retention)
                .unwrap_or(default_per_retention)
                .min(max_per_retention),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivePolicyConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<Vec<ReceivePolicySurface>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_allowed_introduction_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_denied_introduction_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_claim_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_address_max_behavior: Option<InviteReceiveAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_invites_max_behavior: Option<UnknownInviteAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_source_quota: Option<NewSourceQuotaConstraints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_max: Option<ReceiveDisclosureMax>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_handle_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_handle_issuer_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_directory_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_source_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_source_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_subject_did_methods: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_source_quota_defaults_clamp_and_zero_override() {
        let constraints = NewSourceQuotaConstraints::default();
        let defaults = constraints.effective(None).unwrap();
        assert_eq!(defaults.window_seconds, 86_400);
        assert_eq!(defaults.new_sources_per_window, 3);
        assert_eq!(defaults.retention_seconds, 2_592_000);
        assert_eq!(defaults.new_sources_per_retention, 30);

        let subject = NewSourceQuotaOverride {
            new_sources_per_window: Some(999),
            new_sources_per_retention: Some(0),
        };
        let effective = constraints.effective(Some(&subject)).unwrap();
        assert_eq!(effective.new_sources_per_window, 10);
        assert_eq!(effective.new_sources_per_retention, 0);
    }

    #[test]
    fn new_source_quota_rejects_invalid_deployment_invariants() {
        let constraints = NewSourceQuotaConstraints {
            default_new_sources_per_window: Some(4),
            max_new_sources_per_window: Some(3),
            ..NewSourceQuotaConstraints::default()
        };
        assert!(constraints.effective(None).is_err());
    }
}
