//! Authenticated self-query for current or exact committed historical signing
//! keys. Results are query-local projections, not portable authority evidence.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommittedEventRef, CurrentRevision, DeviceId, DidUrl,
    ErrorCode, RealmId, RequestId, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_signer_state::{
    SELF_SIGNER_OUTCOME_MAX_BYTES, SELF_SIGNER_REQUEST_MAX_BYTES, SELF_SIGNER_RESULT_MAX_BYTES,
    StationSigningKey, self_signer_error, validate_ed25519_public_key, validate_self_signer_bytes,
};

pub const MAX_SIGNER_KEY_QUERIES: usize = 64;

/// One exact signer a query names.
///
/// The two nested enums are the complete closed cross product of the two query
/// axes. The outer `verification_mode` tag selects current admission versus one
/// exact accepted historical Event; the flattened inner `sender_kind` tag
/// selects a device-bound account sender versus an Agent sender. Encoding both
/// axes separately is part of the canonical wire contract.
///
/// A historical selector addresses its Event by [`CommittedEventRef`]: under
/// authority-commit only the authority-signed `RealmCommit` carries stream
/// position, so a bare `event_id` cannot say which accepted position is meant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verification_mode", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyQuerySelector {
    CurrentAdmission {
        #[serde(flatten)]
        sender: CurrentSignerKeyQuerySender,
    },
    HistoricalEvent {
        #[serde(flatten)]
        sender: HistoricalSignerKeyQuerySender,
    },
}

/// Sender-specific fields for a current-admission query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sender_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CurrentSignerKeyQuerySender {
    AccountDevice {
        actor: ActorId,
        device_id: DeviceId,
        verification_method: DidUrl,
    },
    Agent {
        actor: ActorId,
        verification_method: DidUrl,
    },
}

/// Sender-specific fields for an exact historical-Event query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sender_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HistoricalSignerKeyQuerySender {
    AccountDevice {
        actor: ActorId,
        device_id: DeviceId,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
    Agent {
        actor: ActorId,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
    Service {
        actor: ActorId,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
}

impl SignerKeyQuerySelector {
    pub fn actor(&self) -> &ActorId {
        match self {
            Self::CurrentAdmission { sender } => sender.actor(),
            Self::HistoricalEvent { sender } => sender.actor(),
        }
    }

    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::CurrentAdmission { sender } => sender.verification_method(),
            Self::HistoricalEvent { sender } => sender.verification_method(),
        }
    }

    /// The device this selector is bound to, or `None` for an Agent selector.
    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::CurrentAdmission { sender } => sender.device_id(),
            Self::HistoricalEvent { sender } => sender.device_id(),
        }
    }

    /// The exact accepted Event a historical selector names.
    pub fn committed_event_ref(&self) -> Option<&CommittedEventRef> {
        match self {
            Self::CurrentAdmission { .. } => None,
            Self::HistoricalEvent { sender } => Some(sender.committed_event_ref()),
        }
    }

    pub const fn is_historical(&self) -> bool {
        matches!(self, Self::HistoricalEvent { .. })
    }

    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        let service = matches!(
            self,
            Self::HistoricalEvent {
                sender: HistoricalSignerKeyQuerySender::Service { .. }
            }
        );
        if service != matches!(self.actor(), ActorId::Service { .. })
            || (!service && self.actor().as_account_id().is_none())
        {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer selector actor differs from its sender kind",
            ));
        }
        self.actor().validate()?;
        if self
            .committed_event_ref()
            .is_some_and(|reference| reference.stream_ref.realm_id() != realm_id)
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "historical signer Event belongs to another Realm",
            ));
        }
        Ok(())
    }
}

impl CurrentSignerKeyQuerySender {
    fn actor(&self) -> &ActorId {
        match self {
            Self::AccountDevice { actor, .. } | Self::Agent { actor, .. } => actor,
        }
    }

    fn verification_method(&self) -> &DidUrl {
        match self {
            Self::AccountDevice {
                verification_method,
                ..
            }
            | Self::Agent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::AccountDevice { device_id, .. } => Some(device_id),
            Self::Agent { .. } => None,
        }
    }
}

impl HistoricalSignerKeyQuerySender {
    fn actor(&self) -> &ActorId {
        match self {
            Self::AccountDevice { actor, .. }
            | Self::Agent { actor, .. }
            | Self::Service { actor, .. } => actor,
        }
    }

    fn verification_method(&self) -> &DidUrl {
        match self {
            Self::AccountDevice {
                verification_method,
                ..
            }
            | Self::Service {
                verification_method,
                ..
            }
            | Self::Agent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::AccountDevice { device_id, .. } => Some(device_id),
            Self::Agent { .. } | Self::Service { .. } => None,
        }
    }

    fn committed_event_ref(&self) -> &CommittedEventRef {
        match self {
            Self::AccountDevice {
                committed_event_ref,
                ..
            }
            | Self::Service {
                committed_event_ref,
                ..
            }
            | Self::Agent {
                committed_event_ref,
                ..
            } => committed_event_ref,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SignerKeysQueryRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub queries: Vec<SignerKeyQuerySelector>,
}

impl SignerKeysQueryRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_REQUEST_MAX_BYTES, true)?;
        self.recipient_account_id.validate()?;
        if self.queries.is_empty() || self.queries.len() > MAX_SIGNER_KEY_QUERIES {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer-key query requires 1..=64 selectors",
            ));
        }
        let mut seen = BTreeSet::new();
        for selector in &self.queries {
            selector.validate(&self.realm_id)?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(selector)?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer-key selector",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolvedSignerKey {
    pub public_key_b64u: Base64UrlString,
    pub authorization_ref: CommittedEventRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: CurrentRevision,
    /// Governance generation verified by `revision.commit_id`.
    pub governance_generation: u64,
}

impl ResolvedSignerKey {
    pub fn validate(&self) -> Result<()> {
        validate_ed25519_public_key(self.public_key_b64u.as_str())?;
        if self.authorization_ref.commit_id == self.revision.commit_id
            && self.authorization_ref.stream_position != self.revision.stream_position
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "resolved signing key authorization and its revision name one commit at two stream positions",
            ));
        }
        if self.authorization_ref.stream_position > self.revision.stream_position {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "resolved signing key is not covered by its authority-stream revision",
            ));
        }
        Ok(())
    }

    /// Check the key and selector as two independent committed coordinates.
    ///
    /// A historical selector names the Event whose producer signature is being
    /// checked. `authorization_ref` independently names the accepted Event that
    /// made this key valid there. They may be equal, but equality is neither
    /// required nor sufficient: each reference is validated for its own role.
    pub fn validate_for_selector(
        &self,
        selector: &SignerKeyQuerySelector,
        realm_id: &RealmId,
    ) -> Result<()> {
        selector.validate(realm_id)?;
        self.validate()?;
        if matches!(
            selector,
            SignerKeyQuerySelector::HistoricalEvent {
                sender: HistoricalSignerKeyQuerySender::Service { .. }
            }
        ) {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "account and Agent key cannot answer a Service selector",
            ));
        }
        // `realm_id` scopes the queried producer Event. An Agent's key
        // authorization lives in its own PCR, and a device authorization can
        // likewise live outside the target collaboration Realm. The result's
        // revision is validated against that authorization stream, never the
        // target Event's stream.
        Ok(())
    }

    /// Lift a Station signing key into the answer for one exact selector.
    ///
    /// A [`StationSigningKey`] names its authorization by bare `event_id`, and
    /// a query answer needs the commit coordinate of that Event plus the
    /// revision it was projected at. Neither is derivable from the key, so the
    /// Station supplies both from the same read and this constructor refuses
    /// any pair that does not name the key's own authorization Event.
    pub fn from_station_key(
        key: StationSigningKey,
        authorization_ref: CommittedEventRef,
        revision: CurrentRevision,
        governance_generation: u64,
        selector: &SignerKeyQuerySelector,
        realm_id: &RealmId,
    ) -> Result<Self> {
        key.validate()?;
        selector.validate(realm_id)?;
        if key.actor != *selector.actor()
            || key.verification_method != *selector.verification_method()
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signing key does not match the exact selector",
            ));
        }
        if authorization_ref.event_id != key.authorization_ref {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "committed authorization reference names another Event than the signing key",
            ));
        }
        let resolved = Self {
            public_key_b64u: key.public_key_b64u,
            authorization_ref,
            revision,
            governance_generation,
        };
        resolved.validate_for_selector(selector, realm_id)?;
        Ok(resolved)
    }
}

/// Own-Station verified human current key; never a portable authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CurrentDeviceSigningKey {
    pub public_key_b64u: Base64UrlString,
}

impl CurrentDeviceSigningKey {
    pub fn validate(&self) -> Result<()> {
        validate_ed25519_public_key(self.public_key_b64u.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ServiceHistoricalSigningKey {
    pub public_key_b64u: Base64UrlString,
    pub applet_id: arkret_wire::AppletId,
    pub registration_epoch: arkret_wire::Hash,
    pub registration_ref: CommittedEventRef,
    pub authorization_ref: CommittedEventRef,
    pub effective_scope: arkret_wire::ScopeRef,
}
impl ServiceHistoricalSigningKey {
    pub fn validate(&self) -> Result<()> {
        validate_ed25519_public_key(self.public_key_b64u.as_str())?;
        let realm = self.effective_scope.realm_id_opt().ok_or_else(|| {
            self_signer_error(
                ErrorCode::SchemaViolation,
                "Service key lacks a collaboration scope",
            )
        })?;
        if !matches!(
            self.effective_scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        ) || self.registration_ref.stream_ref.realm_id() != realm
            || self.authorization_ref.stream_ref.realm_id() != realm
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "Service installation references differ from its scope",
            ));
        }
        Ok(())
    }
    pub fn validate_for_selector(
        &self,
        selector: &SignerKeyQuerySelector,
        realm: &RealmId,
    ) -> Result<()> {
        selector.validate(realm)?;
        self.validate()?;
        if !matches!(
            selector,
            SignerKeyQuerySelector::HistoricalEvent {
                sender: HistoricalSignerKeyQuerySender::Service { .. }
            }
        ) || self.effective_scope.realm_id_opt() != Some(realm)
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "Service key requires an exact Service historical selector",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum QueryKeyWire {
    Device(CurrentDeviceSigningKey),
    Committed(ResolvedSignerKey),
    Service(ServiceHistoricalSigningKey),
}

#[derive(Serialize)]
#[serde(untagged)]
enum QueryKeyWireRef<'a> {
    Device(&'a CurrentDeviceSigningKey),
    Committed(&'a ResolvedSignerKey),
    Service(&'a ServiceHistoricalSigningKey),
}

/// One answer to one exact selector.
///
/// `resolved` carries key material and `unavailable` carries none. Historical
/// resolved answers additionally carry the authorization-effective
/// `accepted_at`; current answers cannot carry that member. The enum therefore
/// mirrors the schema's closed outcome branches instead of treating the time as
/// a nullable or reusable current-result field.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyQueryOutcome {
    CurrentDeviceResolved {
        selector: SignerKeyQuerySelector,
        key: CurrentDeviceSigningKey,
    },
    CurrentResolved {
        selector: SignerKeyQuerySelector,
        key: ResolvedSignerKey,
    },
    HistoricalResolved {
        selector: SignerKeyQuerySelector,
        key: ResolvedSignerKey,
        accepted_at: DateTime<Utc>,
    },
    HistoricalServiceResolved {
        selector: SignerKeyQuerySelector,
        key: ServiceHistoricalSigningKey,
        accepted_at: DateTime<Utc>,
    },
    /// The Station holds no answer it may give for this exact selector.
    ///
    /// It is one indistinguishable bucket on purpose: "no such signer", "not
    /// authorized to see it" and "not retained" are not separated, so a caller
    /// cannot probe for the existence of a signer it may not read.
    Unavailable { selector: SignerKeyQuerySelector },
}

impl SignerKeyQueryOutcome {
    pub fn selector(&self) -> &SignerKeyQuerySelector {
        match self {
            Self::CurrentDeviceResolved { selector, .. }
            | Self::CurrentResolved { selector, .. }
            | Self::HistoricalResolved { selector, .. }
            | Self::HistoricalServiceResolved { selector, .. }
            | Self::Unavailable { selector } => selector,
        }
    }

    pub fn key(&self) -> Option<&ResolvedSignerKey> {
        match self {
            Self::CurrentResolved { key, .. } | Self::HistoricalResolved { key, .. } => Some(key),
            Self::CurrentDeviceResolved { .. }
            | Self::HistoricalServiceResolved { .. }
            | Self::Unavailable { .. } => None,
        }
    }

    pub fn service_key(&self) -> Option<&ServiceHistoricalSigningKey> {
        if let Self::HistoricalServiceResolved { key, .. } = self {
            Some(key)
        } else {
            None
        }
    }

    /// Effective time of a historical authorization fact.
    pub fn accepted_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::HistoricalResolved { accepted_at, .. }
            | Self::HistoricalServiceResolved { accepted_at, .. } => Some(*accepted_at),
            Self::CurrentDeviceResolved { .. }
            | Self::CurrentResolved { .. }
            | Self::Unavailable { .. } => None,
        }
    }

    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_RESULT_MAX_BYTES, false)?;
        self.selector().validate(realm_id)?;
        match self {
            Self::CurrentDeviceResolved { selector, key } => {
                if !matches!(
                    selector,
                    SignerKeyQuerySelector::CurrentAdmission {
                        sender: CurrentSignerKeyQuerySender::AccountDevice { .. }
                    }
                ) {
                    return Err(self_signer_error(
                        ErrorCode::SchemaViolation,
                        "human current key requires a current account_device selector",
                    ));
                }
                key.validate()
            }
            Self::CurrentResolved { selector, key } => {
                if !matches!(
                    selector,
                    SignerKeyQuerySelector::CurrentAdmission {
                        sender: CurrentSignerKeyQuerySender::Agent { .. }
                    }
                ) {
                    return Err(self_signer_error(
                        ErrorCode::SchemaViolation,
                        "current signer-key result requires a current_admission selector",
                    ));
                }
                key.validate_for_selector(selector, realm_id)
            }
            Self::HistoricalResolved { selector, key, .. } => {
                if !selector.is_historical()
                    || matches!(
                        selector,
                        SignerKeyQuerySelector::HistoricalEvent {
                            sender: HistoricalSignerKeyQuerySender::Service { .. }
                        }
                    )
                {
                    return Err(self_signer_error(
                        ErrorCode::SchemaViolation,
                        "historical signer-key result requires a historical_event selector",
                    ));
                }
                key.validate_for_selector(selector, realm_id)
            }
            Self::HistoricalServiceResolved { selector, key, .. } => {
                key.validate_for_selector(selector, realm_id)
            }
            Self::Unavailable { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SignerKeyQueryStatus {
    Resolved,
    Unavailable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerKeyQueryResultWire {
    selector: SignerKeyQuerySelector,
    status: SignerKeyQueryStatus,
    #[serde(default)]
    key: WireField<QueryKeyWire>,
    #[serde(default)]
    accepted_at: WireField<CanonicalAcceptedAt>,
}

/// Distinguish an absent member from an explicit JSON `null`. Every optional
/// member in the schema is optional-by-absence; `null` is never an alias.
#[derive(Default)]
enum WireField<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for WireField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct CanonicalAcceptedAt(
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")] DateTime<Utc>,
);

#[derive(Serialize)]
struct SignerKeyQueryResultWireRef<'a> {
    selector: &'a SignerKeyQuerySelector,
    status: SignerKeyQueryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<QueryKeyWireRef<'a>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    accepted_at: Option<DateTime<Utc>>,
}

impl Serialize for SignerKeyQueryOutcome {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match self {
            Self::CurrentDeviceResolved { selector, key } => {
                if !matches!(
                    selector,
                    SignerKeyQuerySelector::CurrentAdmission {
                        sender: CurrentSignerKeyQuerySender::AccountDevice { .. }
                    }
                ) {
                    return Err(serde::ser::Error::custom(
                        "human current key requires a current account_device selector",
                    ));
                }
                SignerKeyQueryResultWireRef {
                    selector,
                    status: SignerKeyQueryStatus::Resolved,
                    key: Some(QueryKeyWireRef::Device(key)),
                    accepted_at: None,
                }
            }
            Self::CurrentResolved { selector, key } => {
                if !matches!(
                    selector,
                    SignerKeyQuerySelector::CurrentAdmission {
                        sender: CurrentSignerKeyQuerySender::Agent { .. }
                    }
                ) {
                    return Err(serde::ser::Error::custom(
                        "current signer-key result requires a current_admission selector",
                    ));
                }
                SignerKeyQueryResultWireRef {
                    selector,
                    status: SignerKeyQueryStatus::Resolved,
                    key: Some(QueryKeyWireRef::Committed(key)),
                    accepted_at: None,
                }
            }
            Self::HistoricalResolved {
                selector,
                key,
                accepted_at,
            } => {
                if !selector.is_historical()
                    || matches!(
                        selector,
                        SignerKeyQuerySelector::HistoricalEvent {
                            sender: HistoricalSignerKeyQuerySender::Service { .. }
                        }
                    )
                {
                    return Err(serde::ser::Error::custom(
                        "historical signer-key result requires a historical_event selector",
                    ));
                }
                SignerKeyQueryResultWireRef {
                    selector,
                    status: SignerKeyQueryStatus::Resolved,
                    key: Some(QueryKeyWireRef::Committed(key)),
                    accepted_at: Some(*accepted_at),
                }
            }
            Self::HistoricalServiceResolved {
                selector,
                key,
                accepted_at,
            } => {
                if !matches!(
                    selector,
                    SignerKeyQuerySelector::HistoricalEvent {
                        sender: HistoricalSignerKeyQuerySender::Service { .. }
                    }
                ) {
                    return Err(serde::ser::Error::custom(
                        "Service key requires historical Service selector",
                    ));
                }
                SignerKeyQueryResultWireRef {
                    selector,
                    status: SignerKeyQueryStatus::Resolved,
                    key: Some(QueryKeyWireRef::Service(key)),
                    accepted_at: Some(*accepted_at),
                }
            }
            Self::Unavailable { selector } => SignerKeyQueryResultWireRef {
                selector,
                status: SignerKeyQueryStatus::Unavailable,
                key: None,
                accepted_at: None,
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignerKeyQueryOutcome {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SignerKeyQueryResultWire::deserialize(deserializer)?;
        match (wire.status, wire.key, wire.accepted_at) {
            (
                SignerKeyQueryStatus::Resolved,
                WireField::Present(QueryKeyWire::Device(key)),
                WireField::Missing,
            ) if matches!(
                wire.selector,
                SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::AccountDevice { .. }
                }
            ) =>
            {
                Ok(Self::CurrentDeviceResolved {
                    selector: wire.selector,
                    key,
                })
            }
            (
                SignerKeyQueryStatus::Resolved,
                WireField::Present(QueryKeyWire::Committed(key)),
                WireField::Missing,
            ) if matches!(
                wire.selector,
                SignerKeyQuerySelector::CurrentAdmission {
                    sender: CurrentSignerKeyQuerySender::Agent { .. }
                }
            ) =>
            {
                Ok(Self::CurrentResolved {
                    selector: wire.selector,
                    key,
                })
            }
            (
                SignerKeyQueryStatus::Resolved,
                WireField::Present(QueryKeyWire::Committed(key)),
                WireField::Present(CanonicalAcceptedAt(accepted_at)),
            ) if wire.selector.is_historical()
                && !matches!(
                    wire.selector,
                    SignerKeyQuerySelector::HistoricalEvent {
                        sender: HistoricalSignerKeyQuerySender::Service { .. }
                    }
                ) =>
            {
                Ok(Self::HistoricalResolved {
                    selector: wire.selector,
                    key,
                    accepted_at,
                })
            }
            (
                SignerKeyQueryStatus::Resolved,
                WireField::Present(QueryKeyWire::Service(key)),
                WireField::Present(CanonicalAcceptedAt(accepted_at)),
            ) if matches!(
                wire.selector,
                SignerKeyQuerySelector::HistoricalEvent {
                    sender: HistoricalSignerKeyQuerySender::Service { .. }
                }
            ) =>
            {
                Ok(Self::HistoricalServiceResolved {
                    selector: wire.selector,
                    key,
                    accepted_at,
                })
            }
            (SignerKeyQueryStatus::Unavailable, WireField::Missing, WireField::Missing) => {
                Ok(Self::Unavailable {
                    selector: wire.selector,
                })
            }
            (SignerKeyQueryStatus::Resolved, ..) => Err(serde::de::Error::custom(
                "resolved signer-key result has fields inconsistent with verification_mode",
            )),
            (SignerKeyQueryStatus::Unavailable, ..) => Err(serde::de::Error::custom(
                "unavailable signer-key result must not carry key or accepted_at",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SignerKeysQueryOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub results: Vec<SignerKeyQueryOutcome>,
}

impl SignerKeysQueryOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_OUTCOME_MAX_BYTES, false)?;
        if self.results.is_empty() || self.results.len() > MAX_SIGNER_KEY_QUERIES {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer-key outcome requires 1..=64 results",
            ));
        }
        let mut seen = BTreeSet::new();
        for result in &self.results {
            result.validate(&self.realm_id)?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(result.selector())?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer-key result",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &SignerKeysQueryRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.recipient_account_id != request.recipient_account_id
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer-key outcome does not match its request",
            ));
        }
        let asked: BTreeSet<Vec<u8>> = request
            .queries
            .iter()
            .map(arkret_canonical::canonical_json_bytes)
            .collect::<std::result::Result<_, _>>()?;
        let answered: BTreeSet<Vec<u8>> = self
            .results
            .iter()
            .map(|result| arkret_canonical::canonical_json_bytes(result.selector()))
            .collect::<std::result::Result<_, _>>()?;
        if asked != answered {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer-key outcome must answer every exact selector once",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CommitStreamRef, DidCoreId, EventId, RealmCommitId};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const DEVICE: &str = "ak:device:019a0000-0000-7000-8000-000000000001";
    const METHOD: &str = "did:web:alice.example#device-1";

    fn realm_id() -> RealmId {
        RealmId::new(REALM).unwrap()
    }

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn actor() -> ActorId {
        ActorId::account(account_id())
    }

    fn committed_ref(position: u64, byte: u8) -> CommittedEventRef {
        CommittedEventRef {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]),
            commit_id: RealmCommitId::from_digest([byte; 32]),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: position,
        }
    }

    fn public_key() -> Base64UrlString {
        Base64UrlString::new(arkret_wire::base64url::base64url_encode([7_u8; 32])).unwrap()
    }

    /// The revision is a later commit of the same stream, so the key is covered
    /// by it without the two coordinates naming one commit twice.
    fn resolved_key(authorization: CommittedEventRef, revision_position: u64) -> ResolvedSignerKey {
        ResolvedSignerKey {
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([0xfe; 32]),
                stream_position: revision_position,
            },
            public_key_b64u: public_key(),
            authorization_ref: authorization,
            governance_generation: 4,
        }
    }

    fn device_selector() -> SignerKeyQuerySelector {
        SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::AccountDevice {
                actor: actor(),
                device_id: DeviceId::new(DEVICE).unwrap(),
                verification_method: DidUrl::new(METHOD).unwrap(),
            },
        }
    }

    fn historical_agent_selector(reference: CommittedEventRef) -> SignerKeyQuerySelector {
        SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::Agent {
                actor: actor(),
                verification_method: DidUrl::new(METHOD).unwrap(),
                committed_event_ref: reference,
            },
        }
    }

    fn accepted_at() -> DateTime<Utc> {
        "2026-09-20T00:00:00.000Z".parse().unwrap()
    }

    #[test]
    fn historical_service_query_requires_its_closed_key_and_canonical_time() {
        let selector = SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::Service {
                actor: ActorId::service(DidCoreId::new("ak:did_core:web:applet.example").unwrap()),
                verification_method: DidUrl::new("did:web:applet.example#producer").unwrap(),
                committed_event_ref: committed_ref(5, 5),
            },
        };
        let key = ServiceHistoricalSigningKey {
            public_key_b64u: public_key(),
            applet_id: arkret_wire::AppletId::new("ak:applet:018f0f51-7b44-7a2e-8c2f-9b1d6e3a4c5d")
                .unwrap(),
            registration_epoch: arkret_wire::Hash::new(format!("sha256:{}", "12".repeat(32)))
                .unwrap(),
            registration_ref: committed_ref(1, 1),
            authorization_ref: committed_ref(2, 2),
            effective_scope: arkret_wire::ScopeRef::Realm {
                realm_id: realm_id(),
            },
        };
        let result = SignerKeyQueryOutcome::HistoricalServiceResolved {
            selector: selector.clone(),
            key,
            accepted_at: accepted_at(),
        };
        result.validate(&realm_id()).unwrap();
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(
            serde_json::from_value::<SignerKeyQueryOutcome>(value.clone()).unwrap(),
            result
        );
        for member in ["key", "accepted_at"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(member);
            assert!(serde_json::from_value::<SignerKeyQueryOutcome>(missing).is_err());
            let mut null = value.clone();
            null[member] = json!(null);
            assert!(serde_json::from_value::<SignerKeyQueryOutcome>(null).is_err());
        }
        let mut wrong = value;
        wrong["selector"]["sender_kind"] = json!("agent");
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(wrong).is_err());
        let mut current = serde_json::to_value(selector).unwrap();
        current["verification_mode"] = json!("current_admission");
        current
            .as_object_mut()
            .unwrap()
            .remove("committed_event_ref");
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(current).is_err());
    }

    #[test]
    fn a_device_selector_without_its_device_id_is_not_representable() {
        let value = json!({
            "verification_mode": "current_admission",
            "sender_kind": "account_device",
            "actor": actor(),
            "verification_method": METHOD,
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn an_agent_selector_carrying_a_device_id_is_not_representable() {
        let value = json!({
            "verification_mode": "current_admission",
            "sender_kind": "agent",
            "actor": actor(),
            "device_id": DEVICE,
            "verification_method": METHOD,
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn a_historical_selector_without_its_commit_coordinate_is_not_representable() {
        let value = json!({
            "verification_mode": "historical_event",
            "sender_kind": "agent",
            "actor": actor(),
            "verification_method": METHOD,
            "event_id": "ak:event:sha256:00",
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn selector_wire_uses_the_two_registered_axes_and_rejects_the_old_tag() {
        let value = serde_json::to_value(device_selector()).unwrap();
        assert_eq!(value["verification_mode"], "current_admission");
        assert_eq!(value["sender_kind"], "account_device");
        assert!(value.get("selector_kind").is_none());

        let old = json!({
            "selector_kind": "current_account_device",
            "actor": actor(),
            "device_id": DEVICE,
            "verification_method": METHOD,
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(old).is_err());
    }

    #[test]
    fn a_resolved_result_without_a_key_is_not_representable() {
        let value = json!({ "status": "resolved", "selector": device_selector() });
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(value).is_err());

        let value = json!({
            "status": "unavailable",
            "selector": device_selector(),
            "key": resolved_key(committed_ref(4, 0x11), 9),
        });
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(value).is_err());
    }

    #[test]
    fn historical_resolved_result_requires_only_its_registered_timestamp_shape() {
        let selector = historical_agent_selector(committed_ref(12, 0x11));
        let key = resolved_key(committed_ref(7, 0x22), 15);
        let value = json!({
            "selector": selector,
            "status": "resolved",
            "key": key,
            "accepted_at": "2026-09-20T00:00:00.000Z",
        });
        let result: SignerKeyQueryOutcome = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), value);

        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("accepted_at");
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(missing).is_err());

        let mut noncanonical = value;
        noncanonical["accepted_at"] = json!("2026-09-20T00:00:00Z");
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(noncanonical).is_err());

        let explicit_null = json!({
            "selector": historical_agent_selector(committed_ref(12, 0x11)),
            "status": "resolved",
            "key": resolved_key(committed_ref(7, 0x22), 15),
            "accepted_at": null,
        });
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(explicit_null).is_err());

        let current_with_timestamp = json!({
            "selector": device_selector(),
            "status": "resolved",
            "key": resolved_key(committed_ref(7, 0x22), 15),
            "accepted_at": "2026-09-20T00:00:00.000Z",
        });
        assert!(serde_json::from_value::<SignerKeyQueryOutcome>(current_with_timestamp).is_err());

        let unavailable_with_null_key = json!({
            "selector": device_selector(),
            "status": "unavailable",
            "key": null,
        });
        assert!(
            serde_json::from_value::<SignerKeyQueryOutcome>(unavailable_with_null_key).is_err()
        );
    }

    #[test]
    fn a_resolved_key_requires_its_verified_governance_generation() {
        let mut value = serde_json::to_value(resolved_key(committed_ref(7, 0x22), 15)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("governance_generation");
        assert!(serde_json::from_value::<ResolvedSignerKey>(value).is_err());
    }

    #[test]
    fn historical_target_and_authorization_are_independent_complete_coordinates() {
        let target = committed_ref(12, 0x11);
        let authorization = committed_ref(7, 0x22);
        let result = SignerKeyQueryOutcome::HistoricalResolved {
            selector: historical_agent_selector(target),
            key: resolved_key(authorization, 15),
            accepted_at: accepted_at(),
        };
        result
            .validate(&realm_id())
            .expect("a target Event and its independently verified authorization may differ");
    }

    #[test]
    fn target_and_authorization_coordinates_are_validated_separately() {
        let foreign_realm =
            RealmId::new("ak:realm:AQkDA7LFmM6XXBNpdAmM31bTMIpBgRDpMuNP9JKuT-JB").unwrap();
        let mut foreign_target = committed_ref(12, 0x11);
        foreign_target.stream_ref = CommitStreamRef::Realm {
            realm_id: foreign_realm.clone(),
        };
        let target_error = SignerKeyQueryOutcome::HistoricalResolved {
            selector: historical_agent_selector(foreign_target),
            key: resolved_key(committed_ref(7, 0x22), 15),
            accepted_at: accepted_at(),
        }
        .validate(&realm_id())
        .expect_err("a target coordinate from another Realm must fail closed");
        assert!(target_error.to_string().contains("historical signer Event"));

        let mut foreign_authorization = committed_ref(7, 0x22);
        foreign_authorization.stream_ref = CommitStreamRef::Realm {
            realm_id: foreign_realm,
        };
        SignerKeyQueryOutcome::HistoricalResolved {
            selector: historical_agent_selector(committed_ref(12, 0x11)),
            key: resolved_key(foreign_authorization, 15),
            accepted_at: accepted_at(),
        }
        .validate(&realm_id())
        .expect("Agent PCR authorization may be in another Realm than its target Event");
    }

    /// A Station key names its authorization by bare `event_id`. Lifting it
    /// into a query answer needs the commit coordinate of that same Event, and
    /// a coordinate that names a different Event is refused rather than
    /// silently answering about some other authorization.
    #[test]
    fn a_station_key_is_lifted_only_onto_its_own_committed_event() {
        let station_key = StationSigningKey {
            actor: actor(),
            verification_method: DidUrl::new(METHOD).unwrap(),
            public_key_b64u: public_key(),
            authorization_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x11; 32],
            ),
        };
        let revision = CurrentRevision {
            commit_id: RealmCommitId::from_digest([0xfe; 32]),
            stream_position: 9,
        };

        ResolvedSignerKey::from_station_key(
            station_key.clone(),
            committed_ref(4, 0x11),
            revision.clone(),
            4,
            &device_selector(),
            &realm_id(),
        )
        .unwrap();

        let error = ResolvedSignerKey::from_station_key(
            station_key,
            committed_ref(4, 0x22),
            revision,
            4,
            &device_selector(),
            &realm_id(),
        )
        .expect_err("a foreign committed reference must fail closed");
        assert!(error.to_string().contains("another Event"), "{error}");
    }

    #[test]
    fn a_key_authorized_past_its_revision_is_rejected() {
        let key = resolved_key(committed_ref(11, 0x11), 9);
        let error = key.validate().expect_err("an uncovered key must fail");
        assert!(error.to_string().contains("revision"), "{error}");
    }

    #[test]
    fn an_outcome_answers_every_exact_selector_once() {
        let request = SignerKeysQueryRequestBody {
            request_id: RequestId::new("ak:request:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_id: realm_id(),
            recipient_account_id: account_id(),
            queries: vec![device_selector()],
        };
        request.validate().unwrap();

        let outcome = SignerKeysQueryOutcome {
            request_id: request.request_id.clone(),
            realm_id: realm_id(),
            recipient_account_id: account_id(),
            results: vec![SignerKeyQueryOutcome::Unavailable {
                selector: device_selector(),
            }],
        };
        outcome.validate_for_request(&request).unwrap();

        let unasked = SignerKeysQueryOutcome {
            results: vec![SignerKeyQueryOutcome::Unavailable {
                selector: historical_agent_selector(committed_ref(4, 0x11)),
            }],
            ..outcome
        };
        assert!(unasked.validate_for_request(&request).is_err());
    }
}
