//! Authenticated self-query for current or exact committed historical signing
//! keys. Results are query-local projections, not portable authority evidence.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommittedEventRef, CurrentRevision, DeviceId, DidUrl,
    ErrorCode, RealmId, RequestId, Result,
};
use serde::{Deserialize, Serialize};

use crate::agent_signer_state::{
    SELF_SIGNER_OUTCOME_MAX_BYTES, SELF_SIGNER_REQUEST_MAX_BYTES, SELF_SIGNER_RESULT_MAX_BYTES,
    StationSigningKey, self_signer_error, validate_ed25519_public_key, validate_self_signer_bytes,
};

pub const MAX_SIGNER_KEY_QUERIES: usize = 64;

/// One exact signer a query names.
///
/// The four variants are the complete closed cross product of the two query
/// axes: `current` admission versus one exact accepted historical Event, and a
/// device-bound account sender versus an Agent sender. Encoding both axes in
/// the variant is what keeps a device selector from losing its `device_id` and
/// an Agent selector from carrying one; neither state is representable, so no
/// runtime cross-field rule has to hold them together.
///
/// A historical selector addresses its Event by [`CommittedEventRef`]: under
/// authority-commit only the authority-signed `RealmCommit` carries stream
/// position, so a bare `event_id` cannot say which accepted position is meant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "selector_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyQuerySelector {
    CurrentAccountDevice {
        actor: ActorId,
        device_id: DeviceId,
        verification_method: DidUrl,
    },
    CurrentAgent {
        actor: ActorId,
        verification_method: DidUrl,
    },
    HistoricalAccountDevice {
        actor: ActorId,
        device_id: DeviceId,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
    HistoricalAgent {
        actor: ActorId,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
}

impl SignerKeyQuerySelector {
    pub fn actor(&self) -> &ActorId {
        match self {
            Self::CurrentAccountDevice { actor, .. }
            | Self::CurrentAgent { actor, .. }
            | Self::HistoricalAccountDevice { actor, .. }
            | Self::HistoricalAgent { actor, .. } => actor,
        }
    }

    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::CurrentAccountDevice {
                verification_method,
                ..
            }
            | Self::CurrentAgent {
                verification_method,
                ..
            }
            | Self::HistoricalAccountDevice {
                verification_method,
                ..
            }
            | Self::HistoricalAgent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    /// The device this selector is bound to, or `None` for an Agent selector.
    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            Self::CurrentAccountDevice { device_id, .. }
            | Self::HistoricalAccountDevice { device_id, .. } => Some(device_id),
            Self::CurrentAgent { .. } | Self::HistoricalAgent { .. } => None,
        }
    }

    /// The exact accepted Event a historical selector names.
    pub fn committed_event_ref(&self) -> Option<&CommittedEventRef> {
        match self {
            Self::CurrentAccountDevice { .. } | Self::CurrentAgent { .. } => None,
            Self::HistoricalAccountDevice {
                committed_event_ref,
                ..
            }
            | Self::HistoricalAgent {
                committed_event_ref,
                ..
            } => Some(committed_event_ref),
        }
    }

    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        let ActorId::Account { account_id } = self.actor() else {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "device and Agent signer selectors require a complete account ActorId",
            ));
        };
        account_id.validate()?;
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
        if self.authorization_ref.stream_ref.realm_id() != realm_id {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signing-key authorization Event belongs to another Realm",
            ));
        }
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

/// One answer to one exact selector.
///
/// `resolved` carries key material and `unavailable` carries none; the status
/// and the presence of a key are the same fact, so a resolved answer without a
/// key is not representable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyQueryResult {
    Resolved {
        selector: SignerKeyQuerySelector,
        key: ResolvedSignerKey,
    },
    /// The Station holds no answer it may give for this exact selector.
    ///
    /// It is one indistinguishable bucket on purpose: "no such signer", "not
    /// authorized to see it" and "not retained" are not separated, so a caller
    /// cannot probe for the existence of a signer it may not read.
    Unavailable { selector: SignerKeyQuerySelector },
}

impl SignerKeyQueryResult {
    pub fn selector(&self) -> &SignerKeyQuerySelector {
        match self {
            Self::Resolved { selector, .. } | Self::Unavailable { selector } => selector,
        }
    }

    pub fn key(&self) -> Option<&ResolvedSignerKey> {
        match self {
            Self::Resolved { key, .. } => Some(key),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_RESULT_MAX_BYTES, false)?;
        self.selector().validate(realm_id)?;
        match self {
            Self::Resolved { selector, key } => key.validate_for_selector(selector, realm_id),
            Self::Unavailable { .. } => Ok(()),
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
    pub results: Vec<SignerKeyQueryResult>,
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
        SignerKeyQuerySelector::CurrentAccountDevice {
            actor: actor(),
            device_id: DeviceId::new(DEVICE).unwrap(),
            verification_method: DidUrl::new(METHOD).unwrap(),
        }
    }

    fn historical_agent_selector(reference: CommittedEventRef) -> SignerKeyQuerySelector {
        SignerKeyQuerySelector::HistoricalAgent {
            actor: actor(),
            verification_method: DidUrl::new(METHOD).unwrap(),
            committed_event_ref: reference,
        }
    }

    #[test]
    fn a_device_selector_without_its_device_id_is_not_representable() {
        let value = json!({
            "selector_kind": "current_account_device",
            "actor": actor(),
            "verification_method": METHOD,
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn an_agent_selector_carrying_a_device_id_is_not_representable() {
        let value = json!({
            "selector_kind": "current_agent",
            "actor": actor(),
            "device_id": DEVICE,
            "verification_method": METHOD,
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn a_historical_selector_without_its_commit_coordinate_is_not_representable() {
        let value = json!({
            "selector_kind": "historical_agent",
            "actor": actor(),
            "verification_method": METHOD,
            "event_id": "ak:event:sha256:00",
        });
        assert!(serde_json::from_value::<SignerKeyQuerySelector>(value).is_err());
    }

    #[test]
    fn a_resolved_result_without_a_key_is_not_representable() {
        let value = json!({ "status": "resolved", "selector": device_selector() });
        assert!(serde_json::from_value::<SignerKeyQueryResult>(value).is_err());

        let value = json!({
            "status": "unavailable",
            "selector": device_selector(),
            "key": resolved_key(committed_ref(4, 0x11), 9),
        });
        assert!(serde_json::from_value::<SignerKeyQueryResult>(value).is_err());
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
        let result = SignerKeyQueryResult::Resolved {
            selector: historical_agent_selector(target),
            key: resolved_key(authorization, 15),
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
        let target_error = SignerKeyQueryResult::Resolved {
            selector: historical_agent_selector(foreign_target),
            key: resolved_key(committed_ref(7, 0x22), 15),
        }
        .validate(&realm_id())
        .expect_err("a target coordinate from another Realm must fail closed");
        assert!(target_error.to_string().contains("historical signer Event"));

        let mut foreign_authorization = committed_ref(7, 0x22);
        foreign_authorization.stream_ref = CommitStreamRef::Realm {
            realm_id: foreign_realm,
        };
        let authorization_error = SignerKeyQueryResult::Resolved {
            selector: historical_agent_selector(committed_ref(12, 0x11)),
            key: resolved_key(foreign_authorization, 15),
        }
        .validate(&realm_id())
        .expect_err("an authorization coordinate from another Realm must fail closed");
        assert!(
            authorization_error
                .to_string()
                .contains("authorization Event")
        );
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
            results: vec![SignerKeyQueryResult::Unavailable {
                selector: device_selector(),
            }],
        };
        outcome.validate_for_request(&request).unwrap();

        let unasked = SignerKeysQueryOutcome {
            results: vec![SignerKeyQueryResult::Unavailable {
                selector: historical_agent_selector(committed_ref(4, 0x11)),
            }],
            ..outcome
        };
        assert!(unasked.validate_for_request(&request).is_err());
    }
}
