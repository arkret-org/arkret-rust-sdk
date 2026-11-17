//! The one original public certificate establishing an Organization's first governor.

use arkret_models_identity::{AuthenticatedServiceResolution, ResolutionMethodHistoryEvidence};
use arkret_wire::{
    ActorId, Base64UrlString, CommittedEventFullView, Event, EventId, EventKind, GenesisGovernance,
    Hash, RealmAuthorityBundle, Result, WireError,
};
use serde::{Deserialize, Serialize};

/// Native Org authorization source. This is not an Applet installation fact.
/// Its unique target and accepted cut come from the original Event and Commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationGenesisSignerFact {
    pub event_id: EventId,
    pub method_history_evidence: ResolutionMethodHistoryEvidence,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub approval_signatures: Option<Vec<arkret_wire::ApprovalSignature>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub producer_resolution: Option<AuthenticatedServiceResolution>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub public_key_base64url: Option<Base64UrlString>,
}

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

impl OrganizationGenesisSignerFact {
    /// Shape only. Method authority and finite votes require the identity verifier.
    pub fn validate(&self) -> Result<()> {
        self.method_history_evidence.validate_shape()?;
        if !matches!(
            &self.method_history_evidence,
            ResolutionMethodHistoryEvidence::WebvhLog { .. }
        ) || arkret_canonical::canonical_json_bytes(&self.method_history_evidence)?.len()
            > 1024 * 1024
        {
            return Err(invalid(
                "Org Genesis requires bounded complete native WebVH evidence",
            ));
        }
        if let Some(approvals) = &self.approval_signatures {
            if approvals.is_empty() {
                return Err(invalid("present Org approvals cannot be empty"));
            }
            for approval in approvals {
                approval.validate()?;
            }
        }
        match (&self.producer_resolution, &self.public_key_base64url) {
            (Some(_), None) => Ok(()),
            (None, Some(key)) if self.approval_signatures.is_some() => {
                let bytes = arkret_canonical::base64url_decode(key.as_str())?;
                if bytes.len() != 32 || arkret_canonical::base64url_encode(&bytes) != key.as_str() {
                    return Err(invalid(
                        "Org Device source requires the canonical Ed25519 key",
                    ));
                }
                Ok(())
            }
            _ => Err(invalid(
                "Org Genesis requires one actual Service or finite Device source",
            )),
        }
    }

    pub fn digest(&self) -> Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    /// Exact Event binding only; a candidate selector never establishes Org authority.
    pub fn validate_event_binding(
        &self,
        event: &Event,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        self.validate()?;
        if event.kind != EventKind::RealmCreate
            || self.event_id != event.event_id
            || !matches!(
                GenesisGovernance::from_genesis(event)?,
                GenesisGovernance::Organization
            )
        {
            return Err(invalid(
                "Org source belongs only to its exact native Genesis",
            ));
        }
        event.verify_event_id_matches_content_with_digest_suite(suite)?;
        event.verify_producer_proof_self_consistency(suite)?;
        match (
            event.actual_signer(),
            &self.producer_resolution,
            &self.public_key_base64url,
        ) {
            (ActorId::Service { service_id }, Some(resolution), None) => {
                resolution.validate_shape(service_id, event.created_at)
            }
            (ActorId::Account { .. }, None, Some(_))
                if event.account_device_producer()?.is_some() =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "Org fact source differs from the actual Event producer",
            )),
        }
    }

    pub fn validate_commit_binding(
        &self,
        full: &CommittedEventFullView,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        full.validate_shape()?;
        full.commit.verify_commit_id_matches_content()?;
        self.validate_event_binding(&full.event, suite)?;
        let genesis: crate::events_payloads::realm::RealmCreatePayload =
            serde_json::from_value(serde_json::to_value(&full.event.payload)?)?;
        if genesis.object.governance_station_id
            != arkret_wire::detached_signature_service_id(&full.commit.signature)?
        {
            return Err(invalid(
                "Org Genesis Commit signer differs from the governor selected by its signed Event",
            ));
        }

        if full.commit.stream_position != 0
            || full.commit.governance_generation != 0
            || full.commit.previous_commit_ref.is_some()
            || full.commit.producer_signer_fact_digest.as_ref() != Some(&self.digest()?)
        {
            return Err(invalid(
                "original Genesis Commit does not bind this exact Org source",
            ));
        }
        Ok(())
    }
}

/// Decode the closed typed source at the wire crate's raw dependency boundary.
/// This checks original bindings; callers still verify Org intent before trusting G.
pub fn organization_genesis_signer_fact(
    bundle: &RealmAuthorityBundle,
) -> Result<Option<OrganizationGenesisSignerFact>> {
    let candidate = matches!(
        GenesisGovernance::from_genesis(&bundle.genesis_event)?,
        GenesisGovernance::Organization
    );
    if !candidate {
        if bundle.producer_signer_fact.is_some() {
            return Err(invalid(
                "non-Org public bundle must omit its producer signer fact",
            ));
        }
        return Ok(None);
    }
    let value = bundle
        .producer_signer_fact
        .clone()
        .ok_or_else(|| invalid("Org public bundle lacks its original Genesis source"))?;
    let fact: OrganizationGenesisSignerFact = serde_json::from_value(value)?;
    let original = CommittedEventFullView {
        event: bundle.genesis_event.clone(),
        commit: bundle.genesis_commit.clone(),
    };
    fact.validate_commit_binding(
        &original,
        original.event.event_id.digest_suite_code().digest_suite(),
    )?;
    Ok(Some(fact))
}
