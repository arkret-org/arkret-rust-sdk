//! Account Authority controller-account gate wire models.
//!
//! The gate is the Account Authority's signed answer to one question: is the
//! controller principal behind an Agent key authorization still eligible? It is
//! privacy minimised on purpose. Portable evidence never publishes
//! service-local account identity, so the object exposes the controller
//! principal `did_core_id`, a closed eligibility, the six-valued account
//! status, the minimal binding/status digest selected by `basis.kind`, and a
//! validity window. A service-local `account_id`, a raw account typed current
//! result, or a caller-asserted "active" boolean are schema violations, not
//! optional members.
//!
//! This module holds the gate family only. The current-query face of signer
//! keys carries no portable evidence and no reusable current grant
//! (`signer-key-operations.schema.json`); that face lives in
//! [`crate::agent_signer_state`].

use arkret_wire::{
    Base64UrlString, DidCoreId, DidUrl, ErrorCode, Event, EventId, EventKind, Hash, NonEmptyString,
    RequestId, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Longest positive validity an Account Authority may put on a gate.
pub const CONTROLLER_ACCOUNT_GATE_MAX_VALIDITY_SECONDS: i64 = 300;

/// Detached signature envelope carried by an Account Authority attestation.
///
/// `jws` is excluded from the signing bytes; `kind` is covered like every other
/// closed member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentDetachedJws {
    pub kind: NonEmptyString,
    pub jws: NonEmptyString,
}

/// Which authority-owned projection `basis_digest` commits to.
///
/// `account_binding_default` means the authority's private binding carries no
/// stricter accepted status head yet. `account_status_event` binds a real
/// status Event and its checkpoint digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountGateBasis {
    AccountBindingDefault {
        binding_version: u64,
        binding_receipt_digest: Hash,
    },
    AccountStatusEvent {
        status_event_id: EventId,
        status_checkpoint_digest: Hash,
    },
}

/// Closed eligibility axis. It is the only decision a consumer acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountEligibility {
    Active,
    Inactive,
}

/// Six-valued controller account status.
///
/// [`ControllerAccountStatus::Active`] is the single status that maps to an
/// active eligibility; every other value is inactive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ControllerAccountStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl ControllerAccountStatus {
    /// The eligibility this status projects onto. `active` is eligible; the
    /// remaining five statuses are not.
    pub fn eligibility(self) -> ControllerAccountEligibility {
        match self {
            Self::Active => ControllerAccountEligibility::Active,
            Self::SoftLoggedOut
            | Self::Locked
            | Self::Suspended
            | Self::Deactivated
            | Self::ErasurePending => ControllerAccountEligibility::Inactive,
        }
    }
}

/// Account Authority-signed controller lifecycle gate.
///
/// Signed under `ak.controller_account_gate.v1`
/// ([`DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1`](arkret_wire::DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// Field declaration order is byte-for-byte the `binding_fields` order of the
// `"domain": "ak.controller_account_gate.v1"` /
// `"object_family": "controller_account_gate_attestation"` entry in
// `spec/v1/artifacts/registry/proof-context-registry.json`; `proof` follows as
// the detached signature over exactly those bound fields.
pub struct ControllerAccountGateAttestation {
    pub schema: NonEmptyString,
    pub principal_id: DidCoreId,
    pub eligibility: ControllerAccountEligibility,
    pub status: ControllerAccountStatus,
    pub basis: ControllerAccountGateBasis,
    pub basis_digest: Hash,
    pub authority_id: DidCoreId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: AgentDetachedJws,
}

impl ControllerAccountGateAttestation {
    /// Structural invariants an issuer must satisfy and a consumer must
    /// re-check before the detached proof is worth verifying.
    pub fn validate(&self) -> Result<()> {
        if self.status.eligibility() != self.eligibility {
            return Err(gate_error(
                ErrorCode::SchemaViolation,
                "controller gate eligibility is active exactly when status is active",
            ));
        }
        if self.issued_at >= self.expires_at {
            return Err(gate_error(
                ErrorCode::SchemaViolation,
                "controller gate must carry a positive validity window",
            ));
        }
        if (self.expires_at - self.issued_at).num_seconds()
            > CONTROLLER_ACCOUNT_GATE_MAX_VALIDITY_SECONDS
        {
            return Err(gate_error(
                ErrorCode::SchemaViolation,
                "controller gate validity must not exceed 300 seconds",
            ));
        }
        Ok(())
    }

    /// `true` while `now` lies inside the half-open validity window.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Canonical Account Authority signing bytes: the domain separation label,
    /// a newline, then the JCS bytes of this object with `proof.jws` removed.
    /// Every other closed member, `proof.kind` included, stays covered.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            gate_error(
                ErrorCode::SchemaViolation,
                &format!("controller gate is not serializable: {error}"),
            )
        })?;
        value
            .as_object_mut()
            .and_then(|object| object.get_mut("proof"))
            .and_then(Value::as_object_mut)
            .and_then(|proof| proof.remove("jws"))
            .ok_or_else(|| {
                gate_error(
                    ErrorCode::SchemaViolation,
                    "controller gate proof.jws is missing",
                )
            })?;
        let canonical = arkret_canonical::canonical::canonical_json_value_bytes(&value)?;
        let domain = arkret_wire::DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1;
        let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
        bytes.extend_from_slice(domain.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

/// Closed v1 Agent runtime signing-key profile. `Ed25519` is the fully
/// specified JOSE algorithm identifier; polymorphic identifiers are rejected.
// Field declaration order is byte-for-byte the properties order of
// agent-operations.schema.json#/$defs/agent_runtime_public_key, minus the
// `kid`, which the enclosing verification method already carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSigningPublicKey {
    pub kty: NonEmptyString,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
}

/// In-memory projection of the key authenticated by one complete
/// `ak.agent.key.authorize` Event.
///
/// This view is never a second wire certificate and never an authority source:
/// the caller separately verifies the Event's producer proof and the
/// authority-signed RealmCommit that covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorizedSigningKey {
    pub agent_id: DidCoreId,
    pub agent_key_id: NonEmptyString,
    pub verification_method: DidUrl,
    pub public_key: AgentSigningPublicKey,
    pub public_key_digest: Hash,
    pub agent_key_authorize_event_id: EventId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub controller_principal_id: DidCoreId,
}

impl AgentAuthorizedSigningKey {
    /// Parse the key material carried by an authorize Event. Event and
    /// RealmCommit authority are the caller's separate obligation.
    pub fn from_event(event: &Event) -> Result<Self> {
        let invalid = |reason: &str| WireError::Protocol(reason.to_owned());
        if event.kind != EventKind::AgentKeyAuthorize {
            return Err(invalid("Agent key source must be an authorize Event"));
        }
        let field = |name: &str| {
            event
                .payload
                .get(name)
                .cloned()
                .ok_or_else(|| invalid("authorize Event omits key material"))
        };
        let verification_method: DidUrl = serde_json::from_value(field("verification_method")?)?;
        let key = field("public_key")?;
        if key.get("kid").and_then(Value::as_str) != Some(verification_method.as_str())
            || key.get("kty").and_then(Value::as_str) != Some("OKP")
            || key.get("algorithm").and_then(Value::as_str) != Some("Ed25519")
            || key.as_object().is_none_or(|key| key.len() != 4)
        {
            return Err(invalid(
                "authorize Event has an invalid Ed25519 key profile",
            ));
        }
        let public_key = AgentSigningPublicKey {
            kty: serde_json::from_value(key["kty"].clone())?,
            algorithm: serde_json::from_value(key["algorithm"].clone())?,
            key: serde_json::from_value(key["key"].clone())?,
        };
        let raw = arkret_canonical::base64url_decode(public_key.key.as_str())?;
        if raw.len() != 32 || arkret_canonical::base64url_encode(&raw) != public_key.key.as_str() {
            return Err(invalid(
                "authorize Event key is not canonical Ed25519 material",
            ));
        }
        Ok(Self {
            agent_id: serde_json::from_value(field("agent_id")?)?,
            agent_key_id: serde_json::from_value(field("key_id")?)?,
            verification_method,
            public_key,
            public_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(&raw))?,
            agent_key_authorize_event_id: event.event_id.clone(),
            issued_at: serde_json::from_value(field("issued_at")?)?,
            expires_at: event
                .payload
                .get("expires_at")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            controller_principal_id: serde_json::from_value(field("accountable_principal_id")?)?,
        })
    }
}

/// Deployment-authenticated request an Agent Authority sends to obtain the
/// Account Authority-owned controller gate.
///
/// The body carries no service resolution carrier: caller identity comes from
/// the authenticated deployment relationship alone, never from a self-asserted
/// DID, URL, bearer or public key in this object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueRequestBody {
    pub request_id: RequestId,
    pub principal_id: DidCoreId,
    pub agent_authority_id: DidCoreId,
}

/// Byte-stable issuance result. A replay of the same `request_id` and canonical
/// intent returns these original bytes; a different intent is a
/// `duplicate_conflict` with zero issuance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ControllerAccountGateAttestationIssueOutcome {
    pub request_id: RequestId,
    pub controller_account_gate_attestation: ControllerAccountGateAttestation,
}

fn gate_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const BASIS_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn attestation_json() -> Value {
        serde_json::json!({
            "schema": "ak.schema.controller_account_gate_attestation.v1",
            "principal_id": "ak:did_core:web:controller.example",
            "eligibility": "active",
            "status": "active",
            "basis": {
                "kind": "account_binding_default",
                "binding_version": 7,
                "binding_receipt_digest": DIGEST
            },
            "basis_digest": BASIS_DIGEST,
            "authority_id": "ak:did_core:web:authority.example",
            "verification_method": "did:web:authority.example#account-authority",
            "issued_at": "2026-09-16T00:00:00.000Z",
            "expires_at": "2026-09-16T00:05:00.000Z",
            "proof": {
                "kind": "detached_jws",
                "jws": "eyJhbGciOiJFZERTQSJ9..signature"
            }
        })
    }

    fn attestation() -> ControllerAccountGateAttestation {
        serde_json::from_value(attestation_json()).unwrap()
    }

    #[test]
    fn controller_gate_round_trips_byte_for_byte() {
        let json = attestation_json();
        let gate: ControllerAccountGateAttestation = serde_json::from_value(json.clone()).unwrap();
        gate.validate().unwrap();
        assert_eq!(serde_json::to_value(&gate).unwrap(), json);
    }

    #[test]
    fn controller_gate_status_event_basis_round_trips() {
        let mut json = attestation_json();
        json["basis"] = serde_json::json!({
            "kind": "account_status_event",
            "status_event_id": "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "status_checkpoint_digest": DIGEST
        });
        let gate: ControllerAccountGateAttestation = serde_json::from_value(json.clone()).unwrap();
        gate.validate().unwrap();
        assert_eq!(serde_json::to_value(&gate).unwrap(), json);
    }

    #[test]
    fn controller_gate_rejects_unknown_member() {
        for extra in [
            "account_id",
            "account_current_result",
            "caller_asserted_active",
        ] {
            let mut json = attestation_json();
            json[extra] = serde_json::json!("x");
            serde_json::from_value::<ControllerAccountGateAttestation>(json)
                .expect_err("service-local account identity is a schema violation");
        }
        let mut json = attestation_json();
        json["basis"]["account_id"] = serde_json::json!("x");
        serde_json::from_value::<ControllerAccountGateAttestation>(json)
            .expect_err("basis is closed");
    }

    #[test]
    fn controller_gate_rejects_missing_required_member() {
        for required in [
            "schema",
            "principal_id",
            "eligibility",
            "status",
            "basis",
            "basis_digest",
            "authority_id",
            "verification_method",
            "issued_at",
            "expires_at",
            "proof",
        ] {
            let mut json = attestation_json();
            json.as_object_mut().unwrap().remove(required);
            serde_json::from_value::<ControllerAccountGateAttestation>(json)
                .expect_err("required member omission must be rejected");
        }
    }

    #[test]
    fn controller_gate_basis_kind_is_closed() {
        let mut json = attestation_json();
        json["basis"]["kind"] = serde_json::json!("account_status_head");
        serde_json::from_value::<ControllerAccountGateAttestation>(json)
            .expect_err("unknown basis kind must fail closed");
    }

    #[test]
    fn status_is_active_exactly_when_eligibility_is_active() {
        let statuses = [
            ControllerAccountStatus::Active,
            ControllerAccountStatus::SoftLoggedOut,
            ControllerAccountStatus::Locked,
            ControllerAccountStatus::Suspended,
            ControllerAccountStatus::Deactivated,
            ControllerAccountStatus::ErasurePending,
        ];
        for status in statuses {
            let active_status = status == ControllerAccountStatus::Active;
            let active_eligibility = status.eligibility() == ControllerAccountEligibility::Active;
            assert_eq!(active_status, active_eligibility);

            let mut gate = attestation();
            gate.status = status;
            gate.eligibility = status.eligibility();
            gate.validate().unwrap();

            let mut mismatched = attestation();
            mismatched.status = status;
            mismatched.eligibility = if active_eligibility {
                ControllerAccountEligibility::Inactive
            } else {
                ControllerAccountEligibility::Active
            };
            mismatched
                .validate()
                .expect_err("eligibility must track status exactly");
        }
    }

    #[test]
    fn controller_gate_validity_window_is_bounded() {
        let mut gate = attestation();
        gate.expires_at = gate.issued_at;
        gate.validate().expect_err("window must be positive");

        let mut gate = attestation();
        gate.expires_at = gate.issued_at + Duration::seconds(301);
        gate.validate().expect_err("window must not exceed 300s");

        let gate = attestation();
        assert!(gate.is_valid_at(gate.issued_at));
        assert!(!gate.is_valid_at(gate.expires_at));
    }

    #[test]
    fn signing_bytes_cover_every_field_except_the_signature() {
        let gate = attestation();
        let bytes = gate.signing_bytes().unwrap();
        let domain = arkret_wire::DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1;
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with(&format!("{domain}\n")));
        assert!(text.contains("\"kind\":\"detached_jws\""));
        assert!(!text.contains(gate.proof.jws.as_str()));

        let mut rotated = gate.clone();
        rotated.proof.jws = NonEmptyString::new("eyJhbGciOiJFZERTQSJ9..other".to_owned()).unwrap();
        assert_eq!(rotated.signing_bytes().unwrap(), bytes);

        let mut restated = gate;
        restated.status = ControllerAccountStatus::Locked;
        restated.eligibility = ControllerAccountEligibility::Inactive;
        assert_ne!(restated.signing_bytes().unwrap(), bytes);
    }

    #[test]
    fn issue_request_and_outcome_are_closed() {
        let request_json = serde_json::json!({
            "request_id": "ak:request:01970000-0000-7000-8000-000000000021",
            "principal_id": "ak:did_core:web:controller.example",
            "agent_authority_id": "ak:did_core:web:authority.example"
        });
        let request: ControllerAccountGateAttestationIssueRequestBody =
            serde_json::from_value(request_json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), request_json);

        let mut carrier = request_json.clone();
        carrier["source_service_id"] = serde_json::json!("did:web:caller.example");
        serde_json::from_value::<ControllerAccountGateAttestationIssueRequestBody>(carrier)
            .expect_err("no service resolution carrier may enter the request body");

        let outcome_json = serde_json::json!({
            "request_id": "ak:request:01970000-0000-7000-8000-000000000021",
            "controller_account_gate_attestation": attestation_json()
        });
        let outcome: ControllerAccountGateAttestationIssueOutcome =
            serde_json::from_value(outcome_json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&outcome).unwrap(), outcome_json);
    }
}
