//! Handle-claim wire models bridging the identity handle vocabulary and
//! the Realm delivery-binding pipeline.
//!
//! The canonical [`Handle`] scalar, localpart/domain validators, and the
//! handle-claim vocabulary enums live in `arkret-models-identity`.
//! [`HandleClaim`] and [`DeliveryBindingHint`] live here because they
//! embed the collaboration delivery-binding types
//! ([`RecipientServiceType`], [`DeliveryMode`]).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{Did, Error, PayloadProof, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::delivery_binding::{DeliveryMode, RecipientServiceType};
use crate::handle::{
    HANDLE_CLAIM_SCHEMA, Handle, HandleBindingState, HandleClaimKind, HandleHintBindingSource,
    HandleVisibility, validate_handle_claim_subject,
};

/// Builder-side member delivery binding offered by a handle claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct DeliveryBindingHint {
    pub recipient_service_id: Did,
    #[serde(default = "default_hint_recipient_service_type")]
    pub recipient_service_type: RecipientServiceType,
    pub binding_source: HandleHintBindingSource,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub delivery_modes: BTreeSet<DeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<String>,
}

fn default_hint_recipient_service_type() -> RecipientServiceType {
    RecipientServiceType::PrincipalServer
}

fn default_handle_claim_schema() -> String {
    HANDLE_CLAIM_SCHEMA.to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct HandleClaim {
    #[serde(default = "default_handle_claim_schema")]
    pub schema: String,
    /// Canonical handle `<localpart>:<domain>`. R3.1 wire rename from
    /// the prior `handle_uri` field name (arkret-spec @ 7157ee8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_state: Option<HandleBindingState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_kind: Option<HandleClaimKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<HandleVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<DeliveryBindingHint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl Default for HandleClaim {
    fn default() -> Self {
        Self {
            schema: default_handle_claim_schema(),
            handle: None,
            handle_aliases: Vec::new(),
            subject: None,
            issuer: None,
            issuer_service_id: None,
            binding_state: None,
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: BTreeMap::new(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: None,
            expires_at: None,
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }
}

impl HandleClaim {
    /// Enforce schema `allOf` conditional required fields:
    ///   - `binding_state=verified` ⇒ `handle` + `expires_at`
    ///   - `member_delivery_binding` present ⇒ `handle` + `audience` + `expires_at`, and
    ///     binding_source != did_document_default (enforced by the [`HandleHintBindingSource`] type
    ///     itself).
    pub fn validate(&self) -> Result<()> {
        if matches!(self.binding_state, Some(HandleBindingState::Verified)) {
            if self.handle.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires handle".to_owned(),
                ));
            }
            if self.expires_at.is_none() {
                return Err(Error::Protocol(
                    "binding_state=verified requires expires_at".to_owned(),
                ));
            }
        }
        if self.member_delivery_binding.is_some()
            && (self.handle.is_none() || self.audience.is_none() || self.expires_at.is_none())
        {
            return Err(Error::Protocol(
                "member_delivery_binding present requires handle, audience, expires_at".to_owned(),
            ));
        }
        if let Some(subject) = &self.subject {
            validate_handle_claim_subject(subject)?;
        }
        Ok(())
    }

    /// Validate a handle claim before it is consumed as a remote directory or
    /// Principal Server resolution result.
    pub fn validate_remote_resolution(
        &self,
        expected_audience: Option<&str>,
        expected_recipient_service_id: Option<&Did>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if self.schema != HANDLE_CLAIM_SCHEMA {
            return Err(Error::Protocol("handle claim schema mismatch".to_owned()));
        }
        if self.handle.is_none() {
            return Err(Error::Protocol("handle claim requires handle".to_owned()));
        }
        if self.subject.is_none() {
            return Err(Error::Protocol("handle claim requires subject".to_owned()));
        }
        if self.issuer.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Protocol("handle claim requires issuer".to_owned()));
        }
        if self.binding_state != Some(HandleBindingState::Verified) {
            return Err(Error::Protocol("handle claim must be verified".to_owned()));
        }
        let expires_at = self
            .expires_at
            .ok_or_else(|| Error::Protocol("handle claim requires expires_at".to_owned()))?;
        if expires_at <= now {
            return Err(Error::Protocol("handle claim expired".to_owned()));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol("handle claim requires proof".to_owned()));
        }
        if let Some(expected_audience) = expected_audience {
            match self.audience.as_deref() {
                Some(audience) if audience == expected_audience => {}
                _ => {
                    return Err(Error::Protocol("handle claim audience mismatch".to_owned()));
                }
            }
        }
        if let Some(expected_recipient_service_id) = expected_recipient_service_id {
            match self.member_delivery_binding.as_ref() {
                Some(binding) if &binding.recipient_service_id == expected_recipient_service_id => {
                }
                Some(_) => {
                    return Err(Error::Protocol(
                        "handle claim delivery binding mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(Error::Protocol(
                        "handle claim requires member_delivery_binding".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Canonical handle wire form, if any. R3.1 helper exported so
    /// soland / inkson / cotest all agree on the bytes used for
    /// signature / digest transcripts.
    pub fn handle_canonical(&self) -> Option<&str> {
        self.handle.as_ref().map(Handle::canonical)
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::Hash;

    use super::*;

    fn placeholder_payload_proof() -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:issuer.example#key-1".to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "placeholder".to_owned(),
        }
    }

    #[test]
    fn verified_requires_handle_and_expires() {
        let claim = HandleClaim {
            binding_state: Some(HandleBindingState::Verified),
            ..Default::default()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn member_delivery_binding_requires_audience() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_id: Did::new("did:webvh:z6mkfixture:rs.example".to_owned())
                    .unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: BTreeSet::new(),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            expires_at: Some(Utc::now()),
            ..Default::default()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn handle_claim_serializes_current_wire_names_only() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject: Some(Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()),
            issuer: Some("did:webvh:z6mkfixture:issuer.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            claim_kind: Some(HandleClaimKind::HandleBinding),
            created_at: Some(Utc::now()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            proofs: vec![placeholder_payload_proof()],
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_id: Did::new("did:webvh:z6mkfixture:rs.example".to_owned())
                    .unwrap(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: Some(
                    "ak:event:01890000-0000-7000-8000-000000000001".to_owned(),
                ),
                policy_event_ref: Some("ak:event:01890000-0000-7000-8000-000000000002".to_owned()),
            }),
            ..Default::default()
        };

        let value = serde_json::to_value(&claim).unwrap();
        assert_eq!(value["claim_kind"], "handle_binding");
        assert!(value.get("class").is_none());
        assert!(value.get("claim_type").is_none());
        assert!(value.get("issued_at").is_none());
        assert!(value["created_at"].is_string());
        assert_eq!(
            value["member_delivery_binding"]["policy_event_ref"],
            "ak:event:01890000-0000-7000-8000-000000000002"
        );
        assert!(value["member_delivery_binding"].get("policy_ref").is_none());
    }

    #[test]
    fn handle_claim_accepts_and_drops_unknown_wire_fields() {
        // `handle-claim.schema.json` root is `unevaluatedProperties: true`: the
        // open channel carries server-attested hints / cache metadata that are
        // excluded from the signed `semantic_projection` digest. The wire type
        // must accept such extras (no `deny_unknown_fields`) and drop them.
        let wire = serde_json::json!({
            "schema": "ak.schema.handle_claim.v1",
            "handle": "alice:example.com",
            "subject": "did:webvh:z6mkfixture:alice.example",
            "issuer": "did:webvh:z6mkfixture:issuer.example",
            "binding_state": "pending",
            "x_directory_cache_hint": {"served_at": "2026-07-15T00:00:00Z"},
            "server_attested_freshness": 42
        });
        let claim: HandleClaim =
            serde_json::from_value(wire).expect("open handle claim must not reject unknown fields");
        let reserialized = serde_json::to_value(&claim).unwrap();
        assert!(reserialized.get("x_directory_cache_hint").is_none());
        assert!(reserialized.get("server_attested_freshness").is_none());
        assert_eq!(reserialized["handle"], "alice:example.com");
    }

    #[test]
    fn remote_resolution_requires_proof_audience_and_delivery_binding() {
        let audience = "ak:realm:01904100-0000-7000-8000-000000000001";
        let recipient = Did::new("did:webvh:z6mkfixture:rs.example".to_owned()).unwrap();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject: Some(Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap()),
            issuer: Some("did:webvh:z6mkfixture:issuer.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            audience: Some(audience.to_owned()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_service_id: recipient.clone(),
                recipient_service_type: RecipientServiceType::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            proofs: vec![placeholder_payload_proof()],
            ..Default::default()
        };

        assert!(
            claim
                .validate_remote_resolution(Some(audience), Some(&recipient), Utc::now())
                .is_ok()
        );
        assert!(
            claim
                .validate_remote_resolution(
                    Some("did:webvh:z6mkfixture:other.example"),
                    Some(&recipient),
                    Utc::now(),
                )
                .is_err()
        );
        let mut unsigned = claim;
        unsigned.proofs.clear();
        assert!(
            unsigned
                .validate_remote_resolution(Some(audience), Some(&recipient), Utc::now())
                .is_err()
        );
    }
}
