//! Handle-claim wire models bridging the identity handle vocabulary and
//! the Realm delivery-binding pipeline.
//!
//! The canonical [`Handle`] scalar, localpart/domain validators, and the
//! handle-claim vocabulary enums live in `arkret-models-identity`.
//! [`HandleClaim`] and [`DeliveryBindingHint`] live here because they
//! embed the collaboration delivery-binding types
//! ([`RecipientServiceKind`], [`DeliveryMode`]).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{DidCoreId, PayloadProof, Result, SchemaId, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::delivery_binding::{DeliveryMode, RecipientServiceKind};
use crate::handle::{
    Handle, HandleBindingState, HandleClaimKind, HandleHintBindingSource, HandleVisibility,
    validate_handle_claim_subject,
};

/// Builder-side member delivery binding offered by a handle claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryBindingHint {
    pub recipient_id: DidCoreId,
    #[serde(default = "default_hint_recipient_kind")]
    pub recipient_kind: RecipientServiceKind,
    pub binding_source: HandleHintBindingSource,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub delivery_modes: BTreeSet<DeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<String>,
}

fn default_hint_recipient_kind() -> RecipientServiceKind {
    RecipientServiceKind::PrincipalServer
}

fn default_handle_claim_schema() -> String {
    SchemaId::HANDLE_CLAIM_V1.to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub subject_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vouching_id: Option<DidCoreId>,
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
    /// Claim creation timestamp. Required by `handle-claim.schema.json`
    /// (`required` list): a wire claim without `created_at` fails
    /// deserialization instead of being silently accepted.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
}

impl HandleClaim {
    pub const SCHEMA: &'static str = SchemaId::HANDLE_CLAIM_V1;
    /// Enforce schema `allOf` conditional required fields:
    ///   - `binding_state=verified` ⇒ `handle` + `expires_at`
    ///   - `member_delivery_binding` present ⇒ `handle` + `audience` + `expires_at`, and
    ///     binding_source != did_document_default (enforced by the [`HandleHintBindingSource`] type
    ///     itself).
    pub fn validate(&self) -> Result<()> {
        if matches!(self.binding_state, Some(HandleBindingState::Verified)) {
            if self.handle.is_none() {
                return Err(WireError::Protocol(
                    "binding_state=verified requires handle".to_owned(),
                ));
            }
            if self.expires_at.is_none() {
                return Err(WireError::Protocol(
                    "binding_state=verified requires expires_at".to_owned(),
                ));
            }
        }
        if self.member_delivery_binding.is_some()
            && (self.handle.is_none() || self.audience.is_none() || self.expires_at.is_none())
        {
            return Err(WireError::Protocol(
                "member_delivery_binding present requires handle, audience, expires_at".to_owned(),
            ));
        }
        if let Some(subject_id) = &self.subject_id {
            validate_handle_claim_subject(subject_id)?;
        }
        Ok(())
    }

    /// Validate a handle claim before it is consumed as a remote directory or
    /// Principal Server resolution result.
    pub fn validate_remote_resolution(
        &self,
        expected_audience: Option<&str>,
        expected_recipient_id: Option<&DidCoreId>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.validate()?;
        if self.schema != SchemaId::HANDLE_CLAIM_V1 {
            return Err(WireError::Protocol(
                "handle claim schema mismatch".to_owned(),
            ));
        }
        if self.handle.is_none() {
            return Err(WireError::Protocol(
                "handle claim requires handle".to_owned(),
            ));
        }
        if self.subject_id.is_none() {
            return Err(WireError::Protocol(
                "handle claim requires subject_id".to_owned(),
            ));
        }
        if self.issuer_id.is_none() {
            return Err(WireError::Protocol(
                "handle claim requires issuer_id".to_owned(),
            ));
        }
        if self.binding_state != Some(HandleBindingState::Verified) {
            return Err(WireError::Protocol(
                "handle claim must be verified".to_owned(),
            ));
        }
        let expires_at = self
            .expires_at
            .ok_or_else(|| WireError::Protocol("handle claim requires expires_at".to_owned()))?;
        if expires_at <= now {
            return Err(WireError::Protocol("handle claim expired".to_owned()));
        }
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "handle claim requires proof".to_owned(),
            ));
        }
        if let Some(expected_audience) = expected_audience {
            match self.audience.as_deref() {
                Some(audience) if audience == expected_audience => {}
                _ => {
                    return Err(WireError::Protocol(
                        "handle claim audience mismatch".to_owned(),
                    ));
                }
            }
        }
        if let Some(expected_recipient_id) = expected_recipient_id {
            match self.member_delivery_binding.as_ref() {
                Some(binding) if &binding.recipient_id == expected_recipient_id => {
                }
                Some(_) => {
                    return Err(WireError::Protocol(
                        "handle claim delivery binding mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(WireError::Protocol(
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
    use arkret_wire::{DidUrl, Hash};

    use super::*;

    /// Claim shell with every field written explicitly: `HandleClaim` has no
    /// `Default` impl because the schema-required `created_at` must come from
    /// a real constructor, not a fabricated placeholder.
    fn fixture_claim() -> HandleClaim {
        HandleClaim {
            schema: default_handle_claim_schema(),
            handle: None,
            handle_aliases: Vec::new(),
            subject_id: None,
            issuer_id: None,
            vouching_id: None,
            binding_state: None,
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: BTreeMap::new(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: Utc::now(),
            expires_at: None,
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }

    fn placeholder_payload_proof() -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer_id.example#key-1").unwrap(),
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
            ..fixture_claim()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn member_delivery_binding_requires_audience() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned())
                    .unwrap(),
                recipient_kind: RecipientServiceKind::PrincipalServer,
                binding_source: HandleHintBindingSource::Explicit,
                delivery_modes: BTreeSet::new(),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            expires_at: Some(Utc::now()),
            ..fixture_claim()
        };
        assert!(claim.validate().is_err());
    }

    #[test]
    fn handle_claim_serializes_current_wire_names_only() {
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject_id: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap()),
            issuer_id: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
            binding_state: Some(HandleBindingState::Verified),
            claim_kind: Some(HandleClaimKind::HandleBinding),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            proofs: vec![placeholder_payload_proof()],
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned())
                    .unwrap(),
                recipient_kind: RecipientServiceKind::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: Some(
                    "ak:event:ATYeQ_3uy7u8Z1cbK6nfFvEpFMXMcbNvQJsXqt-4f03A".to_owned(),
                ),
                policy_event_ref: Some(
                    "ak:event:Afza12DxrQRj8YMTUh0SADCCuAoyT3X9PH_MYKQ12khk".to_owned(),
                ),
            }),
            ..fixture_claim()
        };

        let value = serde_json::to_value(&claim).unwrap();
        assert_eq!(value["claim_kind"], "handle_binding");
        assert!(value.get("class").is_none());
        assert!(value.get("claim_type").is_none());
        assert!(value.get("issued_at").is_none());
        assert!(value["created_at"].is_string());
        assert_eq!(
            value["member_delivery_binding"]["policy_event_ref"],
            "ak:event:Afza12DxrQRj8YMTUh0SADCCuAoyT3X9PH_MYKQ12khk"
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
            "subject_id": "ak:did_core:webvh:z6mkfixture",
            "issuer_id": "ak:did_core:webvh:z6mkfixture",
            "binding_state": "pending",
            "created_at": "2026-07-15T00:00:00.000Z",
            "x_directory_cache_hint": {"served_at": "2026-07-15T00:00:00.000Z"},
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
    fn handle_claim_deserialization_rejects_missing_created_at() {
        // `created_at` is in the `handle-claim.schema.json` `required` list:
        // a wire claim omitting it MUST fail deserialization instead of being
        // silently accepted as a default.
        let wire = serde_json::json!({
            "schema": "ak.schema.handle_claim.v1",
            "handle": "alice:example.com",
            "subject_id": "ak:did_core:webvh:z6mkfixture",
            "issuer_id": "ak:did_core:webvh:z6mkfixture",
            "binding_state": "pending"
        });
        let err = serde_json::from_value::<HandleClaim>(wire)
            .expect_err("claim without required created_at must be rejected");
        assert!(
            err.to_string().contains("created_at"),
            "error should name the missing field: {err}"
        );
    }

    #[test]
    fn remote_resolution_requires_proof_audience_and_delivery_binding() {
        let audience = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let recipient = DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:example.com").unwrap()),
            subject_id: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap()),
            issuer_id: Some(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
            binding_state: Some(HandleBindingState::Verified),
            audience: Some(audience.to_owned()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            member_delivery_binding: Some(DeliveryBindingHint {
                recipient_id: recipient.clone(),
                recipient_kind: RecipientServiceKind::PrincipalServer,
                binding_source: HandleHintBindingSource::OrganizationPolicy,
                delivery_modes: BTreeSet::from([DeliveryMode::Events]),
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            proofs: vec![placeholder_payload_proof()],
            ..fixture_claim()
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
