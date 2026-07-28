//! Bounded offline publication: [`AuthorizationLease`] and [`IngressReceipt`].
//!
//! `zh/authz/offline-publication.md`. Neither object is an Event field and
//! neither enters the Event digest: they are independently verified
//! publication evidence carried by the submit wrappers in
//! [`crate::event_submission`].
//!
//! The revocation boundary comes from the basis-bound lease plus a signed
//! ingress receipt. An Event's `created_at` — and the verifier's own local
//! first-sight time — carry no such authority, so backdating cannot buy an
//! expired lease more time.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cba::SealBasis;
use crate::error::{Error, Result};
use crate::event_envelope::ScopeRef;
use crate::generated::ProofContextId;
use crate::primitives::{Audience, PayloadProof};
use crate::{AuthorizationLeaseId, DeviceId, Did, Hash, ReceiptId, SealId, canonical};

/// Maximum number of issuer proofs on a lease or receipt
/// (`offline-publication.schema.json`).
pub const MAX_PUBLICATION_PROOFS: usize = 32;

/// Protocol ceiling on `expires_at - issued_at` per risk tier
/// (`offline-publication.md` §1). Realm policy MAY tighten, never widen.
pub const LEASE_MAX_TTL_LOW: Duration = Duration::hours(24);
pub const LEASE_MAX_TTL_MEDIUM: Duration = Duration::hours(8);
pub const LEASE_MAX_TTL_HIGH: Duration = Duration::hours(1);

/// Risk tier of the leased action. An unregistered action is treated as
/// [`RiskTier::High`] by the caller before a lease is minted or checked.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    /// Protocol maximum lease lifetime for this tier.
    pub fn max_lease_ttl(self) -> Duration {
        match self {
            Self::Low => LEASE_MAX_TTL_LOW,
            Self::Medium => LEASE_MAX_TTL_MEDIUM,
            Self::High => LEASE_MAX_TTL_HIGH,
        }
    }
}

/// Immutable reference to the CBA authority-set policy resolved at `basis_ref`.
///
/// `authority_set_digest` binds the canonical policy bytes, so a later mutation
/// of a registry entry cannot silently change which issuers a lease or receipt
/// was checked against.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetRef {
    pub authority_set_id: String,
    pub authority_set_digest: Hash,
}

/// Accepted authorization basis a lease narrows.
///
/// Single-chain finality profiles cite one accepted Seal; `open_set` MUST
/// carry the complete signed multi-leaf basis, because no single leaf can
/// stand in for the joined view.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LeaseBasisRef {
    Seal(SealId),
    Joined(SealBasis),
}

/// Basis-bound, expiring permission to publish one action offline.
///
/// A lease only narrows authorization that the accepted basis already grants:
/// it cannot mint a capability, cannot downgrade a medium/high action to low,
/// and cannot be replayed into another scope.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLease {
    pub authorization_lease_id: AuthorizationLeaseId,
    pub basis_ref: LeaseBasisRef,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub scope_ref: ScopeRef,
    pub action: String,
    pub risk_tier: RiskTier,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authority_set_ref: AuthoritySetRef,
    pub proofs: Vec<PayloadProof>,
}

/// Signed proof that a policy-accepted ingress received one Event digest
/// while its lease was still valid.
///
/// A receipt proves arrival, nothing more: it does not assert that the Event
/// passed the reducer, entered a data projection, was seen by a peer, or
/// reached Seal finality.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressReceipt {
    pub receipt_id: ReceiptId,
    pub event_digest: Hash,
    pub authorization_lease_id: AuthorizationLeaseId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub service_id: Did,
    pub authority_set_ref: AuthoritySetRef,
    pub proofs: Vec<PayloadProof>,
}

fn digest_without_proofs<T: Serialize>(value: &T) -> Result<Hash> {
    let mut json = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut json {
        map.remove("proofs");
    }
    Ok(Hash::new(canonical::canonical_sha256(&json)?)?)
}

/// Canonical bytes each issuer signs for a lease or receipt.
///
/// `payload_digest` is the object's digest with `proofs` removed, so an issuer
/// proof commits to every other member. The fixed `context` keeps a lease proof
/// from being replayed as a receipt proof or as an Event proof.
fn publication_binding_bytes(
    context: &str,
    payload_digest: &Hash,
    authority_set_ref: &AuthoritySetRef,
    verification_method: &str,
    created_at: DateTime<Utc>,
    domain: Option<&str>,
    audience: Option<&Audience>,
) -> Result<Vec<u8>> {
    let mut object = serde_json::Map::new();
    object.insert("context".to_owned(), Value::String(context.to_owned()));
    object.insert(
        "payload_digest".to_owned(),
        Value::String(payload_digest.as_str().to_owned()),
    );
    object.insert(
        "authority_set_ref".to_owned(),
        serde_json::to_value(authority_set_ref)?,
    );
    object.insert(
        "verification_method".to_owned(),
        Value::String(verification_method.to_owned()),
    );
    object.insert(
        "created_at".to_owned(),
        Value::String(canonical::format_timestamp_canonical(created_at)),
    );
    if let Some(domain) = domain {
        object.insert("domain".to_owned(), Value::String(domain.to_owned()));
    }
    if let Some(audience) = audience {
        object.insert("audience".to_owned(), serde_json::to_value(audience)?);
    }
    Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
}

fn validate_proof_set(proofs: &[PayloadProof], expected_digest: &Hash) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_PUBLICATION_PROOFS {
        return Err(Error::Protocol(format!(
            "publication evidence requires 1..={MAX_PUBLICATION_PROOFS} proofs"
        )));
    }
    for proof in proofs {
        proof.validate()?;
        if proof.payload_digest != *expected_digest {
            return Err(Error::Protocol(
                "publication proof does not cover the object's canonical digest".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Count distinct issuer verification methods.
///
/// Signature array length is not a quorum: a duplicated verification method
/// counts once (`offline-publication.md` §1 / §2).
pub fn distinct_issuer_count(proofs: &[PayloadProof]) -> usize {
    proofs
        .iter()
        .map(|proof| proof.verification_method.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

impl AuthorizationLease {
    /// `sha256(canonical_json(lease_without_proofs))`.
    pub fn lease_digest(&self) -> Result<Hash> {
        digest_without_proofs(self)
    }

    /// Canonical bytes the issuer identified by `proof` must sign.
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        publication_binding_bytes(
            ProofContextId::AUTHORIZATION_LEASE_PROOF_V1,
            &self.lease_digest()?,
            &self.authority_set_ref,
            &proof.verification_method,
            proof.created_at,
            proof.domain.as_deref(),
            proof.audience.as_ref(),
        )
    }

    /// Structural validation independent of Realm issuer policy.
    ///
    /// Checks the protocol TTL ceiling, the proof-to-digest binding and the
    /// `created_at == issued_at` rule. Whether the proof set satisfies
    /// the basis-declared issuer quorum is a policy decision the caller makes
    /// with [`distinct_issuer_count`] and the accepted basis.
    pub fn validate_structural(&self) -> Result<()> {
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "lease expires_at must be strictly after issued_at".to_owned(),
            ));
        }
        let ttl = self.expires_at - self.issued_at;
        let ceiling = self.risk_tier.max_lease_ttl();
        if ttl > ceiling {
            return Err(Error::Protocol(format!(
                "lease TTL {} exceeds the {:?} risk-tier ceiling of {} minutes",
                ttl.num_minutes(),
                self.risk_tier,
                ceiling.num_minutes()
            )));
        }
        let digest = self.lease_digest()?;
        validate_proof_set(&self.proofs, &digest)?;
        for proof in &self.proofs {
            if proof.created_at != self.issued_at {
                return Err(Error::Protocol(
                    "lease proof created_at must equal issued_at".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Whether this lease still authorizes a first publication at `instant`.
    pub fn covers_instant(&self, instant: DateTime<Utc>) -> bool {
        self.issued_at <= instant && instant <= self.expires_at
    }
}

impl IngressReceipt {
    /// `sha256(canonical_json(receipt_without_proofs))`.
    pub fn receipt_digest(&self) -> Result<Hash> {
        digest_without_proofs(self)
    }

    /// Canonical bytes the ingress identified by `proof` must sign.
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        publication_binding_bytes(
            ProofContextId::INGRESS_RECEIPT_PROOF_V1,
            &self.receipt_digest()?,
            &self.authority_set_ref,
            &proof.verification_method,
            proof.created_at,
            proof.domain.as_deref(),
            proof.audience.as_ref(),
        )
    }

    /// Structural validation independent of Realm issuer policy.
    pub fn validate_structural(&self) -> Result<()> {
        let digest = self.receipt_digest()?;
        validate_proof_set(&self.proofs, &digest)?;
        for proof in &self.proofs {
            if proof.created_at != self.received_at {
                return Err(Error::Protocol(
                    "ingress receipt proof created_at must equal received_at".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Bind this receipt to the lease and Event digest it claims to cover.
    ///
    /// `issued_at <= received_at <= expires_at` is the revocation boundary: a
    /// receipt minted outside the lease window proves nothing, and a service
    /// MUST NOT re-sign an idempotent retry with a later `received_at` to
    /// extend a window that is already fixed.
    pub fn validate_against_lease(
        &self,
        lease: &AuthorizationLease,
        event_digest: &Hash,
    ) -> Result<()> {
        if self.authorization_lease_id != lease.authorization_lease_id {
            return Err(Error::Protocol(
                "ingress receipt authorization_lease_id does not match the submitted lease"
                    .to_owned(),
            ));
        }
        if self.event_digest != *event_digest {
            return Err(Error::Protocol(
                "ingress receipt event_digest does not match the submitted Event".to_owned(),
            ));
        }
        if !lease.covers_instant(self.received_at) {
            return Err(Error::Protocol(
                "ingress receipt received_at is outside the lease validity window".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::primitives::proof_kind;

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: crate::RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap(),
        }
    }

    fn authority_set(id: &str) -> AuthoritySetRef {
        AuthoritySetRef {
            authority_set_id: id.to_owned(),
            authority_set_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
        }
    }

    fn instant(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, 0, 0).unwrap()
    }

    fn lease_with(risk_tier: RiskTier, expires_at: DateTime<Utc>) -> AuthorizationLease {
        let mut lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: actor(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            scope_ref: scope(),
            action: "ak.message.create".to_owned(),
            risk_tier,
            issued_at: instant(0),
            expires_at,
            authority_set_ref: authority_set("ak.authority_set.realm_admission.v1"),
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:authority.example#key-1".to_owned(),
            payload_digest: digest,
            created_at: lease.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        lease
    }

    fn receipt_for(lease: &AuthorizationLease, received_at: DateTime<Utc>) -> IngressReceipt {
        let mut receipt = IngressReceipt {
            receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            authorization_lease_id: lease.authorization_lease_id.clone(),
            received_at,
            service_id: Did::new("did:webvh:z6mkfixture:ingress.example").unwrap(),
            authority_set_ref: authority_set("ak.authority_set.realm_ingress.v1"),
            proofs: Vec::new(),
        };
        let digest = receipt.receipt_digest().unwrap();
        receipt.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:ingress.example#key-1".to_owned(),
            payload_digest: digest,
            created_at: received_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        receipt
    }

    #[test]
    fn lease_digest_excludes_proofs_but_covers_every_other_member() {
        let lease = lease_with(RiskTier::Medium, instant(8));
        let baseline = lease.lease_digest().unwrap();

        let mut resigned = lease.clone();
        resigned.proofs[0].jws = "z..z".to_owned();
        assert_eq!(baseline, resigned.lease_digest().unwrap());

        let mut rescoped = lease;
        rescoped.action = "ak.member.state".to_owned();
        assert_ne!(baseline, rescoped.lease_digest().unwrap());
    }

    #[test]
    fn lease_ttl_ceiling_is_enforced_per_risk_tier() {
        lease_with(RiskTier::Medium, instant(8))
            .validate_structural()
            .expect("8h medium lease is at the ceiling");
        let err = lease_with(RiskTier::Medium, instant(9))
            .validate_structural()
            .unwrap_err();
        assert!(err.to_string().contains("risk-tier ceiling"), "{err}");
        let err = lease_with(RiskTier::High, instant(2))
            .validate_structural()
            .unwrap_err();
        assert!(err.to_string().contains("risk-tier ceiling"), "{err}");
    }

    #[test]
    fn lease_proof_created_at_must_equal_issued_at() {
        let mut lease = lease_with(RiskTier::Low, instant(12));
        lease.proofs[0].created_at = instant(1);
        let err = lease.validate_structural().unwrap_err();
        assert!(err.to_string().contains("created_at"), "{err}");
    }

    #[test]
    fn duplicate_verification_method_does_not_inflate_the_issuer_count() {
        let mut lease = lease_with(RiskTier::Low, instant(12));
        let duplicate = lease.proofs[0].clone();
        lease.proofs.push(duplicate);
        assert_eq!(lease.proofs.len(), 2);
        assert_eq!(distinct_issuer_count(&lease.proofs), 1);
    }

    #[test]
    fn receipt_outside_the_lease_window_is_rejected() {
        let lease = lease_with(RiskTier::Medium, instant(8));
        let digest = Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap();

        let inside = receipt_for(&lease, instant(7));
        inside.validate_structural().unwrap();
        inside.validate_against_lease(&lease, &digest).unwrap();

        // A backdated Event cannot buy an expired lease more time: only the
        // signed `received_at` decides, and it must fall inside the window.
        let after_expiry = receipt_for(&lease, instant(9));
        let err = after_expiry
            .validate_against_lease(&lease, &digest)
            .unwrap_err();
        assert!(err.to_string().contains("validity window"), "{err}");
    }

    #[test]
    fn lease_and_receipt_bindings_use_distinct_contexts() {
        let lease = lease_with(RiskTier::Low, instant(12));
        let receipt = receipt_for(&lease, instant(1));
        let lease_bytes = lease.proof_binding_bytes(&lease.proofs[0]).unwrap();
        let receipt_bytes = receipt.proof_binding_bytes(&receipt.proofs[0]).unwrap();

        assert!(
            String::from_utf8(lease_bytes)
                .unwrap()
                .contains("ak.authorization-lease-proof-v1")
        );
        assert!(
            String::from_utf8(receipt_bytes)
                .unwrap()
                .contains("ak.ingress-receipt-proof-v1")
        );
    }
}
