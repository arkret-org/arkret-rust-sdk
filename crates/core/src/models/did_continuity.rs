//! DID continuity proof payloads.

use super::*;
use crate::ERROR_CODE_SCHEMA_VIOLATION;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DidContinuityPurpose {
    PrincipalMethodUpgrade,
    PrincipalMigration,
    AccountBindingContinuity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DidContinuityOobConfirmationMethod {
    OfflinePaper,
    PhysicalMeet,
    IndependentChannel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub enum DidContinuitySignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuityTransferEvidence {
    pub old_did_document_canonical_digest: Hash,
    pub old_did_document_fetched_at: DateTime<Utc>,
    pub inception_public_key_fingerprint: Hash,
    pub user_oob_confirmation_id: String,
    pub user_oob_confirmation_method: DidContinuityOobConfirmationMethod,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuitySignatureLink {
    pub principal_id: Did,
    pub verification_method: String,
    pub algorithm: DidContinuitySignatureAlgorithm,
    pub payload_digest: Hash,
    pub signature: String,
}

/// `ck.schema.did_continuity_proof.v1` payload profile for DID method upgrades
/// and account-binding continuity claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidContinuityProof {
    pub schema: String,
    pub old_did: Did,
    pub new_did: Did,
    pub purpose: DidContinuityPurpose,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_did_document_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_did_document_digest: Option<Hash>,
    pub transfer_evidence: DidContinuityTransferEvidence,
    pub signature_chain: Vec<DidContinuitySignatureLink>,
}

impl DidContinuityProof {
    pub const SCHEMA: &'static str = "ck.schema.did_continuity_proof.v1";
    pub const DIGEST_PREFIX: &'static [u8] = b"ck-did-continuity-proof-v1\n";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "DID continuity proof schema must be {} ({ERROR_CODE_SCHEMA_VIOLATION})",
                Self::SCHEMA
            )));
        }
        if self.signature_chain.len() < 2 {
            return Err(Error::Protocol(format!(
                "DID continuity proof requires at least two signature_chain links \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.old_did == self.new_did {
            return Err(Error::Protocol(format!(
                "DID continuity proof old_did and new_did must differ \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.purpose == DidContinuityPurpose::PrincipalMethodUpgrade
            && (!self.old_did.as_str().starts_with("did:web:")
                || !self.new_did.as_str().starts_with("did:webvh:"))
        {
            return Err(Error::Protocol(format!(
                "principal_method_upgrade requires old_did did:web and new_did did:webvh \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if let Some(expires_at) = self.expires_at
            && expires_at <= self.issued_at
        {
            return Err(Error::Protocol(format!(
                "DID continuity proof expires_at must be after issued_at \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        let mut seen_audience = BTreeSet::new();
        for audience in &self.audience {
            if audience.trim().is_empty() || !seen_audience.insert(audience) {
                return Err(Error::Protocol(format!(
                    "DID continuity proof audience entries must be non-empty and unique \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
        }
        if self
            .transfer_evidence
            .user_oob_confirmation_id
            .trim()
            .is_empty()
        {
            return Err(Error::Protocol(format!(
                "DID continuity proof user_oob_confirmation_id is required \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        let expected_digest = self.signature_payload_digest()?;
        let mut has_old_link = false;
        let mut has_new_link = false;
        for link in &self.signature_chain {
            if !link.verification_method.starts_with("did:")
                || !link.verification_method.contains('#')
            {
                return Err(Error::Protocol(format!(
                    "DID continuity proof verification_method must be a DID URL with fragment \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
            if link.signature.trim().is_empty()
                || link
                    .signature
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            {
                return Err(Error::Protocol(format!(
                    "DID continuity proof signature must be base64url-like \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
            let method_principal = link
                .verification_method
                .split('#')
                .next()
                .unwrap_or_default();
            if method_principal != link.principal_id.as_str() {
                return Err(Error::Protocol(format!(
                    "DID continuity proof signature link principal_id must match verification_method DID \
                     ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
            if link.payload_digest.as_str() != expected_digest.as_str() {
                return Err(Error::Protocol(format!(
                    "DID continuity proof payload_digest {} does not match canonical proof digest {} \
                     ({ERROR_CODE_SCHEMA_VIOLATION})",
                    link.payload_digest, expected_digest
                )));
            }
            has_old_link |= link.principal_id == self.old_did;
            has_new_link |= link.principal_id == self.new_did;
        }
        if !has_old_link || !has_new_link {
            return Err(Error::Protocol(format!(
                "DID continuity proof signature_chain must include old_did and new_did links \
                 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        Ok(())
    }

    pub fn signature_payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        if let Some(chain) = value
            .get_mut("signature_chain")
            .and_then(Value::as_array_mut)
        {
            for link in chain {
                if let Some(object) = link.as_object_mut() {
                    object.remove("payload_digest");
                    object.remove("signature");
                }
            }
        }
        let canonical = canonical::canonical_json_bytes(&value)?;
        let mut transcript = Vec::with_capacity(Self::DIGEST_PREFIX.len() + canonical.len());
        transcript.extend_from_slice(Self::DIGEST_PREFIX);
        transcript.extend_from_slice(&canonical);
        Ok(Hash::new(canonical::sha256_digest(transcript))?)
    }
}

/// SEC-04 — the **protocol hard cap** on how long an inception key may remain
/// online after bootstrap, per `identity/key-management.md` §5.0.1 step 5.
///
/// 24h is a non-configurable ceiling: deployment policy MAY declare a *shorter*
/// `inception_key_max_online_window`, but a self-reported *longer* window MUST
/// NOT be honoured by the receiver. The recommended operational window is ≤1h;
/// this constant only encodes the absolute hard limit the receiver enforces
/// independently against its local clock.
///
/// Stored as whole seconds (matching the `*_SECS` / `*_MS` numeric-ceiling
/// convention used elsewhere in this crate, e.g. `MEDIA_TOKEN_TTL_MAX_SECS`)
/// because `chrono::Duration::hours` is not a `const fn`. Use
/// [`inception_key_max_online_window`] for the [`chrono::Duration`] form.
pub const INCEPTION_KEY_MAX_ONLINE_WINDOW_SECS: i64 = 24 * 60 * 60;

/// SEC-04 — [`INCEPTION_KEY_MAX_ONLINE_WINDOW_SECS`] as a [`chrono::Duration`].
pub fn inception_key_max_online_window() -> chrono::Duration {
    chrono::Duration::seconds(INCEPTION_KEY_MAX_ONLINE_WINDOW_SECS)
}

/// SEC-04 — receiver-side independent age check for an inception key, per
/// `identity/key-management.md` §5.0.1 step 5 (receiver independently enforces).
///
/// The receiver / Auth Server seals on the verifiable bootstrap timestamp
/// (`did:webvh` entry-0 / continuity proof) and computes the inception key age
/// against its **own local clock** (`now`), exactly like the §5.0.5
/// evidence-age comparison — an RFC3339 wall-clock subtraction with no added
/// skew tolerance (24h dwarfs ordinary clock skew). Returns `true` when the age
/// exceeds the [`INCEPTION_KEY_MAX_ONLINE_WINDOW`] hard cap, in which case the
/// caller MUST reject the `ck.device.authorize` / `ck.session.grant` /
/// long-lived capability / ordinary DID update signed by that inception key and
/// assign reason [`crate::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`], regardless of
/// any longer window the deployment self-reports. The cap is
/// [`inception_key_max_online_window`] (24h).
///
/// **Conservative-reject convention for missing / unparseable evidence:** this
/// helper takes an already-parsed [`DateTime<Utc>`]. When the caller cannot
/// parse or is missing the bootstrap timestamp, it MUST treat the inception key
/// as window-exceeded (fail closed) — i.e. behave as if this function returned
/// `true` — rather than admitting the key. Do not substitute `now` or a default
/// timestamp to "pass" the check.
///
/// A `bootstrap_ts` in the future (negative age, e.g. seal clock ahead of the
/// receiver) is *not* treated as exceeded by this function; such anomalies are
/// a separate validity concern for the caller and are intentionally left to the
/// bootstrap-evidence validator rather than conflated with the age cap.
pub fn inception_key_age_exceeded(bootstrap_ts: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(bootstrap_ts) > inception_key_max_online_window()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(value: &str) -> Hash {
        Hash::new(format!("sha256:{value:0<64}")).unwrap()
    }

    fn fixture() -> DidContinuityProof {
        DidContinuityProof {
            schema: DidContinuityProof::SCHEMA.to_owned(),
            old_did: Did::new("did:web:old.example").unwrap(),
            new_did: Did::new("did:webvh:new.example").unwrap(),
            purpose: DidContinuityPurpose::PrincipalMethodUpgrade,
            audience: vec!["ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()],
            issued_at: "2026-04-29T00:00:00Z".parse().unwrap(),
            expires_at: Some("2026-04-30T00:00:00Z".parse().unwrap()),
            old_did_document_digest: Some(hash("a")),
            new_did_document_digest: Some(hash("b")),
            transfer_evidence: DidContinuityTransferEvidence {
                old_did_document_canonical_digest: hash("c"),
                old_did_document_fetched_at: "2026-04-28T23:00:00Z".parse().unwrap(),
                inception_public_key_fingerprint: hash("d"),
                user_oob_confirmation_id: "confirm-1".to_owned(),
                user_oob_confirmation_method:
                    DidContinuityOobConfirmationMethod::IndependentChannel,
            },
            signature_chain: vec![
                DidContinuitySignatureLink {
                    principal_id: Did::new("did:web:old.example").unwrap(),
                    verification_method: "did:web:old.example#key-1".to_owned(),
                    algorithm: DidContinuitySignatureAlgorithm::Ed25519,
                    payload_digest: hash("e"),
                    signature: "old_sig".to_owned(),
                },
                DidContinuitySignatureLink {
                    principal_id: Did::new("did:webvh:new.example").unwrap(),
                    verification_method: "did:webvh:new.example#key-1".to_owned(),
                    algorithm: DidContinuitySignatureAlgorithm::MlDsa65,
                    payload_digest: hash("e"),
                    signature: "new_sig".to_owned(),
                },
            ],
        }
    }

    fn valid_fixture() -> DidContinuityProof {
        let mut proof = fixture();
        let digest = proof.signature_payload_digest().unwrap();
        for link in &mut proof.signature_chain {
            link.payload_digest = digest.clone();
        }
        proof
    }

    #[test]
    fn did_continuity_proof_roundtrips_and_validates() {
        let proof = valid_fixture();
        proof.validate_minimal().unwrap();

        let encoded = serde_json::to_value(&proof).unwrap();
        assert_eq!(encoded["schema"], DidContinuityProof::SCHEMA);
        assert_eq!(encoded["signature_chain"][1]["algorithm"], "ML-DSA-65");

        let decoded: DidContinuityProof = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn did_continuity_proof_rejects_short_signature_chain() {
        let mut proof = valid_fixture();
        proof.signature_chain.pop();
        let err = proof.validate_minimal().unwrap_err().to_string();
        assert!(err.contains("at least two signature_chain links"));
    }

    #[test]
    fn did_continuity_proof_rejects_payload_digest_mismatch() {
        let mut proof = valid_fixture();
        proof.signature_chain[0].payload_digest = hash("f");
        let err = proof.validate_minimal().unwrap_err().to_string();
        assert!(err.contains("payload_digest"));
    }

    #[test]
    fn did_continuity_principal_method_upgrade_is_did_web_to_webvh() {
        let mut proof = valid_fixture();
        proof.old_did = Did::new("did:key:z6Mki").unwrap();
        let digest = proof.signature_payload_digest().unwrap();
        for link in &mut proof.signature_chain {
            link.payload_digest = digest.clone();
        }
        let err = proof.validate_minimal().unwrap_err().to_string();
        assert!(err.contains("principal_method_upgrade requires old_did did:web"));
    }

    #[test]
    fn did_continuity_proof_rejects_missing_new_did_link() {
        let mut proof = valid_fixture();
        proof.signature_chain[1].principal_id = Did::new("did:webvh:other.example").unwrap();
        proof.signature_chain[1].verification_method = "did:webvh:other.example#key-1".to_owned();
        let digest = proof.signature_payload_digest().unwrap();
        for link in &mut proof.signature_chain {
            link.payload_digest = digest.clone();
        }
        let err = proof.validate_minimal().unwrap_err().to_string();
        assert!(err.contains("old_did and new_did links"));
    }

    #[test]
    fn inception_key_max_online_window_is_24h_hard_cap() {
        assert_eq!(INCEPTION_KEY_MAX_ONLINE_WINDOW_SECS, 24 * 60 * 60);
        assert_eq!(
            inception_key_max_online_window(),
            chrono::Duration::hours(24)
        );
    }

    #[test]
    fn inception_key_age_under_24h_does_not_exceed() {
        let bootstrap: DateTime<Utc> = "2026-04-29T00:00:00Z".parse().unwrap();
        // 23h59m later — still inside the hard cap.
        let now = bootstrap + chrono::Duration::hours(23) + chrono::Duration::minutes(59);
        assert!(!inception_key_age_exceeded(bootstrap, now));
    }

    #[test]
    fn inception_key_age_over_24h_exceeds() {
        let bootstrap: DateTime<Utc> = "2026-04-29T00:00:00Z".parse().unwrap();
        let now = bootstrap + chrono::Duration::hours(24) + chrono::Duration::seconds(1);
        assert!(inception_key_age_exceeded(bootstrap, now));
    }

    #[test]
    fn inception_key_age_exactly_24h_is_boundary_not_exceeded() {
        let bootstrap: DateTime<Utc> = "2026-04-29T00:00:00Z".parse().unwrap();
        // Exactly at the cap is not "exceeded" (strict `>`); one second past is.
        let at_cap = bootstrap + chrono::Duration::hours(24);
        assert!(!inception_key_age_exceeded(bootstrap, at_cap));
        assert!(inception_key_age_exceeded(
            bootstrap,
            at_cap + chrono::Duration::seconds(1)
        ));
    }

    #[test]
    fn inception_key_age_future_bootstrap_not_exceeded() {
        let bootstrap: DateTime<Utc> = "2026-04-29T00:00:00Z".parse().unwrap();
        let now = bootstrap - chrono::Duration::hours(1);
        assert!(!inception_key_age_exceeded(bootstrap, now));
    }
}
