//! Encrypted event envelope counterpart for `encrypted-envelope.schema.json`.
//!
//! The envelope is payload-agnostic: the ciphertext is opaque and the AAD
//! carries only routing metadata.

use arkret_canonical::canonical;
use arkret_wire::{
    EncryptedPayloadScheme, Error, EventId, Hash, RealmId, ReasonCode, Result, SchemaId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// AEAD purpose fixed by `encryption-and-audit.md` §2.10.2.
pub const MLS_EXPORTER_AEAD_CONTENT_PURPOSE: &str = "mls_exporter_aead_content";

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeAad {
    pub realm_id: RealmId,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_refs: Option<Vec<EventId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_ref_digests: Option<Vec<Hash>>,
}

impl EncryptedEnvelopeAad {
    /// Build the minimal AAD allowed for hidden event-id visibility.
    pub fn hidden(realm_id: RealmId, event_kind: impl Into<String>) -> Self {
        Self {
            realm_id,
            event_kind: event_kind.into(),
            event_id: None,
            event_ref_digest: None,
            causal_refs: None,
            causal_ref_digests: None,
        }
    }
}

/// Disclosure axis of `encrypted-envelope.schema.json#/properties/
/// aad_visibility_event_id`.
///
/// The derived `Ord` **is** the normative disclosure order
/// `hidden < routing_digest < opaque_id`
/// (`crypto-media/encryption-and-audit.md` §2.8), so variant declaration order
/// is wire-significant here and is pinned by
/// `aad_visibility_disclosure_order_is_normative`. Everything that compares two
/// visibilities MUST go through this ordering rather than re-deriving a rank.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedEnvelopeAadVisibility {
    /// Fail-closed default: what a Realm that has not declared the
    /// `aad_visibility` policy component permits.
    #[default]
    Hidden,
    RoutingDigest,
    OpaqueId,
}

/// Realm ceiling on [`EncryptedEnvelopeAadVisibility`], resolved from the
/// `aad_visibility` component of the accepted `ak.realm.policy_bundle`.
///
/// This is the shared judgement entry for services and clients
/// (`crypto-media/encryption-and-audit.md` §§2.3.2 / 2.8). It exists as a
/// distinct type so the absent-component case has to be *resolved* rather than
/// skipped: [`Self::from_declared`] takes an `Option` and maps `None` to
/// [`EncryptedEnvelopeAadVisibility::Hidden`], so "the Realm did not declare a
/// ceiling" can never be spelled as "do not check". An envelope narrower than
/// the ceiling is always fine; only a wider one is a violation, and it MUST be
/// rejected rather than silently downgraded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AadVisibilityCeiling(EncryptedEnvelopeAadVisibility);

impl AadVisibilityCeiling {
    /// Resolve the ceiling from the Realm's declared component value.
    ///
    /// `None` means the Realm carries no `aad_visibility` component, which is
    /// the `hidden` ceiling — not an exemption.
    pub fn from_declared(declared: Option<EncryptedEnvelopeAadVisibility>) -> Self {
        Self(declared.unwrap_or_default())
    }

    pub fn value(self) -> EncryptedEnvelopeAadVisibility {
        self.0
    }

    /// Whether `envelope` is at or below this ceiling.
    pub fn permits(self, envelope: EncryptedEnvelopeAadVisibility) -> bool {
        envelope <= self.0
    }

    /// Reject an envelope that discloses more than the Realm declared.
    ///
    /// The error text carries `aad_visibility_policy_violation` so every
    /// enforcement point reports the one registered sub-reason of
    /// `failed_precondition`. Callers MUST NOT recover by rewriting the
    /// envelope to `hidden`: a silent downgrade leaves the sender believing its
    /// disclosure level took effect and the receiver believing policy held.
    pub fn check(self, envelope: EncryptedEnvelopeAadVisibility) -> Result<()> {
        if self.permits(envelope) {
            return Ok(());
        }
        Err(Error::Protocol(format!(
            "{}: encrypted envelope aad_visibility_event_id {:?} is wider than the Realm ceiling \
             {:?}",
            ReasonCode::AAD_VISIBILITY_POLICY_VIOLATION,
            envelope,
            self.0
        )))
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptedEnvelopeKeyAlgorithm {
    #[serde(rename = "MLS")]
    Mls,
    #[serde(rename = "MLS-EXPORTER-AEAD")]
    MlsExporterAead,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedEnvelopeGroupStateRef {
    Event(EventId),
    Digest(Hash),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelopeKeyRef {
    pub algorithm: EncryptedEnvelopeKeyAlgorithm,
    pub group_state_ref: EncryptedEnvelopeGroupStateRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: EncryptedEnvelopeAadVisibility,
    pub aad: EncryptedEnvelopeAad,
    pub key_ref: EncryptedEnvelopeKeyRef,
    /// AEAD purpose. Required for `mls_exporter_aead_v1` and forbidden for
    /// `mls_rfc9420`, per `encryption-and-audit.md` §2.10.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// `canonical_id` of the ciphersuite the group at `key_ref.group_state_ref`
    /// negotiated. Required for `mls_exporter_aead_v1` and forbidden for
    /// `mls_rfc9420`.
    ///
    /// §2.10.2 closes by noting that every member of the AEAD header except
    /// `aad` is already on the envelope, which is what lets a receiver rebuild
    /// `aead_aad_bytes` — that only holds if this is carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_profile: Option<String>,
    pub payload_digest: Hash,
    pub aad_digest: Hash,
}

impl EncryptedEnvelope {
    pub const SCHEMA: &'static str = SchemaId::ENCRYPTED_ENVELOPE_V1;
    pub fn validate(&self) -> Result<()> {
        if !major_minor_version(&self.version) {
            return Err(Error::Protocol(
                "encrypted envelope version must be major.minor".to_owned(),
            ));
        }
        if !base64url_token(&self.group_id) {
            return Err(Error::Protocol(
                "encrypted envelope group_id is invalid".to_owned(),
            ));
        }
        if !content_type_token(&self.content_type) {
            return Err(Error::Protocol(
                "encrypted envelope content_type is invalid".to_owned(),
            ));
        }
        if !base64url_token(&self.ciphertext) {
            return Err(Error::Protocol(
                "encrypted envelope ciphertext is invalid".to_owned(),
            ));
        }
        let expected_algorithm = match self.scheme {
            EncryptedPayloadScheme::MlsRfc9420 => EncryptedEnvelopeKeyAlgorithm::Mls,
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                EncryptedEnvelopeKeyAlgorithm::MlsExporterAead
            }
        };
        if self.key_ref.algorithm != expected_algorithm {
            return Err(Error::Protocol(
                "encrypted envelope key_ref.algorithm does not match scheme".to_owned(),
            ));
        }
        // `encryption-and-audit.md` §2.10.2. Both directions matter: without
        // aead_profile a receiver cannot derive AEAD.Nk or N_AEAD and has to
        // assume a suite, and carrying either member under mls_rfc9420 claims
        // an exporter AEAD that scheme does not have.
        match self.scheme {
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                if self.purpose.as_deref().unwrap_or_default().is_empty() {
                    return Err(Error::Protocol(
                        "mls_exporter_aead_v1 envelope requires purpose".to_owned(),
                    ));
                }
                if self.aead_profile.as_deref().unwrap_or_default().is_empty() {
                    return Err(Error::Protocol(
                        "mls_exporter_aead_v1 envelope requires aead_profile".to_owned(),
                    ));
                }
            }
            EncryptedPayloadScheme::MlsRfc9420 => {
                if self.purpose.is_some() || self.aead_profile.is_some() {
                    return Err(Error::Protocol(
                        "mls_rfc9420 envelope must not carry purpose or aead_profile".to_owned(),
                    ));
                }
            }
        }
        if self.aad.causal_refs.is_some() && self.aad.causal_ref_digests.is_some() {
            return Err(Error::Protocol(
                "encrypted envelope aad cannot carry both causal_refs and causal_ref_digests"
                    .to_owned(),
            ));
        }
        match self.aad_visibility_event_id {
            EncryptedEnvelopeAadVisibility::Hidden => {
                if self.aad.event_id.is_some() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "hidden encrypted envelope aad forbids event identifiers".to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::RoutingDigest => {
                if self.aad.event_ref_digest.is_none() || self.aad.event_id.is_some() {
                    return Err(Error::Protocol(
                        "routing_digest encrypted envelope aad requires event_ref_digest only"
                            .to_owned(),
                    ));
                }
            }
            EncryptedEnvelopeAadVisibility::OpaqueId => {
                if self.aad.event_id.is_none() || self.aad.event_ref_digest.is_some() {
                    return Err(Error::Protocol(
                        "opaque_id encrypted envelope aad requires event_id only".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Decode and validate an encrypted envelope without initializing an MLS group machine.
pub fn parse_and_validate_encrypted_envelope(value: Value) -> Result<EncryptedEnvelope> {
    let envelope: EncryptedEnvelope = serde_json::from_value(value)
        .map_err(|error| Error::Protocol(format!("encrypted envelope schema: {error}")))?;
    envelope.validate()?;
    Ok(envelope)
}

/// `major.minor` numeric version token (e.g. `1.0`); both parts non-empty and
/// ASCII-digit only. Shared wire-token validator (reused by `arkret-sdk`).
pub fn major_minor_version(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

/// Non-empty base64url token (`[A-Za-z0-9_-]+`, no padding). Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `type/constraint_subkind` content-type token with restricted byte alphabet. Shared
/// wire-token validator (reused by `arkret-sdk`).
pub fn content_type_token(value: &str) -> bool {
    let Some((ty, constraint_subkind)) = value.split_once('/') else {
        return false;
    };
    !ty.is_empty()
        && !constraint_subkind.is_empty()
        && ty.bytes().all(content_type_byte)
        && constraint_subkind.bytes().all(content_type_byte)
}

/// Admissible byte inside a [`content_type_token`] segment. Shared wire-token
/// validator (reused by `arkret-sdk`).
pub fn content_type_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'+' | b'-')
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<EncryptedEnvelopeAad>,
    pub payload_digest: Hash,
    /// Reference to the key material that decrypts `ciphertext`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyRefObject>,
    /// AEAD purpose, present only for `mls_exporter_aead_v1`.
    ///
    /// A nonce-derivation and AAD input, so it separates a content nonce from
    /// every other AEAD domain under the same key and epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// `canonical_id` of an ACTIVE MLS ciphersuite, present only for
    /// `mls_exporter_aead_v1`.
    ///
    /// `encryption-and-audit.md` §2.10.2 requires it to equal the ciphersuite
    /// the group at `key_ref.group_state_ref` actually negotiated. It is what
    /// fixes `AEAD.Nk` for the content key and `N_AEAD` for the nonce, so a
    /// receiver that reads a payload without a local group snapshot cannot
    /// derive either without it — which is why the standalone decrypt path
    /// takes it rather than assuming a suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead_profile: Option<String>,
}

/// Typed `key_ref` per `media-and-blob.md` §encrypted-payload (B-22).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRefObject {
    pub algorithm: String,
    pub group_state_ref: String,
}

/// Closed pre-encryption immutable header for `mls_exporter_aead_v1`.
///
/// Its JCS bytes are the AEAD AAD.  Post-encryption fields such as
/// `payload_digest`, ciphertext, tags and proofs deliberately cannot be
/// represented here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MlsExporterAeadHeader<'a> {
    pub scheme: EncryptedPayloadScheme,
    pub key_ref: &'a KeyRefObject,
    pub epoch: u64,
    pub nonce: String,
    pub purpose: &'static str,
    pub aead_profile: &'a str,
    pub aad: &'a EncryptedEnvelopeAad,
}

impl<'a> MlsExporterAeadHeader<'a> {
    pub fn new(
        key_ref: &'a KeyRefObject,
        epoch: u64,
        nonce: &[u8],
        aead_profile: &'a str,
        aad: &'a EncryptedEnvelopeAad,
    ) -> Self {
        Self {
            scheme: EncryptedPayloadScheme::MlsExporterAeadV1,
            key_ref,
            epoch,
            nonce: arkret_canonical::base64url::base64url_encode(nonce),
            purpose: MLS_EXPORTER_AEAD_CONTENT_PURPOSE,
            aead_profile,
            aad,
        }
    }

    /// JCS bytes passed directly to AEAD seal/open.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(self)?)
    }
}

impl KeyRefObject {
    /// Build an MLS-RFC9420 typed `key_ref` from a group id and epoch.
    pub fn mls_rfc9420(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: EncryptedPayloadScheme::MlsRfc9420.as_str().to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }

    /// Build an MLS-EXPORTER-AEAD typed `key_ref` (§2.10) from a group id and
    /// epoch. The `algorithm` token `MLS-EXPORTER-AEAD` is bound by the
    /// `encrypted-envelope.schema.json` if/then to `scheme=mls_exporter_aead_v1`.
    pub fn mls_exporter_aead(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: "MLS-EXPORTER-AEAD".to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        Self::payload_digest_for_scheme(
            EncryptedPayloadScheme::MlsRfc9420,
            epoch,
            content_type,
            aad,
            ciphertext_bytes,
        )
    }

    /// §2.3.3 content payload digest, parameterized by `scheme`. The digest binds
    /// the `scheme` token into the metadata (`encryption` field) so a payload
    /// authored under `mls_exporter_aead_v1` (§2.10) and one under `mls_rfc9420`
    /// never collide, and the receiver's verification is scheme-bound.
    /// `ciphertext_bytes` are the raw decoded ciphertext bytes (for
    /// `mls_exporter_aead_v1` that is the `nonce || AEAD_ct` blob).
    pub fn payload_digest_for_scheme(
        scheme: EncryptedPayloadScheme,
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: scheme.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::payload_digest_for_scheme(
            self.scheme.clone(),
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted payload digest mismatch".to_owned(),
            ))
        }
    }

    /// Validate that the key reference, when present, is usable for lookup.
    pub fn validate_key_ref(&self) -> Result<()> {
        if let Some(key_ref) = &self.key_ref
            && key_ref.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.algorithm must not be empty".to_owned(),
            ));
        }
        if let Some(key_ref) = &self.key_ref
            && key_ref.group_state_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.group_state_ref must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a EncryptedEnvelopeAad>,
}

#[cfg(test)]
mod aad_visibility_tests {
    use super::*;

    #[test]
    fn aad_visibility_disclosure_order_is_normative() {
        use EncryptedEnvelopeAadVisibility::{Hidden, OpaqueId, RoutingDigest};
        // `encryption-and-audit.md` §2.8: hidden < routing_digest < opaque_id.
        // The derived Ord is the only spelling of this order, so pin it here
        // rather than letting a variant reshuffle silently widen a ceiling.
        assert!(Hidden < RoutingDigest);
        assert!(RoutingDigest < OpaqueId);
        assert_eq!(EncryptedEnvelopeAadVisibility::default(), Hidden);
    }

    #[test]
    fn absent_component_resolves_to_the_hidden_ceiling() {
        use EncryptedEnvelopeAadVisibility::{Hidden, OpaqueId, RoutingDigest};
        let undeclared = AadVisibilityCeiling::from_declared(None);
        assert_eq!(undeclared.value(), Hidden);
        undeclared
            .check(Hidden)
            .expect("hidden is at the default ceiling");
        for wider in [RoutingDigest, OpaqueId] {
            let error = undeclared.check(wider).unwrap_err().to_string();
            assert!(error.contains("aad_visibility_policy_violation"), "{error}");
        }
    }

    #[test]
    fn a_narrower_envelope_is_always_accepted() {
        use EncryptedEnvelopeAadVisibility::{Hidden, OpaqueId, RoutingDigest};
        let ceiling = AadVisibilityCeiling::from_declared(Some(RoutingDigest));
        ceiling.check(Hidden).expect("narrower discloses less");
        ceiling.check(RoutingDigest).expect("at the ceiling");
        assert!(ceiling.check(OpaqueId).is_err());
    }
}
