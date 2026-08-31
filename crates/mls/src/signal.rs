//! `ak.signal_exporter_aead.v1` — the Signal rail's exporter AEAD
//! (`zh/sync/signal.md` §1, `zh/conformance/encoding.md` §10.1 / §10.2).
//!
//! Sibling construction to the `mls_exporter_aead_v1` content scheme in
//! [`crate::group`]. Exporter-content scopes use the per-epoch history root;
//! standard-MLS scopes use the non-deliverable `ak.signal-root-v1` exporter.
//! The accepted scope policy, never an untrusted envelope, selects that root.
//! Signal and content keep separate labels and framing:
//!
//! | | content | signal |
//! | --- | --- | --- |
//! | key label | `ak.content-v1` | `ak.signal-v1` |
//! | `purpose` | `mls_exporter_aead_content` | `ak.signal.v1` |
//! | ciphertext framing | `nonce \|\| ciphertext` | separate `nonce` field |
//!
//! The AEAD itself is *not* a difference: both domains take it from the
//! group's negotiated ciphersuite via [`ExporterAeadSuite`]. The algorithm
//! deliberately lives in `aead_profile`, never in `scheme`: the Signal
//! envelope's `scheme` is the fixed construction id, so activating a further
//! MLS ciphersuite reaches this rail with no wire change. Today only the
//! AES-128-GCM row is `active`, and every other row MUST fail closed until its
//! activation requirements are met.
//!
//! Derivation chain, all of it fixed by the registries:
//!
//! ```text
//! signal_root[N]    = history_secret[N]                 // exporter content
//!                  | MLS-Exporter("ak.signal-root-v1", scope, KDF.Nh)
//! K_signal[N,D]     = ExpandWithLabel(signal_root[N], "ak.signal-v1",
//!                                     sender_domain, AEAD.Nk)
//! nonce             = I2OSP(durable_sender_counter, AEAD.Nn)
//! AAD               = JCS(pre-encryption immutable header)   // §10.2
//! ```

use std::mem::size_of;

use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_crypto::{AeadNonceContext, AeadNonceReplayTracker, compose_aead_nonce};
use arkret_models_crypto::MlsEndpointIdentity;
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_signal_proof};
use arkret_wire::{
    EncryptedPayloadScheme, EventId, Hash, MAX_SIGNAL_PLAINTEXT_BYTES, ReasonCode,
    SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME, SignalAeadBinding, SignalEncryptedPayload,
    SignalEnvelope, canonical,
};
use zeroize::Zeroizing;

use crate::exporter_kdf::derive_signal_key_from_history_secret;
#[cfg(test)]
use crate::group::mls_kdf_label;
use crate::group::{ArkretMlsGroup, ExporterAeadSuite};
use crate::{MlsError as Error, Result};

/// `ExpandWithLabel` label deriving the per-epoch, per-sender Signal key from
/// the `history_secret`. The verified MLS sender domain is the raw KDF context,
/// so distinct active senders do not share an AEAD key.
#[cfg(test)]
const SIGNAL_KEY_LABEL: &str = arkret_wire::ExporterLabelId::SIGNAL_V1;

/// A sealed Signal payload plus the nonce counter it consumed.
///
/// The whole [`SignalEncryptedPayload`] is returned rather than loose bytes so
/// a caller cannot pair a ciphertext with a nonce, `aead_profile`, epoch or
/// `aad_digest` other than the ones it was actually sealed under; the only
/// thing left to attach is the device proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalSeal {
    pub encrypted_payload: SignalEncryptedPayload,
    /// The `device_nonce_counter_be64` value this seal used. Already consumed:
    /// the group's counter has advanced past it. Exposed only so a caller can
    /// record or assert on it — feeding it back in is not possible by design.
    pub nonce_counter: u64,
}

impl ArkretMlsGroup {
    /// The next `device_nonce_counter_be64` this group would use for a Signal.
    ///
    /// `encoding.md` §10.1 makes persisting this mandatory. It is written into
    /// the group state snapshot by [`ArkretMlsGroup::export_state_record`], so
    /// the obligation on a caller is simply: **persist the group state after
    /// every seal**. Reloading a snapshot taken before a seal rewinds the
    /// counter and reuses a nonce, which breaks confidentiality *and*
    /// integrity for the epoch.
    pub fn signal_nonce_counter(&self) -> u64 {
        self.signal_nonce_counter
    }

    /// Seal `plaintext` under `ak.signal_exporter_aead.v1` for the current
    /// epoch.
    ///
    /// The counter is neither a parameter nor caller-supplied state: it lives
    /// in the group and advances here, so there is no call shape that reuses a
    /// nonce. `binding` is the pre-encryption immutable header (§10.2) — it is
    /// the AEAD AAD *and* the source of the nonce-derivation context, so the
    /// caller commits to the routing header before any ciphertext exists.
    /// `content_scheme` must come from locally accepted scope policy.
    pub fn seal_signal_payload(
        &mut self,
        binding: &SignalAeadBinding<'_>,
        content_scheme: EncryptedPayloadScheme,
        plaintext: &[u8],
    ) -> Result<SignalSeal> {
        binding.validate()?;
        if plaintext.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(Error::Protocol(format!(
                "signal plaintext exceeds {MAX_SIGNAL_PLAINTEXT_BYTES} bytes"
            )));
        }
        let suite = self.signal_suite_for(binding)?;
        let Some((principal_id, device_id)) = self.identity.endpoint.as_human_device() else {
            return Err(Error::Protocol(
                "ordinary Signal sender requires a human-device MLS endpoint".to_owned(),
            ));
        };
        if binding.sender_actor_id.as_account_id().is_none()
            || binding.sender_actor_id.signing_principal_id() != principal_id
            || binding.sender_device_id != device_id
        {
            return Err(Error::Protocol(
                "signal sender does not match this MLS identity".to_owned(),
            ));
        }
        let sender_domain = self.verified_signal_sender_domain(binding)?;

        let counter = self.signal_nonce_counter;
        let nonce = self.signal_nonce(binding, &sender_domain, suite, counter)?;
        // Advance before encrypting, not after. Once the nonce is composed it
        // is spent: if anything below fails and the caller retries, it must get
        // a fresh counter. Skipped counter values are harmless; a repeated one
        // is not.
        self.signal_nonce_counter = self
            .signal_nonce_counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("signal nonce counter overflow".to_owned()))?;

        let nonce_b64 = base64url_encode(&nonce);
        let aad = binding.aad_bytes(&nonce_b64)?;
        let key = self.derive_signal_key(binding, content_scheme, &sender_domain, suite)?;
        let ciphertext = suite.seal(&key, &nonce, &aad, plaintext)?;

        Ok(SignalSeal {
            encrypted_payload: SignalEncryptedPayload {
                scheme: SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: binding.key_ref.clone(),
                purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: binding.aead_profile.to_owned(),
                epoch: binding.epoch,
                nonce: nonce_b64,
                ciphertext: base64url_encode(&ciphertext),
                // Digest of the exact bytes just authenticated, so the carried
                // value can never disagree with the AAD that was used.
                aad_digest: Hash::new(canonical::sha256_digest(&aad))?,
            },
            nonce_counter: counter,
        })
    }

    /// Open a Signal payload sealed by another member of this group.
    ///
    /// `replay` is required, not optional: §10.1 obliges a receiver to keep a
    /// seen-counter set per `(key_ref, epoch, device_id, purpose,
    /// aead_profile)`, and an optional tracker is a check that gets skipped.
    /// The tracker keys on exactly that tuple.
    ///
    /// Resolves the declared sender to an active MLS leaf, rejects a repeated
    /// counter (`aead_nonce_counter_replay`), then opens under the verified
    /// sender-domain key and recomputed AAD. This is a cryptographic primitive,
    /// not sender authentication: every epoch member knows the shared root and
    /// can derive every sender-domain key. Use `open_signal_envelope` for the
    /// authenticated receive path with independently current device evidence.
    pub fn open_signal_payload(
        &self,
        binding: &SignalAeadBinding<'_>,
        content_scheme: EncryptedPayloadScheme,
        nonce: &str,
        ciphertext: &str,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        binding.validate()?;
        let suite = self.signal_suite_for(binding)?;
        let sender_domain = self.verified_signal_sender_domain(binding)?;

        let nonce_bytes = base64url_decode(nonce)?;
        if nonce_bytes.len() != suite.nonce_len() {
            return Err(Error::Protocol(format!(
                "{}: signal nonce is {} bytes, expected {} for {}",
                ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
                nonce_bytes.len(),
                suite.nonce_len(),
                binding.aead_profile
            )));
        }
        let counter_offset = nonce_bytes.len() - size_of::<u64>();
        if nonce_bytes[..counter_offset].iter().any(|byte| *byte != 0) {
            return Err(Error::Protocol(format!(
                "{}: signal nonce is not full-width I2OSP of its counter",
                ReasonCode::AEAD_NONCE_DERIVATION_INVALID
            )));
        }
        let mut counter_bytes = [0u8; size_of::<u64>()];
        counter_bytes.copy_from_slice(&nonce_bytes[counter_offset..]);
        // Recomputed from the header we just validated — never the sender's
        // self-reported `aad_digest` (§10.2).
        let aad = binding.aad_bytes(nonce)?;
        let key = self.derive_signal_key(binding, content_scheme, &sender_domain, suite)?;
        let plaintext = suite.open(&key, &nonce_bytes, &aad, &base64url_decode(ciphertext)?)?;
        replay.accept_counter(
            &signal_nonce_context(binding, &sender_domain)?,
            u64::from_be_bytes(counter_bytes),
        )?;
        Ok(plaintext)
    }

    /// Validate a received [`SignalEnvelope`] and open its payload.
    ///
    /// The one-call receive path, so the envelope-level checks
    /// ([`SignalEnvelope::validate_structural`]: TTL ceilings, scope/realm
    /// agreement, size bounds, `envelope_digest` and the carried `aad_digest`)
    /// cannot be forgotten before decryption. The caller must independently
    /// authenticate current device authority (not target-Seal-relative), and
    /// supply the accepted winning state reference for this exact scope/group.
    /// A leaf remaining after known revocation must never provide that current
    /// authority. Here the same current key and authorization Event are bound
    /// to the complete accepted leaf identity before the producer proof and
    /// ciphertext are verified. No server assertion replaces these checks.
    pub fn open_signal_envelope(
        &self,
        envelope: &SignalEnvelope,
        content_scheme: EncryptedPayloadScheme,
        current_device_key: &PublicKeyMaterial,
        device_authorize_event_id: &EventId,
        accepted_group_state_ref: &str,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        envelope.validate_structural()?;
        if envelope.encrypted_payload.key_ref.group_state_ref != accepted_group_state_ref {
            return Err(Error::Protocol(
                "signal group_state_ref is not the accepted winning state".to_owned(),
            ));
        }
        let leaf = self.verified_signal_sender_leaf(&envelope.aead_binding())?;
        let current_key = current_device_key
            .ed25519_bytes()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if base64url_decode(leaf.signature_key.as_str())?.as_slice() != current_key
            || leaf.device_authorize_event_id.as_ref() != Some(device_authorize_event_id)
        {
            return Err(Error::Protocol(
                "signal current device key or authorization differs from the accepted MLS leaf"
                    .to_owned(),
            ));
        }
        verify_ed25519_signal_proof(envelope, current_device_key)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        self.open_signal_payload(
            &envelope.aead_binding(),
            content_scheme,
            &envelope.encrypted_payload.nonce,
            &envelope.encrypted_payload.ciphertext,
            replay,
        )
    }

    /// Resolve the declared `aead_profile` and check it against reality.
    ///
    /// `encoding.md` §10.1 and `signal.md` §1 both require `aead_profile` to
    /// equal the ciphersuite the group at `key_ref.group_state_ref` *actually*
    /// negotiated, not merely a registered active one. Epoch equality is
    /// enforced at the same time because both the Signal key and the sender
    /// nonce prefix come from the MLS exporter, which only ever evaluates
    /// against the group's current epoch.
    fn signal_suite_for(&self, binding: &SignalAeadBinding<'_>) -> Result<ExporterAeadSuite> {
        if self.group_id() != binding.scope_ref.canonical_mls_group_id()? {
            return Err(Error::Protocol(
                "signal scope does not name this MLS group".to_owned(),
            ));
        }
        let suite = ExporterAeadSuite::resolve(binding.aead_profile)?;
        if self.group_ciphersuite_canonical_id()? != binding.aead_profile {
            return Err(Error::Protocol(format!(
                "{}: signal aead_profile {} is not the ciphersuite this MLS group negotiated",
                ReasonCode::UNSUPPORTED_AEAD_PROFILE,
                binding.aead_profile
            )));
        }
        if binding.epoch != self.epoch() {
            return Err(Error::Protocol(format!(
                "signal epoch {} is not the group's current epoch {}; the MLS exporter only \
                 evaluates the current epoch, so neither the Signal key nor the sender nonce \
                 prefix is derivable for it",
                binding.epoch,
                self.epoch()
            )));
        }
        Ok(suite)
    }

    /// `K_signal[N,D] = ExpandWithLabel(signal_root[N], "ak.signal-v1",
    /// sender_domain, AEAD.Nk)`.
    ///
    /// Neither root is retained here: Signal must not make its epoch shareable
    /// history, and standard-MLS roots must never enter history distribution.
    fn derive_signal_key(
        &self,
        binding: &SignalAeadBinding<'_>,
        content_scheme: EncryptedPayloadScheme,
        verified_sender_domain: &[u8],
        suite: ExporterAeadSuite,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let signal_root = match content_scheme {
            EncryptedPayloadScheme::MlsExporterAeadV1 => {
                self.derive_history_secret(binding.realm_id.as_str())?
            }
            EncryptedPayloadScheme::MlsRfc9420 => self.export_secret(
                arkret_wire::ExporterLabelId::SIGNAL_ROOT_V1,
                &binding.scope_ref.canonical_effective_scope_key_bytes()?,
                32,
            )?,
        };
        derive_signal_key_from_history_secret(&signal_root, verified_sender_domain, suite.key_len())
    }

    /// `nonce = I2OSP(counter, AEAD.Nn)` (§10.1).
    fn signal_nonce(
        &self,
        binding: &SignalAeadBinding<'_>,
        verified_sender_domain: &[u8],
        suite: ExporterAeadSuite,
        counter: u64,
    ) -> Result<Vec<u8>> {
        signal_nonce_context(binding, verified_sender_domain)?;
        compose_aead_nonce(counter, suite.nonce_len()).map_err(Into::into)
    }

    fn verified_signal_sender_domain(&self, binding: &SignalAeadBinding<'_>) -> Result<Vec<u8>> {
        self.verified_signal_sender_leaf(binding)?;
        Ok(binding.sender_device_id.as_str().as_bytes().to_vec())
    }

    fn verified_signal_sender_leaf(
        &self,
        binding: &SignalAeadBinding<'_>,
    ) -> Result<crate::group::MlsVerifiedLeafBinding> {
        let matching_leaves = self
            .verified_leaf_bindings()?
            .into_iter()
            .filter(|leaf| {
                matches!(
                    &leaf.endpoint,
                    MlsEndpointIdentity::HumanDevice {
                        device_id,
                        ..
                    } if device_id == binding.sender_device_id
                )
            })
            .collect::<Vec<_>>();
        if matching_leaves.len() != 1 {
            return Err(Error::Protocol(
                "signal sender does not resolve to exactly one active MLS leaf".to_owned(),
            ));
        }
        let leaf = matching_leaves
            .into_iter()
            .next()
            .expect("one verified leaf");
        if &leaf.actor_id != binding.sender_actor_id
            || binding.sender_actor_id.as_account_id().is_none()
        {
            return Err(Error::Protocol(
                "signal sender differs from the complete accepted MLS leaf actor".to_owned(),
            ));
        }
        Ok(leaf)
    }
}

/// The §10.1 exporter Context for this domain, built from the header the AAD
/// also authenticates — so a receiver reconstructs it from what it verified.
fn signal_nonce_context(
    binding: &SignalAeadBinding<'_>,
    verified_sender_domain: &[u8],
) -> Result<AeadNonceContext> {
    let sender_domain = std::str::from_utf8(verified_sender_domain).map_err(|_| {
        Error::Protocol("verified signal sender domain must be canonical UTF-8".to_owned())
    })?;
    Ok(AeadNonceContext {
        mls_group_id: binding.scope_ref.canonical_mls_group_id()?,
        epoch: binding.epoch,
        sender_domain: sender_domain.to_owned(),
    })
}

/// `ExpandWithLabel(history_secret, "ak.signal-v1",
/// sender_domain, AEAD.Nk)`.
///
/// Expand-only, no Extract: the `history_secret` is an MLS exporter output and
/// already has full entropy, which is what `ExpandWithLabel` assumes of its
/// Secret input.
#[cfg(test)]
mod tests {
    use arkret_wire::{
        DeviceId, DidCoreId, DidUrl, RealmId, ScopeRef, SealId, SignalClass, SignalKeyRef,
        SignalProof, proof_kind,
    };
    use chrono::{DateTime, Duration, TimeZone, Utc};

    use super::*;
    use crate::identity::{ARKRET_MLS_CIPHERSUITE_CANONICAL_ID, ArkretMlsIdentity};

    const REALM: &str = "ak:realm:AWaw3_J06Ml7_fh-rnNBMJ3WJ6cLKzz1DvKyRhPSuJs0";
    const GROUP_STATE_REF: &str = "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM";
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000006";
    const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000e";
    const ALICE_SIGNING_SEED: [u8; 32] = [41; 32];
    const TYPING: &[u8] = br#"{"kind":"typing"}"#;
    /// `derive_signal_key(history_secret_of_the_content_key_vector,
    /// ALICE_DEVICE, 16)`.
    const SIGNAL_KEY_ANCHOR_HEX: &str = "b54fe4e8d4f389edb2d02028983dfb43";
    /// Canonical §10.2 AAD for the fixture header at `epoch=7`, all-zero nonce.
    const SIGNAL_AAD_ANCHOR: &str = concat!(
        "{\"aead_profile\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519\",",
        "\"epoch\":7,",
        "\"expires_at\":\"2026-07-28T12:00:30.000Z\",",
        "\"key_ref\":{\"algorithm\":\"MLS-EXPORTER-AEAD\",",
        "\"group_state_ref\":\"ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM\"},",
        "\"nonce\":\"AAAAAAAAAAAAAAAA\",",
        "\"purpose\":\"ak.signal.v1\",",
        "\"realm_id\":\"ak:realm:AWaw3_J06Ml7_fh-rnNBMJ3WJ6cLKzz1DvKyRhPSuJs0\",",
        "\"scheme\":\"ak.signal_exporter_aead.v1\",",
        "\"scope_ref\":{\"kind\":\"realm\",",
        "\"realm_id\":\"ak:realm:AWaw3_J06Ml7_fh-rnNBMJ3WJ6cLKzz1DvKyRhPSuJs0\"},",
        "\"seal_ref\":\"ak:seal:sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
        "\"sender_actor_id\":{\"account_id\":{\"principal_id\":\"ak:did_core:webvh:z6mkfixturealice\",",
        "\"station_id\":\"ak:did_core:web:station.example\"},\"kind\":\"account\"},",
        "\"sender_device_id\":\"ak:device:01904100-0000-7000-8000-000000000006\",",
        "\"sent_at\":\"2026-07-28T12:00:00.000Z\",",
        "\"signal_class\":\"session\"}"
    );

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sent_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap()
    }

    /// Owns the borrowed members of a [`SignalAeadBinding`] so a test can hand
    /// out fresh bindings without repeating the header.
    struct BindingParts {
        realm_id: RealmId,
        scope_ref: ScopeRef,
        sender_actor_id: arkret_wire::ActorId,
        sender_device_id: DeviceId,
        seal_ref: SealId,
        key_ref: SignalKeyRef,
        aead_profile: String,
    }

    impl BindingParts {
        fn new(sender_actor: &str, sender_device: &str) -> Self {
            let realm_id = RealmId::new(REALM).unwrap();
            Self {
                scope_ref: ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                realm_id,
                sender_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    DidCoreId::new(sender_actor.to_owned()).unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                sender_device_id: DeviceId::new(sender_device.to_owned()).unwrap(),
                seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
                key_ref: SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: GROUP_STATE_REF.to_owned(),
                },
                aead_profile: ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
            }
        }

        fn binding(&self, epoch: u64) -> SignalAeadBinding<'_> {
            SignalAeadBinding {
                realm_id: &self.realm_id,
                scope_ref: &self.scope_ref,
                sender_actor_id: &self.sender_actor_id,
                sender_device_id: &self.sender_device_id,
                seal_ref: &self.seal_ref,
                signal_class: SignalClass::Session,
                sent_at: sent_at(),
                expires_at: sent_at() + Duration::seconds(30),
                scheme: SIGNAL_AEAD_SCHEME,
                key_ref: &self.key_ref,
                purpose: SIGNAL_AEAD_PURPOSE,
                aead_profile: &self.aead_profile,
                epoch,
            }
        }
    }

    fn alice_and_bob() -> (ArkretMlsGroup, ArkretMlsGroup) {
        let alice = ArkretMlsIdentity::new_human_device(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DeviceId::new(ALICE_DEVICE.to_owned()).unwrap(),
            crate::identity::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&ALICE_SIGNING_SEED),
            ),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_test_human_device(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob".to_owned()).unwrap(),
            DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let alice_endpoint = alice.endpoint_identity();
        let bob_endpoint = bob.endpoint_identity();
        let mut alice_group = alice.create_group(REALM.as_bytes()).unwrap();
        let add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();
        bob_group
            .install_test_leaf_bindings(vec![alice_endpoint, bob_endpoint])
            .unwrap();
        for group in [&mut alice_group, &mut bob_group] {
            let mut bindings = group.verified_leaf_bindings().unwrap();
            for leaf in &mut bindings {
                let mut account = leaf.actor_id.as_account_id().unwrap().clone();
                account.station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
                leaf.actor_id = arkret_wire::ActorId::account(account);
            }
            group.install_verified_leaf_bindings(bindings).unwrap();
        }
        assert_eq!(alice_group.epoch(), bob_group.epoch());
        (alice_group, bob_group)
    }

    /// Every wire-breaking parameter of the `ak.signal-v1` key derivation,
    /// checked against the registry rows rather than against this module.
    ///
    /// `exporter-label-registry.json` fixes the label and verified-sender
    /// `context_fields`; `mls-ciphersuite-registry.json`'s only active row is
    /// AES-128-GCM, which fixes `AEAD.Nk` = 16 and `N_AEAD` = 12 — and 12 is
    /// what `signal-envelope.schema.json` independently pins by requiring a
    /// 16-character base64url `nonce`.
    #[test]
    fn signal_key_parameters_match_the_registries() {
        assert_eq!(SIGNAL_KEY_LABEL, "ak.signal-v1");
        let descriptor = arkret_wire::EXPORTER_LABELS
            .iter()
            .find(|row| row.label == SIGNAL_KEY_LABEL)
            .unwrap();
        assert_eq!(descriptor.primitive, Some("ExpandWithLabel"));
        assert_eq!(descriptor.context_fields, ["sender_domain"]);

        let suite = ExporterAeadSuite::resolve(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap();
        assert_eq!(suite.key_len(), 16);
        assert_eq!(suite.nonce_len(), 12);
        // 12 raw bytes is exactly 16 unpadded base64url characters, i.e. the
        // schema's `^[A-Za-z0-9_-]{16}$`.
        assert_eq!(base64url_encode(vec![0u8; suite.nonce_len()]).len(), 16);

        // `ExpandWithLabel` info rebuilt from the encoding rule the spec
        // fixture states verbatim, not from `mls_kdf_label`:
        //   uint16_be(Length) || varint(len(full_label)) || full_label
        //                     || varint(len(Context)) || Context
        let full_label = format!("MLS 1.0 {SIGNAL_KEY_LABEL}");
        assert_eq!(full_label.len(), 20);
        let mut expected = 16u16.to_be_bytes().to_vec();
        expected.push(u8::try_from(full_label.len()).unwrap());
        expected.extend_from_slice(full_label.as_bytes());
        let context = ALICE_DEVICE;
        expected.push(u8::try_from(context.len()).unwrap());
        expected.extend_from_slice(context.as_bytes());
        assert_eq!(
            mls_kdf_label(suite.key_len(), SIGNAL_KEY_LABEL, context.as_bytes()).unwrap(),
            expected
        );
    }

    /// The Signal key and the content key hang off the same `history_secret`
    /// under the same group and epoch, so the registered label is the ONLY
    /// thing keeping them apart. Anchored on the `history_secret` the
    /// registered content-key vector produces, so a drift in the shared part
    /// of the chain surfaces here too.
    #[test]
    fn signal_key_is_domain_separated_from_the_content_key() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/arkret-private-kdf-fixture.json",
        )
        .unwrap();
        let case = &fixture["cases"][0];
        let history_secret =
            hex::decode(case["expected"]["history_secret_hex"].as_str().unwrap()).unwrap();
        let content_key_hex = case["expected"]["content_key_hex"].as_str().unwrap();

        let signal_key =
            derive_signal_key_from_history_secret(&history_secret, ALICE_DEVICE.as_bytes(), 16)
                .unwrap();
        let other_sender_key =
            derive_signal_key_from_history_secret(&history_secret, BOB_DEVICE.as_bytes(), 16)
                .unwrap();
        assert_eq!(signal_key.len(), 16);
        assert_ne!(
            signal_key.as_slice(),
            other_sender_key.as_slice(),
            "valid sender domains MUST use distinct Signal AEAD keys even under the same counter nonce"
        );
        assert!(
            !content_key_hex.starts_with(&hex(&signal_key)),
            "ak.signal-v1 and ak.content-v1 MUST NOT share key material"
        );
        // Regression anchor: no registered vector covers the Signal key yet,
        // so this pins the bytes this implementation produces from the
        // vector's own `history_secret`.
        assert_eq!(
            hex(&signal_key),
            SIGNAL_KEY_ANCHOR_HEX,
            "ak.signal-v1 ExpandWithLabel key drifted"
        );
    }

    /// `aead_profile` is the algorithm carrier, so its gate is the whole
    /// algorithm-agility story: unregistered and `reserved` rows MUST fail
    /// closed, and activating a row is a change here with none on the wire.
    #[test]
    fn aead_profile_resolution_fails_closed_off_the_active_registry_row() {
        ExporterAeadSuite::resolve(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap();

        for reserved in [
            "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
            "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
            "MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44",
        ] {
            let error = ExporterAeadSuite::resolve(reserved)
                .unwrap_err()
                .to_string();
            assert!(error.contains("unsupported_aead_profile"), "{error}");
            assert!(error.contains("reserved"), "{error}");
        }

        for unregistered in ["", "mls_exporter_aead_xchacha20poly1305", "AES-128-GCM"] {
            let error = ExporterAeadSuite::resolve(unregistered)
                .unwrap_err()
                .to_string();
            assert!(error.contains("unsupported_aead_profile"), "{error}");
        }
    }

    /// `nonce = I2OSP(counter, AEAD.Nn)` with one durable per-sender counter.
    #[test]
    fn nonce_is_the_full_width_counter() {
        let (alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let alice_parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        let suite = ExporterAeadSuite::resolve(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap();

        let nonce = alice_group
            .signal_nonce(
                &alice_parts.binding(epoch),
                ALICE_DEVICE.as_bytes(),
                suite,
                0x0102_0304_0506_0708,
            )
            .unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(&nonce[..4], &[0; 4]);
        assert_eq!(&nonce[4..], &0x0102_0304_0506_0708u64.to_be_bytes());
    }

    /// The AEAD AAD is the canonical bytes of the pre-encryption immutable
    /// header — the exact closed field set `encoding.md` §10.2 tabulates for
    /// `ak.signal_exporter_aead.v1`, and nothing that depends on AEAD output.
    #[test]
    fn aad_is_the_canonical_pre_encryption_immutable_header() {
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        let aad = parts.binding(7).aad_bytes("AAAAAAAAAAAAAAAA").unwrap();
        let aad = std::str::from_utf8(&aad).unwrap();
        assert_eq!(aad, SIGNAL_AAD_ANCHOR, "canonical signal AAD drifted");
        assert!(!aad.contains("aad_digest"));
        assert!(!aad.contains("ciphertext"));
    }

    #[test]
    fn seal_and_open_round_trip_between_two_members() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        let binding = parts.binding(epoch);

        let seal = alice_group
            .seal_signal_payload(&binding, EncryptedPayloadScheme::MlsExporterAeadV1, TYPING)
            .unwrap();
        assert_eq!(seal.nonce_counter, 0);
        assert_eq!(seal.encrypted_payload.scheme, SIGNAL_AEAD_SCHEME);
        assert_eq!(seal.encrypted_payload.purpose, SIGNAL_AEAD_PURPOSE);
        assert_eq!(seal.encrypted_payload.nonce.len(), 16);
        assert_eq!(
            seal.encrypted_payload.aad_digest,
            binding.aad_digest(&seal.encrypted_payload.nonce).unwrap()
        );

        let mut replay = AeadNonceReplayTracker::new();
        let opened = bob_group
            .open_signal_payload(
                &binding,
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &seal.encrypted_payload.nonce,
                &seal.encrypted_payload.ciphertext,
                &mut replay,
            )
            .unwrap();
        assert_eq!(opened, TYPING);

        // The same counter twice in one sender scope is a replay.
        let error = bob_group
            .open_signal_payload(
                &binding,
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &seal.encrypted_payload.nonce,
                &seal.encrypted_payload.ciphertext,
                &mut replay,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("aead_nonce_counter_replay"), "{error}");
    }

    /// A sender cannot seal under another active identity, and a receiver
    /// derives the key from the sender identity named by the envelope.
    #[test]
    fn sender_identity_is_enforced_in_both_directions() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let alice_parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        let bob_parts = BindingParts::new("ak:did_core:webvh:z6mkfixturebob", BOB_DEVICE);

        let error = alice_group
            .seal_signal_payload(
                &bob_parts.binding(epoch),
                EncryptedPayloadScheme::MlsExporterAeadV1,
                b"spoof",
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("signal sender does not match this MLS identity"),
            "{error}"
        );

        let seal = alice_group
            .seal_signal_payload(
                &alice_parts.binding(epoch),
                EncryptedPayloadScheme::MlsExporterAeadV1,
                TYPING,
            )
            .unwrap();
        // Re-declare Alice's ciphertext as Bob's: both the KDF context and AAD
        // change, so the ciphertext cannot authenticate.
        assert!(
            bob_group
                .open_signal_payload(
                    &bob_parts.binding(epoch),
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &seal.encrypted_payload.nonce,
                    &seal.encrypted_payload.ciphertext,
                    &mut AeadNonceReplayTracker::new(),
                )
                .is_err(),
            "ciphertext accepted under a different verified sender domain"
        );
    }

    /// The counter is monotonic per device and MUST survive persistence:
    /// §10.1 forbids a device that lost its counter from restarting at 0 in
    /// the same epoch.
    #[test]
    fn nonce_counter_is_monotonic_and_persisted() {
        let (mut alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);

        let mut nonces = Vec::new();
        for expected_counter in 0..3u64 {
            let seal = alice_group
                .seal_signal_payload(
                    &parts.binding(epoch),
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    TYPING,
                )
                .unwrap();
            assert_eq!(seal.nonce_counter, expected_counter);
            nonces.push(seal.encrypted_payload.nonce);
        }
        assert_eq!(alice_group.signal_nonce_counter(), 3);
        nonces.sort();
        nonces.dedup();
        assert_eq!(nonces.len(), 3, "a nonce was reused");

        let record = alice_group.export_state_record().unwrap();
        let restored = ArkretMlsGroup::restore_from_state_record(&record).unwrap();
        assert_eq!(restored.signal_nonce_counter(), 3);
    }

    /// A sealed payload drops straight into a `SignalEnvelope` that passes the
    /// shared structural gate — proof that the AAD this module authenticates
    /// is the one an ingress recomputes from the wire header.
    fn signed_envelope(alice_group: &mut ArkretMlsGroup) -> SignalEnvelope {
        signed_envelope_with_scheme(alice_group, EncryptedPayloadScheme::MlsExporterAeadV1)
    }

    fn signed_envelope_with_scheme(
        alice_group: &mut ArkretMlsGroup,
        content_scheme: EncryptedPayloadScheme,
    ) -> SignalEnvelope {
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        let binding = parts.binding(epoch);
        let seal = alice_group
            .seal_signal_payload(&binding, content_scheme, TYPING)
            .unwrap();

        let mut envelope = SignalEnvelope {
            realm_id: parts.realm_id.clone(),
            scope_ref: parts.scope_ref.clone(),
            sender_actor_id: parts.sender_actor_id.clone(),
            sender_device_id: parts.sender_device_id.clone(),
            seal_ref: parts.seal_ref.clone(),
            signal_class: binding.signal_class,
            sent_at: binding.sent_at,
            expires_at: binding.expires_at,
            encrypted_payload: seal.encrypted_payload,
            proof: SignalProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!(
                    "did:webvh:z6mkfixturealice:alice.example#{}",
                    parts.sender_device_id
                ))
                .unwrap(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: binding.sent_at,
                domain: None,
                audience: None,
                jws: "a..b".to_owned(),
            },
        };
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&ALICE_SIGNING_SEED),
            &envelope.proof_binding_bytes().unwrap(),
        )
        .unwrap();
        envelope.validate_structural().unwrap();
        envelope
    }

    fn current_alice_evidence(group: &ArkretMlsGroup) -> (PublicKeyMaterial, EventId) {
        let leaf = group.verified_leaf_bindings().unwrap().into_iter()
            .find(|leaf| matches!(&leaf.endpoint, MlsEndpointIdentity::HumanDevice {device_id, ..} if device_id.as_str() == ALICE_DEVICE))
            .unwrap();
        (
            PublicKeyMaterial::Ed25519Raw {
                bytes: base64url_decode(leaf.signature_key.as_str()).unwrap(),
            },
            leaf.device_authorize_event_id.unwrap(),
        )
    }

    #[test]
    fn sealed_payload_completes_a_valid_signal_envelope() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let envelope = signed_envelope(&mut alice_group);
        let (key, authorization) = current_alice_evidence(&bob_group);

        assert_eq!(
            bob_group
                .open_signal_envelope(
                    &envelope,
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &key,
                    &authorization,
                    GROUP_STATE_REF,
                    &mut AeadNonceReplayTracker::new()
                )
                .unwrap(),
            TYPING
        );
    }

    #[test]
    fn standard_mls_signal_root_is_not_the_deliverable_history_root() {
        let (mut alice, bob) = alice_and_bob();
        let envelope = signed_envelope_with_scheme(&mut alice, EncryptedPayloadScheme::MlsRfc9420);
        let (key, authorization) = current_alice_evidence(&bob);
        assert_eq!(
            bob.open_signal_envelope(
                &envelope,
                EncryptedPayloadScheme::MlsRfc9420,
                &key,
                &authorization,
                GROUP_STATE_REF,
                &mut AeadNonceReplayTracker::new(),
            )
            .unwrap(),
            TYPING
        );
        assert!(
            bob.open_signal_envelope(
                &envelope,
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &key,
                &authorization,
                GROUP_STATE_REF,
                &mut AeadNonceReplayTracker::new(),
            )
            .is_err()
        );
        let binding = envelope.aead_binding();
        let domain = bob.verified_signal_sender_domain(&binding).unwrap();
        let suite = bob.signal_suite_for(&binding).unwrap();
        let standard_key = bob
            .derive_signal_key(&binding, EncryptedPayloadScheme::MlsRfc9420, &domain, suite)
            .unwrap();
        let history_key = bob
            .derive_signal_key(
                &binding,
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &domain,
                suite,
            )
            .unwrap();
        assert_ne!(&*standard_key, &*history_key);
        assert!(alice.history_secrets.is_empty());
        assert!(bob.history_secrets.is_empty());
    }

    #[test]
    fn current_authority_and_winning_leaf_must_name_the_same_key_event_and_account() {
        let (mut alice_group, mut bob_group) = alice_and_bob();
        let envelope = signed_envelope(&mut alice_group);
        let (key, authorization) = current_alice_evidence(&bob_group);
        let wrong_key = PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let replacement = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]);
        for (candidate_key, candidate_authorization, accepted_ref) in [
            (&wrong_key, &authorization, GROUP_STATE_REF),
            (&key, &replacement, GROUP_STATE_REF),
            (&key, &authorization, replacement.as_str()),
        ] {
            assert!(
                bob_group
                    .open_signal_envelope(
                        &envelope,
                        EncryptedPayloadScheme::MlsExporterAeadV1,
                        candidate_key,
                        candidate_authorization,
                        accepted_ref,
                        &mut AeadNonceReplayTracker::new()
                    )
                    .is_err()
            );
        }
        let mut leaves = bob_group.verified_leaf_bindings().unwrap();
        for leaf in &mut leaves {
            if leaf.actor_id == envelope.sender_actor_id {
                let mut account = leaf.actor_id.as_account_id().unwrap().clone();
                account.station_id =
                    DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
                leaf.actor_id = arkret_wire::ActorId::account(account);
            }
        }
        bob_group.install_verified_leaf_bindings(leaves).unwrap();
        assert!(
            bob_group
                .open_signal_envelope(
                    &envelope,
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &key,
                    &authorization,
                    GROUP_STATE_REF,
                    &mut AeadNonceReplayTracker::new()
                )
                .is_err()
        );
    }

    #[test]
    fn an_epoch_member_can_forge_sender_aead_but_not_the_producer_signature() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let mut envelope = signed_envelope(&mut alice_group);
        let (key, authorization) = current_alice_evidence(&bob_group);
        let binding = envelope.aead_binding();
        let sender_domain = bob_group.verified_signal_sender_domain(&binding).unwrap();
        let suite = bob_group.signal_suite_for(&binding).unwrap();
        let shared_key = bob_group
            .derive_signal_key(
                &binding,
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &sender_domain,
                suite,
            )
            .unwrap();
        let nonce = base64url_decode(&envelope.encrypted_payload.nonce).unwrap();
        let aad = binding
            .aad_bytes(&envelope.encrypted_payload.nonce)
            .unwrap();
        envelope.encrypted_payload.ciphertext = base64url_encode(
            suite
                .seal(&shared_key, &nonce, &aad, b"forged by another member")
                .unwrap(),
        );
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            &envelope.proof_binding_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            bob_group
                .open_signal_payload(
                    &envelope.aead_binding(),
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &envelope.encrypted_payload.nonce,
                    &envelope.encrypted_payload.ciphertext,
                    &mut AeadNonceReplayTracker::new()
                )
                .unwrap(),
            b"forged by another member"
        );
        let mut replay = AeadNonceReplayTracker::new();
        assert!(
            bob_group
                .open_signal_envelope(
                    &envelope,
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &key,
                    &authorization,
                    GROUP_STATE_REF,
                    &mut replay
                )
                .is_err()
        );
        // A rejected proof must not poison the honest sender's nonce slot.
        let mut honest = envelope.clone();
        honest.encrypted_payload.ciphertext =
            base64url_encode(suite.seal(&shared_key, &nonce, &aad, TYPING).unwrap());
        honest.proof.envelope_digest = honest.envelope_digest().unwrap();
        honest.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&ALICE_SIGNING_SEED),
            &honest.proof_binding_bytes().unwrap(),
        )
        .unwrap();
        assert!(
            bob_group
                .open_signal_envelope(
                    &honest,
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    &key,
                    &authorization,
                    GROUP_STATE_REF,
                    &mut replay
                )
                .is_ok()
        );
    }

    #[test]
    fn duplicate_device_domains_are_rejected_even_across_different_station_accounts() {
        let (mut alice, _) = alice_and_bob();
        let duplicate = ArkretMlsIdentity::new_test_human_device(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new(ALICE_DEVICE).unwrap(),
        )
        .unwrap();
        alice
            .add_member(&duplicate.key_package_record().unwrap())
            .unwrap();
        let mut leaves = alice.verified_leaf_bindings().unwrap();
        let mut index = 0;
        for leaf in &mut leaves {
            if matches!(&leaf.endpoint, MlsEndpointIdentity::HumanDevice { device_id, .. } if device_id.as_str() == ALICE_DEVICE)
            {
                let mut account = leaf.actor_id.as_account_id().unwrap().clone();
                account.station_id = DidCoreId::new(if index == 0 {
                    "ak:did_core:web:station.example"
                } else {
                    "ak:did_core:web:other-station.example"
                })
                .unwrap();
                leaf.actor_id = arkret_wire::ActorId::account(account);
                index += 1;
            }
        }
        assert_eq!(index, 2);
        alice.install_verified_leaf_bindings(leaves).unwrap();
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        assert!(
            alice
                .verified_signal_sender_domain(&parts.binding(alice.epoch()))
                .unwrap_err()
                .to_string()
                .contains("exactly one active MLS leaf")
        );
    }

    #[test]
    fn a_different_scope_cannot_borrow_the_same_epoch_group() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let mut parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);
        parts.realm_id =
            RealmId::new("ak:realm:AUhJ30wlw7UA5CWJk9HZUsDp0GyhA-QVSF565JjdtLul").unwrap();
        parts.scope_ref = ScopeRef::Realm {
            realm_id: parts.realm_id.clone(),
        };
        let binding = parts.binding(bob_group.epoch());
        assert!(
            alice_group
                .seal_signal_payload(&binding, EncryptedPayloadScheme::MlsExporterAeadV1, TYPING)
                .is_err()
        );
        assert!(
            bob_group
                .open_signal_payload(
                    &binding,
                    EncryptedPayloadScheme::MlsExporterAeadV1,
                    "AAAAAAAAAAAAAAAA",
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    &mut AeadNonceReplayTracker::new()
                )
                .is_err()
        );
    }

    #[test]
    fn bounds_and_epoch_are_enforced_before_sealing() {
        let (mut alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("ak:did_core:webvh:z6mkfixturealice", ALICE_DEVICE);

        let at_limit = alice_group
            .seal_signal_payload(
                &parts.binding(epoch),
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &vec![0; MAX_SIGNAL_PLAINTEXT_BYTES],
            )
            .unwrap();
        assert_eq!(
            at_limit.encrypted_payload.ciphertext.len(),
            arkret_wire::MAX_SIGNAL_CIPHERTEXT_CHARS
        );
        let oversized = vec![0u8; MAX_SIGNAL_PLAINTEXT_BYTES + 1];
        let error = alice_group
            .seal_signal_payload(
                &parts.binding(epoch),
                EncryptedPayloadScheme::MlsExporterAeadV1,
                &oversized,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("signal plaintext exceeds"), "{error}");

        // Neither the Signal key nor the sender prefix is derivable for an
        // epoch the MLS exporter no longer evaluates.
        let error = alice_group
            .seal_signal_payload(
                &parts.binding(epoch + 1),
                EncryptedPayloadScheme::MlsExporterAeadV1,
                TYPING,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("current epoch"), "{error}");
    }
}
