//! `ak.signal_exporter_aead.v1` — the Signal rail's exporter AEAD
//! (`zh/sync/signal.md` §1, `zh/conformance/encoding.md` §10.1 / §10.2).
//!
//! Sibling construction to the `mls_exporter_aead_v1` content scheme in
//! [`crate::group`]: both hang off the same per-epoch `history_secret`, and the
//! registered label is the only thing separating them under one group and
//! epoch. The parameters are *not* shared, and assuming they are is the easiest
//! way to get this wrong:
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
//! history_secret[N] = MLS-Exporter("ak.history-v1", realm_id, KDF.Nh)
//! K_signal[N]       = ExpandWithLabel(history_secret[N], "ak.signal-v1", "", AEAD.Nk)
//! prefix            = MLS-Exporter("arkret-aead-sender-nonce-prefix-v1",
//!                                  JCS({key_ref, epoch, device_id, purpose, aead_profile}),
//!                                  N_AEAD - 8)
//! nonce             = prefix || device_nonce_counter_be64
//! AAD               = JCS(pre-encryption immutable header)   // §10.2
//! ```

use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_crypto::{
    AEAD_NONCE_COUNTER_LEN, AEAD_NONCE_EXPORTER_LABEL, AeadNonceContext, AeadNonceReplayTracker,
    aead_sender_nonce_context_bytes, compose_aead_nonce,
};
use arkret_wire::{
    Hash, MAX_SIGNAL_PLAINTEXT_BYTES, ReasonCode, SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME,
    SignalAeadBinding, SignalEncryptedPayload, SignalEnvelope, canonical,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::group::{ArkretMlsGroup, ExporterAeadSuite, mls_kdf_label};
use crate::{MlsError as Error, Result};

/// `ExpandWithLabel` label deriving the per-epoch Signal key from the
/// `history_secret`, registered in `exporter-label-registry.json` with an empty
/// `context_fields` — exactly like `ak.content-v1`, because the group already
/// binds the Realm or Circle and the label is the only separator still needed.
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
    pub fn seal_signal_payload(
        &mut self,
        binding: &SignalAeadBinding<'_>,
        plaintext: &[u8],
    ) -> Result<SignalSeal> {
        binding.validate()?;
        if plaintext.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(Error::Protocol(format!(
                "signal plaintext exceeds {MAX_SIGNAL_PLAINTEXT_BYTES} bytes"
            )));
        }
        let suite = self.signal_suite_for(binding)?;
        // §10.1 cross-device domain separation is only meaningful if the
        // declared sender is the device that actually derives the prefix. A
        // caller sealing under someone else's device id would mint a nonce in
        // that device's domain.
        if binding.sender_device_id != &self.identity.device_id {
            return Err(Error::Protocol(format!(
                "{}: signal sender_device_id does not match this device",
                ReasonCode::AEAD_NONCE_SENDER_DOMAIN_COLLISION
            )));
        }

        let counter = self.signal_nonce_counter;
        let nonce = self.signal_nonce(binding, suite, counter)?;
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
        let key = self.derive_signal_key(binding, suite)?;
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
    /// Performs, in order, the three receiver duties §10.1 names: recompute the
    /// sender prefix for the *declared* sender and reject a mismatch
    /// (`aead_nonce_sender_domain_collision`), reject a repeated counter
    /// (`aead_nonce_counter_replay`), then open under the recomputed AAD.
    pub fn open_signal_payload(
        &self,
        binding: &SignalAeadBinding<'_>,
        nonce: &str,
        ciphertext: &str,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        binding.validate()?;
        let suite = self.signal_suite_for(binding)?;

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
        let prefix_len = suite.nonce_prefix_len();
        let expected_prefix = self.signal_nonce_prefix(binding, suite)?;
        if nonce_bytes[..prefix_len] != expected_prefix[..] {
            return Err(Error::Protocol(format!(
                "{}: signal sender_nonce_prefix does not match the declared sender device",
                ReasonCode::AEAD_NONCE_SENDER_DOMAIN_COLLISION
            )));
        }
        let mut counter_bytes = [0u8; AEAD_NONCE_COUNTER_LEN];
        counter_bytes.copy_from_slice(&nonce_bytes[prefix_len..]);
        replay.accept_counter(
            &signal_nonce_context(binding)?,
            u64::from_be_bytes(counter_bytes),
        )?;

        // Recomputed from the header we just validated — never the sender's
        // self-reported `aad_digest` (§10.2).
        let aad = binding.aad_bytes(nonce)?;
        let key = self.derive_signal_key(binding, suite)?;
        suite.open(&key, &nonce_bytes, &aad, &base64url_decode(ciphertext)?)
    }

    /// Validate a received [`SignalEnvelope`] and open its payload.
    ///
    /// The one-call receive path, so the envelope-level checks
    /// ([`SignalEnvelope::validate_structural`]: TTL ceilings, scope/realm
    /// agreement, size bounds, `envelope_digest` and the carried `aad_digest`)
    /// cannot be forgotten before decryption. Signature verification and the
    /// `seal_ref`-relative device authorization lookup still belong to the
    /// caller: they need key material and accepted state this crate does not
    /// hold.
    pub fn open_signal_envelope(
        &self,
        envelope: &SignalEnvelope,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        envelope.validate_structural()?;
        self.open_signal_payload(
            &envelope.aead_binding(),
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

    /// `K_signal[N] = ExpandWithLabel(history_secret[N], "ak.signal-v1", "", AEAD.Nk)`.
    ///
    /// The `history_secret` is derived without retaining it: a Signal is
    /// ephemeral and must not make its epoch shareable history.
    fn derive_signal_key(
        &self,
        binding: &SignalAeadBinding<'_>,
        suite: ExporterAeadSuite,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let history_secret = self.derive_history_secret(binding.realm_id.as_str())?;
        derive_signal_key(&history_secret, suite.key_len())
    }

    /// `nonce = sender_nonce_prefix || device_nonce_counter_be64` (§10.1).
    fn signal_nonce(
        &self,
        binding: &SignalAeadBinding<'_>,
        suite: ExporterAeadSuite,
        counter: u64,
    ) -> Result<Vec<u8>> {
        let prefix = self.signal_nonce_prefix(binding, suite)?;
        Ok(compose_aead_nonce(&prefix, counter))
    }

    /// The per-sender prefix, straight from the MLS exporter.
    ///
    /// Label and Context are the registry row verbatim: label
    /// `arkret-aead-sender-nonce-prefix-v1`, Context the canonical bytes of
    /// `{key_ref, epoch, device_id, purpose, aead_profile}`. The row forbids an
    /// empty Context, and [`aead_sender_nonce_context_bytes`] rejects a context
    /// missing any member before it reaches the exporter.
    fn signal_nonce_prefix(
        &self,
        binding: &SignalAeadBinding<'_>,
        suite: ExporterAeadSuite,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let context_bytes = aead_sender_nonce_context_bytes(&signal_nonce_context(binding)?)?;
        self.export_secret(
            AEAD_NONCE_EXPORTER_LABEL,
            &context_bytes,
            suite.nonce_prefix_len(),
        )
    }
}

/// The §10.1 exporter Context for this domain, built from the header the AAD
/// also authenticates — so a receiver reconstructs it from what it verified.
fn signal_nonce_context(binding: &SignalAeadBinding<'_>) -> Result<AeadNonceContext> {
    Ok(AeadNonceContext {
        key_ref: serde_json::to_value(binding.key_ref)?,
        epoch: binding.epoch,
        device_id: binding.sender_device_id.as_str().to_owned(),
        purpose: binding.purpose.to_owned(),
        aead_profile: binding.aead_profile.to_owned(),
    })
}

/// `ExpandWithLabel(history_secret, "ak.signal-v1", "", AEAD.Nk)`.
///
/// Expand-only, no Extract: the `history_secret` is an MLS exporter output and
/// already has full entropy, which is what `ExpandWithLabel` assumes of its
/// Secret input.
fn derive_signal_key(history_secret: &[u8], key_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hkdf = Hkdf::<Sha256>::from_prk(history_secret)
        .map_err(|_| Error::Crypto("history_secret too short for HKDF PRK".to_owned()))?;
    let info = mls_kdf_label(key_len, SIGNAL_KEY_LABEL, &[])?;
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| Error::Crypto("signal key derivation failed".to_owned()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        DeviceId, Did, DidUrl, RealmId, ScopeRef, SealId, SignalClass, SignalKeyRef, SignalProof,
        proof_kind,
    };
    use chrono::{DateTime, Duration, TimeZone, Utc};

    use super::*;
    use crate::identity::{ARKRET_MLS_CIPHERSUITE_CANONICAL_ID, ArkretMlsIdentity};

    const REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000042";
    const GROUP_STATE_REF: &str = "ak:event:01904100-0000-7000-8000-cccccccccccc";
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000006";
    const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000e";
    const TYPING: &[u8] = br#"{"kind":"typing"}"#;
    /// `derive_signal_key(history_secret_of_the_content_key_vector, 16)`.
    const SIGNAL_KEY_ANCHOR_HEX: &str = "6c24824085cbce6c08585acf5b343a51";
    /// Canonical §10.2 AAD for the fixture header at `epoch=7`, all-zero nonce.
    const SIGNAL_AAD_ANCHOR: &str = concat!(
        "{\"aead_profile\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519\",",
        "\"epoch\":7,",
        "\"expires_at\":\"2026-07-28T12:00:30.000Z\",",
        "\"key_ref\":{\"algorithm\":\"MLS-EXPORTER-AEAD\",",
        "\"group_state_ref\":\"ak:event:01904100-0000-7000-8000-cccccccccccc\"},",
        "\"nonce\":\"AAAAAAAAAAAAAAAA\",",
        "\"purpose\":\"ak.signal.v1\",",
        "\"realm_id\":\"ak:realm:01904100-0000-7000-8000-000000000042\",",
        "\"scheme\":\"ak.signal_exporter_aead.v1\",",
        "\"scope_ref\":{\"kind\":\"realm\",",
        "\"realm_id\":\"ak:realm:01904100-0000-7000-8000-000000000042\"},",
        "\"seal_ref\":\"ak:seal:sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
        "\"sender_actor_id\":\"did:webvh:z6mkfixture:alice.example\",",
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
        sender_actor_id: Did,
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
                sender_actor_id: Did::new(sender_actor.to_owned()).unwrap(),
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
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            DeviceId::new(ALICE_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example".to_owned()).unwrap(),
            DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice.create_group(REALM.as_bytes()).unwrap();
        let add = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();
        assert_eq!(alice_group.epoch(), bob_group.epoch());
        (alice_group, bob_group)
    }

    /// Every wire-breaking parameter of the `ak.signal-v1` key derivation,
    /// checked against the registry rows rather than against this module.
    ///
    /// `exporter-label-registry.json` fixes the label and an EMPTY
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
        assert!(descriptor.context_fields.is_empty());

        let suite = ExporterAeadSuite::resolve(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap();
        assert_eq!(suite.key_len(), 16);
        assert_eq!(suite.nonce_len(), 12);
        assert_eq!(suite.nonce_prefix_len(), 4);
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
        expected.push(0);
        assert_eq!(
            mls_kdf_label(suite.key_len(), SIGNAL_KEY_LABEL, &[]).unwrap(),
            expected
        );
        assert_eq!(
            hex(&expected),
            "0010144d4c5320312e3020616b2e7369676e616c2d763100"
        );
    }

    /// The Signal key and the content key hang off the same `history_secret`
    /// under the same group and epoch, so the registered label is the ONLY
    /// thing keeping them apart. Anchored on the `history_secret` the
    /// registered content-key vector produces, so a drift in the shared part
    /// of the chain surfaces here too.
    #[test]
    fn signal_key_is_domain_separated_from_the_content_key() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/arkret-private-kdf-fixture.json")
                .unwrap();
        let case = &fixture["cases"][0];
        let history_secret =
            hex::decode(case["expected"]["history_secret_hex"].as_str().unwrap()).unwrap();
        let content_key_hex = case["expected"]["content_key_hex"].as_str().unwrap();

        let signal_key = derive_signal_key(&history_secret, 16).unwrap();
        assert_eq!(signal_key.len(), 16);
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

    /// `nonce = sender_nonce_prefix || device_nonce_counter_be64` with an
    /// 8-byte unsigned big-endian counter, and two senders under one
    /// `(key_ref, epoch, purpose, aead_profile)` derive distinct prefixes.
    #[test]
    fn nonce_is_the_exporter_prefix_followed_by_a_be64_counter() {
        let (alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let alice_parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);
        let bob_parts = BindingParts::new("did:webvh:z6mkfixture:bob.example", BOB_DEVICE);
        let suite = ExporterAeadSuite::resolve(ARKRET_MLS_CIPHERSUITE_CANONICAL_ID).unwrap();

        let nonce = alice_group
            .signal_nonce(&alice_parts.binding(epoch), suite, 0x0102_0304_0506_0708)
            .unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(&nonce[4..], &0x0102_0304_0506_0708u64.to_be_bytes());

        let alice_prefix = alice_group
            .signal_nonce_prefix(&alice_parts.binding(epoch), suite)
            .unwrap();
        let bob_prefix = alice_group
            .signal_nonce_prefix(&bob_parts.binding(epoch), suite)
            .unwrap();
        assert_eq!(alice_prefix.len(), 4);
        assert_ne!(
            alice_prefix, bob_prefix,
            "per-sender nonce prefixes MUST differ under one key_ref/epoch/purpose"
        );
    }

    /// The AEAD AAD is the canonical bytes of the pre-encryption immutable
    /// header — the exact closed field set `encoding.md` §10.2 tabulates for
    /// `ak.signal_exporter_aead.v1`, and nothing that depends on AEAD output.
    #[test]
    fn aad_is_the_canonical_pre_encryption_immutable_header() {
        let parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);
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
        let parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);
        let binding = parts.binding(epoch);

        let seal = alice_group.seal_signal_payload(&binding, TYPING).unwrap();
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
                &seal.encrypted_payload.nonce,
                &seal.encrypted_payload.ciphertext,
                &mut replay,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("aead_nonce_counter_replay"), "{error}");
    }

    /// A ciphertext whose nonce prefix is not the declared sender's MUST fail
    /// closed, and a sender MUST NOT be able to mint a nonce inside another
    /// device's domain in the first place.
    #[test]
    fn sender_nonce_domain_is_enforced_in_both_directions() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let alice_parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);
        let bob_parts = BindingParts::new("did:webvh:z6mkfixture:bob.example", BOB_DEVICE);

        let error = alice_group
            .seal_signal_payload(&bob_parts.binding(epoch), b"spoof")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("aead_nonce_sender_domain_collision"),
            "{error}"
        );

        let seal = alice_group
            .seal_signal_payload(&alice_parts.binding(epoch), TYPING)
            .unwrap();
        // Re-declare Alice's ciphertext as Bob's: the prefix no longer matches
        // the sender the AAD names.
        let error = bob_group
            .open_signal_payload(
                &bob_parts.binding(epoch),
                &seal.encrypted_payload.nonce,
                &seal.encrypted_payload.ciphertext,
                &mut AeadNonceReplayTracker::new(),
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("aead_nonce_sender_domain_collision"),
            "{error}"
        );
    }

    /// The counter is monotonic per device and MUST survive persistence:
    /// §10.1 forbids a device that lost its counter from restarting at 0 in
    /// the same epoch.
    #[test]
    fn nonce_counter_is_monotonic_and_persisted() {
        let (mut alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);

        let mut nonces = Vec::new();
        for expected_counter in 0..3u64 {
            let seal = alice_group
                .seal_signal_payload(&parts.binding(epoch), TYPING)
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
    #[test]
    fn sealed_payload_completes_a_valid_signal_envelope() {
        let (mut alice_group, bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);
        let binding = parts.binding(epoch);
        let seal = alice_group.seal_signal_payload(&binding, TYPING).unwrap();

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
                    "{}#{}",
                    parts.sender_actor_id, parts.sender_device_id
                ))
                .unwrap(),
                alg: "EdDSA".to_owned(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: binding.sent_at,
                domain: None,
                audience: None,
                jws: "a..b".to_owned(),
            },
        };
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope.validate_structural().unwrap();

        assert_eq!(
            bob_group
                .open_signal_envelope(&envelope, &mut AeadNonceReplayTracker::new())
                .unwrap(),
            TYPING
        );
    }

    #[test]
    fn bounds_and_epoch_are_enforced_before_sealing() {
        let (mut alice_group, _bob_group) = alice_and_bob();
        let epoch = alice_group.epoch();
        let parts = BindingParts::new("did:webvh:z6mkfixture:alice.example", ALICE_DEVICE);

        let oversized = vec![0u8; MAX_SIGNAL_PLAINTEXT_BYTES + 1];
        let error = alice_group
            .seal_signal_payload(&parts.binding(epoch), &oversized)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signal plaintext exceeds"), "{error}");

        // Neither the Signal key nor the sender prefix is derivable for an
        // epoch the MLS exporter no longer evaluates.
        let error = alice_group
            .seal_signal_payload(&parts.binding(epoch + 1), TYPING)
            .unwrap_err()
            .to_string();
        assert!(error.contains("current epoch"), "{error}");
    }
}
