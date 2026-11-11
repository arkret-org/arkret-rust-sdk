//! Live Signal encryption over the current client-held MLS epoch.
//!
//! Signals never export, retain, or distribute prior-epoch material. The
//! key is derived directly from the current MLS exporter and the envelope is
//! bound to the exact head of its Realm/Circle/Sidecar commit stream.

use std::mem::size_of;

use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_crypto::{AeadNonceContext, AeadNonceReplayTracker, compose_aead_nonce};
use arkret_models_crypto::{ContentEndpoint, MlsEndpointIdentity};
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_signal_proof};
use arkret_wire::{
    EventId, MAX_SIGNAL_PLAINTEXT_BYTES, MlsWelcomeRecipientEndpoint, RealmCommitId, ReasonCode,
    SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME, SignalAeadBinding, SignalEncryptedPayload,
    SignalEnvelope, StationSigningKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::group::{ArkretMlsGroup, ExporterAeadSuite};
use crate::{MlsError as Error, Result};

/// An encrypted Signal payload plus the durable nonce counter it consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedSignalPayload {
    pub encrypted_payload: SignalEncryptedPayload,
    pub nonce_counter: u64,
}

/// Local counter continuity belongs to the exact verified encryption domain.
/// Missing counter state is not a fresh endpoint and must not deserialize as 0.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignalNonceCounter {
    pub(crate) context: Option<AeadNonceContext>,
    pub(crate) next: u64,
}

impl SignalNonceCounter {
    fn next_for(&self, context: &AeadNonceContext) -> u64 {
        if self.context.as_ref() == Some(context) {
            self.next
        } else {
            0
        }
    }

    pub(crate) fn merge(&self, other: &Self) -> Result<Self> {
        if self.context == other.context {
            return Ok(Self {
                context: self.context.clone(),
                next: self.next.max(other.next),
            });
        }
        match (&self.context, &other.context) {
            (None, _) if self.next == 0 => Ok(other.clone()),
            (_, None) if other.next == 0 => Ok(self.clone()),
            (Some(left), Some(right))
                if left.mls_group_id == right.mls_group_id && left.epoch != right.epoch =>
            {
                Ok(if left.epoch > right.epoch {
                    self.clone()
                } else {
                    other.clone()
                })
            }
            _ => Err(Error::Protocol(
                "frozen MLS state conflicts with its Signal nonce domain".into(),
            )),
        }
    }

    pub(crate) fn validate(&self, group_id: &arkret_wire::MlsGroupId, epoch: u64) -> Result<()> {
        match &self.context {
            None if self.next == 0 => Ok(()),
            Some(context) if &context.mls_group_id == group_id && context.epoch <= epoch => {
                let endpoint: ContentEndpoint = serde_json::from_str(&context.sender_domain)?;
                endpoint.validate()?;
                if arkret_canonical::canonical::canonical_json_bytes(&endpoint)?
                    != context.sender_domain.as_bytes()
                {
                    return Err(Error::Protocol(
                        "Signal nonce domain is not canonical".into(),
                    ));
                }
                Ok(())
            }
            _ => Err(Error::Protocol(
                "Signal nonce allocator continuity is missing or inconsistent".into(),
            )),
        }
    }
}

/// Independently resolved current authority for a Signal sender.
#[derive(Clone, Copy, Debug)]
pub enum SignalSenderAuthority<'a> {
    AccountDevice {
        public_key: &'a PublicKeyMaterial,
        device_authorize_event_id: &'a EventId,
    },
    Agent {
        public_key: &'a PublicKeyMaterial,
        verification_method: &'a arkret_wire::DidUrl,
        agent_key_authorize_event_id: &'a EventId,
    },
}

impl SignalSenderAuthority<'_> {
    fn public_key(&self) -> &PublicKeyMaterial {
        match self {
            Self::AccountDevice { public_key, .. } | Self::Agent { public_key, .. } => public_key,
        }
    }
}

impl ArkretMlsGroup {
    pub fn signal_nonce_counter(&self) -> u64 {
        self.signal_nonce_counter.next
    }

    /// Derive the local allocator domain only from the installed accepted leaf.
    pub fn local_signal_nonce_context(&self) -> Result<AeadNonceContext> {
        let endpoint = self.local_content_endpoint()?;
        endpoint.validate()?;
        Ok(AeadNonceContext {
            mls_group_id: self.group_id(),
            epoch: self.epoch(),
            sender_domain: String::from_utf8(arkret_canonical::canonical::canonical_json_bytes(
                &endpoint,
            )?)
            .map_err(|error| Error::Protocol(error.to_string()))?,
        })
    }

    /// Return the next safe floor for an external, atomically durable allocator.
    pub fn signal_nonce_reservation(&self) -> Result<(AeadNonceContext, u64)> {
        let context = self.local_signal_nonce_context()?;
        let next = self.signal_nonce_counter.next_for(&context);
        Ok((context, next))
    }

    /// Encrypt a Signal from the current epoch. The caller must persist the
    /// group snapshot after success so the nonce counter cannot rewind.
    pub fn encrypt_signal_payload(
        &mut self,
        binding: &SignalAeadBinding<'_>,
        plaintext: &[u8],
    ) -> Result<EncryptedSignalPayload> {
        self.encrypt_signal_payload_inner(binding, plaintext, None)
    }

    /// Consume an already durably reserved nonce. A different accepted domain or
    /// a stale reservation fails closed, and the caller must burn that value.
    pub fn encrypt_signal_payload_with_reserved_nonce(
        &mut self,
        binding: &SignalAeadBinding<'_>,
        plaintext: &[u8],
        context: &AeadNonceContext,
        counter: u64,
    ) -> Result<EncryptedSignalPayload> {
        self.encrypt_signal_payload_inner(binding, plaintext, Some((context, counter)))
    }

    fn encrypt_signal_payload_inner(
        &mut self,
        binding: &SignalAeadBinding<'_>,
        plaintext: &[u8],
        reservation: Option<(&AeadNonceContext, u64)>,
    ) -> Result<EncryptedSignalPayload> {
        binding.validate()?;
        if plaintext.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(Error::Protocol(format!(
                "signal plaintext exceeds {MAX_SIGNAL_PLAINTEXT_BYTES} bytes"
            )));
        }
        let suite = self.signal_suite_for(binding)?;
        if !self.local_signal_sender_matches(binding) {
            return Err(Error::Protocol(
                "signal sender does not match this MLS identity".to_owned(),
            ));
        }
        let sender_domain = self.verified_signal_sender_domain(binding)?;
        let context = signal_nonce_context(binding, &sender_domain)?;
        if context != self.local_signal_nonce_context()? {
            return Err(Error::Protocol(
                "Signal sender differs from the local accepted endpoint".into(),
            ));
        }
        let floor = self.signal_nonce_counter.next_for(&context);
        let counter = match reservation {
            Some((reserved_context, counter))
                if reserved_context == &context && counter >= floor =>
            {
                counter
            }
            None => floor,
            _ => {
                return Err(Error::Protocol(
                    "Signal nonce reservation is stale or belongs to another endpoint domain"
                        .into(),
                ));
            }
        };
        let nonce = signal_nonce(binding, &sender_domain, suite, counter)?;
        let next = counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("signal nonce counter overflow".to_owned()))?;
        self.signal_nonce_counter = SignalNonceCounter {
            context: Some(context),
            next,
        };

        let nonce_b64 = base64url_encode(&nonce);
        let aad = binding.aad_bytes(&nonce_b64)?;
        let key = self.derive_signal_key(binding, &sender_domain, suite)?;
        let ciphertext = suite.encrypt(&key, &nonce, &aad, plaintext)?;
        Ok(EncryptedSignalPayload {
            encrypted_payload: SignalEncryptedPayload {
                scheme: SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: binding.key_ref.clone(),
                purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: binding.aead_profile.to_owned(),
                epoch: binding.epoch,
                nonce: nonce_b64,
                ciphertext: base64url_encode(&ciphertext),
            },
            nonce_counter: counter,
        })
    }

    pub fn decrypt_signal_payload(
        &self,
        binding: &SignalAeadBinding<'_>,
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
                "{}: signal nonce has the wrong length",
                ReasonCode::AEAD_NONCE_DERIVATION_INVALID
            )));
        }
        let counter_offset = nonce_bytes.len() - size_of::<u64>();
        if nonce_bytes[..counter_offset].iter().any(|byte| *byte != 0) {
            return Err(Error::Protocol(format!(
                "{}: signal nonce is not a full-width counter",
                ReasonCode::AEAD_NONCE_DERIVATION_INVALID
            )));
        }
        let mut counter_bytes = [0_u8; size_of::<u64>()];
        counter_bytes.copy_from_slice(&nonce_bytes[counter_offset..]);
        let aad = binding.aad_bytes(nonce)?;
        let key = self.derive_signal_key(binding, &sender_domain, suite)?;
        let plaintext = suite.decrypt(&key, &nonce_bytes, &aad, &base64url_decode(ciphertext)?)?;
        replay.accept_counter(
            &signal_nonce_context(binding, &sender_domain)?,
            u64::from_be_bytes(counter_bytes),
        )?;
        Ok(plaintext)
    }

    /// Verify sender authority, exact group state and the exact independent
    /// stream head before opening a Signal envelope.
    pub fn open_signal_envelope(
        &self,
        envelope: &SignalEnvelope,
        current_authority: SignalSenderAuthority<'_>,
        accepted_group_state_ref: &str,
        accepted_authority_commit_id: &RealmCommitId,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        envelope.validate_structural()?;
        if envelope.encrypted_payload.key_ref.group_state_ref != accepted_group_state_ref
            || &envelope.authority_commit_id != accepted_authority_commit_id
        {
            return Err(Error::Protocol(
                "signal does not bind the accepted MLS state and independent stream head"
                    .to_owned(),
            ));
        }
        let leaf = self.verified_signal_sender_leaf(&envelope.aead_binding())?;
        let authority_matches_leaf = match (&current_authority, &leaf.endpoint) {
            (
                SignalSenderAuthority::AccountDevice {
                    device_authorize_event_id,
                    ..
                },
                MlsEndpointIdentity::HumanDevice { .. },
            ) => leaf.device_authorize_event_id.as_ref() == Some(*device_authorize_event_id),
            (
                SignalSenderAuthority::Agent {
                    verification_method,
                    agent_key_authorize_event_id,
                    ..
                },
                MlsEndpointIdentity::AgentRuntime {
                    verification_method: leaf_method,
                    agent_key_authorize_event_id: leaf_authorize_event_id,
                    ..
                },
            ) => {
                envelope.proof.verification_method == **verification_method
                    && leaf_method == *verification_method
                    && leaf_authorize_event_id == *agent_key_authorize_event_id
            }
            _ => false,
        };
        if !authority_matches_leaf {
            return Err(Error::Protocol(
                "signal current endpoint authority differs from the accepted MLS leaf".to_owned(),
            ));
        }
        verify_ed25519_signal_proof(envelope, current_authority.public_key())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        self.decrypt_signal_payload(
            &envelope.aead_binding(),
            &envelope.encrypted_payload.nonce,
            &envelope.encrypted_payload.ciphertext,
            replay,
        )
    }

    /// Open under the current signing-key projection delivered by the
    /// authenticated recipient Station, independently of the MLS leaf key.
    pub fn open_signal_envelope_with_station_key(
        &self,
        envelope: &SignalEnvelope,
        key: &StationSigningKey,
        accepted_group_state_ref: &str,
        accepted_authority_commit_id: &RealmCommitId,
        replay: &mut AeadNonceReplayTracker,
    ) -> Result<Vec<u8>> {
        key.validate()?;
        if key.actor != envelope.sender_actor_id
            || key.verification_method != envelope.proof.verification_method
        {
            return Err(Error::Protocol(
                "Signal Station key does not bind the exact sender".into(),
            ));
        }
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: base64url_decode(key.public_key_base64url.as_str())?,
        };
        let authority = match &envelope.sender_device_id {
            Some(device) => {
                if key
                    .verification_method
                    .as_str()
                    .split_once('#')
                    .map(|(_, fragment)| fragment)
                    != Some(device.as_str())
                {
                    return Err(Error::Protocol(
                        "Signal Station key names another Device".into(),
                    ));
                }
                SignalSenderAuthority::AccountDevice {
                    public_key: &public_key,
                    device_authorize_event_id: &key.authorization_ref,
                }
            }
            None => SignalSenderAuthority::Agent {
                public_key: &public_key,
                verification_method: &key.verification_method,
                agent_key_authorize_event_id: &key.authorization_ref,
            },
        };
        self.open_signal_envelope(
            envelope,
            authority,
            accepted_group_state_ref,
            accepted_authority_commit_id,
            replay,
        )
    }

    fn signal_suite_for(&self, binding: &SignalAeadBinding<'_>) -> Result<ExporterAeadSuite> {
        if self.group_id() != binding.scope_ref.canonical_mls_group_id()? {
            return Err(Error::Protocol(
                "signal scope does not name this MLS group".to_owned(),
            ));
        }
        let suite = ExporterAeadSuite::resolve(binding.aead_profile)?;
        if self.group_ciphersuite_canonical_id()? != binding.aead_profile
            || binding.epoch != self.epoch()
        {
            return Err(Error::Protocol(
                "signal ciphersuite or epoch differs from the current MLS state".to_owned(),
            ));
        }
        Ok(suite)
    }

    fn derive_signal_key(
        &self,
        binding: &SignalAeadBinding<'_>,
        verified_sender_domain: &[u8],
        suite: ExporterAeadSuite,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let root = self.export_secret(
            arkret_wire::ExporterLabelId::SIGNAL_ROOT_V1,
            &binding.scope_ref.canonical_effective_scope_key_bytes()?,
            32,
        )?;
        let key = arkret_crypto::mls_exporter::mls_expand_with_label(
            &root,
            arkret_wire::ExporterLabelId::SIGNAL_V1,
            verified_sender_domain,
            suite.key_len(),
        )
        .map_err(|error| Error::Crypto(error.to_string()))?;
        Ok(Zeroizing::new(key))
    }

    fn local_signal_sender_matches(&self, binding: &SignalAeadBinding<'_>) -> bool {
        match &self.identity.endpoint {
            MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => {
                binding.sender_actor_id.as_account_id().is_some()
                    && binding.sender_actor_id.signing_principal_id() == principal_id
                    && binding.sender_device_id == Some(device_id)
            }
            MlsEndpointIdentity::AgentRuntime { agent_id, .. } => {
                binding.sender_actor_id.signing_principal_id() == agent_id
                    && binding.sender_device_id.is_none()
            }
        }
    }

    fn verified_signal_sender_domain(&self, binding: &SignalAeadBinding<'_>) -> Result<Vec<u8>> {
        let leaf = self.verified_signal_sender_leaf(binding)?;
        let (endpoint, authorization_event_ref) = match &leaf.endpoint {
            MlsEndpointIdentity::HumanDevice { device_id, .. } => (
                MlsWelcomeRecipientEndpoint::Device {
                    device_id: device_id.clone(),
                },
                leaf.device_authorize_event_id.clone().ok_or_else(|| {
                    Error::Protocol("Signal Device leaf omits its authorization Event".into())
                })?,
            ),
            MlsEndpointIdentity::AgentRuntime {
                verification_method,
                agent_key_authorize_event_id,
                ..
            } => (
                MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method: verification_method.clone(),
                },
                agent_key_authorize_event_id.clone(),
            ),
        };
        let endpoint = ContentEndpoint {
            actor_id: leaf.actor_id,
            endpoint,
            authorization_event_ref,
            signature_key_base64url: leaf.signature_key.to_string(),
        };
        endpoint.validate()?;
        arkret_canonical::canonical::canonical_json_bytes(&endpoint).map_err(Into::into)
    }

    fn verified_signal_sender_leaf(
        &self,
        binding: &SignalAeadBinding<'_>,
    ) -> Result<crate::group::MlsVerifiedLeafBinding> {
        let matching = self
            .verified_leaf_bindings()?
            .into_iter()
            .filter(|leaf| {
                &leaf.actor_id == binding.sender_actor_id
                    && match (&leaf.endpoint, binding.sender_device_id) {
                        (
                            MlsEndpointIdentity::HumanDevice { device_id, .. },
                            Some(sender_device_id),
                        ) => device_id == sender_device_id,
                        (MlsEndpointIdentity::AgentRuntime { agent_id, .. }, None) => {
                            agent_id == binding.sender_actor_id.signing_principal_id()
                        }
                        _ => false,
                    }
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Error::Protocol(
                "signal sender does not resolve to exactly one active MLS leaf".to_owned(),
            ));
        }
        let leaf = matching.into_iter().next().expect("one verified leaf");
        if &leaf.actor_id != binding.sender_actor_id {
            return Err(Error::Protocol(
                "signal sender differs from the accepted MLS leaf actor".to_owned(),
            ));
        }
        Ok(leaf)
    }
}

fn signal_nonce(
    binding: &SignalAeadBinding<'_>,
    verified_sender_domain: &[u8],
    suite: ExporterAeadSuite,
    counter: u64,
) -> Result<Vec<u8>> {
    signal_nonce_context(binding, verified_sender_domain)?;
    compose_aead_nonce(counter, suite.nonce_len()).map_err(Into::into)
}

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
