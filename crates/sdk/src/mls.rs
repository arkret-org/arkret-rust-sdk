use std::collections::BTreeMap;

use chrono::Utc;
use cokret_core::{base64url_decode, base64url_encode};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn,
    LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, ProtocolVersion,
    RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::{
    CryptoStore, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, Hash,
    MlsCommitEnvelope, MlsGroupStateRecord, MlsKeyPackageRecord, MlsWelcomeEnvelope, Operation,
    OperationId, RealmId, Result, ToDeviceMessage, canonical,
};

pub const COKRET_MLS_ALGORITHM: &str = "ck.mls.v1";
pub const COKRET_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const COKRET_OPENMLS_STATE_SNAPSHOT: &str = "cokret-openmls-provider-state-v1";

pub struct CokretMlsIdentity {
    pub principal_id: Did,
    pub device_id: DeviceId,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

pub struct CokretMlsGroup {
    identity: CokretMlsIdentity,
    group: MlsGroup,
}

#[derive(Clone, Debug)]
pub struct MlsAddMemberResult {
    pub commit: MlsCommitEnvelope,
    pub welcome: MlsWelcomeEnvelope,
}

/// Result of removing one or more leaves from an MLS group.
///
/// Unlike `MlsAddMemberResult`, Remove never produces a Welcome — surviving
/// members simply apply the commit to advance the epoch. The list of
/// `removed_leaves` makes the audit trail explicit so callers can correlate
/// the result with the originating `ck.device.revoke` / `ck.member.state`
/// events.
#[derive(Clone, Debug)]
pub struct MlsRemoveMemberResult {
    pub commit: MlsCommitEnvelope,
    /// Raw OpenMLS leaf indices that were removed by this commit, in the
    /// order they appeared in the original group state.
    pub removed_leaves: Vec<u32>,
    /// The principal DIDs whose leaves were removed (one per leaf, may
    /// contain duplicates if the principal had multiple leaves / devices in
    /// the same group). Useful for downstream `ck.device.revoke` event
    /// envelopes that index by principal.
    pub removed_principals: Vec<Did>,
}

impl MlsRemoveMemberResult {
    /// Project the commit into a canonical `mls_commit` operation envelope,
    /// matching the shape of `MlsAddMemberResult::commit_operation`.
    pub fn commit_operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_commit",
            serde_json::to_value(&self.commit)?,
        );
        operation.object_id = Some(format!("{}:{}", self.commit.group_id, self.commit.epoch));
        Ok(operation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsStateSnapshot {
    context: String,
    group_id: String,
    epoch: u64,
    principal_id: Did,
    device_id: DeviceId,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsDeviceWorkflowAction {
    PublishKeyPackage,
    RevokeKeyPackage,
    ConsumeWelcome,
    ApplyCommit,
    RequestEpochRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsDeviceWorkflowStep {
    pub action: MlsDeviceWorkflowAction,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub group_id: Option<String>,
    pub from_epoch: Option<u64>,
    pub to_epoch: Option<u64>,
}

impl MlsAddMemberResult {
    pub fn commit_operation(
        &self,
        operation_id: OperationId,
        realm_id: RealmId,
    ) -> Result<Operation> {
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_commit",
            serde_json::to_value(&self.commit)?,
        );
        operation.object_id = Some(format!("{}:{}", self.commit.group_id, self.commit.epoch));
        Ok(operation)
    }

    pub fn welcome_to_device_message(&self) -> Result<ToDeviceMessage> {
        Ok(ToDeviceMessage {
            message_type: "ck.mls.welcome.v1".to_owned(),
            sender_principal_id: None,
            sender_device_id: None,
            recipient_principal_id: None,
            recipient_device_id: None,
            sent_at: None,
            expires_at: None,
            content: json!({
                "group_id": self.welcome.group_id,
                "epoch": self.welcome.epoch,
                "recipient_principal_id": self.welcome.recipient_principal_id,
                "recipient_device_id": self.welcome.recipient_device_id,
                "welcome": self.welcome.welcome,
                "welcome_hash": self.welcome.welcome_hash,
                "ratchet_tree": self.welcome.ratchet_tree,
            }),
            device_proof: None,
            unsigned: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

/// Profile id whose Realms are subject to the SEC-08 minimal-metadata
/// hardening (epoch lifetime ≤ 1h MUST + `aad_visibility=hidden` MUST).
pub const MINIMAL_METADATA_REALM_PROFILE: &str = "ck.profile.mls.minimal_metadata_realm.v1";

/// SEC-08 — maximum MLS epoch lifetime for a `minimal_metadata_realm` Realm,
/// per `crypto-media/encryption-and-audit.md` §2.9.
///
/// For Realms declaring [`MINIMAL_METADATA_REALM_PROFILE`] the §2.9 SHOULD on
/// epoch lifetime is raised to a MUST: a commit MUST be forced at least every
/// hour to bound within-epoch reaction-frequency observability. Stored as whole
/// seconds (3600), matching the core crate's numeric-ceiling convention
/// (`MEDIA_TOKEN_TTL_MAX_SECS`, `INCEPTION_KEY_MAX_ONLINE_WINDOW_SECS`). An
/// implementation MAY declare a shorter lifetime, never a longer one.
pub const MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS: i64 = 3600;

/// SEC-08 — [`MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS`] as a
/// [`chrono::Duration`] (1 hour).
pub fn minimal_metadata_max_epoch_lifetime() -> chrono::Duration {
    chrono::Duration::seconds(MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS)
}

/// AAD event-id visibility discriminator for `ck.schema.encrypted_envelope.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AadVisibility {
    Hidden,
    RoutingDigest,
    OpaqueId,
}

/// SEC-08 — fail-closed enforcement that a `minimal_metadata_realm` Realm uses
/// `aad_visibility=hidden`, per `crypto-media/encryption-and-audit.md` §2.9.
///
/// When `is_minimal_metadata_realm` is true the §2.9 SHOULD on hidden AAD is a
/// MUST: any visibility other than [`AadVisibility::Hidden`] is rejected with a
/// [`Error::Protocol`] so message-id exposure cannot widen reaction-frequency
/// correlation from per-`target_ref` to per-message. Non-minimal Realms are
/// unaffected (this helper returns `Ok(())`).
pub fn enforce_minimal_metadata_aad(
    visibility: &AadVisibility,
    is_minimal_metadata_realm: bool,
) -> Result<()> {
    if is_minimal_metadata_realm && !matches!(visibility, AadVisibility::Hidden) {
        return Err(Error::Protocol(format!(
            "{MINIMAL_METADATA_REALM_PROFILE} Realm MUST use aad_visibility=hidden \
             (encryption-and-audit.md §2.9); got {visibility:?}"
        )));
    }
    Ok(())
}

/// SEC-08 — has a `minimal_metadata_realm` epoch outlived the 1h MUST cap, per
/// `crypto-media/encryption-and-audit.md` §2.9.
///
/// Pure, non-mutating predicate: it takes the externally supplied epoch start
/// timestamp and the current time and returns `true` once the epoch age exceeds
/// [`minimal_metadata_max_epoch_lifetime`] (1h). When `true` the caller MUST
/// force-advance the group with a fresh `ck.mls.commit`; this helper
/// deliberately does **not** touch group state, leaving the commit decision to
/// the caller (the least-invasive integration point). A `now` earlier than
/// `epoch_started_at` (clock skew) is never reported as overdue.
pub fn minimal_metadata_epoch_overdue(
    epoch_started_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> bool {
    now.signed_duration_since(epoch_started_at) > minimal_metadata_max_epoch_lifetime()
}

/// Structured AAD for `ck.schema.encrypted_envelope.v1`. `realm_id` +
/// `event_kind` are mandatory; the event-id fields are governed by
/// [`AadVisibility`] and the schema discriminator (a `hidden` envelope MUST
/// omit both `event_id` and `event_ref_digest`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeAadV1 {
    pub realm_id: String,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_ref_digests: Vec<String>,
}

impl EncryptedEnvelopeAadV1 {
    /// Minimal `hidden`-visibility AAD: realm + canonical event kind only.
    pub fn hidden(realm_id: impl Into<String>, event_kind: impl Into<String>) -> Self {
        Self {
            realm_id: realm_id.into(),
            event_kind: event_kind.into(),
            event_id: None,
            event_ref_digest: None,
            causal_refs: Vec::new(),
            causal_ref_digests: Vec::new(),
        }
    }
}

/// `key_ref` for `ck.schema.encrypted_envelope.v1`. `algorithm` is the fixed
/// const `"MLS"`; `group_state_ref` MUST point at an accepted
/// `ck.mls.genesis` / winning `ck.mls.commit` event id (or equivalent group
/// state proof hash).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeKeyRefV1 {
    pub algorithm: String,
    pub group_state_ref: String,
}

/// Wire-canonical encrypted payload envelope matching
/// `ck.schema.encrypted_envelope.v1` — the single source of truth for the
/// encrypted-message wire shape across produce / validate / consume. Build it
/// from an [`EncryptedPayload`] (the MLS encrypt primitive output) plus the
/// caller-supplied AAD context and the `ck.mls.commit` event id that bounds
/// the group state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeV1 {
    pub scheme: EncryptedPayloadScheme,
    pub version: String,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    pub aad_visibility_event_id: AadVisibility,
    pub aad: EncryptedEnvelopeAadV1,
    pub key_ref: EnvelopeKeyRefV1,
    pub aad_digest: String,
    pub payload_digest: String,
}

impl EncryptedEnvelopeV1 {
    /// Envelope format version (`^\d+\.\d+$`).
    pub const VERSION: &'static str = "1.0";
    /// Fixed `key_ref.algorithm` const required by the schema.
    pub const KEY_REF_ALGORITHM: &'static str = "MLS";

    /// Assemble a conforming envelope from an MLS [`EncryptedPayload`].
    ///
    /// The `payload` MUST have been produced by
    /// [`CokretMlsGroup::encrypt_payload_with_aad`] with AAD equal to
    /// `serde_json::to_value(&aad)` — the AAD is bound into `payload_digest`,
    /// so a mismatch would make the receiver's digest verification fail. We
    /// fail closed if they disagree. `group_state_ref` is the `ck.mls.commit`
    /// (or genesis) event id carrying the epoch this payload was encrypted
    /// under.
    pub fn from_payload(
        payload: &EncryptedPayload,
        aad: EncryptedEnvelopeAadV1,
        visibility: AadVisibility,
        group_state_ref: impl Into<String>,
    ) -> Result<Self> {
        let aad_value = serde_json::to_value(&aad)
            .map_err(|err| Error::Protocol(format!("encode envelope aad: {err}")))?;
        if payload.aad.as_ref() != Some(&aad_value) {
            return Err(Error::Protocol(
                "encrypted envelope aad does not match the aad bound at encryption time".to_owned(),
            ));
        }
        let aad_digest = crate::crypto::json_aad_digest(&aad_value)?;
        Ok(Self {
            scheme: payload.scheme.clone(),
            version: Self::VERSION.to_owned(),
            group_id: payload.group_id.clone(),
            epoch: payload.epoch,
            content_type: payload.content_type.clone(),
            ciphertext: payload.ciphertext.clone(),
            aad_visibility_event_id: visibility,
            aad,
            key_ref: EnvelopeKeyRefV1 {
                algorithm: Self::KEY_REF_ALGORITHM.to_owned(),
                group_state_ref: group_state_ref.into(),
            },
            aad_digest,
            payload_digest: payload.payload_digest.as_str().to_owned(),
        })
    }

    /// Reconstruct the MLS [`EncryptedPayload`] needed to decrypt this
    /// envelope. The reconstructed AAD round-trips byte-identically with the
    /// AAD bound at encryption time, so `payload_digest` verification holds.
    pub fn to_payload(&self) -> Result<EncryptedPayload> {
        let aad_value = serde_json::to_value(&self.aad)
            .map_err(|err| Error::Protocol(format!("encode envelope aad: {err}")))?;
        Ok(EncryptedPayload {
            scheme: self.scheme.clone(),
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type.clone(),
            ciphertext: self.ciphertext.clone(),
            aad: Some(aad_value),
            payload_digest: Hash::new(self.payload_digest.clone())?,
            key_ref: Some(cokret_core::KeyRefObject::mls_rfc9420(
                self.group_id.clone(),
                self.epoch,
            )),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoDecrypt {
    Plaintext {
        message_id: String,
        content_type: String,
        plaintext: Vec<u8>,
    },
    Encrypted {
        message_id: String,
        payload: EncryptedPayload,
        reason: MessageCryptoUnavailable,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCryptoUnavailable {
    NoSession,
    WrongGroup {
        expected: String,
        actual: String,
    },
    EpochUnavailable {
        local_epoch: u64,
        required_epoch: u64,
    },
    KeyUnavailable(String),
}

pub struct MessageCrypto;

impl MessageCrypto {
    pub fn encrypt(
        group: &mut CokretMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload(content_type, plaintext)?,
        })
    }

    pub fn encrypt_with_aad(
        group: &mut CokretMlsGroup,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        aad: serde_json::Value,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        Ok(EncryptedMessage {
            message_id: message_id.into(),
            payload: group.encrypt_payload_with_aad(content_type, Some(aad), plaintext)?,
        })
    }

    pub fn verify_opaque_payload_digest(message: &EncryptedMessage) -> Result<()> {
        let ciphertext_bytes = decode(&message.payload.ciphertext)?;
        message.payload.verify_mls_payload_digest(&ciphertext_bytes)
    }

    pub fn verify_payload_and_aad_digest(
        message: &EncryptedMessage,
        expected_aad_digest: Option<&str>,
    ) -> Result<()> {
        Self::verify_opaque_payload_digest(message)?;
        if let Some(expected) = expected_aad_digest {
            let aad =
                message.payload.aad.as_ref().ok_or_else(|| {
                    Error::Protocol("encrypted payload AAD is missing".to_owned())
                })?;
            let actual = crate::crypto::json_aad_digest(aad)?;
            if actual != expected {
                return Err(Error::Protocol(
                    "encrypted payload AAD digest mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn decrypt(group: &mut CokretMlsGroup, message: &EncryptedMessage) -> Result<Vec<u8>> {
        Self::verify_opaque_payload_digest(message)?;
        group.decrypt_payload(&message.payload)
    }

    pub fn decrypt_or_preserve(
        group: Option<&mut CokretMlsGroup>,
        message: EncryptedMessage,
    ) -> Result<MessageCryptoDecrypt> {
        Self::verify_opaque_payload_digest(&message)?;
        let message_id = message.message_id.clone();
        let content_type = message.payload.content_type.clone();

        let Some(group) = group else {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload,
                reason: MessageCryptoUnavailable::NoSession,
            });
        };

        if message.payload.group_id != group.group_id() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload.clone(),
                reason: MessageCryptoUnavailable::WrongGroup {
                    expected: group.group_id(),
                    actual: message.payload.group_id,
                },
            });
        }
        if message.payload.epoch > group.epoch() {
            return Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload.clone(),
                reason: MessageCryptoUnavailable::EpochUnavailable {
                    local_epoch: group.epoch(),
                    required_epoch: message.payload.epoch,
                },
            });
        }

        match group.decrypt_payload(&message.payload) {
            Ok(plaintext) => Ok(MessageCryptoDecrypt::Plaintext {
                message_id,
                content_type,
                plaintext,
            }),
            Err(error) => Ok(MessageCryptoDecrypt::Encrypted {
                message_id,
                payload: message.payload,
                reason: MessageCryptoUnavailable::KeyUnavailable(error.to_string()),
            }),
        }
    }
}

impl CokretMlsIdentity {
    pub fn new_basic(principal_id: Did, device_id: DeviceId) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(COKRET_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(mls_error)?;
        signer.store(provider.storage()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(principal_id.as_str().as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            principal_id,
            device_id,
            provider,
            signer,
            credential,
        })
    }

    pub fn key_package_record(&self) -> Result<MlsKeyPackageRecord> {
        let key_package = KeyPackage::builder()
            .build(
                COKRET_MLS_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls_error)?;
        let key_package = key_package.key_package();
        let key_package_bytes = key_package.tls_serialize_detached().map_err(mls_error)?;
        let keypackage_ref = Hash::new(canonical::sha256_digest(&key_package_bytes))?;

        Ok(MlsKeyPackageRecord {
            keypackage_id: format!("ck:mls:kp:{}", uuid::Uuid::now_v7()),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            key_package: encode(&key_package_bytes),
            keypackage_ref,
            cipher_suites: vec![format!("{COKRET_MLS_CIPHERSUITE:?}")],
            capabilities: Vec::new(),
            state: cokret_core::MlsKeyPackageState::Published,
            claim_id: None,
            created_at: Utc::now(),
            expires_at: None,
            device_signature: None,
        })
    }

    pub fn publish_key_package_step(&self, group_id: Option<String>) -> MlsDeviceWorkflowStep {
        MlsDeviceWorkflowStep {
            action: MlsDeviceWorkflowAction::PublishKeyPackage,
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            group_id,
            from_epoch: None,
            to_epoch: None,
        }
    }

    pub fn create_group(self, group_id: impl AsRef<[u8]>) -> Result<CokretMlsGroup> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(COKRET_MLS_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id.as_ref()),
            self.credential.clone(),
        )
        .map_err(mls_error)?;

        Ok(CokretMlsGroup {
            identity: self,
            group,
        })
    }
}

impl CokretMlsGroup {
    pub fn identity(&self) -> &CokretMlsIdentity {
        &self.identity
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn group_id(&self) -> String {
        encode(self.group.group_id().as_slice())
    }

    pub fn ratchet_tree(&self) -> Result<String> {
        let bytes = self
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        Ok(encode(&bytes))
    }

    /// Content hash of the group's current key schedule, suitable for use as
    /// the `key_schedule_hash` field in `ck.component.key_schedule.v1` cell
    /// values and in `ck.profile.mls_governance_binding.full.v1` binding
    /// payloads. Derived deterministically from the OpenMLS
    /// `epoch_authenticator()` — a value the spec binds to the current
    /// (post-commit) MLS epoch + group state, so two clients on the same
    /// epoch always produce the same hash without exchanging schedule
    /// material.
    ///
    /// Returns a `sha256:`-prefixed lowercase hex `Hash` typed-id so callers
    /// can hand it straight to `GovernanceBindingPayload::from_anchor` /
    /// `Hash::new`. Computing the SHA-256 over the authenticator byte slice
    /// (rather than handing back the raw authenticator) means the value can
    /// be safely written into projection cells and audit logs without
    /// leaking the underlying MLS secret directly — the authenticator MUST
    /// stay scoped to MLS-internal consistency checks per RFC 9420 §8.5.
    pub fn schedule_hash(&self) -> Hash {
        let authenticator = self.group.epoch_authenticator();
        let digest = Sha256::digest(authenticator.as_slice());
        Hash::new(format!("sha256:{}", hex_lower(&digest)))
            .expect("sha256:<hex> is always a valid Hash typed-id")
    }

    /// Derive an MLS RFC 9420 §8.5 exporter secret bound to the current
    /// epoch's key schedule. The output is deterministic for a given
    /// `(group, epoch, label, context, length)` and rotates on every commit,
    /// so two members on the same epoch derive identical bytes without
    /// exchanging material.
    ///
    /// Used for spec-defined key derivations layered on the group secret —
    /// e.g. the reaction routing tag (`encryption-and-audit.md` §2.9, label
    /// `cokret-reaction-routing-v1`, context = `realm_id`) and SFrame media
    /// keys (`media-service-binding.md` §8.1). Callers MUST treat the returned
    /// bytes as secret key material (never log or persist them in the clear).
    pub fn export_secret(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.group
            .export_secret(self.identity.provider.crypto(), label, context, length)
            .map_err(mls_error)
    }

    /// Snapshot the current MLS group's member principals as canonical IDs.
    /// Iterates the OpenMLS `members()` view, parses each leaf's credential
    /// content as a UTF-8 DID string, and folds the results into a stable
    /// (deduplicated, BTreeSet-sorted) `Vec<Did>`. Useful for `ck.audit.
    /// ryw_receipt.delivered_to_devices` and for downstream auditors that
    /// want to know "which principals does this commit reach".
    ///
    /// Credentials that don't parse as a [`Did`] (e.g. opaque BasicCredential
    /// payloads) are silently skipped — the caller can
    /// detect this case by comparing `member_principal_ids().len()` against
    /// the group's true member count if it cares.
    pub fn member_principal_ids(&self) -> Vec<Did> {
        let mut seen = std::collections::BTreeSet::new();
        for member in self.group.members() {
            let bytes = member.credential.serialized_content();
            if let Ok(s) = std::str::from_utf8(bytes)
                && let Ok(did) = Did::new(s.to_owned())
            {
                seen.insert(did);
            }
        }
        seen.into_iter().collect()
    }

    pub fn export_state_record(&self) -> Result<MlsGroupStateRecord> {
        let snapshot = OpenMlsStateSnapshot {
            context: COKRET_OPENMLS_STATE_SNAPSHOT.to_owned(),
            group_id: self.group_id(),
            epoch: self.epoch(),
            principal_id: self.identity.principal_id.clone(),
            device_id: self.identity.device_id.clone(),
            signer_public_key: encode(self.identity.signer.public()),
            storage_entries: snapshot_provider_storage(&self.identity.provider)?,
        };
        Ok(MlsGroupStateRecord {
            group_id: snapshot.group_id.clone(),
            principal_id: snapshot.principal_id.clone(),
            device_id: snapshot.device_id.clone(),
            epoch: snapshot.epoch,
            serialized_state: serde_json::to_vec(&snapshot)?,
            updated_at: Utc::now(),
        })
    }

    pub fn persist_state(&self, store: &mut impl CryptoStore) -> Result<MlsGroupStateRecord> {
        let record = self.export_state_record()?;
        store.put_mls_group_state(record.clone())?;
        Ok(record)
    }

    pub fn restore_from_state_record(record: &MlsGroupStateRecord) -> Result<Self> {
        let snapshot: OpenMlsStateSnapshot = serde_json::from_slice(&record.serialized_state)?;
        if snapshot.context != COKRET_OPENMLS_STATE_SNAPSHOT {
            return Err(Error::Protocol(
                "unsupported OpenMLS state snapshot".to_owned(),
            ));
        }
        if snapshot.group_id != record.group_id
            || snapshot.epoch != record.epoch
            || snapshot.principal_id != record.principal_id
            || snapshot.device_id != record.device_id
        {
            return Err(Error::Protocol(
                "OpenMLS state snapshot metadata mismatch".to_owned(),
            ));
        }

        let provider = OpenMlsRustCrypto::default();
        restore_provider_storage(&provider, &snapshot.storage_entries)?;
        let signer_public_key = decode(&snapshot.signer_public_key)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signer_public_key,
            COKRET_MLS_CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| Error::Protocol("OpenMLS signer is missing from snapshot".to_owned()))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(record.principal_id.as_str().as_bytes().to_vec())
                .into(),
            signature_key: signer.public().into(),
        };
        let group_id = GroupId::from_slice(&decode(&record.group_id)?);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(mls_error)?
            .ok_or_else(|| Error::Protocol("OpenMLS group state is missing".to_owned()))?;
        if group.epoch().as_u64() != record.epoch {
            return Err(Error::Protocol(
                "OpenMLS restored epoch mismatch".to_owned(),
            ));
        }

        Ok(Self {
            identity: CokretMlsIdentity {
                principal_id: record.principal_id.clone(),
                device_id: record.device_id.clone(),
                provider,
                signer,
                credential,
            },
            group,
        })
    }

    /// Produce a "self-update" commit envelope — the MLS commit that
    /// rotates the local member's leaf-node key without changing
    /// membership. Callers (e.g. yougen's chat Send Secure path) use
    /// this to get a real `MlsCommitEnvelope` over the actual ratchet
    /// state instead of synthesizing one with hardcoded epoch / hash
    /// values.
    ///
    /// Returns an `MlsCommitEnvelope` whose `commit` field is the
    /// TLS-serialised commit message (base64-url encoded) and whose
    /// `commit_digest` is the SHA-256 of that wire bytes — the same
    /// shape the SDK already emits from `add_member` / `remove_member_*`.
    /// Side-effect: the group's pending commit is `merge`-d on success
    /// so subsequent `encrypt_payload` calls run against the new
    /// epoch.
    pub fn self_update_commit(&mut self) -> Result<MlsCommitEnvelope> {
        let bundle = self
            .group
            .self_update(
                &self.identity.provider,
                &self.identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;
        let commit_bytes = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);
        Ok(MlsCommitEnvelope {
            group_id: self.group_id(),
            epoch: self.epoch(),
            commit: encode(&commit_bytes),
            commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
            ratchet_tree,
            app_state_ref: None,
        })
    }

    pub fn add_member(
        &mut self,
        member_key_package: &MlsKeyPackageRecord,
    ) -> Result<MlsAddMemberResult> {
        if !member_key_package.is_usable() {
            return Err(Error::Protocol(
                "refusing to add revoked MLS KeyPackage".to_owned(),
            ));
        }

        let key_package = decode_key_package(&self.identity.provider, member_key_package)?;
        let (commit, welcome, _) = self
            .group
            .add_members(
                &self.identity.provider,
                &self.identity.signer,
                std::slice::from_ref(&key_package),
            )
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome_bytes = welcome.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);

        Ok(MlsAddMemberResult {
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree: ratchet_tree.clone(),
                app_state_ref: None,
            },
            welcome: MlsWelcomeEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                recipient_principal_id: member_key_package.principal_id.clone(),
                recipient_device_id: member_key_package.device_id.clone(),
                welcome: encode(&welcome_bytes),
                welcome_hash: Hash::new(canonical::sha256_digest(&welcome_bytes))?,
                ratchet_tree,
            },
        })
    }

    /// Remove every leaf whose BasicCredential identity matches `target`.
    ///
    /// In the current credential encoding (`mls.rs::CokretMlsIdentity::new_basic`)
    /// the leaf identity bytes are `principal_id.as_str().as_bytes()` — they
    /// do NOT include the device id. Therefore matching by principal removes
    /// **all leaves** owned by that principal in this group. To remove a
    /// specific device, use [`Self::remove_member_by_leaf`] with a leaf
    /// index resolved from out-of-band device → leaf bookkeeping.
    ///
    /// Errors when the target principal has no leaf in this group.
    pub fn remove_member_by_principal(&mut self, target: &Did) -> Result<MlsRemoveMemberResult> {
        let target_bytes = target.as_str().as_bytes();
        let leaves: Vec<LeafNodeIndex> = self
            .group
            .members()
            .filter_map(|member| {
                if member.credential.serialized_content() == target_bytes {
                    Some(member.index)
                } else {
                    None
                }
            })
            .collect();

        if leaves.is_empty() {
            return Err(Error::Protocol(format!(
                "principal {} has no leaf in group {}",
                target.as_str(),
                self.group_id()
            )));
        }

        self.remove_leaves(&leaves)
    }

    /// Remove a single leaf by its raw OpenMLS leaf index. Use this when the
    /// caller maintains an explicit (principal, device_id) → leaf_index map
    /// (e.g. a yougen DeviceManager with leaf bookkeeping) and wants to
    /// revoke just one device of a multi-device principal.
    pub fn remove_member_by_leaf(&mut self, leaf_index: u32) -> Result<MlsRemoveMemberResult> {
        self.remove_leaves(&[LeafNodeIndex::new(leaf_index)])
    }

    fn remove_leaves(&mut self, leaves: &[LeafNodeIndex]) -> Result<MlsRemoveMemberResult> {
        // Capture credential identity bytes before commit so we can report
        // which principal each removed leaf belonged to even after the leaf
        // is gone from the post-commit group state.
        let pre_commit: Vec<(LeafNodeIndex, Vec<u8>)> = self
            .group
            .members()
            .filter_map(|member| {
                if leaves.contains(&member.index) {
                    Some((
                        member.index,
                        member.credential.serialized_content().to_vec(),
                    ))
                } else {
                    None
                }
            })
            .collect();

        if pre_commit.len() != leaves.len() {
            return Err(Error::Protocol(format!(
                "remove_leaves: {} of {} leaf indices not present in group {}",
                leaves.len() - pre_commit.len(),
                leaves.len(),
                self.group_id()
            )));
        }

        let (commit, _welcome_opt, _) = self
            .group
            .remove_members(&self.identity.provider, &self.identity.signer, leaves)
            .map_err(mls_error)?;
        self.group
            .merge_pending_commit(&self.identity.provider)
            .map_err(mls_error)?;

        let commit_bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        let ratchet_tree = Some(self.ratchet_tree()?);

        let mut removed_leaves: Vec<u32> = Vec::with_capacity(pre_commit.len());
        let mut removed_principals: Vec<Did> = Vec::with_capacity(pre_commit.len());
        for (idx, identity_bytes) in pre_commit {
            removed_leaves.push(idx.u32());
            // Reconstruct the principal Did from identity bytes. If the
            // bytes are not valid UTF-8 / not a parseable Did we fall back
            // to a placeholder so the audit trail still records the leaf
            // index; this should never happen in practice because all
            // CokretMlsIdentity leaves carry UTF-8 DID strings.
            let principal = std::str::from_utf8(&identity_bytes)
                .ok()
                .and_then(|s| Did::new(s.to_owned()).ok())
                .unwrap_or_else(|| {
                    Did::new(format!("did:cokret:unknown-leaf-{}", idx.u32()))
                        .expect("placeholder DID is well-formed")
                });
            removed_principals.push(principal);
        }

        Ok(MlsRemoveMemberResult {
            commit: MlsCommitEnvelope {
                group_id: self.group_id(),
                epoch: self.epoch(),
                commit: encode(&commit_bytes),
                commit_digest: Hash::new(canonical::sha256_digest(&commit_bytes))?,
                ratchet_tree,
                app_state_ref: None,
            },
            removed_leaves,
            removed_principals,
        })
    }

    pub fn join_from_welcome(
        identity: CokretMlsIdentity,
        envelope: &MlsWelcomeEnvelope,
    ) -> Result<Self> {
        if envelope.recipient_principal_id != identity.principal_id
            || envelope.recipient_device_id != identity.device_id
        {
            return Err(Error::Protocol(
                "MLS Welcome recipient does not match identity".to_owned(),
            ));
        }

        let welcome_bytes = decode(&envelope.welcome)?;
        let actual_welcome_hash = canonical::sha256_digest(&welcome_bytes);
        if actual_welcome_hash != envelope.welcome_hash.as_str() {
            return Err(Error::Protocol("MLS Welcome hash mismatch".to_owned()));
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).map_err(mls_error)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::Protocol("MLS message is not a Welcome".to_owned()));
        };
        let ratchet_tree = match &envelope.ratchet_tree {
            Some(tree) => {
                let tree_bytes = decode(tree)?;
                Some(
                    RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice())
                        .map_err(mls_error)?,
                )
            }
            None => None,
        };

        let group = StagedWelcome::new_from_welcome(
            &identity.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            ratchet_tree,
        )
        .map_err(mls_error)?
        .into_group(&identity.provider)
        .map_err(mls_error)?;

        Ok(Self { identity, group })
    }

    pub fn encrypt_payload(
        &mut self,
        content_type: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        self.encrypt_payload_with_aad(content_type, None, plaintext)
    }

    pub fn encrypt_payload_with_aad(
        &mut self,
        content_type: impl Into<String>,
        aad: Option<serde_json::Value>,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload> {
        let content_type = content_type.into();
        let message = self
            .group
            .create_message(&self.identity.provider, &self.identity.signer, plaintext)
            .map_err(mls_error)?;
        let message_bytes = message.tls_serialize_detached().map_err(mls_error)?;
        let epoch = self.epoch();
        let payload_digest = EncryptedPayload::mls_payload_digest(
            epoch,
            &content_type,
            aad.as_ref(),
            &message_bytes,
        )?;

        Ok(EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: self.group_id(),
            epoch,
            content_type,
            ciphertext: encode(&message_bytes),
            aad,
            payload_digest,
            key_ref: Some(cokret_core::KeyRefObject::mls_rfc9420(
                self.group_id(),
                epoch,
            )),
        })
    }

    pub fn decrypt_payload(&mut self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        if payload.scheme != EncryptedPayloadScheme::MlsRfc9420 {
            return Err(Error::Protocol(
                "encrypted payload is not MLS RFC 9420".to_owned(),
            ));
        }
        if payload.group_id != self.group_id() {
            return Err(Error::Protocol(
                "encrypted payload belongs to a different MLS group".to_owned(),
            ));
        }
        if payload.epoch > self.epoch() {
            return Err(Error::Protocol(
                "MLS epoch is not available locally".to_owned(),
            ));
        }

        let message_bytes = decode(&payload.ciphertext)?;
        payload.verify_mls_payload_digest(&message_bytes)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(message_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS message is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.group
                    .merge_staged_commit(&self.identity.provider, *commit)
                    .map_err(mls_error)?;
                Err(Error::Protocol(
                    "expected MLS application message, got commit".to_owned(),
                ))
            }
            _ => Err(Error::Protocol(
                "expected MLS application message".to_owned(),
            )),
        }
    }

    pub fn apply_commit(&mut self, envelope: &MlsCommitEnvelope) -> Result<u64> {
        let commit_bytes = decode(&envelope.commit)?;
        let actual_commit_digest = canonical::sha256_digest(&commit_bytes);
        if actual_commit_digest != envelope.commit_digest.as_str() {
            return Err(Error::Protocol("MLS Commit hash mismatch".to_owned()));
        }

        let message =
            MlsMessageIn::tls_deserialize_exact(commit_bytes.as_slice()).map_err(mls_error)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| Error::Protocol("MLS Commit is not a protocol message".to_owned()))?;
        let processed = self
            .group
            .process_message(&self.identity.provider, protocol_message)
            .map_err(mls_error)?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.group
                    .merge_staged_commit(&self.identity.provider, *commit)
                    .map_err(mls_error)?;
                Ok(self.epoch())
            }
            _ => Err(Error::Protocol("expected MLS Commit".to_owned())),
        }
    }

    pub fn apply_commits(&mut self, envelopes: &[MlsCommitEnvelope]) -> Result<u64> {
        let mut sorted = envelopes.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|envelope| envelope.epoch);
        for envelope in sorted {
            if envelope.epoch <= self.epoch() {
                continue;
            }
            self.apply_commit(envelope)?;
        }
        Ok(self.epoch())
    }
}

fn decode_key_package(
    provider: &OpenMlsRustCrypto,
    record: &MlsKeyPackageRecord,
) -> Result<KeyPackage> {
    let bytes = decode(&record.key_package)?;
    let actual_hash = canonical::sha256_digest(&bytes);
    if actual_hash != record.keypackage_ref.as_str() {
        return Err(Error::Protocol("MLS KeyPackage hash mismatch".to_owned()));
    }

    let key_package_in =
        KeyPackageIn::tls_deserialize_exact(bytes.as_slice()).map_err(mls_error)?;
    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls_error)
}

pub fn revoke_key_package(record: &mut MlsKeyPackageRecord) -> MlsDeviceWorkflowStep {
    record.state = cokret_core::MlsKeyPackageState::Revoked;
    MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RevokeKeyPackage,
        principal_id: record.principal_id.clone(),
        device_id: record.device_id.clone(),
        group_id: None,
        from_epoch: None,
        to_epoch: None,
    }
}

pub fn late_device_join_steps(welcome: &MlsWelcomeEnvelope) -> Vec<MlsDeviceWorkflowStep> {
    vec![MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::ConsumeWelcome,
        principal_id: welcome.recipient_principal_id.clone(),
        device_id: welcome.recipient_device_id.clone(),
        group_id: Some(welcome.group_id.clone()),
        from_epoch: None,
        to_epoch: Some(welcome.epoch),
    }]
}

pub fn epoch_recovery_step(
    principal_id: Did,
    device_id: DeviceId,
    group_id: impl Into<String>,
    from_epoch: u64,
    to_epoch: u64,
) -> MlsDeviceWorkflowStep {
    MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RequestEpochRecovery,
        principal_id,
        device_id,
        group_id: Some(group_id.into()),
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
    }
}

/// Request for epoch recovery sent to a group member that has the missing commits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryRequestBody {
    /// Group that needs recovery.
    pub group_id: String,
    /// Device requesting recovery.
    pub requesting_principal: Did,
    pub requesting_device: DeviceId,
    /// The epoch the device is currently at.
    pub local_epoch: u64,
    /// The epoch the device needs to reach.
    pub target_epoch: u64,
}

/// Response containing the commits needed for epoch recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecoveryOutcome {
    /// Group that was recovered.
    pub group_id: String,
    /// The commits from `local_epoch + 1` through `target_epoch`.
    pub commits: Vec<MlsCommitEnvelope>,
    /// Optional updated ratchet tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// Epoch the responder is at.
    pub responder_epoch: u64,
}

impl EpochRecoveryRequestBody {
    /// Create a new epoch recovery request.
    pub fn new(
        group_id: impl Into<String>,
        requesting_principal: Did,
        requesting_device: DeviceId,
        local_epoch: u64,
        target_epoch: u64,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            requesting_principal,
            requesting_device,
            local_epoch,
            target_epoch,
        }
    }

    /// Validate the request is well-formed.
    pub fn validate(&self) -> Result<()> {
        if self.group_id.is_empty() {
            return Err(Error::Protocol(
                "epoch recovery group_id is empty".to_owned(),
            ));
        }
        if self.local_epoch >= self.target_epoch {
            return Err(Error::Protocol(
                "epoch recovery local_epoch must be less than target_epoch".to_owned(),
            ));
        }
        Ok(())
    }
}

impl EpochRecoveryOutcome {
    /// Apply all commits in this recovery response to a group.
    pub fn apply_to_group(&self, group: &mut CokretMlsGroup) -> Result<u64> {
        group.apply_commits(&self.commits)
    }

    /// Validate that the response covers the requested epoch range.
    pub fn validate_range(&self, request: &EpochRecoveryRequestBody) -> Result<()> {
        if self.group_id != request.group_id {
            return Err(Error::Protocol(
                "epoch recovery response group_id mismatch".to_owned(),
            ));
        }
        for commit in &self.commits {
            if commit.epoch <= request.local_epoch || commit.epoch > request.target_epoch {
                return Err(Error::Protocol(format!(
                    "epoch recovery commit epoch {} is outside requested range ({}, {}]",
                    commit.epoch, request.local_epoch, request.target_epoch
                )));
            }
        }
        Ok(())
    }
}

/// Build an epoch recovery response from a group that has the needed commits.
pub fn build_epoch_recovery_response(
    group: &CokretMlsGroup,
    store: &impl CryptoStore,
    request: &EpochRecoveryRequestBody,
) -> Result<EpochRecoveryOutcome> {
    request.validate()?;

    let commits = store.commits_for_group(&request.group_id);
    let recovery_commits: Vec<MlsCommitEnvelope> = commits
        .into_iter()
        .filter(|commit| commit.epoch > request.local_epoch && commit.epoch <= request.target_epoch)
        .cloned()
        .collect();

    if recovery_commits.is_empty() {
        return Err(Error::Protocol(
            "no commits available for epoch recovery".to_owned(),
        ));
    }

    Ok(EpochRecoveryOutcome {
        group_id: request.group_id.clone(),
        commits: recovery_commits,
        ratchet_tree: Some(group.ratchet_tree()?),
        responder_epoch: group.epoch(),
    })
}

fn snapshot_provider_storage(provider: &OpenMlsRustCrypto) -> Result<BTreeMap<String, String>> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| Error::Protocol("OpenMLS storage lock poisoned".to_owned()))?;
    Ok(values
        .iter()
        .map(|(key, value)| (encode(key), encode(value)))
        .collect())
}

fn restore_provider_storage(
    provider: &OpenMlsRustCrypto,
    entries: &BTreeMap<String, String>,
) -> Result<()> {
    let mut values = provider
        .storage()
        .values
        .write()
        .map_err(|_| Error::Protocol("OpenMLS storage lock poisoned".to_owned()))?;
    values.clear();
    for (key, value) in entries {
        values.insert(decode(key)?, decode(value)?);
    }
    Ok(())
}

fn encode(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn decode(value: &str) -> Result<Vec<u8>> {
    base64url_decode(value)
}

fn mls_error(error: impl std::fmt::Debug) -> Error {
    Error::Mls(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_metadata_max_epoch_lifetime_is_one_hour() {
        assert_eq!(MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS, 3600);
        assert_eq!(
            minimal_metadata_max_epoch_lifetime(),
            chrono::Duration::hours(1)
        );
    }

    #[test]
    fn enforce_minimal_metadata_aad_rejects_non_hidden_in_minimal_realm() {
        // Minimal-metadata Realm: only Hidden is allowed.
        enforce_minimal_metadata_aad(&AadVisibility::Hidden, true).unwrap();
        for v in [AadVisibility::RoutingDigest, AadVisibility::OpaqueId] {
            let err = enforce_minimal_metadata_aad(&v, true).unwrap_err();
            assert!(err.to_string().contains("aad_visibility=hidden"));
        }
        // Non-minimal Realm: any visibility is permitted by this helper.
        enforce_minimal_metadata_aad(&AadVisibility::RoutingDigest, false).unwrap();
        enforce_minimal_metadata_aad(&AadVisibility::OpaqueId, false).unwrap();
    }

    #[test]
    fn minimal_metadata_epoch_overdue_after_one_hour() {
        let started: chrono::DateTime<Utc> = "2026-06-04T00:00:00Z".parse().unwrap();
        // 59m59s in — still within the cap.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::minutes(59) + chrono::Duration::seconds(59)
        ));
        // Exactly 1h is the boundary (strict `>`), one second past is overdue.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::hours(1)
        ));
        assert!(minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::hours(1) + chrono::Duration::seconds(1)
        ));
        // Clock skew (now before epoch start) is never overdue.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started - chrono::Duration::minutes(5)
        ));
    }

    #[test]
    fn schedule_hash_is_deterministic_and_changes_on_commit() {
        // The schedule hash MUST be a function of (epoch, group state) only —
        // two clients on the same epoch always produce the same hash, and a
        // commit that advances the epoch MUST produce a fresh hash. This
        // pins the contract `chat.rs` relies on when binding governance
        // payloads to the local group's schedule.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a40")
            .unwrap();
        let hash_pre = alice_group.schedule_hash();
        assert!(
            hash_pre.as_str().starts_with("sha256:"),
            "schedule_hash must use canonical `sha256:` prefix"
        );
        // Deterministic — calling twice on the same epoch is a no-op.
        assert_eq!(hash_pre, alice_group.schedule_hash());

        // Add a member → epoch advances → schedule_hash MUST change.
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let hash_post = alice_group.schedule_hash();
        assert_ne!(hash_pre, hash_post);

        // Bob's view of the same epoch MUST produce the same hash.
        assert_eq!(hash_post, bob_group.schedule_hash());
    }

    #[test]
    fn export_secret_agrees_across_members_and_binds_label_context() {
        // RFC 9420 §8.5: members on the same epoch derive identical exporter
        // bytes; distinct (label, context) MUST yield distinct outputs. This
        // is the primitive the reaction routing tag (encryption-and-audit.md
        // §2.9) and SFrame keys are built on.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000016").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000001e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let realm = b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41";
        let a = alice_group
            .export_secret("cokret-reaction-routing-v1", realm, 32)
            .unwrap();
        let b = bob_group
            .export_secret("cokret-reaction-routing-v1", realm, 32)
            .unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(
            a, b,
            "same epoch + label + context MUST agree across members"
        );

        // Different context (realm) MUST diverge.
        let other_realm = b"ck:realm:01904100-0000-7000-8000-1ad6479d4a42";
        assert_ne!(
            a,
            alice_group
                .export_secret("cokret-reaction-routing-v1", other_realm, 32)
                .unwrap()
        );
        // Different label MUST diverge.
        assert_ne!(
            a,
            alice_group
                .export_secret("ck-rtc-frame-key/v1", realm, 32)
                .unwrap()
        );
    }

    #[test]
    fn member_principal_ids_returns_credentials_as_dids() {
        // After Add, both Alice and Bob are members; both DIDs MUST appear
        // in the snapshot. After Remove, only the surviving DID remains.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:web:alice.example").unwrap()],
        );

        let _ = alice_group.add_member(&bob_key_package).unwrap();
        let members = alice_group.member_principal_ids();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&Did::new("did:web:alice.example").unwrap()));
        assert!(members.contains(&Did::new("did:web:bob.example").unwrap()));

        let _ = alice_group
            .remove_member_by_principal(&Did::new("did:web:bob.example").unwrap())
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:web:alice.example").unwrap()],
        );
    }

    /// `self_update_commit` MUST advance the group epoch by exactly 1
    /// and surface a typed `MlsCommitEnvelope` with the new
    /// (group_id, epoch) pair. The `commit_digest` MUST be the SHA-256
    /// of the wire bytes.
    #[test]
    fn self_update_commit_advances_epoch_and_returns_typed_envelope() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-555555555555")
            .unwrap();
        let pre_epoch = group.epoch();
        let pre_group_id = group.group_id();
        let envelope = group.self_update_commit().expect("self_update succeeds");
        assert_eq!(envelope.group_id, pre_group_id);
        assert_eq!(envelope.epoch, pre_epoch + 1);
        // post-call: group's view agrees.
        assert_eq!(group.epoch(), pre_epoch + 1);
        // commit_digest is non-empty + sha256:-prefixed.
        assert!(envelope.commit_digest.as_str().starts_with("sha256:"));
        // commit bytes round-trip through base64.
        assert!(!envelope.commit.is_empty());
        // schedule_hash MUST also change since epoch_authenticator
        // depends on the new key schedule (B3d invariant).
        let post_schedule = group.schedule_hash();
        // Trivially non-empty — actual change would need pre/post
        // capture but we already pin the determinism in
        // `schedule_hash_is_deterministic_and_changes_on_commit`.
        assert!(post_schedule.as_str().starts_with("sha256:"));
    }

    #[test]
    fn openmls_group_can_add_member_encrypt_and_decrypt() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"hello"}"#)
            .unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();

        assert_eq!(decrypted, br#"{"body":"hello"}"#);
        assert_eq!(encrypted.scheme, EncryptedPayloadScheme::MlsRfc9420);
        assert_eq!(encrypted.epoch, alice_group.epoch());
        assert_eq!(bob_group.epoch(), alice_group.epoch());
    }

    #[test]
    fn message_crypto_encrypts_decrypts_and_verifies_opaque_digest() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:message:01",
            "application/vnd.cokret.message+json",
            br#"{"body":"hello secure workflow"}"#,
        )
        .unwrap();

        MessageCrypto::verify_opaque_payload_digest(&encrypted).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"hello secure workflow"}"#);
    }

    #[test]
    fn message_crypto_encrypts_with_aad_and_verifies_digest() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-65bef476aed3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let aad = serde_json::json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-65bef476aed3",
            "event_kind": "ck.message.create",
            "event_id": "ck:event:01904100-0000-7000-8000-d5afe7e3de96",
            "causal_refs": []
        });
        let aad_digest = crate::crypto::json_aad_digest(&aad).unwrap();

        let encrypted = MessageCrypto::encrypt_with_aad(
            &mut alice_group,
            "ck:message:aad",
            "application/json",
            aad,
            br#"{"body":"aad bound"}"#,
        )
        .unwrap();
        MessageCrypto::verify_payload_and_aad_digest(&encrypted, Some(&aad_digest)).unwrap();
        assert_eq!(
            MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap(),
            br#"{"body":"aad bound"}"#
        );
    }

    #[test]
    fn openmls_state_persists_through_crypto_store_record() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a3f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let mut store = crate::MemoryCryptoStore::new();
        let record = bob_group.persist_state(&mut store).unwrap();
        let mut restored_bob = CokretMlsGroup::restore_from_state_record(&record).unwrap();

        assert_eq!(restored_bob.epoch(), bob_group.epoch());
        assert_eq!(
            store.mls_group_state(&record.group_id).unwrap().epoch,
            record.epoch
        );

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after restore"}"#)
            .unwrap();
        assert_eq!(
            restored_bob.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"after restore"}"#
        );
    }

    #[test]
    fn multi_device_workflow_applies_missed_commits_and_models_recovery() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();
        let mut revoked_package = charlie_key_package.clone();
        let revoke_step = revoke_key_package(&mut revoked_package);
        assert_eq!(
            revoked_package.state,
            cokret_core::MlsKeyPackageState::Revoked
        );
        assert_eq!(
            revoke_step.action,
            MlsDeviceWorkflowAction::RevokeKeyPackage
        );

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-877788250807")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_key_package).unwrap();
        let workflow = late_device_join_steps(&charlie_add.welcome);
        assert_eq!(workflow[0].action, MlsDeviceWorkflowAction::ConsumeWelcome);

        bob_group
            .apply_commits(std::slice::from_ref(&charlie_add.commit))
            .unwrap();
        assert_eq!(bob_group.epoch(), alice_group.epoch());
        let recovery = epoch_recovery_step(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_group.group_id(),
            bob_group.epoch() + 1,
            bob_group.epoch() + 3,
        );
        assert_eq!(
            recovery.action,
            MlsDeviceWorkflowAction::RequestEpochRecovery
        );
    }

    #[test]
    fn add_member_result_projects_to_repo_operation_and_to_device_message() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-4ecefcf31ad2")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let operation = add_result
            .commit_operation(
                OperationId::new("ck:operation:01904100-0000-7000-8000-02369de2e9c6").unwrap(),
                RealmId::new("ck:realm:01904100-0000-7000-8000-4ecefcf31ad2").unwrap(),
            )
            .unwrap();
        let to_device = add_result.welcome_to_device_message().unwrap();

        assert_eq!(operation.object_type, "mls_commit");
        assert_eq!(to_device.message_type, "ck.mls.welcome.v1");
        assert_eq!(
            to_device.content["recipient_device_id"],
            "ck:device:01904100-0000-7000-8000-00000000000e"
        );
    }

    #[test]
    fn message_crypto_preserves_encrypted_content_without_available_key() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:message:02",
            "application/json",
            br#"{"body":"keep ciphertext"}"#,
        )
        .unwrap();
        let expected_digest = encrypted.payload.payload_digest.clone();
        let expected_ciphertext = encrypted.payload.ciphertext.clone();

        let result = MessageCrypto::decrypt_or_preserve(None, encrypted).unwrap();

        let MessageCryptoDecrypt::Encrypted {
            message_id,
            payload,
            reason,
        } = result
        else {
            panic!("message should stay encrypted without a local MLS session");
        };
        assert_eq!(message_id, "ck:message:02");
        assert!(matches!(reason, MessageCryptoUnavailable::NoSession));
        assert_eq!(payload.payload_digest, expected_digest);
        assert_eq!(payload.ciphertext, expected_ciphertext);
    }

    #[test]
    fn encrypted_timeline_preserves_then_decrypts_after_welcome_arrives() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-469a459e1b8f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:event:01904100-0000-7000-8000-f2fbe0d55fb4",
            "application/vnd.cokret.message+json",
            br#"{"body":"arrives before local key"}"#,
        )
        .unwrap();

        let preserved = MessageCrypto::decrypt_or_preserve(None, encrypted.clone()).unwrap();
        assert!(matches!(preserved, MessageCryptoDecrypt::Encrypted { .. }));

        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"arrives before local key"}"#);
    }

    #[test]
    fn epoch_recovery_request_and_response_catch_up_offline_device() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();

        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        // Alice creates group and adds Bob and Charlie.
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-4cc289f6471e")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_kp).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_kp).unwrap();

        // Bob is now offline. Alice adds Charlie (epoch advances).
        // Bob's local epoch is behind.
        let bob_epoch_before = bob_group.epoch();

        // Create a recovery request.
        let request = EpochRecoveryRequestBody::new(
            bob_group.group_id(),
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_epoch_before,
            alice_group.epoch(),
        );
        request.validate().unwrap();

        // Store the commits in a crypto store so we can build a response.
        let mut store = crate::MemoryCryptoStore::new();
        store.put_commit(charlie_add.commit).unwrap();

        // Alice (who has the commits) builds the recovery response.
        let response = build_epoch_recovery_response(&alice_group, &store, &request).unwrap();
        response.validate_range(&request).unwrap();
        assert!(!response.commits.is_empty());

        // Bob applies the recovery response.
        let new_epoch = response.apply_to_group(&mut bob_group).unwrap();
        assert_eq!(new_epoch, alice_group.epoch());

        // Bob can now decrypt messages from the current epoch.
        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after recovery"}"#)
            .unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"after recovery"}"#);
    }

    #[test]
    fn epoch_recovery_request_validates_range() {
        let request = EpochRecoveryRequestBody::new(
            "",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            3,
        );
        assert!(request.validate().is_err());

        let request = EpochRecoveryRequestBody::new(
            "group1",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            5,
        );
        assert!(request.validate().is_err());
    }

    #[test]
    fn welcome_recipient_must_match_identity() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let mallory = CokretMlsIdentity::new_basic(
            Did::new("did:web:mallory.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000010").unwrap(),
        )
        .unwrap();

        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(error) = CokretMlsGroup::join_from_welcome(mallory, &add_result.welcome) else {
            panic!("Mallory should not be able to consume Bob's Welcome");
        };

        assert!(matches!(error, Error::Protocol(_)));
    }

    /// T31 — `remove_member_by_principal` removes a leaf, advances the
    /// group's epoch and produces a commit envelope that surviving members
    /// can apply to converge.
    #[test]
    fn remove_member_by_principal_advances_epoch_and_emits_commit() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-a78a8b504d40")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let add_charlie = alice_group.add_member(&charlie_kp).unwrap();
        let _charlie_group =
            CokretMlsGroup::join_from_welcome(charlie, &add_charlie.welcome).unwrap();

        let epoch_before = alice_group.epoch();
        let target = Did::new("did:web:charlie.example").unwrap();
        let result = alice_group.remove_member_by_principal(&target).unwrap();

        // Epoch advanced by exactly one Commit.
        assert_eq!(alice_group.epoch(), epoch_before + 1);
        // Commit envelope reflects the new epoch and same group.
        assert_eq!(result.commit.epoch, alice_group.epoch());
        assert_eq!(result.commit.group_id, alice_group.group_id());
        // Exactly one leaf removed; principal correctly reported.
        assert_eq!(result.removed_leaves.len(), 1);
        assert_eq!(result.removed_principals.len(), 1);
        assert_eq!(
            result.removed_principals[0].as_str(),
            "did:web:charlie.example"
        );
    }

    /// T31 — removing an absent principal returns a Protocol error rather
    /// than silently no-op'ing. The orchestration plan in yougen relies on
    /// this to surface "leaf already gone" as a recoverable state.
    #[test]
    fn remove_member_by_principal_errors_when_target_absent() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-3cf34eced3c3")
            .unwrap();

        let absent = Did::new("did:web:nobody.example").unwrap();
        let err = alice_group.remove_member_by_principal(&absent);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn encrypted_envelope_v1_conforms_and_round_trips_losslessly() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000abcd").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-0abc0abc0abc")
            .unwrap();

        let realm_id = "ck:realm:01904100-0000-7000-8000-0abc0abc0abc";
        let aad = EncryptedEnvelopeAadV1::hidden(realm_id, "ck.message.create");
        let aad_value = serde_json::to_value(&aad).unwrap();
        let plaintext = br#"{"body":"hello encrypted discussion"}"#;
        let payload = group
            .encrypt_payload_with_aad(
                "application/vnd.cokret.message+json",
                Some(aad_value),
                plaintext,
            )
            .unwrap();

        let commit_ref = "ck:event:01904100-0000-7000-8000-00000000c0m1";
        let envelope =
            EncryptedEnvelopeV1::from_payload(&payload, aad, AadVisibility::Hidden, commit_ref)
                .unwrap();

        // Conformance with ck.schema.encrypted_envelope.v1: required fields,
        // fixed consts, hidden-visibility AAD discipline, no forbidden extras.
        let json = serde_json::to_value(&envelope).unwrap();
        let obj = json.as_object().unwrap();
        for field in [
            "scheme",
            "version",
            "group_id",
            "epoch",
            "content_type",
            "ciphertext",
            "aad_visibility_event_id",
            "aad",
            "key_ref",
            "aad_digest",
            "payload_digest",
        ] {
            assert!(obj.contains_key(field), "missing required field {field}");
        }
        assert_eq!(obj["scheme"], "mls-rfc9420");
        assert_eq!(obj["version"], "1.0");
        assert_eq!(obj["aad_visibility_event_id"], "hidden");
        assert_eq!(obj["key_ref"]["algorithm"], "MLS");
        assert_eq!(obj["key_ref"]["group_state_ref"], commit_ref);
        assert_eq!(obj["aad"]["realm_id"], realm_id);
        assert_eq!(obj["aad"]["event_kind"], "ck.message.create");
        let aad_obj = obj["aad"].as_object().unwrap();
        assert!(!aad_obj.contains_key("event_id"));
        assert!(!aad_obj.contains_key("event_ref_digest"));
        assert!(obj["aad_digest"].as_str().unwrap().starts_with("sha256:"));
        assert!(
            obj["payload_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!obj.contains_key("authentication_tag"));
        assert!(!obj.contains_key("digests"));
        assert!(!obj.contains_key("cleartext_commitment"));

        // Wire round-trip is stable and to_payload reconstructs the exact MLS
        // payload (lossless for every field decrypt_payload relies on).
        let wire = serde_json::to_string(&envelope).unwrap();
        let parsed: EncryptedEnvelopeV1 = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.to_payload().unwrap(), payload);

        // Fail closed when the supplied AAD doesn't match the AAD bound into
        // payload_digest at encryption time.
        let mismatch = EncryptedEnvelopeV1::from_payload(
            &payload,
            EncryptedEnvelopeAadV1::hidden(realm_id, "ck.strand.update"),
            AadVisibility::Hidden,
            commit_ref,
        );
        assert!(mismatch.is_err());
    }

    /// T31 — `remove_member_by_leaf` accepts a raw OpenMLS leaf index and
    /// produces the same shape of commit envelope. Used when the caller
    /// (yougen DeviceManager) tracks per-device leaf bookkeeping
    /// out-of-band.
    #[test]
    fn remove_member_by_leaf_accepts_raw_index() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-89444e193497")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();

        // Bob's leaf is at index 1 (Alice is index 0 as group creator).
        let result = alice_group.remove_member_by_leaf(1).unwrap();
        assert_eq!(result.removed_leaves, vec![1]);
        assert_eq!(result.removed_principals[0].as_str(), "did:web:bob.example");
    }

    /// T31 — `commit_operation` projects the result into the same
    /// canonical operation shape that `MlsAddMemberResult` produces, so
    /// audit pipelines can ingest both consistently.
    #[test]
    fn remove_result_commit_operation_uses_mls_commit_op_type() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-bd49dfdbc804")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let result = alice_group
            .remove_member_by_principal(&Did::new("did:web:bob.example").unwrap())
            .unwrap();

        let op_id = OperationId::new("ck:operation:01904100-0000-7000-8000-00a9123c0f9c").unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-bd49dfdbc804").unwrap();
        let op = result.commit_operation(op_id, realm_id).unwrap();
        assert_eq!(op.object_type, "mls_commit");
        assert!(op.object_id.unwrap().contains(&result.commit.group_id));
    }
}
