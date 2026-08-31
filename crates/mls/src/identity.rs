use std::collections::BTreeMap;

use arkret_canonical::base64url_encode;
use arkret_models_collaboration::events_payloads::{
    MlsRequesterTrustBinding, MlsWelcomeClaimEnvelope, UnsignedMlsWelcomeClaimEnvelope,
};
use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageUploadEntry, KeyPackagesConsumeRequestBody,
    KeyPackagesConsumeUnsignedRequest, KeyPackagesUploadRequestBody,
    KeyPackagesUploadUnsignedRequest, MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
    MlsEndpointIdentity, MlsGovernanceBindingPayload, MlsKeyPackageRecord,
    RecipientMlsDurableReceipt, RecipientMlsDurableSigner, decode_keypackage_capability_extension,
    keypackages_consume_signing_input, keypackages_upload_signing_input,
    mls_key_package_record_upload_entry, validate_advertised_keypackage_capabilities,
};
use arkret_wire::{
    ActorId, Base64UrlString, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, RealmId, canonical,
};
use chrono::{Duration, Utc};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, OpenMlsProvider, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer as _;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::group::{
    ArkretMlsGroup, decode, encode, governance_binding_group_context_extensions,
    governance_binding_openmls_capabilities, keypackage_capabilities_leaf_extensions, mls_error,
    restore_provider_storage, snapshot_provider_storage,
};
use crate::{MlsError as Error, Result};

pub const ARKRET_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Canonical wire string for [`ARKRET_MLS_CIPHERSUITE`], taken verbatim from
/// `mls-ciphersuite-registry.json` (`canonical_id`). This is the ONLY source
/// of the `cipher_suite` / `cipher_suites` wire value — implementations MUST
/// NOT derive it from the third-party `Ciphersuite` `Debug` representation,
/// which is not a wire contract and could silently drift on an openmls
/// upgrade. The `ciphersuite_canonical_id_matches_registry` test pins that
/// the current openmls `Debug` output still equals this constant so any
/// upstream drift fails loudly rather than reaching the wire.
pub const ARKRET_MLS_CIPHERSUITE_CANONICAL_ID: &str =
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
pub const ARKRET_MLS_KEY_PACKAGE_CAPABILITIES: &[&str] = &["ak.content.v1", "mimi.content.v1"];

const ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT: &str = "arkret-openmls-identity-state-v1";

pub(super) fn leaf_credential_bytes(device_id: &DeviceId) -> Vec<u8> {
    device_id.as_str().as_bytes().to_vec()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArkretMlsIdentityProfile {
    HumanDevice,
    Agent {
        verification_method: DidUrl,
        agent_key_authorize_event_id: arkret_wire::EventId,
    },
    MinimalMetadataPairwise {
        pairwise_actor_id: DidCoreId,
        verification_method: DidUrl,
    },
}

impl ArkretMlsIdentityProfile {
    pub(super) fn credential_bytes(&self, endpoint: &MlsEndpointIdentity) -> Vec<u8> {
        match (self, endpoint) {
            (Self::HumanDevice, MlsEndpointIdentity::HumanDevice { device_id, .. }) => {
                leaf_credential_bytes(device_id)
            }
            (Self::Agent { .. }, MlsEndpointIdentity::AgentRuntime { agent_id, .. }) => {
                agent_id.as_str().as_bytes().to_vec()
            }
            (
                Self::MinimalMetadataPairwise {
                    pairwise_actor_id, ..
                },
                MlsEndpointIdentity::MinimalMetadataPairwise { .. },
            ) => pairwise_actor_id.as_str().as_bytes().to_vec(),
            _ => unreachable!("MLS identity profile and endpoint are constructed together"),
        }
    }

    pub(super) fn validate_signer(&self, signer_public_key: &[u8]) -> Result<()> {
        let Self::MinimalMetadataPairwise {
            pairwise_actor_id,
            verification_method,
        } = self
        else {
            return Ok(());
        };
        let signer_public_key: [u8; 32] = signer_public_key.try_into().map_err(|_| {
            Error::Protocol("minimal-metadata MLS signer must be Ed25519".to_owned())
        })?;
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&signer_public_key);
        let expected_actor_id = format!("ak:did_core:key:{multibase}");
        let expected_method = format!("did:key:{multibase}#{multibase}");
        if pairwise_actor_id.as_str() != expected_actor_id {
            return Err(Error::Protocol(
                "minimal-metadata pairwise actor does not name the MLS signer key".to_owned(),
            ));
        }
        if verification_method.as_str() != expected_method {
            return Err(Error::Protocol(
                "minimal-metadata verification method is not the exact did:key signer method"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub(super) fn decode_leaf_credential(bytes: &[u8]) -> Result<NonEmptyString> {
    let encoded = std::str::from_utf8(bytes)
        .map_err(|_| Error::Protocol("MLS BasicCredential is not UTF-8".to_owned()))?;
    let credential_ref = NonEmptyString::new(encoded.to_owned())
        .map_err(|error| Error::Protocol(format!("MLS credential ref is invalid: {error}")))?;
    Ok(credential_ref)
}

pub struct ArkretMlsSigner(SignatureKeyPair);

impl ArkretMlsSigner {
    pub fn from_ed25519_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_key = signing_key.to_bytes().to_vec();
        Self(SignatureKeyPair::from_raw(
            ARKRET_MLS_CIPHERSUITE.signature_algorithm(),
            private_key,
            public_key,
        ))
    }
}

pub struct ArkretMlsIdentity {
    pub endpoint: MlsEndpointIdentity,
    pub(super) profile: ArkretMlsIdentityProfile,
    pub(super) provider: OpenMlsRustCrypto,
    pub(super) signer: SignatureKeyPair,
    pub(super) credential: CredentialWithKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsIdentityStateSnapshot {
    context: String,
    endpoint: MlsEndpointIdentity,
    profile: ArkretMlsIdentityProfile,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
}

impl ArkretMlsIdentity {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_test_human_device(principal_id: DidCoreId, device_id: DeviceId) -> Result<Self> {
        let signer = SignatureKeyPair::new(ARKRET_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(mls_error)?;
        Self::new_with_signer(
            MlsEndpointIdentity::human_device(principal_id, device_id),
            ArkretMlsIdentityProfile::HumanDevice,
            signer,
        )
    }

    pub fn new_human_device(
        principal_id: DidCoreId,
        device_id: DeviceId,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        Self::new_with_signer(
            MlsEndpointIdentity::human_device(principal_id, device_id),
            ArkretMlsIdentityProfile::HumanDevice,
            signer.0,
        )
    }

    pub fn new_agent(
        agent_id: DidCoreId,
        verification_method: DidUrl,
        agent_key_authorize_event_id: arkret_wire::EventId,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        let endpoint = MlsEndpointIdentity::agent_runtime(
            agent_id,
            verification_method.clone(),
            agent_key_authorize_event_id.clone(),
        )?;
        Self::new_with_signer(
            endpoint,
            ArkretMlsIdentityProfile::Agent {
                verification_method,
                agent_key_authorize_event_id,
            },
            signer.0,
        )
    }

    /// Construct a Realm-local minimal-metadata MLS identity. The local
    /// principal/device coordinates remain private persistence metadata; the
    /// BasicCredential and sender domain expose only `pairwise_actor_id`.
    pub fn new_minimal_metadata_pairwise(
        pairwise_actor_id: DidCoreId,
        verification_method: DidUrl,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        let endpoint = MlsEndpointIdentity::minimal_metadata_pairwise(
            pairwise_actor_id.clone(),
            verification_method.clone(),
        )?;
        Self::new_with_signer(
            endpoint,
            ArkretMlsIdentityProfile::MinimalMetadataPairwise {
                pairwise_actor_id,
                verification_method,
            },
            signer.0,
        )
    }

    fn new_with_signer(
        endpoint: MlsEndpointIdentity,
        profile: ArkretMlsIdentityProfile,
        signer: SignatureKeyPair,
    ) -> Result<Self> {
        profile.validate_signer(signer.public())?;
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(profile.credential_bytes(&endpoint)).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            endpoint,
            profile,
            provider,
            signer,
            credential,
        })
    }

    pub fn profile(&self) -> &ArkretMlsIdentityProfile {
        &self.profile
    }

    pub fn endpoint_identity(&self) -> MlsEndpointIdentity {
        self.endpoint.clone()
    }

    /// Build a single-use KeyPackage record (consumed on claim).
    pub fn key_package_record(&self) -> Result<MlsKeyPackageRecord> {
        self.key_package_record_inner()
    }

    /// Convert a locally generated MLS record into the canonical typed upload
    /// entry shared by ordinary clients and Agent runtimes.
    pub fn key_package_upload_entry(
        &self,
        record: &MlsKeyPackageRecord,
    ) -> Result<KeyPackageUploadEntry> {
        if record.endpoint != self.endpoint_identity() {
            return Err(Error::Protocol(
                "MLS KeyPackage record owner differs from identity".to_owned(),
            ));
        }
        mls_key_package_record_upload_entry(record)
            .map_err(|error| Error::Protocol(error.to_owned()))
    }

    /// Build and sign a standard KeyPackage upload request with this MLS
    /// identity key. Agent runtimes call this only after the identity private
    /// state and generated KeyPackage material are durably persisted.
    pub fn signed_key_packages_upload_request(
        &self,
        records: &[MlsKeyPackageRecord],
        verification_method: &str,
        intended_realm_id: Option<RealmId>,
    ) -> Result<KeyPackagesUploadRequestBody> {
        if records.is_empty() {
            return Err(Error::Protocol(
                "KeyPackage upload requires at least one record".to_owned(),
            ));
        }
        let keypackages = records
            .iter()
            .map(|record| self.key_package_upload_entry(record))
            .collect::<Result<Vec<_>>>()?;
        let (
            principal_id,
            device_id,
            pairwise_verification_method,
            intended_realm_id,
            agent_verification_method,
            agent_key_authorize_event_id,
        ) = match (&self.profile, &self.endpoint) {
            (
                ArkretMlsIdentityProfile::HumanDevice,
                MlsEndpointIdentity::HumanDevice {
                    principal_id,
                    device_id,
                },
            ) => {
                if intended_realm_id.is_some() {
                    return Err(Error::Protocol(
                        "human-device KeyPackage upload must not carry pairwise Realm affinity"
                            .to_owned(),
                    ));
                }
                (
                    principal_id.clone(),
                    Some(device_id.clone()),
                    None,
                    None,
                    None,
                    None,
                )
            }
            (
                ArkretMlsIdentityProfile::Agent {
                    verification_method,
                    agent_key_authorize_event_id,
                },
                MlsEndpointIdentity::AgentRuntime { agent_id, .. },
            ) => (
                agent_id.clone(),
                None,
                None,
                None,
                Some(verification_method.clone()),
                Some(agent_key_authorize_event_id.clone()),
            ),
            (
                ArkretMlsIdentityProfile::MinimalMetadataPairwise {
                    pairwise_actor_id,
                    verification_method,
                },
                MlsEndpointIdentity::MinimalMetadataPairwise { .. },
            ) => {
                let realm_id = intended_realm_id.ok_or_else(|| {
                    Error::Protocol(
                        "minimal-metadata KeyPackage upload requires intended Realm affinity"
                            .to_owned(),
                    )
                })?;
                (
                    pairwise_actor_id.clone(),
                    None,
                    Some(verification_method.clone()),
                    Some(realm_id),
                    None,
                    None,
                )
            }
            _ => {
                return Err(Error::Protocol(
                    "MLS identity profile/endpoint mismatch".to_owned(),
                ));
            }
        };
        let unsigned = KeyPackagesUploadUnsignedRequest {
            principal_id,
            device_id,
            pairwise_verification_method,
            intended_realm_id,
            agent_verification_method,
            agent_key_authorize_event_id,
            keypackages,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        if unsigned
            .pairwise_verification_method
            .as_ref()
            .is_some_and(|method| method.as_str() != verification_method)
        {
            return Err(Error::Protocol(
                "minimal-metadata upload signer differs from the pairwise endpoint method"
                    .to_owned(),
            ));
        }
        unsigned
            .validate_shape()
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        let signature = self.sign_keypackage_input(
            verification_method,
            &keypackages_upload_signing_input(&unsigned)?,
        )?;
        Ok(unsigned.into_signed(signature))
    }

    /// Sign the recipient's durable-acceptance receipt with the exact MLS
    /// endpoint key that owned the claimed KeyPackage. This is called only
    /// after the joined snapshot has crossed the client's durable barrier.
    pub fn sign_recipient_mls_durable_receipt(
        &self,
        mut receipt: RecipientMlsDurableReceipt,
    ) -> Result<RecipientMlsDurableReceipt> {
        let verification_method = match (&self.endpoint, &receipt.recipient) {
            (
                MlsEndpointIdentity::HumanDevice {
                    principal_id,
                    device_id,
                },
                RecipientMlsDurableSigner::Device {
                    recipient_device_id,
                    device_verification_method,
                },
            ) if &receipt.recipient_principal_id == principal_id
                && recipient_device_id == device_id =>
            {
                device_verification_method
            }
            (
                MlsEndpointIdentity::AgentRuntime {
                    agent_id,
                    verification_method,
                    agent_key_authorize_event_id,
                },
                RecipientMlsDurableSigner::Agent {
                    recipient_agent_id,
                    recipient_agent_verification_method,
                    agent_key_authorize_event_id: recipient_agent_key_authorize_event_id,
                },
            ) if &receipt.recipient_principal_id == agent_id
                && recipient_agent_id == agent_id
                && recipient_agent_verification_method == verification_method
                && recipient_agent_key_authorize_event_id == agent_key_authorize_event_id =>
            {
                recipient_agent_verification_method
            }
            (
                MlsEndpointIdentity::MinimalMetadataPairwise {
                    pairwise_actor_id,
                    verification_method,
                },
                RecipientMlsDurableSigner::MinimalMetadataPairwise {
                    recipient_pairwise_verification_method,
                },
            ) if &receipt.recipient_principal_id == pairwise_actor_id
                && recipient_pairwise_verification_method == verification_method =>
            {
                recipient_pairwise_verification_method
            }
            _ => {
                return Err(Error::Protocol(
                    "recipient durable receipt does not match this MLS endpoint".to_owned(),
                ));
            }
        }
        .clone();
        receipt.signature = self.sign_keypackage_input(
            verification_method.as_str(),
            &receipt.canonical_signing_bytes()?,
        )?;
        receipt
            .validate_shape()
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        Ok(receipt)
    }

    /// Sign the single-source consume command with the same endpoint key as
    /// the required durable receipt. No Account/Device mirror is introduced.
    pub fn signed_key_packages_consume_request(
        &self,
        claim_id: NonEmptyString,
        recipient_durable_receipt: RecipientMlsDurableReceipt,
    ) -> Result<KeyPackagesConsumeRequestBody> {
        let unsigned = KeyPackagesConsumeUnsignedRequest {
            claim_id,
            recipient_durable_receipt,
        };
        unsigned
            .validate_shape()
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        let method = match &unsigned.recipient_durable_receipt.recipient {
            RecipientMlsDurableSigner::Device {
                device_verification_method,
                ..
            } => device_verification_method,
            RecipientMlsDurableSigner::Agent {
                recipient_agent_verification_method,
                ..
            } => recipient_agent_verification_method,
            RecipientMlsDurableSigner::MinimalMetadataPairwise {
                recipient_pairwise_verification_method,
            } => recipient_pairwise_verification_method,
        };
        let signature = self.sign_keypackage_input(
            method.as_str(),
            &keypackages_consume_signing_input(&unsigned)?,
        )?;
        let body = unsigned.into_signed(signature);
        body.validate_shape()
            .map_err(|error| Error::Protocol(error.to_owned()))?;
        Ok(body)
    }

    /// Sign a Welcome claim envelope as a minimal-metadata pairwise requester.
    /// The requester authority is the exact MLS Leaf did:key; no transport
    /// Account or Device identity is inferred or mirrored into the transcript.
    pub fn sign_pairwise_welcome_claim_envelope(
        &self,
        envelope: UnsignedMlsWelcomeClaimEnvelope,
    ) -> Result<MlsWelcomeClaimEnvelope> {
        let ArkretMlsIdentityProfile::MinimalMetadataPairwise {
            pairwise_actor_id,
            verification_method,
        } = &self.profile
        else {
            return Err(Error::Protocol(
                "pairwise Welcome requester signing requires a pairwise MLS identity".to_owned(),
            ));
        };
        let input = envelope.signing_input();
        if input.requester_actor_id != ActorId::service(pairwise_actor_id.clone())
            || !matches!(
                &input.trust_binding,
                MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                    requester_pairwise_verification_method,
                } if requester_pairwise_verification_method == verification_method
            )
        {
            return Err(Error::Protocol(
                "Welcome requester transcript does not match this pairwise MLS identity".to_owned(),
            ));
        }
        let signing_bytes = envelope.canonical_signing_bytes()?;
        let signature = self.signer.sign(&signing_bytes).map_err(mls_error)?;
        envelope
            .attach_signature(
                NonEmptyString::new(verification_method.as_str())
                    .map_err(|error| Error::Protocol(error.to_owned()))?,
                Base64UrlString::new(base64url_encode(signature))
                    .map_err(|error| Error::Protocol(error.to_owned()))?,
            )
            .map_err(Into::into)
    }

    fn sign_keypackage_input(
        &self,
        verification_method: &str,
        signing_input: &[u8],
    ) -> Result<KeyOperationSignature> {
        let signature = self.signer.sign(signing_input).map_err(mls_error)?;
        arkret_signatures::keypackages::keypackage_signature_from_bytes(
            verification_method,
            &signature,
        )
        .map_err(|error| Error::Protocol(error.to_string()))
    }

    fn key_package_record_inner(&self) -> Result<MlsKeyPackageRecord> {
        let capabilities = governance_binding_openmls_capabilities();
        let builder = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(keypackage_capabilities_leaf_extensions()?);
        let keypackage = builder
            .build(
                ARKRET_MLS_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls_error)?;
        let keypackage = keypackage.key_package();
        let key_package_bytes = keypackage.tls_serialize_detached().map_err(mls_error)?;
        let keypackage_ref = Hash::new(canonical::sha256_digest(&key_package_bytes))?;

        let created_at = Utc::now();
        Ok(MlsKeyPackageRecord {
            keypackage_id: format!("ak:mls:kp:{}", uuid::Uuid::now_v7()),
            endpoint: self.endpoint_identity(),
            keypackage: encode(&key_package_bytes),
            keypackage_ref,
            cipher_suites: vec![ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned()],
            capabilities: ARKRET_MLS_KEY_PACKAGE_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            state: arkret_models_crypto::MlsKeyPackageState::Published,
            claim_id: None,
            created_at,
            expires_at: Some(created_at + Duration::days(7)),
            last_resort: false,
        })
    }

    pub fn export_private_state(&self) -> Result<Vec<u8>> {
        let snapshot = OpenMlsIdentityStateSnapshot {
            context: ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT.to_owned(),
            endpoint: self.endpoint.clone(),
            profile: self.profile.clone(),
            signer_public_key: encode(self.signer.public()),
            storage_entries: snapshot_provider_storage(&self.provider)?,
        };
        serde_json::to_vec(&snapshot).map_err(Into::into)
    }

    pub fn restore_from_private_state(
        expected_endpoint: MlsEndpointIdentity,
        serialized_state: &[u8],
    ) -> Result<Self> {
        let snapshot: OpenMlsIdentityStateSnapshot = serde_json::from_slice(serialized_state)?;
        if snapshot.context != ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT {
            return Err(Error::Protocol(
                "unsupported OpenMLS identity state snapshot".to_owned(),
            ));
        }
        if snapshot.endpoint != expected_endpoint {
            return Err(Error::Protocol(
                "OpenMLS identity state snapshot metadata mismatch".to_owned(),
            ));
        }

        let provider = OpenMlsRustCrypto::default();
        restore_provider_storage(&provider, &snapshot.storage_entries)?;
        let signer_public_key = decode(&snapshot.signer_public_key)?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signer_public_key,
            ARKRET_MLS_CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| Error::Protocol("OpenMLS signer is missing from snapshot".to_owned()))?;
        snapshot.profile.validate_signer(signer.public())?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(snapshot.profile.credential_bytes(&snapshot.endpoint))
                .into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            endpoint: snapshot.endpoint,
            profile: snapshot.profile,
            provider,
            signer,
            credential,
        })
    }

    pub fn create_group(self, group_id: impl AsRef<[u8]>) -> Result<ArkretMlsGroup> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ARKRET_MLS_CIPHERSUITE)
            .capabilities(governance_binding_openmls_capabilities())
            .with_group_context_extensions(governance_binding_group_context_extensions(None)?)
            .with_leaf_node_extensions(keypackage_capabilities_leaf_extensions()?)
            .map_err(mls_error)?
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

        #[allow(unused_mut)]
        let mut result = ArkretMlsGroup {
            identity: self,
            group,
            leaf_bindings: BTreeMap::new(),
            history_secrets: BTreeMap::new(),
            content_nonce_counter: 0,
            signal_nonce_counter: 0,
        };
        #[cfg(any(test, feature = "test-utils"))]
        result.install_test_leaf_bindings(vec![result.identity.endpoint.clone()])?;
        Ok(result)
    }

    pub fn create_group_with_governance_binding(
        self,
        group_id: impl AsRef<[u8]>,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<ArkretMlsGroup> {
        let group_id_bytes = group_id.as_ref();
        binding.validate()?;
        if binding.mls_group_id() != base64url_encode(group_id_bytes) {
            return Err(Error::Protocol(
                "mls_governance_binding.mls_group_id does not match new MLS group".to_owned(),
            ));
        }
        if binding.previous_epoch() != 0 || binding.next_epoch() != 0 {
            return Err(Error::Protocol(
                "initial mls_governance_binding epoch must be 0".to_owned(),
            ));
        }

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ARKRET_MLS_CIPHERSUITE)
            .capabilities(governance_binding_openmls_capabilities())
            .with_group_context_extensions(governance_binding_group_context_extensions(Some(
                binding,
            ))?)
            .with_leaf_node_extensions(keypackage_capabilities_leaf_extensions()?)
            .map_err(mls_error)?
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id_bytes),
            self.credential.clone(),
        )
        .map_err(mls_error)?;

        #[allow(unused_mut)]
        let mut result = ArkretMlsGroup {
            identity: self,
            group,
            leaf_bindings: BTreeMap::new(),
            history_secrets: BTreeMap::new(),
            content_nonce_counter: 0,
            signal_nonce_counter: 0,
        };
        #[cfg(any(test, feature = "test-utils"))]
        result.install_test_leaf_bindings(vec![result.identity.endpoint.clone()])?;
        Ok(result)
    }
}

pub(super) fn decode_key_package(
    provider: &OpenMlsRustCrypto,
    record: &MlsKeyPackageRecord,
) -> Result<KeyPackage> {
    let bytes = decode(&record.keypackage)?;
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

/// Decode a TLS-serialized wire KeyPackage into minimal-metadata author-leaf
/// material (encryption-and-audit.md §2.10.3). The KeyPackage is
/// cryptographically validated (RFC 9420 §10) before its leaf fields are
/// trusted. `leaf_index` is caller-assigned — a wire KeyPackage carries no
/// tree position; servers folding claimed KeyPackages into an
/// [`crate::AuthorGroupStateView`] number them by iteration order.
pub fn author_leaf_from_key_package_bytes(
    bytes: &[u8],
    leaf_index: u32,
) -> Result<crate::AuthorLeaf> {
    let provider = OpenMlsRustCrypto::default();
    let key_package_in = KeyPackageIn::tls_deserialize_exact(bytes).map_err(mls_error)?;
    let keypackage = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls_error)?;
    let leaf = keypackage.leaf_node();
    let leaf_credential = leaf.credential();
    let credential = if leaf_credential.credential_type() == openmls::prelude::CredentialType::Basic
    {
        crate::AuthorLeafCredential::Basic {
            identity: leaf_credential.serialized_content().to_vec(),
        }
    } else {
        crate::AuthorLeafCredential::Other {
            credential_type: format!("{:?}", leaf_credential.credential_type()),
        }
    };
    Ok(crate::AuthorLeaf {
        leaf_index,
        credential,
        signature_key: leaf.signature_key().as_slice().to_vec(),
        leaf_node_canonical_bytes: leaf.tls_serialize_detached().map_err(mls_error)?,
    })
}

/// Return the application capabilities authenticated by the KeyPackage
/// LeafNode signature.
pub fn keypackage_capabilities_from_key_package_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let provider = OpenMlsRustCrypto::default();
    let key_package_in = KeyPackageIn::tls_deserialize_exact(bytes).map_err(mls_error)?;
    let keypackage = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls_error)?;
    let extension = keypackage
        .leaf_node()
        .extensions()
        .unknown(MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE)
        .ok_or_else(|| {
            Error::Protocol("KeyPackage LeafNode keypackage_capabilities is missing".to_owned())
        })?;
    decode_keypackage_capability_extension(&extension.0)
        .map_err(|error| Error::Protocol(error.to_string()))
}

/// Verify that the HTTP/storage projection exactly repeats the capabilities
/// authenticated by the KeyPackage LeafNode signature.
pub fn validate_keypackage_capability_binding(bytes: &[u8], advertised: &[String]) -> Result<()> {
    let advertised_refs = advertised.iter().map(String::as_str).collect::<Vec<_>>();
    validate_advertised_keypackage_capabilities(&advertised_refs)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let signed = keypackage_capabilities_from_key_package_bytes(bytes)?;
    if signed != advertised {
        return Err(Error::Protocol(
            "outer KeyPackage capabilities do not match signed LeafNode capabilities".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn ciphersuite_canonical_id_matches_registry() {
        // The wire `cipher_suite(s)` value is sourced from
        // ARKRET_MLS_CIPHERSUITE_CANONICAL_ID (the registry canonical_id),
        // NOT from the openmls `Debug` impl. Pin that the two still agree so
        // an upstream openmls change to `Debug` fails here instead of
        // silently emitting an off-registry cipher_suite string on the wire.
        assert_eq!(
            format!("{ARKRET_MLS_CIPHERSUITE:?}"),
            ARKRET_MLS_CIPHERSUITE_CANONICAL_ID
        );
    }

    #[test]
    fn key_package_record_carries_required_capabilities() {
        let identity = ArkretMlsIdentity::new_test_human_device(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();

        let record = identity.key_package_record().unwrap();
        assert_eq!(
            record.capabilities,
            vec!["ak.content.v1".to_owned(), "mimi.content.v1".to_owned()]
        );

        let value = serde_json::to_value(&record).unwrap();
        assert!(
            matches!(value.get("capabilities"), Some(Value::Array(values)) if !values.is_empty())
        );

        let key_package_bytes = decode(&record.keypackage).unwrap();
        assert_eq!(
            keypackage_capabilities_from_key_package_bytes(&key_package_bytes).unwrap(),
            record.capabilities
        );
        validate_keypackage_capability_binding(&key_package_bytes, &record.capabilities).unwrap();
        let mut mismatched = record.capabilities;
        mismatched.pop();
        assert!(validate_keypackage_capability_binding(&key_package_bytes, &mismatched).is_err());
    }

    #[test]
    fn agent_identity_reuses_authorized_runtime_signing_key() {
        let seed = [7_u8; 32];
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let agent_id = DidCoreId::new("ak:did_core:web:agent.example".to_owned()).unwrap();
        let identity = ArkretMlsIdentity::new_agent(
            agent_id,
            DidUrl::new("did:web:agent.example#runtime".to_owned()).unwrap(),
            arkret_wire::EventId::new(
                "ak:event:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh".to_owned(),
            )
            .unwrap(),
            ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed)),
        )
        .unwrap();

        let record = identity.key_package_record().unwrap();
        let leaf =
            author_leaf_from_key_package_bytes(&decode(&record.keypackage).unwrap(), 0).unwrap();
        assert_eq!(leaf.signature_key, expected);
    }

    fn minimal_profile_inputs(seed: [u8; 32]) -> (DidCoreId, DidUrl) {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key);
        (
            DidCoreId::new(format!("ak:did_core:key:{multibase}")).unwrap(),
            DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap(),
        )
    }

    #[test]
    fn minimal_metadata_identity_binds_pairwise_leaf_sender_and_restore() {
        let seed = [19_u8; 32];
        let (pairwise_actor_id, verification_method) = minimal_profile_inputs(seed);
        let identity = ArkretMlsIdentity::new_minimal_metadata_pairwise(
            pairwise_actor_id.clone(),
            verification_method.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed)),
        )
        .unwrap();
        assert_eq!(
            identity.profile(),
            &ArkretMlsIdentityProfile::MinimalMetadataPairwise {
                pairwise_actor_id: pairwise_actor_id.clone(),
                verification_method: verification_method.clone(),
            }
        );
        let key_package = identity.key_package_record().unwrap();
        assert_eq!(
            key_package.endpoint,
            MlsEndpointIdentity::MinimalMetadataPairwise {
                pairwise_actor_id: pairwise_actor_id.clone(),
                verification_method: verification_method.clone(),
            }
        );
        let key_package_leaf =
            author_leaf_from_key_package_bytes(&decode(&key_package.keypackage).unwrap(), 0)
                .unwrap();
        assert_eq!(
            key_package_leaf.credential,
            crate::AuthorLeafCredential::Basic {
                identity: pairwise_actor_id.as_str().as_bytes().to_vec(),
            }
        );

        let private_state = identity.export_private_state().unwrap();
        let restored = ArkretMlsIdentity::restore_from_private_state(
            MlsEndpointIdentity::minimal_metadata_pairwise(
                pairwise_actor_id.clone(),
                verification_method.clone(),
            )
            .unwrap(),
            &private_state,
        )
        .unwrap();
        let alice = ArkretMlsIdentity::new_test_human_device(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002".to_owned()).unwrap(),
        )
        .unwrap();
        let alice_endpoint = alice.endpoint_identity();
        let mut alice_group = alice.create_group(b"minimal-profile-identity").unwrap();
        let add = alice_group.add_member(&key_package).unwrap();
        assert_eq!(
            add.welcome.recipient,
            MlsEndpointIdentity::MinimalMetadataPairwise {
                pairwise_actor_id: pairwise_actor_id.clone(),
                verification_method: verification_method.clone(),
            }
        );
        let welcome_wire = serde_json::to_value(&add.welcome).unwrap();
        assert!(welcome_wire.get("recipient_principal_id").is_none());
        assert_eq!(
            welcome_wire["recipient_pairwise_actor_id"],
            pairwise_actor_id.as_str()
        );
        assert_eq!(
            welcome_wire["recipient_pairwise_verification_method"],
            verification_method.as_str()
        );
        let welcome: arkret_models_crypto::MlsWelcomeEnvelope =
            serde_json::from_value(welcome_wire).unwrap();
        assert_eq!(welcome, add.welcome);
        let serialized_welcome = serde_json::to_vec(&welcome).unwrap();
        let decoded_welcome: arkret_models_crypto::MlsWelcomeEnvelope =
            serde_json::from_slice(&serialized_welcome).unwrap();
        assert_eq!(decoded_welcome, welcome);
        let mut group = ArkretMlsGroup::join_from_welcome(restored, &decoded_welcome).unwrap();
        group
            .install_test_leaf_bindings(vec![alice_endpoint, key_package.endpoint.clone()])
            .unwrap();
        assert_eq!(
            group.local_content_sender_domain().unwrap(),
            pairwise_actor_id.as_str()
        );
        let leaves = group.active_author_leaves();
        let pairwise_leaf = leaves
            .iter()
            .find(|leaf| {
                leaf.credential
                    == (crate::AuthorLeafCredential::Basic {
                        identity: pairwise_actor_id.as_str().as_bytes().to_vec(),
                    })
            })
            .unwrap();
        assert_eq!(
            pairwise_leaf.signature_key,
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
                .to_vec()
        );

        let record = group.export_state_record().unwrap();
        let restored_group = ArkretMlsGroup::restore_from_state_record(&record).unwrap();
        assert_eq!(
            restored_group.local_content_sender_domain().unwrap(),
            pairwise_actor_id.as_str()
        );
        assert_eq!(
            restored_group.identity().profile(),
            &ArkretMlsIdentityProfile::MinimalMetadataPairwise {
                pairwise_actor_id,
                verification_method,
            }
        );
    }

    #[test]
    fn minimal_metadata_identity_rejects_actor_or_method_key_mismatch() {
        let seed = [23_u8; 32];
        let (pairwise_actor_id, verification_method) = minimal_profile_inputs(seed);
        let (other_actor_id, other_method) = minimal_profile_inputs([24_u8; 32]);
        assert!(
            ArkretMlsIdentity::new_minimal_metadata_pairwise(
                other_actor_id,
                verification_method,
                ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
                    &seed
                ),),
            )
            .is_err()
        );
        assert!(
            ArkretMlsIdentity::new_minimal_metadata_pairwise(
                pairwise_actor_id,
                other_method,
                ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
                    &seed
                ),),
            )
            .is_err()
        );
    }

    #[test]
    fn pairwise_identity_signs_welcome_durable_receipt_and_consume_command() {
        let seed = [31_u8; 32];
        let (pairwise_actor_id, verification_method) = minimal_profile_inputs(seed);
        let identity = ArkretMlsIdentity::new_minimal_metadata_pairwise(
            pairwise_actor_id.clone(),
            verification_method.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed)),
        )
        .unwrap();
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/keypackage-pairwise-welcome-fixture.json",
        )
        .unwrap();
        let claim_receipt: arkret_models_crypto::PeerKeyPackageClaimReceipt =
            serde_json::from_value(
                fixture["schema_validation_cases"][0]["instance"]["claim_receipt"].clone(),
            )
            .unwrap();
        let claim_request_id = claim_receipt.claim_request_id.clone();
        let keypackage_ref = format!("sha256:{}", "11".repeat(32));
        let welcome_digest = Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
        let envelope = UnsignedMlsWelcomeClaimEnvelope::new(
            arkret_models_collaboration::events_payloads::mls::MlsWelcomeClaimEnvelopeSigningInput {
                keypackage_ref: keypackage_ref.clone(),
                keypackage_digest: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
                intended_realm_id: RealmId::new(
                    "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".to_owned(),
                )
                .unwrap(),
                claim_id: NonEmptyString::new("claim-without-keypackage-prefix").unwrap(),
                requester_actor_id: ActorId::service(pairwise_actor_id.clone()),
                trust_binding: MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                    requester_pairwise_verification_method: verification_method.clone(),
                },
                welcome_digest: welcome_digest.clone(),
                created_at: Utc::now(),
            },
            &claim_receipt,
        )
        .unwrap();
        let envelope = identity
            .sign_pairwise_welcome_claim_envelope(envelope)
            .unwrap();
        assert_eq!(
            envelope.signature.kid.as_str(),
            verification_method.as_str()
        );

        let placeholder = KeyOperationSignature {
            kid: NonEmptyString::new(verification_method.as_str()).unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let receipt = RecipientMlsDurableReceipt {
            domain: NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1,
            )
            .unwrap(),
            claim_request_id,
            key_package_ref: NonEmptyString::new(keypackage_ref).unwrap(),
            recipient_principal_id: pairwise_actor_id,
            recipient: RecipientMlsDurableSigner::MinimalMetadataPairwise {
                recipient_pairwise_verification_method: verification_method.clone(),
            },
            recipient_id: DidCoreId::new("ak:did_core:webvh:z6mkfixtureservice".to_owned())
                .unwrap(),
            realm_id: RealmId::new(
                "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".to_owned(),
            )
            .unwrap(),
            mls_group_id: NonEmptyString::new("pairwise-group").unwrap(),
            mls_epoch: 1,
            welcome_ref: arkret_wire::EventId::new(
                "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            )
            .unwrap(),
            welcome_digest,
            durable_at: Utc::now(),
            signature: placeholder,
        };
        let receipt = identity
            .sign_recipient_mls_durable_receipt(receipt)
            .unwrap();
        let request = identity
            .signed_key_packages_consume_request(
                NonEmptyString::new("claim-without-keypackage-prefix").unwrap(),
                receipt,
            )
            .unwrap();
        assert_eq!(request.signature.kid.as_str(), verification_method.as_str());
        request.validate_shape().unwrap();
    }
}
