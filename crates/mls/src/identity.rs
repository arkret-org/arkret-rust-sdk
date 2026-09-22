use std::collections::BTreeMap;

use arkret_canonical::{base64url_decode, base64url_encode};
use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageUploadEntry, KeyPackagesConsumeRequestBody,
    KeyPackagesConsumeUnsignedRequest, KeyPackagesUploadRequestBody,
    KeyPackagesUploadUnsignedRequest, MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
    MlsEndpointIdentity, MlsGovernanceBindingPayload, MlsKeyPackageRecord,
    RecipientMlsDurableReceipt, RecipientMlsDurableSigner, decode_keypackage_capability_extension,
    decode_mls_basic_credential_identity, keypackages_consume_signing_input,
    keypackages_upload_signing_input, mls_basic_credential_identity,
    mls_key_package_record_upload_entry, validate_advertised_keypackage_capabilities,
};
use arkret_wire::{
    ActorId, DeviceId, DidCoreId, DidUrl, Hash, NonEmptyString, RealmId, ScopeRef, canonical,
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
    ArkretMlsGroup, arkret_group_context_extensions, arkret_openmls_capabilities, decode, encode,
    keypackage_capabilities_leaf_extensions, mls_error, restore_provider_storage,
    snapshot_provider_storage,
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

fn account_actor_principal(actor_id: &ActorId) -> Result<DidCoreId> {
    actor_id
        .as_account_id()
        .map(|account_id| account_id.principal_id.clone())
        .ok_or_else(|| {
            Error::Protocol("human-device and Agent MLS holders require an account ActorId".into())
        })
}

fn service_actor_principal(actor_id: &ActorId) -> Result<DidCoreId> {
    match actor_id {
        ActorId::Service { service_id } => Ok(service_id.clone()),
        ActorId::Account { .. } => Err(Error::Protocol(
            "service MLS holder requires a service ActorId".into(),
        )),
    }
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
    pub(super) fn credential_bytes(&self, actor_id: &ActorId) -> Result<Vec<u8>> {
        mls_basic_credential_identity(actor_id).map_err(Into::into)
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

pub fn decode_leaf_credential(bytes: &[u8]) -> Result<ActorId> {
    decode_mls_basic_credential_identity(bytes).map_err(Into::into)
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
    pub actor_id: ActorId,
    pub endpoint: MlsEndpointIdentity,
    pub(super) profile: ArkretMlsIdentityProfile,
    pub(super) provider: OpenMlsRustCrypto,
    pub(super) signer: SignatureKeyPair,
    pub(super) credential: CredentialWithKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsIdentityStateSnapshot {
    context: String,
    actor_id: ActorId,
    endpoint: MlsEndpointIdentity,
    profile: ArkretMlsIdentityProfile,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
}

impl ArkretMlsIdentity {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_test_human_device(actor_id: ActorId, device_id: DeviceId) -> Result<Self> {
        let signer = SignatureKeyPair::new(ARKRET_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(mls_error)?;
        let principal_id = account_actor_principal(&actor_id)?;
        Self::new_with_signer(
            actor_id,
            MlsEndpointIdentity::human_device(principal_id, device_id),
            ArkretMlsIdentityProfile::HumanDevice,
            signer,
        )
    }

    pub fn new_human_device(
        actor_id: ActorId,
        device_id: DeviceId,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        let principal_id = account_actor_principal(&actor_id)?;
        Self::new_with_signer(
            actor_id,
            MlsEndpointIdentity::human_device(principal_id, device_id),
            ArkretMlsIdentityProfile::HumanDevice,
            signer.0,
        )
    }

    pub fn new_agent(
        actor_id: ActorId,
        verification_method: DidUrl,
        agent_key_authorize_event_id: arkret_wire::EventId,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        let agent_id = account_actor_principal(&actor_id)?;
        let endpoint = MlsEndpointIdentity::agent_runtime(
            agent_id,
            verification_method.clone(),
            agent_key_authorize_event_id.clone(),
        )?;
        Self::new_with_signer(
            actor_id,
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
        actor_id: ActorId,
        verification_method: DidUrl,
        signer: ArkretMlsSigner,
    ) -> Result<Self> {
        let pairwise_actor_id = service_actor_principal(&actor_id)?;
        let endpoint = MlsEndpointIdentity::minimal_metadata_pairwise(
            pairwise_actor_id.clone(),
            verification_method.clone(),
        )?;
        Self::new_with_signer(
            actor_id,
            endpoint,
            ArkretMlsIdentityProfile::MinimalMetadataPairwise {
                pairwise_actor_id,
                verification_method,
            },
            signer.0,
        )
    }

    fn new_with_signer(
        actor_id: ActorId,
        endpoint: MlsEndpointIdentity,
        profile: ArkretMlsIdentityProfile,
        signer: SignatureKeyPair,
    ) -> Result<Self> {
        actor_id.validate()?;
        if endpoint.principal_id() != actor_id.signing_principal_id() {
            return Err(Error::Protocol(
                "MLS endpoint selector differs from complete ActorId".to_owned(),
            ));
        }
        profile.validate_signer(signer.public())?;
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(profile.credential_bytes(&actor_id)?).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            actor_id,
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
        if record.actor_id != self.actor_id || record.endpoint != self.endpoint_identity() {
            return Err(Error::Protocol(
                "MLS KeyPackage record owner differs from identity".to_owned(),
            ));
        }
        let keypackage = base64url_decode(record.keypackage.as_bytes())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let leaf = author_leaf_from_key_package_bytes(&keypackage, 0)?;
        let crate::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            return Err(Error::Protocol(
                "uploaded KeyPackage does not carry an Arkret BasicCredential".to_owned(),
            ));
        };
        let credential_actor = decode_mls_basic_credential_identity(&identity)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if credential_actor != record.actor_id {
            return Err(Error::Protocol(
                "uploaded KeyPackage credential differs from record actor_id".to_owned(),
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
            actor_id: self.actor_id.clone(),
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
                    recipient_account_id,
                    recipient_device_id,
                    device_verification_method,
                },
            ) if &recipient_account_id.principal_id == principal_id
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
            ) if receipt.recipient_principal_id().as_ref() == Some(agent_id)
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
            ) if receipt.recipient_principal_id().as_ref() == Some(pairwise_actor_id)
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
        let capabilities = arkret_openmls_capabilities();
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
            actor_id: self.actor_id.clone(),
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
            actor_id: self.actor_id.clone(),
            endpoint: self.endpoint.clone(),
            profile: self.profile.clone(),
            signer_public_key: encode(self.signer.public()),
            storage_entries: snapshot_provider_storage(&self.provider)?,
        };
        serde_json::to_vec(&snapshot).map_err(Into::into)
    }

    pub fn restore_from_private_state(
        expected_actor_id: ActorId,
        expected_endpoint: MlsEndpointIdentity,
        serialized_state: &[u8],
    ) -> Result<Self> {
        let snapshot: OpenMlsIdentityStateSnapshot = serde_json::from_slice(serialized_state)?;
        if snapshot.context != ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT {
            return Err(Error::Protocol(
                "unsupported OpenMLS identity state snapshot".to_owned(),
            ));
        }
        if snapshot.actor_id != expected_actor_id || snapshot.endpoint != expected_endpoint {
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
        if snapshot.endpoint.principal_id() != snapshot.actor_id.signing_principal_id() {
            return Err(Error::Protocol(
                "OpenMLS identity state ActorId differs from endpoint selector".to_owned(),
            ));
        }
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                snapshot.profile.credential_bytes(&snapshot.actor_id)?,
            )
            .into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            actor_id: snapshot.actor_id,
            endpoint: snapshot.endpoint,
            profile: snapshot.profile,
            provider,
            signer,
            credential,
        })
    }

    /// Create the MLS group for an effective security scope.
    ///
    /// The `group_id` is derived here and only here, from the scope, so no
    /// caller can seed a group with bytes of its own choosing — that is what
    /// made the pre-2218 reversible `group_id` possible. The scope also decides
    /// the handshake wire-format policy and is kept on the group, because the
    /// digest cannot be read back.
    pub fn create_group(self, scope: &ScopeRef) -> Result<ArkretMlsGroup> {
        let group_id_bytes = scope.canonical_mls_group_id_bytes()?;
        let config = MlsGroupCreateConfig::builder()
            .wire_format_policy(crate::group::handshake_policy(scope)?)
            .ciphersuite(ARKRET_MLS_CIPHERSUITE)
            .capabilities(arkret_openmls_capabilities())
            .with_group_context_extensions(arkret_group_context_extensions(None)?)
            .with_leaf_node_extensions(keypackage_capabilities_leaf_extensions()?)
            .map_err(mls_error)?
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(&group_id_bytes),
            self.credential.clone(),
        )
        .map_err(mls_error)?;

        #[allow(unused_mut)]
        let mut result = ArkretMlsGroup {
            identity: self,
            group,
            scope: scope.clone(),
            group_id: scope.canonical_mls_group_id()?,
            leaf_bindings: BTreeMap::new(),
            signal_nonce_counter: 0,
        };
        #[cfg(any(test, feature = "test-utils"))]
        result.install_test_leaf_bindings(vec![result.identity.endpoint.clone()])?;
        Ok(result)
    }

    pub fn create_group_with_governance_binding(
        self,
        scope: &ScopeRef,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<ArkretMlsGroup> {
        let group_id_bytes = scope.canonical_mls_group_id_bytes()?;
        binding.validate()?;
        if binding.effective_scope() != scope {
            return Err(Error::Protocol(
                "mls_governance_binding.effective_scope does not match the new MLS group"
                    .to_owned(),
            ));
        }
        if binding.mls_group_id()?.as_str() != base64url_encode(group_id_bytes) {
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
            .wire_format_policy(crate::group::handshake_policy(scope)?)
            .ciphersuite(ARKRET_MLS_CIPHERSUITE)
            .capabilities(arkret_openmls_capabilities())
            .with_group_context_extensions(arkret_group_context_extensions(Some(binding))?)
            .with_leaf_node_extensions(keypackage_capabilities_leaf_extensions()?)
            .map_err(mls_error)?
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(&group_id_bytes),
            self.credential.clone(),
        )
        .map_err(mls_error)?;

        #[allow(unused_mut)]
        let mut result = ArkretMlsGroup {
            identity: self,
            group,
            scope: scope.clone(),
            group_id: scope.canonical_mls_group_id()?,
            leaf_bindings: BTreeMap::new(),
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
