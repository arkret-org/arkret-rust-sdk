use chrono::Utc;
use cokret_core::base64url_encode;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, OpenMlsProvider, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::group::{
    CokretMlsGroup, decode, encode, governance_binding_group_context_extensions,
    governance_binding_openmls_capabilities, mls_error,
};
use super::recovery::{MlsDeviceWorkflowAction, MlsDeviceWorkflowStep};
use crate::{
    DeviceId, Did, Error, Hash, MlsGovernanceBindingPayload, MlsKeyPackageRecord, Result, canonical,
};

pub const COKRET_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub struct CokretMlsIdentity {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub(super) provider: OpenMlsRustCrypto,
    pub(super) signer: SignatureKeyPair,
    pub(super) credential: CredentialWithKey,
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
            .leaf_node_capabilities(governance_binding_openmls_capabilities())
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
            .capabilities(governance_binding_openmls_capabilities())
            .with_group_context_extensions(governance_binding_group_context_extensions(None)?)
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

    pub fn create_group_with_governance_binding(
        self,
        group_id: impl AsRef<[u8]>,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<CokretMlsGroup> {
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
            .ciphersuite(COKRET_MLS_CIPHERSUITE)
            .capabilities(governance_binding_openmls_capabilities())
            .with_group_context_extensions(governance_binding_group_context_extensions(Some(
                binding,
            ))?)
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

        Ok(CokretMlsGroup {
            identity: self,
            group,
        })
    }
}

pub(super) fn decode_key_package(
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
