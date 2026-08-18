use std::collections::BTreeMap;

use arkret_canonical::base64url_encode;
use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageConsumer, KeyPackageUploadEntry,
    KeyPackagesConsumeRequestBody, KeyPackagesConsumeUnsignedRequest, KeyPackagesRevokeRequestBody,
    KeyPackagesRevokeUnsignedRequest, KeyPackagesUploadRequestBody,
    KeyPackagesUploadUnsignedRequest, MlsEndpointIdentity, MlsGovernanceBindingPayload,
    MlsKeyPackageRecord, keypackages_consume_signing_input, keypackages_revoke_signing_input,
    keypackages_upload_signing_input, mls_key_package_record_upload_entry,
};
use arkret_wire::{DeviceId, DidCoreId, Hash, NonEmptyString, canonical};
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
use zeroize::Zeroize;

use crate::group::{
    ArkretMlsGroup, decode, encode, governance_binding_group_context_extensions,
    governance_binding_last_resort_openmls_capabilities, governance_binding_openmls_capabilities,
    mls_error, restore_provider_storage, snapshot_provider_storage,
};
use crate::recovery::{MlsDeviceWorkflowAction, MlsDeviceWorkflowStep};
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
pub const ARKRET_MLS_KEY_PACKAGE_CAPABILITIES: &[&str] = &["mimi.content.v1", "ak.content.v1"];

const ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT: &str = "arkret-openmls-identity-state-v1";

pub(super) fn leaf_credential_bytes(principal_id: &DidCoreId, device_id: &DeviceId) -> Vec<u8> {
    format!("{}#{}", principal_id.as_str(), device_id.as_str()).into_bytes()
}

pub(super) fn decode_leaf_credential(bytes: &[u8]) -> Result<(DidCoreId, NonEmptyString)> {
    let encoded = std::str::from_utf8(bytes)
        .map_err(|_| Error::Protocol("MLS BasicCredential is not UTF-8".to_owned()))?;
    let (principal, device) = encoded.rsplit_once('#').ok_or_else(|| {
        Error::Protocol("MLS BasicCredential must bind a principal DID and device id".to_owned())
    })?;
    let principal_id = DidCoreId::new(principal.to_owned())?;
    DeviceId::new(device.to_owned()).map_err(|error| {
        Error::Protocol(format!("MLS BasicCredential device id is invalid: {error}"))
    })?;
    let credential_ref = NonEmptyString::new(encoded.to_owned())
        .map_err(|error| Error::Protocol(format!("MLS credential ref is invalid: {error}")))?;
    Ok((principal_id, credential_ref))
}

pub struct ArkretMlsIdentity {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub(super) provider: OpenMlsRustCrypto,
    pub(super) signer: SignatureKeyPair,
    pub(super) credential: CredentialWithKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OpenMlsIdentityStateSnapshot {
    context: String,
    principal_id: DidCoreId,
    device_id: DeviceId,
    signer_public_key: String,
    storage_entries: BTreeMap<String, String>,
}

impl ArkretMlsIdentity {
    pub fn new_basic(principal_id: DidCoreId, device_id: DeviceId) -> Result<Self> {
        let signer = SignatureKeyPair::new(ARKRET_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(mls_error)?;
        Self::new_with_signer(principal_id, device_id, signer)
    }

    /// Construct the MLS identity from an already-authorized Ed25519 runtime
    /// seed. Native Agent runtimes use this path so the MLS LeafNode signature
    /// key is the same key named by `ak.agent.key.authorize.verification_method`.
    pub fn from_ed25519_signing_seed(
        principal_id: DidCoreId,
        device_id: DeviceId,
        mut signing_seed: [u8; 32],
    ) -> Result<Self> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        drop(signing_key);
        let signer = SignatureKeyPair::from_raw(
            ARKRET_MLS_CIPHERSUITE.signature_algorithm(),
            signing_seed.to_vec(),
            public_key,
        );
        signing_seed.zeroize();
        Self::new_with_signer(principal_id, device_id, signer)
    }

    fn new_with_signer(
        principal_id: DidCoreId,
        device_id: DeviceId,
        signer: SignatureKeyPair,
    ) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(mls_error)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(leaf_credential_bytes(&principal_id, &device_id))
                .into(),
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

    #[must_use]
    pub fn signature_public_key(&self) -> &[u8] {
        self.signer.public()
    }

    /// Build a single-use KeyPackage record (consumed on claim).
    pub fn key_package_record(&self) -> Result<MlsKeyPackageRecord> {
        self.key_package_record_inner(false)
    }

    /// Convert a locally generated MLS record into the canonical typed upload
    /// entry shared by ordinary clients and Native Agent runtimes.
    pub fn key_package_upload_entry(
        &self,
        record: &MlsKeyPackageRecord,
    ) -> Result<KeyPackageUploadEntry> {
        if record.endpoint
            != MlsEndpointIdentity::human_device(self.principal_id.clone(), self.device_id.clone())
        {
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
        let unsigned = KeyPackagesUploadUnsignedRequest {
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            keypackages,
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };
        let signature = self.sign_keypackage_input(
            verification_method,
            &keypackages_upload_signing_input(&unsigned)?,
        )?;
        Ok(unsigned.into_signed(signature))
    }

    pub fn signed_key_packages_consume_request(
        &self,
        unsigned: KeyPackagesConsumeUnsignedRequest,
        verification_method: &str,
    ) -> Result<KeyPackagesConsumeRequestBody> {
        match &unsigned.consumer {
            KeyPackageConsumer::Device { consumer_device_id }
                if consumer_device_id == &self.device_id => {}
            KeyPackageConsumer::Device { .. } => {
                return Err(Error::Protocol(
                    "KeyPackage consume device differs from MLS identity".to_owned(),
                ));
            }
            KeyPackageConsumer::NativeAgent { .. } => {
                return Err(Error::Protocol(
                    "device MLS identity cannot sign a Native Agent KeyPackage consume request"
                        .to_owned(),
                ));
            }
        }
        unsigned
            .validate_shape()
            .map_err(|reason| Error::Protocol(reason.to_owned()))?;
        let signature = self.sign_keypackage_input(
            verification_method,
            &keypackages_consume_signing_input(&unsigned)?,
        )?;
        Ok(unsigned.into_signed(signature))
    }

    pub fn signed_key_packages_revoke_request(
        &self,
        unsigned: KeyPackagesRevokeUnsignedRequest,
        verification_method: &str,
    ) -> Result<KeyPackagesRevokeRequestBody> {
        if unsigned.device_id != self.device_id {
            return Err(Error::Protocol(
                "KeyPackage revoke device differs from MLS identity".to_owned(),
            ));
        }
        let signature = self.sign_keypackage_input(
            verification_method,
            &keypackages_revoke_signing_input(&unsigned)?,
        )?;
        Ok(unsigned.into_signed(signature))
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

    /// Build a reusable last-resort KeyPackage record. The KeyPackage carries
    /// the OpenMLS `last_resort` extension (`mark_as_last_resort`), so the
    /// holder keeps the init private key after processing a Welcome and can be
    /// (re-)admitted repeatedly against the same KeyPackage. Pairs with the
    /// server keeping last-resort KeyPackages claimable instead of consuming
    /// them — together they prevent a member from becoming permanently
    /// un-addable once its single-use KeyPackages are spent (e.g. a Welcome
    /// that was consumed server-side but never applied client-side).
    pub fn last_resort_key_package_record(&self) -> Result<MlsKeyPackageRecord> {
        self.key_package_record_inner(true)
    }

    fn key_package_record_inner(&self, last_resort: bool) -> Result<MlsKeyPackageRecord> {
        // A last-resort KeyPackage carries the OpenMLS `last_resort` extension,
        // so its leaf-node capabilities MUST also declare `LastResort` or the
        // KeyPackage is self-inconsistent and an `Add` of it is rejected with
        // `UnsupportedExtension` (RFC 9420 §7.2) — the exact failure that stalls
        // admin admission of a last-resort invitee.
        let capabilities = if last_resort {
            governance_binding_last_resort_openmls_capabilities()
        } else {
            governance_binding_openmls_capabilities()
        };
        let mut builder = KeyPackage::builder().leaf_node_capabilities(capabilities);
        if last_resort {
            builder = builder.mark_as_last_resort();
        }
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
            endpoint: MlsEndpointIdentity::human_device(
                self.principal_id.clone(),
                self.device_id.clone(),
            ),
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
            device_signature: None,
            last_resort,
        })
    }

    pub fn export_private_state(&self) -> Result<Vec<u8>> {
        let snapshot = OpenMlsIdentityStateSnapshot {
            context: ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT.to_owned(),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            signer_public_key: encode(self.signer.public()),
            storage_entries: snapshot_provider_storage(&self.provider)?,
        };
        serde_json::to_vec(&snapshot).map_err(Into::into)
    }

    pub fn restore_from_private_state(
        principal_id: DidCoreId,
        device_id: DeviceId,
        serialized_state: &[u8],
    ) -> Result<Self> {
        let snapshot: OpenMlsIdentityStateSnapshot = serde_json::from_slice(serialized_state)?;
        if snapshot.context != ARKRET_OPENMLS_IDENTITY_STATE_SNAPSHOT {
            return Err(Error::Protocol(
                "unsupported OpenMLS identity state snapshot".to_owned(),
            ));
        }
        if snapshot.principal_id != principal_id || snapshot.device_id != device_id {
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
        let credential = CredentialWithKey {
            credential: BasicCredential::new(leaf_credential_bytes(&principal_id, &device_id))
                .into(),
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

    pub fn create_group(self, group_id: impl AsRef<[u8]>) -> Result<ArkretMlsGroup> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ARKRET_MLS_CIPHERSUITE)
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

        Ok(ArkretMlsGroup {
            identity: self,
            group,
            history_secrets: BTreeMap::new(),
            content_nonce_counter: 0,
            signal_nonce_counter: 0,
        })
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

        Ok(ArkretMlsGroup {
            identity: self,
            group,
            history_secrets: BTreeMap::new(),
            content_nonce_counter: 0,
            signal_nonce_counter: 0,
        })
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
    })
}

pub fn revoke_key_package(record: &mut MlsKeyPackageRecord) -> Result<MlsDeviceWorkflowStep> {
    let MlsEndpointIdentity::HumanDevice {
        principal_id,
        device_id,
    } = &record.endpoint
    else {
        return Err(Error::Protocol(
            "device workflow cannot revoke a Native Agent KeyPackage".to_owned(),
        ));
    };
    record.state = arkret_models_crypto::MlsKeyPackageState::Revoked;
    Ok(MlsDeviceWorkflowStep {
        action: MlsDeviceWorkflowAction::RevokeKeyPackage,
        principal_id: principal_id.clone(),
        device_id: device_id.clone(),
        group_id: None,
        from_epoch: None,
        to_epoch: None,
    })
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
        let identity = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned()).unwrap(),
        )
        .unwrap();

        let record = identity.key_package_record().unwrap();
        assert_eq!(
            record.capabilities,
            vec!["mimi.content.v1".to_owned(), "ak.content.v1".to_owned()]
        );

        let value = serde_json::to_value(&record).unwrap();
        assert!(
            matches!(value.get("capabilities"), Some(Value::Array(values)) if !values.is_empty())
        );
    }

    #[test]
    fn native_agent_identity_reuses_authorized_runtime_signing_key() {
        let seed = [7_u8; 32];
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let identity = ArkretMlsIdentity::from_ed25519_signing_seed(
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000d".to_owned()).unwrap(),
            seed,
        )
        .unwrap();
        assert_eq!(identity.signature_public_key(), expected.as_slice());

        let record = identity.key_package_record().unwrap();
        let leaf =
            author_leaf_from_key_package_bytes(&decode(&record.keypackage).unwrap(), 0).unwrap();
        assert_eq!(leaf.signature_key, expected);
    }

    // Regression: a last-resort KeyPackage carries the OpenMLS `last_resort`
    // extension, so its leaf MUST declare the `LastResort` capability. Without
    // it, an admin's `Add` of the invitee fails with `UnsupportedExtension` and
    // admission stalls ("waiting for a Welcome"). Adding it to a real group is
    // the end-to-end check that the KeyPackage is self-consistent.
    #[test]
    fn last_resort_key_package_is_addable_to_a_group() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000a".to_owned()).unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"mls-group-last-resort-add-test")
            .unwrap();

        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000b".to_owned()).unwrap(),
        )
        .unwrap();
        let bob_last_resort = bob.last_resort_key_package_record().unwrap();
        assert!(bob_last_resort.last_resort);

        let result = group.add_member(&bob_last_resort);
        assert!(
            result.is_ok(),
            "adding a last-resort KeyPackage must not fail (UnsupportedExtension regression): {:?}",
            result.err()
        );

        // Sanity: the single-use KeyPackage path still adds cleanly.
        let carol = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecarol".to_owned()).unwrap(),
            DeviceId::new("ak:device:01964137-0000-7000-8000-00000000000c".to_owned()).unwrap(),
        )
        .unwrap();
        let carol_kp = carol.key_package_record().unwrap();
        assert!(
            group.add_member(&carol_kp).is_ok(),
            "single-use KeyPackage add regressed"
        );
    }
}
