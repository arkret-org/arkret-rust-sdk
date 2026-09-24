//! Closed ordinary account-device signer evidence used by keys/query and
//! historical ordinary Event producer verification.
//!
//! This is a sibling of the six-member `AuthenticatedSignerResolutionEvidence`,
//! never a fourth branch of that type. The origin retains this complete root;
//! client keys/query rows carry only its content address.

use arkret_canonical::canonical::{canonical_json_bytes, sha256_hex};
use arkret_models_crypto::DeviceProjectionAttestation;
use arkret_wire::{AccountId, DeviceId, SignerEvidenceRef, WireError};
use serde::{Deserialize, Serialize};

use crate::AuthenticatedServiceResolution;

/// `account-device-signer-evidence.schema.json` exact two-member root.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDeviceSignerEvidence {
    pub device_projection_attestation: DeviceProjectionAttestation,
    pub service_resolution: AuthenticatedServiceResolution,
}

impl AccountDeviceSignerEvidence {
    /// Check only byte-local bindings. The caller separately verifies the
    /// method-native Service history, assertion relationship and signature.
    pub fn validate_binding(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> arkret_wire::Result<()> {
        let attested = &self.device_projection_attestation.attestation;
        if &attested.account_id != account_id || &attested.device_id != device_id {
            return Err(WireError::Protocol(
                "account-device signer evidence addresses another account or device".into(),
            ));
        }
        if self.service_resolution.service_id != account_id.station_id {
            return Err(WireError::Protocol(
                "account-device signer evidence has another origin Station".into(),
            ));
        }
        let method_did = self
            .device_projection_attestation
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .and_then(|(did, fragment)| (!fragment.is_empty()).then_some(did))
            .ok_or_else(|| WireError::Protocol("attestation proof method has no fragment".into()))
            .and_then(|did| Ok(arkret_wire::Did::new(did.to_owned())?))?;
        if method_did != self.service_resolution.normalized_did_document.id
            || arkret_wire::project_did_to_core_id(&method_did)? != account_id.station_id
        {
            return Err(WireError::Protocol(
                "account-device signer evidence proof method has another controller".into(),
            ));
        }
        if self.device_projection_attestation.proof.created_at != attested.attested_at
            || attested.attested_at >= attested.expires_at
            || attested.attested_at < attested.authorization_window.not_before
            || attested
                .authorization_window
                .expires_at
                .is_some_and(|expiry| {
                    attested.attested_at >= expiry || attested.expires_at > expiry
                })
        {
            return Err(WireError::Protocol(
                "account-device signer evidence has an invalid attestation window".into(),
            ));
        }
        Ok(())
    }

    /// Content address of the complete immutable root, including Service
    /// method-native evidence. The pruned keys/query projection is never a
    /// valid preimage.
    pub fn signer_evidence_ref(&self) -> arkret_wire::Result<SignerEvidenceRef> {
        let bytes = canonical_json_bytes(self)?;
        SignerEvidenceRef::new(format!("ak:signer_evidence:sha256:{}", sha256_hex(bytes)))
    }

    pub fn matches_ref(&self, reported: &SignerEvidenceRef) -> arkret_wire::Result<bool> {
        Ok(&self.signer_evidence_ref()? == reported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DidDocument, ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
        ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
        normalized_did_document_digest,
    };
    use arkret_models_crypto::{
        DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
    };
    use arkret_wire::{Did, DidCoreId, DidKey, DidUrl, EventId, NonEmptyString, ProtocolSignature};
    use chrono::{TimeZone as _, Utc};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    fn evidence() -> AccountDeviceSignerEvidence {
        let did = Did::new("did:web:station.example").unwrap();
        let document: DidDocument = serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [],
            "service": [{
                "id": "did:web:station.example#service",
                "type": "ArkretService",
                "serviceKind": "station",
                "serviceEndpoint": "https://station.example/"
            }]
        }))
        .unwrap();
        let digest = normalized_did_document_digest(&document).unwrap();
        let version = format!(
            "synthetic-jcs-sha256:{}",
            digest.as_str().trim_start_matches("sha256:")
        );
        let at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
        AccountDeviceSignerEvidence {
            device_projection_attestation: DeviceProjectionAttestation {
                attestation: DeviceProjectionAttestationCore {
                    account_id: AccountId::new(
                        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                        arkret_wire::project_did_to_core_id(&did).unwrap(),
                    ),
                    device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                        .unwrap(),
                    device_signing_key_did: DidKey::new(
                        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
                    )
                    .unwrap(),
                    hpke_key: NonEmptyString::new("hpke-1").unwrap(),
                    device_authorize_event_id: EventId::new(
                        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                    )
                    .unwrap(),
                    authorized_generation_ref: 1,
                    device_status: DeviceStatus::Active,
                    authorization_window: DeviceAuthorizationWindow {
                        not_before: at,
                        expires_at: None,
                    },
                    attested_at: at,
                    expires_at: at + chrono::Duration::minutes(5),
                },
                proof: ProtocolSignature {
                    verification_method: DidUrl::new("did:web:station.example#signing-1").unwrap(),
                    created_at: at,
                    jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
                },
            },
            service_resolution: AuthenticatedServiceResolution {
                service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
                service_kind: "station".to_owned(),
                method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
                    boundary: ResolutionMethodEvidenceBoundary {
                        from_method_history_head: digest.to_string(),
                        to_method_history_head: digest.to_string(),
                        from_version_id: version.clone(),
                        to_version_id: version,
                    },
                    evidence: ResolutionDidBindingEvidenceReceipt {
                        kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                        method: "web".to_owned(),
                        document_digest: digest,
                        method_proofs: vec![],
                    },
                },
                normalized_did_document: document,
            },
        }
    }

    #[test]
    fn complete_root_is_content_addressed_and_byte_local_bindings_fail_closed() {
        let root = evidence();
        let core = &root.device_projection_attestation.attestation;
        root.validate_binding(&core.account_id, &core.device_id)
            .unwrap();
        let reference = root.signer_evidence_ref().unwrap();
        let bytes = canonical_json_bytes(&root).unwrap();
        let digest = Sha256::digest(bytes);
        let lowercase_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let expected = format!("ak:signer_evidence:sha256:{lowercase_hex}");
        assert_eq!(serde_json::to_value(&reference).unwrap(), json!(expected));
        assert!(root.matches_ref(&reference).unwrap());

        let mut changed = root.clone();
        changed.service_resolution.service_kind = "media".into();
        assert!(!changed.matches_ref(&reference).unwrap());
        changed = root.clone();
        changed
            .device_projection_attestation
            .attestation
            .authorized_generation_ref = 2;
        assert!(!changed.matches_ref(&reference).unwrap());
        changed = root.clone();
        changed.service_resolution.service_id =
            DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            changed
                .validate_binding(&core.account_id, &core.device_id)
                .is_err()
        );
        changed = root.clone();
        changed.device_projection_attestation.proof.created_at -= chrono::Duration::seconds(1);
        assert!(
            changed
                .validate_binding(&core.account_id, &core.device_id)
                .is_err()
        );
        assert!(
            root.validate_binding(
                &core.account_id,
                &DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_wire_is_closed_and_does_not_extend_asre() {
        let root = evidence();
        let mut value = serde_json::to_value(root).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            ["device_projection_attestation", "service_resolution"]
        );
        value["authority_commit_id"] = json!("extra");
        assert!(serde_json::from_value::<AccountDeviceSignerEvidence>(value).is_err());
    }
}
