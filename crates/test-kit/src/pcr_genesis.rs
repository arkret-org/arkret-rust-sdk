//! Real native registration and producer signatures for holder-PCR readers.
//! The originals do not claim a live Station admission, session or database.

use anyhow::Result;
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_identity::{
    CurrentPrincipalResponseBody, DidMethodUri, IdentityDocumentView, IdentityLogListResponseBody,
    PrincipalRegistrationAnchor, PrincipalResolutionProjection, ResolutionCommitment,
};
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions};
use arkret_wire::{
    AccountId, ActorId, DeviceId, Did, DidCoreId, DidUrl, Discoverability, GenesisSalt,
    HistoryAccess, JoinRule, NonEmptyString, PcrGenesisUnit, RequestId, ScopeRef, TrustDomainId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

pub struct HumanPcrFixtureInput<'a> {
    pub station_id: &'a DidCoreId,
    pub endpoint: &'a url::Url,
    pub root_seed: [u8; 32],
    pub next_root_seed: [u8; 32],
    pub device_seed: [u8; 32],
    pub device_hpke_private_key: [u8; 32],
    pub device_id: DeviceId,
    pub genesis_salt: GenesisSalt,
    pub created_at: DateTime<Utc>,
}

pub struct HumanPcrOriginalsFixture {
    pub account: AccountId,
    pub unit: PcrGenesisUnit,
    pub anchor: PrincipalRegistrationAnchor,
    pub resolution: ResolutionCommitment,
    pub document: IdentityDocumentView,
    pub log: IdentityLogListResponseBody,
    pub device_id: DeviceId,
    pub device_signing_key: SigningKey,
    pub device_verification_method: DidUrl,
}

impl HumanPcrOriginalsFixture {
    pub fn webvh(input: HumanPcrFixtureInput<'_>) -> Result<Self> {
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&input.next_root_seed)
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret_signatures::webvh::prepare_principal_inception(
            &arkret_signatures::webvh::PrincipalInceptionInput {
                provider_endpoint: input.endpoint,
                principal_endpoint: input.endpoint,
                local_id: "holder-pcr",
                also_known_as: &[],
                version_created_at: input.created_at,
                root_seed: &input.root_seed,
                next_root_public_key_multibase: &next,
                witness_policy: None,
            },
        )?;
        let did = Did::new(inception.did.clone())?;
        let normalized = serde_json::from_value(inception.log_entry["state"].clone())?;
        let anchor = PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(inception.submit_body),
            log_entries: vec![serde_json::from_value(inception.log_entry.clone())?],
            witness_records: vec![],
            normalized_did_document: normalized,
        };
        let validated = arkret_identity::validate_principal_registration_anchor(&anchor)?;
        let account = AccountId::new(validated.principal_id.clone(), input.station_id.clone());
        let resolution = ResolutionCommitment {
            did: did.clone(),
            method_history_head: validated.method_history_head.to_string(),
            version_id: validated.did_version_id,
        };
        let device_key = SigningKey::from_bytes(&input.device_seed);
        let public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            device_key.verifying_key().as_bytes(),
        );
        let method =
            DidUrl::new(format!("{did}#{}", input.device_id)).map_err(anyhow::Error::msg)?;
        let hpke = arkret_crypto::hpke::x25519_public_key(&input.device_hpke_private_key)?;
        let mut payload = DeviceAuthorizePayload {
            device_id: input.device_id.clone(),
            device_public_key_did: non_empty(format!("did:key:{public}"))?,
            hpke_key: non_empty(arkret_crypto::identity_root::x25519_public_multikey(&hpke))?,
            algorithms: ["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"]
                .into_iter()
                .map(non_empty)
                .collect::<Result<Vec<_>>>()?,
            device_key_algorithm: non_empty("Ed25519")?,
            authorized_by: DeviceOrPrincipalRef::Principal(account.principal_id.clone()),
            scopes: None,
            not_before: input.created_at,
            expires_at: None,
            authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
            authorized_generation_ref: 1,
            device_signature: SignatureMaterial::NonEmptyString(non_empty("pending")?),
            recovery_session_id: None,
            pairing_challenge_transcript_digest: None,
            applet_id: None,
            expected_control_revision: None,
            expected_device_revision: None,
        };
        payload.device_signature =
            SignatureMaterial::NonEmptyString(non_empty(arkret_canonical::base64url_encode(
                device_key
                    .sign(&payload.device_possession_signature_input(&account)?)
                    .to_bytes(),
            ))?);
        let descriptor = FoundingDeviceDescriptor {
            descriptor_version: 1,
            device_id: payload.device_id.clone(),
            device_public_key_did: payload.device_public_key_did.clone(),
            device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
            device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
            hpke_key: payload.hpke_key.clone(),
            hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
            algorithms: payload.algorithms.clone(),
            founding_authorize_payload_digest: device_authorize_payload_digest(
                &serde_json::to_value(&payload)?,
                arkret_canonical::DigestSuite::Sha256,
            )?,
        };
        let mut create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: account.principal_id.clone(),
                governance_station_id: account.station_id.clone(),
                principal_did: did.clone(),
                genesis_salt: input.genesis_salt,
                trust_domain: TrustDomainId::new("ak:trust_domain:holder.example")?,
                initial_resolution: resolution.clone(),
                founding_device_descriptor: descriptor,
                initial_join_rule: JoinRule::Closed,
                initial_history_access: HistoryAccess::SinceJoin,
                initial_discoverability: Discoverability::Secret,
                created_at: input.created_at,
            },
        )?;
        let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&input.root_seed)
                .verifying_key()
                .as_bytes(),
        );
        let root_method =
            DidUrl::new(format!("did:key:{root}#{root}")).map_err(anyhow::Error::msg)?;
        let root_signer = Ed25519PayloadSigner::from_did_key_seed(
            input.root_seed,
            Did::new(format!("did:key:{root}"))?,
            root_method,
        );
        arkret_signatures::sign_event(
            &mut create,
            &root_signer,
            SignEventOptions::new().with_created_at(input.created_at),
        )?;
        let signer = Ed25519PayloadSigner::new(device_key.clone(), did.clone(), method.clone());
        let mut authorize =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceAuthorize>::new(
                ScopeRef::Realm {
                    realm_id: create.realm_id.clone(),
                },
                ActorId::account(account.clone()),
                payload,
            )?
            .author_with_digest_suite(input.created_at, arkret_canonical::DigestSuite::Sha256)?;
        arkret_signatures::sign_event(
            &mut authorize,
            &signer,
            SignEventOptions::new().with_created_at(input.created_at),
        )?;
        let unit =
            arkret_bootstrap::build_pcr_genesis_unit(create.into_event(), authorize.into_event())?;
        arkret_identity::verify_pcr_genesis_events(
            &unit,
            &anchor,
            &ActorId::account(account.clone()),
        )?;
        let document = IdentityDocumentView {
            did_document: serde_json::from_value(inception.log_entry["state"].clone())?,
            normalized_view: None,
            method_evidence: None,
            cached_at: None,
        };
        let log = IdentityLogListResponseBody {
            did,
            method: DidMethodUri::Webvh,
            native_history: Some(true),
            entries: vec![inception.log_entry],
            next_cursor: None,
            has_more: false,
        };
        Ok(Self {
            account,
            unit,
            anchor,
            resolution,
            document,
            log,
            device_id: input.device_id,
            device_signing_key: device_key,
            device_verification_method: method,
        })
    }

    pub fn current_principal(&self, request_id: RequestId) -> CurrentPrincipalResponseBody {
        CurrentPrincipalResponseBody {
            request_id,
            account_id: self.account.clone(),
            principal_control_realm_id: self.unit.create().realm_id.clone(),
            resolution_projection: PrincipalResolutionProjection {
                did: self.resolution.did.clone(),
                method_history_head: self.resolution.method_history_head.clone(),
                version_id: self.resolution.version_id.clone(),
                resolution_event_ref: self.unit.create().event_id.to_string(),
                updated_at: self.unit.create().created_at,
            },
        }
    }
}
