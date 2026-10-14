//! Native service identity material for protocol tests. No database or process setup.

use anyhow::Result;
use arkret_identity::{
    DidResolver as _, DidWebvhDocumentOutcome, DidWebvhLogOutcome, DidWebvhResolver,
};
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidMethodUri, IdentityLogListOutcome,
};
use arkret_wire::{Did, DidCoreId, DidUrl, ProtocolSignature};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand_core::SeedableRng as _;

pub struct ServiceIdentityFixture {
    pub resolution: AuthenticatedServiceResolution,
    pub history: IdentityLogListOutcome,
    pub signing_key: SigningKey,
    pub service_id: DidCoreId,
    pub verification_method: DidUrl,
}

impl ServiceIdentityFixture {
    /// Keep the RNG seed explicit so existing pinned native identities stay exact.
    pub fn webvh(
        endpoint: &url::Url,
        rng_seed: u64,
        signing_seed: [u8; 32],
        fragment: &str,
        inception_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(rng_seed);
        let prepared = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
            &mut rng,
            &arkret_signatures::webvh::ServiceInceptionInput {
                principal_endpoint: endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: inception_at,
                did_key_fragment: Some(fragment),
            },
            &signing_seed,
        )?;
        let did = Did::new(prepared.did.clone())?;
        let service_id = arkret_wire::project_did_to_core_id(&did)?;
        let mut resolver = DidWebvhResolver::new();
        resolver.insert_from_https_response(
            &did,
            DidWebvhDocumentOutcome {
                url: DidWebvhResolver::document_url(&did)?,
                content_type: "application/json".into(),
                body: serde_json::to_vec(&prepared.log_entry["state"])?,
            },
        )?;
        resolver.ingest_log(
            &did,
            DidWebvhLogOutcome {
                url: DidWebvhResolver::log_url(&did)?,
                content_type: "application/jsonl".into(),
                body: serde_json::to_vec(&prepared.log_entry)?,
            },
        )?;
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id.clone(),
            "station".into(),
            resolver.resolve_did(&did)?.document,
            vec![prepared.log_entry.clone()],
            vec![],
            observed_at,
        )?;
        Ok(Self {
            resolution,
            history: IdentityLogListOutcome {
                did,
                method: DidMethodUri::Webvh,
                native_history: Some(true),
                entries: vec![prepared.log_entry.clone()],
                next_cursor: None,
                has_more: false,
            },
            signing_key: SigningKey::from_bytes(&signing_seed),
            service_id,
            verification_method: DidUrl::new(prepared.did_key_id.clone())
                .map_err(anyhow::Error::msg)?,
        })
    }

    pub fn sign(&self, bytes: &[u8], at: DateTime<Utc>) -> arkret_wire::Result<ProtocolSignature> {
        Ok(ProtocolSignature {
            verification_method: self.verification_method.clone(),
            created_at: at,
            jws: arkret_signatures::sign_ed25519_detached_jws(&self.signing_key, bytes)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?,
        })
    }
}
