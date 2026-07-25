//! Directory HTTP request/outcome DTO counterparts
//! (`service-operation-dtos.schema.json`): the two-round RFC 9497 VOPRF
//! private contact discovery wire shapes.

use arkret_wire::BatchId;
use serde::{Deserialize, Serialize};

use crate::service_description::ServiceDescribe;

/// Transparent wrapper over `ServiceDescribe` for
/// `ak.gate.service.query.describe` (Principal Server) Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerDescribeOutcome(pub ServiceDescribe);

/// Transparent wrapper over `ServiceDescribe` for
/// `ak.find.directory.query.describe` (directory service) Salvo OpenAPI bindings.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirectoryDescribeOutcome(pub ServiceDescribe);

/// Two-round RFC 9497 VOPRF request for
/// `ak.find.directory.query.private_contact_discovery`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryPrivateContactDiscoveryRequestBody {
    Blind {
        profile: String,
        batch_id: BatchId,
        ciphersuite: String,
        key_epoch: u64,
        blinded_elements: Vec<String>,
    },
    Match {
        profile: String,
        batch_id: BatchId,
        key_epoch: u64,
        derived_prefixes: Vec<String>,
    },
}

impl DirectoryPrivateContactDiscoveryRequestBody {
    pub fn profile(&self) -> &str {
        match self {
            Self::Blind { profile, .. } | Self::Match { profile, .. } => profile,
        }
    }

    pub fn batch_id(&self) -> &BatchId {
        match self {
            Self::Blind { batch_id, .. } | Self::Match { batch_id, .. } => batch_id,
        }
    }

    pub fn key_epoch(&self) -> u64 {
        match self {
            Self::Blind { key_epoch, .. } | Self::Match { key_epoch, .. } => *key_epoch,
        }
    }
}

/// Fixed-shape response for the corresponding private-discovery round.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryPrivateContactDiscoveryOutcome {
    Blind {
        profile: String,
        batch_id: BatchId,
        ciphersuite: String,
        key_epoch: u64,
        evaluated_elements: Vec<String>,
        proofs: Vec<String>,
        digest_prefix_length: u16,
        padding_count: u32,
        server_public_key: String,
    },
    Match {
        profile: String,
        batch_id: BatchId,
        key_epoch: u64,
        hit_bitmap: Vec<bool>,
        padding_count: u32,
    },
}

#[cfg(test)]
mod private_contact_discovery_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn private_contact_blind_request_matches_normative_shape() {
        let request: DirectoryPrivateContactDiscoveryRequestBody = serde_json::from_value(json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "ciphersuite": "OPRF-ristretto255-SHA512",
            "key_epoch": 14,
            "blinded_elements": ["dGVzdA"]
        }))
        .expect("normative blind request");

        assert!(matches!(
            request,
            DirectoryPrivateContactDiscoveryRequestBody::Blind { key_epoch: 14, .. }
        ));
    }

    #[test]
    fn private_contact_request_rejects_legacy_requester_shape() {
        let error = serde_json::from_value::<DirectoryPrivateContactDiscoveryRequestBody>(json!({
            "profile": "ak.private_contact_discovery.v1",
            "phase": "blind",
            "batch_id": "ak:batch:01964137-0000-7000-8000-000000000777",
            "ciphersuite": "OPRF-ristretto255-SHA512",
            "key_epoch": 14,
            "blinded_elements": ["dGVzdA"],
            "requester": "did:web:alice.example"
        }))
        .expect_err("legacy requester must not remain on the PSI wire");

        assert!(error.to_string().contains("unknown field"));
    }
}
