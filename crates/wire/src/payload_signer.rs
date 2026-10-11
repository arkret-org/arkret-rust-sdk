//! Generic detached-signature boundary for non-Event payloads.
//!
//! Protocol objects that need a detached signature own their
//! transcript; signers only expose key identity and signature bytes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, DidUrl, Hash, Result};

/// Detached signature over the canonical bytes of a non-Event object.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

/// Crypto-provider boundary used by non-Event detached-signature helpers.
pub trait PayloadSigner {
    fn signer_did(&self) -> &Did;

    fn verification_method_id(&self) -> &DidUrl;

    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature>;
}
