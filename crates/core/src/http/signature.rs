use serde::{Deserialize, Serialize};

/// RFC 9421 HTTP message signature wire envelope.
///
/// `Signature-Input` parameters plus the detached `Signature` value. The
/// canonical signature base (the bytes actually signed) is built by the RFC
/// 9421 implementation in `arkret-signatures`; this struct is just the
/// resulting wire envelope, re-exported by `arkret-signatures` and embedded in
/// [`crate::federation::FederationTransactionEnvelope`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMessageSignature {
    pub key_id: String,
    pub alg: String,
    pub signed_fields: Vec<String>,
    pub signature: String,
}
