//! Arkret federation wire frame contracts.
//!
//! The actor-verification challenge signature carried by
//! [`crate::federation::wire_dtos`]. The transaction envelope (which embeds the
//! core HTTP transaction body and RFC 9421 signature envelope), the in-memory
//! replay store, and the delta batch aggregate stay in the `arkret` umbrella.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyActorChallengeSignature {
    pub key_id: String,
    pub signature: String,
}
