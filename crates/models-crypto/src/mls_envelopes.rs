//! MLS transport envelope wire shapes.
//!
//! Proposal / commit / welcome envelopes carried by MLS repo operations
//! and device-message delivery, plus the `cx_app_state_ref` GroupContext
//! extension codec. The event-draft binding (building a repo `Operation`
//! from one of these envelopes) lives in `arkret-event-draft` as an
//! extension trait — this crate holds the data shapes and the deterministic
//! CBOR codec only.

use arkret_wire::{DeviceId, Did, Hash};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsProposalEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub proposal_type: String,
    pub proposal: String,
    pub proposal_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

/// `cx_app_state_ref` MLS GroupContext extension
/// (encryption-and-audit.md / B-12).
///
/// Binds a Arkret Space's reduced state into the MLS GroupContext so
/// that any commit's signature transcript covers the application-layer
/// frontier. Carried as a private-use GroupContext extension at
/// codepoint [`MlsAppStateRef::CODEPOINT`] (within the IANA private
/// range `0xF000..=0xFFFF`).
///
/// CBOR encoding (canonical) — keys in registration order, no
/// indefinite-length items:
///
/// 1. `membership_frontier: bstr` — frontier state-hash
/// 2. `policy_root:        bstr` — Merkle root of policy events
/// 3. `capability_root:    bstr` — Merkle root of capability events
/// 4. `discussion_metadata_digest: bstr` — hash of discussion-track metadata
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsAppStateRef {
    /// Hex-encoded SHA-256 of the canonical state root.
    pub membership_frontier: String,
    pub policy_root: String,
    pub capability_root: String,
    pub discussion_metadata_digest: String,
}

impl MlsAppStateRef {
    /// IANA private-use codepoint chosen for `cx_app_state_ref`. The
    /// Arkret spec reserves it within the `[0xF000, 0xFFFF]` MLS
    /// extension private-use range; deployments MAY override via
    /// future negotiation but MUST stay inside the private range.
    pub const CODEPOINT: u16 = 0xCAFE;

    /// Encode as a deterministic CBOR map (per B-12 normative form).
    /// The output binds 1:1 to `Self::decode_cbor`.
    pub fn encode_cbor(&self) -> Vec<u8> {
        // Build a small canonical CBOR map by hand to avoid a runtime
        // dep just for one extension. Uses RFC 8949 deterministic
        // encoding for a 4-entry map of (uint key -> bstr value).
        fn put_uint(out: &mut Vec<u8>, n: u64) {
            if n < 24 {
                out.push(n as u8);
            } else if n <= u64::from(u8::MAX) {
                out.push(0x18);
                out.push(n as u8);
            } else if n <= u64::from(u16::MAX) {
                out.push(0x19);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else if n <= u64::from(u32::MAX) {
                out.push(0x1a);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            } else {
                out.push(0x1b);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        fn put_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
            // Major type 2 (byte string) — same length encoding as uints.
            let len = bytes.len() as u64;
            if len < 24 {
                out.push(0x40 | (len as u8));
            } else if len <= u64::from(u8::MAX) {
                out.push(0x58);
                out.push(len as u8);
            } else if len <= u64::from(u16::MAX) {
                out.push(0x59);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else if len <= u64::from(u32::MAX) {
                out.push(0x5a);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            } else {
                out.push(0x5b);
                out.extend_from_slice(&len.to_be_bytes());
            }
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(160);
        // Major type 5 (map) with 4 entries.
        out.push(0xa4);
        let entries: [(u64, &[u8]); 4] = [
            (1, self.membership_frontier.as_bytes()),
            (2, self.policy_root.as_bytes()),
            (3, self.capability_root.as_bytes()),
            (4, self.discussion_metadata_digest.as_bytes()),
        ];
        for (k, v) in entries {
            put_uint(&mut out, k);
            put_bstr(&mut out, v);
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsCommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub commit_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// `cx_app_state_ref` GroupContext extension binding the
    /// application-layer Space frontier into the MLS transcript.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_state_ref: Option<MlsAppStateRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub welcome: String,
    pub welcome_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}
