use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{Did, Error, Hash, Result, SchemaId, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::proof::DetachedPayloadProof;

/// Normalized DID key-log operation kind
/// (`did-key-log-entry.schema.json` `operation` enum). The DID
/// method-specific raw operation object travels in
/// [`DidKeyLogEntry::operation_body`]; this discriminator is what the
/// reducer / verifier dispatches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidKeyLogOperation {
    Inception,
    Rotate,
    Recover,
    Deactivate,
    ServiceUpdate,
}

/// Constant-time digest string comparison (service-surface.md §3.1.3 requires
/// constant-time comparison of recomputed digests). Delegates to the single
/// Constant-time comparison is required by service-surface.md §3.1.3.
fn constant_time_digest_eq(a: &Hash, b: &Hash) -> bool {
    bool::from(a.as_str().as_bytes().ct_eq(b.as_str().as_bytes()))
}

fn placeholder_digest() -> Hash {
    Hash::new(format!("sha256:{}", "0".repeat(64))).expect("static digest literal is valid")
}

/// Append-only DID key-log entry. Mirrors
/// `did-key-log-entry.schema.json` (closed schema): `seq=0` is the
/// inception entry and MUST NOT carry `prev_event_digest`; every
/// `seq>0` entry MUST carry `prev_event_digest` equal to the previous
/// accepted entry's `head_event_digest`. Digest / proof byte semantics
/// are normative in `zh/sync/service-surface.md` §3.1.3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidKeyLogEntry {
    /// DID controlled by this entry.
    pub did: Did,
    /// Monotonic DID method log sequence (zero-based).
    pub seq: u64,
    /// Normalized operation kind.
    pub operation: DidKeyLogOperation,
    /// Digest of the previous accepted entry. Required for `seq>0`,
    /// forbidden for `seq=0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_digest: Option<Hash>,
    /// Self digest of this entry: canonical digest of the entry with
    /// `proofs` and `head_event_digest` removed (§3.1.3).
    pub head_event_digest: Hash,
    /// DID method-specific raw operation object (`minProperties: 1`).
    pub operation_body: serde_json::Map<String, Value>,
    /// Entry creation time (canonical UTC `Z` form on wire).
    #[serde(with = "canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Controller proofs over this entry
    /// (`event-envelope.schema.json#/$defs/proof`).
    /// `payload_digest = canonical_digest(entry_without_proofs)`; the
    /// detached JWS signs the canonical binding object of §3.1.3. The
    /// `verification_method` MUST be a controller key authorized for
    /// this operation at the previous accepted entry's state — the
    /// registry host MUST NOT substitute its own key.
    pub proofs: Vec<DetachedPayloadProof>,
}

impl DidKeyLogEntry {
    pub const SCHEMA: &'static str = SchemaId::DID_KEY_LOG_ENTRY_V1;
    /// Build an unsigned entry and seal its `head_event_digest`
    /// (§3.1.3: canonical digest of the entry without `proofs` /
    /// `head_event_digest`). Attach controller proofs afterwards via
    /// `DidKeyLogEntry::attach_controller_proof`.
    pub fn build(
        did: Did,
        seq: u64,
        operation: DidKeyLogOperation,
        prev_event_digest: Option<Hash>,
        operation_body: serde_json::Map<String, Value>,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut entry = Self {
            did,
            seq,
            operation,
            prev_event_digest,
            head_event_digest: placeholder_digest(),
            operation_body,
            created_at,
            proofs: Vec::new(),
        };
        entry.head_event_digest = entry.compute_head_event_digest()?;
        Ok(entry)
    }

    /// JSON view used for digest derivation. `include_head=false` is the
    /// `head_event_digest` transcript (drop `proofs` + `head_event_digest`);
    /// `include_head=true` is the proof `payload_digest` transcript (drop
    /// only `proofs`).
    fn digest_view(&self, include_head: bool) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("DidKeyLogEntry serializes to an object");
        object.remove("proofs");
        if !include_head {
            object.remove("head_event_digest");
        }
        Ok(value)
    }

    /// Recompute `head_event_digest` per §3.1.3.
    pub fn compute_head_event_digest(&self) -> Result<Hash> {
        let bytes = canonical::canonical_json_bytes(&self.digest_view(false)?)?;
        Ok(Hash::new(canonical::sha256_digest(&bytes))?)
    }

    /// Recompute the proof `payload_digest`
    /// (`canonical_digest(entry_without_proofs)`, §3.1.3).
    pub fn proof_payload_digest(&self) -> Result<Hash> {
        let bytes = canonical::canonical_json_bytes(&self.digest_view(true)?)?;
        Ok(Hash::new(canonical::sha256_digest(&bytes))?)
    }

    /// Canonical proof binding object bytes per §3.1.3:
    /// `{payload_digest, did, verification_method, created_at, domain?,
    /// audience?}` in canonical JSON (JCS key order). This is the exact
    /// detached-JWS payload — field-concatenation strings or bare hex
    /// MUST NOT replace this transcript.
    pub fn proof_binding_bytes(&self, proof: &DetachedPayloadProof) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "payload_digest".to_owned(),
            Value::String(proof.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(proof.verification_method.as_str().to_owned()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(proof.created_at)),
        );
        if let Some(domain) = &proof.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
    }

    /// Structural validation against `did-key-log-entry.schema.json` +
    /// the §3.1.3 self-digest rule.
    pub fn validate(&self) -> Result<()> {
        if self.seq == 0 && self.prev_event_digest.is_some() {
            return Err(Error::Protocol(
                "DID key log inception (seq=0) must not carry prev_event_digest".to_owned(),
            ));
        }
        if self.seq > 0 && self.prev_event_digest.is_none() {
            return Err(Error::Protocol(
                "DID key log entry with seq>0 must carry prev_event_digest".to_owned(),
            ));
        }
        if self.operation_body.is_empty() {
            return Err(Error::Protocol(
                "DID key log operation_body must carry at least one property".to_owned(),
            ));
        }
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "DID key log entry must carry at least one controller proof".to_owned(),
            ));
        }
        let recomputed = self.compute_head_event_digest()?;
        if !constant_time_digest_eq(&recomputed, &self.head_event_digest) {
            return Err(Error::Protocol(
                "DID key log head_event_digest does not match the canonical entry bytes".to_owned(),
            ));
        }
        Ok(())
    }
}
