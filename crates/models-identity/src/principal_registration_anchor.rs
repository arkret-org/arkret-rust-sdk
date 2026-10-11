//! Closed, adapter-discriminated registration anchor for a v1 human principal.
//!
//! This is the single primary method-native material that human registration
//! and PCR genesis both consume. v1 supports exactly one active
//! `human_principal_anchor` adapter: `did:webvh:1.0`, selected by the
//! registered `registration_anchor_kind`.
//! Every other DID method is rejected before method-specific parsing.
//!
//! The shape checks here are the closed-form ones a wire model can own. The
//! authoritative derivation - SCID, entry-hash chain, controller proofs,
//! rotation authorization, witness thresholds, normalized document equality and
//! the exported root key - lives in `arkret-identity`, which owns method history
//! verification.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_wire::{Did, DidCoreId, DidUrl, Hash, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DidDocument, DidOperationSubmitRequestBody};

/// Registered `registration_anchor_kind` of the `did:webvh` adapter.
pub const WEBVH_REGISTRATION_ANCHOR_KIND: &str = "webvh_registration";
/// Closed registration anchor union. Unknown discriminators fail closed at
/// deserialization, which is where an ineligible human anchor method - every
/// non-`did:webvh` shape included - is rejected before any method parser runs.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "anchor_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrincipalRegistrationAnchor {
    /// `did:webvh` anchor: the accepted registration operation wrapper, the
    /// gap-free native log from inception through that entry, every applicable
    /// witness record and the exact normalized document of the terminal state.
    WebvhRegistration {
        registration_did_operation: Box<DidOperationSubmitRequestBody>,
        log_entries: Vec<BTreeMap<String, Value>>,
        witness_records: Vec<BTreeMap<String, Value>>,
        #[serde(with = "crate::did_document::normalized_document_wire")]
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
        normalized_did_document: DidDocument,
    },
}

impl PrincipalRegistrationAnchor {
    /// The registered `registration_anchor_kind` this anchor selects.
    pub const fn anchor_kind(&self) -> &'static str {
        match self {
            Self::WebvhRegistration { .. } => WEBVH_REGISTRATION_ANCHOR_KIND,
        }
    }

    /// The anchored DID. The `did:webvh` branch keeps its only copy inside the
    /// accepted operation wrapper, so there is no second DID to disagree with.
    pub fn did(&self) -> &Did {
        match self {
            Self::WebvhRegistration {
                registration_did_operation,
                ..
            } => &registration_did_operation.did,
        }
    }

    /// Canonical digest of the complete typed anchor. This is the value the
    /// registration control proof and the account binding receipt commit to.
    pub fn canonical_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }

    /// `method_history_head` as a pure function of the anchor bytes, under the
    /// registered adapter rule for this branch.
    ///
    /// This is the single implementation of that rule: the authoritative
    /// derivation in `arkret-identity` calls it after the branch material has
    /// been verified. On its own it is a shape-level restatement and proves
    /// nothing about the anchor's authenticity.
    pub fn declared_method_history_head(&self) -> Result<Hash> {
        match self {
            Self::WebvhRegistration { log_entries, .. } => {
                let terminal = log_entries.last().ok_or_else(|| {
                    WireError::Protocol(
                        "webvh registration anchor requires at least the inception entry"
                            .to_owned(),
                    )
                })?;
                Ok(Hash::new(canonical::canonical_sha256(terminal)?)?)
            }
        }
    }

    /// The exact terminal native entry the anchor pins, for `did:webvh` only.
    pub fn webvh_terminal_entry(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::WebvhRegistration { log_entries, .. } => log_entries.last(),
        }
    }

    /// Closed-form shape validation. It never substitutes for the authoritative
    /// method-history derivation in `arkret-identity`.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::WebvhRegistration {
                registration_did_operation,
                log_entries,
                witness_records,
                normalized_did_document,
            } => {
                registration_did_operation.validate()?;
                if registration_did_operation.did_method != crate::DidMethodName::Webvh {
                    return Err(WireError::Protocol(
                        "webvh registration anchor requires a did:webvh operation".to_owned(),
                    ));
                }
                if registration_did_operation.prev_event_digest.is_some() {
                    return Err(WireError::Protocol(
                        "registration anchor carries its predecessor as log_entries, not a digest"
                            .to_owned(),
                    ));
                }
                let terminal = log_entries.last().ok_or_else(|| {
                    WireError::Protocol(
                        "webvh registration anchor requires at least the inception entry"
                            .to_owned(),
                    )
                })?;
                for (index, entry) in log_entries.iter().enumerate() {
                    let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
                    if webvh_version_number(entry) != Some(expected) {
                        return Err(WireError::Protocol(
                            "webvh registration anchor log is not the gap-free inception prefix"
                                .to_owned(),
                        ));
                    }
                }
                let terminal_version = webvh_version_number(terminal);
                if registration_did_operation.seq.is_some()
                    && registration_did_operation.seq != terminal_version
                {
                    return Err(WireError::Protocol(
                        "registration anchor seq is not the terminal entry version".to_owned(),
                    ));
                }
                if canonical::canonical_sha256(&registration_did_operation.operation)?
                    != canonical::canonical_sha256(terminal)?
                {
                    return Err(WireError::Protocol(
                        "accepted registration operation is not the terminal log entry".to_owned(),
                    ));
                }
                let versions = log_entries
                    .iter()
                    .filter_map(|entry| entry.get("versionId").and_then(Value::as_str))
                    .collect::<std::collections::BTreeSet<_>>();
                let mut seen = std::collections::BTreeSet::new();
                for record in witness_records {
                    // A fetched did-witness.json may legitimately carry records
                    // for versions past the head. This anchor's log ends at the
                    // registration entry, so anything else is surplus.
                    let version = record
                        .get("versionId")
                        .and_then(Value::as_str)
                        .filter(|version| versions.contains(version))
                        .ok_or_else(|| {
                            WireError::Protocol(
                                "witness record names a version outside the anchored log"
                                    .to_owned(),
                            )
                        })?;
                    if record.len() != 2 || !record.contains_key("proof") {
                        return Err(WireError::Protocol(
                            "witness record is closed and requires only versionId and proof"
                                .to_owned(),
                        ));
                    }
                    if !seen.insert(version) {
                        return Err(WireError::Protocol(
                            "witness records repeat one versionId".to_owned(),
                        ));
                    }
                }
                if normalized_did_document.id != registration_did_operation.did {
                    return Err(WireError::Protocol(
                        "registration anchor document is not the anchored DID".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Everything a registration anchor authenticates. Only this struct - never the
/// anchor's own members - is compared against PCR genesis coordinates or a
/// registration control proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRegistrationAnchor {
    /// Registered `registration_anchor_kind` the branch selected.
    pub anchor_kind: &'static str,
    /// The anchored DID, taken from the branch's single copy.
    pub did: Did,
    /// Adapter projection of that DID.
    pub principal_id: DidCoreId,
    /// Canonical digest of the complete typed anchor.
    pub registration_anchor_digest: Hash,
    /// Adapter-derived registration `version_id`.
    pub did_version_id: String,
    /// Adapter-derived `method_history_head`.
    pub method_history_head: Hash,
    /// `versionTime` of the registration entry. `None` for a method with no
    /// native publication time, where no ordering claim exists to check.
    pub did_version_time: Option<DateTime<Utc>>,
    /// Digest of the derived root control key bytes.
    pub control_key_digest: Hash,
    /// The derived root control key.
    pub root_public_key_multibase: String,
    /// DID URL that signed the registration entry with that root key.
    pub root_verification_method: DidUrl,
    /// The single method-native pre-rotation commitment, when the method has
    /// one. `None` for an immutable anchor with no rotation rail.
    pub next_root_key_hash: Option<String>,
}

/// `did:webvh` `versionId` is `<version number>-<entryHash>`.
fn webvh_version_number(entry: &BTreeMap<String, Value>) -> Option<u64> {
    let version_id = entry.get("versionId").and_then(Value::as_str)?;
    let (number, _) = version_id.split_once('-')?;
    if number.len() > 1 && number.starts_with('0') {
        return None;
    }
    number.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(version: &str) -> BTreeMap<String, Value> {
        serde_json::from_value(serde_json::json!({
            "versionId": version,
            "versionTime": "2026-09-13T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "QmZL2kpCm1uJHkcg6jEKpx1oWAJvdxwSbuAbXHxCVtAi2C",
                "updateKeys": ["z6MktiAojPDKXTWTn2SUx2j649MeZ2xQSFaZWVz6Wy3Vyk5d"]
            },
            "state": {"id": "did:webvh:QmZL2kpCm1uJHkcg6jEKpx1oWAJvdxwSbuAbXHxCVtAi2C:alice.example"}
        }))
        .unwrap()
    }

    fn webvh_anchor() -> PrincipalRegistrationAnchor {
        let terminal = entry("1-QmbJu2JEt8oYyNPQ5AqXeEGZi6Vi7oR24DsqJ1GCuFaD9Q");
        let did =
            Did::new("did:webvh:QmZL2kpCm1uJHkcg6jEKpx1oWAJvdxwSbuAbXHxCVtAi2C:alice.example")
                .unwrap();
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(DidOperationSubmitRequestBody {
                did: did.clone(),
                did_method: crate::DidMethodName::Webvh,
                seq: Some(1),
                prev_event_digest: None,
                operation: terminal.clone(),
            }),
            log_entries: vec![terminal],
            witness_records: Vec::new(),
            normalized_did_document: serde_json::from_value(
                crate::normalized_did_document(
                    &serde_json::from_value::<DidDocument>(serde_json::json!({"id": did})).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn webvh_anchor_validates_and_exposes_its_single_did() {
        let anchor = webvh_anchor();
        anchor.validate().unwrap();
        assert_eq!(anchor.anchor_kind(), WEBVH_REGISTRATION_ANCHOR_KIND);
        assert_eq!(
            anchor.did().as_str(),
            "did:webvh:QmZL2kpCm1uJHkcg6jEKpx1oWAJvdxwSbuAbXHxCVtAi2C:alice.example"
        );
    }

    #[test]
    fn webvh_anchor_rejects_an_operation_that_is_not_the_terminal_entry() {
        let PrincipalRegistrationAnchor::WebvhRegistration {
            mut registration_did_operation,
            log_entries,
            witness_records,
            normalized_did_document,
        } = webvh_anchor();
        registration_did_operation.operation =
            entry("1-QmcLQFWBGJzDb3yvVEanEBiit18J4aiWCZSZ6xiX8cHhTa");
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries,
            witness_records,
            normalized_did_document,
        }
        .validate()
        .unwrap_err();
    }

    #[test]
    fn webvh_anchor_rejects_a_log_that_skips_its_inception() {
        let PrincipalRegistrationAnchor::WebvhRegistration {
            mut registration_did_operation,
            witness_records,
            normalized_did_document,
            ..
        } = webvh_anchor();
        let terminal = entry("2-QmcLQFWBGJzDb3yvVEanEBiit18J4aiWCZSZ6xiX8cHhTa");
        registration_did_operation.operation = terminal.clone();
        registration_did_operation.seq = Some(2);
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries: vec![terminal],
            witness_records,
            normalized_did_document,
        }
        .validate()
        .unwrap_err();
    }

    #[test]
    fn webvh_anchor_rejects_a_surplus_witness_record() {
        let PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries,
            normalized_did_document,
            ..
        } = webvh_anchor();
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries,
            witness_records: vec![
                serde_json::from_value(serde_json::json!({
                    "versionId": "9-QmSurplusWitnessRecordVersionAaaaaaaaaaaaaaaaaa",
                    "proof": []
                }))
                .unwrap(),
            ],
            normalized_did_document,
        }
        .validate()
        .unwrap_err();
    }

    #[test]
    fn did_key_is_not_a_registered_registration_anchor_branch() {
        serde_json::from_value::<PrincipalRegistrationAnchor>(serde_json::json!({
            "anchor_kind": "did_key_registration",
            "did": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
        }))
        .unwrap_err();
    }

    #[test]
    fn did_web_is_not_a_registered_registration_anchor_branch() {
        serde_json::from_value::<PrincipalRegistrationAnchor>(serde_json::json!({
            "anchor_kind": "did_web_registration",
            "did": "did:web:alice.example"
        }))
        .unwrap_err();
    }
}
