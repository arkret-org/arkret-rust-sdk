//! Notary cell typed value.
//!
//! The notary cell `ak:cell:ak.component.notary.v1:<realm_id>` is a
//! cas-register (bottom=reject) holding the current authoritative value
//! that says **who is allowed to sign Seals for this Realm**. The four
//! profile variants:
//!
//! - **SingleDid** — one DID is the notary (typical principal control).
//! - **Threshold** — `k`-of-`n` threshold scheme with explicit member set.
//! - **OpenSet** — any signer in the listed DID set may sign (used for open-mesh /
//!   committee-coordinated profiles).
//! - **Mixed** — primary notary + `recovery_members` who can step in only when primary is paused /
//!   fails the staleness window.
//!
//! Wire shape uses internal tagging on `type` so consumers can decode
//! without ambiguity.

use serde::{Deserialize, Serialize};

use crate::{Did, Error, Result};

/// Equivocation culprit-attribution mode for [`NotaryValue::Threshold`]
/// committees (realm.schema.json `notary.forensic_attribution`;
/// `event-auth-state-resolution.md` §7.1 / BFT Protocol Forensics).
///
/// - [`QuorumIntersection`](Self::QuorumIntersection) — REQUIRED when `2 * threshold >
///   members.len()`: any two conflicting quorums then intersect in at least one attributable
///   double-signer.
/// - [`Waived`](Self::Waived) — REQUIRED when `2 * threshold <= members.len()`: the deployment
///   explicitly waives automatic culprit attribution and relies on committee-level handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ForensicAttribution {
    QuorumIntersection,
    Waived,
}

/// Current value of the notary cell.
///
/// The wire shape is the authoritative `realm.schema.json` `notary` object
/// (internal tag `type`). For `single_did`, the org-diversity recovery fields
/// (`recovery_members` / `controller_organization` /
/// `recovery_controller_organizations`) are present only when the deployment
/// can derive a controlling organization; personal / orgless Realms omit them
/// (decisions/0003 §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotaryValue {
    SingleDid {
        did: Did,
        /// Explicit recovery-notary path. REQUIRED (non-empty) when
        /// `controller_organization` is declared; otherwise omitted.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_members: Vec<Did>,
        /// Organization DID controlling the primary notary, when derivable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_organization: Option<Did>,
        /// Organizations controlling `recovery_members`; the reducer verifies
        /// at least one differs from `controller_organization`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recovery_controller_organizations: Vec<Did>,
    },
    Threshold {
        /// `k` in a `k`-of-`n` scheme (`n == members.len()`).
        threshold: u32,
        members: Vec<Did>,
        forensic_attribution: ForensicAttribution,
    },
    OpenSet {
        members: Vec<Did>,
    },
    Mixed {
        /// Primary notary DID (`did` per realm.schema.json).
        did: Did,
        recovery_members: Vec<Did>,
    },
}

impl NotaryValue {
    /// Build an orgless `single_did` notary (personal / dev Realm). No
    /// controlling organization, no recovery path — matches the relaxed
    /// `realm.schema.json` single_did genesis shape `{type, did}`.
    pub fn single_did(did: Did) -> Self {
        NotaryValue::SingleDid {
            did,
            recovery_members: Vec::new(),
            controller_organization: None,
            recovery_controller_organizations: Vec::new(),
        }
    }

    /// Build an org-controlled `single_did` notary with the explicit
    /// recovery-notary diversity path the reducer verifies.
    pub fn single_did_with_org(
        did: Did,
        recovery_members: Vec<Did>,
        controller_organization: Did,
        recovery_controller_organizations: Vec<Did>,
    ) -> Self {
        NotaryValue::SingleDid {
            did,
            recovery_members,
            controller_organization: Some(controller_organization),
            recovery_controller_organizations,
        }
    }

    /// Structural validation of the value's internal consistency.
    pub fn validate(&self) -> Result<()> {
        match self {
            NotaryValue::SingleDid {
                recovery_members,
                controller_organization,
                recovery_controller_organizations,
                ..
            } => {
                // Org-controlled single_did MUST declare a recovery-notary
                // diversity path (realm.schema.json single_did allOf).
                if controller_organization.is_some() {
                    if recovery_members.is_empty() {
                        return Err(Error::Protocol(
                            "NotaryValue::SingleDid with controller_organization requires recovery_members"
                                .to_owned(),
                        ));
                    }
                    if recovery_controller_organizations.is_empty() {
                        return Err(Error::Protocol(
                            "NotaryValue::SingleDid with controller_organization requires recovery_controller_organizations"
                                .to_owned(),
                        ));
                    }
                }
                if has_duplicates(recovery_members) {
                    return Err(Error::Protocol(
                        "NotaryValue::SingleDid recovery_members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
            NotaryValue::Threshold {
                threshold,
                members,
                forensic_attribution,
            } => {
                if *threshold == 0 {
                    return Err(Error::Protocol(
                        "NotaryValue::Threshold threshold must be >= 1".to_owned(),
                    ));
                }
                if members.is_empty() {
                    return Err(Error::Protocol(
                        "NotaryValue::Threshold members must not be empty".to_owned(),
                    ));
                }
                if *threshold as usize > members.len() {
                    return Err(Error::Protocol(format!(
                        "NotaryValue::Threshold threshold={threshold} must be <= members.len()={}",
                        members.len()
                    )));
                }
                if has_duplicates(members) {
                    return Err(Error::Protocol(
                        "NotaryValue::Threshold members must be unique".to_owned(),
                    ));
                }
                // forensic_attribution arithmetic (realm.schema.json
                // notary.forensic_attribution $comment): quorum_intersection
                // iff 2*threshold > members.len().
                let needs_intersection = 2 * (*threshold as usize) > members.len();
                match (needs_intersection, forensic_attribution) {
                    (true, ForensicAttribution::Waived) => {
                        return Err(Error::Protocol(
                            "NotaryValue::Threshold with 2*threshold > members.len() requires forensic_attribution=quorum_intersection"
                                .to_owned(),
                        ));
                    }
                    (false, ForensicAttribution::QuorumIntersection) => {
                        return Err(Error::Protocol(
                            "NotaryValue::Threshold with 2*threshold <= members.len() requires forensic_attribution=waived"
                                .to_owned(),
                        ));
                    }
                    _ => {}
                }
                Ok(())
            }
            NotaryValue::OpenSet { members } => {
                if members.is_empty() {
                    return Err(Error::Protocol(
                        "NotaryValue::OpenSet members must not be empty".to_owned(),
                    ));
                }
                if has_duplicates(members) {
                    return Err(Error::Protocol(
                        "NotaryValue::OpenSet members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
            NotaryValue::Mixed {
                did,
                recovery_members,
            } => {
                if recovery_members.is_empty() {
                    return Err(Error::Protocol(
                        "NotaryValue::Mixed recovery_members must not be empty".to_owned(),
                    ));
                }
                if recovery_members.iter().any(|m| m == did) {
                    return Err(Error::Protocol(
                        "NotaryValue::Mixed primary did must not appear in recovery_members"
                            .to_owned(),
                    ));
                }
                if has_duplicates(recovery_members) {
                    return Err(Error::Protocol(
                        "NotaryValue::Mixed recovery_members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Whether `signer` is currently authorized to sign an Seal under
    /// this profile, ignoring per-Seal multi/threshold structural rules
    /// (those live on the Seal-side validator).
    ///
    /// For `Mixed` profiles, this returns `true` for the primary; recovery
    /// members are only authorized after `revocation_freshness_window_ms`
    /// triggers, which is a runtime predicate the caller checks.
    pub fn includes_signer_as_primary(&self, signer: &Did) -> bool {
        match self {
            NotaryValue::SingleDid { did, .. } => signer == did,
            NotaryValue::Threshold { members, .. } | NotaryValue::OpenSet { members } => {
                members.iter().any(|m| m == signer)
            }
            NotaryValue::Mixed { did, .. } => signer == did,
        }
    }

    /// Whether `signer` is a recovery member (Mixed profile only).
    pub fn is_recovery_member(&self, signer: &Did) -> bool {
        matches!(
            self,
            NotaryValue::Mixed { recovery_members, .. }
                if recovery_members.iter().any(|m| m == signer)
        )
    }
}

fn has_duplicates<T: Eq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(i, a)| items.iter().skip(i + 1).any(|b| a == b))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s.to_owned()).unwrap()
    }

    #[test]
    fn single_did_validates() {
        // Orgless personal Realm: `{type, did}` only.
        let v = NotaryValue::single_did(did("did:webvh:z6mkfixture:soland.example"));
        v.validate().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(
            s,
            r#"{"type":"single_did","did":"did:webvh:z6mkfixture:soland.example"}"#
        );
    }

    #[test]
    fn single_did_with_org_validates_and_requires_recovery() {
        let ok = NotaryValue::single_did_with_org(
            did("did:webvh:z6mkfixture:notary.example"),
            vec![did("did:webvh:z6mkfixture:recovery.example")],
            did("did:webvh:z6mkfixture:org.example"),
            vec![did("did:webvh:z6mkfixture:recovery-org.example")],
        );
        ok.validate().unwrap();

        // controller_organization without a recovery path is rejected.
        let bad = NotaryValue::SingleDid {
            did: did("did:webvh:z6mkfixture:notary.example"),
            recovery_members: vec![],
            controller_organization: Some(did("did:webvh:z6mkfixture:org.example")),
            recovery_controller_organizations: vec![],
        };
        let err = bad.validate().unwrap_err();
        assert!(format!("{err}").contains("requires recovery_members"));
    }

    #[test]
    fn threshold_above_member_count_rejected() {
        let v = NotaryValue::Threshold {
            threshold: 5,
            members: vec![
                did("did:webvh:z6mkfixture:a.example"),
                did("did:webvh:z6mkfixture:b.example"),
                did("did:webvh:z6mkfixture:c.example"),
            ],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must be <= members.len()"));
    }

    #[test]
    fn threshold_forensic_attribution_arithmetic_enforced() {
        // 2*2 > 3 → quorum_intersection required; waived is rejected.
        let waived = NotaryValue::Threshold {
            threshold: 2,
            members: vec![
                did("did:webvh:z6mkfixture:a.example"),
                did("did:webvh:z6mkfixture:b.example"),
                did("did:webvh:z6mkfixture:c.example"),
            ],
            forensic_attribution: ForensicAttribution::Waived,
        };
        let err = waived.validate().unwrap_err();
        assert!(format!("{err}").contains("requires forensic_attribution=quorum_intersection"));

        // 2*1 <= 3 → waived required; quorum_intersection is rejected.
        let qi = NotaryValue::Threshold {
            threshold: 1,
            members: vec![
                did("did:webvh:z6mkfixture:a.example"),
                did("did:webvh:z6mkfixture:b.example"),
                did("did:webvh:z6mkfixture:c.example"),
            ],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        let err = qi.validate().unwrap_err();
        assert!(format!("{err}").contains("requires forensic_attribution=waived"));
    }

    #[test]
    fn threshold_duplicate_member_rejected() {
        let v = NotaryValue::Threshold {
            threshold: 2,
            members: vec![
                did("did:webvh:z6mkfixture:a.example"),
                did("did:webvh:z6mkfixture:b.example"),
                did("did:webvh:z6mkfixture:a.example"),
            ],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must be unique"));
    }

    #[test]
    fn open_set_empty_rejected() {
        let v = NotaryValue::OpenSet { members: vec![] };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must not be empty"));
    }

    #[test]
    fn mixed_empty_recovery_rejected() {
        let v = NotaryValue::Mixed {
            did: did("did:webvh:z6mkfixture:soland.example"),
            recovery_members: vec![],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("recovery_members must not be empty"));
    }

    #[test]
    fn mixed_primary_in_recovery_rejected() {
        let v = NotaryValue::Mixed {
            did: did("did:webvh:z6mkfixture:soland.example"),
            recovery_members: vec![did("did:webvh:z6mkfixture:soland.example")],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must not appear in recovery_members"));
    }

    #[test]
    fn includes_signer_dispatches_per_variant() {
        let alice = did("did:webvh:z6mkfixture:alice.example");
        let bob = did("did:webvh:z6mkfixture:bob.example");
        let charlie = did("did:webvh:z6mkfixture:charlie.example");

        let single = NotaryValue::single_did(alice.clone());
        assert!(single.includes_signer_as_primary(&alice));
        assert!(!single.includes_signer_as_primary(&bob));

        let threshold = NotaryValue::Threshold {
            threshold: 2,
            members: vec![alice.clone(), bob.clone(), charlie.clone()],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        assert!(threshold.includes_signer_as_primary(&bob));

        let open = NotaryValue::OpenSet {
            members: vec![alice.clone(), bob.clone()],
        };
        assert!(open.includes_signer_as_primary(&alice));
        assert!(!open.includes_signer_as_primary(&charlie));

        let mixed = NotaryValue::Mixed {
            did: alice.clone(),
            recovery_members: vec![bob.clone()],
        };
        assert!(mixed.includes_signer_as_primary(&alice));
        assert!(!mixed.includes_signer_as_primary(&bob));
        assert!(mixed.is_recovery_member(&bob));
        assert!(!mixed.is_recovery_member(&alice));
    }

    #[test]
    fn serializes_with_type_discriminator() {
        let v = NotaryValue::single_did(did("did:webvh:z6mkfixture:a.example"));
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"type\":\"single_did\""), "got {s}");

        let v = NotaryValue::Threshold {
            threshold: 2,
            members: vec![
                did("did:webvh:z6mkfixture:a.example"),
                did("did:webvh:z6mkfixture:b.example"),
                did("did:webvh:z6mkfixture:c.example"),
            ],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"type\":\"threshold\""), "got {s}");
        assert!(s.contains("\"threshold\":2"), "got {s}");
        assert!(
            s.contains("\"forensic_attribution\":\"quorum_intersection\""),
            "got {s}"
        );
        assert!(!s.contains("\"k\":") && !s.contains("\"n\":"), "got {s}");
    }

    #[test]
    fn deserializes_from_type_tagged_json() {
        let raw = json!({
            "type": "mixed",
            "did": "did:webvh:z6mkfixture:soland.example",
            "recovery_members": ["did:webvh:z6mkfixture:backup.example"]
        });
        let v: NotaryValue = serde_json::from_value(raw).unwrap();
        match v {
            NotaryValue::Mixed {
                did,
                recovery_members,
            } => {
                assert_eq!(did.as_str(), "did:webvh:z6mkfixture:soland.example");
                assert_eq!(recovery_members.len(), 1);
            }
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn unknown_type_rejected() {
        let raw = json!({"type": "future_unknown"});
        let r: std::result::Result<NotaryValue, _> = serde_json::from_value(raw);
        assert!(r.is_err(), "unknown notary type must fail closed");
    }
}
