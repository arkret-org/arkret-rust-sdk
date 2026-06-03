//! Anchorer cell typed value.
//!
//! The anchorer cell `ck:cell:cx.component.anchorer.v1:<space_id>` is a
//! cas-register (bottom=reject) holding the current authoritative value
//! that says **who is allowed to sign Anchors for this Space**. The four
//! profile variants:
//!
//! - **SingleDid** — one DID is the anchorer (typical principal control).
//! - **Threshold** — `k`-of-`n` threshold scheme with explicit member set.
//! - **OpenSet** — any signer in the listed DID set may sign (used for
//!   open-mesh / committee-coordinated profiles).
//! - **Mixed** — primary anchorer + `recovery_members` who can step in
//!   only when primary is paused / fails the staleness window.
//!
//! Wire shape uses internal tagging on `kind` so consumers can decode
//! without ambiguity.

use serde::{Deserialize, Serialize};

use crate::{Did, Error, Result};

/// Current value of the anchorer cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorerValue {
    SingleDid { did: Did },
    Threshold { k: u32, n: u32, members: Vec<Did> },
    OpenSet { members: Vec<Did> },
    Mixed { primary: Did, recovery_members: Vec<Did> },
}

impl AnchorerValue {
    /// Structural validation of the value's internal consistency.
    pub fn validate(&self) -> Result<()> {
        match self {
            AnchorerValue::SingleDid { .. } => Ok(()),
            AnchorerValue::Threshold { k, n, members } => {
                if *n == 0 {
                    return Err(Error::Protocol(
                        "AnchorerValue::Threshold n must be >= 1".to_owned(),
                    ));
                }
                if *k == 0 {
                    return Err(Error::Protocol(
                        "AnchorerValue::Threshold k must be >= 1".to_owned(),
                    ));
                }
                if *k > *n {
                    return Err(Error::Protocol(format!(
                        "AnchorerValue::Threshold k={k} must be <= n={n}"
                    )));
                }
                if members.len() as u32 != *n {
                    return Err(Error::Protocol(format!(
                        "AnchorerValue::Threshold members.len()={} must equal n={}",
                        members.len(),
                        n
                    )));
                }
                if has_duplicates(members) {
                    return Err(Error::Protocol(
                        "AnchorerValue::Threshold members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
            AnchorerValue::OpenSet { members } => {
                if members.is_empty() {
                    return Err(Error::Protocol(
                        "AnchorerValue::OpenSet members must not be empty".to_owned(),
                    ));
                }
                if has_duplicates(members) {
                    return Err(Error::Protocol(
                        "AnchorerValue::OpenSet members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
            AnchorerValue::Mixed { primary, recovery_members } => {
                if recovery_members.is_empty() {
                    return Err(Error::Protocol(
                        "AnchorerValue::Mixed recovery_members must not be empty".to_owned(),
                    ));
                }
                if recovery_members.iter().any(|m| m == primary) {
                    return Err(Error::Protocol(
                        "AnchorerValue::Mixed primary must not appear in recovery_members"
                            .to_owned(),
                    ));
                }
                if has_duplicates(recovery_members) {
                    return Err(Error::Protocol(
                        "AnchorerValue::Mixed recovery_members must be unique".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Whether `signer` is currently authorized to sign an Anchor under
    /// this profile, ignoring per-Anchor multi/threshold structural rules
    /// (those live on the Anchor-side validator).
    ///
    /// For `Mixed` profiles, this returns `true` for the primary; recovery
    /// members are only authorized after `max_anchor_staleness_ms`
    /// triggers, which is a runtime predicate the caller checks.
    pub fn includes_signer_as_primary(&self, signer: &Did) -> bool {
        match self {
            AnchorerValue::SingleDid { did } => signer == did,
            AnchorerValue::Threshold { members, .. } | AnchorerValue::OpenSet { members } => {
                members.iter().any(|m| m == signer)
            }
            AnchorerValue::Mixed { primary, .. } => signer == primary,
        }
    }

    /// Whether `signer` is a recovery member (Mixed profile only).
    pub fn is_recovery_member(&self, signer: &Did) -> bool {
        matches!(
            self,
            AnchorerValue::Mixed { recovery_members, .. }
                if recovery_members.iter().any(|m| m == signer)
        )
    }
}

fn has_duplicates<T: Eq>(items: &[T]) -> bool {
    items.iter().enumerate().any(|(i, a)| items.iter().skip(i + 1).any(|b| a == b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn did(s: &str) -> Did {
        Did::new(s.to_owned()).unwrap()
    }

    #[test]
    fn single_did_validates() {
        let v = AnchorerValue::SingleDid { did: did("did:web:soland.example") };
        v.validate().unwrap();
    }

    #[test]
    fn threshold_k_above_n_rejected() {
        let v = AnchorerValue::Threshold {
            k: 5,
            n: 3,
            members: vec![
                did("did:web:a.example"),
                did("did:web:b.example"),
                did("did:web:c.example"),
            ],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must be <= n"));
    }

    #[test]
    fn threshold_member_count_mismatch_rejected() {
        let v = AnchorerValue::Threshold {
            k: 2,
            n: 5,
            members: vec![did("did:web:a.example"), did("did:web:b.example")],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must equal n"));
    }

    #[test]
    fn threshold_duplicate_member_rejected() {
        let v = AnchorerValue::Threshold {
            k: 2,
            n: 3,
            members: vec![
                did("did:web:a.example"),
                did("did:web:b.example"),
                did("did:web:a.example"),
            ],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must be unique"));
    }

    #[test]
    fn open_set_empty_rejected() {
        let v = AnchorerValue::OpenSet { members: vec![] };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must not be empty"));
    }

    #[test]
    fn mixed_empty_recovery_rejected() {
        let v = AnchorerValue::Mixed {
            primary: did("did:web:soland.example"),
            recovery_members: vec![],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("recovery_members must not be empty"));
    }

    #[test]
    fn mixed_primary_in_recovery_rejected() {
        let v = AnchorerValue::Mixed {
            primary: did("did:web:soland.example"),
            recovery_members: vec![did("did:web:soland.example")],
        };
        let err = v.validate().unwrap_err();
        assert!(format!("{err}").contains("must not appear in recovery_members"));
    }

    #[test]
    fn includes_signer_dispatches_per_variant() {
        let alice = did("did:web:alice.example");
        let bob = did("did:web:bob.example");
        let charlie = did("did:web:charlie.example");

        let single = AnchorerValue::SingleDid { did: alice.clone() };
        assert!(single.includes_signer_as_primary(&alice));
        assert!(!single.includes_signer_as_primary(&bob));

        let threshold = AnchorerValue::Threshold {
            k: 2,
            n: 3,
            members: vec![alice.clone(), bob.clone(), charlie.clone()],
        };
        assert!(threshold.includes_signer_as_primary(&bob));

        let open = AnchorerValue::OpenSet { members: vec![alice.clone(), bob.clone()] };
        assert!(open.includes_signer_as_primary(&alice));
        assert!(!open.includes_signer_as_primary(&charlie));

        let mixed =
            AnchorerValue::Mixed { primary: alice.clone(), recovery_members: vec![bob.clone()] };
        assert!(mixed.includes_signer_as_primary(&alice));
        assert!(!mixed.includes_signer_as_primary(&bob));
        assert!(mixed.is_recovery_member(&bob));
        assert!(!mixed.is_recovery_member(&alice));
    }

    #[test]
    fn serializes_with_kind_discriminator() {
        let v = AnchorerValue::SingleDid { did: did("did:web:a.example") };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"kind\":\"single_did\""), "got {s}");

        let v = AnchorerValue::Threshold {
            k: 2,
            n: 3,
            members: vec![
                did("did:web:a.example"),
                did("did:web:b.example"),
                did("did:web:c.example"),
            ],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"kind\":\"threshold\""), "got {s}");
    }

    #[test]
    fn deserializes_from_kind_tagged_json() {
        let raw = json!({
            "kind": "mixed",
            "primary": "did:web:soland.example",
            "recovery_members": ["did:web:backup.example"]
        });
        let v: AnchorerValue = serde_json::from_value(raw).unwrap();
        match v {
            AnchorerValue::Mixed { primary, recovery_members } => {
                assert_eq!(primary.as_str(), "did:web:soland.example");
                assert_eq!(recovery_members.len(), 1);
            }
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn unknown_kind_rejected() {
        let raw = json!({"kind": "future_unknown"});
        let r: std::result::Result<AnchorerValue, _> = serde_json::from_value(raw);
        assert!(r.is_err(), "unknown anchorer kind must fail closed");
    }
}
