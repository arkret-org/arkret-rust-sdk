//! Closed history-sharing, causal-ingress, and KeyPackage terminal wire DTOs.
//!
//! These types mirror the corresponding definitions in
//! `protocol-journey-wire.schema.json`. They intentionally model the wire
//! unions directly instead of accepting product-defined strings or JSON.

use std::collections::BTreeSet;

// `protocol-journey-wire.schema.json#/$defs/history_visibility`,
// `realm.schema.json#/properties/history_visibility`, and
// `event-payload.schema.json#/$defs/history_visibility_value` share one closed
// wire vocabulary. Re-export the canonical SDK primitive instead of creating
// a second nominal Rust type with identical literals.
pub use arkret_wire::HistoryVisibility;
use arkret_wire::{Did, EventId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ProtocolOpaqueId, ProtocolSignature, string_marker};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryEventRange {
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryT0 {
    pub visibility: HistoryVisibility,
    pub history_policy_ref: EventId,
    pub scope_ref: ProtocolOpaqueId,
    pub event_range: HistoryEventRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ReceiverEligibilityBasis {
    ActiveMember { member_ref: EventId },
    Invited { invite_ref: EventId },
    RemovedT0Visible { remove_ref: EventId },
    WorldReadableRequester { requester_id: Did },
    SharedAuthorized { share_authority_ref: EventId },
    RestrictedAuthorized { policy_authority_ref: EventId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryCausalFrontiers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<EventId>,
    pub share: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryT1 {
    pub receiver_eligibility_basis: ReceiverEligibilityBasis,
    pub causal_frontiers: HistoryCausalFrontiers,
    pub share_authority_ref: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryT2 {
    pub verified_display_allowed: bool,
    pub controlled_cache_allowed: bool,
    pub subsequent_share_allowed: bool,
    pub current_policy_frontier: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HistoryShareContract {
    pub t0: HistoryT0,
    pub t1: HistoryT1,
    pub t2: HistoryT2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct CausalIngressReceipt {
    pub lease_basis: Hash,
    pub event_digest: Hash,
    pub qualified_ingress_id: ProtocolOpaqueId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub ingress_frontier: Vec<EventId>,
    pub issuer: Did,
    pub signature: ProtocolSignature,
}

impl CausalIngressReceipt {
    /// Enforce the schema's non-empty, unique causal frontier.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ingress_frontier.is_empty() {
            return Err("ingress_frontier must not be empty");
        }
        let mut seen = BTreeSet::new();
        if self
            .ingress_frontier
            .iter()
            .any(|event_id| !seen.insert(event_id.as_str()))
        {
            return Err("ingress_frontier must contain unique event ids");
        }
        Ok(())
    }
}

string_marker!(KeypackageRetireAction, Retire, "retire");
string_marker!(KeypackageRevokeAction, Revoke, "revoke");
string_marker!(KeypackageNoWriteAction, NoWrite, "no_write");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "expected_state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum KeypackageTerminalCommand {
    PublishedUnused {
        owner_account_id: Did,
        keypackage_ref: ProtocolOpaqueId,
        action: KeypackageRetireAction,
        idempotency_key: ProtocolOpaqueId,
    },
    ClaimedUnconsumed {
        owner_account_id: Did,
        keypackage_ref: ProtocolOpaqueId,
        claim_id: ProtocolOpaqueId,
        action: KeypackageRevokeAction,
        idempotency_key: ProtocolOpaqueId,
    },
    Consumed {
        owner_account_id: Did,
        keypackage_ref: ProtocolOpaqueId,
        action: KeypackageNoWriteAction,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event_id(suffix: &str) -> String {
        format!("ak:event:01964137-0000-7000-8000-{suffix}")
    }

    #[test]
    fn receiver_basis_is_a_closed_six_branch_union() {
        let cases = [
            json!({"kind":"active_member","member_ref":event_id("000000000001")}),
            json!({"kind":"invited","invite_ref":event_id("000000000002")}),
            json!({"kind":"removed_t0_visible","remove_ref":event_id("000000000003")}),
            json!({"kind":"world_readable_requester","requester_id":"did:webvh:z6mkfixture:reader.example"}),
            json!({"kind":"shared_authorized","share_authority_ref":event_id("000000000004")}),
            json!({"kind":"restricted_authorized","policy_authority_ref":event_id("000000000005")}),
        ];
        for value in cases {
            serde_json::from_value::<ReceiverEligibilityBasis>(value).unwrap();
        }
        assert!(
            serde_json::from_value::<ReceiverEligibilityBasis>(json!({
                "kind":"active_member",
                "member_ref":event_id("000000000001"),
                "extra":true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReceiverEligibilityBasis>(json!({
                "kind":"custom_policy",
                "policy_ref":event_id("000000000001")
            }))
            .is_err()
        );
    }

    #[test]
    fn keypackage_terminal_command_enforces_state_action_pairing() {
        let retired: KeypackageTerminalCommand = serde_json::from_value(json!({
            "owner_account_id":"did:webvh:z6mkfixture:owner.example",
            "keypackage_ref":"kp-1",
            "expected_state":"published_unused",
            "action":"retire",
            "idempotency_key":"retire-1"
        }))
        .unwrap();
        assert!(matches!(
            retired,
            KeypackageTerminalCommand::PublishedUnused { .. }
        ));
        assert!(
            serde_json::from_value::<KeypackageTerminalCommand>(json!({
                "owner_account_id":"did:webvh:z6mkfixture:owner.example",
                "keypackage_ref":"kp-1",
                "expected_state":"published_unused",
                "action":"revoke",
                "idempotency_key":"retire-1"
            }))
            .is_err()
        );
    }

    #[test]
    fn causal_ingress_frontier_must_be_non_empty_and_unique() {
        let mut receipt: CausalIngressReceipt = serde_json::from_value(json!({
            "lease_basis":format!("sha256:{}", "1".repeat(64)),
            "event_digest":format!("sha256:{}", "2".repeat(64)),
            "qualified_ingress_id":"ingress-1",
            "received_at":"2026-08-03T00:00:00.000Z",
            "ingress_frontier":[event_id("000000000001")],
            "issuer":"did:webvh:z6mkfixture:issuer.example",
            "signature":{
                "verification_method":"did:webvh:z6mkfixture:issuer.example#key-1",
                "created_at":"2026-08-03T00:00:00.000Z",
                "jws":"c2ln"
            }
        }))
        .unwrap();
        receipt.validate().unwrap();
        receipt
            .ingress_frontier
            .push(receipt.ingress_frontier[0].clone());
        assert_eq!(
            receipt.validate(),
            Err("ingress_frontier must contain unique event ids")
        );
    }
}
