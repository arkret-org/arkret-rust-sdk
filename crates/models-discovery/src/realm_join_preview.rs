//! Current pre-join Realm preview DTOs.
//!
//! Locator hints are untrusted starting points. A preview becomes usable only
//! after the caller validates the nonce-bound authority bundle from Realm
//! genesis through the current authority generation.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, DidCoreId, HistoryAccess, InviteId, JoinRule, RealmAuthorityBundle, RealmId,
    RequestId, Result, WireError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLocatorSource {
    Invite,
    Directory,
    Cache,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityLocatorHint {
    pub service_id: DidCoreId,
    pub source: AuthorityLocatorSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
}

impl AuthorityLocatorHint {
    pub fn validate(&self) -> Result<()> {
        if self
            .endpoint_url
            .as_ref()
            .is_some_and(|url| !url.starts_with("https://"))
        {
            return Err(WireError::Protocol(
                "authority locator endpoint_url must use https".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinTarget {
    pub realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    pub authority_locator_hints: Vec<AuthorityLocatorHint>,
}

impl RealmJoinTarget {
    pub fn validate(&self) -> Result<()> {
        if !(1..=8).contains(&self.authority_locator_hints.len())
            || self.invite_id.is_some() != self.invite_token.is_some()
        {
            return Err(WireError::Protocol(
                "Realm join target has invalid invite or locator cardinality".to_owned(),
            ));
        }
        let unique = self.authority_locator_hints.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.authority_locator_hints.len() {
            return Err(WireError::Protocol(
                "authority locator hints must be unique".to_owned(),
            ));
        }
        for hint in &self.authority_locator_hints {
            hint.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPublicPreview {
    pub realm_id: RealmId,
    pub join_rule: JoinRule,
    pub history_access: HistoryAccess,
    pub authority_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfPreviewRequestBody {
    pub request_id: RequestId,
    pub target: RealmJoinTarget,
}

impl RealmJoinSelfPreviewRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.target.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinSelfPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

impl RealmJoinSelfPreviewOutcome {
    pub fn validate_for_request(&self, request: &RealmJoinSelfPreviewRequestBody) -> Result<()> {
        request.validate()?;
        self.authority_bundle.validate_shape()?;
        if self.request_id != request.request_id
            || self.preview.realm_id != request.target.realm_id
            || self.authority_bundle.realm_id != request.target.realm_id
            || self.preview.authority_generation != self.authority_bundle.current_generation
        {
            return Err(WireError::Protocol(
                "Realm preview does not bind the request and authority bundle".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerPreviewRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub requester_account_id: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<InviteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

impl RealmJoinPeerPreviewRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.requester_account_id.validate()?;
        if self.invite_id.is_some() != self.invite_token.is_some() {
            return Err(WireError::Protocol(
                "peer Realm preview invite_id and invite_token must appear together".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmJoinPeerPreviewOutcome {
    pub request_id: RequestId,
    pub authority_bundle: RealmAuthorityBundle,
    pub preview: RealmPublicPreview,
}

impl RealmJoinPeerPreviewOutcome {
    pub fn validate_for_request(&self, request: &RealmJoinPeerPreviewRequestBody) -> Result<()> {
        request.validate()?;
        self.authority_bundle.validate_shape()?;
        if self.request_id != request.request_id
            || self.preview.realm_id != request.realm_id
            || self.authority_bundle.realm_id != request.realm_id
            || self.preview.authority_generation != self.authority_bundle.current_generation
        {
            return Err(WireError::Protocol(
                "peer Realm preview does not bind the request and authority bundle".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde::Serialize;
    use serde_json::Value;

    use super::*;

    const INTAKE: &str = "schemas/realm-join-intake.schema.json";

    fn definition(name: &str) -> Value {
        arkret_schema_conformance::spec_json_artifact(INTAKE)
            .unwrap_or_else(|error| panic!("embedded {INTAKE} failed to load: {error}"))["$defs"]
            [name]
            .clone()
    }

    fn assert_matches_schema<T: Serialize>(name: &str, value: &T) {
        let declared = definition(name)["properties"]
            .as_object()
            .expect("schema properties")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let carried = serde_json::to_value(value)
            .expect("serialize")
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(declared, carried, "$defs/{name} and carrier differ");
    }

    fn target() -> RealmJoinTarget {
        RealmJoinTarget {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            invite_id: Some(
                InviteId::new("ak:invite:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G").unwrap(),
            ),
            invite_token: Some("srv-01HYZ8Z000000000000000".to_owned()),
            authority_locator_hints: vec![AuthorityLocatorHint {
                service_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                source: AuthorityLocatorSource::Directory,
                endpoint_url: Some("https://station.example".to_owned()),
            }],
        }
    }

    #[test]
    fn current_request_carriers_match_the_schema() {
        let self_request = RealmJoinSelfPreviewRequestBody {
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000041").unwrap(),
            target: target(),
        };
        assert_matches_schema("self_preview_request_body", &self_request);

        let peer_request = RealmJoinPeerPreviewRequestBody {
            request_id: self_request.request_id,
            realm_id: self_request.target.realm_id,
            requester_account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:invitee.example").unwrap(),
                DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
            ),
            invite_id: self_request.target.invite_id,
            invite_token: self_request.target.invite_token,
        };
        assert_matches_schema("peer_preview_request_body", &peer_request);
    }

    #[test]
    fn target_is_a_single_closed_current_shape() {
        assert_matches_schema("join_target", &target());
        assert!(target().validate().is_ok());
    }
}
