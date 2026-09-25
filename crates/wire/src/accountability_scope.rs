//! Closed accountability scope values and their normalized exact set.
//!
//! `zh/models/actor.md` section 3.3.1 fixes the `identity_accountability`
//! typed current result subject as `(Realm, issuer principal, subject
//! principal, normalized exact scope set)`. The scope component is
//! `string_set_digest(accountability_scope, ak.accountability_scope_set.v1)`,
//! so a wire singleton string and its one-element array address one result.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{DomainSeparationId, Hash, Result, WireError};

/// One closed `accountability-grant.schema.json#/$defs/scope` value.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityScopeKind {
    Employment,
    ContractedService,
    AgentOperator,
}

impl AccountabilityScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Employment => "employment",
            Self::ContractedService => "contracted_service",
            Self::AgentOperator => "agent_operator",
        }
    }
}

/// A non-empty, duplicate-free scope set in ascending raw UTF-8 byte order.
///
/// This is the stored `accountability_projection.accountability_scope` member
/// and the selector's scope member. Deserialization accepts only the already
/// normalized array, because both carriers are reducer outputs; wire authoring
/// shapes normalize through [`AccountabilityScopeSet::normalize`].
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct AccountabilityScopeSet(Vec<AccountabilityScopeKind>);

impl AccountabilityScopeSet {
    /// Normalize a wire scope collection: reject an empty set and duplicates,
    /// then order by raw UTF-8 bytes.
    pub fn normalize(scopes: impl IntoIterator<Item = AccountabilityScopeKind>) -> Result<Self> {
        let scopes = scopes.into_iter().collect::<Vec<_>>();
        if scopes.is_empty() {
            return Err(WireError::Protocol(
                "accountability scope set must not be empty".to_owned(),
            ));
        }
        let unique = scopes.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != scopes.len() {
            return Err(WireError::Protocol(
                "accountability scope set must not repeat a scope".to_owned(),
            ));
        }
        let mut scopes = scopes;
        scopes.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        Ok(Self(scopes))
    }

    pub fn scopes(&self) -> &[AccountabilityScopeKind] {
        &self.0
    }

    /// `string_set_digest(scopes, ak.accountability_scope_set.v1)`:
    /// `"sha256:" || lowercase_hex(SHA256(UTF8(domain "\n") || JCS({"scopes": normalized})))`.
    pub fn digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Transcript<'a> {
            scopes: &'a [AccountabilityScopeKind],
        }
        let mut input = DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1
            .as_bytes()
            .to_vec();
        input.push(b'\n');
        input.extend(arkret_canonical::canonical_json_bytes(&Transcript {
            scopes: &self.0,
        })?);
        Ok(Hash::new(arkret_canonical::sha256_digest(&input))?)
    }
}

impl<'de> Deserialize<'de> for AccountabilityScopeSet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let scopes = Vec::<AccountabilityScopeKind>::deserialize(deserializer)?;
        let normalized = Self::normalize(scopes.clone()).map_err(de::Error::custom)?;
        if normalized.0 != scopes {
            return Err(de::Error::custom(
                "accountability scope set must be in ascending raw UTF-8 byte order",
            ));
        }
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn digest_matches_the_formal_kat() {
        let set = AccountabilityScopeSet::normalize([
            AccountabilityScopeKind::Employment,
            AccountabilityScopeKind::AgentOperator,
            AccountabilityScopeKind::ContractedService,
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&set).unwrap(),
            json!(["agent_operator", "contracted_service", "employment"])
        );
        assert_eq!(
            set.digest().unwrap().as_str(),
            "sha256:3b184e4d6501c2b36ae5c19cfb652d5b203ebd3732e76081ba818b5ad066a9cf"
        );
    }

    #[test]
    fn singleton_digest_is_independent_of_the_wire_spelling() {
        let one =
            AccountabilityScopeSet::normalize([AccountabilityScopeKind::AgentOperator]).unwrap();
        let parsed: AccountabilityScopeSet =
            serde_json::from_value(json!(["agent_operator"])).expect("normalized singleton array");
        assert_eq!(one, parsed);
        assert_eq!(one.digest().unwrap(), parsed.digest().unwrap());
    }

    #[test]
    fn stored_set_rejects_empty_duplicate_and_unordered_arrays() {
        for invalid in [
            json!([]),
            json!(["employment", "employment"]),
            json!(["employment", "agent_operator"]),
            json!("employment"),
        ] {
            assert!(
                serde_json::from_value::<AccountabilityScopeSet>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
    }
}
