//! MLS event payloads from `ck.schema.event_payload.v1`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

use super::*;
use crate::ERROR_CODE_SCHEMA_VIOLATION;
use crate::events::MLS_COMMIT;

pub const MLS_GOVERNANCE_BINDING_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_BINDING_ENCODING_PROFILE: &str = "cbor-deterministic-rfc8949-v1";

/// `event-payload.schema.json#/$defs/mls_governance_binding`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceBindingPayload {
    binding_version: u8,
    encoding_profile: String,
    realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    circle_id: Option<CircleId>,
    effective_scope: EffectiveScope,
    mls_group_id: String,
    previous_epoch: u64,
    next_epoch: u64,
    membership_frontier: Vec<EventId>,
    policy_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discussion_metadata_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reducer_profile: Option<String>,
}

impl MlsGovernanceBindingPayload {
    pub fn realm(
        realm_id: RealmId,
        mls_group_id: impl Into<String>,
        previous_epoch: u64,
        next_epoch: u64,
        membership_frontier: Vec<EventId>,
        policy_root: Hash,
    ) -> Result<Self> {
        let payload = Self {
            binding_version: MLS_GOVERNANCE_BINDING_VERSION,
            encoding_profile: MLS_GOVERNANCE_BINDING_ENCODING_PROFILE.to_owned(),
            realm_id: realm_id.clone(),
            circle_id: None,
            effective_scope: EffectiveScope::Realm { realm_id },
            mls_group_id: mls_group_id.into(),
            previous_epoch,
            next_epoch,
            membership_frontier,
            policy_root,
            capability_root: None,
            discussion_metadata_digest: None,
            binding_profile: None,
            reducer_profile: None,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn circle(
        realm_id: RealmId,
        circle_id: CircleId,
        mls_group_id: impl Into<String>,
        previous_epoch: u64,
        next_epoch: u64,
        membership_frontier: Vec<EventId>,
        policy_root: Hash,
    ) -> Result<Self> {
        let payload = Self {
            binding_version: MLS_GOVERNANCE_BINDING_VERSION,
            encoding_profile: MLS_GOVERNANCE_BINDING_ENCODING_PROFILE.to_owned(),
            realm_id: realm_id.clone(),
            circle_id: Some(circle_id.clone()),
            effective_scope: EffectiveScope::Circle { realm_id, circle_id },
            mls_group_id: mls_group_id.into(),
            previous_epoch,
            next_epoch,
            membership_frontier,
            policy_root,
            capability_root: None,
            discussion_metadata_digest: None,
            binding_profile: None,
            reducer_profile: None,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn with_capability_root(mut self, capability_root: Hash) -> Self {
        self.capability_root = Some(capability_root);
        self
    }

    pub fn with_discussion_metadata_digest(mut self, digest: Hash) -> Self {
        self.discussion_metadata_digest = Some(digest);
        self
    }

    pub fn with_binding_profile(mut self, profile: impl Into<String>) -> Result<Self> {
        self.binding_profile = Some(profile.into());
        self.validate()?;
        Ok(self)
    }

    pub fn with_reducer_profile(mut self, profile: impl Into<String>) -> Result<Self> {
        self.reducer_profile = Some(profile.into());
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.binding_version != MLS_GOVERNANCE_BINDING_VERSION {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.binding_version must be {MLS_GOVERNANCE_BINDING_VERSION} ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.encoding_profile != MLS_GOVERNANCE_BINDING_ENCODING_PROFILE {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.encoding_profile must be {MLS_GOVERNANCE_BINDING_ENCODING_PROFILE} ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.mls_group_id.trim().is_empty() {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.mls_group_id must be non-empty ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.membership_frontier.is_empty() {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.membership_frontier must be non-empty ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if let Some(binding_profile) = &self.binding_profile {
            validate_profile_id("mls_governance_binding.binding_profile", binding_profile)?;
        }
        if self.reducer_profile.as_ref().is_some_and(|profile| profile.is_empty()) {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.reducer_profile must be non-empty ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        match &self.effective_scope {
            EffectiveScope::Realm { realm_id } => {
                if realm_id != &self.realm_id || self.circle_id.is_some() {
                    return Err(Error::Protocol(format!(
                        "mls_governance_binding realm effective_scope mismatch ({ERROR_CODE_SCHEMA_VIOLATION})"
                    )));
                }
            }
            EffectiveScope::Circle { realm_id, circle_id } => {
                if realm_id != &self.realm_id || self.circle_id.as_ref() != Some(circle_id) {
                    return Err(Error::Protocol(format!(
                        "mls_governance_binding circle effective_scope mismatch ({ERROR_CODE_SCHEMA_VIOLATION})"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn circle_id(&self) -> Option<&CircleId> {
        self.circle_id.as_ref()
    }

    pub fn effective_scope(&self) -> &EffectiveScope {
        &self.effective_scope
    }

    pub fn mls_group_id(&self) -> &str {
        &self.mls_group_id
    }

    pub fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }

    pub fn next_epoch(&self) -> u64 {
        self.next_epoch
    }

    pub fn membership_frontier(&self) -> &[EventId] {
        &self.membership_frontier
    }

    pub fn policy_root(&self) -> &Hash {
        &self.policy_root
    }
}

/// `event-payload.schema.json#/$defs/mls_commit_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsCommitPayload {
    mls_group_id: String,
    base_epoch: u64,
    base_epoch_ref: String,
    proposal_refs: Vec<EventId>,
    next_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_message_ref: Option<String>,
    commit_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

impl MlsCommitPayload {
    pub fn new(
        mls_group_id: impl Into<String>,
        base_epoch: u64,
        base_epoch_ref: impl Into<String>,
        proposal_refs: Vec<EventId>,
        next_epoch: u64,
        commit_digest: Hash,
        governance_binding: MlsGovernanceBindingPayload,
    ) -> Result<Self> {
        let payload = Self {
            mls_group_id: mls_group_id.into(),
            base_epoch,
            base_epoch_ref: base_epoch_ref.into(),
            proposal_refs,
            next_epoch,
            commit_message_ref: None,
            commit_digest,
            governance_binding,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn with_commit_message_ref(
        mut self,
        commit_message_ref: impl Into<String>,
    ) -> Result<Self> {
        self.commit_message_ref = Some(commit_message_ref.into());
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.mls_group_id.trim().is_empty() {
            return Err(Error::Protocol(format!(
                "mls_commit_payload.mls_group_id must be non-empty ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.base_epoch.checked_add(1) != Some(self.next_epoch) {
            return Err(Error::Protocol(format!(
                "mls_commit_payload.next_epoch must equal base_epoch + 1 ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        validate_object_ref("mls_commit_payload.base_epoch_ref", &self.base_epoch_ref)?;
        if let Some(commit_message_ref) = &self.commit_message_ref {
            validate_object_ref("mls_commit_payload.commit_message_ref", commit_message_ref)?;
        }
        let mut seen = BTreeSet::new();
        for proposal_ref in &self.proposal_refs {
            if !seen.insert(proposal_ref.to_string()) {
                return Err(Error::Protocol(format!(
                    "mls_commit_payload.proposal_refs must be unique ({ERROR_CODE_SCHEMA_VIOLATION})"
                )));
            }
        }
        self.governance_binding.validate()?;
        if self.governance_binding.mls_group_id() != self.mls_group_id {
            return Err(Error::Protocol(format!(
                "mls_commit_payload.governance_binding.mls_group_id mismatch ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        if self.governance_binding.previous_epoch() != self.base_epoch
            || self.governance_binding.next_epoch() != self.next_epoch
        {
            return Err(Error::Protocol(format!(
                "mls_commit_payload.governance_binding epoch mismatch ({ERROR_CODE_SCHEMA_VIOLATION})"
            )));
        }
        Ok(())
    }

    pub fn event_kind(&self) -> &'static str {
        MLS_COMMIT
    }

    pub fn mls_group_id(&self) -> &str {
        &self.mls_group_id
    }

    pub fn base_epoch(&self) -> u64 {
        self.base_epoch
    }

    pub fn base_epoch_ref(&self) -> &str {
        &self.base_epoch_ref
    }

    pub fn proposal_refs(&self) -> &[EventId] {
        &self.proposal_refs
    }

    pub fn next_epoch(&self) -> u64 {
        self.next_epoch
    }

    pub fn commit_message_ref(&self) -> Option<&str> {
        self.commit_message_ref.as_deref()
    }

    pub fn commit_digest(&self) -> &Hash {
        &self.commit_digest
    }

    pub fn governance_binding(&self) -> &MlsGovernanceBindingPayload {
        &self.governance_binding
    }
}

fn object_ref_regex() -> &'static Regex {
    static OBJECT_REF: OnceLock<Regex> = OnceLock::new();
    OBJECT_REF.get_or_init(|| {
        Regex::new(
            r"^(ck:(realm|circle|space|actor_profile|flow|message|morph|relation|view|policy|grant|invite|call|agent_session|blob|snapshot|event|franking_proof|report):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|ck:blob:sha256:[0-9a-f]{64}|did:[^\s]+|sha256:[0-9a-f]{64})$",
        )
        .expect("object_ref regex compiles")
    })
}

fn profile_id_regex() -> &'static Regex {
    static PROFILE_ID: OnceLock<Regex> = OnceLock::new();
    PROFILE_ID.get_or_init(|| {
        Regex::new(r"^cx\.profile\.[a-z0-9][a-z0-9_.-]*\.v[0-9]+$")
            .expect("profile id regex compiles")
    })
}

fn validate_object_ref(field: &str, value: &str) -> Result<()> {
    if object_ref_regex().is_match(value) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "{field} must match event-payload.schema.json#/$defs/object_ref ({ERROR_CODE_SCHEMA_VIOLATION})"
        )))
    }
}

fn validate_profile_id(field: &str, value: &str) -> Result<()> {
    if profile_id_regex().is_match(value) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "{field} must match event-payload.schema.json#/$defs/mls_governance_binding.binding_profile ({ERROR_CODE_SCHEMA_VIOLATION})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn event(n: u8) -> EventId {
        EventId::new(format!("ck:event:0196419b-0000-7000-8000-00000000000{n}")).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn mls_commit_payload_matches_registered_event_schema() {
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "ck:mls_group:test",
            0,
            1,
            vec![event(2)],
            hash('2'),
        )
        .unwrap();
        let payload = MlsCommitPayload::new(
            "ck:mls_group:test",
            0,
            event(1).to_string(),
            Vec::new(),
            1,
            hash('7'),
            binding,
        )
        .unwrap();
        let value = serde_json::to_value(&payload).unwrap();

        crate::schema::event_payload_validator_catalog()
            .validate_payload(payload.event_kind(), &value)
            .unwrap();
        assert!(value.get("group_id").is_none());
        assert!(value.get("expected_prev_epoch").is_none());
        assert!(value.get("commit_bytes_b64").is_none());
    }

    #[test]
    fn mls_governance_binding_rejects_extra_fields_on_decode() {
        let err = serde_json::from_value::<MlsGovernanceBindingPayload>(json!({
            "binding_version": 1,
            "encoding_profile": MLS_GOVERNANCE_BINDING_ENCODING_PROFILE,
            "realm_id": realm(),
            "effective_scope": {"kind": "realm", "realm_id": realm()},
            "mls_group_id": "ck:mls_group:test",
            "previous_epoch": 0,
            "next_epoch": 1,
            "membership_frontier": [event(2)],
            "policy_root": hash('2'),
            "unexpected_field": true
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn mls_governance_binding_validates_optional_profile_fields() {
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "ck:mls_group:test",
            0,
            1,
            vec![event(2)],
            hash('2'),
        )
        .unwrap();

        binding.clone().with_binding_profile("ck.profile.mls_governance_binding.full.v1").unwrap();
        assert!(binding.clone().with_binding_profile("mls.full").is_err());
        assert!(binding.with_reducer_profile("").is_err());
    }
}
