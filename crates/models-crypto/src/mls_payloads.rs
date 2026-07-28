//! MLS event payloads from `ak.schema.event_payload.v1`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use arkret_wire::base64url::{base64url_decode, base64url_encode};
use arkret_wire::event_envelope::ScopeRef;
use arkret_wire::{
    CircleId, Did, Error, EventId, EventKind, Hash, MlsGroupId, NonEmptyString, RealmId, Result,
    SealId, SidecarId, canonical,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MLS_GOVERNANCE_BINDING_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_BINDING_ENCODING_PROFILE: &str = "cbor-deterministic-rfc8949-v1";
pub const MLS_GOVERNANCE_BINDING_EXTENSION_TYPE: u16 = 0xF1C0;
pub const MLS_GOVERNANCE_BINDING_EXTENSION_NAME: &str = "mls_governance_binding";
pub const MLS_GOVERNANCE_BINDING_FULL_PROFILE: &str = "ak.profile.mls_governance_binding.full.v1";
pub const MLS_GOVERNANCE_BINDING_RELAXED_PROFILE: &str = "ak.profile.e2ee_relaxed.v1";

/// Sidecar-specific extension of an MLS governance binding.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarMlsBinding {
    pub sidecar_id: SidecarId,
    pub desired_access_digest: Hash,
    pub control_frontier: Vec<NonEmptyString>,
}

impl SidecarMlsBinding {
    pub fn validate(&self) -> Result<()> {
        if self.control_frontier.is_empty() {
            return Err(Error::Protocol(
                "mls_governance_binding.sidecar_binding.control_frontier must be non-empty (schema_violation)"
                    .to_owned(),
            ));
        }
        if self
            .control_frontier
            .windows(2)
            .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
        {
            return Err(Error::Protocol(
                "mls_governance_binding.sidecar_binding.control_frontier must be UTF-8 byte-lexicographically sorted and unique (schema_violation)"
                    .to_owned(),
            ));
        }
        hash_digest_bytes(
            "sidecar_binding.desired_access_digest",
            &self.desired_access_digest,
        )?;
        Ok(())
    }
}

/// `event-payload.schema.json#/$defs/mls_governance_binding`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MlsGovernanceBindingPayload {
    binding_version: u8,
    encoding_profile: String,
    realm_id: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    circle_id: Option<CircleId>,
    effective_scope: ScopeRef,
    mls_group_id: MlsGroupId,
    previous_epoch: u64,
    next_epoch: u64,
    membership_frontier: Vec<EventId>,
    covered_seal_refs: Vec<SealId>,
    policy_root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discussion_metadata_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sidecar_binding: Option<SidecarMlsBinding>,
    binding_profile: String,
    reducer_profile: String,
}

impl MlsGovernanceBindingPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn realm(
        realm_id: RealmId,
        mls_group_id: impl Into<String>,
        previous_epoch: u64,
        next_epoch: u64,
        membership_frontier: Vec<EventId>,
        covered_seal_refs: Vec<SealId>,
        policy_root: Hash,
        capability_root: Hash,
        discussion_metadata_digest: Hash,
        binding_profile: impl Into<String>,
        reducer_profile: impl Into<String>,
    ) -> Result<Self> {
        let payload = Self {
            binding_version: MLS_GOVERNANCE_BINDING_VERSION,
            encoding_profile: MLS_GOVERNANCE_BINDING_ENCODING_PROFILE.to_owned(),
            realm_id: realm_id.clone(),
            circle_id: None,
            effective_scope: ScopeRef::Realm { realm_id },
            mls_group_id: MlsGroupId::new(mls_group_id.into()).map_err(|err| {
                Error::Protocol(format!(
                    "mls_governance_binding.mls_group_id is invalid: {err} (schema_violation)"
                ))
            })?,
            previous_epoch,
            next_epoch,
            membership_frontier,
            covered_seal_refs,
            policy_root,
            capability_root: Some(capability_root),
            discussion_metadata_digest: Some(discussion_metadata_digest),
            sidecar_binding: None,
            binding_profile: binding_profile.into(),
            reducer_profile: reducer_profile.into(),
        };
        payload.validate()?;
        Ok(payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn circle(
        realm_id: RealmId,
        circle_id: CircleId,
        mls_group_id: impl Into<String>,
        previous_epoch: u64,
        next_epoch: u64,
        membership_frontier: Vec<EventId>,
        covered_seal_refs: Vec<SealId>,
        policy_root: Hash,
        capability_root: Hash,
        discussion_metadata_digest: Hash,
        binding_profile: impl Into<String>,
        reducer_profile: impl Into<String>,
    ) -> Result<Self> {
        let payload = Self {
            binding_version: MLS_GOVERNANCE_BINDING_VERSION,
            encoding_profile: MLS_GOVERNANCE_BINDING_ENCODING_PROFILE.to_owned(),
            realm_id: realm_id.clone(),
            circle_id: Some(circle_id.clone()),
            effective_scope: ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            mls_group_id: MlsGroupId::new(mls_group_id.into()).map_err(|err| {
                Error::Protocol(format!(
                    "mls_governance_binding.mls_group_id is invalid: {err} (schema_violation)"
                ))
            })?,
            previous_epoch,
            next_epoch,
            membership_frontier,
            covered_seal_refs,
            policy_root,
            capability_root: Some(capability_root),
            discussion_metadata_digest: Some(discussion_metadata_digest),
            sidecar_binding: None,
            binding_profile: binding_profile.into(),
            reducer_profile: reducer_profile.into(),
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

    pub fn with_sidecar_binding(mut self, binding: SidecarMlsBinding) -> Result<Self> {
        self.sidecar_binding = Some(binding);
        self.validate()?;
        Ok(self)
    }

    pub fn without_sidecar_binding(mut self) -> Self {
        self.sidecar_binding = None;
        self
    }

    pub fn with_binding_profile(mut self, profile: impl Into<String>) -> Result<Self> {
        self.binding_profile = profile.into();
        self.validate()?;
        Ok(self)
    }

    pub fn with_reducer_profile(mut self, profile: impl Into<String>) -> Result<Self> {
        self.reducer_profile = profile.into();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.binding_version != MLS_GOVERNANCE_BINDING_VERSION {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.binding_version must be {MLS_GOVERNANCE_BINDING_VERSION} (schema_violation)"
            )));
        }
        if self.encoding_profile != MLS_GOVERNANCE_BINDING_ENCODING_PROFILE {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.encoding_profile must be {MLS_GOVERNANCE_BINDING_ENCODING_PROFILE} (schema_violation)"
            )));
        }
        if self.membership_frontier.is_empty() {
            return Err(Error::Protocol(
                "mls_governance_binding.membership_frontier must be non-empty (schema_violation)"
                    .to_owned(),
            ));
        }
        if self.covered_seal_refs.is_empty() {
            return Err(Error::Protocol(
                "mls_governance_binding.covered_seal_refs must be non-empty (schema_violation)"
                    .to_owned(),
            ));
        }
        // `uniqueItems` only: the reducer sorts by canonical value before it
        // numbers the `or_set_batch_add` tags, so producers MUST NOT be
        // required to pre-sort the array.
        let mut seen = BTreeSet::new();
        for seal_ref in &self.covered_seal_refs {
            if !seen.insert(seal_ref.as_str()) {
                return Err(Error::Protocol(
                    "mls_governance_binding.covered_seal_refs must be unique (schema_violation)"
                        .to_owned(),
                ));
            }
        }
        validate_profile_id(
            "mls_governance_binding.binding_profile",
            &self.binding_profile,
        )?;
        if self.binding_profile == MLS_GOVERNANCE_BINDING_FULL_PROFILE {
            if self.capability_root.is_none() {
                return Err(Error::Protocol(
                    "full mls_governance_binding requires capability_root (schema_violation)"
                        .to_owned(),
                ));
            }
            if self.discussion_metadata_digest.is_none() {
                return Err(Error::Protocol("full mls_governance_binding requires discussion_metadata_digest (schema_violation)".to_owned()));
            }
        }
        if self.reducer_profile.is_empty() {
            return Err(Error::Protocol(
                "mls_governance_binding.reducer_profile must be non-empty (schema_violation)"
                    .to_owned(),
            ));
        }
        match &self.effective_scope {
            ScopeRef::Realm { realm_id } => {
                if realm_id != &self.realm_id
                    || self.circle_id.is_some()
                    || self.sidecar_binding.is_some()
                {
                    return Err(Error::Protocol(
                        "mls_governance_binding realm effective_scope mismatch (schema_violation)"
                            .to_owned(),
                    ));
                }
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                if realm_id != &self.realm_id || self.circle_id.as_ref() != Some(circle_id) {
                    return Err(Error::Protocol(
                        "mls_governance_binding circle effective_scope mismatch (schema_violation)"
                            .to_owned(),
                    ));
                }
                if let Some(binding) = &self.sidecar_binding {
                    binding.validate()?;
                }
            }
            // Fail closed on scope kinds this crate does not know about.
            _ => {
                return Err(Error::Protocol(
                    "mls_governance_binding effective_scope kind is unsupported (schema_violation)"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        expected: &MlsGovernanceBindingValidationContext<'_>,
    ) -> Result<()> {
        self.validate()?;
        if self.mls_group_id.as_str() != expected.mls_group_id {
            return Err(Error::Protocol("mls_governance_binding.mls_group_id does not match expected commit group (state_mismatch)".to_owned()));
        }
        if self.previous_epoch != expected.previous_epoch || self.next_epoch != expected.next_epoch
        {
            return Err(Error::Protocol("mls_governance_binding epoch does not match expected commit epoch (state_mismatch)".to_owned()));
        }
        if self.binding_profile != expected.binding_profile {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.binding_profile mismatch: expected {} got {} (profile_unsupported)",
                expected.binding_profile, self.binding_profile
            )));
        }
        if self.reducer_profile != expected.reducer_profile {
            return Err(Error::Protocol(format!(
                "mls_governance_binding.reducer_profile mismatch: expected {} got {} (reducer_profile_mismatch)",
                expected.reducer_profile, self.reducer_profile
            )));
        }
        if let Some(scope) = expected.effective_scope
            && &self.effective_scope != scope
        {
            return Err(Error::Protocol(
                "mls_governance_binding.effective_scope mismatch (state_mismatch)".to_owned(),
            ));
        }
        if let Some(frontier) = expected.membership_frontier
            && self.membership_frontier.as_slice() != frontier
        {
            return Err(Error::Protocol("mls_governance_binding.membership_frontier is stale (mls_governance_binding_stale)".to_owned()));
        }
        if let Some(policy_root) = expected.policy_root
            && &self.policy_root != policy_root
        {
            return Err(Error::Protocol(
                "mls_governance_binding.policy_root is stale (mls_governance_binding_stale)"
                    .to_owned(),
            ));
        }
        if let Some(capability_root) = expected.capability_root
            && self.capability_root.as_ref() != Some(capability_root)
        {
            return Err(Error::Protocol(
                "mls_governance_binding.capability_root is stale (mls_governance_binding_stale)"
                    .to_owned(),
            ));
        }
        if let Some(digest) = expected.discussion_metadata_digest
            && self.discussion_metadata_digest.as_ref() != Some(digest)
        {
            return Err(Error::Protocol("mls_governance_binding.discussion_metadata_digest is stale (mls_governance_binding_stale)".to_owned()));
        }
        if let Some(sidecar_binding) = expected.sidecar_binding
            && self.sidecar_binding.as_ref() != Some(sidecar_binding)
        {
            return Err(Error::Protocol(
                "mls_governance_binding.sidecar_binding is stale (mls_governance_binding_stale)"
                    .to_owned(),
            ));
        }
        if expected.forbid_sidecar_binding && self.sidecar_binding.is_some() {
            return Err(Error::Protocol(
                "mls_governance_binding.sidecar_binding is forbidden for this scope (state_mismatch)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        cbor_put_map_len(&mut out, self.cbor_field_count());
        cbor_put_tstr(&mut out, "binding_profile");
        cbor_put_tstr(&mut out, &self.binding_profile);
        cbor_put_tstr(&mut out, "binding_version");
        cbor_put_uint(&mut out, u64::from(self.binding_version));
        if let Some(capability_root) = &self.capability_root {
            cbor_put_tstr(&mut out, "capability_root");
            cbor_put_bstr(
                &mut out,
                &hash_digest_bytes("capability_root", capability_root)?,
            );
        }
        if let Some(circle_id) = &self.circle_id {
            cbor_put_tstr(&mut out, "circle_id");
            cbor_put_tstr(&mut out, circle_id.as_str());
        }
        cbor_put_tstr(&mut out, "covered_seal_refs");
        cbor_put_array_len(&mut out, self.covered_seal_refs.len() as u64);
        for seal_ref in &self.covered_seal_refs {
            cbor_put_bstr(&mut out, seal_ref.as_str().as_bytes());
        }
        if let Some(digest) = &self.discussion_metadata_digest {
            cbor_put_tstr(&mut out, "discussion_metadata_digest");
            cbor_put_bstr(
                &mut out,
                &hash_digest_bytes("discussion_metadata_digest", digest)?,
            );
        }
        cbor_put_tstr(&mut out, "effective_scope");
        encode_effective_scope(&mut out, &self.effective_scope)?;
        cbor_put_tstr(&mut out, "encoding_profile");
        cbor_put_tstr(&mut out, &self.encoding_profile);
        cbor_put_tstr(&mut out, "membership_frontier");
        cbor_put_array_len(&mut out, self.membership_frontier.len() as u64);
        for event_id in &self.membership_frontier {
            cbor_put_bstr(&mut out, event_id.as_str().as_bytes());
        }
        cbor_put_tstr(&mut out, "mls_group_id");
        cbor_put_bstr(&mut out, &base64url_decode(self.mls_group_id.as_str()).map_err(|err| {
            Error::Protocol(format!(
                "mls_governance_binding.mls_group_id must be base64url for CBOR bstr encoding: {err} (schema_violation)"
            ))
        })?);
        cbor_put_tstr(&mut out, "next_epoch");
        cbor_put_uint(&mut out, self.next_epoch);
        cbor_put_tstr(&mut out, "policy_root");
        cbor_put_bstr(
            &mut out,
            &hash_digest_bytes("policy_root", &self.policy_root)?,
        );
        cbor_put_tstr(&mut out, "previous_epoch");
        cbor_put_uint(&mut out, self.previous_epoch);
        cbor_put_tstr(&mut out, "realm_id");
        cbor_put_tstr(&mut out, self.realm_id.as_str());
        cbor_put_tstr(&mut out, "reducer_profile");
        cbor_put_tstr(&mut out, &self.reducer_profile);
        if let Some(binding) = &self.sidecar_binding {
            cbor_put_tstr(&mut out, "sidecar_binding");
            encode_sidecar_binding(&mut out, binding)?;
        }
        Ok(out)
    }

    pub fn from_deterministic_cbor(bytes: &[u8]) -> Result<Self> {
        let mut reader = CborReader::new(bytes);
        let fields = reader.read_map()?;
        reader.finish()?;
        let payload = Self::from_cbor_fields(fields)?;
        let canonical = payload.to_deterministic_cbor()?;
        if canonical != bytes {
            return Err(Error::Protocol("mls_governance_binding CBOR is not deterministic canonical encoding (schema_violation)".to_owned()));
        }
        Ok(payload)
    }

    pub fn to_group_context_extension(&self) -> Result<MlsGovernanceBindingExtension> {
        Ok(MlsGovernanceBindingExtension {
            extension_type: MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
            extension_data: self.to_deterministic_cbor()?,
        })
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn circle_id(&self) -> Option<&CircleId> {
        self.circle_id.as_ref()
    }

    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }

    pub fn mls_group_id(&self) -> &str {
        self.mls_group_id.as_str()
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

    pub fn covered_seal_refs(&self) -> &[SealId] {
        &self.covered_seal_refs
    }

    pub fn policy_root(&self) -> &Hash {
        &self.policy_root
    }

    pub fn capability_root(&self) -> Option<&Hash> {
        self.capability_root.as_ref()
    }

    pub fn discussion_metadata_digest(&self) -> Option<&Hash> {
        self.discussion_metadata_digest.as_ref()
    }

    pub fn sidecar_binding(&self) -> Option<&SidecarMlsBinding> {
        self.sidecar_binding.as_ref()
    }

    pub fn binding_profile(&self) -> &str {
        &self.binding_profile
    }

    pub fn reducer_profile(&self) -> &str {
        &self.reducer_profile
    }

    fn cbor_field_count(&self) -> u64 {
        12 + self.capability_root.is_some() as u64
            + self.circle_id.is_some() as u64
            + self.discussion_metadata_digest.is_some() as u64
            + self.sidecar_binding.is_some() as u64
    }

    fn from_cbor_fields(mut fields: BTreeMap<String, CborValue>) -> Result<Self> {
        let binding_profile = take_tstr(&mut fields, "binding_profile")?;
        let binding_version = take_uint(&mut fields, "binding_version")?;
        if binding_version > u64::from(u8::MAX) {
            return Err(cbor_error("binding_version is out of range"));
        }
        let capability_root = take_optional_hash(&mut fields, "capability_root")?;
        let circle_id = take_optional_tstr(&mut fields, "circle_id")?
            .map(CircleId::new)
            .transpose()
            .map_err(|err| cbor_error_message(format!("circle_id is invalid: {err}")))?;
        let covered_seal_refs = take_bstr_array(&mut fields, "covered_seal_refs")?
            .into_iter()
            .map(|bytes| {
                std::str::from_utf8(&bytes)
                    .map_err(|err| {
                        cbor_error_message(format!("covered_seal_refs is not UTF-8: {err}"))
                    })
                    .and_then(|value| {
                        SealId::new(value.to_owned()).map_err(|err| {
                            cbor_error_message(format!("covered_seal_refs item is invalid: {err}"))
                        })
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let discussion_metadata_digest =
            take_optional_hash(&mut fields, "discussion_metadata_digest")?;
        let effective_scope = take_effective_scope(&mut fields)?;
        let encoding_profile = take_tstr(&mut fields, "encoding_profile")?;
        let membership_frontier = take_bstr_array(&mut fields, "membership_frontier")?
            .into_iter()
            .map(|bytes| {
                std::str::from_utf8(&bytes)
                    .map_err(|err| {
                        cbor_error_message(format!("membership_frontier is not UTF-8: {err}"))
                    })
                    .and_then(|value| {
                        EventId::new(value.to_owned()).map_err(|err| {
                            cbor_error_message(format!(
                                "membership_frontier item is invalid: {err}"
                            ))
                        })
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let mls_group_id =
            MlsGroupId::new(base64url_encode(&take_bstr(&mut fields, "mls_group_id")?))
                .map_err(|err| cbor_error_message(format!("mls_group_id is invalid: {err}")))?;
        let next_epoch = take_uint(&mut fields, "next_epoch")?;
        let policy_root = take_hash(&mut fields, "policy_root")?;
        let previous_epoch = take_uint(&mut fields, "previous_epoch")?;
        let realm_id = RealmId::new(take_tstr(&mut fields, "realm_id")?)
            .map_err(|err| cbor_error_message(format!("realm_id is invalid: {err}")))?;
        let reducer_profile = take_tstr(&mut fields, "reducer_profile")?;
        let sidecar_binding = take_optional_sidecar_binding(&mut fields)?;
        if let Some(extra) = fields.keys().next() {
            return Err(cbor_error_message(format!(
                "unexpected mls_governance_binding CBOR key `{extra}`"
            )));
        }
        let payload = Self {
            binding_version: binding_version as u8,
            encoding_profile,
            realm_id,
            circle_id,
            effective_scope,
            mls_group_id,
            previous_epoch,
            next_epoch,
            membership_frontier,
            covered_seal_refs,
            policy_root,
            capability_root,
            discussion_metadata_digest,
            sidecar_binding,
            binding_profile,
            reducer_profile,
        };
        payload.validate()?;
        Ok(payload)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsGovernanceBindingPayloadWire {
    binding_version: u8,
    encoding_profile: String,
    realm_id: RealmId,
    #[serde(default)]
    circle_id: Option<CircleId>,
    effective_scope: ScopeRef,
    mls_group_id: MlsGroupId,
    previous_epoch: u64,
    next_epoch: u64,
    membership_frontier: Vec<EventId>,
    covered_seal_refs: Vec<SealId>,
    policy_root: Hash,
    #[serde(default)]
    capability_root: Option<Hash>,
    #[serde(default)]
    discussion_metadata_digest: Option<Hash>,
    #[serde(default)]
    sidecar_binding: Option<SidecarMlsBinding>,
    binding_profile: String,
    reducer_profile: String,
}

impl TryFrom<MlsGovernanceBindingPayloadWire> for MlsGovernanceBindingPayload {
    type Error = Error;

    fn try_from(wire: MlsGovernanceBindingPayloadWire) -> Result<Self> {
        let payload = Self {
            binding_version: wire.binding_version,
            encoding_profile: wire.encoding_profile,
            realm_id: wire.realm_id,
            circle_id: wire.circle_id,
            effective_scope: wire.effective_scope,
            mls_group_id: wire.mls_group_id,
            previous_epoch: wire.previous_epoch,
            next_epoch: wire.next_epoch,
            membership_frontier: wire.membership_frontier,
            covered_seal_refs: wire.covered_seal_refs,
            policy_root: wire.policy_root,
            capability_root: wire.capability_root,
            discussion_metadata_digest: wire.discussion_metadata_digest,
            sidecar_binding: wire.sidecar_binding,
            binding_profile: wire.binding_profile,
            reducer_profile: wire.reducer_profile,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl<'de> Deserialize<'de> for MlsGovernanceBindingPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsGovernanceBindingPayloadWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsGovernanceBindingExtension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

impl MlsGovernanceBindingExtension {
    pub fn decode_payload(&self) -> Result<MlsGovernanceBindingPayload> {
        decode_mls_governance_binding_extension(self.extension_type, &self.extension_data)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MlsGovernanceBindingValidationContext<'a> {
    pub mls_group_id: &'a str,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub binding_profile: &'a str,
    pub reducer_profile: &'a str,
    pub effective_scope: Option<&'a ScopeRef>,
    pub membership_frontier: Option<&'a [EventId]>,
    pub policy_root: Option<&'a Hash>,
    pub capability_root: Option<&'a Hash>,
    pub discussion_metadata_digest: Option<&'a Hash>,
    pub sidecar_binding: Option<&'a SidecarMlsBinding>,
    pub forbid_sidecar_binding: bool,
}

impl<'a> MlsGovernanceBindingValidationContext<'a> {
    pub fn for_commit(
        mls_group_id: &'a str,
        previous_epoch: u64,
        next_epoch: u64,
        binding_profile: &'a str,
        reducer_profile: &'a str,
    ) -> Self {
        Self {
            mls_group_id,
            previous_epoch,
            next_epoch,
            binding_profile,
            reducer_profile,
            effective_scope: None,
            membership_frontier: None,
            policy_root: None,
            capability_root: None,
            discussion_metadata_digest: None,
            sidecar_binding: None,
            forbid_sidecar_binding: false,
        }
    }

    pub fn with_sidecar_binding(mut self, binding: &'a SidecarMlsBinding) -> Self {
        self.sidecar_binding = Some(binding);
        self.forbid_sidecar_binding = false;
        self
    }

    pub fn without_sidecar_binding(mut self) -> Self {
        self.sidecar_binding = None;
        self.forbid_sidecar_binding = true;
        self
    }
}

pub fn decode_mls_governance_binding_extension(
    extension_type: u16,
    extension_data: &[u8],
) -> Result<MlsGovernanceBindingPayload> {
    if extension_type != MLS_GOVERNANCE_BINDING_EXTENSION_TYPE {
        return Err(Error::Protocol(format!(
            "expected {MLS_GOVERNANCE_BINDING_EXTENSION_NAME} GroupContext extension codepoint 0x{MLS_GOVERNANCE_BINDING_EXTENSION_TYPE:04X}, got 0x{extension_type:04X} (profile_unsupported)"
        )));
    }
    MlsGovernanceBindingPayload::from_deterministic_cbor(extension_data)
}

pub fn verify_mls_governance_binding_extension(
    extension: Option<&MlsGovernanceBindingExtension>,
    expected: &MlsGovernanceBindingValidationContext<'_>,
) -> Result<MlsGovernanceBindingPayload> {
    let extension = extension.ok_or_else(|| {
        Error::Protocol(format!(
            "missing {MLS_GOVERNANCE_BINDING_EXTENSION_NAME} GroupContext extension 0x{MLS_GOVERNANCE_BINDING_EXTENSION_TYPE:04X} (profile_unsupported)"
        ))
    })?;
    let payload = extension.decode_payload()?;
    payload.validate_against(expected)?;
    Ok(payload)
}

/// `event-payload.schema.json#/$defs/mls_commit_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MlsCommitPayload {
    mls_group_id: MlsGroupId,
    base_epoch: u64,
    base_epoch_ref: String,
    proposal_refs: Vec<EventId>,
    next_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_message_ref: Option<String>,
    commit_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsCommitPayloadWire {
    mls_group_id: MlsGroupId,
    base_epoch: u64,
    base_epoch_ref: String,
    proposal_refs: Vec<EventId>,
    next_epoch: u64,
    #[serde(default)]
    commit_message_ref: Option<String>,
    commit_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

impl<'de> Deserialize<'de> for MlsCommitPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsCommitPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            mls_group_id: wire.mls_group_id,
            base_epoch: wire.base_epoch,
            base_epoch_ref: wire.base_epoch_ref,
            proposal_refs: wire.proposal_refs,
            next_epoch: wire.next_epoch,
            commit_message_ref: wire.commit_message_ref,
            commit_digest: wire.commit_digest,
            governance_binding: wire.governance_binding,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
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
            mls_group_id: MlsGroupId::new(mls_group_id.into()).map_err(|err| {
                Error::Protocol(format!(
                    "mls_commit_payload.mls_group_id is invalid: {err} (schema_violation)"
                ))
            })?,
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
        if self.base_epoch.checked_add(1) != Some(self.next_epoch) {
            return Err(Error::Protocol(
                "mls_commit_payload.next_epoch must equal base_epoch + 1 (schema_violation)"
                    .to_owned(),
            ));
        }
        validate_object_ref("mls_commit_payload.base_epoch_ref", &self.base_epoch_ref)?;
        if let Some(commit_message_ref) = &self.commit_message_ref {
            validate_object_ref("mls_commit_payload.commit_message_ref", commit_message_ref)?;
        }
        let mut seen = BTreeSet::new();
        for proposal_ref in &self.proposal_refs {
            if !seen.insert(proposal_ref.to_string()) {
                return Err(Error::Protocol(
                    "mls_commit_payload.proposal_refs must be unique (schema_violation)".to_owned(),
                ));
            }
        }
        self.governance_binding.validate()?;
        if self.governance_binding.mls_group_id() != self.mls_group_id.as_str() {
            return Err(Error::Protocol(
                "mls_commit_payload.governance_binding.mls_group_id mismatch (schema_violation)"
                    .to_owned(),
            ));
        }
        if self.governance_binding.previous_epoch() != self.base_epoch
            || self.governance_binding.next_epoch() != self.next_epoch
        {
            return Err(Error::Protocol(
                "mls_commit_payload.governance_binding epoch mismatch (schema_violation)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn event_kind(&self) -> &'static str {
        EventKind::MLS_COMMIT
    }

    pub fn mls_group_id(&self) -> &str {
        self.mls_group_id.as_str()
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

/// SEC-03 — one service entry whose `data_classes[]` contains
/// `media_plaintext`, covered by the
/// governance-binding `discussion_metadata_digest`.
///
/// Carries the SFU / MCU service DID that media-service-binding.md §8.2 rule 2
/// requires to be listed in `plaintext_visible_services[]`. Only the fields a
/// member can independently recompute from the MLS transcript are bound into
/// the digest; transport-only metadata MUST NOT leak in here.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlaintextService {
    /// Service DID authorised to decrypt media (`data_classes=media_plaintext`).
    pub service_id: Did,
}

/// SEC-03 — the member-visible policy cell value covered by the governance
/// binding `discussion_metadata_digest`, per
/// `crypto-media/media-service-binding.md` §8.2 rules 1–3 and
/// `crypto-media/encryption-and-audit.md` §2.5 / §2.5.3.
///
/// `media_service_decrypts=true` is **not** an SFU-self-reported toggle: the
/// fact MUST be derivable from the MLS transcript so any member can recompute
/// it without trusting client UI. This struct is the canonical input to
/// [`derive_media_decrypt_metadata_digest`]; it mirrors the policy cell value
/// that §10.5.1 rules 1–3 already place under `policy_root` coverage.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaDecryptPolicyValue {
    /// `ak.realm.policy_bundle.media_service_decrypts` (§10.5.1 rule 1).
    pub media_service_decrypts: bool,
    /// `plaintext_visible_services[]` whose `data_classes[]` contains
    /// `media_plaintext`
    /// (§10.5.1 rule 2). Order is normalised before hashing so two members
    /// holding the same set derive an identical digest.
    pub plaintext_visible_services: Vec<MediaPlaintextService>,
}

impl MediaDecryptPolicyValue {
    /// Canonical (deterministic) value used for digest derivation: the
    /// `plaintext_visible_services` are sorted by DID so set-equal inputs
    /// hash identically regardless of source ordering.
    fn canonical_value(&self) -> Value {
        let mut services: Vec<String> = self
            .plaintext_visible_services
            .iter()
            .map(|s| s.service_id.to_string())
            .collect();
        services.sort_unstable();
        services.dedup();
        json!({
            "media_service_decrypts": self.media_service_decrypts,
            "plaintext_visible_services": services,
        })
    }
}

/// SEC-03: deterministically derive the governance-binding
/// `discussion_metadata_digest` from the section 10.5.1 rule 1-3 policy cell value.
///
/// The digest is `sha256(canonical_json(value))` using the same canonical /
/// hash primitives as every other Arkret digest:
/// [`canonical::canonical_json_bytes`] and [`canonical::sha256_digest`].
/// The result is byte-identical across every member and service. The fact
/// `media_service_decrypts=true` is bound into the member-visible metadata covered
/// by the MLS governance binding, satisfying `media-service-binding.md` section 8.2
/// rule 5.
///
/// The returned [`Hash`] is wire-form (`sha256:<hex>`) and can be passed
/// straight to [`MlsGovernanceBindingPayload::with_discussion_metadata_digest`].
pub fn derive_media_decrypt_metadata_digest(value: &MediaDecryptPolicyValue) -> Result<Hash> {
    let canonical_bytes = canonical::canonical_json_bytes(&value.canonical_value())?;
    Ok(Hash::new(canonical::sha256_digest(canonical_bytes))?)
}

/// SEC-03: member-side recomputation check for the media-decrypt fact.
///
/// `binding_covered_digest` is the `discussion_metadata_digest` carried by the
/// accepted governance binding for the current epoch; `recomputed` is the
/// member's local [`derive_media_decrypt_metadata_digest`] over its own view
/// of the section 10.5.1 rule 1-3 policy cell value. A mismatch means the member's
/// local policy view disagrees with what the binding attests, so per
/// §10.5.1 rule 5 the member MUST treat the binding as stale and refuse media
/// negotiation. The mismatch returns [`Error::Protocol`] tagged with
/// [`arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE`].
pub fn verify_media_decrypt_metadata(
    binding_covered_digest: &Hash,
    recomputed: &Hash,
) -> Result<()> {
    if binding_covered_digest == recomputed {
        Ok(())
    } else {
        Err(Error::Protocol(
            "media_service_decrypts metadata digest does not match governance binding; \
             refusing media negotiation (mls_governance_binding_stale)"
                .to_owned(),
        ))
    }
}

fn object_ref_regex() -> &'static Regex {
    static OBJECT_REF: OnceLock<Regex> = OnceLock::new();
    OBJECT_REF.get_or_init(|| {
        Regex::new(
            r"^(ak:(realm|circle|space|actor_profile|strand|message|morph|relation|view|policy|grant|invite|call|blob|snapshot|event|franking_proof|report):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|ak:blob:sha256:[0-9a-f]{64}|did:[^\s]+|sha256:[0-9a-f]{64})$",
        )
        .expect("object_ref regex compiles")
    })
}

fn profile_id_regex() -> &'static Regex {
    static PROFILE_ID: OnceLock<Regex> = OnceLock::new();
    PROFILE_ID.get_or_init(|| {
        Regex::new(r"^ak\.profile\.[a-z0-9][a-z0-9_.-]*\.v[0-9]+$")
            .expect("profile id regex compiles")
    })
}

fn validate_object_ref(field: &str, value: &str) -> Result<()> {
    if object_ref_regex().is_match(value) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "{field} must match event-payload.schema.json#/$defs/object_ref (schema_violation)"
        )))
    }
}

fn validate_profile_id(field: &str, value: &str) -> Result<()> {
    if profile_id_regex().is_match(value) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "{field} must match event-payload.schema.json#/$defs/mls_governance_binding.binding_profile (schema_violation)"
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CborValue {
    UInt(u64),
    Bstr(Vec<u8>),
    Tstr(String),
    Array(Vec<CborValue>),
    Map(BTreeMap<String, CborValue>),
}

/// Maximum CBOR container nesting depth accepted from the wire
/// (`scalability-constraints.md` §2: objects and arrays combined, inclusive
/// cap shared with canonical JSON). The governance-binding payload is at most
/// a few levels deep; the cap keeps a hand-rolled `0x81` nesting chain from
/// turning recursion depth into a stack-overflow abort.
const MAX_CBOR_NESTING_DEPTH: usize = 64;

/// Maximum number of items a single definite-length CBOR array or map may
/// declare or carry (`scalability-constraints.md` §2;
/// `ak.vector.encoding.reject_cbor_array_bounds.v1`). Checked before any
/// storage is sized from the declared count.
const MAX_CBOR_CONTAINER_ITEMS: usize = 65_536;

struct CborReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(cbor_error("trailing bytes after CBOR object"))
        }
    }

    fn read_map(&mut self) -> Result<BTreeMap<String, CborValue>> {
        match self.read_value(0)? {
            CborValue::Map(map) => Ok(map),
            _ => Err(cbor_error("expected top-level CBOR map")),
        }
    }

    fn read_value(&mut self, depth: usize) -> Result<CborValue> {
        if depth > MAX_CBOR_NESTING_DEPTH {
            return Err(cbor_error(
                "mls_governance_binding CBOR nesting exceeds maximum depth",
            ));
        }
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CborValue::UInt(self.read_len(additional)?)),
            2 => {
                let len = self.read_container_len(additional)?;
                Ok(CborValue::Bstr(self.read_bytes(len)?.to_vec()))
            }
            3 => {
                let len = self.read_container_len(additional)?;
                let bytes = self.read_bytes(len)?;
                let value = std::str::from_utf8(bytes).map_err(|err| {
                    cbor_error_message(format!("invalid CBOR text string: {err}"))
                })?;
                Ok(CborValue::Tstr(value.to_owned()))
            }
            4 => {
                let len = self.read_container_len(additional)?;
                if len > MAX_CBOR_CONTAINER_ITEMS {
                    return Err(cbor_error(
                        "CBOR array exceeds the v1 maximum of 65536 items",
                    ));
                }
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    values.push(self.read_value(depth + 1)?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let len = self.read_container_len(additional)?;
                if len > MAX_CBOR_CONTAINER_ITEMS {
                    return Err(cbor_error("CBOR map exceeds the v1 maximum of 65536 items"));
                }
                let mut map = BTreeMap::new();
                for _ in 0..len {
                    let CborValue::Tstr(key) = self.read_value(depth + 1)? else {
                        return Err(cbor_error(
                            "mls_governance_binding CBOR map key is not tstr",
                        ));
                    };
                    let value = self.read_value(depth + 1)?;
                    if map.insert(key.clone(), value).is_some() {
                        return Err(cbor_error_message(format!(
                            "duplicate mls_governance_binding CBOR key `{key}`"
                        )));
                    }
                }
                Ok(CborValue::Map(map))
            }
            _ => Err(cbor_error(
                "unsupported CBOR type in mls_governance_binding",
            )),
        }
    }

    /// Read a length header for a sized item (bstr / tstr payload bytes,
    /// array / map element counts) and clamp it to the remaining input.
    /// Every payload byte or container element consumes at least one input
    /// byte, so a header larger than the remaining input is unsatisfiable —
    /// reject it *before* any allocation is sized from the untrusted header
    /// (capacity-bomb guard: `0x9b FF..FF` must not reach
    /// `Vec::with_capacity`).
    fn read_container_len(&mut self, additional: u8) -> Result<usize> {
        let len = self.read_len(additional)?;
        let remaining = (self.bytes.len() - self.pos) as u64;
        if len > remaining {
            return Err(cbor_error(
                "CBOR length header exceeds remaining input bytes",
            ));
        }
        Ok(len as usize)
    }

    fn read_len(&mut self, additional: u8) -> Result<u64> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.read_u8()?)),
            25 => {
                let bytes = self.read_fixed::<2>()?;
                Ok(u64::from(u16::from_be_bytes(bytes)))
            }
            26 => {
                let bytes = self.read_fixed::<4>()?;
                Ok(u64::from(u32::from_be_bytes(bytes)))
            }
            27 => Ok(u64::from_be_bytes(self.read_fixed::<8>()?)),
            _ => Err(cbor_error("indefinite-length CBOR is not allowed")),
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let Some(value) = self.bytes.get(self.pos) else {
            return Err(cbor_error("unexpected end of CBOR input"));
        };
        self.pos += 1;
        Ok(*value)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| cbor_error("CBOR length overflow"))?;
        if end > self.bytes.len() {
            return Err(cbor_error("CBOR item length exceeds input"));
        }
        let bytes = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

fn cbor_put_uint(out: &mut Vec<u8>, value: u64) {
    cbor_put_type_len(out, 0, value);
}

fn cbor_put_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_put_type_len(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_put_tstr(out: &mut Vec<u8>, value: &str) {
    cbor_put_type_len(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn cbor_put_array_len(out: &mut Vec<u8>, len: u64) {
    cbor_put_type_len(out, 4, len);
}

fn cbor_put_map_len(out: &mut Vec<u8>, len: u64) {
    cbor_put_type_len(out, 5, len);
}

fn cbor_put_type_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let head = major << 5;
    if value < 24 {
        out.push(head | value as u8);
    } else if value <= u64::from(u8::MAX) {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(head | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(head | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_effective_scope(out: &mut Vec<u8>, scope: &ScopeRef) -> Result<()> {
    match scope {
        ScopeRef::Realm { realm_id } => {
            cbor_put_map_len(out, 2);
            cbor_put_tstr(out, "kind");
            cbor_put_tstr(out, "realm");
            cbor_put_tstr(out, "realm_id");
            cbor_put_tstr(out, realm_id.as_str());
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            cbor_put_map_len(out, 3);
            cbor_put_tstr(out, "circle_id");
            cbor_put_tstr(out, circle_id.as_str());
            cbor_put_tstr(out, "kind");
            cbor_put_tstr(out, "circle");
            cbor_put_tstr(out, "realm_id");
            cbor_put_tstr(out, realm_id.as_str());
        }
        // Fail closed on scope kinds this crate does not know about.
        _ => {
            return Err(Error::Protocol(
                "mls_governance_binding effective_scope kind is unsupported (schema_violation)"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn encode_sidecar_binding(out: &mut Vec<u8>, binding: &SidecarMlsBinding) -> Result<()> {
    binding.validate()?;
    cbor_put_map_len(out, 3);
    cbor_put_tstr(out, "control_frontier");
    cbor_put_array_len(out, binding.control_frontier.len() as u64);
    for control_ref in &binding.control_frontier {
        cbor_put_tstr(out, control_ref.as_str());
    }
    cbor_put_tstr(out, "desired_access_digest");
    cbor_put_bstr(
        out,
        &hash_digest_bytes(
            "sidecar_binding.desired_access_digest",
            &binding.desired_access_digest,
        )?,
    );
    cbor_put_tstr(out, "sidecar_id");
    cbor_put_tstr(out, binding.sidecar_id.as_str());
    Ok(())
}

fn take_tstr(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<String> {
    match fields.remove(key) {
        Some(CborValue::Tstr(value)) => Ok(value),
        Some(_) => Err(cbor_error_message(format!("CBOR key `{key}` must be tstr"))),
        None => Err(cbor_error_message(format!("missing CBOR key `{key}`"))),
    }
}

fn take_optional_tstr(
    fields: &mut BTreeMap<String, CborValue>,
    key: &str,
) -> Result<Option<String>> {
    match fields.remove(key) {
        Some(CborValue::Tstr(value)) => Ok(Some(value)),
        Some(_) => Err(cbor_error_message(format!("CBOR key `{key}` must be tstr"))),
        None => Ok(None),
    }
}

fn take_uint(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<u64> {
    match fields.remove(key) {
        Some(CborValue::UInt(value)) => Ok(value),
        Some(_) => Err(cbor_error_message(format!("CBOR key `{key}` must be uint"))),
        None => Err(cbor_error_message(format!("missing CBOR key `{key}`"))),
    }
}

fn take_bstr(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<Vec<u8>> {
    match fields.remove(key) {
        Some(CborValue::Bstr(value)) => Ok(value),
        Some(_) => Err(cbor_error_message(format!("CBOR key `{key}` must be bstr"))),
        None => Err(cbor_error_message(format!("missing CBOR key `{key}`"))),
    }
}

fn take_bstr_array(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<Vec<Vec<u8>>> {
    match fields.remove(key) {
        Some(CborValue::Array(values)) => values
            .into_iter()
            .map(|value| match value {
                CborValue::Bstr(bytes) => Ok(bytes),
                _ => Err(cbor_error_message(format!(
                    "CBOR key `{key}` array items must be bstr"
                ))),
            })
            .collect(),
        Some(_) => Err(cbor_error_message(format!(
            "CBOR key `{key}` must be array"
        ))),
        None => Err(cbor_error_message(format!("missing CBOR key `{key}`"))),
    }
}

fn take_tstr_array(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<Vec<String>> {
    match fields.remove(key) {
        Some(CborValue::Array(values)) => values
            .into_iter()
            .map(|value| match value {
                CborValue::Tstr(value) => Ok(value),
                _ => Err(cbor_error_message(format!(
                    "CBOR key `{key}` array items must be tstr"
                ))),
            })
            .collect(),
        Some(_) => Err(cbor_error_message(format!(
            "CBOR key `{key}` must be array"
        ))),
        None => Err(cbor_error_message(format!("missing CBOR key `{key}`"))),
    }
}

fn take_hash(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<Hash> {
    hash_from_digest_bytes(key, &take_bstr(fields, key)?)
}

fn take_optional_hash(fields: &mut BTreeMap<String, CborValue>, key: &str) -> Result<Option<Hash>> {
    match fields.remove(key) {
        Some(CborValue::Bstr(bytes)) => Ok(Some(hash_from_digest_bytes(key, &bytes)?)),
        Some(_) => Err(cbor_error_message(format!("CBOR key `{key}` must be bstr"))),
        None => Ok(None),
    }
}

fn take_effective_scope(fields: &mut BTreeMap<String, CborValue>) -> Result<ScopeRef> {
    let Some(CborValue::Map(mut map)) = fields.remove("effective_scope") else {
        return Err(cbor_error("missing or invalid CBOR key `effective_scope`"));
    };
    let kind = take_tstr(&mut map, "kind")?;
    let realm_id = RealmId::new(take_tstr(&mut map, "realm_id")?)
        .map_err(|err| cbor_error_message(format!("effective_scope.realm_id is invalid: {err}")))?;
    match kind.as_str() {
        "realm" => {
            if let Some(extra) = map.keys().next() {
                return Err(cbor_error_message(format!(
                    "unexpected effective_scope realm key `{extra}`"
                )));
            }
            Ok(ScopeRef::Realm { realm_id })
        }
        "circle" => {
            let circle_id = CircleId::new(take_tstr(&mut map, "circle_id")?).map_err(|err| {
                cbor_error_message(format!("effective_scope.circle_id is invalid: {err}"))
            })?;
            if let Some(extra) = map.keys().next() {
                return Err(cbor_error_message(format!(
                    "unexpected effective_scope circle key `{extra}`"
                )));
            }
            Ok(ScopeRef::Circle {
                realm_id,
                circle_id,
            })
        }
        _ => Err(cbor_error("effective_scope.kind must be realm or circle")),
    }
}

fn take_optional_sidecar_binding(
    fields: &mut BTreeMap<String, CborValue>,
) -> Result<Option<SidecarMlsBinding>> {
    let Some(value) = fields.remove("sidecar_binding") else {
        return Ok(None);
    };
    let CborValue::Map(mut map) = value else {
        return Err(cbor_error("CBOR key `sidecar_binding` must be map"));
    };
    let control_frontier = take_tstr_array(&mut map, "control_frontier")?
        .into_iter()
        .map(NonEmptyString::new)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| {
            cbor_error_message(format!(
                "sidecar_binding.control_frontier is invalid: {err}"
            ))
        })?;
    let desired_access_digest = take_hash(&mut map, "desired_access_digest")?;
    let sidecar_id = SidecarId::new(take_tstr(&mut map, "sidecar_id")?).map_err(|err| {
        cbor_error_message(format!("sidecar_binding.sidecar_id is invalid: {err}"))
    })?;
    if let Some(extra) = map.keys().next() {
        return Err(cbor_error_message(format!(
            "unexpected sidecar_binding CBOR key `{extra}`"
        )));
    }
    let binding = SidecarMlsBinding {
        sidecar_id,
        desired_access_digest,
        control_frontier,
    };
    binding.validate()?;
    Ok(Some(binding))
}

fn hash_digest_bytes(field: &str, hash: &Hash) -> Result<Vec<u8>> {
    let Some(hex_value) = hash.as_str().strip_prefix("sha256:") else {
        return Err(Error::Protocol(format!(
            "mls_governance_binding.{field} must be sha256:<hex> (schema_violation)"
        )));
    };
    let bytes = hex::decode(hex_value).map_err(|err| {
        Error::Protocol(format!(
            "mls_governance_binding.{field} hash is not hex: {err} (schema_violation)"
        ))
    })?;
    if bytes.len() != 32 {
        return Err(Error::Protocol(format!(
            "mls_governance_binding.{field} hash must be 32 bytes (schema_violation)"
        )));
    }
    Ok(bytes)
}

fn hash_from_digest_bytes(field: &str, bytes: &[u8]) -> Result<Hash> {
    if bytes.len() != 32 {
        return Err(cbor_error_message(format!(
            "CBOR key `{field}` hash bstr must be 32 bytes"
        )));
    }
    Hash::new(format!("sha256:{}", hex::encode(bytes))).map_err(|err| {
        cbor_error_message(format!(
            "CBOR key `{field}` cannot be converted to Hash: {err}"
        ))
    })
}

fn cbor_error(message: &str) -> Error {
    cbor_error_message(message.to_owned())
}

fn cbor_error_message(message: String) -> Error {
    Error::Protocol(format!(
        "mls_governance_binding CBOR decode failed: {message} (schema_violation)"
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn event(n: u8) -> EventId {
        EventId::new(format!("ak:event:0196419b-0000-7000-8000-00000000000{n}")).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn seal(byte: char) -> SealId {
        SealId::new(format!("ak:seal:sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn group_id() -> String {
        base64url_encode(b"arkret-mls-test-group")
    }

    fn reducer_profile() -> &'static str {
        "ak.reducer.v1"
    }

    fn full_binding() -> MlsGovernanceBindingPayload {
        MlsGovernanceBindingPayload::realm(
            realm(),
            group_id(),
            0,
            1,
            vec![event(2)],
            vec![seal('a')],
            hash('2'),
            hash('3'),
            hash('4'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .unwrap()
    }

    #[test]
    fn mls_governance_binding_rejects_extra_fields_on_decode() {
        let err = serde_json::from_value::<MlsGovernanceBindingPayload>(json!({
            "binding_version": 1,
            "encoding_profile": MLS_GOVERNANCE_BINDING_ENCODING_PROFILE,
            "realm_id": realm(),
            "effective_scope": {"kind": "realm", "realm_id": realm()},
            "mls_group_id": "ak:mls_group:test",
            "previous_epoch": 0,
            "next_epoch": 1,
            "membership_frontier": [event(2)],
            "covered_seal_refs": [seal('a')],
            "policy_root": hash('2'),
            "binding_profile": MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "reducer_profile": reducer_profile(),
            "unexpected_field": true
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn mls_governance_binding_full_profile_requires_all_roots() {
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            group_id(),
            0,
            1,
            vec![event(2)],
            vec![seal('a')],
            hash('2'),
            hash('3'),
            hash('4'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .unwrap();

        binding
            .clone()
            .with_binding_profile("ak.profile.mls_governance_binding.full.v1")
            .unwrap();
        assert!(binding.clone().with_binding_profile("mls.full").is_err());
        assert!(binding.with_reducer_profile("").is_err());

        let error = serde_json::from_value::<MlsGovernanceBindingPayload>(json!({
            "binding_version": MLS_GOVERNANCE_BINDING_VERSION,
            "encoding_profile": MLS_GOVERNANCE_BINDING_ENCODING_PROFILE,
            "realm_id": realm(),
            "effective_scope": {"kind": "realm", "realm_id": realm()},
            "mls_group_id": group_id(),
            "previous_epoch": 0,
            "next_epoch": 1,
            "membership_frontier": [event(2)],
            "covered_seal_refs": [seal('a')],
            "policy_root": hash('2'),
            "binding_profile": MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "reducer_profile": reducer_profile(),
        }))
        .unwrap_err();
        assert!(error.to_string().contains("requires capability_root"));
    }

    #[test]
    fn mls_governance_binding_cbor_round_trips_realm_payload() {
        let binding = full_binding();
        let bytes = binding.to_deterministic_cbor().unwrap();
        let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes).unwrap();

        assert_eq!(decoded, binding);
        assert_eq!(
            decoded.to_group_context_extension().unwrap().extension_type,
            MLS_GOVERNANCE_BINDING_EXTENSION_TYPE
        );
        assert!(!bytes.windows(7).any(|window| window == b"track"));
        assert!(!bytes.windows(9).any(|window| window == b"strand_id"));
    }

    #[test]
    fn mls_governance_binding_cbor_round_trips_circle_payload() {
        let circle_id = CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000009").unwrap();
        let binding = MlsGovernanceBindingPayload::circle(
            realm(),
            circle_id.clone(),
            group_id(),
            7,
            8,
            vec![event(2), event(3)],
            vec![seal('a'), seal('b')],
            hash('5'),
            hash('6'),
            hash('7'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .unwrap();
        let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(
            &binding.to_deterministic_cbor().unwrap(),
        )
        .unwrap();

        assert_eq!(decoded.circle_id(), Some(&circle_id));
        assert_eq!(decoded, binding);
    }

    #[test]
    fn sidecar_mls_binding_round_trips_and_is_validated_exactly() {
        let circle_id = CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000009").unwrap();
        let sidecar_binding = SidecarMlsBinding {
            sidecar_id: SidecarId::new("ak:sidecar:0196419b-0000-7000-8000-000000000010").unwrap(),
            desired_access_digest: hash('8'),
            control_frontier: vec![
                NonEmptyString::new(event(2).to_string()).unwrap(),
                NonEmptyString::new(event(3).to_string()).unwrap(),
            ],
        };
        let binding = MlsGovernanceBindingPayload::circle(
            realm(),
            circle_id,
            group_id(),
            7,
            8,
            vec![event(2), event(3)],
            vec![seal('a'), seal('b')],
            hash('5'),
            hash('6'),
            hash('7'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .unwrap()
        .with_sidecar_binding(sidecar_binding.clone())
        .unwrap();

        let bytes = binding.to_deterministic_cbor().unwrap();
        assert_eq!(
            canonical::sha256_digest(&bytes),
            "sha256:2912bc6e77cde758bc341f20e4c02ab10ed500395a7b7266562d4fc1b1946ea7"
        );
        let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes).unwrap();
        assert_eq!(decoded.sidecar_binding(), Some(&sidecar_binding));
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            binding.mls_group_id(),
            binding.previous_epoch(),
            binding.next_epoch(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .with_sidecar_binding(&sidecar_binding);
        decoded.validate_against(&expected).unwrap();

        let mut stale = sidecar_binding.clone();
        stale.desired_access_digest = hash('9');
        let stale_expected = MlsGovernanceBindingValidationContext::for_commit(
            binding.mls_group_id(),
            binding.previous_epoch(),
            binding.next_epoch(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        )
        .with_sidecar_binding(&stale);
        assert!(decoded.validate_against(&stale_expected).is_err());
        assert!(
            decoded
                .validate_against(
                    &MlsGovernanceBindingValidationContext::for_commit(
                        binding.mls_group_id(),
                        binding.previous_epoch(),
                        binding.next_epoch(),
                        MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                        reducer_profile(),
                    )
                    .without_sidecar_binding(),
                )
                .is_err()
        );
    }

    #[test]
    fn sidecar_mls_binding_rejects_realm_scope_and_unsorted_frontier() {
        let sidecar_binding = SidecarMlsBinding {
            sidecar_id: SidecarId::new("ak:sidecar:0196419b-0000-7000-8000-000000000010").unwrap(),
            desired_access_digest: hash('8'),
            control_frontier: vec![
                NonEmptyString::new(event(3).to_string()).unwrap(),
                NonEmptyString::new(event(2).to_string()).unwrap(),
            ],
        };
        assert!(sidecar_binding.validate().is_err());
        assert!(
            full_binding()
                .with_sidecar_binding(sidecar_binding)
                .is_err()
        );
    }

    #[test]
    fn mls_governance_binding_rejects_missing_or_wrong_extension_codepoint() {
        let binding = full_binding();
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            binding.mls_group_id(),
            binding.previous_epoch(),
            binding.next_epoch(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        );
        expected.policy_root = Some(binding.policy_root());

        let missing = verify_mls_governance_binding_extension(None, &expected).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains(arkret_wire::ErrorCode::PROFILE_UNSUPPORTED)
        );

        let wrong = MlsGovernanceBindingExtension {
            extension_type: MLS_GOVERNANCE_BINDING_EXTENSION_TYPE + 1,
            extension_data: binding.to_deterministic_cbor().unwrap(),
        };
        let err = verify_mls_governance_binding_extension(Some(&wrong), &expected).unwrap_err();
        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::PROFILE_UNSUPPORTED)
        );
    }

    #[test]
    fn mls_governance_binding_rejects_profile_downgrade_in_full_context() {
        let relaxed = full_binding()
            .with_binding_profile(MLS_GOVERNANCE_BINDING_RELAXED_PROFILE)
            .unwrap();
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            relaxed.mls_group_id(),
            relaxed.previous_epoch(),
            relaxed.next_epoch(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        );
        let extension = relaxed.to_group_context_extension().unwrap();
        let err = verify_mls_governance_binding_extension(Some(&extension), &expected).unwrap_err();

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::PROFILE_UNSUPPORTED)
        );
    }

    #[test]
    fn mls_governance_binding_rejects_stale_policy_root() {
        let binding = full_binding();
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            binding.mls_group_id(),
            binding.previous_epoch(),
            binding.next_epoch(),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            reducer_profile(),
        );
        let stale_policy_root = hash('9');
        expected.policy_root = Some(&stale_policy_root);
        let extension = binding.to_group_context_extension().unwrap();
        let err = verify_mls_governance_binding_extension(Some(&extension), &expected).unwrap_err();

        assert!(
            err.to_string()
                .contains(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn mls_governance_binding_rejects_noncanonical_cbor_order() {
        let binding = full_binding();
        let mut bytes = Vec::new();
        cbor_put_map_len(&mut bytes, binding.cbor_field_count());
        cbor_put_tstr(&mut bytes, "binding_version");
        cbor_put_uint(&mut bytes, u64::from(binding.binding_version));
        cbor_put_tstr(&mut bytes, "binding_profile");
        cbor_put_tstr(&mut bytes, &binding.binding_profile);
        cbor_put_tstr(&mut bytes, "capability_root");
        cbor_put_bstr(
            &mut bytes,
            &hash_digest_bytes("capability_root", binding.capability_root().unwrap()).unwrap(),
        );
        cbor_put_tstr(&mut bytes, "covered_seal_refs");
        cbor_put_array_len(&mut bytes, binding.covered_seal_refs().len() as u64);
        for seal_ref in binding.covered_seal_refs() {
            cbor_put_bstr(&mut bytes, seal_ref.as_str().as_bytes());
        }
        cbor_put_tstr(&mut bytes, "discussion_metadata_digest");
        cbor_put_bstr(
            &mut bytes,
            &hash_digest_bytes(
                "discussion_metadata_digest",
                binding.discussion_metadata_digest().unwrap(),
            )
            .unwrap(),
        );
        cbor_put_tstr(&mut bytes, "effective_scope");
        encode_effective_scope(&mut bytes, binding.effective_scope()).unwrap();
        cbor_put_tstr(&mut bytes, "encoding_profile");
        cbor_put_tstr(&mut bytes, &binding.encoding_profile);
        cbor_put_tstr(&mut bytes, "membership_frontier");
        cbor_put_array_len(&mut bytes, binding.membership_frontier().len() as u64);
        for event_id in binding.membership_frontier() {
            cbor_put_bstr(&mut bytes, event_id.as_str().as_bytes());
        }
        cbor_put_tstr(&mut bytes, "mls_group_id");
        cbor_put_bstr(
            &mut bytes,
            &base64url_decode(binding.mls_group_id()).unwrap(),
        );
        cbor_put_tstr(&mut bytes, "next_epoch");
        cbor_put_uint(&mut bytes, binding.next_epoch());
        cbor_put_tstr(&mut bytes, "policy_root");
        cbor_put_bstr(
            &mut bytes,
            &hash_digest_bytes("policy_root", binding.policy_root()).unwrap(),
        );
        cbor_put_tstr(&mut bytes, "previous_epoch");
        cbor_put_uint(&mut bytes, binding.previous_epoch());
        cbor_put_tstr(&mut bytes, "realm_id");
        cbor_put_tstr(&mut bytes, binding.realm_id().as_str());
        cbor_put_tstr(&mut bytes, "reducer_profile");
        cbor_put_tstr(&mut bytes, binding.reducer_profile());

        let err = MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes).unwrap_err();

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::SCHEMA_VIOLATION)
        );
    }

    #[test]
    fn mls_governance_binding_cbor_rejects_capacity_bomb_length_header() {
        // Array header claiming 2^64-1 elements with no payload behind it:
        // the length header MUST be clamped against the remaining input
        // before any `Vec::with_capacity` is sized from it (a 9-byte input
        // must not trigger a multi-gigabyte allocation).
        let mut array_bomb = vec![0x9b];
        array_bomb.extend_from_slice(&[0xff; 8]);
        let err = MlsGovernanceBindingPayload::from_deterministic_cbor(&array_bomb).unwrap_err();
        assert!(err.to_string().contains("exceeds remaining input"));

        // Same guard for map (major 5) and text-string (major 3) headers.
        let mut map_bomb = vec![0xbb];
        map_bomb.extend_from_slice(&[0xff; 8]);
        assert!(MlsGovernanceBindingPayload::from_deterministic_cbor(&map_bomb).is_err());

        let mut tstr_bomb = vec![0x7b];
        tstr_bomb.extend_from_slice(&[0xff; 8]);
        assert!(MlsGovernanceBindingPayload::from_deterministic_cbor(&tstr_bomb).is_err());
    }

    #[test]
    fn mls_governance_binding_cbor_rejects_deep_nesting() {
        // Map value made of a chain of single-element arrays
        // (`0x81 0x81 ... 0x00`): recursion depth MUST be bounded by a
        // constant, not proportional to the input length, or a ~1 MB input
        // becomes a stack-overflow abort.
        let mut bytes = vec![0xa1];
        cbor_put_tstr(&mut bytes, "k");
        bytes.extend(std::iter::repeat_n(0x81u8, 64));
        bytes.push(0x00);
        let err = MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("nesting exceeds maximum depth"));
    }

    fn media_service(host: &str) -> MediaPlaintextService {
        MediaPlaintextService {
            service_id: Did::new(format!("did:webvh:z6mkfixture:{host}")).unwrap(),
        }
    }

    fn media_value(decrypts: bool, hosts: &[&str]) -> MediaDecryptPolicyValue {
        MediaDecryptPolicyValue {
            media_service_decrypts: decrypts,
            plaintext_visible_services: hosts.iter().map(|h| media_service(h)).collect(),
        }
    }

    #[test]
    fn media_decrypt_metadata_digest_is_deterministic() {
        let value = media_value(true, &["sfu-a.example", "sfu-b.example"]);
        let h1 = derive_media_decrypt_metadata_digest(&value).unwrap();
        let h2 = derive_media_decrypt_metadata_digest(&value).unwrap();
        assert_eq!(h1, h2);
        // Set order MUST NOT change the digest (canonical sorting).
        let reordered = media_value(true, &["sfu-b.example", "sfu-a.example"]);
        assert_eq!(
            h1,
            derive_media_decrypt_metadata_digest(&reordered).unwrap()
        );
    }

    #[test]
    fn media_decrypt_metadata_digest_separates_on_toggle_and_services() {
        let on =
            derive_media_decrypt_metadata_digest(&media_value(true, &["sfu-a.example"])).unwrap();
        let off =
            derive_media_decrypt_metadata_digest(&media_value(false, &["sfu-a.example"])).unwrap();
        assert_ne!(on, off, "media_service_decrypts toggle MUST change digest");
        let other_service =
            derive_media_decrypt_metadata_digest(&media_value(true, &["sfu-b.example"])).unwrap();
        assert_ne!(on, other_service, "service set MUST change digest");
    }

    #[test]
    fn verify_media_decrypt_metadata_accepts_match_rejects_stale() {
        let value = media_value(true, &["sfu-a.example"]);
        let digest = derive_media_decrypt_metadata_digest(&value).unwrap();
        assert!(verify_media_decrypt_metadata(&digest, &digest).is_ok());

        let recomputed =
            derive_media_decrypt_metadata_digest(&media_value(false, &["sfu-a.example"])).unwrap();
        let err = verify_media_decrypt_metadata(&digest, &recomputed).unwrap_err();
        assert!(
            err.to_string()
                .contains(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
