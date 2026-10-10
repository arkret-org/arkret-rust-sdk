//! MLS governance and Commit Event payloads for the authority-commit protocol.

use arkret_wire::{
    BlobRef, CircleId, ErrorCode, EventId, Hash, MlsGroupId, RealmId, Result, ScopeRef, SidecarId,
    WireError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

const MLS_GOVERNANCE_BINDING_MAX_INPUT_BYTES: usize = 16_384;
const MLS_GOVERNANCE_BINDING_MAX_NESTING_DEPTH: usize = 8;
const MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS: u64 = 64;

/// Arkret v1 RFC 9420 GroupContext extension carrying the governance binding.
pub const MLS_GOVERNANCE_BINDING_EXTENSION_TYPE: u16 = 0xF1C0;

use crate::mls_envelopes::MlsCommitEnvelope;

/// Authority-selected MLS group state coordinates carried in every transition.
///
/// Superseded reducer, archive, and sidecar-proof carriers are
/// deliberately absent. The accepted
/// `RealmCommit` is the ordering and governance authority.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceBindingPayload {
    effective_scope: ScopeRef,
    #[serde(deserialize_with = "deserialize_present_nullable")]
    base_group_state_ref: Option<EventId>,
    previous_epoch: u64,
    next_epoch: u64,
    key_access_revision: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    participant_authority_digest: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_optional"
    )]
    authority_stream_head: Option<Vec<EventId>>,
}

fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn deserialize_non_null_optional<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The Sidecar-only authority coordinates inside a signed MLS binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarMlsBinding {
    pub sidecar_id: SidecarId,
    pub participant_authority_digest: Hash,
    pub authority_stream_head: Vec<EventId>,
}

impl MlsGovernanceBindingPayload {
    pub fn realm(
        realm_id: RealmId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ScopeRef::Realm { realm_id },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        )
    }

    pub fn circle(
        realm_id: RealmId,
        circle_id: CircleId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument names an independent field of the authoritative Sidecar MLS governance binding."
    )]
    pub fn sidecar(
        realm_id: RealmId,
        sidecar_id: SidecarId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
        participant_authority_digest: Hash,
        authority_stream_head: Vec<EventId>,
    ) -> Result<Self> {
        let value = Self {
            effective_scope: ScopeRef::Sidecar {
                realm_id,
                sidecar_id,
            },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
            participant_authority_digest: Some(participant_authority_digest),
            authority_stream_head: Some(authority_stream_head),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new(
        effective_scope: ScopeRef,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        let value = Self {
            effective_scope,
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
            participant_authority_digest: None,
            authority_stream_head: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        match &self.effective_scope {
            ScopeRef::Sidecar { .. } => {
                if self.participant_authority_digest.is_none() {
                    return schema_violation(
                        "Sidecar MLS binding requires participant authority digest",
                    );
                }
                let Some(head) = &self.authority_stream_head else {
                    return schema_violation("Sidecar MLS binding requires authority stream head");
                };
                if head.is_empty()
                    || head.len() as u64 > MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS
                    || head
                        .windows(2)
                        .any(|pair| pair[0].as_str() >= pair[1].as_str())
                {
                    return schema_violation(
                        "Sidecar MLS authority stream head must hold 1..=64 sorted unique refs",
                    );
                }
            }
            _ if self.participant_authority_digest.is_some()
                || self.authority_stream_head.is_some() =>
            {
                return schema_violation(
                    "Realm and Circle MLS bindings forbid Sidecar authority fields",
                );
            }
            _ => {}
        }
        if self.next_epoch == 0 {
            if self.previous_epoch != 0 || self.base_group_state_ref.is_some() {
                return protocol("MLS genesis binding must be epoch zero without a base state");
            }
        } else if self.base_group_state_ref.is_none()
            || self.previous_epoch.checked_add(1) != Some(self.next_epoch)
        {
            return protocol("MLS transition binding requires its immediate base group state");
        }
        Ok(())
    }

    /// Validation for consumers whose MLS history surface is intentionally
    /// restricted to Realm and Circle groups.
    pub fn validate_realm_or_circle_scope(&self) -> Result<()> {
        self.validate()?;
        if !matches!(
            self.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) {
            return protocol("MLS history scope must be Realm or Circle");
        }
        Ok(())
    }

    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn base_group_state_ref(&self) -> Option<&EventId> {
        self.base_group_state_ref.as_ref()
    }
    pub const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    pub const fn key_access_revision(&self) -> u64 {
        self.key_access_revision
    }
    pub fn participant_authority_digest(&self) -> Option<&Hash> {
        self.participant_authority_digest.as_ref()
    }
    pub fn authority_stream_head(&self) -> Option<&[EventId]> {
        self.authority_stream_head.as_deref()
    }
    pub fn sidecar_id(&self) -> Option<&SidecarId> {
        match &self.effective_scope {
            ScopeRef::Sidecar { sidecar_id, .. } => Some(sidecar_id),
            _ => None,
        }
    }
    pub fn sidecar_binding(&self) -> Option<SidecarMlsBinding> {
        Some(SidecarMlsBinding {
            sidecar_id: self.sidecar_id()?.clone(),
            participant_authority_digest: self.participant_authority_digest.clone()?,
            authority_stream_head: self.authority_stream_head.clone()?,
        })
    }

    pub fn mls_group_id(&self) -> Result<MlsGroupId> {
        self.effective_scope.canonical_mls_group_id()
    }

    /// Decode the exact deterministic-CBOR v1 representation registered for
    /// the MLS GroupContext governance-binding extension.
    ///
    /// This is the schema boundary: malformed, non-deterministic, unknown or
    /// missing-member input is rejected with `schema_violation` before any
    /// state or payload comparison runs.
    pub fn from_deterministic_cbor(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MLS_GOVERNANCE_BINDING_MAX_INPUT_BYTES {
            return schema_violation("MLS governance binding exceeds the input byte limit");
        }
        let mut decoder = DeterministicCborDecoder::new(encoded);
        let value = decoder.decode_value(1)?;
        if decoder.offset != encoded.len() {
            return schema_violation("MLS governance binding contains trailing bytes");
        }
        let json = cbor_value_to_json(value)?;
        let binding: Self =
            serde_json::from_value(json).map_err(|error| WireError::ProtocolCode {
                code: ErrorCode::SchemaViolation,
                message: format!("MLS governance binding violates its closed schema: {error}"),
            })?;
        binding.validate()?;
        Ok(binding)
    }

    /// Encode the exact deterministic-CBOR v1 representation used by the MLS
    /// GroupContext governance-binding extension.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        let mut encoded = Vec::new();
        encode_deterministic_cbor(&value, &mut encoded)?;
        if encoded.len() > MLS_GOVERNANCE_BINDING_MAX_INPUT_BYTES {
            return schema_violation("MLS governance binding exceeds the input byte limit");
        }
        Ok(encoded)
    }
}

#[derive(Debug)]
enum DecodedCborValue {
    Null,
    Unsigned(u64),
    Text(String),
    Array(Vec<DecodedCborValue>),
    Map(Vec<(String, DecodedCborValue)>),
}

struct DeterministicCborDecoder<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> DeterministicCborDecoder<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn decode_value(&mut self, depth: usize) -> Result<DecodedCborValue> {
        if depth > MLS_GOVERNANCE_BINDING_MAX_NESTING_DEPTH {
            return schema_violation("MLS governance binding exceeds the nesting limit");
        }
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(DecodedCborValue::Unsigned(
                self.decode_argument(additional)?,
            )),
            3 => self.decode_text(additional).map(DecodedCborValue::Text),
            4 => self.decode_array(additional, depth),
            5 => self.decode_map(additional, depth),
            7 if additional == 22 => Ok(DecodedCborValue::Null),
            _ => schema_violation("MLS governance binding uses an unsupported CBOR type"),
        }
    }

    fn decode_array(&mut self, additional: u8, depth: usize) -> Result<DecodedCborValue> {
        let count = self.decode_argument(additional)?;
        if count > MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS {
            return schema_violation("MLS governance binding exceeds the collection item limit");
        }
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            items.push(self.decode_value(depth + 1)?);
        }
        Ok(DecodedCborValue::Array(items))
    }

    fn decode_map(&mut self, additional: u8, depth: usize) -> Result<DecodedCborValue> {
        let count = self.decode_argument(additional)?;
        if count > MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS {
            return schema_violation("MLS governance binding exceeds the collection item limit");
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut previous_key_encoding: Option<&[u8]> = None;
        for _ in 0..count {
            let key_start = self.offset;
            let initial = self.read_byte()?;
            if initial >> 5 != 3 {
                return schema_violation("MLS governance binding map keys must be text");
            }
            let key = self.decode_text(initial & 0x1f)?;
            let key_encoding = &self.encoded[key_start..self.offset];
            if previous_key_encoding.is_some_and(|previous| previous >= key_encoding) {
                return schema_violation(
                    "MLS governance binding map keys are duplicate or not in deterministic order",
                );
            }
            previous_key_encoding = Some(key_encoding);
            entries.push((key, self.decode_value(depth + 1)?));
        }
        Ok(DecodedCborValue::Map(entries))
    }

    fn decode_text(&mut self, additional: u8) -> Result<String> {
        let length = self.decode_argument(additional)?;
        let length = usize::try_from(length)
            .map_err(|_| schema_violation_error("CBOR text length exceeds this platform"))?;
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.encoded.len())
            .ok_or_else(|| schema_violation_error("CBOR text length exceeds remaining input"))?;
        let text = std::str::from_utf8(&self.encoded[self.offset..end])
            .map_err(|_| schema_violation_error("CBOR text is not UTF-8"))?
            .to_owned();
        self.offset = end;
        Ok(text)
    }

    fn decode_argument(&mut self, additional: u8) -> Result<u64> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    return schema_violation("CBOR integer or length is not minimally encoded");
                }
                Ok(value)
            }
            25 => self.decode_fixed_argument(2, 0x100),
            26 => self.decode_fixed_argument(4, 0x1_0000),
            27 => self.decode_fixed_argument(8, 0x1_0000_0000),
            _ => schema_violation("indefinite or reserved CBOR arguments are forbidden"),
        }
    }

    fn decode_fixed_argument(&mut self, width: usize, minimum: u64) -> Result<u64> {
        let end = self
            .offset
            .checked_add(width)
            .filter(|end| *end <= self.encoded.len())
            .ok_or_else(|| schema_violation_error("CBOR argument exceeds remaining input"))?;
        let mut bytes = [0_u8; 8];
        bytes[8 - width..].copy_from_slice(&self.encoded[self.offset..end]);
        self.offset = end;
        let value = u64::from_be_bytes(bytes);
        if value < minimum {
            return schema_violation("CBOR integer or length is not minimally encoded");
        }
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = self
            .encoded
            .get(self.offset)
            .copied()
            .ok_or_else(|| schema_violation_error("CBOR input is truncated"))?;
        self.offset += 1;
        Ok(byte)
    }
}

fn cbor_value_to_json(value: DecodedCborValue) -> Result<Value> {
    match value {
        DecodedCborValue::Null => Ok(Value::Null),
        DecodedCborValue::Unsigned(value) => Ok(Value::Number(Number::from(value))),
        DecodedCborValue::Text(value) => Ok(Value::String(value)),
        DecodedCborValue::Array(items) => items
            .into_iter()
            .map(cbor_value_to_json)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        DecodedCborValue::Map(entries) => {
            let mut object = Map::new();
            for (key, value) in entries {
                if object.insert(key, cbor_value_to_json(value)?).is_some() {
                    return schema_violation("MLS governance binding contains a duplicate map key");
                }
            }
            Ok(Value::Object(object))
        }
    }
}

fn encode_deterministic_cbor(value: &Value, encoded: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => encoded.push(0xf6),
        Value::Number(number) => encode_cbor_head(
            0,
            number
                .as_u64()
                .ok_or_else(|| schema_violation_error("CBOR value is not an unsigned integer"))?,
            encoded,
        ),
        Value::String(text) => {
            encode_cbor_head(3, text.len() as u64, encoded);
            encoded.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            if items.len() as u64 > MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS {
                return schema_violation(
                    "MLS governance binding exceeds the collection item limit",
                );
            }
            encode_cbor_head(4, items.len() as u64, encoded);
            for item in items {
                encode_deterministic_cbor(item, encoded)?;
            }
        }
        Value::Object(object) => {
            if object.len() as u64 > MLS_GOVERNANCE_BINDING_MAX_COLLECTION_ITEMS {
                return schema_violation(
                    "MLS governance binding exceeds the collection item limit",
                );
            }
            let mut entries = object
                .iter()
                .map(|(key, value)| {
                    let mut encoded_key = Vec::new();
                    encode_deterministic_cbor(&Value::String(key.clone()), &mut encoded_key)?;
                    Ok((encoded_key, value))
                })
                .collect::<Result<Vec<_>>>()?;
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            encode_cbor_head(5, entries.len() as u64, encoded);
            for (key, value) in entries {
                encoded.extend_from_slice(&key);
                encode_deterministic_cbor(value, encoded)?;
            }
        }
        _ => return schema_violation("unsupported MLS governance binding CBOR value"),
    }
    Ok(())
}

fn encode_cbor_head(major: u8, value: u64, encoded: &mut Vec<u8>) {
    match value {
        0..=23 => encoded.push((major << 5) | value as u8),
        24..=0xff => encoded.extend_from_slice(&[(major << 5) | 24, value as u8]),
        0x100..=0xffff => {
            encoded.push((major << 5) | 25);
            encoded.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            encoded.push((major << 5) | 26);
            encoded.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            encoded.push((major << 5) | 27);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(schema_violation_error(message))
}

fn schema_violation_error(message: impl Into<String>) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::SchemaViolation,
        message: message.into(),
    }
}

/// Compact `ak.mls.commit` Event payload.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MlsCommitPayload {
    base_group_state_ref: EventId,
    previous_epoch: u64,
    next_epoch: u64,
    covers_key_access_revision: u64,
    commit_bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_message_ref: Option<BlobRef>,
    #[serde(skip)]
    commit_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsCommitPayloadWire {
    base_group_state_ref: EventId,
    previous_epoch: u64,
    next_epoch: u64,
    covers_key_access_revision: u64,
    commit_bytes_b64: String,
    #[serde(default)]
    commit_message_ref: Option<BlobRef>,
    governance_binding: MlsGovernanceBindingPayload,
}

impl<'de> Deserialize<'de> for MlsCommitPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsCommitPayloadWire::deserialize(deserializer)?;
        let commit_bytes = arkret_wire::base64url::base64url_decode(&wire.commit_bytes_b64)
            .map_err(serde::de::Error::custom)?;
        let commit_digest = Hash::new(arkret_wire::canonical::sha256_digest(&commit_bytes))
            .map_err(serde::de::Error::custom)?;
        let payload = Self {
            base_group_state_ref: wire.base_group_state_ref,
            previous_epoch: wire.previous_epoch,
            next_epoch: wire.next_epoch,
            covers_key_access_revision: wire.covers_key_access_revision,
            commit_bytes_b64: wire.commit_bytes_b64,
            commit_message_ref: wire.commit_message_ref,
            commit_digest,
            governance_binding: wire.governance_binding,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl MlsCommitPayload {
    pub fn new(
        base_group_state_ref: EventId,
        covers_key_access_revision: u64,
        commit: &MlsCommitEnvelope,
        governance_binding: MlsGovernanceBindingPayload,
    ) -> Result<Self> {
        governance_binding.validate()?;
        if governance_binding.base_group_state_ref() != Some(&base_group_state_ref)
            || commit.group_id != governance_binding.mls_group_id()?
            || commit.epoch != governance_binding.next_epoch()
        {
            return protocol("MLS Commit envelope differs from its governance binding");
        }
        let payload = Self {
            base_group_state_ref,
            previous_epoch: governance_binding.previous_epoch(),
            next_epoch: governance_binding.next_epoch(),
            covers_key_access_revision,
            commit_bytes_b64: commit.commit.clone(),
            commit_message_ref: None,
            commit_digest: commit.commit_digest.clone(),
            governance_binding,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        self.governance_binding.validate()?;
        if self.previous_epoch != self.governance_binding.previous_epoch()
            || self.next_epoch != self.governance_binding.next_epoch()
            || self.governance_binding.base_group_state_ref() != Some(&self.base_group_state_ref)
            || self.covers_key_access_revision < self.governance_binding.key_access_revision()
        {
            return protocol("MLS Commit coordinates differ from governance_binding");
        }
        let bytes = arkret_wire::base64url::base64url_decode(&self.commit_bytes_b64)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if arkret_wire::canonical::sha256_digest(&bytes) != self.commit_digest.as_str() {
            return protocol("MLS Commit digest does not match commit bytes");
        }
        if let Some(reference) = &self.commit_message_ref {
            let expected = reference
                .as_str()
                .strip_prefix("ak:blob:")
                .ok_or_else(|| WireError::Protocol("invalid Commit blob ref".to_owned()))?;
            arkret_wire::canonical::verify_digest(&bytes, expected).map_err(|_| {
                WireError::Protocol("Commit blob ref does not address bytes".to_owned())
            })?;
        }
        Ok(())
    }

    pub fn event_kind(&self) -> &'static str {
        arkret_wire::event_kind_str::MLS_COMMIT
    }
    pub fn base_group_state_ref(&self) -> &EventId {
        &self.base_group_state_ref
    }
    pub const fn base_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    pub const fn covers_key_access_revision(&self) -> u64 {
        self.covers_key_access_revision
    }
    pub fn commit_bytes_b64(&self) -> &str {
        &self.commit_bytes_b64
    }
    pub fn commit_message_ref(&self) -> Option<&BlobRef> {
        self.commit_message_ref.as_ref()
    }
    pub fn commit_digest(&self) -> &Hash {
        &self.commit_digest
    }
    pub fn governance_binding(&self) -> &MlsGovernanceBindingPayload {
        &self.governance_binding
    }
    pub fn mls_group_id(&self) -> Result<MlsGroupId> {
        self.governance_binding.mls_group_id()
    }

    pub fn commit_envelope(&self) -> Result<MlsCommitEnvelope> {
        Ok(MlsCommitEnvelope {
            group_id: self.mls_group_id()?,
            epoch: self.next_epoch,
            commit: self.commit_bytes_b64.clone(),
            commit_digest: self.commit_digest.clone(),
            ratchet_tree: None,
        })
    }
}

fn protocol<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(message.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(byte: u8) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_wire::canonical::sha256_digest([byte])).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn history_scope_validator_rejects_sidecar_without_rejecting_sidecar_mls() {
        let binding = MlsGovernanceBindingPayload::sidecar(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
            Some(event(1)),
            1,
            2,
            0,
            Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
            vec![event(2)],
        )
        .unwrap();
        binding.validate().unwrap();
        assert!(binding.validate_realm_or_circle_scope().is_err());
    }

    #[test]
    fn sidecar_authority_fields_are_closed_and_bound_by_cbor() {
        let mut head = vec![event(1), event(2)];
        head.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let binding = MlsGovernanceBindingPayload::sidecar(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
            None,
            0,
            0,
            0,
            Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
            head.clone(),
        )
        .unwrap();
        let encoded = binding.to_deterministic_cbor().unwrap();
        assert_eq!(
            MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap(),
            binding
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(MlsGovernanceBindingPayload::from_deterministic_cbor(&trailing).is_err());
        let mut missing = serde_json::to_value(&binding).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("authority_stream_head");
        assert!(
            serde_json::from_value::<MlsGovernanceBindingPayload>(missing)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut missing_digest = serde_json::to_value(&binding).unwrap();
        missing_digest
            .as_object_mut()
            .unwrap()
            .remove("participant_authority_digest");
        assert!(
            serde_json::from_value::<MlsGovernanceBindingPayload>(missing_digest)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut unsorted = serde_json::to_value(&binding).unwrap();
        head.reverse();
        unsorted["authority_stream_head"] = serde_json::json!(head);
        assert!(
            serde_json::from_value::<MlsGovernanceBindingPayload>(unsorted)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut duplicate = serde_json::to_value(&binding).unwrap();
        duplicate["authority_stream_head"] = serde_json::json!([event(1), event(1)]);
        assert!(
            serde_json::from_value::<MlsGovernanceBindingPayload>(duplicate)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut realm = MlsGovernanceBindingPayload::realm(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            None,
            0,
            0,
            0,
        )
        .unwrap();
        realm.participant_authority_digest = binding.participant_authority_digest.clone();
        assert!(realm.validate().is_err());
        realm.participant_authority_digest = None;
        realm.authority_stream_head = binding.authority_stream_head;
        assert!(realm.validate().is_err());
    }

    #[test]
    fn sidecar_binding_encodes_members_in_schema_map_key_order() {
        let binding = MlsGovernanceBindingPayload::sidecar(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
            Some(event(1)),
            1,
            2,
            3,
            Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
            vec![event(2)],
        )
        .unwrap();
        let encoded = binding.to_deterministic_cbor().unwrap();
        assert_eq!(encoded[0], 0xa7);
        let order = [
            "next_epoch",
            "previous_epoch",
            "effective_scope",
            "key_access_revision",
            "base_group_state_ref",
            "authority_stream_head",
            "participant_authority_digest",
        ];
        let positions = order
            .iter()
            .map(|key| {
                let mut encoded_key = Vec::new();
                encode_deterministic_cbor(&Value::String((*key).to_owned()), &mut encoded_key)
                    .unwrap();
                encoded
                    .windows(encoded_key.len())
                    .position(|window| window == encoded_key.as_slice())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn sidecar_authority_stream_head_is_bounded_by_the_decoder_limit() {
        let mut head = (0..=64_u8).map(event).collect::<Vec<_>>();
        head.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let sidecar = |head: Vec<EventId>| {
            MlsGovernanceBindingPayload::sidecar(
                RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
                SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
                None,
                0,
                0,
                0,
                Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap(),
                head,
            )
        };
        let error = sidecar(head.clone()).unwrap_err();
        assert_eq!(error.error_code(), Some(ErrorCode::SchemaViolation));
        head.pop();
        let binding = sidecar(head).unwrap();
        let encoded = binding.to_deterministic_cbor().unwrap();
        assert_eq!(
            MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded).unwrap(),
            binding
        );
    }

    #[test]
    fn binding_members_reject_null_or_absent_spellings() {
        let realm = MlsGovernanceBindingPayload::realm(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            None,
            0,
            0,
            0,
        )
        .unwrap();
        let value = serde_json::to_value(&realm).unwrap();
        assert_eq!(value["base_group_state_ref"], Value::Null);
        let mut absent_base = value.clone();
        absent_base
            .as_object_mut()
            .unwrap()
            .remove("base_group_state_ref");
        assert!(serde_json::from_value::<MlsGovernanceBindingPayload>(absent_base).is_err());
        for member in ["participant_authority_digest", "authority_stream_head"] {
            let mut null_member = value.clone();
            null_member[member] = Value::Null;
            assert!(serde_json::from_value::<MlsGovernanceBindingPayload>(null_member).is_err());
        }
    }
}
