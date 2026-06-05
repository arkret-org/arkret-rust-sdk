use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Operation {
    pub schema: String,
    pub operation_id: OperationId,
    #[serde(rename = "type")]
    pub record_type: String,
    pub operation_type: OperationType,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub object_type: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Operation {
    pub fn create(
        operation_id: OperationId,
        realm_id: RealmId,
        object_type: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            schema: OPERATION_SCHEMA.to_owned(),
            operation_id,
            record_type: "operation".to_owned(),
            operation_type: OperationType::Create,
            realm_id,
            object_id: None,
            object_type: object_type.into(),
            payload,
            idempotency_key: None,
            created_at: Utc::now(),
        }
    }

    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(self)
    }

    pub fn validate_payload_object(&self) -> Result<()> {
        if self.payload.is_object() {
            Ok(())
        } else {
            Err(Error::Protocol("operation payload must be a JSON object".to_owned()))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationEnvelope {
    pub operation_id: OperationId,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub causal: CausalRef,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEnvelope {
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "operation envelope proofs must contain at least one proof".to_owned(),
            ));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol(
                "operation envelope content must be a JSON object".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this operation's digest.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.operation_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.event_digest != expected_hash {
                return Err(Error::Protocol(format!(
                    "operation proof event_digest '{}' does not match operation digest '{}'",
                    proof.event_digest, expected_hash
                )));
            }
        }
        Ok(())
    }

    /// Materialize this SDK-local operation draft as a signed Event Envelope.
    ///
    /// Operation envelopes are not Cokret v1 wire facts. Callers must choose
    /// the event causal/auth references during conversion, then submit the
    /// returned [`EventEnvelope`] to network, sync, federation or reducers.
    pub fn into_event_envelope(
        self,
        conversion: OperationEventConversion,
    ) -> Result<EventEnvelope> {
        let mut event = Event::new(
            self.kind.clone(),
            self.realm_id,
            self.actor_id,
            self.causal.actor_seq,
            self.causal.hlc,
            self.content,
        )?;
        event.prev_refs = conversion.prev_refs;
        event.refs = conversion.refs;
        event.requirements = EventRequirements {
            schema_profile_refs: conversion.schema_profile_refs,
            reducer_profile_ref: conversion.reducer_profile_ref,
            required_features: conversion.required_features,
            critical_extensions: conversion.critical_extensions,
        };
        event.proofs = conversion.proofs;
        event.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(self.operation_id.to_string()),
        );
        if !self.causal.deps.is_empty() {
            event.unsigned.insert(
                "local_operation_dependencies".to_owned(),
                serde_json::to_value(self.causal.deps)?,
            );
        }
        if let Some(target_ref) = self.target_ref {
            event.unsigned.insert("local_target_ref".to_owned(), Value::String(target_ref));
        }
        Ok(event)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationEventConversion {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_profile_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reducer_profile_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub critical_extensions: Vec<CriticalExtension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl OperationEventConversion {
    pub fn with_prev_ref(mut self, event_id: EventId) -> Self {
        self.prev_refs.push(event_id);
        self
    }

    pub fn with_authorized_by_ref(mut self, event_id: EventId) -> Self {
        self.refs.push(EventRef::authorized_by(event_id));
        self
    }

    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proofs.push(proof);
        self
    }
}

/// Registry-backed builder for [`OperationEnvelope`].
#[derive(Clone, Debug)]
pub struct OperationEnvelopeBuilder {
    operation_id: OperationId,
    realm_id: RealmId,
    actor_id: Did,
    kind: String,
    target_ref: Option<String>,
    deps: Vec<OperationId>,
    hlc: Hlc,
    actor_seq: u64,
    content: Value,
    authz_ref: Option<GrantId>,
    proofs: Vec<Proof>,
}

impl OperationEnvelopeBuilder {
    /// Create a builder for one registered operation kind.
    pub fn new(
        operation_id: OperationId,
        realm_id: RealmId,
        actor_id: Did,
        kind: impl Into<String>,
        actor_seq: u64,
        hlc: Hlc,
    ) -> Self {
        Self {
            operation_id,
            realm_id,
            actor_id,
            kind: kind.into(),
            target_ref: None,
            deps: Vec::new(),
            hlc,
            actor_seq,
            content: Value::Object(Default::default()),
            authz_ref: None,
            proofs: Vec::new(),
        }
    }

    /// Set a target reference.
    pub fn with_target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Add a causal dependency.
    pub fn with_dependency(mut self, dependency: OperationId) -> Self {
        self.deps.push(dependency);
        self
    }

    /// Replace the content object.
    pub fn with_content(mut self, content: Value) -> Self {
        self.content = content;
        self
    }

    /// Insert one content field.
    pub fn with_content_field(mut self, field: impl Into<String>, value: Value) -> Self {
        if !self.content.is_object() {
            self.content = Value::Object(Default::default());
        }
        if let Value::Object(content) = &mut self.content {
            content.insert(field.into(), value);
        }
        self
    }

    /// Attach an authorization reference.
    pub fn with_authz_ref(mut self, authz_ref: GrantId) -> Self {
        self.authz_ref = Some(authz_ref);
        self
    }

    /// Attach a proof.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Build and validate the operation envelope against a registry.
    pub fn build(self, registry: &OperationKindRegistry) -> Result<OperationEnvelope> {
        let validation = registry.canonicalize(&self.kind)?;
        let envelope = OperationEnvelope {
            operation_id: self.operation_id,
            realm_id: self.realm_id,
            actor_id: self.actor_id,
            kind: validation.canonical_kind,
            target_ref: self.target_ref,
            causal: CausalRef { deps: self.deps, hlc: self.hlc, actor_seq: self.actor_seq },
            content: self.content,
            authz_ref: self.authz_ref,
            proofs: self.proofs,
        };
        registry.validate_envelope(&envelope)?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CausalRef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<OperationId>,
    pub hlc: Hlc,
    pub actor_seq: u64,
}

const RANK_MIN: u64 = 0;
const RANK_MAX: u64 = u64::MAX;

pub fn rank_between(before: Option<&str>, after: Option<&str>) -> Result<String> {
    let low = before.map(parse_rank).transpose()?.unwrap_or(RANK_MIN);
    let high = after.map(parse_rank).transpose()?.unwrap_or(RANK_MAX);
    if low >= high || low.saturating_add(1) >= high {
        return Err(Error::Protocol("rank interval is exhausted".to_owned()));
    }
    Ok(format_rank(low + ((high - low) / 2)))
}

pub fn rank_exhausted(before: Option<&str>, after: Option<&str>) -> Result<bool> {
    let low = before.map(parse_rank).transpose()?.unwrap_or(RANK_MIN);
    let high = after.map(parse_rank).transpose()?.unwrap_or(RANK_MAX);
    Ok(low >= high || low.saturating_add(1) >= high)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ContainerRebalanceAssignment {
    pub object_ref: String,
    pub rank: String,
}

pub fn container_rebalance_assignments(
    object_refs: &[String],
) -> Result<Vec<ContainerRebalanceAssignment>> {
    if object_refs.is_empty() {
        return Ok(Vec::new());
    }
    let step = RANK_MAX / (object_refs.len() as u64 + 1);
    if step == 0 {
        return Err(Error::Protocol("too many container assignments to rebalance".to_owned()));
    }
    Ok(object_refs
        .iter()
        .enumerate()
        .map(|(index, object_ref)| ContainerRebalanceAssignment {
            object_ref: object_ref.clone(),
            rank: format_rank(step * (index as u64 + 1)),
        })
        .collect())
}

fn parse_rank(rank: &str) -> Result<u64> {
    let raw = rank.strip_prefix("r:").unwrap_or(rank);
    if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Protocol(format!("invalid rank '{rank}'")));
    }
    u64::from_str_radix(raw, 16).map_err(|_| Error::Protocol(format!("invalid rank '{rank}'")))
}

fn format_rank(value: u64) -> String {
    format!("r:{value:016x}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OperationSignature {
    pub key_id: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum CapabilitySubject {
    Did(Did),
    Selector(Value),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityGrant {
    pub schema: String,
    pub id: GrantId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer: Did,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Value>,
    #[serde(default)]
    pub delegable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Policy {
    pub schema: String,
    pub id: PolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub policy_type: PolicyType,
    pub rules: Vec<PolicyRule>,
    pub default_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

/// Discriminator for a [`PolicyRule`] (mirrors `policy.schema.json`
/// `$defs.policy_rule.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    Action,
    Resource,
    Server,
    Actor,
    Temporal,
    RateLimit,
    Crypto,
    Moderation,
    Extension,
}

/// A single typed policy rule (mirrors `policy.schema.json`
/// `$defs.policy_rule`). `rule_id` / `kind` / `effect` are required; the
/// kind-specific fields (e.g. `actions` for `kind=action`) ride in `extra`
/// and are validated by [`PolicyRule::validate`]. This replaces the former
/// untyped `Vec<Value>` so callers can no longer build a rule that is
/// missing its required discriminators without the SDK noticing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    pub effect: PolicyEffect,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl PolicyRule {
    /// Validate the kind-conditional required fields that
    /// `policy.schema.json` enforces (e.g. `kind=action` MUST carry a
    /// non-empty `actions` array). Returns `Err(Error::Protocol(...))` on
    /// violation.
    pub fn validate(&self) -> Result<()> {
        if self.rule_id.trim().is_empty() {
            return Err(Error::Protocol("policy rule rule_id must not be empty".to_owned()));
        }
        let require = |field: &str| -> Result<()> {
            match self.extra.get(field) {
                Some(Value::Array(items)) if !items.is_empty() => Ok(()),
                Some(value) if !value.is_null() => Ok(()),
                _ => Err(Error::Protocol(format!(
                    "policy rule kind={:?} requires field '{field}'",
                    self.kind
                ))),
            }
        };
        match self.kind {
            PolicyRuleKind::Action => require("actions"),
            PolicyRuleKind::Resource => require("resources"),
            PolicyRuleKind::RateLimit => require("rate_limit"),
            PolicyRuleKind::Temporal => require("temporal"),
            // server / actor / crypto / moderation / extension have no
            // additional unconditional required field beyond the base triple.
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Invite {
    pub schema: String,
    pub id: InviteId,
    pub realm_id: RealmId,
    pub inviter: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_id: Option<Value>,
    pub join_rule_snapshot: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub state: InviteState,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursor {
    pub schema: String,
    pub id: ReadCursorId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadScope,
    pub position: ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

impl ReadCursor {
    /// Deserialize an inbound read cursor after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        canonical::from_canonical_json_slice(bytes)
    }
}

pub type ReadMarker = ReadCursor;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursorPosition {
    pub event_id: EventId,
    pub hlc: Hlc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub receipt_type: String,
    pub schema: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub read_scope: ReadScope,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub created_at: DateTime<Utc>,
}

impl ReadReceipt {
    /// Deserialize an inbound read receipt after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        canonical::from_canonical_json_slice(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Notification {
    pub schema: String,
    pub id: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<FlowId>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    pub source_event_id: EventId,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobMetadata {
    pub schema: String,
    pub blob_ref: BlobRef,
    pub content_digest: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub encryption: Value,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EncryptedPayload {
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<Value>,
    pub payload_digest: Hash,
    /// Reference to the key material that decrypts `ciphertext`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyRefObject>,
}

/// Typed `key_ref` per `media-and-blob.md` §encrypted-payload (B-22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyRefObject {
    pub algorithm: String,
    pub group_state_ref: String,
}

impl KeyRefObject {
    /// Build an MLS-RFC9420 typed `key_ref` from a group id and epoch.
    pub fn mls_rfc9420(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: EncryptedPayloadScheme::MlsRfc9420.as_str().to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&Value>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: EncryptedPayloadScheme::MlsRfc9420.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Ok(Hash::new(format!("sha256:{:x}", Sha256::digest(&input)))?)
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::mls_payload_digest(
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol("encrypted payload digest mismatch".to_owned()))
        }
    }

    /// Validate that the key reference, when present, is usable for lookup.
    pub fn validate_key_ref(&self) -> Result<()> {
        if let Some(key_ref) = &self.key_ref
            && key_ref.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol("key_ref.algorithm must not be empty".to_owned()));
        }
        if let Some(key_ref) = &self.key_ref
            && key_ref.group_state_ref.trim().is_empty()
        {
            return Err(Error::Protocol("key_ref.group_state_ref must not be empty".to_owned()));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a Value>,
}

/// Lifecycle of a published KeyPackage per `device-lifecycle.md` §2 /
/// `encryption-and-audit.md` §2.6. Once a KeyPackage is `claimed` it
/// MUST NOT be re-claimed; once `consumed` it MUST NOT return to
/// `published`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MlsKeyPackageState {
    #[default]
    Published,
    Claimed,
    Consumed,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsKeyPackageRecord {
    /// Globally unique identifier (`ck:mls:kp:<uuid>`, RFC 9562 UUIDv7).
    pub keypackage_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// MLS KeyPackage material (base64url).
    pub key_package: String,
    /// Canonical hash of `key_package`.
    pub keypackage_ref: Hash,
    pub cipher_suites: Vec<String>,
    /// Content / MLS profile capabilities (e.g. `mimi.content.v1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Lifecycle state.
    #[serde(default)]
    pub state: MlsKeyPackageState,
    /// Bound `claim_id` once `state = claimed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
}

impl MlsKeyPackageRecord {
    /// Schema id for `ck.mls.keypackage` events / records.
    pub const SCHEMA: &'static str = "ck.schema.mls_keypackage.v1";

    /// Whether the record is currently usable for a Welcome.
    pub fn is_usable(&self) -> bool {
        !matches!(self.state, MlsKeyPackageState::Revoked | MlsKeyPackageState::Consumed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsProposalEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub proposal_type: String,
    pub proposal: String,
    pub proposal_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

impl MlsProposalEnvelope {
    /// Build a repo operation that carries this MLS proposal.
    pub fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, realm_id, "mls_proposal", serde_json::to_value(self)?);
        operation.object_id =
            Some(format!("{}:{}:{}", self.group_id, self.epoch, self.proposal_type));
        Ok(operation)
    }
}

/// `cx_app_state_ref` MLS GroupContext extension
/// (encryption-and-audit.md / B-12).
///
/// Binds a Cokret Space's reduced state into the MLS GroupContext so
/// that any commit's signature transcript covers the application-layer
/// frontier. Carried as a private-use GroupContext extension at
/// codepoint [`MlsAppStateRef::CODEPOINT`] (within the IANA private
/// range `0xF000..=0xFFFF`).
///
/// CBOR encoding (canonical) — keys in registration order, no
/// indefinite-length items:
///
/// 1. `membership_frontier: bstr` — frontier state-hash
/// 2. `policy_root:        bstr` — Merkle root of policy events
/// 3. `capability_root:    bstr` — Merkle root of capability events
/// 4. `discussion_metadata_digest: bstr` — hash of discussion-track metadata
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsAppStateRef {
    /// Hex-encoded SHA-256 of the canonical state root.
    pub membership_frontier: String,
    pub policy_root: String,
    pub capability_root: String,
    pub discussion_metadata_digest: String,
}

impl MlsAppStateRef {
    /// IANA private-use codepoint chosen for `cx_app_state_ref`. The
    /// Cokret spec reserves it within the `[0xF000, 0xFFFF]` MLS
    /// extension private-use range; deployments MAY override via
    /// future negotiation but MUST stay inside the private range.
    pub const CODEPOINT: u16 = 0xCAFE;

    /// Encode as a deterministic CBOR map (per B-12 normative form).
    /// The output binds 1:1 to `Self::decode_cbor`.
    pub fn encode_cbor(&self) -> Vec<u8> {
        // Build a small canonical CBOR map by hand to avoid a runtime
        // dep just for one extension. Uses RFC 8949 deterministic
        // encoding for a 4-entry map of (uint key -> bstr value).
        fn put_uint(out: &mut Vec<u8>, n: u64) {
            if n < 24 {
                out.push(n as u8);
            } else if n <= u64::from(u8::MAX) {
                out.push(0x18);
                out.push(n as u8);
            } else if n <= u64::from(u16::MAX) {
                out.push(0x19);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else if n <= u64::from(u32::MAX) {
                out.push(0x1a);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            } else {
                out.push(0x1b);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        fn put_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
            // Major type 2 (byte string) — same length encoding as uints.
            let len = bytes.len() as u64;
            if len < 24 {
                out.push(0x40 | (len as u8));
            } else if len <= u64::from(u8::MAX) {
                out.push(0x58);
                out.push(len as u8);
            } else if len <= u64::from(u16::MAX) {
                out.push(0x59);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            } else if len <= u64::from(u32::MAX) {
                out.push(0x5a);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            } else {
                out.push(0x5b);
                out.extend_from_slice(&len.to_be_bytes());
            }
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(160);
        // Major type 5 (map) with 4 entries.
        out.push(0xa4);
        let entries: [(u64, &[u8]); 4] = [
            (1, self.membership_frontier.as_bytes()),
            (2, self.policy_root.as_bytes()),
            (3, self.capability_root.as_bytes()),
            (4, self.discussion_metadata_digest.as_bytes()),
        ];
        for (k, v) in entries {
            put_uint(&mut out, k);
            put_bstr(&mut out, v);
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsCommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub commit_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
    /// `cx_app_state_ref` GroupContext extension binding the
    /// application-layer Space frontier into the MLS transcript.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_state_ref: Option<MlsAppStateRef>,
}

impl MlsCommitEnvelope {
    /// Build a repo operation that carries this MLS commit.
    pub fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, realm_id, "mls_commit", serde_json::to_value(self)?);
        operation.object_id = Some(format!("{}:{}", self.group_id, self.epoch));
        Ok(operation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub welcome: String,
    pub welcome_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

impl MlsWelcomeEnvelope {
    /// Build a repo operation that records this MLS welcome delivery.
    pub fn operation(&self, operation_id: OperationId, realm_id: RealmId) -> Result<Operation> {
        let mut operation =
            Operation::create(operation_id, realm_id, "mls_welcome", serde_json::to_value(self)?);
        operation.object_id = Some(format!(
            "{}:{}:{}:{}",
            self.group_id, self.epoch, self.recipient_principal_id, self.recipient_device_id
        ));
        Ok(operation)
    }
}
