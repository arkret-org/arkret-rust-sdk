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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub canonical_event_digest: Option<String>,
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
            refs: Vec::new(),
            idempotency_key: None,
            created_at: Utc::now(),
            canonical_event_digest: None,
        }
    }

    pub fn operation_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(self)?)
    }

    /// Canonical acting-principal accessor for operation payloads.
    ///
    /// Resolves the actor DID from the payload object by probing the alias
    /// fields in this fixed priority order:
    /// `actor_id` → `sender` → `actor` → `member` → `subject` →
    /// `created_by` → `updated_by`. An alias only wins when its value is a
    /// string that parses as a syntactically valid DID ([`Did::new`]);
    /// non-string or malformed values are skipped and the next alias is
    /// tried. Returns `None` when no alias yields a valid DID.
    ///
    /// This is the single-source replacement for the three hand-written
    /// payload-actor extraction copies in soland; downstream crates MUST
    /// call this accessor instead of re-implementing the alias order.
    pub fn actor(&self) -> Option<Did> {
        const ACTOR_ALIASES: [&str; 7] = [
            "actor_id",
            "sender",
            "actor",
            "member",
            "subject",
            "created_by",
            "updated_by",
        ];
        let object = self.payload.as_object()?;
        for alias in ACTOR_ALIASES {
            if let Some(candidate) = object.get(alias).and_then(Value::as_str)
                && let Ok(did) = Did::new(candidate)
            {
                return Some(did);
            }
        }
        None
    }

    pub fn validate_payload_object(&self) -> Result<()> {
        if self.payload.is_object() {
            Ok(())
        } else {
            Err(Error::Protocol(
                "operation payload must be a JSON object".to_owned(),
            ))
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
    pub payload: Value,
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
        Ok(canonical::canonical_sha256(&self.digest_payload()?)?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "operation envelope proofs must contain at least one proof".to_owned(),
            ));
        }
        if !self.payload.is_object() {
            return Err(Error::Protocol(
                "operation envelope payload must be a JSON object".to_owned(),
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

    pub fn validate_proof_bindings_with_context(
        &self,
        domain: Option<String>,
        audience: Option<Audience>,
        requirements: ProofBindingRequirements,
    ) -> Result<()> {
        let expected_hash = Hash::new(self.operation_digest()?)?;
        for proof in &self.proofs {
            let expected = SignatureBindingPayload {
                payload_digest: expected_hash.clone(),
                actor_id: self.actor_id.clone(),
                verification_method: proof.verification_method.clone(),
                created_at: proof.created_at,
                domain: domain.clone(),
                audience: audience.clone(),
            };
            proof.validate_binding_with_requirements(&expected, requirements)?;
        }
        Ok(())
    }

    /// Materialize this SDK-local operation draft as a signed Event Envelope.
    ///
    /// Operation envelopes are not Arkret v1 wire facts. Callers must choose
    /// the event causal/auth references during conversion, then submit the
    /// returned [`Event`] to network, sync, federation or reducers.
    pub fn into_event_envelope(self, conversion: OperationEventConversion) -> Result<Event> {
        let mut event = Event::new(
            self.kind.clone(),
            self.realm_id,
            self.actor_id,
            self.causal.actor_seq,
            self.causal.hlc,
            self.payload,
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
            event
                .unsigned
                .insert("local_target_ref".to_owned(), Value::String(target_ref));
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

    pub fn with_authorized_by_ref(mut self, grant_id: GrantId) -> Self {
        self.refs.push(EventRef::authorized_by_grant(grant_id));
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
    payload: Value,
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
            payload: Value::Object(Default::default()),
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

    /// Replace the payload object.
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// Insert one payload field.
    pub fn with_payload_field(mut self, field: impl Into<String>, value: Value) -> Self {
        if !self.payload.is_object() {
            self.payload = Value::Object(Default::default());
        }
        if let Value::Object(payload) = &mut self.payload {
            payload.insert(field.into(), value);
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
    pub fn build(self, registry: &EventDraftKindRegistry) -> Result<OperationEnvelope> {
        let validation = registry.canonicalize(&self.kind)?;
        let envelope = OperationEnvelope {
            operation_id: self.operation_id,
            realm_id: self.realm_id,
            actor_id: self.actor_id,
            kind: validation.canonical_kind,
            target_ref: self.target_ref,
            causal: CausalRef {
                deps: self.deps,
                hlc: self.hlc,
                actor_seq: self.actor_seq,
            },
            payload: self.payload,
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

const RANK_ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const RANK_MAX_LEN: usize = 128;

pub fn rank_between(before: Option<&str>, after: Option<&str>) -> Result<String> {
    let left = before.unwrap_or("");
    let right = after.unwrap_or("");
    validate_rank_boundary(left)?;
    validate_rank_boundary(right)?;
    if !left.is_empty() && !right.is_empty() && left >= right {
        return Err(Error::Protocol(format!(
            "invalid rank interval '{left}'..'{right}'"
        )));
    }

    let mut prefix = String::new();
    let mut index = 0;
    while prefix.len() < RANK_MAX_LEN {
        let low = left
            .as_bytes()
            .get(index)
            .map(|byte| rank_value(*byte).expect("validated rank boundary"))
            .unwrap_or(-1);
        let high = if right.is_empty() {
            RANK_ALPHABET.len() as i16
        } else {
            right
                .as_bytes()
                .get(index)
                .map(|byte| rank_value(*byte).expect("validated rank boundary"))
                .unwrap_or(RANK_ALPHABET.len() as i16)
        };
        if high - low > 1 {
            let midpoint = ((low + high) / 2) as usize;
            prefix.push(RANK_ALPHABET[midpoint] as char);
            return Ok(prefix);
        }
        if let Some(byte) = left.as_bytes().get(index) {
            prefix.push(*byte as char);
        } else {
            prefix.push(RANK_ALPHABET[0] as char);
            if !right.is_empty() && prefix == right {
                return Err(Error::Protocol("rank interval is exhausted".to_owned()));
            }
            return Ok(prefix);
        }
        index += 1;
    }
    Err(Error::Protocol("rank interval is exhausted".to_owned()))
}

pub fn rank_exhausted(before: Option<&str>, after: Option<&str>) -> Result<bool> {
    match rank_between(before, after) {
        Ok(_) => Ok(false),
        Err(Error::Protocol(message)) if message == "rank interval is exhausted" => Ok(true),
        Err(error) => Err(error),
    }
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
    let count = object_refs.len() as u128;
    let denominator = count + 1;
    let required_capacity = denominator
        .checked_mul(2)
        .ok_or_else(|| Error::Protocol("too many container assignments to rebalance".to_owned()))?;
    let mut width = 0usize;
    let mut capacity = 1u128;
    while capacity < required_capacity {
        width += 1;
        if width > RANK_MAX_LEN {
            return Err(Error::Protocol(
                "too many container assignments to rebalance".to_owned(),
            ));
        }
        capacity = capacity
            .checked_mul(RANK_ALPHABET.len() as u128)
            .ok_or_else(|| {
                Error::Protocol("too many container assignments to rebalance".to_owned())
            })?;
    }
    object_refs
        .iter()
        .enumerate()
        .map(|(index, object_ref)| {
            let rank_number = (index as u128 + 1)
                .checked_mul(capacity)
                .map(|product| product / denominator)
                .ok_or_else(|| {
                    Error::Protocol("too many container assignments to rebalance".to_owned())
                })?;
            Ok(ContainerRebalanceAssignment {
                object_ref: object_ref.clone(),
                rank: format_rank_number(rank_number, width),
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn validate_rank_boundary(rank: &str) -> Result<()> {
    if rank.len() > RANK_MAX_LEN || !rank.bytes().all(|byte| rank_value(byte).is_some()) {
        return Err(Error::Protocol(format!("invalid rank '{rank}'")));
    }
    Ok(())
}

fn rank_value(byte: u8) -> Option<i16> {
    RANK_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as i16)
}

fn format_rank_number(mut value: u128, width: usize) -> String {
    let mut output = vec![RANK_ALPHABET[0]; width];
    for byte in output.iter_mut().rev() {
        *byte = RANK_ALPHABET[(value % RANK_ALPHABET.len() as u128) as usize];
        value /= RANK_ALPHABET.len() as u128;
    }
    String::from_utf8(output).expect("rank alphabet is valid UTF-8")
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

/// Grant constraint family discriminator from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintType {
    Temporal,
    FieldAccess,
    TypeRestriction,
    ScopeLimitation,
    DelegationControl,
    Quota,
    ClaimBased,
    Confidentiality,
}

/// Grant constraint effect from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

/// Optional specialization discriminator inside a grant constraint family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintSubtype {
    Claim,
    Approval,
    Accountability,
    Rate,
    Resource,
    Encryption,
    Visibility,
    Window,
    EditWindow,
    RedactWindow,
    Session,
}

/// Quota counting scope from `grant-constraint.schema.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintScope {
    PerActor,
    PerSpace,
    PerRealm,
    Global,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintRecurrenceFrequency {
    Daily,
    Weekly,
    Monthly,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintRecurrenceDay {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// Recurrence rule for temporal grant constraints.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GrantConstraintRecurrence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency: Option<GrantConstraintRecurrenceFrequency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<GrantConstraintRecurrenceDay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Named condition predicate for grant constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintConditionKind {
    ObjectIsOwnedByActor,
    ActorIsAssignee,
    ActorIsResponsible,
    ActorIsGuardian,
    ActorIsController,
    ObjectInActorContainer,
    ObjectIsUnencrypted,
    ObjectIsEncrypted,
    Always,
    Never,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GrantConstraintCondition {
    pub kind: GrantConstraintConditionKind,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantConstraintSensitiveHandling {
    Redact,
    Hash,
    Omit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantApprovalRelation {
    Responsible,
    Controller,
    Guardian,
    RealmAdmin,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantApprovalThreshold {
    Majority,
    Unanimous,
    Quorum,
    Custom,
}

/// Conditional claim requirement in a grant constraint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GrantConstraintClaimRequirement {
    pub claim_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_matches_actor: Option<bool>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value_constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BlobPresignPurpose {
    MediaInline,
    Thumbnail,
    Download,
}

/// Scope limiter for blob presign grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BlobPresignScope {
    pub allowed_purposes: Vec<BlobPresignPurpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_ref_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub realm_ids: Vec<RealmId>,
}

/// Schema extension key for grant constraints.
///
/// `grant-constraint.schema.json` only allows top-level extension fields
/// matching `^x_[a-z][a-z0-9_]{0,63}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GrantConstraintExtensionKey(String);

impl GrantConstraintExtensionKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if grant_constraint_extension_key_is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(Error::Protocol(format!(
                "invalid grant constraint extension key '{value}'"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Serialize for GrantConstraintExtensionKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GrantConstraintExtensionKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if grant_constraint_extension_key_is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid grant constraint extension key '{value}'"
            )))
        }
    }
}

fn grant_constraint_extension_key_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3 || bytes.len() > 66 || bytes[0] != b'x' || bytes[1] != b'_' {
        return false;
    }
    if !bytes[2].is_ascii_lowercase() {
        return false;
    }
    bytes[3..]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Strong wire DTO for `grant-constraint.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct GrantConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_id: Option<String>,
    pub constraint_type: GrantConstraintType,
    pub effect: GrantConstraintEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_class: Option<EvaluationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<GrantConstraintSubtype>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<GrantConstraintRecurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_edit_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_redact_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_redact_after_window: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<GrantConstraintCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_write_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_read_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_read_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive_handling: Option<GrantConstraintSensitiveHandling>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_object_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_morph_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_space_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_space_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_facets: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_strand_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_strand_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_space_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_space_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_ids: Vec<CircleId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_session_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_view_renderers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_view_renderers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_relation_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_from_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_to_container_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_limit_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tracks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_tracks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_presign_scope: Option<BlobPresignScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_path: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prohibit_subdelegation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_scope_expansion: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_parent_reference: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_presign_max_ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_blob_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_scope: Option<GrantConstraintScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_resources: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalWorkflowMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_actor_ids: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_relation: Option<GrantApprovalRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reject_on_timeout: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_morph_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_threshold: Option<GrantApprovalThreshold>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_claims: Vec<GrantConstraintClaimRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_claim_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_refresh_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_max_age: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_history_visibility_values: Vec<HistoryVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_redacted_history: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_encryption_level: Option<EncryptionProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_fallback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_audit_trail: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rotation_period: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_key_age: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_key_backup: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_key_issuers: Vec<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on_moderation_state: Option<bool>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default, flatten, skip_serializing_if = "XExtensionMap::is_empty")]
    pub extensions: XExtensionMap,
}

impl GrantConstraint {
    pub fn new(constraint_type: GrantConstraintType, effect: GrantConstraintEffect) -> Self {
        Self {
            constraint_id: None,
            constraint_type,
            effect,
            evaluation_class: None,
            subtype: None,
            applies_to_actions: Vec::new(),
            not_before: None,
            expires_at: None,
            recurrence: None,
            max_duration: None,
            max_session_duration: None,
            inactivity_timeout: None,
            expires_after: None,
            message_edit_window: None,
            message_redact_window: None,
            allow_redact_after_window: None,
            condition: None,
            allowed_write_fields: Vec::new(),
            denied_write_fields: Vec::new(),
            allowed_read_fields: Vec::new(),
            denied_read_fields: Vec::new(),
            sensitive_fields: Vec::new(),
            sensitive_handling: None,
            allowed_object_types: Vec::new(),
            denied_object_types: Vec::new(),
            allowed_morph_types: Vec::new(),
            denied_morph_types: Vec::new(),
            allowed_space_kinds: Vec::new(),
            denied_space_kinds: Vec::new(),
            allowed_facets: Vec::new(),
            denied_facets: Vec::new(),
            allowed_view_ids: Vec::new(),
            allowed_strand_ids: Vec::new(),
            denied_strand_ids: Vec::new(),
            allowed_space_ids: Vec::new(),
            denied_space_ids: Vec::new(),
            allowed_circle_ids: Vec::new(),
            allowed_session_ids: Vec::new(),
            allowed_view_kinds: Vec::new(),
            allowed_view_renderers: Vec::new(),
            denied_view_kinds: Vec::new(),
            denied_view_renderers: Vec::new(),
            allowed_relation_kinds: Vec::new(),
            allowed_from_container_refs: Vec::new(),
            allowed_to_container_refs: Vec::new(),
            wip_limit_override: None,
            allowed_tracks: Vec::new(),
            denied_tracks: Vec::new(),
            blob_presign_scope: None,
            allowed_data_classes: Vec::new(),
            allowed_endpoints: Vec::new(),
            max_delegation_depth: None,
            delegation_path: Vec::new(),
            prohibit_subdelegation: None,
            delegation_scope: None,
            allow_scope_expansion: None,
            require_parent_reference: None,
            blob_max_bytes: None,
            blob_presign_max_ttl_seconds: None,
            max_total_blob_bytes: None,
            max_artifact_bytes: None,
            max_operations: None,
            period: None,
            burst: None,
            constraint_scope: None,
            max_resources: None,
            resource_type: None,
            approval_required: None,
            approval_mode: None,
            approval_actor_ids: Vec::new(),
            approval_relation: None,
            timeout: None,
            auto_reject_on_timeout: None,
            proposal_morph_type: None,
            approval_threshold: None,
            approvers: Vec::new(),
            accountability_required: None,
            guardian_approval_required: None,
            controller_approval_required: None,
            requires_claims: Vec::new(),
            trusted_claim_issuers: Vec::new(),
            claim_refresh_required: None,
            claim_max_age: None,
            allowed_history_visibility_values: Vec::new(),
            deny_redacted_history: None,
            encryption_required: None,
            min_encryption_level: None,
            allow_plaintext_fallback: None,
            require_audit_trail: None,
            key_rotation_period: None,
            max_key_age: None,
            require_key_backup: None,
            approved_key_issuers: Vec::new(),
            depends_on_moderation_state: None,
            extensions: XExtensionMap::default(),
        }
    }

    pub fn delegation_control(max_delegation_depth: u64, prohibit_subdelegation: bool) -> Self {
        let mut constraint = Self::new(
            GrantConstraintType::DelegationControl,
            GrantConstraintEffect::Allow,
        );
        constraint.max_delegation_depth = Some(max_delegation_depth);
        constraint.prohibit_subdelegation = Some(prohibit_subdelegation);
        constraint
    }

    /// Schema-aligned scaffold examples for approval, claim, and container-move constraints.
    pub fn scaffold_examples() -> Vec<Self> {
        let mut approval = Self::new(
            GrantConstraintType::ClaimBased,
            GrantConstraintEffect::RequireReview,
        );
        approval.subtype = Some(GrantConstraintSubtype::Approval);
        approval.denied_write_fields = vec!["assignee".to_owned(), "status".to_owned()];
        approval.allowed_object_types = vec!["strand".to_owned()];
        approval.allowed_view_ids = vec!["ak:view:01904100-0000-7000-8000-b74ef68eeddf".to_owned()];
        approval.allowed_relation_kinds = vec!["responsible".to_owned()];
        approval.wip_limit_override = Some(false);
        approval.denied_view_kinds = vec!["public_board".to_owned()];
        approval.allowed_tracks = vec!["discussion".to_owned()];
        approval.max_delegation_depth = Some(1);
        approval.approval_required = Some(true);
        approval.approval_mode = Some(ApprovalWorkflowMode::BeforeCommit);
        approval.approval_actor_ids = vec![
            Did::new("did:webvh:z6mkfixture:controller.example").expect("scaffold DID is valid"),
            Did::new("did:webvh:z6mkfixture:guardian.example").expect("scaffold DID is valid"),
        ];
        approval.approval_relation = Some(GrantApprovalRelation::Controller);

        let mut claim = Self::new(
            GrantConstraintType::ClaimBased,
            GrantConstraintEffect::Allow,
        );
        claim.subtype = Some(GrantConstraintSubtype::Claim);
        claim.allowed_object_types = vec!["key_backup".to_owned()];
        claim.allowed_facets = vec![Facet::Reviewable];
        claim.max_delegation_depth = Some(0);
        claim.approval_required = Some(false);
        claim.requires_claims = vec![GrantConstraintClaimRequirement {
            claim_type: "recovery_operator".to_owned(),
            issuer: Some(
                Did::new("did:webvh:z6mkfixture:coauth.example").expect("scaffold DID is valid"),
            ),
            trusted_issuers: Vec::new(),
            subject_matches_actor: None,
            value_constraints: BTreeMap::new(),
            organization: Some(
                Did::new("did:webvh:z6mkfixture:example-org").expect("scaffold DID is valid"),
            ),
            status: Some("active".to_owned()),
            roles: vec!["backup_admin".to_owned()],
            extra: BTreeMap::new(),
        }];

        let mut container_move = Self::new(
            GrantConstraintType::ScopeLimitation,
            GrantConstraintEffect::Deny,
        );
        container_move.allowed_object_types = vec!["strand".to_owned()];
        container_move.allowed_from_container_refs = vec!["ak:list:triage".to_owned()];
        container_move.allowed_to_container_refs = vec!["ak:list:ready".to_owned()];
        container_move.wip_limit_override = Some(false);
        container_move.allowed_tracks = vec!["synthesis".to_owned()];
        container_move.denied_tracks = vec!["discussion".to_owned()];
        container_move.max_delegation_depth = Some(0);
        container_move.approval_required = Some(true);
        container_move.approval_mode = Some(ApprovalWorkflowMode::ProposalThenApprove);
        container_move.approval_actor_ids =
            vec![Did::new("did:webvh:z6mkfixture:ops.example").expect("scaffold DID is valid")];
        container_move.approval_relation = Some(GrantApprovalRelation::Responsible);

        vec![approval, claim, container_move]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CapabilityGrant {
    pub id: GrantId,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub issuer: Did,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<WireResourceSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_action_registry_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<GrantId>,
    #[serde(
        serialize_with = "crate::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub proofs: Vec<PayloadProof>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
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
    pub extra: XExtensionMap,
}

impl PolicyRule {
    /// Validate the kind-conditional required fields that
    /// `policy.schema.json` enforces (e.g. `kind=action` MUST carry a
    /// non-empty `actions` array). Returns `Err(Error::Protocol(...))` on
    /// violation.
    pub fn validate(&self) -> Result<()> {
        if self.rule_id.trim().is_empty() {
            return Err(Error::Protocol(
                "policy rule rule_id must not be empty".to_owned(),
            ));
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

/// Invite object. Mirrors `invite.schema.json` (required: `id`, `schema`,
/// `realm_id`, `inviter`, `join_rule_snapshot`, `state`, `expires_at`,
/// `created_at`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Invite {
    pub id: InviteId,
    pub schema: String,
    pub realm_id: RealmId,
    pub inviter: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<Did>,
    /// Public durable target for private invite delivery (required by the
    /// schema `allOf` when `invitee` is set without `third_party_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_delivery_target: Option<InviteDeliveryTarget>,
    /// Digest of the private invite delivery `introduction_evidence`. Raw
    /// locator tokens MUST NOT appear in durable Realm events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduction_evidence_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_id: Option<ThirdPartyInvite>,
    pub join_rule_snapshot: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    pub state: InviteState,
    /// Required by `invite.schema.json` — every invite carries a hard expiry.
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Reducer-derived actor that produced the most recent state update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursor {
    pub id: ReadCursorId,
    pub schema: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

impl ReadCursor {
    /// Deserialize an inbound read cursor after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }
}

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
pub struct ReadCursorAdvanceRequestBody {
    pub realm_id: RealmId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadMarkerOutcome {
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub read_scope: ReadCursorScope,
    pub position: ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadCursorList {
    #[serde(default)]
    pub markers: Vec<ReadMarkerOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadReceipt {
    pub receipt_type: String,
    pub schema: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<Hlc>,
    pub read_scope: ReadReceiptScope,
    pub created_at: DateTime<Utc>,
}

impl ReadReceipt {
    /// Deserialize an inbound read receipt after canonical JSON ingress checks.
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
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
    pub strand_id: Option<StrandId>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    pub source_event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<BTreeMap<String, Value>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobMetadata {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub blob_ref: BlobRef,
    pub content_digest: String,
    /// Spec rename (head 37ce729): `size` → `size_bytes` on blob/media metadata.
    pub size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub encryption: Option<EncryptedAttachment>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
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
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub aad: Option<EncryptedEnvelopeAad>,
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

    /// Build an MLS-EXPORTER-AEAD typed `key_ref` (§2.10) from a group id and
    /// epoch. The `algorithm` token `MLS-EXPORTER-AEAD` is bound by the
    /// `encrypted-envelope.schema.json` if/then to `scheme=mls-exporter-aead-v1`.
    pub fn mls_exporter_aead(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: "MLS-EXPORTER-AEAD".to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        Self::payload_digest_for_scheme(
            EncryptedPayloadScheme::MlsRfc9420,
            epoch,
            content_type,
            aad,
            ciphertext_bytes,
        )
    }

    /// §2.3.3 content payload digest, parameterized by `scheme`. The digest binds
    /// the `scheme` token into the metadata (`encryption` field) so a payload
    /// authored under `mls-exporter-aead-v1` (§2.10) and one under `mls-rfc9420`
    /// never collide, and the receiver's verification is scheme-bound.
    /// `ciphertext_bytes` are the raw decoded ciphertext bytes (for
    /// `mls-exporter-aead-v1` that is the `nonce || AEAD_ct` blob).
    pub fn payload_digest_for_scheme(
        scheme: EncryptedPayloadScheme,
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: scheme.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::payload_digest_for_scheme(
            self.scheme.clone(),
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted payload digest mismatch".to_owned(),
            ))
        }
    }

    /// Validate that the key reference, when present, is usable for lookup.
    pub fn validate_key_ref(&self) -> Result<()> {
        if let Some(key_ref) = &self.key_ref
            && key_ref.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.algorithm must not be empty".to_owned(),
            ));
        }
        if let Some(key_ref) = &self.key_ref
            && key_ref.group_state_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.group_state_ref must not be empty".to_owned(),
            ));
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
    pub aad: Option<&'a EncryptedEnvelopeAad>,
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
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsKeyPackageRecord {
    /// Globally unique identifier (`ak:mls:kp:<uuid>`, RFC 9562 UUIDv7).
    pub keypackage_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// MLS KeyPackage material (base64url).
    pub key_package: String,
    /// Canonical hash of `key_package`.
    pub keypackage_ref: Hash,
    pub cipher_suites: Vec<String>,
    /// Content / MLS profile capabilities (e.g. `mimi.content.v1`).
    #[serde(default)]
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
    /// Whether this is a reusable last-resort KeyPackage. Last-resort
    /// KeyPackages are NOT consumed on claim (the server keeps them
    /// claimable), so a member is always (re-)addable even after its
    /// single-use KeyPackages are exhausted. The init-key forward-secrecy
    /// trade-off is the standard MLS last-resort guarantee. The KeyPackage
    /// material MUST itself carry the OpenMLS `last_resort` extension (built
    /// via `mark_as_last_resort`) so the holder retains the init private key
    /// across repeated Welcome processing.
    #[serde(default)]
    pub last_resort: bool,
}

impl MlsKeyPackageRecord {
    /// Schema id for `ak.mls.keypackage` events / records.
    pub const SCHEMA: &'static str = "ak.schema.mls_keypackage.v1";

    /// Whether the record is currently usable for a Welcome.
    pub fn is_usable(&self) -> bool {
        !matches!(
            self.state,
            MlsKeyPackageState::Revoked
                | MlsKeyPackageState::Consumed
                | MlsKeyPackageState::Expired
        )
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
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_proposal",
            serde_json::to_value(self)?,
        );
        operation.object_id = Some(format!(
            "{}:{}:{}",
            self.group_id, self.epoch, self.proposal_type
        ));
        Ok(operation)
    }
}

/// `cx_app_state_ref` MLS GroupContext extension
/// (encryption-and-audit.md / B-12).
///
/// Binds a Arkret Space's reduced state into the MLS GroupContext so
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
    /// Arkret spec reserves it within the `[0xF000, 0xFFFF]` MLS
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
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_commit",
            serde_json::to_value(self)?,
        );
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
        let mut operation = Operation::create(
            operation_id,
            realm_id,
            "mls_welcome",
            serde_json::to_value(self)?,
        );
        operation.object_id = Some(format!(
            "{}:{}:{}:{}",
            self.group_id, self.epoch, self.recipient_principal_id, self.recipient_device_id
        ));
        Ok(operation)
    }
}

#[cfg(test)]
mod actor_accessor_tests {
    use serde_json::json;

    use super::*;

    fn operation_with_payload(payload: Value) -> Operation {
        Operation::create(
            OperationId::new("ak:operation:01904100-0000-7000-8000-000000000001").unwrap(),
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            "message",
            payload,
        )
    }

    #[test]
    fn actor_resolves_aliases_in_priority_order() {
        let operation = operation_with_payload(json!({
            "sender": "did:webvh:QmScid:bob.example",
            "actor_id": "did:webvh:QmScid:alice.example",
        }));
        assert_eq!(
            operation.actor().unwrap().as_str(),
            "did:webvh:QmScid:alice.example",
        );
    }

    #[test]
    fn actor_skips_aliases_that_are_not_valid_dids() {
        let operation = operation_with_payload(json!({
            "actor_id": "not-a-did",
            "sender": 42,
            "member": "did:webvh:QmScid:carol.example",
        }));
        assert_eq!(
            operation.actor().unwrap().as_str(),
            "did:webvh:QmScid:carol.example",
        );
    }

    #[test]
    fn actor_returns_none_without_any_alias() {
        let operation = operation_with_payload(json!({"body": "hello"}));
        assert!(operation.actor().is_none());
        let non_object = operation_with_payload(json!("string payload"));
        assert!(non_object.actor().is_none());
    }

    #[test]
    fn capability_grant_serializes_all_timestamps_canonically() {
        let fractional = DateTime::parse_from_rfc3339("2026-07-14T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        let grant = CapabilityGrant {
            id: GrantId::new("ak:grant:01904100-0000-7000-8000-000000000001").unwrap(),
            schema: "ak.schema.capability.v1".to_owned(),
            realm_id: Some(RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()),
            issuer: Did::new("did:web:issuer.example").unwrap(),
            subject: CapabilitySubject::Did(Did::new("did:web:subject.example").unwrap()),
            actions: vec!["ak.event.read".to_owned()],
            resources: vec![serde_json::from_value(json!({"kind": "realm"})).unwrap()],
            capability_action_registry_digest: None,
            constraints: Vec::new(),
            parent_grant_id: None,
            issued_at: fractional,
            not_before: Some(fractional),
            expires_at: Some(fractional),
            updated_by: None,
            updated_at: Some(fractional),
            revoked_by: None,
            revoked_at: Some(fractional),
            proofs: vec![PayloadProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:issuer.example#key-1".to_owned(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: fractional,
                domain: None,
                audience: None,
                proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
                jws: "header..signature".to_owned(),
            }],
        };

        let wire = serde_json::to_value(grant).unwrap();
        for pointer in [
            "/issued_at",
            "/not_before",
            "/expires_at",
            "/updated_at",
            "/revoked_at",
            "/proofs/0/created_at",
        ] {
            assert_eq!(
                wire.pointer(pointer).and_then(Value::as_str),
                Some("2026-07-14T12:34:56Z")
            );
        }
    }
}
