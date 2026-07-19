pub use arkret_models_collaboration::governance::grant_constraint::*;
pub use arkret_models_collaboration::governance::operation_wire::*;
pub use arkret_models_collaboration::objects::read_receipts::*;

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

pub use arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsKeyPackageState;

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
}
