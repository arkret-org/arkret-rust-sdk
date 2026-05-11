use super::*;

pub const EVENT_REF_ROLE_AUTHORIZED_BY: &str = "authorized_by";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_event_ref_critical")]
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl EventRef {
    pub fn new(id: impl Into<String>, role: impl Into<String>) -> Self {
        Self { id: id.into(), role: role.into(), critical: true, proof: None }
    }

    pub fn authorized_by(event_id: EventId) -> Self {
        Self::new(event_id.to_string(), EVENT_REF_ROLE_AUTHORIZED_BY)
    }
}

fn default_event_ref_critical() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Event {
    pub event_id: EventId,
    pub kind: String,
    pub space_id: SpaceId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    #[serde(default)]
    pub refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_profile_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reducer_profile_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub critical_extensions: Vec<CriticalExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    #[serde(rename = "payload")]
    pub content: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

impl Event {
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
            map.remove("unsigned");
        }
        Ok(value)
    }

    pub fn event_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol("event proofs must contain at least one proof".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("event content must be a JSON object".to_owned()));
        }
        if self.critical_extensions.iter().any(|extension| !extension.fail_closed) {
            return Err(Error::Protocol(
                "event critical extensions must declare fail_closed=true".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that all proofs bind to this event's digest.
    ///
    /// Checks each proof's `payload_hash` matches the canonical event digest,
    /// and that each proof is structurally valid.
    pub fn validate_proof_bindings(&self) -> Result<()> {
        let digest = self.event_digest()?;
        let expected_hash = Hash::new(digest)?;
        for proof in &self.proofs {
            proof.validate()?;
            if proof.payload_hash != expected_hash {
                return Err(Error::Protocol(format!(
                    "event proof payload_hash '{}' does not match event digest '{}'",
                    proof.payload_hash, expected_hash
                )));
            }
        }
        Ok(())
    }

    pub fn new(
        kind: impl Into<String>,
        space_id: SpaceId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        content: Value,
    ) -> Result<Self> {
        Ok(Self {
            event_id: EventId::new(new_prefixed_uuid7("cx:event:"))?,
            kind: kind.into(),
            space_id,
            actor_id,
            actor_seq,
            created_at: Utc::now(),
            hlc,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            schema_profile_refs: Vec::new(),
            reducer_profile_ref: None,
            required_features: Vec::new(),
            critical_extensions: Vec::new(),
            redacts: None,
            content,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        })
    }
}

/// Canonical signed Event Envelope wire model.
pub type EventEnvelope = Event;
