use super::*;

/// State snapshot at a specific point in time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub realm_id: RealmId,
    pub reducer_profile: String,
    pub frontier: Vec<EventId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subjects: BTreeMap<String, Flow>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub morphs: BTreeMap<String, Morph>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<String, Space>,
    pub relations: BTreeMap<String, Relation>,
    pub resolved_state: BTreeMap<String, ResolvedStateEvent>,
    pub messages: BTreeMap<String, ResolvedMessage>,
    pub reactions: BTreeMap<String, ResolvedReaction>,
    pub state_digest: String,
    pub snapshot_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ReducerSnapshotManifest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReducerSnapshotManifest {
    pub schema: String,
    pub reducer_profile: String,
    pub realm_id: RealmId,
    pub frontier: Vec<EventId>,
    pub state_digest: String,
    pub merkle_root: String,
    pub chunk_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<SnapshotChunkManifest>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SnapshotSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunkManifest {
    pub index: u32,
    pub digest: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotSignature {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub signature: String,
}

impl SnapshotSignature {
    pub fn manifest_binding_payload(
        &self,
        manifest: &ReducerSnapshotManifest,
    ) -> Result<SnapshotSignatureBindingPayload> {
        Ok(SnapshotSignatureBindingPayload {
            payload_digest: canonical_sha256(&manifest.signature_payload())?,
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotSignatureBindingPayload {
    pub payload_digest: String,
    pub verification_method: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotRestoreSource {
    Snapshot,
    RepoReplay,
}

#[derive(Clone, Debug)]
pub struct SnapshotRestore {
    pub state: RealmState,
    pub source: SnapshotRestoreSource,
    pub snapshot_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedStateEvent {
    pub kind: String,
    /// Cell subject derived from the event's typed payload per the spec
    /// event-kind-registry's `cell_subject`. Empty string for singleton
    /// kinds.
    pub subject: String,
    pub source_event_id: EventId,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: crate::Hlc,
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedMessage {
    pub message_id: String,
    pub source_event_id: EventId,
    pub latest_event_id: EventId,
    pub created_by: Did,
    pub latest_actor_id: Did,
    pub latest_actor_seq: u64,
    pub latest_hlc: crate::Hlc,
    pub content: Value,
    pub revision_event_ids: Vec<EventId>,
    pub redacted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedReaction {
    pub message_id: String,
    pub actor_id: Did,
    pub reaction_key: String,
    pub source_event_id: EventId,
    pub actor_seq: u64,
    pub hlc: crate::Hlc,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub key: String,
    pub winner_event_id: EventId,
    pub loser_event_id: EventId,
    pub reason: String,
}

pub(super) fn membership_rank(content: &Value) -> u8 {
    match content.get("membership").and_then(Value::as_str) {
        Some("ban") => 4,
        Some("leave") => 3,
        Some("invite") => 2,
        Some("join") => 1,
        _ => 0,
    }
}

pub(super) fn object_state_from_str(state: &str) -> Result<crate::ObjectState> {
    // C47 (spec e10b6ad): `deleted` is no longer a valid lifecycle state for
    // Flow / Morph; the only terminal state is `redacted`. Receivers MUST
    // reject the legacy `deleted` literal.
    match state {
        "active" => Ok(crate::ObjectState::Active),
        "archived" => Ok(crate::ObjectState::Archived),
        "redacted" => Ok(crate::ObjectState::Redacted),
        _ => Err(Error::Protocol(format!("invalid state: {}", state))),
    }
}

pub(super) fn space_state_from_str(state: &str) -> Result<crate::model::SpaceState> {
    match state {
        "active" => Ok(crate::model::SpaceState::Active),
        "archived" => Ok(crate::model::SpaceState::Archived),
        "tombstoned" => Ok(crate::model::SpaceState::Tombstoned),
        _ => Err(Error::Protocol(format!("invalid space state: {}", state))),
    }
}

pub(super) fn patch_string(patch: &Option<BTreeMap<String, Value>>, field: &str) -> Option<String> {
    patch.as_ref()?.get(field)?.as_str().map(ToOwned::to_owned)
}

pub(super) fn patch_fields(
    patch: &Option<BTreeMap<String, Value>>,
) -> Option<BTreeMap<String, Value>> {
    serde_json::from_value(patch.as_ref()?.get("fields")?.clone()).ok()
}

pub(super) fn patch_state(
    patch: &Option<BTreeMap<String, Value>>,
) -> Option<Result<crate::ObjectState>> {
    patch_string(patch, "state").map(|state| object_state_from_str(&state))
}

pub(super) fn canonicalize_flow_ref(value: &str) -> String {
    value.to_owned()
}

impl StateSnapshot {
    /// Verify the state hash.
    pub fn verify_hash(&self) -> Result<bool> {
        Ok(self.compute_state_digest()? == self.state_digest)
    }

    pub fn compute_state_digest(&self) -> Result<String> {
        canonical_sha256(&self.state_payload())
    }

    pub fn state_merkle_root(&self) -> Result<String> {
        state_merkle_root(&self.state_payload())
    }

    pub fn canonical_snapshot_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&self.state_payload())
    }

    pub fn chunk_manifest(&self, chunk_size: usize) -> Result<Vec<SnapshotChunkManifest>> {
        if chunk_size == 0 {
            return Err(Error::Protocol(
                "snapshot chunk size must be greater than zero".to_owned(),
            ));
        }
        let bytes = self.canonical_snapshot_bytes()?;
        Ok(bytes
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, chunk)| SnapshotChunkManifest {
                index: index as u32,
                digest: sha256_digest(chunk),
                byte_len: chunk.len(),
            })
            .collect())
    }

    pub fn manifest(&self) -> ReducerSnapshotManifest {
        let merkle_root = self
            .state_merkle_root()
            .unwrap_or_else(|_| sha256_digest(format!("{:?}", self.frontier)));
        ReducerSnapshotManifest {
            schema: REDUCER_SNAPSHOT_SCHEMA.to_owned(),
            reducer_profile: self.reducer_profile.clone(),
            realm_id: self.realm_id.clone(),
            frontier: self.frontier.clone(),
            state_digest: self.state_digest.clone(),
            merkle_root,
            chunk_count: 0,
            chunks: Vec::new(),
            created_at: self.snapshot_timestamp,
            signatures: Vec::new(),
        }
    }

    pub fn manifest_with_chunks(&self, chunk_size: usize) -> Result<ReducerSnapshotManifest> {
        let chunks = self.chunk_manifest(chunk_size)?;
        let mut manifest = self.manifest();
        manifest.chunk_count = chunks.len() as u32;
        manifest.chunks = chunks;
        Ok(manifest)
    }

    pub fn verify(&self) -> Result<()> {
        if !self.verify_hash()? {
            return Err(Error::Protocol("snapshot state hash mismatch".to_owned()));
        }
        let actual_root = self.state_merkle_root()?;
        if let Some(manifest) = &self.manifest {
            manifest.verify_against_snapshot(self, &actual_root)?;
        }
        Ok(())
    }

    fn state_payload(&self) -> Value {
        state_digest_payload(StateHashInput {
            realm_id: &self.realm_id,
            reducer_profile: &self.reducer_profile,
            frontier: &self.frontier,
            subjects: &self.subjects,
            morphs: &self.morphs,
            spaces: &self.spaces,
            relations: &self.relations,
            resolved_state: &self.resolved_state,
            messages: &self.messages,
            reactions: &self.reactions,
            tombstone_event_id: &self.tombstone_event_id,
        })
    }
}

impl ReducerSnapshotManifest {
    pub fn verify_against_snapshot(
        &self,
        snapshot: &StateSnapshot,
        actual_merkle_root: &str,
    ) -> Result<()> {
        if self.schema != REDUCER_SNAPSHOT_SCHEMA {
            return Err(Error::Protocol("snapshot manifest schema mismatch".to_owned()));
        }
        if self.reducer_profile != REDUCER_SNAPSHOT_PROFILE {
            return Err(Error::Protocol("snapshot manifest reducer profile mismatch".to_owned()));
        }
        if self.realm_id != snapshot.realm_id
            || self.reducer_profile != snapshot.reducer_profile
            || self.frontier != snapshot.frontier
            || self.state_digest != snapshot.state_digest
        {
            return Err(Error::Protocol("snapshot manifest does not match snapshot".to_owned()));
        }
        if self.merkle_root != actual_merkle_root {
            return Err(Error::Protocol("snapshot manifest merkle root mismatch".to_owned()));
        }
        if self.chunk_count as usize != self.chunks.len() {
            return Err(Error::Protocol("snapshot manifest chunk count mismatch".to_owned()));
        }
        Ok(())
    }

    pub fn verify_chunks<I, B>(&self, chunks: I) -> Result<()>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let chunks: Vec<B> = chunks.into_iter().collect();
        if chunks.len() != self.chunks.len() {
            return Err(Error::Protocol("snapshot chunk count mismatch".to_owned()));
        }
        for (expected, chunk) in self.chunks.iter().zip(chunks.iter()) {
            let chunk = chunk.as_ref();
            if expected.byte_len != chunk.len() {
                return Err(Error::Protocol(format!(
                    "snapshot chunk {} length mismatch",
                    expected.index
                )));
            }
            let actual = sha256_digest(chunk);
            if expected.digest != actual {
                return Err(Error::Protocol(format!(
                    "snapshot chunk {} digest mismatch",
                    expected.index
                )));
            }
        }
        Ok(())
    }

    pub fn signature_payload(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Value::Object(map) = &mut value {
            map.remove("signatures");
        }
        value
    }
}

pub fn verify_snapshot_chunks<I, B>(manifest: &ReducerSnapshotManifest, chunks: I) -> Result<()>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    manifest.verify_chunks(chunks)
}

/// One step in a Merkle inclusion proof. `is_left == true` means the
/// sibling hash is the **left** child (so the running hash is the
/// right one for the next level).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling: String,
    pub is_left: bool,
}

/// Verify that `event_id`'s canonical leaf hash is a member of the
/// Merkle tree rooted at `root` per `operations-sync.md` §11.
///
/// The proof is the bottom-up sibling chain from the leaf to the root.
/// At each step the running hash and the sibling are combined into the
/// canonical inner-node payload `{ "left": .., "right": .. }`, matching
/// [`merkle_root`].
pub fn verify_snapshot_inclusion(
    event_id: &str,
    proof: &[MerkleProofStep],
    root: &str,
) -> Result<()> {
    let leaf_hash = canonical_sha256(&serde_json::json!({
        "key": event_id,
        "value": event_id,
    }))?;
    let mut running = leaf_hash;
    for step in proof {
        let (left, right) = if step.is_left {
            (step.sibling.as_str(), running.as_str())
        } else {
            (running.as_str(), step.sibling.as_str())
        };
        running = canonical_sha256(&serde_json::json!({
            "left": left,
            "right": right,
        }))?;
    }
    if running == root {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "snapshot inclusion proof for '{event_id}' does not match Merkle root '{root}'"
        )))
    }
}

pub fn state_merkle_root(payload: &Value) -> Result<String> {
    let Value::Object(map) = payload else {
        return Err(Error::Protocol("state merkle payload must be an object".to_owned()));
    };
    let leaves = map
        .iter()
        .map(|(key, value)| {
            canonical_sha256(&serde_json::json!({
                "key": key,
                "value": value,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    merkle_root(leaves)
}

pub fn merkle_root(mut leaves: Vec<String>) -> Result<String> {
    if leaves.is_empty() {
        return Ok(sha256_digest([]));
    }
    leaves.sort();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(canonical_sha256(&serde_json::json!({
                "left": pair[0],
                "right": right,
            }))?);
        }
        leaves = next;
    }
    Ok(leaves.remove(0))
}

pub(super) struct StateHashInput<'a> {
    pub(super) realm_id: &'a RealmId,
    pub(super) reducer_profile: &'a str,
    pub(super) frontier: &'a [EventId],
    pub(super) subjects: &'a BTreeMap<String, Flow>,
    pub(super) morphs: &'a BTreeMap<String, Morph>,
    pub(super) spaces: &'a BTreeMap<String, Space>,
    pub(super) relations: &'a BTreeMap<String, Relation>,
    pub(super) resolved_state: &'a BTreeMap<String, ResolvedStateEvent>,
    pub(super) messages: &'a BTreeMap<String, ResolvedMessage>,
    pub(super) reactions: &'a BTreeMap<String, ResolvedReaction>,
    pub(super) tombstone_event_id: &'a Option<EventId>,
}

pub(super) fn state_digest_payload(input: StateHashInput<'_>) -> Value {
    serde_json::json!({
        "realm_id": input.realm_id,
        "reducer_profile": input.reducer_profile,
        "frontier": input.frontier,
        "subjects": input.subjects,
        "morphs": input.morphs,
        "spaces": input.spaces,
        "relations": input.relations,
        "resolved_state": input.resolved_state,
        "messages": input.messages,
        "reactions": input.reactions,
        "tombstone_event_id": input.tombstone_event_id,
    })
}
