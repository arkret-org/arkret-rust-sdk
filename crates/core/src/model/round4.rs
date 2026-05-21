//! Round 4 (2026-05-20, spec a77b9958) wire additions and breakers.
//!
//! Spec window: `contrix-spec` `2a4d39b..a77b995` (8 commits, protocol
//! review closure round). Highlights:
//!
//! - **DID regex tightening** — `^did:[a-z0-9]+:[^\s]+$` is enforced by
//!   the [`Did`] validator in `crates/identifiers`. The pre-round-4
//!   permissive method-name shape (which accepted `.`/`-`/`_`/`:` in the
//!   method segment) is wire-broken.
//! - **Trust-domain binding** — [`crate::TypedTrustDomainId`] is now a
//!   required field on `Realm` / `ServiceDescribe` / `AuditRywReceipt`
//!   and is mixed into the canonical signing transcript of high-risk
//!   proofs ([`compute_audit_policy_version_hash`]).
//! - **Federation S2S headers** — [`crate::HEADER_SOURCE_TRUST_DOMAIN`],
//!   [`crate::HEADER_DESTINATION_TRUST_DOMAIN`], and
//!   [`crate::HEADER_REQUEST_CANONICAL_HASH`] are mandatory request
//!   headers that MUST appear in the canonical message-signature
//!   transcript so a sender from trust domain A cannot replay the same
//!   signed bytes into trust domain B.
//! - **CrossSigning publish CAS** — `expected_previous_generation` is
//!   now a REQUIRED field on `cx.cross_signing.publish`. The reducer
//!   compares it against state BEFORE verifying signatures. See
//!   [`crate::CrossSigningPublishContent`] and
//!   [`crate::cross_signing_publish_cell_subject`].
//! - **EphemeralEnvelope v2 (`cx.call.signal`)** — `device_id`, `proof`
//!   and the `payload.{call_id, signal_type, seq}` tuple are REQUIRED;
//!   the `signal_type` enum is widened from 6 to 13 values. See
//!   [`validate_signal_seq`] and [`CallSignalState`].
//! - **EventsFrontier 3-way split** — single shape replaced with
//!   `account_client` / `federation_peer` / `anonymous_health` variants.
//!   `anonymous_health` carries NO receipts / signatures.
//! - **PolicyCheck v2** — request carries `signed_transport`, response
//!   carries `bound_to{realm_id, actor, action, request_canonical_hash,
//!   policy_server_id}` and signing transcript fields.
//! - **Object-level lifecycle payloads** — `space.archive` / `restore` /
//!   `tombstone` now carry the typed
//!   [`SpaceStateTransitionPayload`] / [`SpaceObjectTombstonePayload`]
//!   shapes (the legacy top-level `target_ref` form is rejected).
//! - **AccessKind::E2EELateRecovery** — new `cx.audit.policy_access`
//!   enum variant with required `late_recovery_original_event_id`.
//! - **ConsentRevokePayload.observed_dots** — required, prevents
//!   implicit cascade.

use super::*;
use crate::canonical;

// ── Capability action & call_signal_type sets are exposed via
//    [`crate::CAP_ACTION_MORPH_CREATE`] / [`crate::CALL_SIGNAL_TYPES`]
//    in `crate::model::constants` so the registry helpers can include
//    them in the SDK's spec coverage declarations.

// ── Trust domain plumbing ───────────────────────────────────────────────

/// Round 4 — compute the canonical `audit_policy_version_hash` 4-tuple
/// digest. Wire-breaking: the pre-round-4 2-arg signature
/// `(audit_disclosure, audit_assurance)` is deleted. Receipts issued
/// against the old hash MUST be rejected.
///
/// Canonical JSON over the object:
/// ```text
/// { "realm_id": <realm_id>,
///   "trust_domain": <trust_domain>,
///   "audit_disclosure": <audit_disclosure>,
///   "audit_assurance": <audit_assurance> }
/// ```
/// hashed with SHA-256 per RFC 8785 JCS.
pub fn compute_audit_policy_version_hash(
    realm_id: &RealmId,
    trust_domain: &TypedTrustDomainId,
    audit_disclosure: &Value,
    audit_assurance: &Value,
) -> Result<[u8; 32]> {
    let canonical_bytes = canonical::canonical_json_bytes(&serde_json::json!({
        "realm_id": realm_id.as_str(),
        "trust_domain": trust_domain.as_str(),
        "audit_disclosure": audit_disclosure,
        "audit_assurance": audit_assurance,
    }))?;
    let digest = Sha256::digest(&canonical_bytes);
    Ok(digest.into())
}

// ── ThirdPartyInvite (3PID) ─────────────────────────────────────────────

/// Round 4 — discriminator for the 3PID invite OOB mode.
///
/// `cx.schema.invite.v1` carries a `oneOf` of:
/// - `offline_token`: token_commitment + token_salt_id +
///   token_entropy_bits (>= 128).
/// - `lookup`: lookup_table_ref + pepper_id, rate-limited (3 errors
///   invalidates the entry).
///
/// The plaintext 3PID (email / SMS) MUST NEVER appear on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteOobKind {
    OfflineToken,
    Lookup,
}

/// Round 4 — `cx.schema.invite.v1` third_party_invite (3PID) carrier.
///
/// Two-mode `oneOf`:
/// - `offline_token` requires `token_commitment` + `token_salt_id` +
///   `token_entropy_bits >= 128`.
/// - `lookup` requires `lookup_table_ref` + `pepper_id`.
///
/// Both modes ALWAYS carry `max_claims`,
/// `verification_service_did`, and `verification_public_key`. Internal
/// verifier chain (`verification_service_did` chain of trust + replay
/// guard against `pepper_id` reuse) is TODO; the SDK only needs the
/// wire shape right now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ThirdPartyInvite {
    pub oob_code_kind: ThirdPartyInviteOobKind,
    /// `offline_token` mode — SHA-256 of `token | salt[salt_id]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_commitment: Option<Hash>,
    /// `offline_token` mode — opaque salt id, MUST be rotated per token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_salt_id: Option<String>,
    /// `offline_token` mode — claimed entropy. MUST be >= 128.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_entropy_bits: Option<u32>,
    /// `lookup` mode — opaque reference to the auth-server-side lookup
    /// table holding the (peppered) 3PID hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_table_ref: Option<String>,
    /// `lookup` mode — opaque pepper id; rotate after 3 verification
    /// failures (`invalidated_by_rate_limit` terminal state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pepper_id: Option<String>,
    /// Maximum claim attempts before terminal `invalidated_by_rate_limit`.
    pub max_claims: u32,
    /// DID of the auth server expected to verify the OOB code.
    pub verification_service_did: Did,
    /// Verifying public key for the verification proof chain.
    pub verification_public_key: String,
}

impl ThirdPartyInvite {
    /// Reject envelopes whose `oob_code_kind` is incompatible with the
    /// populated fields. Round 4 (spec a77b995 §third_party_invite).
    pub fn validate_minimal(&self) -> Result<()> {
        match self.oob_code_kind {
            ThirdPartyInviteOobKind::OfflineToken => {
                if self.token_commitment.is_none()
                    || self.token_salt_id.is_none()
                    || self.token_entropy_bits.is_none()
                {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token mode requires token_commitment + \
                         token_salt_id + token_entropy_bits"
                            .to_owned(),
                    ));
                }
                if self.token_entropy_bits.is_some_and(|bits| bits < 128) {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token token_entropy_bits MUST be >= 128"
                            .to_owned(),
                    ));
                }
                if self.lookup_table_ref.is_some() || self.pepper_id.is_some() {
                    return Err(Error::Protocol(
                        "third_party_invite offline_token mode must NOT set lookup fields"
                            .to_owned(),
                    ));
                }
            }
            ThirdPartyInviteOobKind::Lookup => {
                if self.lookup_table_ref.is_none() || self.pepper_id.is_none() {
                    return Err(Error::Protocol(
                        "third_party_invite lookup mode requires lookup_table_ref + pepper_id"
                            .to_owned(),
                    ));
                }
                if self.token_commitment.is_some()
                    || self.token_salt_id.is_some()
                    || self.token_entropy_bits.is_some()
                {
                    return Err(Error::Protocol(
                        "third_party_invite lookup mode must NOT set offline_token fields"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Round 4 — terminal states for a 3PID invite (auth server side).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyInviteTerminalState {
    Claimed,
    SendFailed,
    RevokedByCapabilityLoss,
    RevokedByInviterLeft,
    InvalidatedByRateLimit,
}

// ── Space lifecycle payloads ────────────────────────────────────────────

/// Round 4 (commit 369f544) — typed payload for
/// `cx.space.archive` and `cx.space.restore`.
///
/// Reducers MUST reject the legacy top-level `target_ref` form with
/// `schema_violation` and consume this shape exclusively.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceStateTransitionPayload {
    pub space_id: SpaceId,
    /// New ObjectState; reducers reject any transition not in the
    /// allowed FSM (see `model::primitives::ObjectState`).
    pub new_state: ObjectState,
    /// Optional human-readable reason for the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Round 4 — typed payload for `cx.space.tombstone`. Marks the Space
/// permanently deleted; receivers MUST surface the
/// `tombstone_event_id` to the user before purging local state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpaceObjectTombstonePayload {
    pub space_id: SpaceId,
    pub tombstone_reason: String,
    /// Optional successor space id, if migration is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_space_id: Option<SpaceId>,
}

// ── EphemeralEnvelope v2 / cx.call.signal ───────────────────────────────

/// Round 4 (commit 58c5926) — typed `cx.call.signal` envelope payload.
///
/// The pre-round-4 envelope carried an open `Value` payload; the round-4
/// wire requires the three fields `call_id` + `signal_type` + `seq` and
/// validates `signal_type` against [`crate::CALL_SIGNAL_TYPES`] (13
/// values). `seq` is monotonic per `(realm, call, actor, device)` —
/// see [`validate_signal_seq`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallSignalPayload {
    pub call_id: CallId,
    pub signal_type: String,
    pub seq: u64,
    /// Per-signal_type extra fields nested under `data` so the
    /// envelope shape stays predictable (sdp, ice, mute_state, etc.).
    /// The SDK does not parse this — the client renderer does.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

impl CallSignalPayload {
    /// Returns `true` when `signal_type` is in the round-4 canonical
    /// 13-value enum.
    pub fn signal_type_is_canonical(&self) -> bool {
        CALL_SIGNAL_TYPES.contains(&self.signal_type.as_str())
    }

    /// Reject envelopes whose `signal_type` is not in the canonical set.
    pub fn validate_signal_type(&self) -> Result<()> {
        if !self.signal_type_is_canonical() {
            return Err(Error::Protocol(format!(
                "cx.call.signal payload.signal_type {:?} not in canonical 13-value enum \
                 ({})",
                self.signal_type,
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

/// Round 4 — composite key for the `cx.call.signal` `seq` monotonicity
/// guard. Receivers maintain one `seq` per `(realm, call, actor,
/// device)` tuple; rollback rejects the signal and the receiver SHOULD
/// emit `hangup` for that call.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallSignalSeqKey {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub actor_id: Did,
    pub device_id: DeviceId,
}

impl CallSignalSeqKey {
    pub fn new(realm_id: RealmId, call_id: CallId, actor_id: Did, device_id: DeviceId) -> Self {
        Self { realm_id, call_id, actor_id, device_id }
    }
}

/// Round 4 — verify `next` is strictly greater than `prev` for the same
/// `key`. `prev = None` accepts any `next` (first observation).
///
/// Returns `Err(ERROR_CODE_SCHEMA_VIOLATION)` on rollback / repeat —
/// receivers MUST drop the signal and emit `hangup`.
pub fn validate_signal_seq(prev: Option<u64>, next: u64) -> Result<()> {
    match prev {
        None => Ok(()),
        Some(prev) if next > prev => Ok(()),
        Some(prev) => Err(Error::Protocol(format!(
            "cx.call.signal seq rollback prev={prev} next={next} ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        ))),
    }
}

/// Round 4 — in-memory bookkeeping for `seq` monotonicity per key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallSignalState {
    seqs: BTreeMap<String, u64>,
}

impl CallSignalState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reduce a `seq` observation for `key`. Returns `Ok` when monotonic;
    /// `Err` (rollback) otherwise. On `Ok`, the per-key seq advances.
    pub fn observe(&mut self, key: &CallSignalSeqKey, next: u64) -> Result<()> {
        let composite = format!(
            "{}|{}|{}|{}",
            key.realm_id.as_str(),
            key.call_id.as_str(),
            key.actor_id.as_str(),
            key.device_id.as_str()
        );
        let prev = self.seqs.get(&composite).copied();
        validate_signal_seq(prev, next)?;
        self.seqs.insert(composite, next);
        Ok(())
    }
}

// ── EphemeralEnvelope v2 helpers (cx.call.signal required fields) ────

/// Round 4 — verify a `cx.call.signal` [`EphemeralEnvelope`] satisfies
/// the v2 wire requirements: `device_id` + `proof` are REQUIRED, and
/// the payload deserialises into a [`CallSignalPayload`] with a
/// canonical `signal_type`.
pub fn validate_call_signal_envelope(env: &EphemeralEnvelope) -> Result<CallSignalPayload> {
    if env.kind != "cx.call.signal" {
        return Err(Error::Protocol(format!("envelope kind {:?} is not cx.call.signal", env.kind)));
    }
    if env.device_id.is_none() {
        return Err(Error::Protocol(format!(
            "cx.call.signal envelope MUST carry device_id ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        )));
    }
    if env.proof.is_none() {
        return Err(Error::Protocol(format!(
            "cx.call.signal envelope MUST carry proof ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        )));
    }
    let payload: CallSignalPayload = serde_json::from_value(env.payload.clone()).map_err(|e| {
        Error::Protocol(format!(
            "cx.call.signal payload must carry {{call_id, signal_type, seq}}: {e} ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        ))
    })?;
    payload.validate_signal_type()?;
    Ok(payload)
}

// ── EventsFrontier 3-way split ──────────────────────────────────────────

/// Round 4 (commit f9bd7eb) — peer role discriminator for the
/// `/events/frontier` endpoint. The pre-round-4 single-shape response
/// is wire-broken; receivers MUST route by `peer_role` and produce one
/// of three discriminated response variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FrontierPeerRole {
    AccountClient,
    FederationPeer,
    AnonymousHealth,
}

/// Round 4 — account-client variant of the `/events/frontier` response.
/// Used by signed-in clients; the SDK does NOT include `frontier_root`
/// or transport signatures here (client UI does not need them).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAccountClientResponse {
    pub peer_role: FrontierPeerRole,
    pub frontier: BTreeMap<SpaceId, Vec<EventId>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_seq_upper_bounds: BTreeMap<Did, u64>,
}

/// Round 4 — federation-peer variant of `/events/frontier`. Carries
/// `frontier_root` + transport receipts + `service_binding_ref` so a
/// remote peer can verify the response binds to the producing service.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierFederationPeerResponse {
    pub peer_role: FrontierPeerRole,
    pub frontier: BTreeMap<SpaceId, Vec<EventId>>,
    pub frontier_root: Hash,
    pub service_binding_ref: FederationServiceBindingRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actor_seq_upper_bounds: BTreeMap<Did, u64>,
}

/// Round 4 — anonymous-health variant. Used by public health checks
/// (`peer_role=anonymous_health`); the wire shape MUST NOT carry
/// receipts, signatures, or actor_seq_upper_bounds. Type system
/// enforces this (no such fields).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsFrontierAnonymousHealthResponse {
    pub peer_role: FrontierPeerRole,
    pub service_did: Did,
    pub healthy: bool,
    /// Wall-clock instant the frontier snapshot was generated. Used for
    /// staleness detection only — not signed.
    pub generated_at: DateTime<Utc>,
}

/// Round 4 — discriminated `/events/frontier` response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum EventsFrontierResponse {
    AccountClient(EventsFrontierAccountClientResponse),
    FederationPeer(EventsFrontierFederationPeerResponse),
    AnonymousHealth(EventsFrontierAnonymousHealthResponse),
}

// ── FederationServiceBindingRef ─────────────────────────────────────────

/// Round 4 (commit 7446832) — typed binding reference for federation
/// transport. All six fields REQUIRED. Carried inside
/// `cx.events.submit` (federation variant) and the
/// `events/frontier` federation-peer response so a receiver can verify
/// the request is bound to the sender's current reducer state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationServiceBindingRef {
    pub realm_id: RealmId,
    pub space_policy_hash: Hash,
    pub membership_frontier: Vec<EventId>,
    pub delivery_binding_frontier: Vec<EventId>,
    pub destination_service_type: String,
    pub reducer_profile_hash: Hash,
}

// ── EventsSubmit variants ───────────────────────────────────────────────

/// Round 4 — batch `/events/submit` request. Multiple envelopes
/// submitted in a single round trip. The receiver MUST process each
/// envelope independently; partial-success returns the per-envelope
/// rejected list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitBatchRequest {
    pub events: Vec<Value>,
    /// Optional idempotency key for the entire batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Round 4 — federation `/events/submit` request. Used when a remote
/// service forwards events from another principal server. MUST carry
/// the full [`FederationServiceBindingRef`] so the receiver can verify
/// origin reducer state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EventsSubmitFederationRequest {
    pub service_binding_ref: FederationServiceBindingRef,
    pub events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

// ── PolicyCheck v2 ──────────────────────────────────────────────────────

/// Round 4 — `source` discriminator for [`PolicyCheckRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckSource {
    pub service_did: Did,
    pub service_type: String,
}

/// Round 4 (commit 7446832) — typed `/policy/check` request body.
///
/// Wire-breaking: replaces the pre-round-4 `PolicyCheckReqBody` (kept
/// in `model::api` only for transport-layer salvo compatibility while
/// upstream consumers migrate).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckRequest {
    pub request_id: String,
    pub realm_id: RealmId,
    pub actor: Did,
    pub action: String,
    pub request_canonical_hash: Hash,
    pub source: PolicyCheckSource,
    /// Hex-encoded hash of the source IP (privacy-preserving), see
    /// `policy-server.md` §4.2.
    pub source_ip_hash: Hash,
    /// Signed transport envelope (HTTP message-signature transcript).
    /// Required so policy server can verify the originating request
    /// is bound to the calling service.
    pub signed_transport: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub event_preview: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth_context: Value,
}

/// Round 4 — `bound_to` binding inside [`PolicyCheckResponse`].
///
/// MUST include all five fields so the response can be verified against
/// the request transcript without trusting the policy server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckBoundTo {
    pub realm_id: RealmId,
    pub actor: Did,
    pub action: String,
    pub request_canonical_hash: Hash,
    pub policy_server_id: Did,
}

/// Round 4 — signature carrier for [`PolicyCheckResponse`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckSignature {
    /// DID URL verification method, MUST match
    /// `^did:[a-z0-9]+:[^\s]+#.+$`.
    pub kid: String,
    pub sig: String,
}

/// Round 4 (commit 7446832) — `/policy/check` response with full
/// binding transcript.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckResponse {
    pub decision: AuthzDecision,
    pub bound_to: PolicyCheckBoundTo,
    pub auth_state_hash: Hash,
    pub policy_frontier_hash: Hash,
    pub membership_frontier_hash: Hash,
    pub signature: PolicyCheckSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
}

// ── EventsSubscribe NDJSON frame discriminator ──────────────────────────

/// Round 4 — typed `/events/subscribe` NDJSON frame body.
///
/// Wire-breaking: replaces the pre-round-4 untyped string frames. The
/// `Dropped` variant MUST carry a cursor so receivers can resume; an
/// implementation that emits `Dropped` without cursor MUST downgrade
/// to `ResyncRequired`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventsSubscribeFrameBody {
    Event {
        event: Value,
    },
    Frontier {
        frontier: Value,
    },
    Heartbeat {
        /// Server time the heartbeat was emitted (staleness guard).
        emitted_at: DateTime<Utc>,
    },
    CatchupComplete,
    EpochRotation {
        epoch: u64,
    },
    Dropped {
        /// REQUIRED resume cursor; absence MUST be treated as
        /// `ResyncRequired` by the implementation that produced the
        /// frame.
        cursor: Cursor,
        reason: String,
    },
    ResyncRequired {
        reason: String,
    },
    Unauthorized {
        reason: String,
    },
}

// ── SnapshotBootstrap ───────────────────────────────────────────────────

/// Round 4 — chunked snapshot delivery envelope. The full verifier
/// chain (per-chunk digest + merkle proof + signature) is a soland
/// TODO; the SDK only needs the wire shape so producer / consumer
/// services can agree on field names.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrap {
    /// Signature over the canonical bootstrap header (state_hash +
    /// snapshot_frontier + per-chunk digest merkle root).
    /// TODO(round4-snapshot-bootstrap): wire the full signing
    /// transcript and verifier chain. SDK only needs the wire shape.
    pub signature: Value,
    /// Canonical state root over the snapshot's projected state.
    pub state_hash: Hash,
    /// Frontier the snapshot was generated against.
    pub snapshot_frontier: Vec<EventId>,
    /// Ordered chunk digests. Consumers MUST verify each chunk's bytes
    /// match the declared digest before applying.
    pub chunks: Vec<SnapshotBootstrapChunk>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SnapshotBootstrapChunk {
    pub chunk_id: String,
    pub digest: Hash,
    pub size_bytes: u64,
    /// HTTP URL or `cx:blob:` reference where the chunk bytes can be
    /// fetched.
    pub fetch_ref: String,
}

// ── AgentId / AppletId typed wrappers (DID required) ─────────────────

/// Round 4 (commit 7fae9ba) — typed `agent_id`. The pre-round-4 wire
/// permitted plain strings; round 4 enforces the DID shape only.
pub type AgentId = Did;

/// Round 4 — typed `applet_id`. Accepts either a DID
/// (`did:webvh:applet.example`) or a strictly-validated
/// `cx:applet:<uuidv7>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum AppletIdentifier {
    Did(Did),
    Cx(AppletId),
}

impl AppletIdentifier {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Did(d) => d.as_str(),
            Self::Cx(a) => a.as_str(),
        }
    }
}

// ── AccessKind (cx.audit.policy_access) ────────────────────────────────

/// Round 4 (commit 7fae9ba) — `cx.audit.policy_access.access_kind`
/// enum. Round 4 adds `E2EELateRecovery`; deployments emitting it
/// MUST also populate `late_recovery_original_event_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Plaintext,
    Audit,
    Erasure,
    Backup,
    /// Round 4 — late-key-recovery path. Carried alongside
    /// `late_recovery_original_event_id` on the payload.
    E2EELateRecovery,
}

/// Round 4 — typed `cx.audit.policy_access` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuditPolicyAccessPayload {
    pub realm_id: RealmId,
    pub actor: Did,
    pub access_kind: AccessKind,
    /// REQUIRED when `access_kind == E2EELateRecovery`. References the
    /// original event the late recovery targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<EventId>,
    pub observed_at: DateTime<Utc>,
}

impl AuditPolicyAccessPayload {
    pub fn validate_minimal(&self) -> Result<()> {
        match (self.access_kind, &self.late_recovery_original_event_id) {
            (AccessKind::E2EELateRecovery, None) => Err(Error::Protocol(format!(
                "cx.audit.policy_access access_kind=e2ee_late_recovery requires \
                 late_recovery_original_event_id ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            ))),
            (kind, Some(_)) if !matches!(kind, AccessKind::E2EELateRecovery) => {
                Err(Error::Protocol(format!(
                    "cx.audit.policy_access late_recovery_original_event_id is only valid for \
                     access_kind=e2ee_late_recovery ({})",
                    crate::ERROR_CODE_SCHEMA_VIOLATION
                )))
            }
            _ => Ok(()),
        }
    }
}

// ── ConsentRevokePayload (observed_dots required) ──────────────────────

/// Round 4 (commit 7fae9ba) — Dot identifier for `observed_dots`.
///
/// Wire shape: `(actor_id, actor_seq)` per zh/identity/consent-model.md
/// §3.3.1. Receivers MUST NOT silently cascade revoke to dots not
/// explicitly observed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Dot {
    pub actor_id: Did,
    pub actor_seq: u64,
}

/// Round 4 — typed `cx.consent.revoke` payload with REQUIRED
/// `observed_dots`. Reducers MUST reject envelopes that omit this
/// field with `schema_violation` (it would otherwise enable implicit
/// cascade revoke).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ConsentRevokePayload {
    pub consent_id: String,
    pub peer: Did,
    pub scope: String,
    pub observed_dots: Vec<Dot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ConsentRevokePayload {
    pub fn validate_minimal(&self) -> Result<()> {
        if self.observed_dots.is_empty() {
            return Err(Error::Protocol(format!(
                "cx.consent.revoke MUST carry non-empty observed_dots ({})",
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

// ── Flow cell metadata helpers ─────────────────────────────────────────

/// Round 4 — cell family for `cx.flow.update` / `cx.flow.tracks_patch`
/// CAS-register cells. `bottom=reject` semantics — concurrent writes
/// to the same cell are not joinable (CAS contention).
pub const FLOW_FIELDS_CELL_FAMILY: &str = "cx.component.flow.fields.v1";

/// Round 4 — build the cell_subject for `cx.flow.update`.
/// `(family=FLOW_FIELDS_CELL_FAMILY, subject=flow_id)`, CAS-register
/// semantics, bottom=reject.
pub fn flow_update_cell_subject(flow_id: &FlowId) -> String {
    flow_id.as_str().to_owned()
}

/// Round 4 — build the cell_subject for `cx.flow.tracks_patch`. Same
/// cell family and bottom semantics as [`flow_update_cell_subject`];
/// the two events share the cell so they compete via CAS rather than
/// silently overwriting each other.
pub fn flow_tracks_patch_cell_subject(flow_id: &FlowId) -> String {
    flow_id.as_str().to_owned()
}

// ── HTTP message-signature transcript extension ────────────────────────

/// Round 4 — build the canonical signing-transcript fragment for the
/// three federation trust-domain headers. Callers append this fragment
/// to the existing RFC 9421 signature base produced by
/// `crates/sdk/src/federation::rfc9421_http_message_signature_base`.
///
/// Wire shape: three lines, each with the header name in lower-case
/// quoted form per RFC 9421 §2.2.
pub fn federation_trust_domain_transcript_fragment(
    source_trust_domain: &TypedTrustDomainId,
    destination_trust_domain: &TypedTrustDomainId,
    request_canonical_hash: &Hash,
) -> String {
    let header_name = |s: &str| s.to_ascii_lowercase();
    format!(
        "\"{src_h}\": {src}\n\"{dst_h}\": {dst}\n\"{rch_h}\": {rch}\n",
        src_h = header_name(HEADER_SOURCE_TRUST_DOMAIN),
        dst_h = header_name(HEADER_DESTINATION_TRUST_DOMAIN),
        rch_h = header_name(HEADER_REQUEST_CANONICAL_HASH),
        src = source_trust_domain.as_str(),
        dst = destination_trust_domain.as_str(),
        rch = request_canonical_hash.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }
    fn td() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:example.net").unwrap()
    }
    fn td2() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:other.example").unwrap()
    }

    #[test]
    fn audit_policy_version_hash_is_deterministic_and_domain_separates() {
        let disclosure = serde_json::json!({"mode": "strict"});
        let assurance = serde_json::json!("attested_hardware");
        let h1 =
            compute_audit_policy_version_hash(&realm(), &td(), &disclosure, &assurance).unwrap();
        let h2 =
            compute_audit_policy_version_hash(&realm(), &td(), &disclosure, &assurance).unwrap();
        assert_eq!(h1, h2);
        // Different trust domain MUST produce a different digest.
        let h3 =
            compute_audit_policy_version_hash(&realm(), &td2(), &disclosure, &assurance).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn third_party_invite_rejects_mode_mismatch() {
        let mut invite = ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: Some(64),
            lookup_table_ref: None,
            pepper_id: None,
            max_claims: 3,
            verification_service_did: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkVK".to_owned(),
        };
        // Missing token_commitment + token_salt_id → reject.
        assert!(invite.validate_minimal().is_err());

        invite.token_commitment = Some(Hash::new("sha256:".to_owned() + &"0".repeat(64)).unwrap());
        invite.token_salt_id = Some("salt-1".to_owned());
        // entropy_bits = 64 still < 128 → reject.
        assert!(invite.validate_minimal().is_err());

        invite.token_entropy_bits = Some(128);
        assert!(invite.validate_minimal().is_ok());

        // Lookup mode requires lookup_table_ref + pepper_id, not offline_token fields.
        let lookup_bad = ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            token_commitment: invite.token_commitment.clone(),
            ..invite
        };
        assert!(lookup_bad.validate_minimal().is_err());
    }

    #[test]
    fn validate_signal_seq_enforces_monotonicity() {
        assert!(validate_signal_seq(None, 0).is_ok());
        assert!(validate_signal_seq(Some(0), 1).is_ok());
        assert!(validate_signal_seq(Some(5), 6).is_ok());
        assert!(validate_signal_seq(Some(5), 5).is_err());
        assert!(validate_signal_seq(Some(5), 4).is_err());
    }

    #[test]
    fn call_signal_state_tracks_per_key_seq() {
        let mut state = CallSignalState::new();
        let key = CallSignalSeqKey::new(
            realm(),
            CallId::new("cx:call:01904100-0000-7000-8000-000000000002").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000003").unwrap(),
        );
        assert!(state.observe(&key, 1).is_ok());
        assert!(state.observe(&key, 2).is_ok());
        assert!(state.observe(&key, 2).is_err()); // repeat = rollback
        assert!(state.observe(&key, 5).is_ok());
    }

    #[test]
    fn audit_policy_access_payload_validates_late_recovery_pairing() {
        let payload = AuditPolicyAccessPayload {
            realm_id: realm(),
            actor: Did::new("did:web:alice.example").unwrap(),
            access_kind: AccessKind::E2EELateRecovery,
            late_recovery_original_event_id: None,
            observed_at: Utc::now(),
        };
        assert!(payload.validate_minimal().is_err());
    }

    #[test]
    fn consent_revoke_requires_observed_dots() {
        let payload = ConsentRevokePayload {
            consent_id: "cid".to_owned(),
            peer: Did::new("did:web:bob.example").unwrap(),
            scope: "invite".to_owned(),
            observed_dots: Vec::new(),
            revoked_at: None,
            reason: None,
        };
        assert!(payload.validate_minimal().is_err());
    }

    #[test]
    fn flow_cell_subject_helpers_return_flow_id() {
        let flow = FlowId::new("cx:flow:01904100-0000-7000-8000-000000000004").unwrap();
        assert_eq!(flow_update_cell_subject(&flow), flow.as_str());
        assert_eq!(flow_tracks_patch_cell_subject(&flow), flow.as_str());
    }
}
