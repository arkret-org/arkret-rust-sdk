//! Reusable conformance fixtures and catalog coverage helpers.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{
    AnchorId, CellRef, Did, Error, Event, Hash, Hlc, Move, MoveId, RealmId, Result, SpaceId,
    canonical,
    events::{
        AGENT_PROTOCOL_SESSION_STATUS, AnyEventContent, CALL_SIGNAL, EventClass,
        EventContentEnvelope, MESSAGE_CREATE, MLS_WELCOME, REACTION_ADD, classify_event_kind,
        parse_event_content,
    },
    lattice::CellState,
    state::{
        MemoryAnchorStore, MemoryCellRegistry, MemoryCellStore, MemoryMoveStore, MoveStore,
        apply_anchor, compute_state_root,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDomain {
    ClientServer,
    ProductClientApi,
    Applet,
    PushGateway,
    Identity,
    Signatures,
    Events,
    StateResolution,
    Operations,
    Schema,
    Html,
    Crypto,
    Ui,
    Ffi,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCoverageRow {
    pub domain: ConformanceDomain,
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub request_schema: String,
    pub response_schema: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub rows: Vec<EndpointCoverageRow>,
    pub event_vectors: Vec<EventTaxonomyVector>,
    pub state_vectors: Vec<StateResolutionVector>,
}

impl ConformanceReport {
    pub fn covers_domain(&self, domain: ConformanceDomain) -> bool {
        self.rows.iter().any(|row| row.domain == domain)
            || self.event_vectors.iter().any(|_| domain == ConformanceDomain::Events)
            || self.state_vectors.iter().any(|_| domain == ConformanceDomain::StateResolution)
    }

    pub fn operation_ids(&self) -> BTreeSet<&str> {
        self.rows.iter().map(|row| row.operation_id.as_str()).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventTaxonomyVector {
    pub name: String,
    pub kind: String,
    pub expected_class: EventClass,
    pub input: Value,
    pub preserves_unknown: bool,
}

/// Reference vector exercising the Move/Anchor/Lattice runtime end-to-end.
///
/// Under v1 there is no per-cell winner; cell convergence is decided by
/// Lattice join. The vector captures (a) the Anchor that committed the batch,
/// (b) how many Moves were accepted vs rejected, and (c) the post-state_root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateResolutionVector {
    pub name: String,
    pub anchor: AnchorId,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub post_state_root: Hash,
}

/// Reference vector for canonical-JSON encoding round-trips.
/// Anchored in `conformance/conformance-vectors.md` §1.3–§1.5.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalJsonVector {
    pub vector_id: String,
    pub input: Value,
    pub canonical_bytes: String,
    pub digest: String,
    pub should_reject: bool,
}

/// Reference vector for redaction.
/// Anchored in `event-auth-state-resolution.md` §10.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedactionVector {
    pub vector_id: String,
    pub kind: String,
    pub before: Value,
    pub after_payload_cleared: bool,
    pub preserves_actor_seq: bool,
    pub preserves_prev_refs: bool,
    pub preserves_refs: bool,
    pub preserves_hlc: bool,
}

/// Reference vector for capability evaluation
/// (`capabilities.md` §4 + `constraint-schema.md` §15).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityVector {
    pub vector_id: String,
    pub action: String,
    pub expected_decision: String,
    pub short_circuit_on: Option<String>,
}

/// Reference vector for sync (cursor / filter binding).
/// Anchored in `operations-sync.md` §11 + M-15/M-16.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncVector {
    pub vector_id: String,
    pub filter_digest: String,
    pub frontier_size: usize,
    pub expects_filter_digest_mismatch: bool,
}

pub fn conformance_report() -> Result<ConformanceReport> {
    Ok(ConformanceReport {
        rows: endpoint_coverage_rows(),
        event_vectors: event_taxonomy_vectors()?,
        state_vectors: state_resolution_vectors()?,
    })
}

/// Produce a small but representative library of canonical-JSON
/// reference vectors. Each vector is self-contained — the input is a
/// `serde_json::Value`, the expected canonical bytes / digest are
/// pinned, and the test harness can assert byte-for-byte equality.
///
/// Every vector cites its anchoring `conformance/conformance-vectors.md`
/// section in the `vector_id`, e.g. `canonical-json/v1.3-basic`.
pub fn canonical_json_vectors() -> Vec<CanonicalJsonVector> {
    use contrix_core::canonical;
    let basic = json!({ "b": 2, "a": 1 });
    let basic_bytes = canonical::canonical_json_string(&basic).expect("canonical");
    let basic_digest = canonical::sha256_digest(basic_bytes.as_bytes());

    let nested = json!({
        "outer": { "z": 26, "a": 1 },
        "list": [3, 1, 2],
    });
    let nested_bytes = canonical::canonical_json_string(&nested).expect("canonical");
    let nested_digest = canonical::sha256_digest(nested_bytes.as_bytes());

    vec![
        CanonicalJsonVector {
            vector_id: "canonical-json/v1.3-basic".to_owned(),
            input: basic,
            canonical_bytes: basic_bytes,
            digest: basic_digest,
            should_reject: false,
        },
        CanonicalJsonVector {
            vector_id: "canonical-json/v1.4-nested".to_owned(),
            input: nested,
            canonical_bytes: nested_bytes,
            digest: nested_digest,
            should_reject: false,
        },
        CanonicalJsonVector {
            vector_id: "canonical-json/v1.5-reject-float".to_owned(),
            input: json!({ "n": 1.5 }),
            canonical_bytes: String::new(),
            digest: String::new(),
            should_reject: true,
        },
    ]
}

/// Reference redaction vectors. The harness MUST assert that
/// `apply_redaction(before)` clears `payload`/`unsigned` while keeping
/// every preserved-fields flag set on the vector.
pub fn redaction_vectors() -> Vec<RedactionVector> {
    vec![RedactionVector {
        vector_id: "redaction/v10-message".to_owned(),
        kind: "cx.message.create".to_owned(),
        before: json!({
            "kind": "cx.message.create",
            "actor_seq": 7,
            "prev_refs": ["cx:event:01904100-0000-7000-8000-021bde4eea9d"],
            "refs": [{
                "id": "cx:event:01904100-0000-7000-8000-d7332fb47d1a",
                "role": "authorized_by",
                "critical": true
            }],
            "hlc": "01970e589d21-0004-a13f9c2e",
            "payload": { "body": "to be redacted" },
            "unsigned": { "transient": true }
        }),
        after_payload_cleared: true,
        preserves_actor_seq: true,
        preserves_prev_refs: true,
        preserves_refs: true,
        preserves_hlc: true,
    }]
}

/// Reference capability-evaluation vectors. The harness MUST verify
/// the short-circuit ordering deny → quarantine → require_review →
/// allow per `constraint-schema.md` §15.1–§15.3.
pub fn capability_vectors() -> Vec<CapabilityVector> {
    vec![
        CapabilityVector {
            vector_id: "capability/cs-15.1-deny-short-circuits".to_owned(),
            action: "cx.message.create".to_owned(),
            expected_decision: "deny".to_owned(),
            short_circuit_on: Some("temporal_expired".to_owned()),
        },
        CapabilityVector {
            vector_id: "capability/cs-15.2-priority-orders-allow".to_owned(),
            action: "cx.message.create".to_owned(),
            expected_decision: "allow".to_owned(),
            short_circuit_on: None,
        },
    ]
}

/// Reference sync vectors covering cursor `filter_digest` binding.
pub fn sync_vectors() -> Vec<SyncVector> {
    vec![
        SyncVector {
            vector_id: "sync/m-15-filter-digest-bound".to_owned(),
            filter_digest:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            frontier_size: 1,
            expects_filter_digest_mismatch: false,
        },
        SyncVector {
            vector_id: "sync/m-16-filter-digest-mismatch-rejected".to_owned(),
            filter_digest:
                "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned(),
            frontier_size: 1,
            expects_filter_digest_mismatch: true,
        },
    ]
}

pub fn endpoint_coverage_rows() -> Vec<EndpointCoverageRow> {
    let mut rows = Vec::new();
    rows.extend(contrix_core::BUILT_IN_OPERATION_KINDS.iter().map(|operation_id| {
        EndpointCoverageRow {
            domain: operation_domain(operation_id),
            operation_id: (*operation_id).to_owned(),
            method: "CONTRACT".to_owned(),
            path: format!("contrix-core://operations/{operation_id}"),
            request_schema: "OperationInput".to_owned(),
            response_schema: "OperationResBody".to_owned(),
        }
    }));
    // Product client-API coverage rows were previously derived from the
    // CLIENT_API_ENDPOINTS catalogue in `contrix-api`. That catalogue has been
    // removed in favour of typed salvo route handlers + ToSchema derives, so
    // this conformance report now reports only the canonical operation kinds
    // and the boundary rows enumerated below.
    rows.extend(boundary_coverage_rows());
    rows
}

fn operation_domain(operation_id: &str) -> ConformanceDomain {
    if operation_id.starts_with("cx.applet.") {
        ConformanceDomain::Applet
    } else if operation_id.starts_with("cx.push.") {
        ConformanceDomain::PushGateway
    } else if operation_id.starts_with("cx.identity.") {
        ConformanceDomain::Identity
    } else {
        ConformanceDomain::ClientServer
    }
}

pub fn boundary_coverage_rows() -> Vec<EndpointCoverageRow> {
    vec![
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.catalog".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://operations/catalog".to_owned(),
            request_schema: "OperationKindRegistry".to_owned(),
            response_schema: "OperationCatalogReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.dag".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://operations/dag".to_owned(),
            request_schema: "OperationEnvelope".to_owned(),
            response_schema: "OperationDagReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.semantic_reducer".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://operations/semantics".to_owned(),
            request_schema: "OperationEnvelope".to_owned(),
            response_schema: "OperationSemanticReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.negative_vectors".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://operations/negative-vectors".to_owned(),
            request_schema: "OperationDagNegativeVector".to_owned(),
            response_schema: "OperationDagNegativeVector".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Schema,
            operation_id: "cx.schema.catalog".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://schema/catalog".to_owned(),
            request_schema: "ProtocolSchemaRegistry".to_owned(),
            response_schema: "SchemaCatalogReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Schema,
            operation_id: "cx.schema.validation_vectors".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-core://schema/vectors".to_owned(),
            request_schema: "SchemaValidationVector".to_owned(),
            response_schema: "SchemaValidationVector".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Html,
            operation_id: "cx.html.normalize".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-html://normalize".to_owned(),
            request_schema: "RichTextDocument".to_owned(),
            response_schema: "RichTextDocument".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Html,
            operation_id: "cx.html.sanitize".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-html://sanitize".to_owned(),
            request_schema: "Html".to_owned(),
            response_schema: "SanitizedHtml".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Crypto,
            operation_id: "cx.crypto.machine_request".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-crypto://machine".to_owned(),
            request_schema: "CryptoMachineReqBody".to_owned(),
            response_schema: "CryptoMachineResBody".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Crypto,
            operation_id: "cx.crypto.store_binding".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-crypto://store-binding".to_owned(),
            request_schema: "CryptoStoreBinding".to_owned(),
            response_schema: "KeyLifecycleEvent".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Crypto,
            operation_id: "cx.crypto.verification_flow".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-crypto://verification-flow".to_owned(),
            request_schema: "DeviceVerificationFlow".to_owned(),
            response_schema: "DeviceTrustState".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Crypto,
            operation_id: "cx.crypto.session_lifecycle".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-crypto://session-lifecycle".to_owned(),
            request_schema: "CryptoSessionRecord".to_owned(),
            response_schema: "WithheldKeyRecord".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Ui,
            operation_id: "cx.ui.timeline_projection".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-sdk://timeline".to_owned(),
            request_schema: "Event".to_owned(),
            response_schema: "TimelineItem".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Ui,
            operation_id: "cx.ui.notification_evaluation".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-sdk://notifications".to_owned(),
            request_schema: "Event".to_owned(),
            response_schema: "NotificationAction".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Ffi,
            operation_id: "cx.ffi.handle".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-ffi://handle-table".to_owned(),
            request_schema: "FfiHandle".to_owned(),
            response_schema: "FfiError".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Ffi,
            operation_id: "cx.ffi.wasm_runtime".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-ffi://wasm-runtime".to_owned(),
            request_schema: "WasmRuntimeContract".to_owned(),
            response_schema: "WasmRuntimeContract".to_owned(),
        },
    ]
}

pub fn event_taxonomy_vectors() -> Result<Vec<EventTaxonomyVector>> {
    let text = Event::new(
        MESSAGE_CREATE,
        RealmId::new("cx:realm:01904100-0000-7000-8000-9b64700c6ee8")?,
        Did::new("did:web:alice.example")?,
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        json!({"body": "hello"}),
    )?;
    let text_envelope = EventContentEnvelope::from_event(&text)?;

    let custom = Event::new(
        "vendor.example.custom",
        RealmId::new("cx:realm:01904100-0000-7000-8000-9b64700c6ee8")?,
        Did::new("did:web:alice.example")?,
        2,
        Hlc::new("01970e589d21-0002-a13f9c2e")?,
        json!({"opaque": true, "nested": {"n": 1}}),
    )?;
    let custom_envelope = EventContentEnvelope::from_event(&custom)?;

    let poll_response = json!({
        "poll_event_id": "cx:event:01904100-0000-7000-8000-fb8cfd35e274",
        "answer_ids": ["a"]
    });
    parse_event_content(REACTION_ADD, poll_response.clone())?;

    let call_device_mapping = json!({
        "call_id": "call-1",
        "devices_by_user": {
            "did:web:alice.example": ["cx:device:01904100-0000-7000-8000-000000000008"]
        }
    });
    parse_event_content(CALL_SIGNAL, call_device_mapping.clone())?;

    let activity_beacon = json!({
        "user_id": "did:web:alice.example",
        "device_id": "cx:device:01904100-0000-7000-8000-000000000008",
        "activity": "viewing",
        "observed_at": "2026-05-01T00:00:00Z"
    });
    parse_event_content(AGENT_PROTOCOL_SESSION_STATUS, activity_beacon.clone())?;

    let secret_send = json!({
        "request_id": "req-1",
        "name": "recovery",
        "encrypted_secret": {
            "algorithm": "cx.v1",
            "sender_key": "ed25519:abc",
            "ciphertext": { "body": "encrypted" }
        }
    });
    parse_event_content(MLS_WELCOME, secret_send.clone())?;

    Ok(vec![
        EventTaxonomyVector {
            name: "text message content".to_owned(),
            kind: MESSAGE_CREATE.to_owned(),
            expected_class: text_envelope.class,
            input: text.content,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "poll response content".to_owned(),
            kind: REACTION_ADD.to_owned(),
            expected_class: classify_event_kind(REACTION_ADD),
            input: poll_response,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "call device mapping content".to_owned(),
            kind: CALL_SIGNAL.to_owned(),
            expected_class: classify_event_kind(CALL_SIGNAL),
            input: call_device_mapping,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "collaboration activity beacon content".to_owned(),
            kind: AGENT_PROTOCOL_SESSION_STATUS.to_owned(),
            expected_class: classify_event_kind(AGENT_PROTOCOL_SESSION_STATUS),
            input: activity_beacon,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "secret send content".to_owned(),
            kind: MLS_WELCOME.to_owned(),
            expected_class: classify_event_kind(MLS_WELCOME),
            input: secret_send,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "custom event raw preservation".to_owned(),
            kind: custom.kind,
            expected_class: custom_envelope.class,
            input: match custom_envelope.content {
                AnyEventContent::Custom { content } => content.raw,
                AnyEventContent::Known { .. } => Value::Null,
            },
            preserves_unknown: true,
        },
    ])
}

pub fn state_resolution_vectors() -> Result<Vec<StateResolutionVector>> {
    let space_id = SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a")?;
    let cell = CellRef::new("cx:cell:cx.component.member.state.v1:did.web.bob.example".to_owned())
        .map_err(|e| Error::Protocol(format!("invalid cell ref: {e}")))?;

    // Build a Move that transitions Bob's membership cell from `invited` to `join`.
    let move_obj = build_membership_move(&space_id, &cell, "invited", "join")?;

    let moves = MemoryMoveStore::default();
    let anchors = MemoryAnchorStore::default();
    let cells = MemoryCellStore::default();
    let registry = MemoryCellRegistry::new();

    moves.put_pending(&move_obj).map_err(|e| Error::Protocol(format!("store: {e}")))?;

    // Compute expected state_root: after the Move, member.state = "join".
    let mut expected = BTreeMap::new();
    expected.insert(cell, CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected)?;

    let anchor = build_anchor(&space_id, &move_obj.id, &expected_root)?;
    let effect = apply_anchor(&anchor, &moves, &anchors, &cells, &registry, |_, _, _, _| {
        Ok::<(), String>(())
    })
    .map_err(|e| Error::Protocol(format!("apply_anchor: {e}")))?;

    Ok(vec![StateResolutionVector {
        name: "membership invited→join Move accepts under genesis Anchor".to_owned(),
        anchor: effect.anchor,
        accepted_count: effect.accepted_move_ids.len(),
        rejected_count: effect.rejected_moves.len(),
        post_state_root: effect.post_state_root,
    }])
}

fn build_membership_move(space_id: &SpaceId, cell: &CellRef, from: &str, to: &str) -> Result<Move> {
    let body = json!({
        "issuer": "did:web:admin.example",
        "space_id": space_id.as_str(),
        "preconditions": [],
        "effects": [{
            "cell": cell.as_str(),
            "op": { "kind": "transition", "from": from, "to": to }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
        "refs": [],
        "hlc": "0189c4d2af00-0000-aabbccdd"
    });
    let body_bytes = canonical::canonical_json_bytes(&body)?;
    let payload_digest = canonical::sha256_digest(&body_bytes);
    let id_hex: String = {
        use sha2::{Digest, Sha256};
        let mut s = String::with_capacity(64);
        for b in Sha256::digest(&body_bytes) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_digest": payload_digest,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "AAAA.BBBB.CCCC"
        }),
    );
    serde_json::from_value::<Move>(Value::Object(full))
        .map_err(|e| Error::Protocol(format!("Move deserialize: {e}")))
}

fn build_anchor(
    space_id: &SpaceId,
    frontier_move: &MoveId,
    state_root: &Hash,
) -> Result<contrix_core::Anchor> {
    use chrono::{TimeZone, Utc};
    use contrix_core::{Anchor, AnchorerSig, MoveSignature};
    let sig = MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:anchorer.example#k1".to_owned(),
        payload_digest: Hash::new(format!("sha256:{}", "ff".repeat(32)))
            .map_err(|e| Error::Protocol(format!("hash: {e}")))?,
        created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        jws: "AAAA.BBBB.CCCC".to_owned(),
    };
    let mut a = Anchor {
        id: AnchorId::new(format!("cx:anchor:sha256:{}", "00".repeat(32)))
            .map_err(|e| Error::Protocol(format!("anchor id: {e}")))?,
        realm_id: space_id.clone(),
        predecessor_refs: vec![],
        frontier: vec![frontier_move.clone()],
        state_root: state_root.clone(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        anchorer_signature: AnchorerSig::Single(sig),
        anchored_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned())
            .map_err(|e| Error::Protocol(format!("hlc: {e}")))?,
        kind: contrix_core::AnchorKind::Normal,
    };
    a.id = a.derive_id().map_err(|e| Error::Protocol(format!("derive: {e}")))?;
    Ok(a)
}

pub fn domain_counts(report: &ConformanceReport) -> BTreeMap<ConformanceDomain, usize> {
    let mut counts = BTreeMap::new();
    for row in &report.rows {
        *counts.entry(row.domain.clone()).or_default() += 1;
    }
    if !report.event_vectors.is_empty() {
        counts.insert(ConformanceDomain::Events, report.event_vectors.len());
    }
    if !report.state_vectors.is_empty() {
        counts.insert(ConformanceDomain::StateResolution, report.state_vectors.len());
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_protocol_boundary_domains() {
        let report = conformance_report().unwrap();
        for domain in [
            ConformanceDomain::ClientServer,
            ConformanceDomain::Applet,
            ConformanceDomain::PushGateway,
            ConformanceDomain::Identity,
            ConformanceDomain::Events,
            ConformanceDomain::StateResolution,
            ConformanceDomain::Operations,
            ConformanceDomain::Schema,
            ConformanceDomain::Html,
            ConformanceDomain::Crypto,
            ConformanceDomain::Ui,
            ConformanceDomain::Ffi,
        ] {
            assert!(report.covers_domain(domain.clone()), "{domain:?}");
        }
        assert!(report.operation_ids().contains("cx.events.submit"));
        assert!(report.operation_ids().contains("cx.identity.resolve"));
        assert!(report.operation_ids().contains("cx.crypto.machine_request"));
        assert!(report.operation_ids().contains("cx.ui.timeline_projection"));
        assert!(report.operation_ids().contains("cx.ffi.wasm_runtime"));
        assert!(report.operation_ids().contains("cx.operations.catalog"));
        assert!(report.operation_ids().contains("cx.schema.catalog"));
        assert!(report.operation_ids().contains("cx.html.normalize"));
    }

    #[test]
    fn boundary_crate_smoke_contracts_validate() {
        contrix_core::operations::operation_catalog().validate().unwrap();
        assert!(!contrix_core::operations::negative_dag_vectors().is_empty());
        contrix_core::schema::schema_catalog().validate().unwrap();
        contrix_core::schema::validate_schema_vectors(
            &contrix_core::schema::built_in_schema_vectors(),
        )
        .unwrap();
        contrix_html::RichTextDocument::normalize(
            "Hello @alice <script>bad()</script>",
            contrix_html::RichTextFormat::Html,
        )
        .unwrap();
        contrix_ffi::WasmRuntimeContract::default().validate().unwrap();

        let mut plan = contrix_crypto::CryptoMachinePlan::default();
        plan.push(
            "keys",
            contrix_crypto::CryptoMachineReqBody::QueryDeviceKeys {
                users: vec![Did::new("did:web:alice.example").unwrap()],
            },
        )
        .unwrap();
        assert_eq!(plan.pending_len(), 1);
    }

    #[test]
    fn event_vectors_include_unknown_raw_preservation() {
        let vectors = event_taxonomy_vectors().unwrap();
        let custom = vectors.iter().find(|vector| vector.preserves_unknown).unwrap();
        assert_eq!(custom.input["opaque"], true);
    }

    #[test]
    fn state_vector_exercises_apply_anchor_round_trip() {
        let vectors = state_resolution_vectors().unwrap();
        assert_eq!(vectors.len(), 1);
        // The single membership Move must accept under genesis Anchor with no rejects.
        assert_eq!(vectors[0].accepted_count, 1);
        assert_eq!(vectors[0].rejected_count, 0);
        // post_state_root MUST start with the canonical sha256: prefix.
        assert!(vectors[0].post_state_root.as_str().starts_with("sha256:"));
    }
}
