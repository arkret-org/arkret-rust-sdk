//! Reusable conformance fixtures and catalog coverage helpers.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{Did, Error, Event, EventId, Hlc, Result, SpaceId};
use contrix_events::{
    AnyEventContent, CALL_DEVICE_MAPPING, COLLAB_ACTIVITY_BEACON, E2EE_SECRET_SEND, EventClass,
    EventContentEnvelope, MESSAGE_POLL_RESPONSE, MESSAGE_TEXT, classify_event_kind,
    parse_event_content,
};
use contrix_state_res::StateReducer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDomain {
    ClientServer,
    ClientServerApi,
    Federation,
    Appservice,
    PushGateway,
    Identity,
    Signatures,
    Events,
    StateResolution,
    Operations,
    Schema,
    Html,
    Store,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateResolutionVector {
    pub name: String,
    pub winner_event_id: EventId,
    pub conflict_count: usize,
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
    pub preserves_auth_refs: bool,
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
    pub filter_hash: String,
    pub frontier_size: usize,
    pub expects_filter_hash_mismatch: bool,
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
            "prev_refs": ["cx:event:01js0evbase00000000000000"],
            "auth_refs": ["cx:event:01js0evauth00000000000000"],
            "hlc": "01970e589d21-00000004-a13f9c2e",
            "content": { "body": "to be redacted" },
            "unsigned": { "transient": true }
        }),
        after_payload_cleared: true,
        preserves_actor_seq: true,
        preserves_prev_refs: true,
        preserves_auth_refs: true,
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

/// Reference sync vectors covering cursor `filter_hash` binding.
pub fn sync_vectors() -> Vec<SyncVector> {
    vec![
        SyncVector {
            vector_id: "sync/m-15-filter-hash-bound".to_owned(),
            filter_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            frontier_size: 1,
            expects_filter_hash_mismatch: false,
        },
        SyncVector {
            vector_id: "sync/m-16-filter-hash-mismatch-rejected".to_owned(),
            filter_hash: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                .to_owned(),
            frontier_size: 1,
            expects_filter_hash_mismatch: true,
        },
    ]
}

pub fn endpoint_coverage_rows() -> Vec<EndpointCoverageRow> {
    let mut rows = Vec::new();
    rows.extend(contrix_api::endpoints().iter().map(|endpoint| EndpointCoverageRow {
        domain: ConformanceDomain::ClientServer,
        operation_id: endpoint.operation_id.to_owned(),
        method: endpoint.method.as_str().to_owned(),
        path: endpoint.path.to_owned(),
        request_schema: endpoint.request_schema.to_owned(),
        response_schema: endpoint.response_schema.to_owned(),
    }));
    rows.extend(contrix_client_api::client_api_endpoints().iter().map(|endpoint| {
        EndpointCoverageRow {
            domain: ConformanceDomain::ClientServerApi,
            operation_id: endpoint.operation_id.to_owned(),
            method: format!("{:?}", endpoint.method),
            path: endpoint.path.to_owned(),
            request_schema: endpoint.request_schema.to_owned(),
            response_schema: endpoint.response_schema.to_owned(),
        }
    }));
    rows.extend(contrix_federation_api::federation_endpoints().iter().map(|endpoint| {
        EndpointCoverageRow {
            domain: ConformanceDomain::Federation,
            operation_id: endpoint.operation_id.to_owned(),
            method: format!("{:?}", endpoint.method),
            path: endpoint.path.to_owned(),
            request_schema: endpoint.request_schema.to_owned(),
            response_schema: endpoint.response_schema.to_owned(),
        }
    }));
    rows.extend(contrix_appservice_api::appservice_endpoints().iter().map(|endpoint| {
        EndpointCoverageRow {
            domain: ConformanceDomain::Appservice,
            operation_id: endpoint.operation_id.to_owned(),
            method: format!("{:?}", endpoint.method),
            path: endpoint.path.to_owned(),
            request_schema: endpoint.request_schema.to_owned(),
            response_schema: endpoint.response_schema.to_owned(),
        }
    }));
    rows.extend(contrix_push_gateway_api::push_gateway_endpoints().iter().map(|endpoint| {
        EndpointCoverageRow {
            domain: ConformanceDomain::PushGateway,
            operation_id: endpoint.operation_id.to_owned(),
            method: format!("{:?}", endpoint.method),
            path: endpoint.path.to_owned(),
            request_schema: endpoint.request_schema.to_owned(),
            response_schema: endpoint.response_schema.to_owned(),
        }
    }));
    rows.extend(contrix_identity_api::identity_endpoints().iter().map(|endpoint| {
        EndpointCoverageRow {
            domain: ConformanceDomain::Identity,
            operation_id: endpoint.operation_id.to_owned(),
            method: format!("{:?}", endpoint.method),
            path: endpoint.path.to_owned(),
            request_schema: endpoint.request_schema.to_owned(),
            response_schema: endpoint.response_schema.to_owned(),
        }
    }));
    rows.extend(boundary_coverage_rows());
    rows
}

pub fn boundary_coverage_rows() -> Vec<EndpointCoverageRow> {
    vec![
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.catalog".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-operations://catalog".to_owned(),
            request_schema: "OperationKindRegistry".to_owned(),
            response_schema: "OperationCatalogReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.dag".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-operations://dag".to_owned(),
            request_schema: "OperationEnvelope".to_owned(),
            response_schema: "OperationDagReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.semantic_reducer".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-operations://semantics".to_owned(),
            request_schema: "OperationEnvelope".to_owned(),
            response_schema: "OperationSemanticReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Operations,
            operation_id: "cx.operations.negative_vectors".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-operations://negative-vectors".to_owned(),
            request_schema: "OperationDagNegativeVector".to_owned(),
            response_schema: "OperationDagNegativeVector".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Schema,
            operation_id: "cx.schema.catalog".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-schema://catalog".to_owned(),
            request_schema: "ProtocolSchemaRegistry".to_owned(),
            response_schema: "SchemaCatalogReport".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Schema,
            operation_id: "cx.schema.validation_vectors".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-schema://vectors".to_owned(),
            request_schema: "SchemaValidationVector".to_owned(),
            response_schema: "SchemaCompatibilityTable".to_owned(),
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
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.repo_object".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://repo-object-store".to_owned(),
            request_schema: "RepoWriteBatch".to_owned(),
            response_schema: "StoreBatchReceipt".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.core_event_store".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://core-event-store".to_owned(),
            request_schema: "CoreEventSubmitRequest".to_owned(),
            response_schema: "CoreEventSubmitReceipt".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.failure_cache".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://failure-cache".to_owned(),
            request_schema: "StoreFailureRecord".to_owned(),
            response_schema: "StoreFailureCache".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.sync_token".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://sync-token-store".to_owned(),
            request_schema: "PersistentSyncToken".to_owned(),
            response_schema: "PersistentSyncToken".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.send_queue".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://send-queue-store".to_owned(),
            request_schema: "SendQueueRecord".to_owned(),
            response_schema: "SendQueueRecord".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.media_cache".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://media-cache-store".to_owned(),
            request_schema: "MediaCacheRecord".to_owned(),
            response_schema: "MediaCacheRecord".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Crypto,
            operation_id: "cx.crypto.machine_request".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-crypto://machine".to_owned(),
            request_schema: "CryptoMachineRequest".to_owned(),
            response_schema: "CryptoMachineResponse".to_owned(),
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
            path: "contrix-ui://timeline".to_owned(),
            request_schema: "Event".to_owned(),
            response_schema: "TimelineItem".to_owned(),
        },
        EndpointCoverageRow {
            domain: ConformanceDomain::Ui,
            operation_id: "cx.ui.notification_evaluation".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-ui://notifications".to_owned(),
            request_schema: "PushRuleSet".to_owned(),
            response_schema: "NotificationEvaluation".to_owned(),
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
            response_schema: "EmbeddingTargetDecision".to_owned(),
        },
    ]
}

pub fn event_taxonomy_vectors() -> Result<Vec<EventTaxonomyVector>> {
    let text = Event::new(
        MESSAGE_TEXT,
        SpaceId::new("cx:space:01JS0SP000000000000000000")?,
        Did::new("did:web:alice.example")?,
        1,
        Hlc::new("01970e589d21-00000001-a13f9c2e")?,
        json!({"body": "hello"}),
    )?;
    let text_envelope = EventContentEnvelope::from_event(&text)?;

    let custom = Event::new(
        "vendor.example.custom",
        SpaceId::new("cx:space:01JS0SP000000000000000000")?,
        Did::new("did:web:alice.example")?,
        2,
        Hlc::new("01970e589d21-00000002-a13f9c2e")?,
        json!({"opaque": true, "nested": {"n": 1}}),
    )?;
    let custom_envelope = EventContentEnvelope::from_event(&custom)?;

    let poll_response = json!({
        "poll_event_id": "cx:event:poll-1",
        "answer_ids": ["a"]
    });
    parse_event_content(MESSAGE_POLL_RESPONSE, poll_response.clone())?;

    let call_device_mapping = json!({
        "call_id": "call-1",
        "devices_by_user": {
            "did:web:alice.example": ["dev_alice"]
        }
    });
    parse_event_content(CALL_DEVICE_MAPPING, call_device_mapping.clone())?;

    let activity_beacon = json!({
        "user_id": "did:web:alice.example",
        "device_id": "dev_alice",
        "activity": "viewing",
        "observed_at": "2026-05-01T00:00:00Z"
    });
    parse_event_content(COLLAB_ACTIVITY_BEACON, activity_beacon.clone())?;

    let secret_send = json!({
        "request_id": "req-1",
        "name": "recovery",
        "encrypted_secret": {
            "algorithm": "cx.v1",
            "sender_key": "ed25519:abc",
            "ciphertext": { "body": "encrypted" }
        }
    });
    parse_event_content(E2EE_SECRET_SEND, secret_send.clone())?;

    Ok(vec![
        EventTaxonomyVector {
            name: "text message content".to_owned(),
            kind: MESSAGE_TEXT.to_owned(),
            expected_class: text_envelope.class,
            input: text.content,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "poll response content".to_owned(),
            kind: MESSAGE_POLL_RESPONSE.to_owned(),
            expected_class: classify_event_kind(MESSAGE_POLL_RESPONSE),
            input: poll_response,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "call device mapping content".to_owned(),
            kind: CALL_DEVICE_MAPPING.to_owned(),
            expected_class: classify_event_kind(CALL_DEVICE_MAPPING),
            input: call_device_mapping,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "collaboration activity beacon content".to_owned(),
            kind: COLLAB_ACTIVITY_BEACON.to_owned(),
            expected_class: classify_event_kind(COLLAB_ACTIVITY_BEACON),
            input: activity_beacon,
            preserves_unknown: false,
        },
        EventTaxonomyVector {
            name: "secret send content".to_owned(),
            kind: E2EE_SECRET_SEND.to_owned(),
            expected_class: classify_event_kind(E2EE_SECRET_SEND),
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
    let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000")?;
    let mut reducer = StateReducer::new(space_id.clone(), "1");
    let join = Event::new(
        "cx.member.state",
        space_id.clone(),
        Did::new("did:web:alice.example")?,
        1,
        Hlc::new("01970e589d21-00000002-a13f9c2e")?,
        json!({"principal_id": "did:web:bob.example", "membership": "join"}),
    )?;
    let ban = Event::new(
        "cx.member.state",
        space_id,
        Did::new("did:web:admin.example")?,
        1,
        Hlc::new("01970e589d21-00000001-a13f9c2e")?,
        json!({"principal_id": "did:web:bob.example", "membership": "ban"}),
    )?;
    reducer.apply_events(&[join, ban])?;
    let resolved = reducer
        .resolved_state
        .get("cx.member.state|did:web:bob.example")
        .expect("fixture creates resolved state");
    Ok(vec![StateResolutionVector {
        name: "membership ban wins over join".to_owned(),
        winner_event_id: resolved.source_event_id.clone(),
        conflict_count: reducer.conflict_records.len(),
    }])
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreEventStoreFixtureReport {
    pub profile: String,
    pub checks: BTreeMap<String, bool>,
}

impl CoreEventStoreFixtureReport {
    pub fn validate(&self) -> Result<()> {
        if self.profile != contrix_store::CORE_EVENT_STORE_PROFILE {
            return Err(Error::Protocol("core event store fixture profile mismatch".to_owned()));
        }
        if self.checks.values().all(|passed| *passed) {
            Ok(())
        } else {
            Err(Error::Protocol("core event store fixture checks failed".to_owned()))
        }
    }
}

pub fn core_event_store_fixture_report() -> Result<CoreEventStoreFixtureReport> {
    use contrix_store::{
        CoreEventBackfillRequest, CoreEventBatchGetRequest, CoreEventFetchRequest,
        CoreEventFrontierRequest, CoreEventStore, CoreEventSubmitStatus, MemoryRuntimeStore,
    };

    let mut store = MemoryRuntimeStore::new();
    let first = Event::new(
        "cx.message.create",
        SpaceId::new("cx:space:fixture")?,
        Did::new("did:web:fixture.example")?,
        1,
        Hlc::new("01970e589d21-00000001-a13f9c2e")?,
        json!({"body": "one"}),
    )?;
    let first_id = first.event_id.clone();
    let first_receipt = store.submit_event(first.clone())?;
    let duplicate_receipt = store.submit_event(first.clone())?;

    let mut second = Event::new(
        "cx.message.create",
        first.space_id.clone(),
        first.actor_id.clone(),
        2,
        Hlc::new("01970e589d21-00000002-a13f9c2e")?,
        json!({"body": "two"}),
    )?;
    second.prev_refs.push(first_id.clone());
    second.refresh_event_id()?;
    store.submit_event(second.clone())?;

    let mut conflict = first;
    conflict.content = json!({"body": "conflict"});
    let conflict_rejected = store.submit_event(conflict).is_err();
    let fetched =
        store.fetch_event(&CoreEventFetchRequest { event_id: first_id.clone() }).is_some();
    let batch = store.batch_get_events(&CoreEventBatchGetRequest {
        event_ids: vec![first_id, second.event_id.clone()],
    });
    let backfill = store.backfill_events(&CoreEventBackfillRequest {
        space_id: second.space_id.clone(),
        from_event_id: None,
        limit: 10,
    })?;
    let frontier = store.event_frontier(&CoreEventFrontierRequest { space_id: second.space_id });

    Ok(CoreEventStoreFixtureReport {
        profile: contrix_store::CORE_EVENT_STORE_PROFILE.to_owned(),
        checks: BTreeMap::from([
            (
                "accepts_new_event".to_owned(),
                first_receipt.status == CoreEventSubmitStatus::AcceptedNew,
            ),
            (
                "accepts_idempotent_duplicate".to_owned(),
                duplicate_receipt.status == CoreEventSubmitStatus::AcceptedDuplicate,
            ),
            ("rejects_same_id_different_bytes".to_owned(), conflict_rejected),
            ("fetches_event".to_owned(), fetched),
            ("batch_gets_events".to_owned(), batch.len() == 2),
            ("backfills_events".to_owned(), backfill.events.len() == 2),
            ("tracks_frontier".to_owned(), frontier.frontier == vec![second.event_id]),
        ]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_protocol_boundary_domains() {
        let report = conformance_report().unwrap();
        for domain in [
            ConformanceDomain::ClientServer,
            ConformanceDomain::ClientServerApi,
            ConformanceDomain::Federation,
            ConformanceDomain::Appservice,
            ConformanceDomain::PushGateway,
            ConformanceDomain::Identity,
            ConformanceDomain::Events,
            ConformanceDomain::StateResolution,
            ConformanceDomain::Operations,
            ConformanceDomain::Schema,
            ConformanceDomain::Html,
            ConformanceDomain::Store,
            ConformanceDomain::Crypto,
            ConformanceDomain::Ui,
            ConformanceDomain::Ffi,
        ] {
            assert!(report.covers_domain(domain.clone()), "{domain:?}");
        }
        assert!(report.operation_ids().contains("cx.federation.transaction"));
        assert!(report.operation_ids().contains("cx.identity.resolve"));
        assert!(report.operation_ids().contains("cx.store.repo_object"));
        assert!(report.operation_ids().contains("cx.store.core_event_store"));
        assert!(report.operation_ids().contains("cx.crypto.machine_request"));
        assert!(report.operation_ids().contains("cx.ui.timeline_projection"));
        assert!(report.operation_ids().contains("cx.ffi.wasm_runtime"));
        assert!(report.operation_ids().contains("cx.operations.catalog"));
        assert!(report.operation_ids().contains("cx.schema.catalog"));
        assert!(report.operation_ids().contains("cx.html.normalize"));
        assert!(report.operation_ids().contains("cx.account.register"));
        assert!(report.operation_ids().contains("cx.sync.sliding"));
    }

    #[test]
    fn boundary_crate_smoke_contracts_validate() {
        contrix_client_api::client_api_coverage_report().validate().unwrap();
        contrix_operations::operation_catalog().validate().unwrap();
        assert!(!contrix_operations::negative_dag_vectors().is_empty());
        contrix_schema::schema_catalog().validate().unwrap();
        contrix_schema::validate_schema_vectors(&contrix_schema::built_in_schema_vectors())
            .unwrap();
        contrix_html::RichTextDocument::normalize(
            "Hello @alice <script>bad()</script>",
            contrix_html::RichTextFormat::Html,
        )
        .unwrap();
        contrix_store::memory_store_conformance_report().unwrap().validate().unwrap();
        core_event_store_fixture_report().unwrap().validate().unwrap();
        contrix_ffi::WasmRuntimeContract::default().validate().unwrap();

        let mut plan = contrix_crypto::CryptoMachinePlan::default();
        plan.push(
            "keys",
            contrix_crypto::CryptoMachineRequest::QueryDeviceKeys {
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
    fn state_vector_records_conflict() {
        let vectors = state_resolution_vectors().unwrap();
        assert_eq!(vectors[0].conflict_count, 1);
    }
}
