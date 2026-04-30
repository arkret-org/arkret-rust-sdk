//! Reusable conformance fixtures and catalog coverage helpers.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{Did, Event, EventId, Hlc, Result, SpaceId};
use contrix_events::{AnyEventContent, EventClass, EventContentEnvelope, MESSAGE_TEXT};
use contrix_state_res::StateReducer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDomain {
    ClientServer,
    Federation,
    Appservice,
    PushGateway,
    Identity,
    Signatures,
    Events,
    StateResolution,
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

pub fn conformance_report() -> Result<ConformanceReport> {
    Ok(ConformanceReport {
        rows: endpoint_coverage_rows(),
        event_vectors: event_taxonomy_vectors()?,
        state_vectors: state_resolution_vectors()?,
    })
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
            domain: ConformanceDomain::Store,
            operation_id: "cx.store.repo_object".to_owned(),
            method: "CONTRACT".to_owned(),
            path: "contrix-store://repo-object-store".to_owned(),
            request_schema: "RepoWriteBatch".to_owned(),
            response_schema: "StoreBatchReceipt".to_owned(),
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

    Ok(vec![
        EventTaxonomyVector {
            name: "text message content".to_owned(),
            kind: MESSAGE_TEXT.to_owned(),
            expected_class: text_envelope.class,
            input: text.content,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_protocol_boundary_domains() {
        let report = conformance_report().unwrap();
        for domain in [
            ConformanceDomain::ClientServer,
            ConformanceDomain::Federation,
            ConformanceDomain::Appservice,
            ConformanceDomain::PushGateway,
            ConformanceDomain::Identity,
            ConformanceDomain::Events,
            ConformanceDomain::StateResolution,
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
        assert!(report.operation_ids().contains("cx.crypto.machine_request"));
        assert!(report.operation_ids().contains("cx.ui.timeline_projection"));
        assert!(report.operation_ids().contains("cx.ffi.wasm_runtime"));
    }

    #[test]
    fn boundary_crate_smoke_contracts_validate() {
        contrix_store::memory_store_conformance_report().unwrap().validate().unwrap();
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
