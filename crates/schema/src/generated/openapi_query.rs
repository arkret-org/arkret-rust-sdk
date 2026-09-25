//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: openapi/arkret-service-api.openapi.yaml; version=1.0.0;
//! sha256=e5fdcc4432119ba688c960edb1e7958ec2bc19a293b8bff02476a74a0c577a52

pub fn openapi_query_operations() -> Vec<(&'static str, serde_json::Value)> {
    vec![(
        "/_arkret/self/events/delivery-status",
        serde_json::json!({"description":"Canonical RFC 10008 QUERY binding for\n`ak.self.events.read.delivery_status.v1`. Unknown and caller-invisible Events\nshare the same `not_found` response. This read does not resolve a new route,\nadvance delivery retry state, mutate an intent, or create another fanout round.\n","operationId":"ak.self.events.read.delivery_status","parameters":[{"description":"Required exact versioned operation_id selector for every canonical Arkret HTTP request.","in":"header","name":"Arkret-Operation","required":true,"schema":{"const":"ak.self.events.read.delivery_status.v1","type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/EventDeliveryStatusRequestBody"}}},"required":true},"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/EventDeliveryStatusOutcome"}}},"description":"Complete frozen target set, sorted byte-wise by opaque target_id."},"404":{"description":"`not_found` — no such accepted Event, or the caller may not know it exists."}},"security":[{"dpopProof":[],"sessionGrantAuth":[]}],"summary":"Read the durable frozen fanout target set for one visible Event."}),
    )]
}

pub fn openapi_query_components() -> serde_json::Value {
    serde_json::json!({"schemas":{"EventDeliveryStatusOutcome":{"$ref":"../schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusOutcome"},"EventDeliveryStatusRequestBody":{"$ref":"../schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusRequestBody"}}})
}
