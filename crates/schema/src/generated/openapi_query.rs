//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen

pub fn openapi_query_operations() -> Vec<(&'static str, serde_json::Value)> {
    vec![(
        "/_arkret/self/relation-conflicts/candidates",
        serde_json::json!({"description":"Canonical RFC 10008 QUERY binding for\n`ak.self.relation_conflicts.read.candidates.v1`. The JSON content names one\nRealm and one primary conflict domain; the response carries the frozen\nbaseline, one 256-member page of the canonically ordered candidate list\nand the page chain digests. The ordinary 16-head diagnostic bound governs\nonly the optional diagnostic field and never truncates this material.\n","operationId":"ak.self.relation_conflicts.read.candidates","parameters":[{"description":"Required exact versioned operation_id selector for every canonical Arkret HTTP request.","in":"header","name":"Arkret-Operation","required":true,"schema":{"const":"ak.self.relation_conflicts.read.candidates.v1","type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RelationConflictCandidatesRequestBody"}}},"required":true},"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RelationConflictCandidatesOutcome"}}},"description":"One verified page of the Relation conflict repair material."},"404":{"description":"`not_found` — no such Realm, domain, or the caller may not know the group exists."},"409":{"description":"`failed_precondition` — `relation_conflict_group_not_visible`, `relation_conflict_material_unavailable`, or `relation_conflict_material_page_gap`."}},"security":[{"dpopProof":[],"sessionGrantAuth":[]},{"destinationServiceId":[],"httpMessageSignature":[],"sourceServiceId":[]}],"summary":"Read one page of the frozen Relation conflict repair material."}),
    )]
}

pub fn openapi_query_components() -> serde_json::Value {
    serde_json::json!({"schemas":{"RelationConflictCandidatesOutcome":{"$ref":"../schemas/relation.schema.json#/$defs/relation_conflict_candidates_outcome"},"RelationConflictCandidatesRequestBody":{"$ref":"../schemas/relation.schema.json#/$defs/relation_conflict_candidates_request_body"}}})
}
