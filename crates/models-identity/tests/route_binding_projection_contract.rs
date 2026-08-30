//! Byte-exact contract for the `describe_digest` route-binding projection.
//!
//! `zh/sync/service-surface.md` §2.6 fixes the projection to exactly
//! `{service_id, service_kind, service_resolution, http_json_base_url}`.
//! Every producer and verifier in the workspace derives it through
//! [`route_binding_describe_digest`], so a field rename, reorder, or added
//! member here silently invalidates every signed service resolution record.
//! Pin the canonical JCS bytes so that can only happen deliberately.
use arkret_models_identity::{ResolutionCommitment, route_binding_describe_digest};
use arkret_wire::{Did, ServiceKind};

#[test]
fn route_binding_projection_is_byte_exact() {
    let did = Did::new("did:webvh:QmExampleScidValue123456:media.example".to_owned()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let commitment = ResolutionCommitment {
        did,
        method_history_head: format!("sha256:{}", "1".repeat(64)),
        version_id: "fixture-route-v1".to_owned(),
    };

    let digest = route_binding_describe_digest(
        &service_id,
        ServiceKind::Station.as_str(),
        &commitment,
        "https://media.example/",
    )
    .unwrap();

    assert_eq!(
        digest.as_str(),
        "sha256:f8494350acf39bc9d240531451c4770b20f9776dcf10703299b985e73f6d81ea",
        "route-binding projection digest changed"
    );
}
