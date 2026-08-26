//! Byte-exact contract for the `describe_digest` route-binding projection.
//!
//! `zh/sync/service-surface.md` §2.6 fixes the projection to exactly
//! `{service_id, service_kind, service_resolution, http_json_base_url}`.
//! Every producer and verifier in the workspace derives it through
//! [`route_binding_describe_digest`], so a field rename, reorder, or added
//! member here silently invalidates every signed service resolution record.
//! Pin the canonical JCS bytes so that can only happen deliberately.
use arkret_models_identity::{ResolutionCommitment, route_binding_describe_digest};
use arkret_wire::{DidFullId, ServiceKind};

#[test]
fn route_binding_projection_is_byte_exact() {
    let full_id =
        DidFullId::new("did:webvh:QmExampleScidValue123456:media.example".to_owned()).unwrap();
    let service_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
    let commitment = ResolutionCommitment {
        full_id,
        method_history_head: format!("sha256:{}", "1".repeat(64)),
        version_id: "fixture-route-v1".to_owned(),
    };

    let digest = route_binding_describe_digest(
        &service_id,
        ServiceKind::PrincipalServer.as_str(),
        &commitment,
        "https://media.example/",
    )
    .unwrap();

    assert_eq!(
        digest.as_str(),
        "sha256:3b951dbb8416fcfd1a6fb4ed63c3ea5c7f005af5690cecd41c641eca3e6f3230",
        "route-binding projection digest changed"
    );
}
