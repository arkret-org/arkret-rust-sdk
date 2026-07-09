use arkret::{
    Did, Hlc, OP_MESSAGE_CREATE, OperationEnvelopeBuilder, OperationEventConversion, OperationId,
    OperationKindRegistry, RealmId,
};
use serde_json::json;

#[test]
fn default_feature_surface_exposes_protocol_types() -> arkret::Result<()> {
    let draft = OperationEnvelopeBuilder::new(
        OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")?,
        RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d")?,
        Did::new("did:webvh:z6mkfixture:alice.example")?,
        OP_MESSAGE_CREATE,
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
    )
    .with_payload(json!({
        "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
        "track_name": "main",
        "content": {"kind": "ck.content.text", "body": "hello"}
    }))
    .build(&OperationKindRegistry::default())?;

    let event = draft.into_event_envelope(OperationEventConversion::default())?;
    assert_eq!(event.payload["content"]["body"], "hello");
    Ok(())
}
