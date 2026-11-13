//! Selection tests only; the caller's native original/Commit authority is separate.
use super::*;

fn fixture() -> (Event, serde_json::Value) {
    let f = arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
        .unwrap();
    let receive = &f["attachment_key_receive"];
    let mut original = receive["original"].clone();
    let event_id: arkret_wire::EventId =
        serde_json::from_value(original["event_id"].clone()).unwrap();
    original["payload"]["strand_id"] =
        serde_json::to_value(arkret_wire::StrandId::from_event_id(&event_id)).unwrap();
    original["payload"]["track_name"] = serde_json::json!("discussion");
    (
        serde_json::from_value(original).unwrap(),
        receive["parent_plaintext"].clone(),
    )
}

#[test]
fn whole_envelope_requires_no_parent_key_but_attachment_does() {
    let (event, plaintext) = fixture();
    let path = "/payload/encrypted_content";
    assert_eq!(history_content_key_width(&event, path).unwrap(), 16);
    assert!(matches!(
        select_history_content(&event, path, |_| panic!(
            "a whole envelope must not be opened to select it"
        ))
        .unwrap(),
        HistoryContentSelection::Envelope(_)
    ));
    let child = format!("{path}/attachments/0");
    assert_eq!(history_content_key_width(&event, &child).unwrap(), 32);
    assert!(
        select_history_content(&event, &child, |_| Err(invalid(
            "independent parent key absent"
        )))
        .is_err()
    );
    let selected = select_history_content(&event, &child, |_| {
        Ok(arkret_canonical::canonical_json_bytes(&plaintext)?)
    })
    .unwrap();
    let HistoryContentSelection::Attachment {
        descriptor, parent, ..
    } = selected
    else {
        panic!("expected exact attachment")
    };
    assert!(parent.is_some());
    assert_eq!(
        serde_json::to_value(descriptor).unwrap(),
        plaintext["attachments"][0]
    );
}

#[test]
fn containers_extension_fields_noncanonical_indices_and_missing_slots_fail_closed() {
    let (event, plaintext) = fixture();
    for suffix in [
        "",
        "/attachments",
        "/attachments/00",
        "/attachments/-",
        "/attachments/-1",
        "/attachments/999",
        "/attachments/0/key_commitment",
        "/unknown/attachments/0",
        "/parts/00/attachments/0",
    ] {
        let path = format!("/payload/encrypted_content{suffix}");
        if suffix.is_empty() {
            continue;
        }
        assert!(
            select_history_content(&event, &path, |_| Ok(
                arkret_canonical::canonical_json_bytes(&plaintext)?
            ))
            .is_err(),
            "{path}"
        );
    }
    assert!(select_history_content(&event, "/payload", |_| unreachable!()).is_err());
    assert!(
        select_history_content(&event, "/payload/encrypted_content/attachments/0", |_| Ok(
            br#"{"kind":"ak.content.text","body":"a","body":"b","attachments":[]}"#.to_vec()
        ))
        .is_err()
    );
}

#[test]
fn nested_and_plaintext_content_blocks_keep_original_array_positions() {
    let (event, plaintext) = fixture();
    let nested = serde_json::json!({"kind":"ak.content.composite","body":"", "parts":[plaintext]});
    let path = "/payload/encrypted_content/parts/0/attachments/0";
    assert!(matches!(
        select_history_content(&event, path, |_| Ok(
            arkret_canonical::canonical_json_bytes(&nested)?
        ))
        .unwrap(),
        HistoryContentSelection::Attachment { .. }
    ));
    let mut raw = serde_json::to_value(event).unwrap();
    raw["payload"]
        .as_object_mut()
        .unwrap()
        .remove("encrypted_content");
    raw["payload"]["content"] = nested;
    let plain: Event = serde_json::from_value(raw).unwrap();
    let path = "/payload/content/parts/0/attachments/0";
    let selected = select_history_content(&plain, path, |_| {
        panic!("plaintext parent belongs to the authenticated original")
    })
    .unwrap();
    assert!(matches!(
        selected,
        HistoryContentSelection::Attachment { parent: None, .. }
    ));
    let blocks = event_plain_content_blocks(&plain).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(
        history_attachment_slots(&blocks[0].1, &blocks[0].0).unwrap()[0].0,
        path
    );
    let mut patch = serde_json::to_value(&plain).unwrap();
    patch["kind"] = serde_json::json!("ak.strand.update");
    patch["payload"] = serde_json::json!({"strand_id":plain.payload["strand_id"], "patch":{"content":{"$op":"set","value":blocks[0].1}}});
    let patch: Event = serde_json::from_value(patch).unwrap();
    let path = "/payload/patch/content/value/parts/0/attachments/0";
    assert!(matches!(
        select_history_content(&patch, path, |_| unreachable!()).unwrap(),
        HistoryContentSelection::Attachment { parent: None, .. }
    ));
    assert_eq!(event_plain_content_blocks(&patch).unwrap().len(), 1);
}
