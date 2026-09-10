use arkret_models_collaboration::history_key::{
    EpochRange, HistoryKeyResponseContent, HistoryKeyResponseSendRequestBody,
    HistoryKeyResponseSigningInput, HistoryResponseChunkDescriptor, HistoryResponseId,
    HistoryResponseManifest, HistoryResponseManifestKind,
};
use arkret_wire::{
    ActorId, DidCoreId, DidUrl, Hash, HistoryEffectiveScope, RealmId, SignerEvidenceRef,
};
use chrono::{DateTime, Utc};

fn digest(byte: &str) -> Hash {
    Hash::new(format!("sha256:{}", byte.repeat(64))).unwrap()
}

fn signing_input() -> HistoryKeyResponseSigningInput {
    HistoryKeyResponseSigningInput {
        response_id: HistoryResponseId::new(
            "ak:history_response:019c0000-0000-7000-8000-000000000001",
        )
        .unwrap(),
        effective_scope: HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
        },
        source_actor_id: ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
        source_sender_domain: "history.example".to_owned(),
        source_signer_evidence_ref: SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            digest("a")
        ))
        .unwrap(),
        request_digest: digest("1"),
        request_receipt_digest: digest("2"),
        expires_at: DateTime::parse_from_rfc3339("2026-08-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        content: HistoryKeyResponseContent::Manifest(HistoryResponseManifest {
            kind: HistoryResponseManifestKind::Value,
            chunks: vec![HistoryResponseChunkDescriptor {
                chunk_response_id: HistoryResponseId::new(
                    "ak:history_response:019c0000-0000-7000-8000-000000000002",
                )
                .unwrap(),
                chunk_index: 0,
                covered_epoch_range: EpochRange {
                    from_epoch: 0,
                    to_epoch: 0,
                },
            }],
        }),
    }
}

#[test]
fn source_proof_binds_reusable_evidence_reference() {
    let observation = signing_input();
    let evidence_digest = digest("a");
    let evidence_ref =
        SignerEvidenceRef::new(format!("ak:signer_evidence:{evidence_digest}")).unwrap();
    let verification_method = DidUrl::new("did:web:agent.example#response-1").unwrap();
    let source = HistoryKeyResponseSendRequestBody::build_signed_proof(
        verification_method,
        observation.expires_at - chrono::Duration::minutes(1),
        |source_proof| HistoryKeyResponseSendRequestBody {
            response_id: observation.response_id.clone(),
            effective_scope: observation.effective_scope.clone(),
            source_actor_id: observation.source_actor_id.clone(),
            source_sender_domain: observation.source_sender_domain.clone(),
            source_signer_evidence_ref: evidence_ref.clone(),
            request_digest: observation.request_digest.clone(),
            request_receipt_digest: observation.request_receipt_digest.clone(),
            expires_at: observation.expires_at,
            content: observation.content.clone(),
            source_proof,
        },
        |bytes| {
            arkret_signatures::jws::sign_jws_ed25519(
                bytes,
                &ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
            )
            .map_err(arkret_wire::WireError::Protocol)
        },
    )
    .unwrap();

    source.validate().unwrap();
}
