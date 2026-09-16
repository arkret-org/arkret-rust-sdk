//! MLS transport-envelope projection bindings.
//!
//! These integration tests moved here from `arkret-mls` when the OpenMLS
//! isolation layer was split out: the envelope -> typed local draft and
//! envelope -> typed local draft projections live on the event-draft side.
//! Welcome delivery is now a Station-authored atomic delivery artifact rather
//! than the retired account-sync device-message facade.

use arkret_event_draft::MlsEnvelopeOperationExt;
use arkret_models_crypto::mls_envelopes::{MlsCommitEnvelope, MlsProposalEnvelope};
use arkret_wire::{Hash, OperationId, RealmId};

fn hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn commit_envelope() -> MlsCommitEnvelope {
    MlsCommitEnvelope {
        group_id: "Zml4dHVyZS1yZWFsbQ".to_owned(),
        epoch: 7,
        commit: "AQIDBA".to_owned(),
        commit_digest: hash('c'),
        ratchet_tree: None,
    }
}

fn proposal_envelope() -> MlsProposalEnvelope {
    MlsProposalEnvelope {
        group_id: "Zml4dHVyZS1yZWFsbQ".to_owned(),
        epoch: 6,
        proposal_type: "add".to_owned(),
        proposal: "UFJPUE9TQUw".to_owned(),
        proposal_digest: hash('b'),
        ratchet_tree: None,
    }
}

#[test]
fn commit_envelope_projects_to_mls_commit_operation() {
    let op = commit_envelope()
        .operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-02369de2e9c6").unwrap(),
            RealmId::new("ak:realm:Aem4Fslkz9MYTpkIWXBkG7oIckLtfqNcZAC_WeexhdkQ").unwrap(),
        )
        .unwrap();

    assert_eq!(op.object_kind, "mls_commit");
    let object_id = op.object_id.as_deref().unwrap();
    assert!(object_id.contains("Zml4dHVyZS1yZWFsbQ"));
    assert_eq!(object_id, "Zml4dHVyZS1yZWFsbQ:7");
    assert_eq!(op.payload.epoch, 7);
}

#[test]
fn proposal_envelope_projects_to_mls_proposal_operation() {
    let op = proposal_envelope()
        .operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-335be376d210").unwrap(),
            RealmId::new("ak:realm:Aem4Fslkz9MYTpkIWXBkG7oIckLtfqNcZAC_WeexhdkQ").unwrap(),
        )
        .unwrap();

    assert_eq!(op.object_kind, "mls_proposal");
    assert_eq!(op.payload.proposal_type, "add");
}
