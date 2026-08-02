//! MLS transport-envelope projection bindings.
//!
//! These integration tests moved here from `arkret-mls` when the OpenMLS
//! isolation layer was split out: the envelope -> repo-`Operation` and
//! envelope -> `DeviceMessageTarget` projections live on the event-draft side
//! (`MlsEnvelopeOperationExt` / `MlsWelcomeTargetExt`), which owns the drafting
//! and to-device wire shapes. `arkret-mls` must not depend on this crate, so it
//! only tests that MLS group operations emit correct envelope fields; the
//! projection is exercised here over hand-constructed envelopes.

use arkret_event_draft::{MlsEnvelopeOperationExt, MlsWelcomeTargetExt};
use arkret_models_crypto::mls_envelopes::{
    MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
use arkret_wire::{DeviceId, DeviceMessageId, Did, Hash, OperationId, RealmId};
use chrono::Utc;

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

fn welcome_envelope() -> MlsWelcomeEnvelope {
    MlsWelcomeEnvelope {
        group_id: "Zml4dHVyZS1yZWFsbQ".to_owned(),
        epoch: 7,
        recipient_principal_id: Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e")
            .unwrap(),
        welcome: "V0VMQ09NRQ".to_owned(),
        welcome_hash: hash('e'),
        ratchet_tree: Some("VFJFRQ".to_owned()),
    }
}

#[test]
fn commit_envelope_projects_to_mls_commit_operation() {
    let op = commit_envelope()
        .operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-02369de2e9c6").unwrap(),
            RealmId::new("ak:realm:01904100-0000-7000-8000-4ecefcf31ad2").unwrap(),
        )
        .unwrap();

    assert_eq!(op.object_kind, "mls_commit");
    let object_id = op.object_id.unwrap();
    assert!(object_id.contains("Zml4dHVyZS1yZWFsbQ"));
    assert_eq!(object_id, "Zml4dHVyZS1yZWFsbQ:7");
    assert_eq!(op.payload["epoch"], 7);
}

#[test]
fn proposal_envelope_projects_to_mls_proposal_operation() {
    let op = proposal_envelope()
        .operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-335be376d210").unwrap(),
            RealmId::new("ak:realm:01904100-0000-7000-8000-4ecefcf31ad2").unwrap(),
        )
        .unwrap();

    assert_eq!(op.object_kind, "mls_proposal");
    assert_eq!(op.payload["proposal_type"], "add");
}

#[test]
fn welcome_envelope_projects_to_device_message_target() {
    let target = welcome_envelope()
        .welcome_device_message_target(
            DeviceMessageId::new("ak:device_message:01904100-0000-7000-8000-000000000001").unwrap(),
            Utc::now(),
        )
        .unwrap();

    assert_eq!(target.kind.as_str(), "ak.mls.welcome.v1");
    assert_eq!(
        target.content["recipient_device_id"],
        "ak:device:01904100-0000-7000-8000-00000000000e"
    );
    assert_eq!(target.content["epoch"], 7);
    assert_eq!(target.content["group_id"], "Zml4dHVyZS1yZWFsbQ");
}
