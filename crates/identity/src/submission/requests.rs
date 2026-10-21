//! Typed traversal of SDK-owned publication requests, never a JSON classifier.

use arkret_models_collaboration::account_operations::{
    AccountRegisterRequestBody, AccountUpdateProfileRequestBody,
};
use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentPauseRequestBody, AgentProvisionRequestBody,
    AgentResumeRequestBody,
};
use arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody;
use arkret_models_collaboration::authority_commit::{
    PeerAuthoritySubmitRequest, PeerRegisteredAtomicUnit, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody;
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactCommitRequestBody, ContactOperationRequestBody,
    ContactRejectRequestBody, ContactScopeUpdateRequestBody, ContactTombstoneRequestBody,
};
use arkret_models_collaboration::device_pairing::AccountDevicePairRequestBody;
use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleMemberDeleteRequestBody, CircleMemberRequestBody,
    CircleScopeRotateRequestBody,
};
use arkret_models_collaboration::governance::moderation::ModerationReportRequestBody;
use arkret_models_collaboration::message_authoring::MessageSubmitRequestBody;
use arkret_models_collaboration::objects::read_receipts::ReadCursorAdvanceRequestBody;
use arkret_models_collaboration::sidecar_operations::SidecarEnsureRequestBody;
use arkret_models_collaboration::strand_watch_operations::{
    PeerWatchAuditReadRequest, WatchAuditReadRequest,
};
use arkret_models_identity::account::{
    AccountDataDeleteRequestBody, AccountDataReplaceRequestBody,
};
use arkret_models_integration::{
    AppletInstallRequestBody, AppletRevokeRequestBody, AppletTransactionRequestBody,
};
use arkret_wire::{
    ActorPrivateEventSubmitRequestBody, AuthoritySubmitRequest, Event, EventAdmissionSubmission,
    EventsSubmitBatchRequestBody, MlsCommitSubmission, RealmCommit,
};

mod sealed {
    pub trait Sealed {}
}

/// Closed traversal of the originals carried by a concrete SDK request.
/// Downstream crates cannot define another request interpretation.
pub trait PublicationRequest: sealed::Sealed {
    fn producer_events(&self) -> Vec<&Event>;
    fn realm_commits(&self) -> Vec<&RealmCommit> {
        Vec::new()
    }
    fn validate_publication_shape(&self) -> arkret_wire::Result<()>;
}

macro_rules! request {
    ($ty:ty, $this:ident, $events:expr, $validate:expr) => {
        impl sealed::Sealed for $ty {}
        impl PublicationRequest for $ty {
            fn producer_events(&$this) -> Vec<&Event> { $events }
            fn validate_publication_shape(&$this) -> arkret_wire::Result<()> { $validate }
        }
    };
}

fn canonical_shape<T: serde::Serialize>(request: &T) -> arkret_wire::Result<()> {
    arkret_canonical::canonical_json_bytes(request)?;
    Ok(())
}

request!(
    ContactCommitRequestBody,
    self,
    vec![&self.signed_event],
    canonical_shape(self)
);
request!(
    ContactRejectRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.signed_event],
    },
    canonical_shape(self)
);
request!(
    ContactScopeUpdateRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.signed_event],
    },
    canonical_shape(self)
);
request!(
    ConsentReplaceRequestBody,
    self,
    vec![&self.consent_event.event],
    self.validate()
);
request!(
    ReadCursorAdvanceRequestBody,
    self,
    vec![&self.advance_event.event],
    self.advance_event.validate()
);

request!(
    EventAdmissionSubmission,
    self,
    vec![&self.event],
    self.validate()
);
request!(
    PeerWatchAuditReadRequest,
    self,
    vec![&self.audit_submission.event],
    self.validate()
);
request!(
    MlsCommitSubmission,
    self,
    vec![&self.commit_event],
    self.validate()
);
request!(
    ActorPrivateEventSubmitRequestBody,
    self,
    vec![&self.event],
    self.validate()
);
request!(
    MessageSubmitRequestBody,
    self,
    vec![&self.submission.event],
    self.validate()
);
request!(
    EventsSubmitBatchRequestBody,
    self,
    self.events.iter().map(|slot| &slot.event).collect(),
    self.validate()
);
request!(
    AuthoritySubmitRequest,
    self,
    match self {
        Self::Event(value) => vec![&value.event],
        Self::MlsCommit(value) => vec![&value.commit_event],
    },
    self.validate()
);

request!(
    AccountDataReplaceRequestBody,
    self,
    vec![&self.set_event.event],
    canonical_shape(self)
);
request!(
    AccountDataDeleteRequestBody,
    self,
    vec![&self.set_event.event],
    canonical_shape(self)
);
request!(
    AccountUpdateProfileRequestBody,
    self,
    vec![&self.profile_event.event],
    self.validate()
);
request!(
    AccountDevicePairRequestBody,
    self,
    vec![&self.authorize_event.event],
    canonical_shape(self)
);
request!(
    AgentKeyPairRequestBody,
    self,
    vec![&self.authorize_event.event],
    canonical_shape(self)
);
request!(
    AgentPauseRequestBody,
    self,
    vec![&self.lifecycle_event.event],
    canonical_shape(self)
);
request!(
    AgentResumeRequestBody,
    self,
    vec![&self.lifecycle_event.event],
    canonical_shape(self)
);
request!(
    AgentDeactivateRequestBody,
    self,
    vec![&self.lifecycle_event.event],
    canonical_shape(self)
);
request!(
    ModerationReportRequestBody,
    self,
    vec![&self.report_event.event],
    canonical_shape(self)
);
request!(
    WatchAuditReadRequest,
    self,
    vec![&self.audit_submission.event],
    self.validate()
);
request!(
    CircleCreateRequestBody,
    self,
    vec![&self.create_event.event],
    canonical_shape(self)
);
request!(
    CircleMemberRequestBody,
    self,
    vec![&self.member_event.event],
    canonical_shape(self)
);
request!(
    CircleMemberDeleteRequestBody,
    self,
    vec![&self.member_event.event],
    canonical_shape(self)
);
request!(
    CircleScopeRotateRequestBody,
    self,
    self.events.iter().collect(),
    canonical_shape(self)
);
request!(
    AgentProvisionRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.provision_event.event],
    },
    canonical_shape(self)
);
request!(
    SidecarEnsureRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.create_event, &value.context_attach_event],
        Self::Attach(value) => vec![&value.context_attach_event],
    },
    self.validate_shape()
);
request!(
    ContactOperationRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.signed_event],
    },
    canonical_shape(self)
);
request!(
    ContactAcceptRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.signed_event],
    },
    canonical_shape(self)
);
request!(
    ContactTombstoneRequestBody,
    self,
    match self {
        Self::Prepare(_) => Vec::new(),
        Self::Commit(value) => vec![&value.signed_event],
    },
    canonical_shape(self)
);
request!(
    AccountRegisterRequestBody,
    self,
    self.identity_creation
        .as_ref()
        .map(|creation| creation.pcr_genesis_unit.events.iter().collect())
        .unwrap_or_default(),
    self.validate()
);

request!(
    arkret_models_integration::AppletManagedActorAuthorOutcome,
    self,
    vec![&self.create_event],
    canonical_shape(self)
);
request!(
    AppletInstallRequestBody,
    self,
    std::iter::once(&self.authoring_request_basis.registration_event)
        .chain(self.authoring_request_basis.capability_grant_events.iter())
        .collect(),
    canonical_shape(self)
);
request!(
    AppletRevokeRequestBody,
    self,
    self.capability_revoke_events
        .iter()
        .chain(&self.membership_state_events)
        .map(|slot| &slot.event)
        .collect(),
    canonical_shape(self)
);

impl sealed::Sealed for AppletTransactionRequestBody {}
impl PublicationRequest for AppletTransactionRequestBody {
    fn producer_events(&self) -> Vec<&Event> {
        match self {
            Self::Events(body) => body
                .events
                .iter()
                .chain(body.committed_events.iter().map(|slot| &slot.event))
                .collect(),
            // This branch requests authoring; it does not publish the embedded candidate.
            Self::Authoring(_) => Vec::new(),
        }
    }
    fn realm_commits(&self) -> Vec<&RealmCommit> {
        match self {
            Self::Events(body) => body
                .committed_events
                .iter()
                .map(|slot| &slot.commit)
                .collect(),
            Self::Authoring(_) => Vec::new(),
        }
    }
    fn validate_publication_shape(&self) -> arkret_wire::Result<()> {
        self.validate()
    }
}
request!(
    SelfAuthoritySubmitRequest,
    self,
    match self {
        Self::Event(value) => vec![&value.event],
        Self::MlsCommit(value) => vec![&value.commit_event],
        Self::OrdinaryRealmBootstrap(value) =>
            value.events.iter().map(|slot| &slot.event).collect(),
        Self::DirectConversationFounding(value) =>
            value.events.iter().map(|slot| &slot.event).collect(),
        Self::MembershipCompensation(value) => vec![&value.event_submission.event],
        Self::AuditPairedEvent(value) => value.events.iter().map(|slot| &slot.event).collect(),
    },
    self.validate()
);

impl sealed::Sealed for PeerAuthoritySubmitRequest {}

impl PublicationRequest for PeerAuthoritySubmitRequest {
    fn producer_events(&self) -> Vec<&Event> {
        match self {
            Self::AuthorityForwardEvent(value) => vec![&value.event_submission.event],
            Self::AuthorityForwardMls(value) => vec![&value.mls_submission.commit_event],
            Self::AuthorityForwardAtomic(value) => value
                .atomic_submission
                .events
                .iter()
                .map(|slot| &slot.event)
                .collect(),
            Self::CommittedReplication(value) => value
                .replications
                .iter()
                .map(|slot| &slot.event_submission.event)
                .collect(),
            Self::RegisteredAtomicUnit(value) => match &value.unit {
                PeerRegisteredAtomicUnit::DirectConversationFounding(value) => value
                    .committed_events
                    .iter()
                    .map(|slot| &slot.event_submission.event)
                    .collect(),
                PeerRegisteredAtomicUnit::MembershipCompensation(value) => {
                    vec![&value.committed_event.event_submission.event]
                }
                PeerRegisteredAtomicUnit::AuditPairedEvent(value) => value
                    .committed_events
                    .iter()
                    .map(|slot| &slot.event_submission.event)
                    .collect(),
            },
        }
    }

    fn realm_commits(&self) -> Vec<&RealmCommit> {
        match self {
            Self::AuthorityForwardEvent(_) => Vec::new(),
            Self::AuthorityForwardMls(_) => Vec::new(),
            Self::AuthorityForwardAtomic(_) => Vec::new(),
            Self::CommittedReplication(value) => value
                .replications
                .iter()
                .map(|slot| &slot.source_commit)
                .collect(),
            Self::RegisteredAtomicUnit(value) => match &value.unit {
                PeerRegisteredAtomicUnit::DirectConversationFounding(value) => value
                    .committed_events
                    .iter()
                    .map(|slot| &slot.source_commit)
                    .collect(),
                PeerRegisteredAtomicUnit::MembershipCompensation(value) => {
                    vec![&value.committed_event.source_commit]
                }
                PeerRegisteredAtomicUnit::AuditPairedEvent(value) => value
                    .committed_events
                    .iter()
                    .map(|slot| &slot.source_commit)
                    .collect(),
            },
        }
    }

    fn validate_publication_shape(&self) -> arkret_wire::Result<()> {
        self.validate()
    }
}

// A durable security transaction publishes these exact producer batches later.
request!(
    arkret_models_crypto::SecurityTransactionCreateRequest,
    self,
    match self {
        Self::Recovery(value) => value
            .recovery_intent
            .reanchor_unit
            .request
            .events
            .iter()
            .map(|slot| &slot.event)
            .collect(),
        Self::SecurityRotation(value) => value
            .prepared_plan
            .revoke_unit
            .request
            .events
            .iter()
            .chain(
                value
                    .prepared_plan
                    .backup_rotations
                    .iter()
                    .flat_map(|rotation| rotation.active_series_unit.request.events.iter())
            )
            .map(|slot| &slot.event)
            .collect(),
    },
    self.validate()
);
