//! Authority-committed event synchronization.
//!
//! Each Realm, Circle, and Sidecar has its own linear commit stream. Producer
//! Events do not form a predecessor graph; ordering and finality are carried
//! exclusively by the governance Station's [`RealmCommit`] records.

pub use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityRejectionStatus,
    AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead, CommitStreamRef,
    CommittedEventFullView, CommittedEventRef, CommittedEventView, CommittedEventWithheldView,
    EventAdmissionSubmission, EventDisclosure, EventDisclosureStatus, RealmAuthorityBundle,
    RealmAuthorityCurrentAssertion, RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit,
    RealmCommitAuthorityRef, RealmStateSnapshot, RetentionAndHistoryFloor, StreamHistoryFloor,
    StreamScanOutcome, StreamScanRequest,
};

pub use crate::authority_commit::AuthorityHandoffRequest;
