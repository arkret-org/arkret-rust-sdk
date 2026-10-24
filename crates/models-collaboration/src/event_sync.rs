//! Authority-committed event synchronization.
//!
//! Each Realm, Circle, and Sidecar has its own linear commit stream. Producer
//! Events do not form a predecessor graph; ordering and finality are carried
//! exclusively by the governance Station's [`RealmCommit`] records.

pub use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitRequestBody,
    AuthoritySubmitResponseBody, CommitStreamHead, CommitStreamRef, CommittedEventFullView,
    CommittedEventRef, CommittedEventView, CommittedEventWithheldView, EventAdmissionSubmission,
    EventDisclosure, EventDisclosureStatus, RealmAuthorityBundle, RealmAuthorityBundleRequestBody,
    RealmAuthorityCurrentAssertion, RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit,
    RealmCommitAuthorityRef, RealmStateSnapshot, RetentionAndHistoryFloor, StreamHistoryFloor,
    StreamScanRequestBody, StreamScanResponseBody,
};

pub use crate::authority_commit::AuthorityRealmAuthorityHandoffRequestBody;
