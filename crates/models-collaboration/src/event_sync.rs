//! Authority-committed event synchronization.
//!
//! Each Realm, Circle, and Sidecar has its own linear commit stream. Producer
//! Events do not form a predecessor graph; ordering and finality are carried
//! exclusively by the governance Station's [`RealmCommit`] records.

pub use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest,
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead,
    CommitStreamRef, CommittedEventRef, CommittedEventResolveOutcome, CommittedEventResolveRequest,
    EventCommitSubmission, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit, RealmCommitAuthorityRef,
    RealmStateSnapshot, RetentionAndHistoryFloor, StreamHistoryFloor, StreamRow,
    StreamScanOutcome, StreamScanRequest,
};
