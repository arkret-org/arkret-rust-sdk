//! Cross-domain Arkret v1 wire primitives.
//!
//! This crate owns serialized state object shapes. Reducers, stores, snapshot
//! construction, transports, and framework adapters deliberately live in
//! higher-level crates.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod error;
mod extension_map;

pub mod base64url {
    pub use arkret_canonical::base64url::*;
}
pub mod canonical {
    pub use arkret_canonical::canonical::*;
}
pub mod serde_helpers {
    pub use arkret_canonical::serde_helpers::*;
}

pub mod applet_revoke_mode;
pub mod bottom;
pub mod cba;
pub mod cba_proof_bundle;
pub mod cell;
pub mod consent_scope;
pub mod constants;
pub mod control_proposal;
pub mod cursor;
pub mod error_codes;
pub mod event_envelope;
pub mod event_receipt;
pub mod event_submission;
pub mod events;
pub mod extension_manifest;
pub mod generated;
pub mod http_signature;
pub mod notary;
pub mod object_address;
pub mod offline_publication;
pub mod patch;
pub mod plaintext;
pub mod platform;
pub mod primitives;
pub mod problem_details;
pub mod query_auth;
pub mod receive_policy;
pub mod recovery_authority;
pub mod resource_selector;
pub mod seal;
pub mod security_transaction;
pub mod self_contact_paths;
pub mod service_kind;
pub mod signal;
pub mod signer;
pub mod string_profiles;
pub mod wire_strings;

pub use applet_revoke_mode::AppletRevokeMode;
pub use arkret_identifiers::*;
pub use bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use cba::{
    LatticeOp, LatticeOpType, ObservedRemoveMatch, Precondition, Predicate, PredicateOp,
    ProjectedCellWrite, ProjectedOp, ProjectionEffect, SealBasis,
};
pub use cba_proof_bundle::{AvailabilityReceipt, CbaProofBundle};
pub use cell::{
    CellId, CompositeSubjectComponent, NULL_SUBJECT, REALM_CREATE_CELL, REALM_METADATA_CELL,
    REALM_NOTARY_CELL, composite_subject, composite_subject_pipe, null_subject_cell,
    string_set_digest_component,
};
pub use consent_scope::*;
pub use constants::*;
pub use control_proposal::{
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalDeferReason,
    ControlProposalReceipt, ControlProposalReceiptKind, ControlProposalRejectReason,
    ProposalMemberReceipt, MAX_PROPOSAL_ABSOLUTE_HORIZON, MAX_PROPOSAL_DECISION_WINDOW,
    MAX_PROPOSAL_DEFERS, MAX_PROPOSAL_RECEIPT_MEMBERS,
};
pub use error::{Error, Result, WireError};
pub use error_codes::*;
pub use event_envelope::*;
pub use event_receipt::*;
pub use event_submission::{
    AuthorizationLeaseIssueOutcome, AuthorizationLeaseIssueRequest,
    ControlProposalReceiptIssueOutcome, ControlProposalReceiptIssueRequestBody,
    EventFederationSubmission, EventInitialSubmission, EventsSubmitBatchRequestBody,
    validate_anchor_unit_lease_bindings,
};
pub use events::*;
pub use extension_manifest::{
    ConcurrencyClass, ConfidentialityClass, ExtensionManifest, ManifestResourceLimits,
    ProtocolLayerKind, ReducerContractRef, RegistryContentRef,
};
pub use extension_map::XExtensionMap;
pub use generated::{
    AlgorithmSuiteDescriptor, CapabilityActionId, DIGEST_SUITES, EVENT_KIND_COUNT, EXPORTER_LABELS,
    EventKind, ExporterLabelDescriptor, ExporterLabelId, HPKE_SUITES, MLS_CIPHERSUITES,
    MLS_EXTENSIONS, MlsExtensionDescriptor, PROOF_CONTEXTS, ProofContextDescriptor, ProofContextId,
    RELATION_KIND_DESCRIPTORS, SERVICE_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS,
    SIGNATURE_ALGORITHMS, ServiceKindDescriptor, ServiceOperationDescriptor, ServiceOperationId,
};
pub use http_signature::HttpMessageSignature;
pub use notary::{ForensicAttribution, NotaryValue};
pub use object_address::*;
pub use offline_publication::{
    AUTHORITY_SET_POLICY_SCHEMA, AnchorUnitLeaseBasis, AnchorUnitLeaseBasisRef,
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizationLease, IngressReceipt, LeaseBasisRef, RECOVERY_ACCOUNT_AUTHORITY_SET_ID,
    RECOVERY_CROSS_SIGNING_AUTHORITY_SET_ID, RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID, RiskTier,
    distinct_issuer_count,
};
pub use patch::*;
pub use plaintext::PlaintextDataClassKind;
pub use platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use primitives::{proof_kind, *};
pub use problem_details::*;
pub use query_auth::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use receive_policy::*;
pub use recovery_authority::{
    AuthorizeEventPublicationIntent, AuthorizeRecoveryDeviceOutcome,
    AuthorizeRecoveryDeviceRequest, CanonicalEncoding, CanonicalPublicMaterial,
    EnrollmentAuthorityIdentityModel, IssueAuthorityTicketStep,
    MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS, PromoteRecoverySessionGrantOutcome,
    PromoteRecoverySessionGrantRequest, RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS,
    RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS, RecoveryAuthorityHolderProof,
    RecoveryAuthorityTicket, RecoveryAuthorityTicketAuthData, RecoveryAuthorityTicketIssueRequest,
    RecoveryAuthorizationPreimage, RecoveryCompletionAttestation,
    RecoveryCompletionAttestationAuthData, RecoveryModelGenerationRef,
    ReplacementDevicePossessionProof, ServiceSignatureAlgorithm,
};
pub use resource_selector::{ResourceMatchScope, ResourceSelectorKind, WireResourceSelector};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, PayloadSignature, SEAL_SIGNATURE_ALGS, Seal, SealKind,
    ThresholdSigKind, ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use security_transaction::{
    AcceptedStep, BackupSeriesEraseIntent, BackupSeriesEraseObject, BackupSeriesEraseRequestBody,
    BackupSeriesEraseTarget, CLIENT_STEP_ATTESTATION_SIGNED_FIELDS, ClientStepAttestation,
    ClientStepAttestationAuthData, CrossSigningRecoveryBinding, CrossSigningRecoveryPlan,
    EnrollmentAuthorityRecoveryBinding, EnrollmentAuthorityRecoveryPlan, PreparedDidPublication,
    PreparedEventUnit, RecoveryBinding, RecoveryIdentityModel, RecoveryPreparedPlan,
    RecoveryTransactionCreateRequest, SecurityRotationBackupBinding, SecurityRotationBackupKind,
    SecurityRotationBackupPlan, SecurityRotationBinding, SecurityRotationPlan,
    SecurityRotationTransactionCreateRequest, SecurityTransaction, SecurityTransactionBinding,
    SecurityTransactionContinueRequest, SecurityTransactionCreateRequest, SecurityTransactionKind,
    SecurityTransactionPreparedPlan, SecurityTransactionResultKind, SecurityTransactionState,
    SecurityTransactionStep, SecurityTransactionTerminalResult,
};
pub use self_contact_paths::*;
pub use service_kind::{EvaluationClass, ServiceKind};
pub use signal::{
    MAX_SIGNAL_CIPHERTEXT_CHARS, MAX_SIGNAL_ENVELOPE_BYTES, MAX_SIGNAL_PLAINTEXT_BYTES,
    MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES, MAX_SIGNAL_RELAY_ITEMS, MAX_SIGNAL_STREAM_REASON_CHARS,
    MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS, MAX_SIGNAL_TTL, SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME,
    SIGNAL_EXPORTER_LABEL, SignalAeadBinding, SignalClass, SignalEncryptedPayload, SignalEnvelope,
    SignalKeyRef, SignalProof, SignalRelayOutcome, SignalRelayRequest, SignalStreamFrame,
};
pub use signer::{PartialSignature, PayloadSigner, ThresholdAggregator};
pub use string_profiles::*;
pub use wire_strings::*;
