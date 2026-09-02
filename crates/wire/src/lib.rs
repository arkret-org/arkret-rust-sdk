//! Cross-domain Arkret v1 wire primitives.
//!
//! This crate owns serialized state object shapes. Reducers, stores, snapshot
//! construction, transports, and framework adapters deliberately live in
//! higher-level crates.

// Registry generators intentionally spell the public constant ABI as
// `&'static str`; keep that stable while allowing strict Clippy on the crate.
#![allow(clippy::redundant_static_lifetimes)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "diesel")]
mod diesel_support;
mod error;
mod extension_map;
mod genesis_salt;

pub mod base64url {
    pub use arkret_canonical::base64url::*;
}
pub mod canonical {
    pub use arkret_canonical::canonical::*;
}
pub mod serde_helpers {
    pub use arkret_canonical::serde_helpers::*;
}

pub mod accepted_device_possession;
pub mod applet_revoke_mode;
pub mod authored_event;
pub mod authorization_lease_issuance_fixture;
pub mod bottom;
pub mod cba;
pub mod cba_proof_bundle;
pub mod cell;
pub mod consent_scope;
pub mod constants;
pub mod control_proposal;
pub mod cursor;
pub mod device_revocation;
pub mod error_codes;
pub mod event_envelope;
pub mod event_receipt;
pub mod event_submission;
pub mod events;
pub mod extension_manifest;
pub mod generated;
pub mod history_secret;
pub mod history_store;
pub mod ingress_budget;
pub mod mls_transition;
pub mod notary;
pub mod object_address;
pub mod object_ref;
pub mod offline_publication;
pub mod operation_types;
pub mod organization_recovery;
pub mod patch;
pub mod peer_operation_paths;
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
pub mod signer_evidence;
pub mod string_profiles;
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tsp_vid;
pub mod websocket_binding;
pub mod webvh_parameters;
pub mod wire_presence;
pub mod wire_strings;

pub use accepted_device_possession::*;
pub use applet_revoke_mode::AppletRevokeMode;
pub use arkret_identifiers::*;
pub use authored_event::AuthoredEvent;
pub use authorization_lease_issuance_fixture::{
    AuthorizationLeaseIssuanceProjection, run_authorization_lease_issuance_fixture,
};
pub use bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use cba::{
    DeviceReanchorPreFenceSealFrontier, LatticeOp, LatticeOpType, ObservedRemoveMatch,
    Precondition, Predicate, PredicateOp, ProjectedCellWrite, ProjectedOp, ProjectionEffect,
    SealBasis,
};
pub use cba_proof_bundle::{AvailabilityReceipt, CbaProofBundle};
pub use cell::{
    CellId, CompositeSubjectComponent, NULL_SUBJECT, REALM_AUTHORITY_ROOT_CELL, REALM_CREATE_CELL,
    REALM_GENESIS_CELL, REALM_NOTARY_CELL, REALM_PROFILE_CELL, REALM_REDUCER_PROFILE_CELL,
    composite_subject, composite_subject_pipe, null_subject_cell, string_set_digest_component,
    subject_cell, uri_cell_subject,
};
pub use consent_scope::*;
pub use constants::*;
pub use control_proposal::{
    ControlProposalAck, ControlProposalAckIssueOutcome, ControlProposalAckIssueRequest,
    ControlProposalAckKind, ControlProposalAuthorityAck, ControlProposalAuthorityKind,
    ControlProposalDecision, ControlProposalDecisionFaultReason, ControlProposalDecisionKind,
    ControlProposalDecisionPolicy, ControlProposalDecisionReadOutcome,
    ControlProposalDecisionReadRequestBody, ControlProposalDecisionSubmitOutcome,
    ControlProposalDecisionSubmitRequestBody, ControlProposalDecisionSubmitStatus,
    ControlProposalDeferReason, ControlProposalRejectReason, ControlProposalState,
    MAX_PROPOSAL_ABSOLUTE_HORIZON, MAX_PROPOSAL_AUTHORITY_ACKS, MAX_PROPOSAL_AUTHORITY_PROOFS,
    MAX_PROPOSAL_DECISION_WINDOW, MAX_PROPOSAL_DEFERS, MAX_PROPOSAL_INTAKE_SLA,
};
pub use device_revocation::*;
pub use error::{Result, WireError};
pub use error_codes::*;
pub use event_envelope::*;
pub use event_receipt::*;
pub use event_submission::{
    AcklessSelfPrincipalAdmissionEvidence, AuthorizationLeaseIssueIntent,
    AuthorizationLeaseIssueOutcome, AuthorizationLeaseIssueRequestBody, EventFederationSubmission,
    EventInitialSubmission, EventPublicationLane, EventsSubmitBatchRequestBody, PcrGenesisUnit,
    classify_event_submit_context, classify_federated_event_submit_context,
    validate_anchor_unit_lease_bindings,
};
pub use events::*;
pub use extension_manifest::{
    ConcurrencyClass, ConfidentialityClass, ExtensionManifest, ExtensionManifestCatalog,
    ExtensionManifestProofVerifier, LoadedExtensionManifests, ManifestDependencyLayer,
    ManifestKernelLimits, ManifestRegistryContent, ManifestRegistryContentKind,
    ManifestResourceLimits, ProtocolLayerKind, ReducerContractRef, RegistryContentRef,
    load_extension_manifests,
};
pub use extension_map::XExtensionMap;
pub use generated::{
    AccountDataKey, ActorPrivateUpdateKind, AeadProfileId, AlgorithmSuiteDescriptor,
    AuthoritySetId, AuthoritySetPolicyKind, AuthoritySetSourceKind, AuthoritySourceId, BindingKind,
    CapabilityActionId, CellFamilyId, DIGEST_SUITES, DidFreshnessProfileId, DidFreshnessRiskTier,
    DidMethodEvidenceKind, DomainSeparationId, EVENT_KIND_COUNT, EVENT_KIND_DESCRIPTORS, EVENT_KIND_REGISTRY_SHA256,
    EXPORTER_LABELS, EventCellRule, EventCellRuleField, EventCellRuleKey, EventCellRuleOperator,
    EventKind, ExporterLabelDescriptor, ExporterLabelId, FEATURES, FeatureDescriptor,
    FeatureStatus, HISTORY_STORE_LIMITS, HPKE_SUITES, HistoryStoreLimits, HpkeSuiteId,
    MLS_CIPHERSUITES, MLS_EXTENSIONS, MlsExtensionDescriptor, OPERATION_BUNDLES,
    OperationBindingPair, OperationBundleDescriptor, PROOF_CONTEXTS, ProfileEnforcementPhase,
    ProfileId, ProfileOperationDirection, ProfileOperationRequirement, ProfileRole,
    ProofContextDescriptor, ProofContextId, REDUCER_PROFILE_UPGRADE_EDGES,
    RELATION_KIND_DESCRIPTORS, ReducerProfileId, SERVICE_KIND_DESCRIPTORS,
    SERVICE_OPERATION_DESCRIPTORS, SIGNATURE_ALGORITHMS, SchemaId, ServiceContractId,
    ServiceKindDescriptor, ServiceOperationDescriptor, ServiceOperationId, TrackName,
    can_upgrade_reducer_profile, event_kind_str, event_spec, feature_descriptor,
    is_reducer_profile_id, operation_binding_is_registered, operation_bundle_descriptor,
    operation_bundles_for_service_kind, requirements_for, role_describe_bundle_descriptor,
};
pub use genesis_salt::GenesisSalt;
pub use history_secret::{EpochRange, HistorySecretRange, validate_canonical_ranges};
pub use history_store::{
    EventCandidateBinding, EventCandidateBindingKey, EventCandidateBindingOutcome,
    HistoryCandidateMaterialKey, HistoryCandidateMaterialRecord, LocalAuthoritativeHistorySecret,
    MAX_HISTORY_SENDER_DOMAIN_CHARS, MAX_LOCAL_MLS_STATE_REF_CHARS,
};
pub use ingress_budget::WireBodyClass;
pub use mls_transition::mls_genesis_transition_digest;
pub use notary::{
    ForensicAttribution, NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor, NotaryValue,
};
pub use object_address::*;
pub use object_ref::is_object_ref;
pub use offline_publication::{
    AnchorUnitLeaseBasis, AnchorUnitLeaseBasisRef, AuthoritySetAuthorizationRule,
    AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicySource,
    AuthoritySetRef, AuthorizationLease, IngressReceipt, LeaseBasisRef,
    RECOVERY_ACCOUNT_AUTHORITY_SET_ID, RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID, RiskTier,
    distinct_issuer_count,
};
pub use operation_types::*;
pub use organization_recovery::{
    OrganizationRecoveryArchive, OrganizationRecoveryArchiveSealContext,
    OrganizationRecoveryHpkeSuite,
};
pub use patch::*;
pub use peer_operation_paths::*;
pub use plaintext::PlaintextDataClassKind;
pub use platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use primitives::{proof_kind, *};
pub use problem_details::*;
pub use query_auth::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use receive_policy::*;
pub use recovery_authority::{
    CanonicalEncoding, CanonicalPublicMaterial, IssueRecoveryCompletionGrantOutcome,
    IssueRecoveryCompletionGrantRequest, RecoveryCompletionAttestation,
    RecoveryCompletionAttestationAuthData, UnsignedRecoveryCompletionAttestation,
    UnsignedRecoveryCompletionAttestationBody,
};
pub use resource_selector::{
    ObjectRef, ResourceMatchScope, ResourceSelectorKind, WireResourceSelector,
};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, PayloadSignature, Seal, SealKind, SealSignature,
    compute_seal_id, seal_canonical_bytes,
};
pub use security_transaction::{
    AcceptedStep, BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    ClientStepAttestation, ClientStepAttestationAuthData, PCR_POLICY_RECOVERY_STEP_ORDER,
    PcrPolicyRecoveryBinding, PcrPolicyRecoveryPlan, PreparedEventUnit, RecoveryIdentityModel,
    RecoveryPreparedPlan, RecoveryTransactionCreateRequest, SECURITY_ROTATION_STEP_ORDER,
    SecurityRotationPlan, SecurityRotationTransactionCreateRequest, SecurityTransaction,
    SecurityTransactionAcceptor, SecurityTransactionCreateRequest, SecurityTransactionKind,
    SecurityTransactionPreparedPlan, SecurityTransactionResultKind, SecurityTransactionStep,
    SecurityTransactionTerminalResult, UnsignedClientStepAttestation,
    security_rotation_erase_confirmation_digest, security_rotation_local_commit_digest,
};
pub use self_contact_paths::*;
pub use service_kind::{EvaluationClass, ServiceKind};
pub use signal::{
    MAX_SIGNAL_CIPHERTEXT_CHARS, MAX_SIGNAL_ENVELOPE_BYTES, MAX_SIGNAL_PLAINTEXT_BYTES,
    MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES, MAX_SIGNAL_RELAY_ITEMS, MAX_SIGNAL_STREAM_REASON_CHARS,
    MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS, MAX_SIGNAL_TTL, SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME,
    SIGNAL_EXPORTER_LABEL, SignalAeadBinding, SignalClass, SignalEncryptedPayload, SignalEnvelope,
    SignalKeyRef, SignalProof, SignalRelayOutcome, SignalRelayRequest, SignalSenderEndpoint,
    SignalStreamFrame,
};
pub use signer::{PartialSignature, PayloadSigner, ThresholdAggregator};
pub use signer_evidence::SignerEvidenceRef;
pub use string_profiles::*;
pub use tsp_vid::*;
pub use websocket_binding::{
    WEBSOCKET_AUTH_METHOD_TOKEN, WEBSOCKET_AUTH_REPLAY_CONTEXT, WEBSOCKET_AUTHENTICATION,
    WEBSOCKET_AUTHENTICATION_DEADLINE_MS, WEBSOCKET_HARD_MAX_FRAME_BYTES,
    WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS, WEBSOCKET_SUBPROTOCOL, WebSocketChallengeRecord,
    WebSocketCloseCode, WebSocketDpopClaims, WebSocketDpopProof, WebSocketDpopProtectedHeader,
    WebSocketDpopPublicJwk, WebSocketOperationId, WebSocketReplayLedgerKey,
    WebSocketTransportError, canonical_http_origin, validate_websocket_base_url,
};
pub use webvh_parameters::{
    did_webvh_v1_effective_portable, validate_did_webvh_v1_parameter_names,
};
pub use wire_presence::WirePresence;
pub use wire_strings::*;
