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
pub mod authority_commit;
pub mod consent_scope;
pub mod constants;
pub mod cursor;
pub mod device_revocation;
pub mod error_codes;
pub mod event_envelope;
pub mod event_submission;
pub mod events;
pub mod extension_manifest;
pub mod forbidden_wire;
pub mod generated;
pub mod ingress_budget;
pub mod invite_token;
pub mod mls_transition;
pub mod object_address;
pub mod object_ref;
pub mod operation_types;
pub mod pairwise_endpoint_possession;
pub mod patch;
pub mod payload_signer;
pub mod peer_operation_paths;
pub mod plaintext;
pub mod platform;
pub mod primitives;
pub mod problem_details;
pub mod query_auth;
pub mod realm_authority_signer;
pub mod receive_policy;
pub mod recovery_authority;
pub mod request_digest;
pub mod resource_selector;
pub mod self_contact_paths;
pub mod service_kind;
pub mod signal;
pub mod signer_evidence;
pub mod string_profiles;
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod websocket_binding;
pub mod webvh_parameters;
pub mod wire_presence;
pub mod wire_strings;

pub use accepted_device_possession::*;
pub use applet_revoke_mode::AppletRevokeMode;
pub use arkret_identifiers::*;
pub use authored_event::AuthoredEvent;
pub use authority_commit::*;
pub use consent_scope::*;
pub use constants::*;
pub use device_revocation::*;
pub use error::{Result, WireError};
pub use error_codes::*;
pub use event_envelope::*;
pub use event_submission::*;
pub use events::*;
pub use extension_manifest::{
    ConfidentialityClass, ExtensionManifest, ExtensionManifestCatalog,
    ExtensionManifestProofVerifier, LoadedExtensionManifests, ManifestDependencyLayer,
    ManifestKernelLimits, ManifestRegistryContent, ManifestRegistryContentKind,
    ManifestResourceLimits, ProtocolLayerKind, ReducerContractRef, RegistryContentRef,
    load_extension_manifests,
};
pub use extension_map::XExtensionMap;
pub use generated::*;
pub use genesis_salt::GenesisSalt;
pub use ingress_budget::WireBodyClass;
pub use invite_token::{INVITE_TOKEN_MAX_CHARS, validate_invite_token};
pub use mls_transition::mls_genesis_transition_digest;
pub use object_address::*;
pub use object_ref::is_object_ref;
pub use operation_types::*;
pub use pairwise_endpoint_possession::*;
pub use patch::*;
pub use payload_signer::{PayloadSignature, PayloadSigner};
pub use peer_operation_paths::*;
pub use plaintext::PlaintextDataClassKind;
pub use platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use primitives::{proof_kind, *};
pub use problem_details::*;
pub use query_auth::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use realm_authority_signer::{
    RealmAuthorityJoseAlgorithm, RealmAuthoritySignerDescriptor, RealmAuthoritySignerKeyKind,
    RealmAuthoritySignerValue,
};
pub use receive_policy::*;
pub use recovery_authority::{
    CanonicalEncoding, CanonicalPublicMaterial, IssueRecoveryCompletionGrantOutcome,
    IssueRecoveryCompletionGrantRequest, RecoveryCompletionAttestation,
    RecoveryCompletionAttestationAuthData, UnsignedRecoveryCompletionAttestation,
    UnsignedRecoveryCompletionAttestationBody,
};
pub use request_digest::framed_request_digest;
pub use resource_selector::{
    ObjectRef, ResourceMatchScope, ResourceSelectorKind, WireResourceSelector,
};
pub use self_contact_paths::*;
pub use service_kind::{EvaluationClass, ServiceKind};
pub use signal::{
    MAX_SIGNAL_CIPHERTEXT_CHARS, MAX_SIGNAL_ENVELOPE_BYTES, MAX_SIGNAL_PLAINTEXT_BYTES,
    MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES, MAX_SIGNAL_RELAY_ITEMS, MAX_SIGNAL_STREAM_REASON_CHARS,
    MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS, MAX_SIGNAL_TTL, SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME,
    SIGNAL_EXPORTER_LABEL, SignalAeadBinding, SignalClass, SignalDeliveryAuthority,
    SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof, SignalRelayOutcome,
    SignalRelayRequest, SignalSenderEndpoint, SignalStreamFrame, StationSigningKey,
};
pub use signer_evidence::SignerEvidenceRef;
pub use string_profiles::*;
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

// Retain the pre-existing SDK identity-link surface until its own registry
// drift is adjudicated; the current committed-event migration does not delete it.
impl SchemaId {
    pub const IDENTITY_LINK_V1: &'static str = "ak.schema.identity_link.v1";
}

// Keep this pre-existing policy-facing string while its registry removal is
// handled independently from the committed-event protocol migration.
impl ReasonCode {
    pub const MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID: &'static str =
        "minimal_metadata_author_credential_invalid";
}
