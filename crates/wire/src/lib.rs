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
pub mod cell;
pub mod consent_scope;
pub mod constants;
pub mod cursor;
pub mod error_codes;
pub mod event_envelope;
pub mod event_receipt;
pub mod events;
pub mod generated;
pub mod http_signature;
pub mod move_event;
pub mod notary;
pub mod object_address;
pub mod patch;
pub mod plaintext;
pub mod primitives;
pub mod problem_details;
pub mod query_auth;
pub mod receive_policy;
pub mod resource_selector;
pub mod seal;
pub mod self_contact_paths;
pub mod service_type;
pub mod signer;
pub mod wire_strings;

pub use applet_revoke_mode::AppletRevokeMode;
pub use arkret_identifiers::*;
pub use bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use cell::{CellId, composite_subject, composite_subject_pipe};
pub use consent_scope::*;
pub use constants::*;
pub use error::{Error, Result, WireError};
pub use error_codes::*;
pub use event_envelope::*;
pub use event_receipt::*;
pub use events::*;
pub use extension_map::XExtensionMap;
pub use generated::{
    AlgorithmSuiteDescriptor, CapabilityActionId, DIGEST_SUITES, EVENT_KIND_COUNT, EXPORTER_LABELS,
    EventKind, ExporterLabelDescriptor, ExporterLabelId, HPKE_SUITES, MLS_CIPHERSUITES,
    MLS_EXTENSIONS, MlsExtensionDescriptor, PROOF_CONTEXTS, ProofContextDescriptor, ProofContextId,
    RELATION_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS, SERVICE_TYPE_DESCRIPTORS,
    SIGNATURE_ALGORITHMS, ServiceOperationDescriptor, ServiceOperationId, ServiceTypeDescriptor,
};
pub use http_signature::HttpMessageSignature;
pub use move_event::{
    Effect, LatticeOp, LatticeOpType, MOVE_SIGNATURE_ALGS, Move, MoveSignature, Precondition,
    Predicate, PredicateOp, SealBasis, SemanticRef,
};
pub use notary::{ForensicAttribution, NotaryValue};
pub use object_address::*;
pub use patch::*;
pub use plaintext::PlaintextDataClassKind;
pub use primitives::{proof_kind, *};
pub use problem_details::*;
pub use query_auth::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use receive_policy::*;
pub use resource_selector::{ResourceMatchScope, ResourceSelectorKind, WireResourceSelector};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, SEAL_SIGNATURE_ALGS, Seal, SealKind, ThresholdSigKind,
    ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use self_contact_paths::*;
pub use service_type::{EvaluationClass, ServiceType};
pub use signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use wire_strings::*;
