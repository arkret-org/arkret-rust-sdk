//! Applet package, registration, namespace, endpoint, and webhook wire contracts.
//!
//! Includes the package / registration-epoch aggregates (`AppletPackage`,
//! `AppletRegistrationEpochTranscript`, `AppletRegistrationEpochEvidence`),
//! which bind the DID document (`arkret-models-identity`) and the widget
//! declaration (`crate::Widget`). Event materialization belongs to
//! `arkret-event-draft`; this crate owns only the wire contracts and their
//! type-local invariants.

mod ghost;
mod namespace_match;
mod registration;

pub use ghost::*;
pub use namespace_match::*;
pub use registration::*;
