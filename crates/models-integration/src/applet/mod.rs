//! Applet package, registration, namespace, endpoint, and webhook wire contracts.
//!
//! Includes the package / registration-epoch aggregates (`AppletPackage`,
//! `AppletRegistrationEpochTranscript`, `AppletRegistrationEpochEvidence`),
//! which bind the DID document (`arkret-models-identity`) and the widget
//! declaration (`crate::Widget`). The Ghost Actor profile /
//! accountability-grant builders stay in `arkret-core` (they build
//! collaboration-owned events and grants).

mod ghost;
mod namespace_match;
mod registration;
mod service;

pub use ghost::*;
pub use namespace_match::*;
pub use registration::*;
pub use service::*;
