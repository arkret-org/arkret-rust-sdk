//! Applet package, registration, namespace, endpoint, and webhook wire contracts.
//!
//! The package / registration-epoch aggregates that embed `arkret-core`
//! entangled types (`AppletPackage`, `AppletRegistrationEpochTranscript`,
//! `AppletRegistrationEpochEvidence`) and the Ghost Actor profile /
//! accountability-grant builders stay in `arkret-core`.

mod ghost;
mod namespace_match;
mod registration;
mod service;

pub use ghost::*;
pub use namespace_match::*;
pub use registration::*;
pub use service::*;
