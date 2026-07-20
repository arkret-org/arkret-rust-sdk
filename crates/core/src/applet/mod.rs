//! Applet package, registration, namespace, endpoint, and webhook wire contracts.
//!
//! The pure wire shapes (namespace claims, webhook auth, endpoint policy,
//! `WireAppletRegistration`, ghost provision bodies) and the package /
//! registration-epoch aggregates (`AppletPackage`,
//! `AppletRegistrationEpochTranscript`, `AppletRegistrationEpochEvidence`)
//! migrated to `arkret-models-integration` (re-exported below). The
//! aggregates kept here are entangled with collaboration-owned types: the
//! Ghost Actor profile / accountability-grant builders (build
//! `ObjectCreatePayload` events and governance-owned grants) and the applet
//! service transaction envelope (embeds `EphemeralEnvelope`).

mod ghost;
mod service;

pub use arkret_models_integration::applet::*;
pub use ghost::*;
pub use service::*;
