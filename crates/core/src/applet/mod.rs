//! Applet package, registration, namespace, endpoint, and webhook wire contracts.
//!
//! The pure wire shapes (namespace claims, webhook auth, endpoint policy,
//! `WireAppletRegistration`, ghost provision bodies) migrated to
//! `arkret-models-integration` (re-exported below). The aggregates kept
//! here are entangled with core-only or collaboration-owned types:
//! `AppletPackage` / `AppletRegistrationEpochTranscript` (embed `Widget`),
//! `AppletRegistrationEpochEvidence` (built from the core `DidDocument`),
//! the Ghost Actor profile / accountability-grant builders (build
//! `ObjectCreatePayload` events and governance-owned grants), and the
//! applet service transaction envelope (embeds `EphemeralEnvelope`).

mod ghost;
mod registration;
mod service;

pub use arkret_models_integration::applet::*;
pub use ghost::*;
pub use registration::*;
pub use service::*;
