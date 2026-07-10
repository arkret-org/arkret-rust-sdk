//! Applet package, registration, namespace, endpoint, and webhook wire contracts.

mod ghost;
mod namespace_match;
mod registration;
mod service;

pub use ghost::*;
pub use namespace_match::*;
pub use registration::*;
pub use service::*;
