//! Message-create payload and content-block validation.
//!
//! The `ContentBlock` wire family, `MessageCreatePayload`, morph-update
//! payload, disappearing-message expiry types, and the content-block
//! validators (`validate_content_block`, `ContentBlockValidationError`, …)
//! all live in `arkret-models-collaboration`
//! (`events_payloads::morph_message`); re-exported here for path stability.

pub use arkret_models_collaboration::events_payloads::morph_message::*;
