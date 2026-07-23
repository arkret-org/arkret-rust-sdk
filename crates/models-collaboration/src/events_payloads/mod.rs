//! Event payload wire shapes for collaboration objects: message /
//! morph content payloads, strand container operations, generic object
//! creation envelopes, and mention AST nodes. Builder functions that
//! need schema validation or event-draft assembly stay in the `arkret` umbrella.

pub mod account_misc;
pub mod agent;
pub mod audit;
pub mod call;
pub mod capability_circle_consent_contact;
pub mod content_block_poll;
pub mod device_identity;
pub mod ephemeral;
pub mod event_wire;
pub mod list_message_mimi_mls;
pub mod mention;
pub mod moderation;
pub mod moderation_morph_misc;
pub mod morph_message;
pub mod object_create;
pub mod preview_realm_reaction;
pub mod redaction;
pub mod strand_history_join;
pub mod strand_ops;
