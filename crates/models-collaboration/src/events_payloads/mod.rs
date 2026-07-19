//! Event payload wire shapes for collaboration objects: message /
//! morph content payloads, strand container operations, generic object
//! creation envelopes, and mention AST nodes. Builder functions that
//! need schema validation or event-draft assembly stay in `arkret-core`.

pub mod mention;
pub mod morph_message;
pub mod object_create;
pub mod strand_ops;
