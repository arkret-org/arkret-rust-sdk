//! Compatibility layer for rich content helpers.
//!
//! The source of truth now lives in `contrix-core::events`; this module keeps the
//! historical `contrix::content::*` paths working for higher-level SDK users.

pub use contrix_core::events::{
    LinkPreview, MarkdownDocument, Mention, MentionTarget, Reaction, ReactionManager,
    ReactionSummary, RichTextBlock, extract_link_previews, parse_mentions,
};
