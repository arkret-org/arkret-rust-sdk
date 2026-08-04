//! `ak.content.long_text` normative validators.
//!
//! Covers the rules that JSON Schema cannot express: UTF-8 byte bounds,
//! normalization, the format / media-type binding, hash-only Blob refs and the
//! mandatory streaming AEAD scheme for the E2EE branch.
//! See `zh/models/content-types.md` sections 4.1.1 - 4.1.4.

use arkret_models_collaboration::events_payloads::message::{
    CONTENT_KIND_LONG_TEXT, CONTENT_TEXT_INLINE_MAX_BYTES, ContentBlock, ContentBlockKind,
    LONG_TEXT_FALLBACK_MAX_BYTES, LongTextBodyKind, LongTextFormat, long_text_line_count,
    long_text_prefix, normalize_long_text,
};
use serde_json::json;

fn plaintext_block() -> ContentBlock {
    ContentBlock::new(CONTENT_KIND_LONG_TEXT, "first four KiB of the body")
        .with_field("format", json!("markdown"))
        .with_field("body_kind", json!("prefix"))
        .with_field(
            "blob_ref",
            json!(format!("ak:blob:sha256:{}", "a".repeat(64))),
        )
        .with_field("size_bytes", json!(700_000u64))
        .with_field("media_type", json!("text/markdown"))
}

fn e2ee_block() -> ContentBlock {
    ContentBlock::new(CONTENT_KIND_LONG_TEXT, "authenticated summary")
        .with_field("format", json!("plain"))
        .with_field("body_kind", json!("summary"))
        .with_field(
            "attachment",
            json!({
                "blob_ref": format!("ak:blob:sha256:{}", "b".repeat(64)),
                "encrypted": true,
                "scheme": "ak.blob.stream_aead.v1",
                "encryption_algorithm": "mls_exporter_aead_xchacha20poly1305_stream",
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "ak:event:01900000-0000-7000-8000-000000000000"
                },
                "epoch": 42,
                "ciphertext_digest": format!("sha256:{}", "b".repeat(64)),
                "size_bytes": 700_000u64,
                "media_type": "text/plain",
                "nonce_prefix": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
                "segment_bytes": 262_144u64,
                "segment_count": 3u64
            }),
        )
}

#[test]
fn long_text_kind_round_trips() {
    assert_eq!(
        ContentBlockKind::parse(CONTENT_KIND_LONG_TEXT),
        Some(ContentBlockKind::LongText)
    );
    assert_eq!(ContentBlockKind::LongText.as_str(), CONTENT_KIND_LONG_TEXT);
    assert!(!ContentBlockKind::LongText.is_media());
}

#[test]
fn both_wire_branches_validate() {
    plaintext_block().validate_long_text().unwrap();
    e2ee_block().validate_long_text().unwrap();
}

#[test]
fn exactly_one_branch_is_allowed() {
    let both = plaintext_block().with_field(
        "attachment",
        e2ee_block().extra.get("attachment").unwrap().clone(),
    );
    assert!(both.validate_long_text().is_err());

    let mut neither = plaintext_block();
    neither.extra.remove("blob_ref");
    assert!(neither.validate_long_text().is_err());
}

#[test]
fn media_type_is_bound_to_format() {
    let mismatched = plaintext_block().with_field("media_type", json!("text/plain"));
    assert!(mismatched.validate_long_text().is_err());

    let parameterized =
        plaintext_block().with_field("media_type", json!("text/markdown; charset=utf-8"));
    assert!(parameterized.validate_long_text().is_err());

    assert_eq!(LongTextFormat::Plain.media_type(), "text/plain");
    assert_eq!(LongTextFormat::Markdown.media_type(), "text/markdown");
}

#[test]
fn plaintext_branch_requires_a_hash_addressed_blob_ref() {
    let uuid_ref = plaintext_block().with_field(
        "blob_ref",
        json!("ak:blob:01900000-0000-7000-8000-000000000000"),
    );
    assert!(uuid_ref.validate_long_text().is_err());

    let short_hex = plaintext_block().with_field("blob_ref", json!("ak:blob:sha256:abcd"));
    assert!(short_hex.validate_long_text().is_err());

    let upper_hex = plaintext_block().with_field(
        "blob_ref",
        json!(format!("ak:blob:sha256:{}", "A".repeat(64))),
    );
    assert!(upper_hex.validate_long_text().is_err());
}

#[test]
fn e2ee_branch_requires_the_streaming_aead_scheme() {
    let mut attachment = e2ee_block().extra.get("attachment").unwrap().clone();
    attachment["scheme"] = json!("ak.blob.whole_file_aead.v1");
    attachment["encryption_algorithm"] = json!("mls_exporter_aead_xchacha20poly1305");
    let whole_file = e2ee_block().with_field("attachment", attachment);
    assert!(whole_file.validate_long_text().is_err());
}

#[test]
fn e2ee_ciphertext_digest_must_equal_the_blob_ref_digest() {
    let mut attachment = e2ee_block().extra.get("attachment").unwrap().clone();
    attachment["ciphertext_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
    let mismatched = e2ee_block().with_field("attachment", attachment);
    assert!(mismatched.validate_long_text().is_err());
}

#[test]
fn e2ee_segment_count_is_derived_from_the_plaintext_size() {
    let mut attachment = e2ee_block().extra.get("attachment").unwrap().clone();
    attachment["segment_count"] = json!(2u64);
    let wrong_count = e2ee_block().with_field("attachment", attachment);
    assert!(wrong_count.validate_long_text().is_err());
}

#[test]
fn the_shape_is_closed_and_the_plaintext_size_has_one_home() {
    // The E2EE branch keeps the plaintext byte count in attachment.size_bytes only; a second
    // top-level field would be a competing source of truth.
    let duplicated = e2ee_block().with_field("plaintext_size_bytes", json!(700_000u64));
    assert!(duplicated.validate_long_text().is_err());
    let top_level_size = e2ee_block().with_field("size_bytes", json!(700_000u64));
    assert!(top_level_size.validate_long_text().is_err());
    // The plaintext branch is closed too.
    let stray = plaintext_block().with_field("formatted_body", json!("<p>x</p>"));
    assert!(stray.validate_long_text().is_err());
}

#[test]
fn fallback_body_is_bounded_in_utf8_bytes() {
    // 2048 three-byte scalars are 6144 UTF-8 bytes but only 2048 code points, so a code-point
    // bound would wrongly accept this.
    let oversized = "\u{4e2d}".repeat(2048);
    assert!(oversized.chars().count() < LONG_TEXT_FALLBACK_MAX_BYTES);
    assert!(oversized.len() > LONG_TEXT_FALLBACK_MAX_BYTES);
    let block = ContentBlock::new(CONTENT_KIND_LONG_TEXT, oversized)
        .with_field("format", json!("plain"))
        .with_field("body_kind", json!("summary"))
        .with_field(
            "blob_ref",
            json!(format!("ak:blob:sha256:{}", "a".repeat(64))),
        )
        .with_field("size_bytes", json!(700_000u64))
        .with_field("media_type", json!("text/plain"));
    assert!(block.validate_long_text().is_err());
}

#[test]
fn fallback_body_must_already_be_normalized() {
    let crlf = plaintext_block();
    let crlf = ContentBlock::new(CONTENT_KIND_LONG_TEXT, "line one\r\nline two")
        .with_field("format", json!("markdown"))
        .with_field("body_kind", json!("prefix"))
        .with_field("blob_ref", crlf.extra.get("blob_ref").unwrap().clone())
        .with_field("size_bytes", json!(700_000u64))
        .with_field("media_type", json!("text/markdown"));
    assert!(crlf.validate_long_text().is_err());
}

#[test]
fn normalization_rewrites_line_endings_and_rejects_control_characters() {
    assert_eq!(normalize_long_text("a\r\nb\rc\nd").unwrap(), "a\nb\nc\nd");
    assert_eq!(normalize_long_text("tab\there").unwrap(), "tab\there");
    assert!(normalize_long_text("\u{feff}body").is_err());
    assert!(normalize_long_text("bell\u{7}").is_err());
    assert!(normalize_long_text("del\u{7f}").is_err());
}

#[test]
fn line_count_matches_the_normative_formula() {
    assert_eq!(long_text_line_count(""), 0);
    assert_eq!(long_text_line_count("a"), 1);
    assert_eq!(long_text_line_count("a\n"), 1);
    assert_eq!(long_text_line_count("a\nb"), 2);
    assert_eq!(long_text_line_count("a\nb\n"), 2);
    assert_eq!(long_text_line_count("\n"), 1);
}

#[test]
fn body_kind_is_a_closed_set() {
    assert_eq!(
        LongTextBodyKind::parse("prefix"),
        Some(LongTextBodyKind::Prefix)
    );
    assert_eq!(
        LongTextBodyKind::parse("summary"),
        Some(LongTextBodyKind::Summary)
    );
    assert_eq!(LongTextBodyKind::parse("excerpt"), None);
    let unknown = plaintext_block().with_field("body_kind", json!("excerpt"));
    assert!(unknown.validate_long_text().is_err());
}

#[test]
fn format_is_a_closed_set_without_prosemirror() {
    assert_eq!(LongTextFormat::parse("prosemirror_json"), None);
    let structured = plaintext_block().with_field("format", json!("prosemirror_json"));
    assert!(structured.validate_long_text().is_err());
}

#[test]
fn inline_text_boundary_is_measured_in_utf8_bytes() {
    let at_limit = ContentBlock::text("a".repeat(CONTENT_TEXT_INLINE_MAX_BYTES));
    at_limit.validate_inline_text().unwrap();

    let over_limit = ContentBlock::text("a".repeat(CONTENT_TEXT_INLINE_MAX_BYTES + 1));
    assert!(over_limit.validate_inline_text().is_err());

    // Code points alone are not the bound: 100_000 three-byte scalars stay under the code-point
    // count but exceed the byte budget.
    let multibyte = ContentBlock::text("\u{4e2d}".repeat(100_000));
    assert!(multibyte.body.chars().count() < CONTENT_TEXT_INLINE_MAX_BYTES);
    assert!(multibyte.validate_inline_text().is_err());
}

#[test]
fn plaintext_builder_derives_normalized_metadata_and_scalar_safe_prefix() {
    let source = format!("{}\r\nlast", "\u{4e2d}".repeat(1_400));
    let block = ContentBlock::plaintext_long_text(
        &source,
        LongTextFormat::Markdown,
        format!("ak:blob:sha256:{}", "d".repeat(64)),
        LongTextBodyKind::Prefix,
        None,
    )
    .unwrap();
    let normalized = normalize_long_text(&source).unwrap();
    assert_eq!(block.body, long_text_prefix(&normalized));
    assert!(block.body.is_char_boundary(block.body.len()));
    assert!(block.body.len() <= LONG_TEXT_FALLBACK_MAX_BYTES);
    assert_eq!(block.extra_u64("size_bytes"), Some(normalized.len() as u64));
    assert_eq!(
        block.extra_u64("line_count"),
        Some(long_text_line_count(&normalized))
    );
    block.validate_long_text().unwrap();
}

#[test]
fn plaintext_builder_requires_a_bounded_normalized_summary() {
    let blob_ref = format!("ak:blob:sha256:{}", "e".repeat(64));
    assert!(
        ContentBlock::plaintext_long_text(
            "full body",
            LongTextFormat::Plain,
            &blob_ref,
            LongTextBodyKind::Summary,
            None,
        )
        .is_err()
    );
    let block = ContentBlock::plaintext_long_text(
        "line one\r\nline two",
        LongTextFormat::Plain,
        blob_ref,
        LongTextBodyKind::Summary,
        Some("short\rsummary"),
    )
    .unwrap();
    assert_eq!(block.body, "short\nsummary");
}
