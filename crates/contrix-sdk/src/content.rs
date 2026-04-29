//! Rich content helpers: Markdown, mentions, link previews and reactions.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Did;

/// Parsed Markdown block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RichTextBlock {
    /// Heading with level 1-6.
    Heading { level: u8, text: String },
    /// Paragraph text.
    Paragraph(String),
    /// Fenced code block.
    CodeBlock { language: Option<String>, code: String },
    /// Unordered list.
    List { items: Vec<String> },
}

/// Parsed Markdown document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkdownDocument {
    /// Original markdown source.
    pub source: String,
    /// Parsed blocks.
    pub blocks: Vec<RichTextBlock>,
}

impl MarkdownDocument {
    /// Parse a small CommonMark-compatible subset used by the SDK.
    pub fn parse(source: impl Into<String>) -> Self {
        let source = source.into();
        let mut blocks = Vec::new();
        let mut paragraph = Vec::new();
        let mut list = Vec::new();
        let mut code = Vec::new();
        let mut code_language = None;
        let mut in_code = false;

        let flush_paragraph = |blocks: &mut Vec<RichTextBlock>, paragraph: &mut Vec<String>| {
            if !paragraph.is_empty() {
                blocks.push(RichTextBlock::Paragraph(paragraph.join(" ")));
                paragraph.clear();
            }
        };
        let flush_list = |blocks: &mut Vec<RichTextBlock>, list: &mut Vec<String>| {
            if !list.is_empty() {
                blocks.push(RichTextBlock::List { items: list.clone() });
                list.clear();
            }
        };

        for line in source.lines() {
            let trimmed = line.trim_end();
            if let Some(fence) = trimmed.strip_prefix("```") {
                if in_code {
                    blocks.push(RichTextBlock::CodeBlock {
                        language: code_language.take(),
                        code: code.join("\n"),
                    });
                    code.clear();
                    in_code = false;
                } else {
                    flush_paragraph(&mut blocks, &mut paragraph);
                    flush_list(&mut blocks, &mut list);
                    code_language =
                        if fence.trim().is_empty() { None } else { Some(fence.trim().to_owned()) };
                    in_code = true;
                }
                continue;
            }

            if in_code {
                code.push(trimmed.to_owned());
                continue;
            }

            if trimmed.is_empty() {
                flush_paragraph(&mut blocks, &mut paragraph);
                flush_list(&mut blocks, &mut list);
                continue;
            }

            if let Some((level, text)) = parse_heading(trimmed) {
                flush_paragraph(&mut blocks, &mut paragraph);
                flush_list(&mut blocks, &mut list);
                blocks.push(RichTextBlock::Heading { level, text });
            } else if let Some(item) = trimmed.strip_prefix("- ") {
                flush_paragraph(&mut blocks, &mut paragraph);
                list.push(item.to_owned());
            } else {
                flush_list(&mut blocks, &mut list);
                paragraph.push(trimmed.to_owned());
            }
        }

        if in_code {
            blocks
                .push(RichTextBlock::CodeBlock { language: code_language, code: code.join("\n") });
        }
        flush_paragraph(&mut blocks, &mut paragraph);
        flush_list(&mut blocks, &mut list);

        Self { source, blocks }
    }

    /// Render parsed Markdown to safe HTML.
    pub fn render_html(&self) -> String {
        self.blocks
            .iter()
            .map(|block| match block {
                RichTextBlock::Heading { level, text } => {
                    format!("<h{level}>{}</h{level}>", render_inline(text))
                }
                RichTextBlock::Paragraph(text) => format!("<p>{}</p>", render_inline(text)),
                RichTextBlock::CodeBlock { language, code } => {
                    let class = language
                        .as_ref()
                        .map(|language| format!(" class=\"language-{}\"", escape_html(language)))
                        .unwrap_or_default();
                    format!(
                        "<pre><code{class}>{}</code></pre>",
                        highlight_code(code, language.as_deref())
                    )
                }
                RichTextBlock::List { items } => {
                    let items = items
                        .iter()
                        .map(|item| format!("<li>{}</li>", render_inline(item)))
                        .collect::<String>();
                    format!("<ul>{items}</ul>")
                }
            })
            .collect::<Vec<_>>()
            .join("")
    }
}

/// Mention parsed from rich text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mention {
    /// Mention token without `@`.
    pub token: String,
    /// Byte start offset.
    pub start: usize,
    /// Byte end offset.
    pub end: usize,
    /// What kind of target this mention resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<MentionTarget>,
    /// Resolved target reference (DID, entity ID, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
}

/// Target kind for a structured mention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionTarget {
    /// Mention targets a user/actor by DID or handle.
    User,
    /// Mention targets an entity (task, document, etc.).
    Entity,
    /// Mention targets a space.
    Space,
    /// Mention targets a room/channel.
    Channel,
}

impl Mention {
    /// Create a mention with a resolved target.
    pub fn with_target(mut self, kind: MentionTarget, target_ref: impl Into<String>) -> Self {
        self.target_kind = Some(kind);
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Render the mention as a display string (e.g., `@alice`).
    pub fn display(&self) -> String {
        format!("@{}", self.token)
    }

    /// Render the mention as a structured reference (e.g., `@did:web:alice.example`).
    pub fn structured_display(&self) -> String {
        match &self.target_ref {
            Some(reference) => format!("@{reference}"),
            None => format!("@{}", self.token),
        }
    }
}

/// Parse `@mention` tokens.
pub fn parse_mentions(text: &str) -> Vec<Mention> {
    let mut mentions = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'@' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        let token_start = index;
        while index < bytes.len()
            && matches!(bytes[index], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b':')
        {
            index += 1;
        }
        if index > token_start {
            let token = text[token_start..index].to_owned();
            let (target_kind, target_ref) = if token.starts_with("did:") {
                (Some(MentionTarget::User), Some(token.clone()))
            } else {
                (None, None)
            };
            mentions.push(Mention { token, start, end: index, target_kind, target_ref });
        }
    }
    mentions
}

/// Lightweight link preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPreview {
    /// URL.
    pub url: String,
    /// Title from markdown link text or domain.
    pub title: String,
    /// Domain/host.
    pub domain: String,
    /// Optional description.
    pub description: Option<String>,
}

/// Extract link previews from markdown links and bare HTTP URLs.
pub fn extract_link_previews(text: &str) -> Vec<LinkPreview> {
    let mut previews = Vec::new();
    let mut seen = BTreeSet::new();

    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find("](") else {
            break;
        };
        let title = &after_open[..close];
        let after_close = &after_open[close + 2..];
        let Some(end) = after_close.find(')') else {
            break;
        };
        let url = &after_close[..end];
        if is_http_url(url) && seen.insert(url.to_owned()) {
            previews.push(link_preview(url, Some(title)));
        }
        rest = &after_close[end + 1..];
    }

    for token in text.split_whitespace() {
        let url = token.trim_matches(|ch: char| matches!(ch, ',' | '.' | ')' | '('));
        if is_http_url(url) && seen.insert(url.to_owned()) {
            previews.push(link_preview(url, None));
        }
    }

    previews
}

/// Reaction entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    /// Target event/entity ID.
    pub target_id: String,
    /// Reacting user.
    pub user_id: Did,
    /// Canonical shortcode, for example `:thumbsup:`.
    pub shortcode: String,
    /// Renderable emoji or fallback text.
    pub emoji: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Aggregated reactions for a target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReactionSummary {
    /// Counts by shortcode.
    pub counts: BTreeMap<String, usize>,
}

/// In-memory reaction manager.
#[derive(Clone, Debug, Default)]
pub struct ReactionManager {
    reactions: BTreeMap<(String, Did, String), Reaction>,
}

impl ReactionManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a user reaction.
    pub fn add_reaction(
        &mut self,
        target_id: impl Into<String>,
        user_id: Did,
        shortcode: impl Into<String>,
    ) -> Reaction {
        let target_id = target_id.into();
        let shortcode = normalize_shortcode(&shortcode.into());
        let reaction = Reaction {
            target_id: target_id.clone(),
            user_id: user_id.clone(),
            emoji: emoji_shortcode_value(&shortcode),
            shortcode: shortcode.clone(),
            created_at: Utc::now(),
        };
        self.reactions.insert((target_id, user_id, shortcode), reaction.clone());
        reaction
    }

    /// Remove a user reaction.
    pub fn remove_reaction(&mut self, target_id: &str, user_id: &Did, shortcode: &str) -> bool {
        self.reactions
            .remove(&(target_id.to_owned(), user_id.clone(), normalize_shortcode(shortcode)))
            .is_some()
    }

    /// Aggregate reactions by shortcode for a target.
    pub fn aggregate(&self, target_id: &str) -> ReactionSummary {
        let mut summary = ReactionSummary::default();
        for reaction in self.reactions.values().filter(|reaction| reaction.target_id == target_id) {
            *summary.counts.entry(reaction.shortcode.clone()).or_default() += 1;
        }
        summary
    }
}

fn parse_heading(line: &str) -> Option<(u8, String)> {
    let hashes = line.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&hashes) || line.as_bytes().get(hashes).is_none_or(|byte| *byte != b' ') {
        return None;
    }
    Some((hashes as u8, line[hashes + 1..].to_owned()))
}

fn render_inline(text: &str) -> String {
    let mut output = escape_html(text);
    for preview in extract_link_previews(text) {
        let escaped_url = escape_html(&preview.url);
        let escaped_title = escape_html(&preview.title);
        output =
            output.replace(&escaped_url, &format!("<a href=\"{escaped_url}\">{escaped_title}</a>"));
    }
    output
}

fn highlight_code(code: &str, language: Option<&str>) -> String {
    let escaped = escape_html(code);
    if !matches!(language, Some("rust" | "rs")) {
        return escaped;
    }

    escaped
        .split_whitespace()
        .map(|word| match word {
            "fn" | "let" | "pub" | "struct" | "impl" | "use" | "mod" => {
                format!("<span class=\"kw\">{word}</span>")
            }
            _ => word.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

fn link_preview(url: &str, title: Option<&str>) -> LinkPreview {
    let domain = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_owned();
    LinkPreview {
        url: url.to_owned(),
        title: title.unwrap_or(&domain).to_owned(),
        domain,
        description: None,
    }
}

fn normalize_shortcode(shortcode: &str) -> String {
    let trimmed = shortcode.trim();
    if trimmed.starts_with(':') && trimmed.ends_with(':') {
        trimmed.to_owned()
    } else {
        format!(":{trimmed}:")
    }
}

fn emoji_shortcode_value(shortcode: &str) -> String {
    match shortcode {
        ":thumbsup:" | ":+1:" => "+1",
        ":heart:" => "<3",
        ":laugh:" => "laugh",
        _ => shortcode.trim_matches(':'),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn markdown_parses_renders_highlights_mentions_and_links() {
        let markdown = "# Title\nHello @alice see [docs](https://example.com/docs)\n\n```rust\npub fn main() {}\n```";
        let document = MarkdownDocument::parse(markdown);

        assert_eq!(document.blocks.len(), 3);
        let html = document.render_html();
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<span class=\"kw\">pub</span>"));

        let mentions = parse_mentions(markdown);
        assert_eq!(mentions[0].token, "alice");

        let previews = extract_link_previews(markdown);
        assert_eq!(previews[0].domain, "example.com");
        assert_eq!(previews[0].title, "docs");
    }

    #[test]
    fn reactions_add_remove_and_aggregate_shortcodes() {
        let mut manager = ReactionManager::new();
        let alice = did("alice");
        let bob = did("bob");

        manager.add_reaction("event1", alice.clone(), "thumbsup");
        manager.add_reaction("event1", bob, ":thumbsup:");
        assert_eq!(manager.aggregate("event1").counts[":thumbsup:"], 2);

        assert!(manager.remove_reaction("event1", &alice, "thumbsup"));
        assert_eq!(manager.aggregate("event1").counts[":thumbsup:"], 1);
    }
}
