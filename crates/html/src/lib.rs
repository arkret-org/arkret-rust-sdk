//! Rich text, mention and link normalization contracts.

use std::collections::BTreeSet;

use contrix_core::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RichTextFormat {
    PlainText,
    Markdown,
    Html,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RichTextBlock {
    Heading { level: u8, text: String },
    Paragraph(String),
    CodeBlock { language: Option<String>, code: String },
    List { items: Vec<String> },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkdownDocument {
    pub source: String,
    pub blocks: Vec<RichTextBlock>,
}

impl MarkdownDocument {
    pub fn parse(source: impl Into<String>) -> Self {
        let source = source.into();
        let mut blocks = Vec::new();
        let mut paragraph = Vec::new();
        let mut list = Vec::new();
        let mut code = Vec::new();
        let mut code_language = None;
        let mut in_code = false;

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
                    format!("<pre><code{class}>{}</code></pre>", escape_html(code))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionTarget {
    Audience,
    Actor,
    Space,
    Flow,
    Message,
    Morph,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mention {
    pub token: String,
    pub start: usize,
    pub end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<MentionTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
}

impl Mention {
    pub fn with_target(mut self, kind: MentionTarget, target_ref: impl Into<String>) -> Self {
        self.target_kind = Some(kind);
        self.target_ref = Some(target_ref.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    pub title: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichTextDocument {
    pub source_format: RichTextFormat,
    pub source: String,
    pub sanitized_html: String,
    pub plain_text: String,
    pub mentions: Vec<Mention>,
    pub links: Vec<LinkPreview>,
}

impl RichTextDocument {
    pub fn normalize(source: impl Into<String>, source_format: RichTextFormat) -> Result<Self> {
        let source = source.into();
        let sanitized_html = match source_format {
            RichTextFormat::PlainText => format!("<p>{}</p>", escape_html(&source)),
            RichTextFormat::Markdown => MarkdownDocument::parse(&source).render_html(),
            RichTextFormat::Html => sanitize_html(&source)?,
        };
        let plain_text = plain_text_from_html(&sanitized_html);
        let mut links = extract_link_previews(&source);
        for href in extract_href_links(&sanitized_html) {
            if !links.iter().any(|link| link.url == href) {
                links.push(link_preview(&href, None));
            }
        }
        Ok(Self {
            source_format,
            source,
            mentions: parse_mentions(&plain_text),
            plain_text,
            sanitized_html,
            links,
        })
    }
}

pub fn sanitize_html(input: &str) -> Result<String> {
    if input.len() > 256 * 1024 {
        return Err(Error::Protocol("rich text HTML exceeds sanitizer limit".to_owned()));
    }
    let input = remove_dangerous_blocks(input);
    let mut output = String::with_capacity(input.len());
    let mut rest = input.as_str();
    while let Some(open) = rest.find('<') {
        output.push_str(&escape_html(&decode_basic_entities(&rest[..open])));
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('>') else {
            output.push_str("&lt;");
            rest = after_open;
            continue;
        };
        let raw_tag = after_open[..close].trim();
        output.push_str(&sanitize_tag(raw_tag));
        rest = &after_open[close + 1..];
    }
    output.push_str(&escape_html(&decode_basic_entities(rest)));
    Ok(output)
}

pub fn plain_text_from_html(input: &str) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    decode_basic_entities(&collapse_whitespace(&output))
}

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
            let (target_kind, target_ref) = classify_mention_token(&token);
            mentions.push(Mention { token, start, end: index, target_kind, target_ref });
        }
    }
    mentions
}

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
        if is_safe_http_url(url) && seen.insert(url.to_owned()) {
            previews.push(link_preview(url, Some(title)));
        }
        rest = &after_close[end + 1..];
    }

    for token in text.split_whitespace() {
        let url = token.trim_matches(|ch: char| matches!(ch, ',' | '.' | ')' | '(' | '"' | '\''));
        if is_safe_http_url(url) && seen.insert(url.to_owned()) {
            previews.push(link_preview(url, None));
        }
    }

    previews
}

fn sanitize_tag(raw_tag: &str) -> String {
    if raw_tag.is_empty() || raw_tag.starts_with('!') || raw_tag.starts_with('?') {
        return String::new();
    }
    let closing = raw_tag.starts_with('/');
    let content = raw_tag.trim_start_matches('/').trim();
    let tag = content
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    if !is_allowed_tag(&tag) {
        return String::new();
    }
    if closing {
        return format!("</{tag}>");
    }
    if tag == "a" {
        if let Some(href) = extract_attr(content, "href").filter(|href| is_safe_http_url(href)) {
            return format!("<a href=\"{}\">", escape_html(&href));
        }
        return "<a>".to_owned();
    }
    if tag == "code"
        && let Some(class) = extract_attr(content, "class").filter(|value| {
            value
                .strip_prefix("language-")
                .is_some_and(|name| name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'))
        })
    {
        return format!("<code class=\"{}\">", escape_html(&class));
    }
    if matches!(tag.as_str(), "br") {
        return "<br>".to_owned();
    }
    format!("<{tag}>")
}

fn is_allowed_tag(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "br"
            | "ul"
            | "ol"
            | "li"
            | "pre"
            | "code"
            | "strong"
            | "em"
            | "blockquote"
            | "a"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

fn remove_dangerous_blocks(input: &str) -> String {
    let mut output = input.to_owned();
    for tag in ["script", "style", "iframe", "object"] {
        loop {
            let lower = output.to_ascii_lowercase();
            let Some(start) = lower.find(&format!("<{tag}")) else {
                break;
            };
            let Some(end_relative) = lower[start..].find(&format!("</{tag}>")) else {
                output.truncate(start);
                break;
            };
            let end = start + end_relative + tag.len() + 3;
            output.replace_range(start..end, "");
        }
    }
    output
}

fn extract_attr(content: &str, name: &str) -> Option<String> {
    let mut rest = content;
    loop {
        let index = rest.to_ascii_lowercase().find(name)?;
        let candidate = &rest[index + name.len()..];
        let candidate = candidate.trim_start();
        let candidate = candidate.strip_prefix('=')?.trim_start();
        let quote = candidate.chars().next()?;
        if quote != '"' && quote != '\'' {
            rest = &candidate[1..];
            continue;
        }
        let value_start = quote.len_utf8();
        let value_rest = &candidate[value_start..];
        let value_end = value_rest.find(quote)?;
        return Some(value_rest[..value_end].to_owned());
    }
}

fn extract_href_links(html: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = html;
    while let Some(index) = rest.find("<a ") {
        let after = &rest[index + 3..];
        let Some(close) = after.find('>') else {
            break;
        };
        if let Some(href) =
            extract_attr(&after[..close], "href").filter(|href| is_safe_http_url(href))
        {
            links.push(href);
        }
        rest = &after[close + 1..];
    }
    links
}

fn classify_mention_token(token: &str) -> (Option<MentionTarget>, Option<String>) {
    if matches!(
        token.to_ascii_lowercase().as_str(),
        "all" | "participants" | "watchers" | "here" | "assigned" | "assignees"
    ) {
        (Some(MentionTarget::Audience), Some(token.to_ascii_lowercase()))
    } else if token.starts_with("did:") {
        (Some(MentionTarget::Actor), Some(token.to_owned()))
    } else if token.starts_with("ck:space:") {
        (Some(MentionTarget::Space), Some(token.to_owned()))
    } else if token.starts_with("ck:flow:") {
        (Some(MentionTarget::Flow), Some(token.to_owned()))
    } else if token.starts_with("ck:message:") {
        (Some(MentionTarget::Message), Some(token.to_owned()))
    } else if token.starts_with("ck:morph:") {
        (Some(MentionTarget::Morph), Some(token.to_owned()))
    } else {
        (None, None)
    }
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

fn flush_paragraph(blocks: &mut Vec<RichTextBlock>, paragraph: &mut Vec<String>) {
    if !paragraph.is_empty() {
        blocks.push(RichTextBlock::Paragraph(paragraph.join(" ")));
        paragraph.clear();
    }
}

fn flush_list(blocks: &mut Vec<RichTextBlock>, list: &mut Vec<String>) {
    if !list.is_empty() {
        blocks.push(RichTextBlock::List { items: list.clone() });
        list.clear();
    }
}

fn parse_heading(line: &str) -> Option<(u8, String)> {
    let hashes = line.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&hashes) || line.as_bytes().get(hashes).is_none_or(|byte| *byte != b' ') {
        return None;
    }
    Some((hashes as u8, line[hashes + 1..].to_owned()))
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

fn is_safe_http_url(value: &str) -> bool {
    (value.starts_with("https://") || value.starts_with("http://"))
        && !value.bytes().any(|byte| matches!(byte, 0..=31 | 127))
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_renders_safe_html_mentions_and_links() {
        let document = RichTextDocument::normalize(
            "# Title\nHello @did:web:alice.example see [docs](https://example.com/docs)",
            RichTextFormat::Markdown,
        )
        .unwrap();
        assert!(document.sanitized_html.contains("<h1>Title</h1>"));
        assert_eq!(document.mentions[0].target_kind, Some(MentionTarget::Actor));
        assert_eq!(document.links[0].domain, "example.com");
    }

    #[test]
    fn sanitizer_removes_script_handlers_and_javascript_urls() {
        let html = r#"<p onclick="x">Hi <script>alert(1)</script><a href="javascript:bad">bad</a><a href="https://example.com">ok</a></p>"#;
        let sanitized = sanitize_html(html).unwrap();
        assert!(!sanitized.contains("script"));
        assert!(!sanitized.contains("onclick"));
        assert!(!sanitized.contains("javascript:"));
        assert!(sanitized.contains("<a href=\"https://example.com\">"));
    }

    #[test]
    fn html_plaintext_fallback_decodes_entities() {
        let document = RichTextDocument::normalize(
            "<p>Hello &amp; welcome<br>@alice</p>",
            RichTextFormat::Html,
        )
        .unwrap();
        assert_eq!(document.plain_text, "Hello & welcome @alice");
        assert_eq!(document.mentions[0].token, "alice");
    }
}
