use super::registration::AppletNamespaceDomain;

/// Exact nonempty intersection of the two namespace glob languages.
/// Wildcards must consume at least one byte, matching the wire grammar.
pub fn namespace_patterns_overlap(domain: AppletNamespaceDomain, left: &str, right: &str) -> bool {
    #[derive(Clone, Copy)]
    enum Token {
        Literal(u8),
        Star,
        Deep,
    }
    fn tokens(pattern: &str) -> Vec<Token> {
        let mut result = Vec::new();
        let mut bytes = pattern.bytes().peekable();
        while let Some(byte) = bytes.next() {
            result.push(match byte {
                b'\\' if bytes.peek() == Some(&b'*') => {
                    bytes.next();
                    Token::Literal(b'*')
                }
                b'*' if bytes.peek() == Some(&b'*') => {
                    bytes.next();
                    Token::Deep
                }
                b'*' => Token::Star,
                other => Token::Literal(other),
            });
        }
        result
    }
    let left = tokens(left);
    let right = tokens(right);
    let accepts = |token: Token, byte| match token {
        Token::Literal(literal) => literal == byte,
        Token::Star => !domain.separators().contains(&byte),
        Token::Deep => byte != b':',
    };
    let mut pending = vec![(0, 0)];
    let mut seen = std::collections::BTreeSet::new();
    while let Some((a, b)) = pending.pop() {
        if !seen.insert((a, b)) {
            continue;
        }
        if a == left.len() && b == right.len() {
            return true;
        }
        let (Some(&l), Some(&r)) = (left.get(a), right.get(b)) else {
            continue;
        };
        if !(0..=255).any(|byte| accepts(l, byte) && accepts(r, byte)) {
            continue;
        }
        pending.push((a + 1, b + 1));
        if !matches!(l, Token::Literal(_)) {
            pending.push((a, b + 1));
        }
        if !matches!(r, Token::Literal(_)) {
            pending.push((a + 1, b));
        }
    }
    false
}

/// Test whether `candidate` matches an applet namespace `pattern` in
/// `domain`.
///
/// Grammar (spec `applet-schema.md` §2):
/// - `*` matches exactly one segment: one or more chars that are not a separator for `domain` (`:`
///   and `/`). It never crosses a separator and never matches an empty segment.
/// - `**` matches one or more path-like segments: one or more chars that may include `/` but never
///   `:`. It never matches empty.
/// - Literal `*` is escaped as `\*`.
/// - An empty pattern matches only an empty candidate.
pub fn namespace_pattern_matches(
    domain: AppletNamespaceDomain,
    pattern: &str,
    candidate: &str,
) -> bool {
    namespace_pattern_match_bytes(
        domain.separators(),
        pattern.as_bytes(),
        candidate.as_bytes(),
    )
}

fn namespace_pattern_match_bytes(separators: &[u8], pattern: &[u8], candidate: &[u8]) -> bool {
    let is_sep = |byte: u8| separators.contains(&byte);
    let mut pi = 0;
    let mut ci = 0;

    while pi < pattern.len() {
        match pattern[pi] {
            b'\\' if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' => {
                // Escaped literal `*`.
                if ci >= candidate.len() || candidate[ci] != b'*' {
                    return false;
                }
                pi += 2;
                ci += 1;
            }
            b'*' => {
                if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' {
                    // `**`: one or more chars, may cross `/` but never `:`.
                    let rest = &pattern[pi + 2..];
                    if ci >= candidate.len() || candidate[ci] == b':' {
                        return false;
                    }
                    let mut split = ci + 1;
                    loop {
                        if namespace_pattern_match_bytes(separators, rest, &candidate[split..]) {
                            return true;
                        }
                        if split >= candidate.len() || candidate[split] == b':' {
                            return false;
                        }
                        split += 1;
                    }
                } else {
                    // `*`: one or more non-separator chars.
                    let rest = &pattern[pi + 1..];
                    if ci >= candidate.len() || is_sep(candidate[ci]) {
                        return false;
                    }
                    let mut split = ci + 1;
                    loop {
                        if namespace_pattern_match_bytes(separators, rest, &candidate[split..]) {
                            return true;
                        }
                        if split >= candidate.len() || is_sep(candidate[split]) {
                            return false;
                        }
                        split += 1;
                    }
                }
            }
            byte => {
                if ci >= candidate.len() || candidate[ci] != byte {
                    return false;
                }
                pi += 1;
                ci += 1;
            }
        }
    }

    ci == candidate.len()
}

#[cfg(test)]
mod tests {
    use AppletNamespaceDomain::Realms;

    use super::*;

    #[test]
    fn namespace_overlap_checks_the_whole_language_not_sample_prefixes() {
        for (left, right, expected) in [
            ("team/*/room", "team/alice/*", true),
            ("team/*/room", "team/alice/other", false),
            ("team/*", "team/", false),
            ("team/*", "team/alice/room", false),
            ("team/**", "team/alice/room", true),
            ("team/**", "team/alice:room", false),
            ("literal\\*", "literal*", true),
            ("literal\\*", "literalX", false),
            ("*x", "y*", true),
            ("a**z", "ab*z", true),
            ("*", "", false),
        ] {
            assert_eq!(
                namespace_patterns_overlap(Realms, left, right),
                expected,
                "{left} intersects {right}"
            );
            assert_eq!(
                namespace_patterns_overlap(Realms, right, left),
                expected,
                "{right} intersects {left}"
            );
        }
    }

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(namespace_pattern_matches(
            Realms,
            "did:webvh:z6mkmanagedfixture:actors.example:managed:*",
            "did:webvh:z6mkmanagedfixture:actors.example:managed:u123"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "did:webvh:z6mkmanagedfixture:actors.example:managed:*",
            "did:webvh:z6mkotherfixture:other.example:managed:u123"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn double_star_crosses_slash_but_not_colon_or_empty_segment() {
        assert!(namespace_pattern_matches(
            Realms,
            "slack.acme.example/**",
            "slack.acme.example/team/a/b"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:**",
            "slack:team:T123:channel:C456"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "slack.acme.example/**",
            "slack.acme.example/"
        ));
    }

    #[test]
    fn escaped_star_is_literal_and_empty_pattern_is_closed() {
        assert!(namespace_pattern_matches(
            Realms,
            "literal\\*pattern",
            "literal*pattern"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "literal\\*pattern",
            "literalXpattern"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "",
            "did:webvh:z6mkfixture:anything.example"
        ));
    }
}
