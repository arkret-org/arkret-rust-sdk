use super::registration::AppletNamespaceDomain;

/// Strip the DID `#fragment` for actor-domain matching (`applet-schema.md`
/// §2: `#fragment` does not participate). Other domains keep `#` literal.
fn strip_fragment(domain: AppletNamespaceDomain, value: &str) -> &str {
    if matches!(domain, AppletNamespaceDomain::Actors) {
        value.split('#').next().unwrap_or(value)
    } else {
        value
    }
}

/// Conservative overlap test between two exclusive namespace patterns.
/// Conflict detection MUST NOT miss a real overlap, so this errs toward
/// over-reporting: it strips a trailing `*` / `**` and tests prefix
/// containment after fragment normalization.
pub fn namespace_patterns_overlap(domain: AppletNamespaceDomain, left: &str, right: &str) -> bool {
    let left = strip_fragment(domain, left);
    let right = strip_fragment(domain, right);
    if left == right {
        return true;
    }
    let left_prefix = left.trim_end_matches('*');
    let right_prefix = right.trim_end_matches('*');
    left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix)
}

/// Test whether `candidate` matches an applet namespace `pattern` in
/// `domain`.
///
/// Grammar (spec `applet-schema.md` §2):
/// - `*` matches exactly one segment: one or more chars that are not a separator for `domain`
///   (actor: `:`; realm / handle: `:` and `/`). It never crosses a separator and never matches an
///   empty segment.
/// - `**` matches one or more path-like segments: one or more chars that may include `/` but never
///   `:`. It never matches empty.
/// - Literal `*` is escaped as `\*`.
/// - For the actor domain a DID `#fragment` is ignored on both sides.
/// - An empty pattern matches only an empty candidate.
pub fn namespace_pattern_matches(
    domain: AppletNamespaceDomain,
    pattern: &str,
    candidate: &str,
) -> bool {
    let pattern = strip_fragment(domain, pattern);
    let candidate = strip_fragment(domain, candidate);
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
    use AppletNamespaceDomain::{Actors, Realms};

    use super::*;

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u123"
        ));
        assert!(!namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:other.example:ghost:u123"
        ));
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn actor_matching_ignores_did_fragment() {
        assert!(namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u123#key-1"
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
            Actors,
            "",
            "did:webvh:z6mkfixture:anything.example"
        ));
    }
}
