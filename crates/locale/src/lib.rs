//! The single UI-locale vocabulary and resolution order for the workspace.
//!
//! Before this crate existed, "which language is the UI in?" was answered
//! independently in six places: coauth's SPA, coauth's request handlers,
//! coauth's notification layer, the `users.preferred_locale` column, inkson's
//! client, and an unused `client.language` account-data key. Each carried its
//! own supported set and its own precedence rules — two of them even had their
//! own `Accept-Language` parser — so the two applications could disagree about
//! the same user's language and neither could tell you why.
//!
//! Everything here is deliberately dependency-free and `wasm32`-safe: coauth's
//! server, coauth's browser SPA and inkson's cross-platform client all link it.
//!
//! # Resolution order
//!
//! [`resolve`] applies exactly one precedence chain, documented on
//! [`LocaleSources`]. Call sites supply whichever tiers they can observe and
//! leave the rest `None`; they do not re-order or short-circuit it.

#![cfg_attr(docsrs, feature(doc_cfg))]

/// The locales the product UI ships.
///
/// Deliberately closed. Adding a variant is a product decision that requires a
/// complete dictionary on every surface — a partially-translated locale reads
/// as a bug to the user, which is precisely the failure this crate exists to
/// prevent. Callers that need to render a *language name* the product does not
/// itself speak should keep the raw BCP 47 tag alongside this value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum UiLocale {
    /// English — the reference locale and the terminal fallback.
    #[default]
    En,
    /// Simplified Chinese.
    Zh,
}

/// Every locale the product exposes, in menu order.
pub const SUPPORTED: [UiLocale; 2] = [UiLocale::En, UiLocale::Zh];

impl UiLocale {
    /// The canonical base tag persisted and sent on the wire (`"en"` / `"zh"`).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh",
        }
    }

    /// Writing direction, for the `dir` attribute and mirrored layout.
    ///
    /// Both shipped locales are left-to-right. The distinction is kept — rather
    /// than assumed away — so that adding a right-to-left locale is a change
    /// here and not an audit of every layout in two applications.
    #[must_use]
    pub const fn direction(self) -> TextDirection {
        match self {
            Self::En | Self::Zh => TextDirection::Ltr,
        }
    }

    /// Parse a single BCP 47 tag, matching on the primary language subtag.
    ///
    /// Region and script subtags fall through to the base language, so
    /// `zh-CN`, `zh-Hans`, `zh_TW` and `ZH` all resolve to [`UiLocale::Zh`].
    /// Returns `None` for a language the product does not ship — the caller
    /// decides whether that means "try the next tier" or "use the default".
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        let base = tag
            .trim()
            .split(['-', '_'])
            .next()
            .unwrap_or_default()
            .trim();
        if base.eq_ignore_ascii_case("en") {
            Some(Self::En)
        } else if base.eq_ignore_ascii_case("zh") {
            Some(Self::Zh)
        } else {
            None
        }
    }

    /// Parse a preference *list* and return the highest-ranked supported tag.
    ///
    /// One parser covers all three carriers the workspace uses, because they
    /// differ only in separator:
    ///
    /// * `Accept-Language` — comma-separated, optional `;q=` weights
    /// * OIDC `ui_locales` — space-separated, no weights
    /// * `navigator.language` / a stored preference — a single bare tag
    ///
    /// Entries are ordered by descending `q` (absent `q` means `1.0`), ties
    /// keep document order, and `q=0` is an explicit refusal so it is dropped.
    /// A malformed weight makes that one entry lowest-priority rather than
    /// discarding the whole header.
    #[must_use]
    pub fn from_tag_list(list: &str) -> Option<Self> {
        let mut best: Option<(u16, usize, Self)> = None;
        for (position, entry) in list
            .split([',', ' ', '\t', '\n'])
            .filter(|entry| !entry.trim().is_empty())
            .enumerate()
        {
            let mut parts = entry.split(';');
            let tag = parts.next().unwrap_or_default();
            let quality = parse_quality(parts);
            if quality == 0 {
                continue;
            }
            let Some(locale) = Self::from_tag(tag) else {
                continue;
            };
            let better = match best {
                None => true,
                Some((best_quality, best_position, _)) => {
                    quality > best_quality || (quality == best_quality && position < best_position)
                }
            };
            if better {
                best = Some((quality, position, locale));
            }
        }
        best.map(|(_, _, locale)| locale)
    }
}

/// Parse the `q=` parameter of one `Accept-Language` entry into thousandths.
///
/// Absent weight is `q=1`. An unparseable weight yields `1` (lowest non-zero
/// rank) rather than an error: a client sending a broken weight still stated a
/// language preference, and dropping it would silently fall through to a
/// language the user did not ask for.
fn parse_quality<'a>(params: impl Iterator<Item = &'a str>) -> u16 {
    for param in params {
        let param = param.trim();
        let Some(raw) = param
            .strip_prefix("q=")
            .or_else(|| param.strip_prefix("Q="))
        else {
            continue;
        };
        let Ok(value) = raw.trim().parse::<f64>() else {
            return 1;
        };
        if !value.is_finite() || value <= 0.0 {
            return 0;
        }
        let clamped = if value > 1.0 { 1.0 } else { value };
        // Three decimal places is all RFC 9110 permits.
        return (clamped * 1000.0).round() as u16;
    }
    1000
}

/// Writing direction of a locale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextDirection {
    /// Left-to-right.
    Ltr,
    /// Right-to-left.
    Rtl,
}

impl TextDirection {
    /// The HTML `dir` attribute value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

/// The tiers a caller can observe, in precedence order.
///
/// Leave a field `None` when the surface cannot see it — a server request has
/// no device cache, a signed-out browser has no account preference. Every field
/// takes a raw preference *list*, so the same struct accepts a single tag, an
/// OIDC `ui_locales` value or a full `Accept-Language` header.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocaleSources<'a> {
    /// The account's stored `preferred_locale`, however it arrived: read
    /// directly from the database, or from the OIDC `locale` claim. This is the
    /// source of truth for a signed-in user and therefore ranks first — it is
    /// the only tier that follows the person across devices.
    pub account: Option<&'a str>,
    /// An explicit request attached to this navigation — in practice OIDC
    /// `ui_locales`, which is how a client hands its live selection to the
    /// authority mid-flow. Ranks above the device cache because it is a
    /// deliberate statement made *now*, while the cache may be stale.
    pub requested: Option<&'a str>,
    /// This device's remembered choice (`localStorage`, a device preference
    /// store). A cache, not an authority: it seeds the experience before
    /// sign-in and must never override the account tier afterwards.
    pub device_cache: Option<&'a str>,
    /// The platform default — `Accept-Language` on a request,
    /// `navigator.language` in a browser. The user never chose this explicitly,
    /// so it only applies when nobody stated a preference.
    pub platform: Option<&'a str>,
}

/// Resolve the UI locale from whichever tiers the caller can observe.
///
/// Falls back to [`UiLocale::En`] when no tier offers a supported language.
#[must_use]
pub fn resolve(sources: &LocaleSources<'_>) -> UiLocale {
    let tiers = [
        sources.account,
        sources.requested,
        sources.device_cache,
        sources.platform,
    ];
    for raw in tiers {
        if let Some(locale) = raw.and_then(UiLocale::from_tag_list) {
            return locale;
        }
    }
    UiLocale::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_and_script_variants_fold_onto_the_base_language() {
        for tag in ["zh", "zh-CN", "zh-Hans", "zh_TW", "ZH", "zh-Hant-HK"] {
            assert_eq!(UiLocale::from_tag(tag), Some(UiLocale::Zh), "{tag}");
        }
        for tag in ["en", "en-US", "EN-gb", "en_AU"] {
            assert_eq!(UiLocale::from_tag(tag), Some(UiLocale::En), "{tag}");
        }
    }

    #[test]
    fn unsupported_languages_do_not_resolve() {
        for tag in ["fr", "ja-JP", "ar-SA", "es", "", "   ", "-"] {
            assert_eq!(UiLocale::from_tag(tag), None, "{tag}");
        }
    }

    #[test]
    fn tag_list_skips_unsupported_entries_in_order() {
        assert_eq!(UiLocale::from_tag_list("fr, zh-CN, en"), Some(UiLocale::Zh));
        assert_eq!(
            UiLocale::from_tag_list("fr-CA ja en-US"),
            Some(UiLocale::En)
        );
        assert_eq!(UiLocale::from_tag_list("fr, ja, ar"), None);
    }

    #[test]
    fn quality_weights_outrank_document_order() {
        // en appears first but concedes to zh on weight.
        assert_eq!(
            UiLocale::from_tag_list("en;q=0.5, zh-CN;q=0.9"),
            Some(UiLocale::Zh)
        );
        // Equal weight keeps document order.
        assert_eq!(
            UiLocale::from_tag_list("zh;q=0.8, en;q=0.8"),
            Some(UiLocale::Zh)
        );
        // An absent weight means q=1 and beats any explicit fraction.
        assert_eq!(UiLocale::from_tag_list("zh;q=0.9, en"), Some(UiLocale::En));
    }

    #[test]
    fn q_zero_is_an_explicit_refusal() {
        assert_eq!(
            UiLocale::from_tag_list("zh;q=0, en;q=0.1"),
            Some(UiLocale::En)
        );
        assert_eq!(UiLocale::from_tag_list("zh;q=0, en;q=0"), None);
    }

    #[test]
    fn a_malformed_weight_keeps_the_entry_at_lowest_priority() {
        // The client still stated a preference; it must not be discarded.
        assert_eq!(UiLocale::from_tag_list("zh;q=oops"), Some(UiLocale::Zh));
        // ...but anything well-formed outranks it.
        assert_eq!(
            UiLocale::from_tag_list("zh;q=oops, en;q=0.2"),
            Some(UiLocale::En)
        );
    }

    #[test]
    fn account_preference_outranks_every_other_tier() {
        let locale = resolve(&LocaleSources {
            account: Some("zh"),
            requested: Some("en"),
            device_cache: Some("en"),
            platform: Some("en-US"),
        });
        assert_eq!(locale, UiLocale::Zh);
    }

    #[test]
    fn an_explicit_request_outranks_a_stale_device_cache() {
        let locale = resolve(&LocaleSources {
            account: None,
            requested: Some("zh-CN"),
            device_cache: Some("en"),
            platform: Some("en-US"),
        });
        assert_eq!(locale, UiLocale::Zh);
    }

    #[test]
    fn the_device_cache_seeds_a_signed_out_surface() {
        let locale = resolve(&LocaleSources {
            device_cache: Some("zh"),
            platform: Some("en-US"),
            ..Default::default()
        });
        assert_eq!(locale, UiLocale::Zh);
    }

    #[test]
    fn an_unsupported_tier_falls_through_rather_than_terminating() {
        // A French account preference must not pin the UI to the default while
        // a supported Chinese request is sitting in the next tier.
        let locale = resolve(&LocaleSources {
            account: Some("fr"),
            requested: Some("zh"),
            ..Default::default()
        });
        assert_eq!(locale, UiLocale::Zh);
    }

    #[test]
    fn nothing_supported_anywhere_yields_english() {
        let locale = resolve(&LocaleSources {
            account: Some("fr"),
            requested: Some(""),
            device_cache: None,
            platform: Some("ja-JP, ar"),
        });
        assert_eq!(locale, UiLocale::En);
    }

    #[test]
    fn codes_round_trip_through_the_parser() {
        for locale in SUPPORTED {
            assert_eq!(UiLocale::from_tag(locale.code()), Some(locale));
        }
    }
}
