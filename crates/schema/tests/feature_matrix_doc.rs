//! Cross-check guard for the hand-written `docs/feature-matrix.md` profile
//! mirror against the generated `profile_requirements` table (SPEC-FEAT-02).
//!
//! `docs/feature-matrix.md` carries a human-readable conformance-profile table
//! maintained by hand, while `arkret_wire::generated::profile_requirements` is
//! derived from the spec artifact. These are two sources for the same facts and
//! can drift. This test asserts every `ak.profile.*.vN` ID named in the doc is a
//! real profile in the generated (authoritative) table, so the mirror can never
//! reference a profile the code does not back.

use std::collections::BTreeSet;

use arkret_wire::generated::profile_requirements::requirements_for;

/// Load the workspace-root `docs/feature-matrix.md` relative to this crate's
/// manifest directory (`crates/schema`).
fn feature_matrix_markdown() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("feature-matrix.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("feature-matrix.md must be readable at {path:?}: {err}"))
}

/// Extract every `ak.profile.<...>.vN` identifier that appears in the document.
fn documented_profile_ids(markdown: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut rest = markdown;
    // Simple, dependency-free scan: find each "ak.profile." occurrence and read
    // the identifier run (letters, digits, '_', '.').
    while let Some(start) = rest.find("ak.profile.") {
        let tail = &rest[start..];
        let end = tail
            .char_indices()
            .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.'))
            .map(|(idx, _)| idx)
            .unwrap_or(tail.len());
        let mut id = tail[..end].to_owned();
        // Trim a trailing '.' that a sentence period may have absorbed.
        while id.ends_with('.') {
            id.pop();
        }
        // Only keep versioned profile IDs (`...vN`), skipping bare prose like
        // "ak.profile." mentions without a version suffix.
        if id.rsplit('.').next().is_some_and(|last| {
            last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()) && last.len() > 1
        }) {
            ids.insert(id);
        }
        rest = &tail[end..];
    }
    ids
}

#[test]
fn feature_matrix_profiles_subset_of_generated() {
    let markdown = feature_matrix_markdown();
    let documented = documented_profile_ids(&markdown);
    assert!(
        !documented.is_empty(),
        "feature-matrix.md must reference at least one profile ID; parser drifted?"
    );

    let mut unknown = Vec::new();
    for id in &documented {
        if requirements_for(id).is_none() {
            unknown.push(id.clone());
        }
    }
    assert!(
        unknown.is_empty(),
        "feature-matrix.md names profile IDs absent from the generated \
         profile_requirements table (mirror drifted ahead of the authoritative \
         source): {unknown:?}"
    );
}
