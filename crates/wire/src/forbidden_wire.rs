//! Consumer surface for `registry/forbidden-wire-fields.json`.
//!
//! The registry is the source of truth for field names that MUST NOT appear
//! on the current v1 wire in a named context (a payload class, a patch
//! document, the envelope, ...). Its canonical projection is
//! [`crate::generated::FORBIDDEN_WIRE_FIELDS`]; this module answers the one
//! question reducers and admission layers need — whether a concrete dotted
//! path is `hard_reject` in a context — so no consumer hand-copies the list.

use crate::generated::FORBIDDEN_WIRE_FIELDS;
use crate::patch::patch_path_covers;

/// Whether `path` hits a `hard_reject` registry entry in `context`.
///
/// `path` is a dotted payload or patch path (`metadata.fields.status`,
/// `stage`, ...). An entry matches when its id equals the path or is a dotted
/// ancestor of it, so a ban on `metadata.fields.status` also bans a write at
/// `metadata.fields.status.anything`. Patch-context entries carry the
/// registry's `patch:` prefix on their id (for example `patch:stage`); the
/// prefix is stripped before comparison so the same query covers create
/// payloads and patch documents.
pub fn forbidden_wire_path_hard_reject(context: &str, path: &str) -> bool {
    FORBIDDEN_WIRE_FIELDS.iter().any(|entry| {
        entry.context == context
            && entry.rejection_level == "hard_reject"
            && patch_path_covers(entry.id.strip_prefix("patch:").unwrap_or(entry.id), path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_projects_strand_and_morph_contexts() {
        // The counts pin the registry surface this module projects; a spec-side
        // entry addition or removal must be reflected here deliberately.
        let count = |context: &str| {
            FORBIDDEN_WIRE_FIELDS
                .iter()
                .filter(|entry| entry.context == context)
                .count()
        };
        assert_eq!(count("strand_payload"), 12);
        assert_eq!(count("strand_patch_payload"), 9);
        assert_eq!(count("morph_payload"), 6);
        assert_eq!(count("morph_update_payload"), 2);
    }

    #[test]
    fn dotted_payload_entries_match_exactly_and_cover_descendants() {
        assert!(forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.status"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.status.detail"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields.jira_status"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.title"
        ));
        // An ancestor of a registered path is not itself registered; callers
        // that accept a whole-object set value must descend into it.
        assert!(!forbidden_wire_path_hard_reject(
            "strand_payload",
            "metadata.fields"
        ));
    }

    #[test]
    fn patch_prefixed_entries_match_the_bare_path() {
        assert!(forbidden_wire_path_hard_reject(
            "strand_patch_payload",
            "stage"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "strand_patch_payload",
            "metadata.fields.assignee"
        ));
        assert!(forbidden_wire_path_hard_reject(
            "morph_update_payload",
            "morph_kind"
        ));
        assert!(!forbidden_wire_path_hard_reject(
            "morph_update_payload",
            "metadata.title"
        ));
        // Contexts are pinned: a name forbidden in one context may be legal
        // in another.
        assert!(!forbidden_wire_path_hard_reject(
            "morph_payload",
            "metadata.fields.status"
        ));
    }

    #[test]
    fn morph_reserved_field_names_are_hard_reject() {
        for leaf in [
            "lifecycle",
            "progress_state",
            "stage",
            "stage_changed_at",
            "stage_note",
            "stage_reason",
        ] {
            let path = format!("fields.{leaf}");
            assert!(
                forbidden_wire_path_hard_reject("morph_payload", &path),
                "{path} is hard_reject in morph_payload"
            );
        }
    }
}
