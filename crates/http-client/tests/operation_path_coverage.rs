//! Pins every `/_arkret/...` path this client sends to the generated service
//! operation registry.
//!
//! `crates/server` builds its routing table straight from
//! [`SERVICE_OPERATION_DESCRIPTORS`], so a spec path change moves the server
//! automatically. The client does not: it spells all ~115 distinct paths as
//! string literals and never referenced the descriptors at all, which made it
//! the one spec-derived surface in the workspace with no drift gate. A renamed
//! path in `operation-registry.json` would regenerate the descriptors, keep the
//! server correct, and leave this crate silently issuing 404s.
//!
//! Scanning source text rather than refactoring 137 call sites onto descriptor
//! lookups keeps the gate independent of how any single endpoint builds its
//! URL — `format!` with inline captures, positional arguments, or a plain
//! literal all normalise to the same template.

use std::collections::BTreeSet;

use arkret_wire::SERVICE_OPERATION_DESCRIPTORS;

/// Every client source file, so a new endpoint module cannot join the crate
/// without either appearing here or failing [`sources_cover_the_crate`].
const SOURCES: &[(&str, &str)] = &[
    (
        "station_connection.rs",
        include_str!("../src/station_connection.rs"),
    ),
    (
        "account_subscribe.rs",
        include_str!("../src/account_subscribe.rs"),
    ),
    ("builder.rs", include_str!("../src/builder.rs")),
    (
        "client_internals.rs",
        include_str!("../src/client_internals.rs"),
    ),
    ("endpoints.rs", include_str!("../src/endpoints.rs")),
    (
        "endpoints/account.rs",
        include_str!("../src/endpoints/account.rs"),
    ),
    (
        "endpoints/agent.rs",
        include_str!("../src/endpoints/agent.rs"),
    ),
    (
        "endpoints/applet.rs",
        include_str!("../src/endpoints/applet.rs"),
    ),
    (
        "endpoints/circle.rs",
        include_str!("../src/endpoints/circle.rs"),
    ),
    (
        "endpoints/data.rs",
        include_str!("../src/endpoints/data.rs"),
    ),
    (
        "endpoints/events.rs",
        include_str!("../src/endpoints/events.rs"),
    ),
    (
        "endpoints/history_key.rs",
        include_str!("../src/endpoints/history_key.rs"),
    ),
    (
        "endpoints/identity.rs",
        include_str!("../src/endpoints/identity.rs"),
    ),
    (
        "endpoints/invite.rs",
        include_str!("../src/endpoints/invite.rs"),
    ),
    (
        "endpoints/media.rs",
        include_str!("../src/endpoints/media.rs"),
    ),
    (
        "endpoints/message_authoring.rs",
        include_str!("../src/endpoints/message_authoring.rs"),
    ),
    (
        "endpoints/mimi.rs",
        include_str!("../src/endpoints/mimi.rs"),
    ),
    (
        "endpoints/moderation.rs",
        include_str!("../src/endpoints/moderation.rs"),
    ),
    (
        "endpoints/peer.rs",
        include_str!("../src/endpoints/peer.rs"),
    ),
    (
        "endpoints/push.rs",
        include_str!("../src/endpoints/push.rs"),
    ),
    (
        "endpoints/realm_join.rs",
        include_str!("../src/endpoints/realm_join.rs"),
    ),
    (
        "endpoints/relation.rs",
        include_str!("../src/endpoints/relation.rs"),
    ),
    (
        "endpoints/security.rs",
        include_str!("../src/endpoints/security.rs"),
    ),
    (
        "endpoints/signal.rs",
        include_str!("../src/endpoints/signal.rs"),
    ),
    ("error.rs", include_str!("../src/error.rs")),
    (
        "http_did_resolver.rs",
        include_str!("../src/http_did_resolver.rs"),
    ),
    (
        "key_backup_client.rs",
        include_str!("../src/key_backup_client.rs"),
    ),
    ("lib.rs", include_str!("../src/lib.rs")),
    ("request.rs", include_str!("../src/request.rs")),
    (
        "service_resolution_fetcher.rs",
        include_str!("../src/service_resolution_fetcher.rs"),
    ),
    (
        "subscribe_body.rs",
        include_str!("../src/subscribe_body.rs"),
    ),
    ("tests.rs", include_str!("../src/tests.rs")),
    ("tls_roots.rs", include_str!("../src/tls_roots.rs")),
];

/// Literals that are deliberately not operation paths. Each entry states why,
/// because an unexplained entry here is indistinguishable from a suppressed
/// drift.
const NON_OPERATION_LITERALS: &[(&str, &str)] = &[
    (
        "/_arkret/self/",
        "client_internals.rs authentication-scope prefix test, not a request target",
    ),
    (
        "/_arkret/root/",
        "client_internals.rs authentication-scope prefix test, not a request target",
    ),
    (
        "/_arkret/self/applets/ak:applet:01904100-0000-7000-8000-000000000001/ghosts/provision",
        "endpoints/applet.rs in-file unit test expectation with a substituted sample applet id",
    ),
];

/// Collapse a concrete or templated path to its registry-comparable shape:
/// drop any query string, then reduce every `{...}` capture to `{}` so
/// `format!("…/{realm_id}/…")`, `format!("…/{}", id)` and the registry's
/// `{realm_id}` all agree.
fn normalise(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for character in path.chars() {
        match character {
            '{' => {
                if depth == 0 {
                    out.push_str("{}");
                }
                depth += 1;
            }
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(character),
            _ => {}
        }
    }
    out
}

/// Pull every `"/_arkret/..."` string literal out of one source file.
fn arkret_path_literals(source: &str) -> Vec<String> {
    const OPENING: &str = "\"/_arkret/";
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find(OPENING) {
        let body = &rest[start + 1..];
        let Some(end) = body.find('"') else { break };
        found.push(body[..end].to_owned());
        rest = &body[end..];
    }
    found
}

fn registry_paths() -> BTreeSet<String> {
    SERVICE_OPERATION_DESCRIPTORS
        .iter()
        .map(|descriptor| normalise(descriptor.http_path))
        .collect()
}

fn rust_sources_under(
    directory: &std::path::Path,
    source_root: &std::path::Path,
    sources: &mut BTreeSet<String>,
) {
    for entry in std::fs::read_dir(directory).expect("client source directory is readable") {
        let entry = entry.expect("client source directory entry is readable");
        let path = entry.path();
        if path.is_dir() {
            rust_sources_under(&path, source_root, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(source_root)
                .expect("source file is below client source root")
                .to_string_lossy()
                .replace('\\', "/");
            sources.insert(relative);
        }
    }
}

#[test]
fn every_client_path_is_a_registered_operation_path() {
    let registered = registry_paths();
    let exempt: BTreeSet<&str> = NON_OPERATION_LITERALS
        .iter()
        .map(|(literal, _)| *literal)
        .collect();

    let mut unregistered: Vec<String> = Vec::new();
    for (file, source) in SOURCES {
        for literal in arkret_path_literals(source) {
            let normalised = normalise(&literal);
            if registered.contains(&normalised) || exempt.contains(normalised.as_str()) {
                continue;
            }
            unregistered.push(format!("{file}: {literal}"));
        }
    }
    unregistered.sort();
    unregistered.dedup();

    assert!(
        unregistered.is_empty(),
        "these client paths are not in the generated service operation registry, so the \
         client would call an endpoint the protocol does not define:\n  {}\n\
         Fix the path, or — if it is genuinely not an operation target — add it to \
         NON_OPERATION_LITERALS with a reason.",
        unregistered.join("\n  ")
    );
}

#[test]
fn exemptions_still_occur_in_the_source() {
    let present: BTreeSet<String> = SOURCES
        .iter()
        .flat_map(|(_, source)| arkret_path_literals(source))
        .map(|literal| normalise(&literal))
        .collect();

    let stale: Vec<&str> = NON_OPERATION_LITERALS
        .iter()
        .map(|(literal, _)| *literal)
        .filter(|literal| !present.contains(&normalise(literal)))
        .collect();

    assert!(
        stale.is_empty(),
        "NON_OPERATION_LITERALS exempts paths that no longer appear in the client: \
         {stale:?}. Delete them so the exemption list cannot accumulate blanket \
         suppressions."
    );
}

/// Guard for the guard: if the extractor or the descriptor table returned
/// nothing, the assertion above would pass while checking nothing at all.
#[test]
fn both_sides_of_the_comparison_are_populated() {
    let registered = registry_paths();
    assert!(
        registered.len() > 100,
        "SERVICE_OPERATION_DESCRIPTORS yielded only {} distinct paths",
        registered.len()
    );

    let scanned: BTreeSet<String> = SOURCES
        .iter()
        .flat_map(|(_, source)| arkret_path_literals(source))
        .map(|literal| normalise(&literal))
        .collect();
    assert!(
        scanned.len() > 100,
        "the client path scanner found only {} distinct paths; it has stopped matching \
         the way endpoints spell their URLs",
        scanned.len()
    );
}

/// The scan is only as complete as [`SOURCES`]. A new endpoint module that
/// nobody adds here would be invisible to the gate.
#[test]
fn sources_cover_the_crate() {
    let listed: BTreeSet<&str> = SOURCES.iter().map(|(name, _)| *name).collect();
    let source_root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut on_disk = BTreeSet::new();
    rust_sources_under(source_root, source_root, &mut on_disk);

    let unscanned: Vec<&String> = on_disk
        .iter()
        .filter(|name| !listed.contains(name.as_str()))
        .collect();
    assert!(
        unscanned.is_empty(),
        "client source files are not covered by the path gate: {unscanned:?}. Add them to \
         SOURCES."
    );
}

#[test]
fn normalise_reduces_captures_and_query_strings() {
    assert_eq!(
        normalise("/_arkret/self/realms/{realm_id}/spaces"),
        "/_arkret/self/realms/{}/spaces"
    );
    assert_eq!(
        normalise("/_arkret/self/keys/backups/{}"),
        "/_arkret/self/keys/backups/{}"
    );
    assert_eq!(
        normalise("/_arkret/self/events?cursor=x"),
        "/_arkret/self/events"
    );
    assert_eq!(normalise("/_arkret/describe"), "/_arkret/describe");
}
