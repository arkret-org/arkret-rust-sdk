//! Executable entry point for the SDK-declared spec coverage gate.
//!
//! [`SpecArtifactBundle::drift_report`] cross-checks the hand-maintained
//! `SUPPORTED_*` coverage constants against the live spec registries in both
//! directions (`missing_*` = the SDK declares an entry the spec dropped;
//! `unlisted_*` = the spec ships an active entry the SDK never declared).
//! Without this binary the gate is only ever compiled, never run.
//!
//! Artifact source resolution:
//!
//! 1. `ARKRET_SPEC_ARTIFACTS` — a co-checkout of `arkret-spec/spec/v1/artifacts`. This is what the
//!    `spec-drift` CI job sets, and it is the only mode that compares against the *live* spec.
//! 2. Otherwise the embedded snapshot, which requires the crate's `embedded-artifacts` feature;
//!    without it the snapshot compiles to `{}` and every lookup fails, so the run reports the
//!    missing feature instead of pretending the SDK drifted.

use std::process::ExitCode;

use arkret_schema::{SpecArtifactBundle, default_spec_artifacts_dir};

fn main() -> ExitCode {
    let (bundle, source) = match load_bundle() {
        Ok(loaded) => loaded,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };

    let report = bundle.drift_report();
    match serde_json::to_string_pretty(&report) {
        Ok(rendered) => println!("{rendered}"),
        Err(error) => {
            eprintln!("failed to render drift report: {error}");
            return ExitCode::FAILURE;
        }
    }

    match report.validate() {
        Ok(()) => {
            println!(
                "spec artifact coverage matches {source} ({} artifacts checked)",
                report.checked_files.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            eprintln!(
                "update the SUPPORTED_* constants in crates/schema/src/artifacts.rs, then \
                 re-run this example against the same artifact tree"
            );
            ExitCode::FAILURE
        }
    }
}

fn load_bundle() -> Result<(SpecArtifactBundle, String), String> {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        let bundle = SpecArtifactBundle::load(&artifacts_dir)
            .map_err(|error| format!("failed to load {}: {error}", artifacts_dir.display()))?;
        return Ok((bundle, artifacts_dir.display().to_string()));
    }

    SpecArtifactBundle::load_embedded()
        .map(|bundle| (bundle, "the embedded spec snapshot".to_owned()))
        .map_err(|error| {
            format!(
                "no spec artifacts available: {error}\n\
                 set ARKRET_SPEC_ARTIFACTS=<arkret-spec>/spec/v1/artifacts to check the live \
                 spec, or add --features embedded-artifacts to check the embedded snapshot"
            )
        })
}
