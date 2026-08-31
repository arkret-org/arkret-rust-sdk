//! Executable entry point for the SDK-declared spec coverage gate.

use std::process::ExitCode;

use arkret_schema_conformance::{SpecArtifactBundle, default_spec_artifacts_dir};

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
                "update the conformance coverage declarations, then re-run this example against \
                 the same artifact tree"
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

    Err("no spec artifacts available; set \
         ARKRET_SPEC_ARTIFACTS=<arkret-spec>/spec/v1/artifacts"
        .to_owned())
}
