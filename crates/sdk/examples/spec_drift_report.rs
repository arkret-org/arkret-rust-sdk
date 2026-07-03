//! Print the SDK ↔ spec artifact drift report.
//!
//! Run with the sibling `cokret-spec` repo checked out alongside this one,
//! or with `COKRET_SPEC_ARTIFACTS` pointing at any `artifacts/` directory:
//!
//! ```sh
//! cargo run --example spec_drift_report
//! COKRET_SPEC_ARTIFACTS=/path/to/cokret-spec/spec/v1/artifacts \
//!     cargo run --example spec_drift_report
//! ```
//!
//! The report distinguishes:
//!
//! * `missing_*`: the SDK declares coverage for an entry the spec no longer ships.
//! * `unlisted_*`: the spec ships an active entry the SDK has not declared coverage for.
//!
//! Any drift exits non-zero so CI fails fast.
//!
//! In CI, point this at a checked-out spec to surface drift before tagging:
//!
//! ```yaml
//! - uses: actions/checkout@v4
//!   with: { repository: cokret/cokret-spec, path: cokret-spec }
//! - run: cargo run --example spec_drift_report
//!   env: { COKRET_SPEC_ARTIFACTS: cokret-spec/spec/v1/artifacts }
//! ```

use std::process::ExitCode;

use cokret::schema_contracts::artifact_drift_report_from_default_location;

fn main() -> ExitCode {
    let report = match artifact_drift_report_from_default_location() {
        Ok(Some(report)) => report,
        Ok(None) => {
            eprintln!(
                "no spec artifact bundle found; set COKRET_SPEC_ARTIFACTS or check out \
                 ../cokret-spec/spec/v1/artifacts/ alongside this repo"
            );
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("failed to load spec artifact bundle: {err}");
            return ExitCode::from(2);
        }
    };

    let mut hard = false;
    if !report.missing_schemas.is_empty() {
        hard = true;
        println!("missing schemas (declared by SDK, absent from spec):");
        for entry in &report.missing_schemas {
            println!("  {entry}");
        }
    }
    if !report.missing_event_kinds.is_empty() {
        hard = true;
        println!("missing event kinds (declared by SDK, absent from spec):");
        for entry in &report.missing_event_kinds {
            println!("  {entry}");
        }
    }
    if !report.missing_operations.is_empty() {
        hard = true;
        println!("missing service operations (declared by SDK, absent from spec):");
        for entry in &report.missing_operations {
            println!("  {entry}");
        }
    }
    if !report.missing_id_kinds.is_empty() {
        hard = true;
        println!("missing typed ID kinds (declared by SDK, absent from spec):");
        for entry in &report.missing_id_kinds {
            println!("  {entry}");
        }
    }
    if !report.missing_special_form_id_kinds.is_empty() {
        hard = true;
        println!("missing special-form ID kinds (declared by SDK, absent from spec):");
        for entry in &report.missing_special_form_id_kinds {
            println!("  {entry}");
        }
    }

    if !report.unlisted_schemas.is_empty() {
        hard = true;
        println!("unlisted schemas (active in spec, absent from SDK):");
        for entry in &report.unlisted_schemas {
            println!("  {entry}");
        }
    }
    if !report.unlisted_event_kinds.is_empty() {
        hard = true;
        println!("unlisted event kinds (active in spec, absent from SDK):");
        for entry in &report.unlisted_event_kinds {
            println!("  {entry}");
        }
    }
    if !report.unlisted_operations.is_empty() {
        hard = true;
        println!("unlisted service operations (active in spec, absent from SDK):");
        for entry in &report.unlisted_operations {
            println!("  {entry}");
        }
    }
    if !report.unlisted_id_kinds.is_empty() {
        hard = true;
        println!("unlisted typed ID kinds (active in spec, absent from SDK):");
        for entry in &report.unlisted_id_kinds {
            println!("  {entry}");
        }
    }
    if !report.unlisted_special_form_id_kinds.is_empty() {
        hard = true;
        println!("unlisted special-form ID kinds (active in spec, absent from SDK):");
        for entry in &report.unlisted_special_form_id_kinds {
            println!("  {entry}");
        }
    }

    if hard {
        eprintln!(
            "drift detected - update ARTIFACT_BACKED_* in crates/core/src/schema/artifacts.rs"
        );
        return ExitCode::from(1);
    }
    println!(
        "no drift detected ({} files checked)",
        report.checked_files.len()
    );
    ExitCode::SUCCESS
}
