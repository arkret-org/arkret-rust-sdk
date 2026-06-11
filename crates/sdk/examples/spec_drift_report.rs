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
//! * **hard drift** (`missing_*`) — the SDK declares coverage for an entry the spec no longer
//!   ships. Exits non-zero so CI fails fast.
//! * **soft drift** (`unlisted_event_kinds`) — the spec ships an active entry the SDK has not yet
//!   declared coverage for. Reported as informational output; exits zero so CI doesn't block on
//!   intentional gaps.
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

    if report.has_unlisted() {
        println!(
            "soft drift — {} active event kind(s) shipped by spec, not yet declared by SDK:",
            report.unlisted_event_kinds.len()
        );
        for entry in &report.unlisted_event_kinds {
            println!("  {entry}");
        }
    }

    if hard {
        eprintln!("hard drift detected — update ARTIFACT_BACKED_* in crates/core/src/schema.rs");
        return ExitCode::from(1);
    }
    if !report.has_unlisted() {
        println!(
            "no drift detected ({} files checked)",
            report.checked_files.len()
        );
    }
    ExitCode::SUCCESS
}
