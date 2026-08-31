mod lattice_contracts;
mod model;
mod openapi;
mod registry_types;
mod render;
mod runtime_contracts;

use std::path::PathBuf;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use model::SpecInputs;

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let mut artifacts_dir = None;
    let mut output_root = None;
    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "--artifacts-dir" => artifacts_dir = args.next().map(PathBuf::from),
            "--output-root" => output_root = args.next().map(PathBuf::from),
            unknown => bail!("unknown argument: {unknown}"),
        }
    }
    let artifacts_dir = artifacts_dir.context("--artifacts-dir is required")?;
    let output_root = output_root.context("--output-root is required")?;
    let inputs = SpecInputs::load(&artifacts_dir)?;
    let mut outputs = runtime_contracts::generate(&inputs)?;
    outputs.push(lattice_contracts::generate(&inputs)?);
    outputs.extend(registry_types::generate(&artifacts_dir)?);
    outputs.push(openapi::generate(&artifacts_dir)?);
    for output in outputs {
        let path = output_root.join(output.relative_path);
        fs::create_dir_all(path.parent().context("generated output has no parent")?)
            .with_context(|| format!("create {}", path.display()))?;
        fs::write(&path, output.contents).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}
