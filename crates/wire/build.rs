use std::path::{Path, PathBuf};
use std::{env, fs};

use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("arkret-wire must live under <workspace>/crates/wire");

    let mut files = Vec::new();
    for name in ["Cargo.toml", "Cargo.lock"] {
        let path = workspace_root.join(name);
        if path.is_file() {
            files.push(path);
        }
    }
    collect_contract_sources(&workspace_root.join("crates"), &mut files);
    files.sort();

    let mut digest = Sha256::new();
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let relative = path
            .strip_prefix(workspace_root)
            .expect("SDK source must be inside the workspace");
        let relative = relative.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(&path).expect("SDK source must be readable");
        digest.update(relative.as_bytes());
        digest.update([0]);
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }

    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=ARKRET_SDK_SOURCE_SHA256={digest}");
}

fn collect_contract_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut entries = fs::read_dir(directory)
        .expect("SDK source directory must be readable")
        .map(|entry| entry.expect("SDK source entry must be readable").path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_contract_sources(&path, files);
            continue;
        }
        let include = path.file_name().is_some_and(|name| name == "Cargo.toml")
            || path.extension().is_some_and(|extension| extension == "rs");
        if include {
            files.push(path);
        }
    }
}
