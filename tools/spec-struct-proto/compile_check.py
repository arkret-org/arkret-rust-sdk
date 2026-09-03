#!/usr/bin/env python3
"""Compile the prototype's output in a throwaway crate.

Diffing proves the shapes line up; only rustc proves the emitted text is valid
Rust that serde can derive on. The crate is written to a temporary directory
with its own ``CARGO_TARGET_DIR`` so it never touches the workspace's shared
target, and it stubs every SDK newtype the generator referenced instead of
depending on the SDK (a path dependency would rebuild the workspace).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

GENERATED = Path(__file__).resolve().parent / "out" / "generated.rs"
KNOWN = {
    "String", "bool", "u8", "u16", "u32", "u64", "i32", "i64", "f64", "Value",
    "Vec", "Option", "BTreeMap", "BTreeSet", "DateTime", "Utc", "Self", "(", ")",
}
CARGO_TOML = """[package]
name = "spec-struct-proto-check"
version = "0.0.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }

[workspace]
"""
STUB_PRELUDE = """// Stand-ins for the SDK newtypes the generator binds to. Only their serde
// behaviour matters here: the point is to prove the generated declarations
// compile and derive, not to re-implement the identifier invariants.
pub mod arkret_canonical {
    pub mod serde_helpers {
        pub mod canonical_timestamp {
            use chrono::{DateTime, Utc};
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                value: &DateTime<Utc>,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&value.to_rfc3339())
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<DateTime<Utc>, D::Error> {
                let raw = String::deserialize(deserializer)?;
                raw.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
            }
        }

        pub mod optional_canonical_timestamp {
            use chrono::{DateTime, Utc};
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                value: &Option<DateTime<Utc>>,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                match value {
                    Some(inner) => serializer.serialize_str(&inner.to_rfc3339()),
                    None => serializer.serialize_none(),
                }
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Option<DateTime<Utc>>, D::Error> {
                let raw = Option::<String>::deserialize(deserializer)?;
                raw.map(|text| text.parse::<DateTime<Utc>>())
                    .transpose()
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}
"""


def referenced_types(source: str) -> set[str]:
    declared = set(re.findall(r"^pub (?:struct|enum) ([A-Za-z0-9_]+)", source, re.M))
    used: set[str] = set()
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped.startswith("pub ") or "struct" in stripped or "enum" in stripped:
            continue
        _, _, tail = stripped.partition(":")
        used.update(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", tail))
    for line in source.splitlines():
        match = re.match(r"\s{4}[A-Za-z0-9_]+\(([A-Za-z0-9_:<>, ]+)\),", line)
        if match:
            used.update(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", match.group(1)))
    return {name for name in used - declared - KNOWN}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", type=Path, default=GENERATED)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    source = args.generated.read_text(encoding="utf-8")
    # The generator emits SDK paths verbatim; here only the leaf name matters,
    # so flatten every qualified type onto the stub of the same name. The serde
    # helper module is the one path that must survive.
    qualified = re.compile(r"\b[a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)*::(?=[A-Z])")
    source = "\n".join(
        line
        if line.startswith("use ") or "#[serde(" in line
        else qualified.sub("", line)
        for line in source.splitlines()
    )
    stubs = sorted(referenced_types(source))
    stub_text = "\n".join(
        f"#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]\n"
        f"pub struct {name}(pub String);"
        for name in stubs
    )

    root = Path(tempfile.mkdtemp(prefix="spec-struct-proto-"))
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
    body = source.replace("#![allow(dead_code)]", "#![allow(dead_code)]\n")
    (root / "src" / "lib.rs").write_text(
        body + "\n" + STUB_PRELUDE + "\n" + stub_text + "\n", encoding="utf-8"
    )

    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = str(root / "target")
    completed = subprocess.run(
        ["cargo", "check", "--quiet", "--offline"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        completed = subprocess.run(
            ["cargo", "check", "--quiet"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
        )
    print(f"crate       : {root}")
    print(f"stubbed     : {len(stubs)} external types")
    print(f"exit status : {completed.returncode}")
    errors = [
        line
        for line in completed.stderr.splitlines()
        if line.startswith("error") or line.strip().startswith("--> ")
    ]
    for line in errors[:80]:
        print(line)
    if not args.keep and completed.returncode == 0:
        import shutil

        shutil.rmtree(root, ignore_errors=True)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
