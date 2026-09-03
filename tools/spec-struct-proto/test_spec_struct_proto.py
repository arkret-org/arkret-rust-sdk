#!/usr/bin/env python3
"""Self-checks for the feasibility prototype.

These guard the two parsing steps whose failures are silent: a mis-parsed Rust
field would fabricate drift, and a mis-keyed inline pointer would make the
generator invent a type where the crate already names one.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_model  # noqa: E402
from generate import child_pointer, sanitize_ident, variant_ident  # noqa: E402


def _parse_text(source: str) -> rust_model.RustType:
    import tempfile

    root = Path(tempfile.mkdtemp())
    target = root / "crates" / "x" / "src"
    target.mkdir(parents=True)
    file = target / "lib.rs"
    file.write_text(source, encoding="utf-8")
    return rust_model.parse_file(file, root)[0]


def test_field_type_survives_a_doc_comment_naming_the_field() -> None:
    item = _parse_text(
        """
#[derive(Serialize, Deserialize)]
pub struct Sample {
    /// claimed_profiles is documented here and must not be mistaken for the type.
    #[serde(default)]
    pub claimed_profiles: Vec<Entry>,
}
"""
    )
    assert [f.rust_type for f in item.fields] == ["Vec<Entry>"]


def test_rename_all_snake_case_lowers_variant_names() -> None:
    item = _parse_text(
        """
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    MatrixPassthrough,
    MimiPassthrough,
}
"""
    )
    assert [v.wire_name for v in item.variants] == [
        "matrix_passthrough",
        "mimi_passthrough",
    ]


def test_explicit_rename_wins_over_rename_all() -> None:
    item = _parse_text(
        """
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[serde(rename = "ristretto255-SHA512")]
    Ristretto255Sha512,
}
"""
    )
    assert [v.wire_name for v in item.variants] == ["ristretto255-SHA512"]


def test_struct_level_serde_flags_are_read() -> None:
    item = _parse_text(
        """
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closed {
    pub a: String,
}
"""
    )
    assert item.deny_unknown_fields is True
    assert item.is_serde is True


def test_untagged_enum_is_detected() -> None:
    item = _parse_text(
        """
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Either {
    Left(A),
    Right(u64),
}
"""
    )
    assert item.untagged is True
    assert [v.payload for v in item.variants] == ["tuple", "tuple"]


def test_child_pointer_opens_a_fragment_when_there_is_none() -> None:
    assert child_pointer("a.schema.json", "/properties/x") == (
        "a.schema.json#/properties/x"
    )
    assert child_pointer("a.schema.json#/$defs/y", "/properties/x") == (
        "a.schema.json#/$defs/y/properties/x"
    )


def test_identifier_sanitising() -> None:
    assert sanitize_ident("type") == ("r#type", True)
    assert sanitize_ident("handle") == ("handle", False)
    assert variant_ident("2000+") == "V2000"
    assert variant_ident("ristretto255-SHA512") == "Ristretto255SHA512"


if __name__ == "__main__":
    failures = 0
    for name, function in sorted(globals().items()):
        if not name.startswith("test_") or not callable(function):
            continue
        try:
            function()
        except AssertionError as error:  # noqa: PERF203 - a tiny runner
            failures += 1
            print(f"FAIL {name}: {error}")
        else:
            print(f"ok   {name}")
    raise SystemExit(1 if failures else 0)
