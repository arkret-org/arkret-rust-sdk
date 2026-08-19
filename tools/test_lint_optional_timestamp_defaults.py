#!/usr/bin/env python3
"""Self-test for `tools/lint-optional-timestamp-defaults.py`.

Covers the shapes that really occur in the tree: stacked single-line
attributes, combined and multi-line serde blocks, enum-variant fields,
container-level defaults, one-way signing transcripts, and adapter path
mentions in plain code.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "lint-optional-timestamp-defaults.py"
SPEC = importlib.util.spec_from_file_location("lint_optional_timestamp_defaults", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LINT = importlib.util.module_from_spec(SPEC)
# dataclasses resolve __module__ through sys.modules on Python 3.14+.
sys.modules[SPEC.name] = LINT
SPEC.loader.exec_module(LINT)

MISSING_DEFAULT = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}
"""

WITH_DEFAULT = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}
"""


class OptionalTimestampDefaultGateTests(unittest.TestCase):
    def scan(
        self,
        sources: dict[str, str],
        entries: list[dict[str, str]],
    ) -> int:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "some-repo"
            for relative, text in sources.items():
                path = root / "crates" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            allowlist_path = Path(directory) / "allowlist.json"
            allowlist_path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
            parsed = LINT.argparse.Namespace(root=root, allowlist=allowlist_path)
            original = LINT.argparse.ArgumentParser.parse_args
            LINT.argparse.ArgumentParser.parse_args = lambda self, *a, **k: parsed  # type: ignore[assignment]
            try:
                return LINT.main()
            finally:
                LINT.argparse.ArgumentParser.parse_args = original  # type: ignore[assignment]

    def allowlist_entry(self) -> dict[str, str]:
        return {
            "file": "crates/models/src/record.rs",
            "type": "Record",
            "field": "expires_at",
            "reason": "Schema-required field kept fail-closed per spec.",
        }

    def test_flags_triple_without_default(self) -> None:
        self.assertEqual(self.scan({"models/src/record.rs": MISSING_DEFAULT}, []), 1)

    def test_accepts_triple_with_default(self) -> None:
        self.assertEqual(self.scan({"models/src/record.rs": WITH_DEFAULT}, []), 0)

    def test_accepts_combined_attribute_form(self) -> None:
        source = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 0)

    def test_multiline_default_attr_above_adapter_counts(self) -> None:
        source = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 0)

    def test_container_level_default_covers_field(self) -> None:
        source = """\
/// Doc comment between the struct attributes and the field group.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    /// Field doc comment must not sever the attribute group.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 0)

    def test_flags_enum_variant_field(self) -> None:
        source = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    Temporal {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
        not_before: Option<DateTime<Utc>>,
    },
}
"""
        self.assertEqual(self.scan({"models/src/constraint.rs": source}, []), 1)

    def test_ignores_serialize_only_transcript(self) -> None:
        source = """\
#[derive(Debug, Serialize)]
struct Transcript<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
    marker: &'a str,
}
"""
        self.assertEqual(self.scan({"models/src/transcript.rs": source}, []), 0)

    def test_ignores_adapter_path_in_plain_code(self) -> None:
        source = """\
fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    arkret_canonical::serde_helpers::optional_canonical_timestamp::deserialize(deserializer)
}
"""
        self.assertEqual(self.scan({"models/src/helper.rs": source}, []), 0)

    def test_ignores_field_without_skip_serializing_if(self) -> None:
        source = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub completed_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 0)

    def test_ignores_cfg_test_code(self) -> None:
        source = WITH_DEFAULT + """\
#[cfg(test)]
mod tests {
    #[derive(Serialize, Deserialize)]
    struct Fixture {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
        expires_at: Option<DateTime<Utc>>,
    }
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 0)

    def test_allowlisted_violation_passes(self) -> None:
        self.assertEqual(
            self.scan(
                {"models/src/record.rs": MISSING_DEFAULT},
                [self.allowlist_entry()],
            ),
            0,
        )

    def test_allowlist_entry_without_reason_fails(self) -> None:
        entry = self.allowlist_entry()
        entry["reason"] = "  "
        self.assertEqual(
            self.scan({"models/src/record.rs": MISSING_DEFAULT}, [entry]),
            1,
        )

    def test_stale_allowlist_entry_fails(self) -> None:
        self.assertEqual(
            self.scan(
                {"models/src/record.rs": WITH_DEFAULT},
                [self.allowlist_entry()],
            ),
            1,
        )

    def test_flags_split_pair_without_default(self) -> None:
        source = """\
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/record.rs": source}, []), 1)

    def test_flags_serialize_with_on_deserializable_type(self) -> None:
        source = """\
use arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<DateTime<Utc>>,
}
"""
        self.assertEqual(self.scan({"models/src/payload.rs": source}, []), 1)

    def test_unqualified_adapter_form_is_scanned(self) -> None:
        source = """\
use arkret_canonical::serde_helpers::optional_canonical_timestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Binding {
    Claim {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "optional_canonical_timestamp")]
        resolved_at: Option<DateTime<Utc>>,
    },
}
"""
        self.assertEqual(self.scan({"models/src/binding.rs": source}, []), 1)


if __name__ == "__main__":
    unittest.main()
