import json
import tempfile
import unittest
from pathlib import Path

from tools.schema_struct_gate import validate


class SchemaStructGateTests(unittest.TestCase):
    def fixture(self, rust_field: str = "recovery_keys", registered: bool = True) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates" / "models" / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                f'''/// Counterpart for `example.schema.json#/$defs/payload`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Payload {{
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub {rust_field}: Vec<String>,
    #[serde(rename = "created_at")]
    pub created: String,
}}
''',
                encoding="utf-8",
            )
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                json.dumps(
                    {
                        "$defs": {
                            "payload": {
                                "allOf": [
                                    {"properties": {"created_at": {"type": "string"}}},
                                    {
                                        "oneOf": [
                                            {"properties": {"recovery_keys": {"type": "array"}}},
                                            {"properties": {"recovery_keys": {"type": "array"}}},
                                        ]
                                    },
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            registry = root / "registry.json"
            registry.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "mappings": (
                            [
                                {
                                    "rust_type": "crates/models/src/lib.rs::Payload",
                                    "schema": "example.schema.json#/$defs/payload",
                                }
                            ]
                            if registered
                            else []
                        ),
                        "exemptions": [],
                    }
                ),
                encoding="utf-8",
            )
            return validate(registry, schemas, root)

    def test_matching_composed_schema_passes(self) -> None:
        self.assertEqual(self.fixture(), [])

    def test_field_name_mutation_fails(self) -> None:
        errors = self.fixture("recovery_key_entries")
        self.assertTrue(any("field mismatch" in error for error in errors))

    def test_unregistered_counterpart_fails(self) -> None:
        errors = self.fixture(registered=False)
        self.assertTrue(any("unregistered schema counterpart" in error for error in errors))

    def flatten_fixture(self, declared_field: str) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates" / "models" / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                f'''/// Counterpart for `example.schema.json#/$defs/payload`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Payload {{
    pub {declared_field}: String,
    #[serde(flatten)]
    pub extra: ExtensionMap,
}}
''',
                encoding="utf-8",
            )
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                json.dumps(
                    {
                        "$defs": {
                            "payload": {
                                "properties": {
                                    "declared": {"type": "string"},
                                    "future": {"type": "string"},
                                }
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            registry = root / "registry.json"
            registry.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "mappings": [],
                        "exemptions": [
                            {
                                "rust_type": "crates/models/src/lib.rs::Payload",
                                "schema": "example.schema.json#/$defs/payload",
                                "reason": "serde flatten permits schema-only fields while declared fields remain checked",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            return validate(registry, schemas, root)

    def test_flatten_allows_schema_only_fields(self) -> None:
        self.assertEqual(self.flatten_fixture("declared"), [])

    def test_flatten_does_not_hide_rust_only_fields(self) -> None:
        errors = self.flatten_fixture("ghost")
        self.assertTrue(any("Rust-only=['ghost']" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
