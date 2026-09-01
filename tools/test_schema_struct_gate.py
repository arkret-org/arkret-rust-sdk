import json
import tempfile
import unittest
from pathlib import Path

from tools.schema_struct_gate import validate


class SchemaStructGateTests(unittest.TestCase):
    def fixture(
        self,
        rust_field: str = "recovery_keys",
        registered: bool = True,
        flattened: bool = False,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates" / "models" / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            flatten_field = (
                "    #[serde(flatten)]\n"
                "    pub extra: std::collections::BTreeMap<String, serde_json::Value>,\n"
                if flattened
                else ""
            )
            source.write_text(
                f'''/// Counterpart for `example.schema.json#/$defs/payload`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Payload {{
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub {rust_field}: Vec<String>,
    #[serde(rename = "created_at")]
    pub created: String,
{flatten_field}
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
                                    **(
                                        {
                                            "comparison": "rust_fields_subset",
                                            "reason": (
                                                "serde(flatten) carries schema-only fields while "
                                                "declared Rust fields remain checked."
                                            ),
                                        }
                                        if flattened
                                        else {}
                                    ),
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

    def test_flattened_struct_allows_schema_only_fields(self) -> None:
        self.assertEqual(self.fixture(flattened=True), [])

    def test_flattened_struct_rust_only_mutation_fails(self) -> None:
        errors = self.fixture("ghost_field", flattened=True)
        self.assertTrue(
            any("Rust-only=['ghost_field']" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
