import tempfile
import unittest
from pathlib import Path

from identity_type_audit import SchemaResolver, scan_source_file, validate


class IdentityTypeAuditTests(unittest.TestCase):
    def test_core_schema_rejects_full_did_rust_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                """{
  "$defs": {
    "did_core_id": {"type": "string", "pattern": "^ak:did_core:"},
    "claim_issuer": {
      "type": "object",
      "properties": {
        "actor_id": {"$ref": "#/$defs/did_core_id"}
      }
    }
  }
}
""",
                encoding="utf-8",
            )
            source = root / "lib.rs"
            source.write_text(
                """/// `example.schema.json#/$defs/claim_issuer`
pub struct ClaimIssuer {
    pub actor_id: DidFullId,
}
""",
                encoding="utf-8",
            )
            fields = scan_source_file(source, root)
            errors = validate(fields, SchemaResolver(schemas))

        self.assertEqual(len(errors), 1)
        self.assertIn("requires core (DidCoreId)", errors[0])

    def test_core_schema_accepts_did_core_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                """{
  "$defs": {
    "did_core_id": {"type": "string"},
    "claim_issuer": {
      "type": "object",
      "properties": {
        "actor_id": {"$ref": "#/$defs/did_core_id"}
      }
    }
  }
}
""",
                encoding="utf-8",
            )
            source = root / "lib.rs"
            source.write_text(
                """/// `example.schema.json#/$defs/claim_issuer`
pub struct ClaimIssuer {
    pub actor_id: DidCoreId,
}
""",
                encoding="utf-8",
            )
            fields = scan_source_file(source, root)
            errors = validate(fields, SchemaResolver(schemas))

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
