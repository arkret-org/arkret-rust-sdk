import tempfile
import unittest
from pathlib import Path

from identity_type_audit import SchemaResolver, scan_source_file, validate


class IdentityTypeAuditTests(unittest.TestCase):
    def test_core_schema_rejects_did_rust_field(self) -> None:
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
    pub actor_id: Did,
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

    def test_did_schema_accepts_did_and_rejects_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                """{
  "$defs": {
    "did": {"type": "string", "pattern": "^did:"},
    "resolution": {
      "type": "object",
      "properties": {
        "did": {"$ref": "#/$defs/did"}
      }
    }
  }
}
""",
                encoding="utf-8",
            )
            valid = root / "valid.rs"
            valid.write_text(
                """/// `example.schema.json#/$defs/resolution`
pub struct Resolution {
    pub did: Did,
}
""",
                encoding="utf-8",
            )
            invalid = root / "invalid.rs"
            invalid.write_text(
                """/// `example.schema.json#/$defs/resolution`
pub struct Resolution {
    pub did: DidCoreId,
}
""",
                encoding="utf-8",
            )
            resolver = SchemaResolver(schemas)
            valid_errors = validate(scan_source_file(valid, root), resolver)
            invalid_errors = validate(scan_source_file(invalid, root), resolver)

        self.assertEqual(valid_errors, [])
        self.assertEqual(len(invalid_errors), 1)
        self.assertIn("requires did (Did)", invalid_errors[0])


if __name__ == "__main__":
    unittest.main()
