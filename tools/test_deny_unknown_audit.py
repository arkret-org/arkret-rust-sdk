import tempfile
import unittest
from pathlib import Path

from tools.deny_unknown_audit import scan_file


class DenyUnknownAuditTests(unittest.TestCase):
    def test_explicit_schema_pointer_above_pub_struct_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates" / "fixture" / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                """
/// Counterpart for
/// `spec/v1/artifacts/schemas/example.schema.json#/$defs/example_payload`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExamplePayload {
    pub value: String,
}
""".lstrip(),
                encoding="utf-8",
            )

            sites = scan_file(source, root)

        self.assertEqual(len(sites), 1)
        self.assertEqual(
            sites[0].spec_pointer,
            "example.schema.json#/$defs/example_payload",
        )


if __name__ == "__main__":
    unittest.main()
