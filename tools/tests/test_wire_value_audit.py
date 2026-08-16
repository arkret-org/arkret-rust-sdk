import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "wire_value_audit.py"
SPEC = importlib.util.spec_from_file_location("wire_value_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class WireValueAuditTests(unittest.TestCase):
    def test_restricted_visibility_functions_use_parameter_parenthesis(self) -> None:
        source = textwrap.dedent(
            """
            use serde_json::Value;

            pub(super) fn validate_super(kind: &str, payload: &Value) {}
            pub(crate) fn validate_crate(kind: &str, payload: &Value) {}
            pub(in crate::nested) fn validate_in(kind: &str, payload: &Value) {}
            pub(crate) fn context_is_not_a_discriminator(state: &AppState, payload: &Value) {}
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            repository_root = Path(temporary)
            path = repository_root / "visibility.rs"
            path.write_text(source, encoding="utf-8")
            findings = AUDIT.scan_dynamic_file(path, repository_root, "fixture")

        paired_symbols = {
            finding.symbol
            for finding in findings
            if finding.category == "paired_api"
        }
        self.assertEqual(
            paired_symbols,
            {"validate_super", "validate_crate", "validate_in"},
        )


if __name__ == "__main__":
    unittest.main()
