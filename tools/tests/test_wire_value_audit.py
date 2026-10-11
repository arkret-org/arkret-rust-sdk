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

    def test_index_comparison_is_not_a_mutation(self) -> None:
        source = 'row["value"] == expected; row["kind"] => arm; row["body"] = replacement;'
        self.assertEqual(
            [(operation, field) for _, operation, field in AUDIT.mutation_evidence(source)],
            [("index_assign", "body")],
        )

    def test_nested_generic_functions_own_their_mutations(self) -> None:
        source = textwrap.dedent(
            """
            fn serialize<S>(serializer: S) {}
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) {
                object.remove("value");
            }
            fn project<T: Into<Vec<String>>>(kind: &str, payload: &Value) {}
            fn declaration<T>();
            fn after(kind: &str, payload: &Value) {}
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "generic.rs"
            path.write_text(source, encoding="utf-8")
            findings = AUDIT.scan_dynamic_file(path, root, "fixture")
        self.assertEqual(
            {finding.symbol for finding in findings if finding.category == "json_path_mutation"},
            {"deserialize"},
        )
        self.assertEqual(
            {finding.symbol for finding in findings if finding.category == "paired_api"},
            {"project", "after"},
        )

    def test_gitignored_generated_output_is_not_production_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "tools" / "spec-struct-proto" / "out"
            generated.mkdir(parents=True)
            (generated / "generated.rs").write_text("", encoding="utf-8")
            tracked = root / "tools" / "spec-struct-proto" / "src"
            tracked.mkdir(parents=True)
            (tracked / "tracked.rs").write_text("", encoding="utf-8")
            found = {
                path.relative_to(root).as_posix()
                for path in AUDIT.production_rust_files(root)
            }
        self.assertEqual(found, {"tools/spec-struct-proto/src/tracked.rs"})

    def test_cfg_test_module_declarations_are_not_production_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src"
            (source / "support" / "nested").mkdir(parents=True)
            (source / "runtime").mkdir()
            (source / "lib.rs").write_text(
                textwrap.dedent(
                    """
                    pub mod runtime;
                    /// Shared fixtures.
                    #[cfg(test)]
                    pub(crate) mod support;
                    #[cfg(not(test))]
                    mod shipped;
                    """
                ),
                encoding="utf-8",
            )
            (source / "shipped.rs").write_text("", encoding="utf-8")
            (source / "support" / "mod.rs").write_text("", encoding="utf-8")
            (source / "support" / "nested" / "deep.rs").write_text("", encoding="utf-8")
            (source / "runtime.rs").write_text("#[cfg(test)]\nmod fixture;\n", encoding="utf-8")
            (source / "runtime" / "fixture.rs").write_text("", encoding="utf-8")
            found = {
                path.relative_to(root).as_posix()
                for path in AUDIT.production_rust_files(root)
            }
        self.assertEqual(found, {"src/lib.rs", "src/runtime.rs", "src/shipped.rs"})


if __name__ == "__main__":
    unittest.main()
