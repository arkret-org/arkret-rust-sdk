import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_ARTIFACTS = REPO_ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts"
MODULE_PATH = REPO_ROOT / "tools" / "generate-registry-types.py"
SPEC = importlib.util.spec_from_file_location("generate_registry_types", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class RegistryGeneratorTests(unittest.TestCase):
    def registry_fixture(self, names: list[str]) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        artifacts = Path(temporary.name)
        registry = artifacts / "registry"
        registry.mkdir()
        for name in names:
            shutil.copy2(SPEC_ARTIFACTS / "registry" / name, registry / name)
        return temporary, artifacts

    def test_operation_error_mapping_rejects_incomplete_coverage(self) -> None:
        temporary, artifacts = self.registry_fixture(
            [
                "operation-registry.json",
                "operations-error-mapping.json",
                "error-code-registry.json",
            ]
        )
        with temporary:
            path = artifacts / "registry" / "operations-error-mapping.json"
            mapping = json.loads(path.read_text(encoding="utf-8"))
            mapping["operations"].pop()
            path.write_text(json.dumps(mapping), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                GENERATOR.generate_operation_error_mappings(artifacts)

    def test_operation_error_mapping_rejects_unknown_error(self) -> None:
        temporary, artifacts = self.registry_fixture(
            [
                "operation-registry.json",
                "operations-error-mapping.json",
                "error-code-registry.json",
            ]
        )
        with temporary:
            path = artifacts / "registry" / "operations-error-mapping.json"
            mapping = json.loads(path.read_text(encoding="utf-8"))
            mapping["operations"][0]["operation_specific"].append("injected_unknown")
            path.write_text(json.dumps(mapping), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unknown errors"):
                GENERATOR.generate_operation_error_mappings(artifacts)

    def test_closed_registry_output_contains_the_complete_current_sets(self) -> None:
        temporary, artifacts = self.registry_fixture(
            [
                "track-name-registry.json",
                "binding-kind-registry.json",
                "authority-set-policy-registry.json",
            ]
        )
        with temporary:
            generated = GENERATOR.generate_closed_registry_types(artifacts)

        self.assertIn("Self::Synthesis", generated)
        self.assertIn("Self::Websocket", generated)
        self.assertIn("Self::RealmAdmission", generated)


if __name__ == "__main__":
    unittest.main()
