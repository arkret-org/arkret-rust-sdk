import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).with_name("check-spec-generation-inputs.py")
SPEC = importlib.util.spec_from_file_location("check_spec_generation_inputs", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GenerationInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "registry").mkdir()
        self.manifest = self.root / "sdk-manifest.json"
        self.registry_manifest = self.root / "registry/registry-manifest.json"
        self.registry_input = self.root / "registry/canonical.json"
        self.write_json(self.registry_input, {"source_of_truth": True})
        self.write_json(
            self.registry_manifest,
            {
                "source_of_truth": True,
                "registries": [
                    {
                        "file": "registry/canonical.json",
                        "source_role": "canonical",
                        "source_of_truth": True,
                    }
                ],
            },
        )
        self.write_json(self.manifest, {"entries": [{"artifacts": ["registry/canonical.json"]}]})

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def check(self):
        MODULE.check_inputs(self.root, self.manifest)

    def test_canonical_registry_is_accepted(self):
        self.check()

    def test_derived_registry_role_is_rejected(self):
        value = json.loads(self.registry_manifest.read_text())
        value["registries"][0]["source_role"] = "generated"
        self.write_json(self.registry_manifest, value)
        with self.assertRaisesRegex(ValueError, "derived registry"):
            self.check()

    def test_derived_artifact_flag_is_rejected(self):
        self.write_json(self.registry_input, {"source_of_truth": False})
        with self.assertRaisesRegex(ValueError, "derived artifact"):
            self.check()

    def test_unregistered_registry_is_rejected(self):
        value = json.loads(self.registry_manifest.read_text())
        value["registries"] = []
        self.write_json(self.registry_manifest, value)
        with self.assertRaisesRegex(ValueError, "unregistered registry"):
            self.check()

    def test_unmatched_or_escaping_input_is_rejected(self):
        for path, reason in (("registry/missing.json", "matches no file"), ("../outside.json", "escapes artifacts root")):
            with self.subTest(path=path):
                self.write_json(self.manifest, {"entries": [{"artifacts": [path]}]})
                with self.assertRaisesRegex(ValueError, reason):
                    self.check()


if __name__ == "__main__":
    unittest.main()
