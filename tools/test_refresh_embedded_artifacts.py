import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("refresh-embedded-artifacts.py")
SPEC = importlib.util.spec_from_file_location("refresh_embedded_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EmbeddedArtifactGeneratorTests(unittest.TestCase):
    def test_number_lexemes_are_preserved(self) -> None:
        raw = '{ "float": 1.0, "integer": 1, "exponent": 1e0 }\n'
        self.assertEqual(
            MODULE.minify_json_preserving_number_lexemes(raw),
            '{"float":1.0,"integer":1,"exponent":1e0}',
        )

    def test_snapshot_is_path_sorted_and_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.json").write_text('{"n":1.0}\n', encoding="utf-8")
            (root / "a.json").write_text('{"n":1}\n', encoding="utf-8")
            snapshot = MODULE.build_snapshot(root)
            self.assertLess(snapshot.index('"a.json"'), snapshot.index('"z.json"'))
            self.assertIn('"z.json":{"n":1.0}', snapshot)
            self.assertEqual(json.loads(snapshot)["z.json"]["n"], 1.0)

    def test_manifest_binds_relative_source_tree_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "openapi").mkdir()
            (root / "z.json").write_text('{"n":1.0}\n', encoding="utf-8")
            (root / "a.json").write_text('{"n":1}\n', encoding="utf-8")
            openapi = "openapi: 3.1.0\n"
            snapshot = MODULE.build_snapshot(root)
            manifest = json.loads(MODULE.build_manifest(root, snapshot, openapi))

            self.assertEqual(manifest["source"]["root"], "spec/v1/artifacts")
            self.assertEqual(manifest["source"]["json_file_count"], 2)
            self.assertRegex(
                manifest["source"]["json_tree_digest"], r"^sha256:[0-9a-f]{64}$"
            )
            self.assertEqual(
                manifest["outputs"][MODULE.TARGET.name],
                MODULE.sha256_digest(snapshot.encode("utf-8")),
            )
            self.assertNotIn(temporary, json.dumps(manifest))

            first_digest = manifest["source"]["json_tree_digest"]
            (root / "a.json").write_text('{"n":2}\n', encoding="utf-8")
            changed = json.loads(MODULE.build_manifest(root, MODULE.build_snapshot(root), openapi))
            self.assertNotEqual(changed["source"]["json_tree_digest"], first_digest)


if __name__ == "__main__":
    unittest.main()
