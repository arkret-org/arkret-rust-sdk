import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("closed_models", ROOT / "generate-closed-models.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ClosedModelsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.schema = {
            "type": "object", "additionalProperties": False,
            "required": ["second"],
            "properties": {"second": {"type": "boolean"}, "first": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
        }
        self.bindings = {"version": 1, "references": {}, "families": [{"output": "out.rs", "types": [{"name": "Example", "schema": "example.schema.json"}]}]}

    def generate(self):
        (self.root / "example.schema.json").write_text(json.dumps(self.schema), encoding="utf-8")
        return module.Generator(self.root, self.bindings).generate()["out.rs"]

    def test_field_order_presence_and_default_annotations(self):
        output = self.generate()
        self.assertLess(output.index("pub second"), output.index("pub first"))
        self.assertIn("pub first: Option<u8>", output)
        self.assertIn("deserialize_non_null_optional", output)
        self.assertNotIn("= 20", output)
        self.assertIn("sha256=", output)

    def test_rejects_unknown_structural_composition(self):
        for keyword, value in (("oneOf", []), ("allOf", []), ("patternProperties", {}), ("dependentSchemas", {})):
            with self.subTest(keyword=keyword):
                original = copy.deepcopy(self.schema)
                self.schema[keyword] = value
                with self.assertRaises(ValueError):
                    self.generate()
                self.schema = original

    def test_rejects_unbound_refs_nullable_and_open_objects(self):
        for shape in ({"$ref": "other.schema.json"}, {"type": ["string", "null"]}, {"type": "object"}):
            self.schema["properties"]["first"] = shape
            with self.assertRaises(ValueError):
                self.generate()
        self.schema["additionalProperties"] = True
        with self.assertRaises(ValueError):
            self.generate()

    def test_rejects_derived_inputs_and_path_escape(self):
        self.schema["source_of_truth"] = False
        with self.assertRaises(ValueError):
            self.generate()

    def test_union_requires_disjoint_closed_required_kind(self):
        self.schema = {"oneOf": [{"$ref": "#/$defs/left"}, {"$ref": "#/$defs/right"}], "$defs": {}}
        for name in ("left", "right"):
            self.schema["$defs"][name] = {"type": "object", "additionalProperties": False, "required": ["kind"], "properties": {"kind": {"const": name}}}
            self.bindings["references"][f"example.schema.json#/$defs/{name}"] = name.title()
        output = self.generate()
        self.assertIn("Left(Left)", output)
        self.assertIn("Right(Right)", output)
        for change in ("duplicate_kind", "optional_kind", "open_branch"):
            original = copy.deepcopy(self.schema)
            if change == "duplicate_kind":
                self.schema["$defs"]["right"]["properties"]["kind"]["const"] = "left"
            elif change == "optional_kind":
                self.schema["$defs"]["right"]["required"] = []
            else:
                self.schema["$defs"]["right"]["additionalProperties"] = True
            with self.assertRaises(ValueError):
                self.generate()
            self.schema = original
        self.bindings["families"][0]["types"][0]["schema"] = "../example.schema.json"
        with self.assertRaises(ValueError):
            self.generate()


if __name__ == "__main__":
    unittest.main()
