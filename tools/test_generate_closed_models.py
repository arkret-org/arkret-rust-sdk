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

    def test_local_generated_references_do_not_keep_qualified_reexports(self):
        self.schema["properties"]["first"] = {"$ref": "#/$defs/child"}
        self.schema["$defs"] = {"child": {"const": "child"}}
        child_schema = "example.schema.json#/$defs/child"
        self.bindings["references"][child_schema] = "crate::example::Child"
        self.bindings["families"][0]["types"].append({"name": "Child", "schema": child_schema})
        output = self.generate()
        self.assertIn("pub first: Option<Child>", output)
        self.assertNotIn("Option<crate::example::Child>", output)

        self.bindings["families"][0]["types"].pop()
        output = self.generate()
        self.assertIn("pub first: Option<crate::example::Child>", output)

    def test_string_const_and_partial_equality_representation(self):
        self.schema = {"const": "holder_session"}
        row = self.bindings["families"][0]["types"][0]
        row["eq"] = False
        output = self.generate()
        self.assertIn('serde(rename = "holder_session")', output)
        self.assertIn("HolderSession,", output)
        self.assertIn("PartialEq, serde::Serialize", output)
        self.assertNotIn("PartialEq, Eq,", output)
        self.schema = {"const": 42}
        with self.assertRaisesRegex(ValueError, "unsupported enum"):
            self.generate()

    def representation(self):
        row = self.bindings["families"][0]["types"][0]
        row["rust"] = {"signature": "pub struct Example", "attributes": ['#[derive(serde::Serialize, serde::Deserialize)]', '#[serde(deny_unknown_fields)]'], "members": {
            "first": {"name": "first", "type": "Option<u32>", "visibility": "pub", "attributes": []},
            "second": {"name": "second", "type": "bool", "visibility": "pub", "attributes": ['#[serde(default)]']}}}
        self.bindings["families"][0]["inline"] = True
        return row["rust"]

    def test_representation_schema_owns_order_presence_and_member_set(self):
        rust = self.representation()
        output = self.generate()
        self.assertLess(output.index("pub second"), output.index("pub first"))
        self.assertNotIn("#[serde(default)]", output)
        self.assertIn("deserialize_non_null_optional", output)
        self.assertNotIn("//!", output)
        rust["members"]["invented"] = rust["members"]["first"]
        with self.assertRaisesRegex(ValueError, "member set drifted"):
            self.generate()

    def test_representation_required_nullable_rejects_absence(self):
        rust = self.representation()
        self.schema["required"].append("first")
        self.schema["properties"]["first"] = {"type": ["integer", "null"]}
        rust["members"]["first"]["attributes"] = ['#[serde(default)]']
        output = self.generate()
        self.assertIn("deserialize_required_nullable", output)
        self.assertNotIn("default", output)

    def test_representation_cannot_omit_a_required_member(self):
        rust = self.representation()
        self.schema["required"].append("first")
        self.schema["properties"]["first"] = {"type": ["integer", "null"]}
        rust["members"]["first"]["attributes"] = ['#[serde(skip_serializing_if = "Option::is_none")]']
        with self.assertRaisesRegex(ValueError, "required member cannot be omitted"):
            self.generate()

    def test_representation_enforces_schema_closedness_for_derived_decoder(self):
        rust = self.representation()
        rust["attributes"] = ['#[derive(serde::Serialize, serde::Deserialize)]']
        self.assertIn("#[serde(deny_unknown_fields)]", self.generate())

    def test_representation_free_json_and_nullable_union_keep_null(self):
        rust = self.representation()
        for shape in ({}, {"anyOf": [{"type": "string"}, {"type": "null"}]}):
            self.schema["properties"]["first"] = shape
            rust["members"]["first"]["type"] = "Option<serde_json::Value>"
            self.assertNotIn("deserialize_non_null_optional", self.generate())

    def test_representation_non_null_timestamp_keeps_canonical_adapter(self):
        rust = self.representation()
        self.schema["properties"]["first"] = {"type": "string"}
        rust["members"]["first"]["type"] = "Option<chrono::DateTime<chrono::Utc>>"
        rust["members"]["first"]["attributes"] = ['#[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]']
        output = self.generate()
        self.assertIn("deserialize_non_null_optional_timestamp", output)
        self.assertIn("serialize_optional_canonical_timestamp", output)

    def test_null_applicability_requires_exactly_one_union_branch(self):
        generator = module.Generator(self.root, self.bindings)
        for shape, expected in (
            (True, True), (False, False),
            ({"oneOf": [{}, {"type": "null"}]}, False),
            ({"oneOf": [{"type": "string"}, {"type": "null"}]}, True),
            ({"anyOf": [{}, {"type": "null"}]}, True),
            ({"not": {"const": None}}, False),
            ({"if": {"type": "null"}, "then": False, "else": True}, False),
            ({"if": {"type": "string"}, "then": False, "else": True}, True),
        ):
            with self.subTest(shape=shape):
                self.assertEqual(generator.nullable(shape, "example.schema.json"), expected)

    def test_null_applicability_retains_reference_siblings_and_rejects_cycles(self):
        (self.root / "target.schema.json").write_text('{}', encoding="utf-8")
        generator = module.Generator(self.root, self.bindings)
        self.assertFalse(generator.nullable(
            {"$ref": "target.schema.json", "not": {"const": None}}, "example.schema.json"))
        (self.root / "cycle.schema.json").write_text('{"$ref":"cycle.schema.json"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cyclic null applicability"):
            generator.nullable({"$ref": "cycle.schema.json"}, "example.schema.json")

    def test_representation_root_ref_and_composition_track_dependencies(self):
        self.representation()
        (self.root / "target.schema.json").write_text(json.dumps(self.schema), encoding="utf-8")
        self.schema = {"$ref": "target.schema.json"}
        output = self.generate()
        self.assertIn("Input: schemas/target.schema.json", output)
        self.assertIn("pub first", output)

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
