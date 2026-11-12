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
from canonical_openapi import CanonicalClosure, SCHEMA_BASE, children, generate_bundle


class ClosedModelsTests(unittest.TestCase):
    def test_dotted_suite_constant_preserves_exact_wire_value(self):
        self.schema = {"type": "string", "const": "ak.hpke_x25519_aead_chacha20poly1305.v1"}
        output = self.generate()
        self.assertIn('serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")', output)
        self.assertIn("AkHpkeX25519AeadChacha20poly1305V1,", output)
        self.schema = {"type": "string", "enum": ["ak.suite", "ak_suite"]}
        with self.assertRaisesRegex(ValueError, "duplicate Rust variant"):
            self.generate()

    def test_manifest_provides_match_actual_generated_declarations(self):
        entry = {'generator': 'closed-models', 'outputs': ['out.rs'], 'provides': ['Example']}
        module.validate_manifest_provides(self.bindings, {'entries': [entry]})
        for declared in ([], ['RetiredAlias'], ['Example', 'RetiredAlias'], ['Example', 'Example']):
            with self.assertRaisesRegex(ValueError, 'provides differ'):
                module.validate_manifest_provides(self.bindings, {'entries': [{**entry, 'provides': declared}]})
        with self.assertRaisesRegex(ValueError, 'no output'):
            module.validate_manifest_provides(self.bindings, {'entries': [{**entry, 'outputs': []}]})

    def test_two_schema_types_cannot_collapse_to_one_rust_name(self):
        self.bindings['families'][0]['types'].append({
            'name': 'Example', 'schema': 'another.schema.json'})
        with self.assertRaisesRegex(ValueError, 'duplicate Rust type name'):
            self.generate()

    def test_representation_cannot_emit_a_stale_wire_member(self):
        self.bindings['families'][0]['types'][0]['rust'] = {
            'signature':'pub struct Example',
            'attributes':['#[derive(serde::Serialize, serde::Deserialize)]'],
            'members':{
                'second':{'name':'old_second','visibility':'pub','type':'bool','attributes':[]},
                'first':{'name':'first','visibility':'pub','type':'Option<u8>','attributes':[]},
            },
        }
        with self.assertRaisesRegex(ValueError,'different wire member'):
            self.generate()
        self.bindings['families'][0]['types'][0]['rust']['members']['second']['name']='second'
        self.assertIn('pub second: bool',self.generate())

    def test_an_outcome_cannot_hide_a_response_or_current_state(self):
        self.bindings['families'][0]['types'][0]['name']='ExampleOutcome'
        with self.assertRaisesRegex(ValueError,'settled processing role'):
            self.generate()

    def test_scoped_identifier_adapter_follows_refs_and_stricter_siblings(self):
        profile = {"$defs": {"bounded": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^(?!ak:)"}}}
        (self.root / "profiles.schema.json").write_text(json.dumps(profile), encoding="utf-8")
        ref = "profiles.schema.json#/$defs/bounded"
        self.bindings["references"][ref] = "String"
        self.schema["properties"]["second"] = {"$ref": ref, "maxLength": 64}
        self.schema["properties"]["first"] = {"$ref": ref}
        output = self.generate()
        self.assertIn("deserialize_focus_identifier", output)
        self.assertIn("deserialize_optional_bounded_non_typed_identifier", output)
        self.assertNotIn("deserialize_non_null_optional", output)

    def test_reviewed_namespaced_const_variant_keeps_exact_wire_literal(self):
        self.schema = {"const": "ak.schema.private_plaintext.v1"}
        self.bindings["families"][0]["types"][0]["variant_names"] = {"ak.schema.private_plaintext.v1": "V1"}
        output = self.generate()
        self.assertIn('#[serde(rename = "ak.schema.private_plaintext.v1")]', output)
        self.assertIn("    V1,", output)
        self.bindings["families"][0]["types"][0]["variant_names"] = {"ak.schema.private_plaintext.v1": "bad::variant"}
        with self.assertRaisesRegex(ValueError, "invalid reviewed Rust variant"):
            self.generate()

    def test_indirect_timestamp_reference_keeps_canonical_timestamp_adapter(self):
        (self.root / "time.schema.json").write_text(json.dumps({"$defs": {"timestamp": {"type": "string"}}}), encoding="utf-8")
        (self.root / "alias.schema.json").write_text(json.dumps({"$ref": "time.schema.json#/$defs/timestamp"}), encoding="utf-8")
        self.bindings["references"]["alias.schema.json"] = "chrono::DateTime<chrono::Utc>"
        self.schema["properties"]["second"] = {"$ref": "alias.schema.json"}
        output = self.generate()
        self.assertIn("::canonical_timestamp", output)

    def test_agent_key_profile_reference_selects_the_full_vocabulary_adapter(self):
        profile = {"$defs": {"agent_key_id": {"type": "string", "minLength": 1, "maxLength": 256,
            "pattern": r"^(?!ak:)(?:did:[a-z0-9]+:[^\s#]+#[^\s#]+|[a-zA-Z0-9._:-]{1,256})(?![\s\S])"}}}
        (self.root / "event-payload.schema.json").write_text(json.dumps(profile), encoding="utf-8")
        ref = "event-payload.schema.json#/$defs/agent_key_id"
        self.bindings["references"][ref] = "String"
        self.schema["properties"]["second"] = {"$ref": ref}
        self.schema["properties"]["first"] = {"$ref": ref}
        output = self.generate()
        self.assertIn("deserialize_agent_key_identifier", output)
        self.assertIn("deserialize_optional_agent_key_identifier", output)
        self.assertNotIn("deserialize_bounded_non_typed_identifier", output)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.schema = {
            "type": "object", "additionalProperties": False,
            "required": ["second"],
            "properties": {"second": {"type": "boolean"}, "first": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
        }
        self.bindings = {"references": {}, "families": [{"output": "out.rs", "types": [{"name": "Example", "schema": "example.schema.json"}]}]}

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

    def test_selected_output_matches_full_generation_including_provenance(self):
        full = self.generate()
        selected = module.Generator(self.root, self.bindings).generate({"out.rs"})
        self.assertEqual(selected, {"out.rs": full})

    def test_selected_output_does_not_generate_an_unrelated_missing_schema(self):
        self.generate()
        self.bindings["families"].append({"output": "other.rs", "types": [
            {"name": "Other", "schema": "unavailable.schema.json"}
        ]})
        selected = module.Generator(self.root, self.bindings).generate({"out.rs"})
        self.assertEqual(set(selected), {"out.rs"})
        self.assertIn("Bindings: tools/closed-model-bindings.json", selected["out.rs"])
        with self.assertRaises(FileNotFoundError):
            module.Generator(self.root, self.bindings).generate()

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

    def test_rejects_path_escape(self):
        with self.assertRaisesRegex(ValueError, "escapes root"):
            module.Generator(self.root, self.bindings).node("../outside.schema.json")

    def test_inline_state_union_requires_a_closed_distinct_required_discriminator(self):
        self.schema = {"oneOf": [
            {"type": "object", "additionalProperties": False, "required": ["state"],
             "properties": {"state": {"const": "never_written"}}},
            {"type": "object", "additionalProperties": False, "required": ["state", "revision"],
             "properties": {"state": {"const": "present"}, "revision": {"type": "string"}}},
        ]}
        output = self.generate()
        self.assertIn('serde(tag = "state", deny_unknown_fields)', output)
        self.assertIn('NeverWritten {', output)
        self.assertIn('revision: String', output)
        for change in ("duplicate", "optional", "open", "composition"):
            original = copy.deepcopy(self.schema)
            branch = self.schema["oneOf"][1]
            if change == "duplicate":
                branch["properties"]["state"]["const"] = "never_written"
            elif change == "optional":
                branch["required"] = ["revision"]
            elif change == "open":
                branch["additionalProperties"] = True
            else:
                branch["not"] = {}
            with self.assertRaises(ValueError):
                self.generate()
            self.schema = original

    def test_inline_finite_state_branch_preserves_all_tags_and_shared_fields(self):
        self.schema = {"oneOf": [
            {"type": "object", "additionalProperties": False, "required": ["state", "root"],
             "properties": {"state": {"const": "rekeyed"}, "root": {"type": "string"}}},
            {"type": "object", "additionalProperties": False, "required": ["state", "proof"],
             "properties": {"state": {"enum": ["removed", "terminated"]}, "proof": {"type": "string"}}},
        ]}
        output = self.generate()
        self.assertIn('Rekeyed {\n        root: String,', output)
        for tag in ("Removed", "Terminated"):
            self.assertIn(tag + ' {\n        proof: String,', output)
        self.assertNotIn('state:', output)
        original = copy.deepcopy(self.schema)
        for values in (["rekeyed", "removed"], ["removed", "removed"], [], ["removed", 7]):
            with self.subTest(values=values):
                self.schema = copy.deepcopy(original)
                self.schema["oneOf"][1]["properties"]["state"]["enum"] = values
                with self.assertRaises(ValueError):
                    self.generate()
        self.schema = copy.deepcopy(original)
        self.schema["oneOf"][1]["properties"]["state"]["enum"] = ["a_b", "aB"]
        with self.assertRaisesRegex(ValueError, "duplicate Rust variant"):
            self.generate()

    def test_conditional_state_union_cannot_mix_retirement_evidence(self):
        self.schema = {
            "type": "object", "additionalProperties": False,
            "required": ["state", "scope"],
            "properties": {
                "state": {"enum": ["removed", "terminated"]}, "scope": {"type": "string"},
                "absence": {"type": "string"}, "terminal": {"type": "string"},
            },
            "allOf": [{
                "if": {"properties": {"state": {"const": "removed"}}, "required": ["state"]},
                "then": {"required": ["absence"], "not": {"required": ["terminal"]}},
                "else": {"required": ["terminal"], "not": {"required": ["absence"]}},
            }],
        }
        self.schema["properties"]["epoch"] = {"$ref": "decimal-integers.schema.json#/$defs/uint64_decimal"}
        self.schema["required"].append("epoch")
        (self.root / "decimal-integers.schema.json").write_text(json.dumps({
            "$defs": {"uint64_decimal": {"type": "string"}}
        }), encoding="utf-8")
        output = self.generate()
        self.assertEqual(output.count('serde(with = "arkret_canonical::serde_helpers::uint64_decimal")'), 2)
        self.assertIn('Removed {\n        scope: String,\n        absence: String,', output)
        self.assertIn('Terminated {\n        scope: String,\n        terminal: String,', output)
        self.assertNotIn('Option<', output)
        original = copy.deepcopy(self.schema)
        for change in ("extra_field", "missing_forbidden", "overlapping_required", "wrong_tag", "root_constraint"):
            with self.subTest(change=change):
                self.schema = copy.deepcopy(original)
                if change == "extra_field":
                    self.schema["properties"]["unknown"] = {"type": "string"}
                elif change == "missing_forbidden":
                    self.schema["allOf"][0]["then"].pop("not")
                elif change == "overlapping_required":
                    self.schema["allOf"][0]["else"]["required"] = ["absence"]
                elif change == "wrong_tag":
                    self.schema["allOf"][0]["if"]["properties"]["state"]["const"] = "unregistered"
                else:
                    self.schema["not"] = {}
                with self.assertRaisesRegex(ValueError, 'unsupported object composition'):
                    self.generate()

    def test_named_inline_union_cannot_broaden_closed_branch_membership(self):
        self.schema = {"oneOf": [
            {"type": "object", "additionalProperties": False, "required": ["state"],
             "properties": {"state": {"const": "pending"}}},
            {"type": "object", "additionalProperties": False, "required": ["cleanup"],
             "properties": {"cleanup": {"type": "string"}}},
        ]}
        row = self.bindings["families"][0]["types"][0]
        row['branch_variants'] = ['Pending', 'Retired']
        # Named branches use real schema-pointer identities, never field lists
        # supplied by a Rust binding or a permissive serde_json::Value branch.
        for index, name in enumerate(['PendingBody', 'RetiredBody']):
            self.bindings['references'][f'example.schema.json#/oneOf/{index}'] = name
        output = self.generate()
        self.assertIn('Pending(PendingBody)', output)
        self.assertIn('Retired(RetiredBody)', output)
        self.schema['oneOf'][1]['required'] = []
        with self.assertRaisesRegex(ValueError, 'distinct closed required branch types'):
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


class CanonicalOpenApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, **schema):
        (self.root / name).write_text(json.dumps({"$id": SCHEMA_BASE + name, **schema}), encoding="utf-8")

    def test_cycles_boolean_anchors_ref_siblings_and_instance_data_are_preserved(self):
        self.write("a.json", properties={"next": {"$ref": "b.json#node", "not": False}},
                   examples=[{"$ref": "https://untrusted.invalid/data"}],
                   default={"$ref": "instance"}, **{"x-data": {"$ref": "literal"}})
        self.write("b.json", **{"$defs": {"node": {"$anchor": "node", "anyOf": [
            {"$ref": "a.json"}, True, False]}}})
        first = CanonicalClosure(self.root).build({"Root": "a.json"})
        self.assertEqual(first, CanonicalClosure(self.root).build({"Root": "a.json"}))
        self.assertEqual(len(first["components"]), 2)
        root = first["components"][first["roots"]["Root"]]
        self.assertEqual(root["examples"], [{"$ref": "https://untrusted.invalid/data"}])
        self.assertIs(root["properties"]["next"]["not"], False)
        self.assertEqual(root["default"], {"$ref": "instance"})
        self.assertEqual(root["x-data"], {"$ref": "literal"})
        self.assertTrue(root["properties"]["next"]["$ref"].startswith("#/components/schemas/"))

    def test_unregistered_authority_escapes_queries_and_invalid_fragments_are_refused(self):
        self.write("a.json", type="object")
        for reference in ["https://attacker.invalid/v1/schemas/a.json", "../a.json",
                          "a.json?query=1", "a.json?", SCHEMA_BASE + "a.json?", "a.json#missing", "a.json#/%GG",
                          "a.json#/~2", "a.json#/type", "https://arkret.org/v1/schemas/%2e%2e/a.json"]:
            with self.subTest(reference=reference), self.assertRaises((ValueError, KeyError)):
                closure = CanonicalClosure(self.root)
                closure.node(closure.target("a.json", reference))

    def test_unsupported_reference_scopes_fail_closed(self):
        for schema in [{"$dynamicRef": "#node"}, {"properties": {"x": {"$id": "nested"}}}]:
            self.write("a.json", **schema)
            with self.assertRaises(ValueError):
                CanonicalClosure(self.root).build({"Root": "a.json"})

    def test_strict_json_pointer_indices_and_raw_uri_control_are_rejected(self):
        self.write("a.json", allOf=[True, False], **{"$defs": {"C": {"const": 1}, "a b": True}})
        closure = CanonicalClosure(self.root)
        self.assertIs(closure.node(closure.target("a.json", "#/allOf/0")), True)
        self.assertIs(closure.node(closure.target("a.json", "#/$defs/a%20b")), True)
        for ref in ["#/allOf/-1", "#/allOf/+1", "#/allOf/01", "#/allOf/2",
                    "#/$defs/\nC", "#/$defs/\tC", "#/$defs/%FF", "#/$defs/ C"]:
            with self.subTest(reference=ref), self.assertRaises(ValueError):
                closure.node(closure.target("a.json", ref))

    def test_pointer_activated_schema_anchors_resolve_without_annotation_discovery(self):
        self.write("a.json", allOf=[{"$ref": "#activated"}, {"$ref": "#/x-schema"}],
                   **{"x-schema": {"$anchor": "activated", "const": "PASS"},
                      "examples": [{"$anchor": "activated", "const": "FAKE"}]})
        result = CanonicalClosure(self.root).build({"Root": "a.json"})
        root = result["components"][result["roots"]["Root"]]
        self.assertEqual(root["allOf"][0]["$ref"], root["allOf"][1]["$ref"])

    def test_exact_uri_owner_is_required(self):
        (self.root / "a.json").write_text('{"$id":"https://attacker.invalid/a.json"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "owning file"):
            CanonicalClosure(self.root).build({"Root": "a.json"})

    def test_formal_roots_have_complete_local_reference_closure(self):
        tools = Path(__file__).resolve().parent
        artifacts = tools.parent.parent / "arkret-spec/spec/v1/artifacts"
        bindings = json.loads((tools / "closed-model-bindings.json").read_text(encoding="utf-8"))
        manifest = json.loads((tools / "spec-generation-manifest.json").read_text(encoding="utf-8"))
        for bundle in bindings["openapi_bundles"]:
            text, inputs, result = generate_bundle(artifacts / "schemas", bundle)
            entry = next(row for row in manifest["entries"] if bundle["output"] in row["outputs"])
            self.assertEqual(entry["artifacts"], ["schemas/" + path for path in inputs])
            self.assertNotIn("impl salvo_oapi::ToSchema for super::Event", text)
            seen = set()

            def walk(node):
                if isinstance(node, dict) and "$ref" in node:
                    prefix = "#/components/schemas/"
                    self.assertTrue(node["$ref"].startswith(prefix))
                    target = node["$ref"][len(prefix):]
                    self.assertIn(target, result["components"])
                    seen.add(target)
                for _, child in children(node):
                    walk(child)
            for component in result["components"].values():
                walk(component)
            self.assertGreater(len(seen), 100)
            self.assertTrue(any(source.endswith("event-envelope.schema.json#") for source in result["sources"].values()))


if __name__ == "__main__":
    unittest.main()
