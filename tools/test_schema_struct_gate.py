import json
import tempfile
import unittest
from pathlib import Path

from tools.schema_struct_gate import schema_property_names, validate
from tools.wire_value_audit import SchemaResolver


class SchemaStructGateTests(unittest.TestCase):
    def representation_fixture(self, source, mapping, properties, **schema_keywords):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'crates/models/src/lib.rs'
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding='utf-8')
            schemas = root / 'schemas'
            schemas.mkdir()
            (schemas / 'example.schema.json').write_text(json.dumps({
                'type': 'object', 'properties': properties, **schema_keywords,
            }), encoding='utf-8')
            registry = root / 'registry.json'
            registry.write_text(json.dumps({'version': 1, 'mappings': [{
                'rust_type': 'crates/models/src/lib.rs::Payload',
                'schema': 'example.schema.json#', **mapping,
            }], 'exemptions': []}), encoding='utf-8')
            return validate(registry, schemas, root)

    def test_private_wire_adapter_is_checked_instead_of_domain_members(self):
        source = '''#[derive(Serialize, Deserialize)]
#[serde(try_from = "PayloadWire")]
// An ordinary comment must not hide the attached serde representation.
pub struct Payload { #[serde(flatten)] pub branch: Branch }
#[derive(Deserialize)]
struct PayloadWire { member: String }
'''
        mapping = {'wire_adapter': 'crates/models/src/lib.rs::PayloadWire'}
        self.assertEqual(self.representation_fixture(source, mapping, {'member': {}}), [])
        errors = self.representation_fixture(source.replace('member:', 'stale:'), mapping, {'member': {}})
        self.assertTrue(any('field mismatch' in error for error in errors), errors)
        errors = self.representation_fixture(source.replace('PayloadWire")', 'OtherWire")'), mapping, {'member': {}})
        self.assertTrue(any('actual validating decode' in error for error in errors), errors)

    def test_manual_map_uses_emitted_names_and_requires_open_dynamic_contract(self):
        source = '''pub struct Payload { pub internal: String }
impl Serialize for Payload { fn serialize() {
    let mut map = serializer.serialize_map(None)?;
    map.serialize_entry("member", &self.internal)?;
    map.end()
} }
'''
        self.assertEqual(self.representation_fixture(source, {'manual_map': True}, {'member': {}}), [])
        bad = source.replace('"member"', '"stale"')
        errors = self.representation_fixture(bad, {'manual_map': True}, {'member': {}})
        self.assertTrue(any('unregistered members' in error for error in errors), errors)
        dynamic = source.replace('map.end()', 'map.serialize_entry(key, value)?; map.end()')
        errors = self.representation_fixture(dynamic, {'manual_map': True}, {'member': {}}, additionalProperties=False)
        self.assertTrue(any('explicit open extension contract' in error for error in errors), errors)
        self.assertEqual(self.representation_fixture(dynamic, {'manual_map': True}, {'member': {}}, additionalProperties=True), [])

    def test_same_name_object_cannot_omit_its_schema_pointer_to_escape_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'crates/models/src/lib.rs'
            source.parent.mkdir(parents=True)
            source.write_text('#[derive(Serialize)]\npub struct ReadView { pub stale: String }', encoding='utf-8')
            schemas = root / 'schemas'
            schemas.mkdir()
            (schemas / 'example.schema.json').write_text(json.dumps({'$defs': {
                'read_view': {'type': 'object', 'properties': {'canonical': {'type': 'string'}}}
            }}), encoding='utf-8')
            registry = root / 'registry.json'
            registry.write_text(json.dumps({'version': 1, 'mappings': [], 'exemptions': []}), encoding='utf-8')
            self.assertTrue(any('unregistered named object' in error
                                for error in validate(registry, schemas, root)))

    def test_full_width_coordinate_cannot_fall_back_to_json_number(self) -> None:
        for helper in ('', '#[serde(with = "arkret_canonical::serde_helpers::uint64_decimal")]'):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'crates/models/src/lib.rs'
                source.parent.mkdir(parents=True)
                source.write_text(f'pub struct Payload {{\n{helper}\npub epoch: u64,\n}}', encoding='utf-8')
                schemas = root / 'schemas'
                schemas.mkdir()
                (schemas / 'example.schema.json').write_text(json.dumps({'properties': {
                    'epoch': {'$ref': './decimal-integers.schema.json#/$defs/uint64_decimal'}}}), encoding='utf-8')
                registry = root / 'registry.json'
                registry.write_text(json.dumps({'version': 1, 'mappings': [{
                    'rust_type': 'crates/models/src/lib.rs::Payload', 'schema': 'example.schema.json#'}],
                    'exemptions': []}), encoding='utf-8')
                errors = validate(registry, schemas, root)
                self.assertEqual(any('decimal serialization mismatch' in error for error in errors), not bool(helper), errors)

    def property_names(self, node: dict) -> set[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema = root / "example.schema.json"
            schema.write_text(json.dumps({"$defs": {"payload": node}}), encoding="utf-8")
            return schema_property_names(SchemaResolver(root), schema, {"$ref": "#/$defs/payload"}, accepted=True)

    def test_member_forbidden_in_every_branch_is_not_a_wire_field(self) -> None:
        self.assertEqual(self.property_names({
            "properties": {"device": {}, "agent": {}, "retired": {}},
            "oneOf": [
                {"not": {"anyOf": [{"required": ["agent"]}, {"required": ["retired"]}]}},
                {"not": {"anyOf": [{"required": ["device"]}, {"required": ["retired"]}]}},
            ],
        }), {"device", "agent"})

    def test_member_allowed_by_one_branch_is_retained(self) -> None:
        self.assertEqual(self.property_names({
            "properties": {"member": {}},
            "anyOf": [{"not": {"required": ["member"]}}, {}],
        }), {"member"})

    def test_negated_joint_presence_does_not_forbid_individual_members(self) -> None:
        self.assertEqual(self.property_names({
            "properties": {"first": {}, "second": {}},
            "allOf": [{"not": {"required": ["first", "second"]}}],
        }), {"first", "second"})

    def test_ref_and_all_of_preserve_global_presence_exclusion(self) -> None:
        self.assertEqual(self.property_names({
            "properties": {"active": {}, "retired": {}},
            "allOf": [{"not": {"required": ["retired"]}}],
        }), {"active"})

    def fixture(
        self,
        rust_field: str = "recovery_keys",
        registered: bool = True,
        flattened: bool = False,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates" / "models" / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            flatten_field = (
                "    #[serde(flatten)]\n"
                "    pub extra: std::collections::BTreeMap<String, serde_json::Value>,\n"
                if flattened
                else ""
            )
            source.write_text(
                f'''/// Counterpart for `example.schema.json#/$defs/payload`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Payload {{
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub {rust_field}: Vec<String>,
    #[serde(rename = "created_at")]
    pub created: String,
{flatten_field}
}}
''',
                encoding="utf-8",
            )
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "example.schema.json").write_text(
                json.dumps(
                    {
                        "$defs": {
                            "payload": {
                                "allOf": [
                                    {"properties": {"created_at": {"type": "string"}}},
                                    {
                                        "oneOf": [
                                            {"properties": {"recovery_keys": {"type": "array"}}},
                                            {"properties": {"recovery_keys": {"type": "array"}}},
                                        ]
                                    },
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            registry = root / "registry.json"
            registry.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "mappings": (
                            [
                                {
                                    "rust_type": "crates/models/src/lib.rs::Payload",
                                    "schema": "example.schema.json#/$defs/payload",
                                    **(
                                        {
                                            "comparison": "rust_fields_subset",
                                            "reason": (
                                                "serde(flatten) carries schema-only fields while "
                                                "declared Rust fields remain checked."
                                            ),
                                        }
                                        if flattened
                                        else {}
                                    ),
                                }
                            ]
                            if registered
                            else []
                        ),
                        "exemptions": [],
                    }
                ),
                encoding="utf-8",
            )
            return validate(registry, schemas, root)

    def test_matching_composed_schema_passes(self) -> None:
        self.assertEqual(self.fixture(), [])

    def test_field_name_mutation_fails(self) -> None:
        errors = self.fixture("recovery_key_entries")
        self.assertTrue(any("field mismatch" in error for error in errors))

    def test_unregistered_counterpart_fails(self) -> None:
        errors = self.fixture(registered=False)
        self.assertTrue(any("unregistered schema counterpart" in error for error in errors))

    def test_flattened_struct_allows_schema_only_fields(self) -> None:
        self.assertEqual(self.fixture(flattened=True), [])

    def test_flattened_struct_rust_only_mutation_fails(self) -> None:
        errors = self.fixture("ghost_field", flattened=True)
        self.assertTrue(
            any("Rust-only=['ghost_field']" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
