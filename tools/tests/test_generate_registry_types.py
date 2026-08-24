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

    def test_digest_suite_codes_are_generated_from_the_registry(self) -> None:
        temporary, artifacts = self.registry_fixture(["digest-suite-registry.json"])
        with temporary:
            generated = GENERATOR.generate_digest_suite_codes(artifacts)

        self.assertIn("Sha256 = 0x01,", generated)
        self.assertIn("Blake3 = 0x02,", generated)
        self.assertIn("0x01 => Ok(Self::Sha256),", generated)

    def test_digest_suite_codes_reject_nonzero_high_nibble(self) -> None:
        temporary, artifacts = self.registry_fixture(["digest-suite-registry.json"])
        with temporary:
            path = artifacts / "registry" / "digest-suite-registry.json"
            registry = json.loads(path.read_text(encoding="utf-8"))
            registry["suites"][0]["wire_code"] = 0x11
            path.write_text(json.dumps(registry), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "high nibble zero"):
                GENERATOR.generate_digest_suite_codes(artifacts)

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

    def test_reason_code_as_str_reuses_associated_constants(self) -> None:
        temporary, artifacts = self.registry_fixture(["error-code-registry.json"])
        with temporary:
            generated = GENERATOR.generate_reason_codes(artifacts)

        as_str = generated.split("    pub fn as_str(&self) -> &str {", 1)[1].split(
            "    pub fn from_wire(value: &str) -> Self {", 1
        )[0]
        self.assertIn(
            "Self::LegalHoldActive => Self::LEGAL_HOLD_ACTIVE,",
            as_str,
        )
        self.assertNotIn(' => "', as_str)

    def test_reason_code_from_wire_reuses_associated_constants(self) -> None:
        temporary, artifacts = self.registry_fixture(["error-code-registry.json"])
        with temporary:
            generated = GENERATOR.generate_reason_codes(artifacts)

        from_wire = generated.split(
            "    pub fn from_wire(value: &str) -> Self {", 1
        )[1].split("    pub fn is_valid_wire(value: &str) -> bool {", 1)[0]
        self.assertIn(
            "Self::LEGAL_HOLD_ACTIVE => Self::LegalHoldActive,",
            from_wire,
        )
        self.assertNotIn('            "', from_wire)

    def test_reason_code_descriptors_reuse_associated_constants(self) -> None:
        temporary, artifacts = self.registry_fixture(["error-code-registry.json"])
        with temporary:
            generated = GENERATOR.generate_reason_codes(artifacts)

        descriptors = generated.split(
            "pub const REASON_CODE_DESCRIPTORS: &[ReasonCodeDescriptor] = &[", 1
        )[1]
        self.assertIn(
            "code: ReasonCode::LEGAL_HOLD_ACTIVE,",
            descriptors,
        )
        self.assertNotIn('        code: "', descriptors)

    def test_relation_kind_descriptors_are_generated(self) -> None:
        temporary, artifacts = self.registry_fixture(["relation-kind-registry.json"])
        with temporary:
            generated = GENERATOR.generate_relation_kinds(artifacts)

        self.assertIn("pub struct RelationKindDescriptor", generated)
        self.assertIn("pub const RELATION_KIND_DESCRIPTORS", generated)

    def test_authority_sources_generate_every_registered_id(self) -> None:
        temporary, artifacts = self.registry_fixture(["authority-source-registry.json"])
        with temporary:
            generated = GENERATOR.generate_authority_sources(artifacts)
            registry = json.loads(
                (artifacts / "registry" / "authority-source-registry.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertIn("pub enum AuthoritySourceId", generated)
        for source in registry["sources"]:
            source_id = source["authority_source_id"]
            variant = GENERATOR.variant(source_id, GENERATOR.AUTHORITY_SOURCE_PREFIXES)
            self.assertIn(f"Self::{variant}", generated)
            self.assertIn(json.dumps(source_id), generated)


class RustdocTextTests(unittest.TestCase):
    def test_escapes_html_metacharacters_from_registry_descriptions(self) -> None:
        self.assertEqual(
            GENERATOR.rustdoc_text("@<controller>/<agent> & peer"),
            "@&lt;controller&gt;/&lt;agent&gt; &amp; peer",
        )


if __name__ == "__main__":
    unittest.main()
