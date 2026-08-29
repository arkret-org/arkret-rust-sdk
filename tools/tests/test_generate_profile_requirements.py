import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_ARTIFACTS = REPO_ROOT.parent / "arkret-spec" / "spec" / "v1" / "artifacts"
MODULE_PATH = REPO_ROOT / "tools" / "generate-sdk-profile-requirements.py"
SPEC = importlib.util.spec_from_file_location(
    "generate_sdk_profile_requirements", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class ProfileRequirementGeneratorTests(unittest.TestCase):
    def test_registered_event_kinds_reuse_generated_constants(self) -> None:
        generated = GENERATOR.generate(
            SPEC_ARTIFACTS / "profiles" / "conformance-profiles.json",
            SPEC_ARTIFACTS / "registry" / "event-kind-registry.json",
        )

        self.assertIn(
            "event_kind_str::IDENTITY_RESOLUTION_UPDATE,",
            generated,
        )
        self.assertNotIn('"ak.identity.resolution.update"', generated)

    def test_non_event_wire_scope_selector_remains_a_literal(self) -> None:
        generated = GENERATOR.generate(
            SPEC_ARTIFACTS / "profiles" / "conformance-profiles.json",
            SPEC_ARTIFACTS / "registry" / "event-kind-registry.json",
        )

        self.assertIn('"wire_scope:actor_private_event"', generated)


if __name__ == "__main__":
    unittest.main()
