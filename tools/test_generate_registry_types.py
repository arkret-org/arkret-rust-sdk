from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate-registry-types.py")
SPEC = importlib.util.spec_from_file_location("generate_registry_types", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class RustdocTextTests(unittest.TestCase):
    def test_escapes_html_metacharacters_from_registry_descriptions(self) -> None:
        self.assertEqual(
            GENERATOR.rustdoc_text("@<controller>/<agent> & peer"),
            "@&lt;controller&gt;/&lt;agent&gt; &amp; peer",
        )


if __name__ == "__main__":
    unittest.main()
