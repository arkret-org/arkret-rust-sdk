from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "test_layout_gate.py"
SPEC = importlib.util.spec_from_file_location("test_layout_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class TestLayoutGateTests(unittest.TestCase):
    def write_source(self, root: Path, relative: str, text: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_rejects_a_new_early_test_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_source(
                root,
                "crates/example/src/lib.rs",
                "#[cfg(test)]\nmod tests { #[test] fn it_works() {} }\n"
                + "pub fn production() {}\n" * 20,
            )
            previous = GATE.MAX_EARLY_TEST_MODULE_FILES
            GATE.MAX_EARLY_TEST_MODULE_FILES = 0
            try:
                self.assertTrue(GATE.scan(root))
            finally:
                GATE.MAX_EARLY_TEST_MODULE_FILES = previous

    def test_allows_a_small_tail_test_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_source(
                root,
                "crates/example/src/lib.rs",
                "pub fn production() {}\n" * 20
                + "#[cfg(test)]\nmod tests { #[test] fn it_works() {} }\n",
            )
            self.assertEqual(GATE.scan(root), [])


if __name__ == "__main__":
    unittest.main()
