#!/usr/bin/env python3
"""Guards that every generator under `tools/` writes LF, on every platform.

A writer that omits `newline` inherits the platform line ending, so the same
generator emitted CRLF on Windows and LF elsewhere. The repository pins
`* text=auto eol=lf`, so a Windows run rewrote its own artifacts end to end and
`git status` went dirty on nothing but line endings. `dep_matrix.py` made that
cross-repository: its default output directory is
`<workspace>/arkret-work/reports/dep-matrix`, so running the SDK gate dirtied a
different checkout.

`csv.writer` gets its own guard because it is the one writer that ignores the
platform: its default `lineterminator` is CRLF everywhere, so the CSV artifact
was wrong on Linux too.

`newline=""` is a correct pin, not an omission -- it disables translation and
lets the text's own `\\n` reach the file unchanged, which is exactly what the
`csv` module requires of the handle it is given.
"""

from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent

MODULE_PATH = TOOLS / "dep_matrix.py"
SPEC = importlib.util.spec_from_file_location("dep_matrix", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
dep_matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dep_matrix)


def call_arguments(source: str, opener: str) -> list[str]:
    """Return the argument text of every `opener` call in `source`."""

    calls: list[str] = []
    for match in re.finditer(re.escape(opener), source):
        index = match.end()
        depth = 1
        while index < len(source) and depth:
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
            index += 1
        calls.append(source[match.end() : index])
    return calls


def tool_sources() -> list[Path]:
    """Every non-test Python script under `tools/`."""

    return [
        path
        for path in sorted(TOOLS.rglob("*.py"))
        if not path.name.startswith("test_")
    ]


class GeneratedFileNewlineTest(unittest.TestCase):
    def test_every_tool_writer_pins_a_newline(self) -> None:
        offenders: list[str] = []
        for path in tool_sources():
            source = path.read_text(encoding="utf-8")
            name = path.relative_to(ROOT).as_posix()
            for call in call_arguments(source, ".write_text("):
                if "newline=" not in call:
                    offenders.append(f"{name}: write_text")
            for call in call_arguments(source, "open("):
                if re.search(r"""["'][wax]\+?b?["']""", call) and "newline=" not in call:
                    offenders.append(f"{name}: open")
        self.assertEqual(offenders, [])

    def test_every_csv_writer_pins_lf(self) -> None:
        """`csv.writer` defaults to CRLF regardless of platform or `newline`."""

        offenders: list[str] = []
        for path in tool_sources():
            source = path.read_text(encoding="utf-8")
            name = path.relative_to(ROOT).as_posix()
            for opener in ("csv.writer(", "csv.DictWriter("):
                for call in call_arguments(source, opener):
                    if "lineterminator=" not in call:
                        offenders.append(f"{name}: {opener.rstrip('(')}")
        self.assertEqual(offenders, [])

    def test_the_scan_would_catch_an_unpinned_writer(self) -> None:
        """The guard is only worth anything if the scan actually matches."""

        unpinned = 'path.write_text(body, encoding="utf-8")'
        self.assertNotIn("newline=", call_arguments(unpinned, ".write_text(")[0])
        pinned = 'path.write_text(body, encoding="utf-8", newline="\\n")'
        self.assertIn("newline=", call_arguments(pinned, ".write_text(")[0])


class DepMatrixArtifactBytesTest(unittest.TestCase):
    """The writers behind the artifacts that went dirty, exercised for real."""

    CRATES = {
        "serde": {
            "cross_repo_split": False,
            "local": False,
            "repos": {
                "arkret-rust-sdk": {
                    "resolved_versions": ["1.0.0"],
                    "resolved_majors": ["1"],
                    "intra_lock_split": False,
                    "direct": [],
                },
                "soland": {
                    "resolved_versions": ["1.0.0"],
                    "resolved_majors": ["1"],
                    "intra_lock_split": False,
                    "direct": [],
                },
            },
        }
    }

    def test_json_artifact_has_no_carriage_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dep-matrix.json"
            dep_matrix.write_json(path, {"version": 1, "crates": self.CRATES})
            written = path.read_bytes()
        self.assertNotIn(b"\r", written)
        self.assertTrue(written.endswith(b"\n"))

    def test_csv_artifact_has_no_carriage_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dep-matrix.csv"
            dep_matrix.write_csv(path, self.CRATES)
            written = path.read_bytes()
        self.assertNotIn(b"\r", written)
        self.assertGreater(written.count(b"\n"), 1)


if __name__ == "__main__":
    unittest.main()
