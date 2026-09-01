#!/usr/bin/env python3
"""Prevent large in-source Rust test modules from spreading or regrowing."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


EARLY_TEST_MODULE_RATIO = 0.80
LARGE_SOURCE_LINES = 1_500
MAX_TEST_MODULES = 307
MAX_EARLY_TEST_MODULE_FILES = 211
MAX_LARGE_TEST_SOURCE_FILES = 28

# Existing debt is budgeted at the revalidation baseline. Moving tests out may
# lower these ceilings; adding production or test lines to a hotspot must first
# split the test module instead of raising the budget.
HOTSPOT_BUDGETS = {
    "crates/schema-conformance/src/payloads.rs": 882,
    "crates/mls/src/signal.rs": 1_246,
    "crates/schema/src/event_cell_contract.rs": 3_683,
    "crates/models-discovery/src/service_description.rs": 1_860,
}

TEST_MODULE = re.compile(
    r"(?m)^\s*#\[cfg\(test\)\]\s*(?:#\[[^\n]+\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
)


def rust_sources(root: Path) -> list[Path]:
    return sorted((root / "crates").glob("*/src/**/*.rs"))


def test_module_lines(text: str) -> list[int]:
    return [text.count("\n", 0, match.start()) + 1 for match in TEST_MODULE.finditer(text)]


def scan(root: Path) -> list[str]:
    violations: list[str] = []
    test_module_count = 0
    early_test_module_files: list[str] = []
    large_test_source_files: list[str] = []
    for path in rust_sources(root):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        line_count = text.count("\n") + (0 if text.endswith("\n") else 1)
        module_lines = test_module_lines(text)
        test_module_count += len(module_lines)

        budget = HOTSPOT_BUDGETS.get(relative)
        if budget is not None and line_count > budget:
            violations.append(
                f"{relative}: {line_count} lines exceeds frozen hotspot budget {budget}"
            )

        if not module_lines:
            continue
        first_ratio = module_lines[0] / max(line_count, 1)
        if first_ratio < EARLY_TEST_MODULE_RATIO and relative not in HOTSPOT_BUDGETS:
            early_test_module_files.append(relative)
        if (
            line_count >= LARGE_SOURCE_LINES
            and relative not in HOTSPOT_BUDGETS
            and "/generated/" not in relative
        ):
            large_test_source_files.append(relative)

    aggregate_budgets = (
        (test_module_count, MAX_TEST_MODULES, "in-source test modules"),
        (
            len(early_test_module_files),
            MAX_EARLY_TEST_MODULE_FILES,
            "files whose first test module begins before the final 20%",
        ),
        (
            len(large_test_source_files),
            MAX_LARGE_TEST_SOURCE_FILES,
            f"files with at least {LARGE_SOURCE_LINES} lines and in-source tests",
        ),
    )
    for actual, maximum, label in aggregate_budgets:
        if actual > maximum:
            violations.append(f"{label}: {actual} exceeds frozen baseline {maximum}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    violations = scan(args.root.resolve())
    if violations:
        print("test layout gate failed:")
        for violation in violations:
            print(f"  - {violation}")
        return 1
    print("test layout gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
