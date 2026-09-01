#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).with_name("compatibility_train.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("compatibility_train", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
train = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(train)


class FakeGitHub:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.refs: dict[tuple[str, str], str] = {}
        self.candidates: set[tuple[str, str]] = set()
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        for entry in manifest["repositories"].values():
            self.refs[(entry["repository"], "main")] = "0" * 40
            self.candidates.add((entry["repository"], entry["commit"]))

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        self.calls.append((method, path, body))
        prefix, _, rest = path.partition("/git/ref/heads/")
        if rest and method == "GET":
            repository = prefix.removeprefix("repos/")
            return {"object": {"sha": self.refs[(repository, rest)]}}
        if "/commits/" in path and method == "GET":
            return {"sha": path.rsplit("/", 1)[1]}
        if "/compare/" in path and method == "GET":
            return {"status": "ahead"}
        if path.endswith("/git/refs") and method == "POST":
            repository = path.removeprefix("repos/").removesuffix("/git/refs")
            assert body is not None
            self.refs[(repository, body["ref"].removeprefix("refs/heads/"))] = body["sha"]
            return {"object": {"sha": body["sha"]}}
        if "/git/refs/heads/main" in path and method == "PATCH":
            repository = path.removeprefix("repos/").removesuffix("/git/refs/heads/main")
            assert body is not None
            self.refs[(repository, "main")] = body["sha"]
            return {"object": {"sha": body["sha"]}}
        if "/actions/workflows/" in path and method == "POST":
            return None
        raise AssertionError((method, path, body))


class CompatibilityTrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdk_root = Path(__file__).resolve().parents[1]
        cls.manifest = json.loads(
            (cls.sdk_root / "compatibility" / "manifest.json").read_text(encoding="utf-8")
        )

    def test_stage_plan_consumes_manifest_merge_order(self) -> None:
        client = FakeGitHub(self.manifest)
        evidence = train.preflight_stage(self.manifest, client, "run-1")
        self.assertEqual(
            [row["name"] for row in evidence["repositories"]],
            self.manifest["train"]["merge_order"],
        )

    def test_every_candidate_is_preflighted_before_any_ref_is_created(self) -> None:
        client = FakeGitHub(self.manifest)
        original = client.request
        comparisons = 0

        def fail(method: str, path: str, body: dict[str, Any] | None = None):
            nonlocal comparisons
            if "/compare/" in path:
                comparisons += 1
                if comparisons == 2:
                    return {"status": "diverged"}
            return original(method, path, body)

        client.request = fail  # type: ignore[method-assign]
        with self.assertRaisesRegex(train.gate.CompatibilityError, "not a fast-forward"):
            train.preflight_stage(self.manifest, client, "run-2")
        self.assertFalse(any(method == "POST" for method, _, _ in client.calls))

    def test_promotion_checks_all_main_and_stage_refs_before_first_write(self) -> None:
        client = FakeGitHub(self.manifest)
        evidence = train.create_staged_refs(
            train.preflight_stage(self.manifest, client, "run-3"), client
        )
        first = evidence["repositories"][0]
        client.refs[(first["repository"], "main")] = "f" * 40
        with self.assertRaisesRegex(train.gate.CompatibilityError, "main moved"):
            train.preflight_promotion(self.manifest, evidence, client)
        self.assertFalse(any(method == "PATCH" for method, _, _ in client.calls))

    def test_promotion_writes_and_verifies_in_merge_order(self) -> None:
        client = FakeGitHub(self.manifest)
        evidence = train.create_staged_refs(
            train.preflight_stage(self.manifest, client, "run-4"), client
        )
        train.preflight_promotion(self.manifest, evidence, client)
        result = train.promote(evidence, client, "123")
        promoted = [
            path.split("/")[2]
            for method, path, _ in client.calls
            if method == "PATCH"
        ]
        expected = [
            self.manifest["repositories"][name]["repository"].split("/", 1)[1]
            for name in self.manifest["train"]["merge_order"]
        ]
        self.assertEqual(promoted, expected)
        self.assertEqual(result["phase"], "promoted")

    def test_resolved_workflow_manifest_must_match_every_candidate(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["repositories"]["soland"]["commit"] = "f" * 40
        with self.assertRaisesRegex(train.gate.CompatibilityError, "complete staged candidate set"):
            train.verify_resolved_manifest(self.manifest, mutated)


if __name__ == "__main__":
    unittest.main()
