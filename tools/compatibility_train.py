#!/usr/bin/env python3
"""Stage and promote an exact-SHA multi-repository compatibility train."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Protocol

import compatibility_gate as gate


RUN_ID_PATTERN = re.compile(r"^[1-9][0-9]*$")
TRAIN_RUN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class GitHubApi(Protocol):
    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any] | list[Any] | None: ...


class GhClient:
    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any] | list[Any] | None:
        command = ["gh", "api", "--method", method, path]
        encoded = None
        if body is not None:
            command.extend(["--input", "-"])
            encoded = json.dumps(body, separators=(",", ":"))
        try:
            completed = subprocess.run(
                command,
                input=encoded,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            raise gate.CompatibilityError(
                f"GitHub API {method} {path} failed: {detail.strip()}"
            ) from error
        if not completed.stdout.strip():
            return None
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise gate.CompatibilityError(
                f"GitHub API {method} {path} returned invalid JSON"
            ) from error


def canonical_digest(document: dict[str, Any]) -> str:
    encoded = json.dumps(
        document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def api_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise gate.CompatibilityError(f"GitHub API response for {label} is not an object")
    return value


def ref_sha(client: GitHubApi, repository: str, ref: str) -> str:
    response = api_object(
        client.request("GET", f"repos/{repository}/git/ref/heads/{ref}"),
        f"{repository}:{ref}",
    )
    obj = api_object(response.get("object"), f"{repository}:{ref}.object")
    sha = obj.get("sha")
    if not isinstance(sha, str) or not gate.SHA_PATTERN.fullmatch(sha):
        raise gate.CompatibilityError(f"{repository}:{ref} returned an invalid SHA")
    return sha


def candidate_is_fast_forward(
    client: GitHubApi, repository: str, base_sha: str, candidate_sha: str
) -> None:
    client.request("GET", f"repos/{repository}/commits/{candidate_sha}")
    comparison = api_object(
        client.request(
            "GET", f"repos/{repository}/compare/{base_sha}...{candidate_sha}"
        ),
        f"{repository} comparison",
    )
    if comparison.get("status") not in {"ahead", "identical"}:
        raise gate.CompatibilityError(
            f"candidate {repository}@{candidate_sha} is not a fast-forward from main {base_sha}"
        )


def stage_ref_name(document: dict[str, Any], run_id: str) -> str:
    train_id = document["train"].get("id")
    if not isinstance(train_id, str) or not TRAIN_RUN_PATTERN.fullmatch(train_id):
        raise gate.CompatibilityError("train.id is not safe for a Git reference")
    if not TRAIN_RUN_PATTERN.fullmatch(run_id):
        raise gate.CompatibilityError("run-id is not safe for a Git reference")
    return f"compatibility/{train_id}/{run_id}"


def preflight_stage(
    document: dict[str, Any], client: GitHubApi, run_id: str
) -> dict[str, Any]:
    gate.validate_manifest(document)
    stage_ref = stage_ref_name(document, run_id)
    repositories: list[dict[str, str]] = []
    for name in document["train"]["merge_order"]:
        entry = document["repositories"][name]
        repository = entry["repository"]
        candidate = entry["commit"]
        baseline = ref_sha(client, repository, "main")
        candidate_is_fast_forward(client, repository, baseline, candidate)
        repositories.append(
            {
                "name": name,
                "repository": repository,
                "candidate": candidate,
                "baseline_main": baseline,
                "stage_ref": stage_ref,
            }
        )
    return {
        "schema_version": 1,
        "train_id": document["train"]["id"],
        "run_id": run_id,
        "phase": "planned",
        "manifest_digest": canonical_digest(document),
        "merge_order": list(document["train"]["merge_order"]),
        "repositories": repositories,
        "created_at": utc_now(),
    }


def create_staged_refs(
    evidence: dict[str, Any], client: GitHubApi
) -> dict[str, Any]:
    for item in evidence["repositories"]:
        client.request(
            "POST",
            f"repos/{item['repository']}/git/refs",
            {
                "ref": f"refs/heads/{item['stage_ref']}",
                "sha": item["candidate"],
            },
        )
        actual = ref_sha(client, item["repository"], item["stage_ref"])
        if actual != item["candidate"]:
            raise gate.CompatibilityError(
                f"staged ref mismatch for {item['name']}: expected {item['candidate']}, got {actual}"
            )
    evidence = json.loads(json.dumps(evidence))
    evidence["phase"] = "staged"
    evidence["staged_at"] = utc_now()
    return evidence


def dispatch_exact_gate(evidence: dict[str, Any], client: GitHubApi) -> None:
    sdk = next(
        item for item in evidence["repositories"] if item["name"] == "arkret-rust-sdk"
    )
    client.request(
        "POST",
        f"repos/{sdk['repository']}/actions/workflows/compatibility.yml/dispatches",
        {
            "ref": sdk["stage_ref"],
            "inputs": {"manifest_ref": sdk["stage_ref"]},
        },
    )


def validate_evidence(document: dict[str, Any], evidence: dict[str, Any]) -> None:
    gate.validate_manifest(document)
    if evidence.get("schema_version") != 1:
        raise gate.CompatibilityError("train evidence schema_version must be 1")
    if evidence.get("manifest_digest") != canonical_digest(document):
        raise gate.CompatibilityError("train evidence does not bind the supplied manifest")
    if evidence.get("merge_order") != document["train"]["merge_order"]:
        raise gate.CompatibilityError("train evidence merge order differs from the manifest")
    rows = evidence.get("repositories")
    if not isinstance(rows, list) or len(rows) != len(document["repositories"]):
        raise gate.CompatibilityError("train evidence repository set is incomplete")
    for name, row in zip(document["train"]["merge_order"], rows, strict=True):
        entry = document["repositories"][name]
        if not isinstance(row, dict) or (
            row.get("name") != name
            or row.get("repository") != entry["repository"]
            or row.get("candidate") != entry["commit"]
        ):
            raise gate.CompatibilityError(f"train evidence row does not match {name}")


def verify_successful_gate_run(
    evidence: dict[str, Any], client: GitHubApi, workflow_run_id: str
) -> None:
    if not RUN_ID_PATTERN.fullmatch(workflow_run_id):
        raise gate.CompatibilityError("workflow-run-id must be a positive integer")
    sdk = next(
        item for item in evidence["repositories"] if item["name"] == "arkret-rust-sdk"
    )
    run = api_object(
        client.request(
            "GET", f"repos/{sdk['repository']}/actions/runs/{workflow_run_id}"
        ),
        "compatibility workflow run",
    )
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or run.get("head_sha") != sdk["candidate"]
        or run.get("path") != ".github/workflows/compatibility.yml"
    ):
        raise gate.CompatibilityError(
            "workflow run is not a successful exact compatibility dispatch for the staged SDK candidate"
        )


def verify_resolved_manifest(
    document: dict[str, Any], resolved_document: dict[str, Any]
) -> None:
    gate.validate_manifest(resolved_document)
    expected = {
        name: entry["commit"] for name, entry in document["repositories"].items()
    }
    actual = {
        name: entry["commit"]
        for name, entry in resolved_document["repositories"].items()
    }
    if actual != expected:
        raise gate.CompatibilityError(
            "workflow resolved manifest does not equal the complete staged candidate set"
        )


def download_resolved_manifest(repository: str, run_id: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="arkret-compat-train-") as temporary:
        destination = Path(temporary)
        artifact = f"resolved-compatibility-manifest-{run_id}"
        try:
            subprocess.run(
                [
                    "gh",
                    "run",
                    "download",
                    run_id,
                    "--repo",
                    repository,
                    "--name",
                    artifact,
                    "--dir",
                    str(destination),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            raise gate.CompatibilityError(
                f"resolved manifest artifact download failed: {detail.strip()}"
            ) from error
        matches = list(destination.rglob("resolved-compatibility-manifest.json"))
        if len(matches) != 1:
            raise gate.CompatibilityError(
                "resolved manifest artifact must contain exactly one resolved manifest"
            )
        return gate.load_manifest(matches[0])


def preflight_promotion(
    document: dict[str, Any], evidence: dict[str, Any], client: GitHubApi
) -> None:
    validate_evidence(document, evidence)
    if evidence.get("phase") != "staged":
        raise gate.CompatibilityError("only staged evidence can be promoted")
    mismatches: list[str] = []
    for item in evidence["repositories"]:
        main = ref_sha(client, item["repository"], "main")
        staged = ref_sha(client, item["repository"], item["stage_ref"])
        if main != item["baseline_main"]:
            mismatches.append(
                f"{item['name']} main moved from {item['baseline_main']} to {main}"
            )
        if staged != item["candidate"]:
            mismatches.append(
                f"{item['name']} staged ref is {staged}, expected {item['candidate']}"
            )
    if mismatches:
        raise gate.CompatibilityError("promotion preflight failed: " + "; ".join(mismatches))


def promote(
    evidence: dict[str, Any],
    client: GitHubApi,
    workflow_run_id: str,
    evidence_output: Path | None = None,
) -> dict[str, Any]:
    result = json.loads(json.dumps(evidence))
    result["workflow_run_id"] = workflow_run_id
    result["promotion"] = []
    if evidence_output is not None:
        write_document(evidence_output, result)
    for item in result["repositories"]:
        client.request(
            "PATCH",
            f"repos/{item['repository']}/git/refs/heads/main",
            {"sha": item["candidate"], "force": False},
        )
        actual = ref_sha(client, item["repository"], "main")
        if actual != item["candidate"]:
            result["phase"] = "promotion_failed"
            result["promotion"].append(
                {"name": item["name"], "status": "mismatch", "actual": actual}
            )
            if evidence_output is not None:
                write_document(evidence_output, result)
            raise gate.CompatibilityError(
                f"promotion verification failed for {item['name']}: got {actual}"
            )
        result["promotion"].append(
            {"name": item["name"], "status": "promoted", "commit": actual}
        )
        if evidence_output is not None:
            write_document(evidence_output, result)
    result["phase"] = "promoted"
    result["promoted_at"] = utc_now()
    if evidence_output is not None:
        write_document(evidence_output, result)
    return result


def write_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("--manifest", type=Path, default=gate.default_manifest_path())
    stage.add_argument("--run-id", required=True)
    stage.add_argument("--evidence", type=Path, required=True)
    stage.add_argument("--execute", action="store_true")
    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("--manifest", type=Path, default=gate.default_manifest_path())
    promote_parser.add_argument("--evidence", type=Path, required=True)
    promote_parser.add_argument("--workflow-run-id", required=True)
    promote_parser.add_argument("--output", type=Path, required=True)
    promote_parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    client = GhClient()
    try:
        document = gate.load_manifest(arguments.manifest)
        if arguments.command == "stage":
            evidence = preflight_stage(document, client, arguments.run_id)
            if arguments.execute:
                evidence = create_staged_refs(evidence, client)
                dispatch_exact_gate(evidence, client)
            write_document(arguments.evidence, evidence)
            print(f"compatibility train {evidence['phase']} evidence written to {arguments.evidence}")
        elif arguments.command == "promote":
            evidence = gate.load_manifest(arguments.evidence)
            verify_successful_gate_run(evidence, client, arguments.workflow_run_id)
            sdk_repository = document["repositories"]["arkret-rust-sdk"]["repository"]
            resolved = download_resolved_manifest(sdk_repository, arguments.workflow_run_id)
            verify_resolved_manifest(document, resolved)
            preflight_promotion(document, evidence, client)
            if not arguments.execute:
                result = json.loads(json.dumps(evidence))
                result["phase"] = "promotion_ready"
                result["workflow_run_id"] = arguments.workflow_run_id
                write_document(arguments.output, result)
                print(
                    f"promotion preflight passed; evidence written to {arguments.output}; "
                    "rerun with --execute to advance main refs"
                )
            else:
                result = promote(
                    evidence, client, arguments.workflow_run_id, arguments.output
                )
                print(f"compatibility train promoted; evidence written to {arguments.output}")
    except gate.CompatibilityError as error:
        print(f"compatibility train failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
