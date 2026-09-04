#!/usr/bin/env python3
"""Validate and execute an exact-SHA Arkret compatibility train."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


REQUIRED_REPOSITORIES = {
    "arkret-spec",
    "arkret-rust-sdk",
    "soland",
    "coauth",
    "garth",
    "inkson",
    "cotest",
}
REQUIRED_POLICY = {
    "consumer-local-compatibility-dto",
    "dual-read-fallback",
    "permissive-extra-fields",
}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class CompatibilityError(RuntimeError):
    """A deterministic compatibility-gate failure."""


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CompatibilityError(f"manifest could not be read: {path}: {error}") from error
    if not isinstance(document, dict):
        raise CompatibilityError("manifest root must be an object")
    return document


def validate_manifest(document: dict[str, Any]) -> None:
    if document.get("schema_version") != 1:
        raise CompatibilityError("manifest schema_version must be 1")

    repositories = document.get("repositories")
    if not isinstance(repositories, dict):
        raise CompatibilityError("manifest repositories must be an object")
    missing_repositories = REQUIRED_REPOSITORIES - set(repositories)
    if missing_repositories:
        raise CompatibilityError(
            "manifest missing repositories: " + ", ".join(sorted(missing_repositories))
        )

    checkout_paths: set[str] = set()
    for name, entry in repositories.items():
        if not isinstance(entry, dict):
            raise CompatibilityError(f"repository {name} must be an object")
        commit = entry.get("commit")
        if not isinstance(commit, str) or not SHA_PATTERN.fullmatch(commit):
            raise CompatibilityError(f"repository {name} commit must be an exact 40-byte hex SHA")
        repository = entry.get("repository")
        if not isinstance(repository, str) or repository.count("/") != 1:
            raise CompatibilityError(f"repository {name} has an invalid GitHub repository name")
        checkout_path = entry.get("checkout_path")
        if not isinstance(checkout_path, str) or not checkout_path:
            raise CompatibilityError(f"repository {name} checkout_path must be non-empty")
        if checkout_path in checkout_paths:
            raise CompatibilityError(f"duplicate checkout_path: {checkout_path}")
        checkout_paths.add(checkout_path)
        roles = entry.get("roles")
        if not isinstance(roles, list) or not roles or not all(isinstance(role, str) for role in roles):
            raise CompatibilityError(f"repository {name} roles must be a non-empty string array")

    train = document.get("train")
    if not isinstance(train, dict) or not isinstance(train.get("merge_order"), list):
        raise CompatibilityError("train.merge_order must be an array")
    merge_order = train["merge_order"]
    if len(merge_order) != len(set(merge_order)):
        raise CompatibilityError("train.merge_order contains duplicates")
    if set(merge_order) != set(repositories):
        raise CompatibilityError("train.merge_order must list every repository exactly once")
    ordering_constraints = [
        ("arkret-spec", "arkret-rust-sdk"),
        ("arkret-rust-sdk", "soland"),
        ("arkret-rust-sdk", "coauth"),
        ("arkret-rust-sdk", "garth"),
        ("floria", "soland"),
        ("garth", "inkson"),
        ("chime", "inkson"),
        ("inkson", "cotest"),
        ("soland", "cotest"),
        ("coauth", "cotest"),
    ]
    positions = {repository: position for position, repository in enumerate(merge_order)}
    for predecessor, successor in ordering_constraints:
        if predecessor in positions and successor in positions:
            if positions[predecessor] >= positions[successor]:
                raise CompatibilityError(
                    f"train.merge_order must place {predecessor} before {successor}"
                )

    probes = document.get("public_model_probes")
    if not isinstance(probes, list) or not probes:
        raise CompatibilityError("public_model_probes must be non-empty")
    for probe in probes:
        if not isinstance(probe, dict):
            raise CompatibilityError("public model probe must be an object")
        repository = probe.get("repository")
        if repository not in repositories:
            raise CompatibilityError(f"public model probe references unknown repository: {repository}")
        fields = probe.get("required_fields")
        if not isinstance(fields, list) or not fields or len(fields) != len(set(fields)):
            raise CompatibilityError(f"public model probe {probe.get('type')} has invalid required_fields")
        if not all(isinstance(field, str) and field for field in fields):
            raise CompatibilityError(f"public model probe {probe.get('type')} has invalid field name")

    artifact_probes = document.get("artifact_probes")
    if not isinstance(artifact_probes, list) or not artifact_probes:
        raise CompatibilityError("artifact_probes must be non-empty")
    for probe in artifact_probes:
        if not isinstance(probe, dict) or probe.get("repository") not in repositories:
            raise CompatibilityError("artifact probe references an unknown repository")
        if probe.get("kind") not in {"operation", "schema", "registry"}:
            raise CompatibilityError("artifact probe kind must be operation, schema, or registry")

    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        raise CompatibilityError("checks must be non-empty")
    check_ids: set[str] = set()
    covered_repositories: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise CompatibilityError("check must be an object")
        check_id = check.get("id")
        if not isinstance(check_id, str) or not check_id or check_id in check_ids:
            raise CompatibilityError(f"invalid or duplicate check id: {check_id}")
        check_ids.add(check_id)
        repository = check.get("repository")
        if repository not in repositories:
            raise CompatibilityError(f"check {check_id} references unknown repository: {repository}")
        covered_repositories.add(repository)
        if check.get("category") not in {"static", "compile", "contract"}:
            raise CompatibilityError(f"check {check_id} has invalid category")
        surface = check.get("surface")
        if not isinstance(surface, dict) or surface.get("kind") not in {
            "operation",
            "schema",
            "type",
        } or not isinstance(surface.get("name"), str):
            raise CompatibilityError(f"check {check_id} must identify an operation/schema/type surface")
        command = check.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(argument, str) and argument for argument in command
        ):
            raise CompatibilityError(f"check {check_id} command must be a non-empty argv array")

    compile_repositories = {"arkret-rust-sdk", "soland", "coauth", "garth", "inkson", "cotest"}
    missing_compile_checks = compile_repositories - covered_repositories
    if missing_compile_checks:
        raise CompatibilityError(
            "manifest missing repository checks: " + ", ".join(sorted(missing_compile_checks))
        )

    policy = document.get("policy")
    techniques = policy.get("forbidden_compatibility_techniques") if isinstance(policy, dict) else None
    if not isinstance(techniques, list) or not REQUIRED_POLICY.issubset(set(techniques)):
        raise CompatibilityError("manifest policy does not forbid every compatibility masking technique")
    if not isinstance(policy.get("required_status_check"), str) or not policy["required_status_check"]:
        raise CompatibilityError("manifest policy required_status_check must be non-empty")
    source_guards = policy.get("source_guards")
    if not isinstance(source_guards, list) or len(source_guards) < 3:
        raise CompatibilityError("manifest policy source_guards must contain every masking guard")
    guard_ids: set[str] = set()
    for guard in source_guards:
        if not isinstance(guard, dict) or not isinstance(guard.get("id"), str):
            raise CompatibilityError("source guard must have an id")
        if guard["id"] in guard_ids:
            raise CompatibilityError(f"duplicate source guard id: {guard['id']}")
        guard_ids.add(guard["id"])
        guard_repositories = guard.get("repositories")
        if not isinstance(guard_repositories, list) or not guard_repositories:
            raise CompatibilityError(f"source guard {guard['id']} has no repositories")
        unknown_guard_repositories = set(guard_repositories) - set(repositories)
        if unknown_guard_repositories:
            raise CompatibilityError(
                f"source guard {guard['id']} references unknown repositories: "
                + ", ".join(sorted(unknown_guard_repositories))
            )
        try:
            re.compile(guard.get("pattern", ""))
        except re.error as error:
            raise CompatibilityError(f"source guard {guard['id']} has invalid regex: {error}") from error


def repository_root(document: dict[str, Any], workspace_root: Path, repository: str) -> Path:
    entry = document["repositories"][repository]
    return workspace_root / entry["checkout_path"]


def extract_public_fields(source: str, type_name: str) -> set[str]:
    short_name = type_name.rsplit("::", 1)[-1]
    declaration = re.search(rf"\bpub\s+struct\s+{re.escape(short_name)}\s*\{{", source)
    if declaration is None:
        raise CompatibilityError(f"type {type_name} declaration not found")
    start = declaration.end()
    depth = 1
    position = start
    while position < len(source) and depth:
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
        position += 1
    if depth:
        raise CompatibilityError(f"type {type_name} has an unterminated declaration")
    body = source[start : position - 1]
    return set(re.findall(r"^\s*pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", body, re.MULTILINE))


def check_public_models(document: dict[str, Any], workspace_root: Path) -> None:
    for probe in document["public_model_probes"]:
        path = repository_root(document, workspace_root, probe["repository"]) / probe["source"]
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            raise CompatibilityError(
                f"type {probe['type']} source could not be read: {path}: {error}"
            ) from error
        actual_fields = extract_public_fields(source, probe["type"])
        for field in probe["required_fields"]:
            if field not in actual_fields:
                raise CompatibilityError(f"type {probe['type']} missing field {field}")


def check_artifacts(document: dict[str, Any], workspace_root: Path) -> None:
    for probe in document["artifact_probes"]:
        path = repository_root(document, workspace_root, probe["repository"]) / probe["path"]
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise CompatibilityError(
                f"{probe['kind']} {probe['name']} missing at {path}: {error}"
            ) from error
        except json.JSONDecodeError as error:
            raise CompatibilityError(
                f"{probe['kind']} {probe['name']} is not valid JSON: {path}: {error}"
            ) from error
        if not isinstance(parsed, (dict, list)):
            raise CompatibilityError(f"{probe['kind']} {probe['name']} must contain a JSON object or array")


def check_source_guards(document: dict[str, Any], workspace_root: Path) -> None:
    excluded_directories = {".git", "node_modules", "target", "vendor"}
    source_suffixes = {".rs", ".ts", ".tsx"}
    guards_by_repository: dict[str, list[tuple[dict[str, Any], re.Pattern[str]]]] = {}
    for guard in document["policy"]["source_guards"]:
        pattern = re.compile(guard["pattern"])
        for repository in guard["repositories"]:
            guards_by_repository.setdefault(repository, []).append((guard, pattern))

    for repository, guards in guards_by_repository.items():
        root = repository_root(document, workspace_root, repository)
        for current_root, directory_names, file_names in os.walk(root):
            directory_names[:] = [
                name for name in directory_names if name not in excluded_directories
            ]
            current_path = Path(current_root)
            for file_name in file_names:
                path = current_path / file_name
                if path.suffix not in source_suffixes:
                    continue
                relative = f"{repository}/{path.relative_to(root).as_posix()}"
                source = path.read_text(encoding="utf-8", errors="replace")
                for guard, pattern in guards:
                    if relative in set(guard.get("allow_paths", [])):
                        continue
                    match = pattern.search(source)
                    if match is not None:
                        line = source.count("\n", 0, match.start()) + 1
                        raise CompatibilityError(
                            f"policy {guard['id']} matched {relative}:{line}"
                        )


def verify_workspace_heads(document: dict[str, Any], workspace_root: Path) -> None:
    for repository, entry in document["repositories"].items():
        checkout = workspace_root / entry["checkout_path"]
        try:
            actual = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise CompatibilityError(f"repository {repository} is not a readable git checkout") from error
        if actual != entry["commit"]:
            raise CompatibilityError(
                f"repository {repository} HEAD mismatch: expected {entry['commit']}, got {actual}"
            )
        dirty = subprocess.run(
            ["git", "-C", str(checkout), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if dirty:
            raise CompatibilityError(
                f"repository {repository} has uncommitted files outside the exact manifest commit"
            )


def snapshot_workspace_heads(
    document: dict[str, Any], workspace_root: Path, allow_dirty: bool = False
) -> dict[str, Any]:
    validate_manifest(document)
    snapshot = copy.deepcopy(document)
    snapshot.pop("resolved_candidates", None)
    for repository, entry in snapshot["repositories"].items():
        checkout = workspace_root / entry["checkout_path"]
        try:
            commit = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise CompatibilityError(f"repository {repository} is not a readable git checkout") from error
        if not SHA_PATTERN.fullmatch(commit):
            raise CompatibilityError(f"repository {repository} returned an invalid HEAD: {commit}")
        dirty = subprocess.run(
            ["git", "-C", str(checkout), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if dirty:
            if not allow_dirty:
                raise CompatibilityError(
                    f"repository {repository} is dirty; commit candidates before taking a snapshot"
                )
            # The pin names HEAD, so uncommitted work is simply not in the
            # candidate set. Say so on stderr: a silently narrowed snapshot is
            # how a pin ends up claiming a set nobody verified.
            print(
                f"warning: {repository} had uncommitted files at snapshot time; "
                f"the pin {commit} does not contain them",
                file=sys.stderr,
            )
        entry["commit"] = commit
    return snapshot


def check_workspace(
    document: dict[str, Any], workspace_root: Path, verify_heads: bool = False
) -> None:
    validate_manifest(document)
    if verify_heads:
        verify_workspace_heads(document, workspace_root)
    check_artifacts(document, workspace_root)
    check_public_models(document, workspace_root)
    check_source_guards(document, workspace_root)


def parse_candidates(values: Iterable[str]) -> dict[str, str]:
    candidates: dict[str, str] = {}
    for value in values:
        name, separator, commit = value.partition("=")
        if not separator or not name or not SHA_PATTERN.fullmatch(commit):
            raise CompatibilityError(f"candidate must use repository=<40-hex-sha>: {value}")
        candidates[name] = commit
    return candidates


def resolve_manifest(document: dict[str, Any], candidates: dict[str, str]) -> dict[str, Any]:
    validate_manifest(document)
    unknown = set(candidates) - set(document["repositories"])
    if unknown:
        raise CompatibilityError("candidate references unknown repositories: " + ", ".join(sorted(unknown)))
    resolved = copy.deepcopy(document)
    for repository, commit in candidates.items():
        resolved["repositories"][repository]["commit"] = commit
    resolved["resolved_candidates"] = [
        {"repository": repository, "commit": candidates[repository]}
        for repository in resolved["train"]["merge_order"]
        if repository in candidates
    ]
    return resolved


def write_github_outputs(document: dict[str, Any], output_path: Path) -> None:
    lines = []
    for repository, entry in document["repositories"].items():
        key = repository.replace("-", "_")
        lines.append(f"{key}={entry['commit']}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_checks(
    document: dict[str, Any],
    workspace_root: Path,
    categories: set[str],
    skipped: set[str],
) -> None:
    for check in document["checks"]:
        if check["category"] not in categories or check["id"] in skipped:
            continue
        working_directory = workspace_root / check["working_directory"]
        print(f"==> {check['id']}: {' '.join(check['command'])}", flush=True)
        try:
            completed = subprocess.run(check["command"], cwd=working_directory, check=False)
        except OSError as error:
            completed_code = 127
            detail = str(error)
        else:
            completed_code = completed.returncode
            detail = "command exited non-zero"
        if completed_code:
            failure = {
                "check_id": check["id"],
                "repository": check["repository"],
                "surface": check["surface"],
                "exit_code": completed_code,
                "detail": detail,
            }
            raise CompatibilityError("first_incompatibility=" + json.dumps(failure, sort_keys=True))


def negative_mutation(document: dict[str, Any], workspace_root: Path) -> str:
    validate_manifest(document)
    probe = document["public_model_probes"][0]
    repository = probe["repository"]
    source_path = repository_root(document, workspace_root, repository) / probe["source"]
    source = source_path.read_text(encoding="utf-8")
    field = probe["required_fields"][0]
    pattern = re.compile(rf"^\s*pub\s+{re.escape(field)}\s*:[^\n]*\n", re.MULTILINE)
    mutated, replacements = pattern.subn("", source, count=1)
    if replacements != 1:
        raise CompatibilityError(f"negative mutation could not delete field {field}")

    with tempfile.TemporaryDirectory(prefix="arkret-compat-negative-") as temporary:
        temporary_root = Path(temporary)
        mutated_path = (
            temporary_root
            / document["repositories"][repository]["checkout_path"]
            / probe["source"]
        )
        mutated_path.parent.mkdir(parents=True)
        mutated_path.write_text(mutated, encoding="utf-8")
        try:
            check_public_models({"repositories": document["repositories"], "public_model_probes": [probe]}, temporary_root)
        except CompatibilityError as error:
            expected = f"type {probe['type']} missing field {field}"
            if str(error) != expected:
                raise CompatibilityError(
                    f"negative mutation failed for an unexpected reason: {error}"
                ) from error
            return expected
    raise CompatibilityError("negative mutation was not rejected")


def default_manifest_path() -> Path:
    return Path(__file__).resolve().parents[1] / "compatibility" / "manifest.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="validate manifest and static probes")
    check_parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    check_parser.add_argument("--workspace-root", type=Path, required=True)
    check_parser.add_argument("--verify-workspace-heads", action="store_true")

    resolve_parser = subparsers.add_parser("resolve", help="resolve candidate commits")
    resolve_parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    resolve_parser.add_argument("--candidate", action="append", default=[])
    resolve_parser.add_argument("--output", type=Path, required=True)
    resolve_parser.add_argument("--github-output", type=Path)

    snapshot_parser = subparsers.add_parser(
        "snapshot", help="generate an exact manifest from sibling checkout HEADs"
    )
    snapshot_parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    snapshot_parser.add_argument("--workspace-root", type=Path, required=True)
    snapshot_parser.add_argument("--output", type=Path, required=True)
    snapshot_parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help=(
            "pin HEAD even where a checkout has uncommitted files, naming each "
            "such repository on stderr; needed in a shared workspace where the "
            "cleanliness of sibling checkouts is not under the caller's control"
        ),
    )

    run_parser = subparsers.add_parser("run", help="execute ordered manifest checks")
    run_parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    run_parser.add_argument("--workspace-root", type=Path, required=True)
    run_parser.add_argument(
        "--category",
        action="append",
        choices=["static", "compile", "contract"],
        default=[],
    )
    run_parser.add_argument("--skip", action="append", default=[])

    negative_parser = subparsers.add_parser(
        "negative-mutation", help="prove a deleted SDK field is rejected"
    )
    negative_parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    negative_parser.add_argument("--workspace-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        document = load_manifest(arguments.manifest)
        if arguments.command == "check":
            check_workspace(document, arguments.workspace_root, arguments.verify_workspace_heads)
            print("compatibility manifest and static probes are valid")
        elif arguments.command == "resolve":
            resolved = resolve_manifest(document, parse_candidates(arguments.candidate))
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(
                json.dumps(resolved, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            if arguments.github_output:
                write_github_outputs(resolved, arguments.github_output)
            print(f"resolved compatibility manifest written to {arguments.output}")
        elif arguments.command == "snapshot":
            snapshot = snapshot_workspace_heads(
                document, arguments.workspace_root, arguments.allow_dirty
            )
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(
                json.dumps(snapshot, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            print(f"compatibility manifest snapshot written to {arguments.output}")
        elif arguments.command == "run":
            validate_manifest(document)
            categories = set(arguments.category) or {"static", "compile", "contract"}
            known_checks = {check["id"] for check in document["checks"]}
            unknown_skips = set(arguments.skip) - known_checks
            if unknown_skips:
                raise CompatibilityError("unknown skipped checks: " + ", ".join(sorted(unknown_skips)))
            run_checks(document, arguments.workspace_root, categories, set(arguments.skip))
            print("selected compatibility checks passed")
        elif arguments.command == "negative-mutation":
            failure = negative_mutation(document, arguments.workspace_root)
            print(f"negative mutation rejected as expected: {failure}")
        else:
            parser.error(f"unsupported command: {arguments.command}")
    except CompatibilityError as error:
        print(f"compatibility gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
