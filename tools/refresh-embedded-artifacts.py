#!/usr/bin/env python3
"""Generate SDK-embedded machine-readable artifacts from the live spec.

The embedded snapshot is a single JSON object mapping the artifact path
(relative to arkret-spec/spec/v1/artifacts, forward slashes) to the parsed
artifact JSON. The canonical OpenAPI YAML is copied without transformation.
The drift gates
`schema::tests::embedded_spec_artifacts_match_live_spec_when_available`
and `schema::tests::embedded_openapi_matches_live_spec_when_available`
compare both resources against a co-checkout of arkret-spec; run this script
after any spec artifacts change, then re-run those tests.

The generator deliberately embeds each artifact's raw JSON tokens instead of
round-tripping parsed numbers. This preserves protocol-significant negative
fixtures such as ``1.0`` (which must never silently become ``1``).

Usage:
  python tools/refresh-embedded-artifacts.py [path-to-spec-artifacts]
  python tools/refresh-embedded-artifacts.py --check [path-to-spec-artifacts]
  python tools/refresh-embedded-artifacts.py --openapi-only [path-to-spec-artifacts]
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_ARTIFACTS = REPO.parent / "arkret-spec" / "spec" / "v1" / "artifacts"
TARGET = REPO / "crates" / "schema" / "src" / "embedded_artifacts.json"
OPENAPI_RELATIVE_PATH = Path("openapi") / "arkret-service-api.openapi.yaml"
OPENAPI_TARGET = REPO / "crates" / "schema" / "src" / "embedded_openapi.yaml"


def minify_json_preserving_number_lexemes(raw: str) -> str:
    """Remove insignificant JSON whitespace without rewriting any token."""
    output: list[str] = []
    in_string = False
    escaped = False
    for char in raw:
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            output.append(char)
        elif not char.isspace():
            output.append(char)
    if in_string or escaped:
        raise ValueError("unterminated JSON string")
    return "".join(output)


def build_snapshot(artifacts: Path) -> str:
    entries: list[str] = []
    for path in sorted(artifacts.rglob("*.json")):
        rel = path.relative_to(artifacts).as_posix()
        raw = path.read_text(encoding="utf-8")
        json.loads(raw)
        entries.append(
            f"{json.dumps(rel, ensure_ascii=False, separators=(',', ':'))}:"
            f"{minify_json_preserving_number_lexemes(raw)}"
        )
    return "{" + ",".join(entries) + "}"


def write_atomic(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=target.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--openapi-only", action="store_true")
    parser.add_argument("artifacts", nargs="?", type=Path, default=DEFAULT_ARTIFACTS)
    args = parser.parse_args(argv)
    artifacts = args.artifacts
    if not artifacts.is_dir():
        print(f"spec artifacts dir not found: {artifacts}", file=sys.stderr)
        return 1

    openapi_source = artifacts / OPENAPI_RELATIVE_PATH
    if not openapi_source.is_file():
        print(f"spec OpenAPI artifact not found: {openapi_source}", file=sys.stderr)
        return 1
    openapi_output = openapi_source.read_text(encoding="utf-8")

    if args.openapi_only:
        if args.check:
            if (
                not OPENAPI_TARGET.is_file()
                or OPENAPI_TARGET.read_text(encoding="utf-8") != openapi_output
            ):
                print(
                    "embedded OpenAPI artifact drifted; run "
                    "python tools/refresh-embedded-artifacts.py --openapi-only",
                    file=sys.stderr,
                )
                return 1
            print("embedded OpenAPI artifact is current")
            return 0
        write_atomic(OPENAPI_TARGET, openapi_output)
        print(f"embedded OpenAPI artifact -> {OPENAPI_TARGET}")
        return 0

    output = build_snapshot(artifacts)
    artifact_count = sum(1 for _ in artifacts.rglob("*.json"))
    if args.check:
        json_drifted = (
            not TARGET.is_file() or TARGET.read_text(encoding="utf-8") != output
        )
        openapi_drifted = (
            not OPENAPI_TARGET.is_file()
            or OPENAPI_TARGET.read_text(encoding="utf-8") != openapi_output
        )
        if json_drifted or openapi_drifted:
            print(
                "embedded artifact resources drifted; run "
                "python tools/refresh-embedded-artifacts.py",
                file=sys.stderr,
            )
            return 1
        print(
            "embedded artifact resources are current "
            f"({artifact_count} JSON artifacts + OpenAPI)"
        )
        return 0

    write_atomic(TARGET, output)
    write_atomic(OPENAPI_TARGET, openapi_output)
    print(f"embedded {artifact_count} JSON artifacts -> {TARGET}")
    print(f"embedded OpenAPI artifact -> {OPENAPI_TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
