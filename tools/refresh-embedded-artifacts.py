#!/usr/bin/env python3
"""Refresh crates/core/src/schema/embedded_artifacts.json from the live spec.

The embedded snapshot is a single JSON object mapping the artifact path
(relative to arkret-spec/spec/v1/artifacts, forward slashes) to the parsed
artifact JSON. The drift gate
`schema::tests::embedded_spec_artifacts_match_live_spec_when_available`
compares path sets and parsed values against a co-checkout of arkret-spec;
run this script after any spec artifacts change, then re-run that test.

Usage: python tools/refresh-embedded-artifacts.py [path-to-spec-artifacts]
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_ARTIFACTS = REPO.parent / "arkret-spec" / "spec" / "v1" / "artifacts"
TARGET = REPO / "crates" / "core" / "src" / "schema" / "embedded_artifacts.json"


def main() -> int:
    artifacts = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ARTIFACTS
    if not artifacts.is_dir():
        print(f"spec artifacts dir not found: {artifacts}", file=sys.stderr)
        return 1

    snapshot: dict[str, object] = {}
    for path in sorted(artifacts.rglob("*.json")):
        rel = path.relative_to(artifacts).as_posix()
        with open(path, encoding="utf-8") as f:
            snapshot[rel] = json.load(f)

    out = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    with open(TARGET, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print(f"embedded {len(snapshot)} artifacts -> {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
