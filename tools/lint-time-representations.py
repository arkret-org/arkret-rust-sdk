#!/usr/bin/env python3
"""Reject drift from Arkret's canonical UTC-millisecond wire profile."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "crates"
EXTERNAL_FORMATTER_FILES = {Path("crates/signatures/src/webvh/inception.rs")}
EXTERNAL_DATETIME_FIELDS = {
    (Path("crates/identity/src/resolvers/did_webvh.rs"), "version_time"),
    (Path("crates/models-identity/src/service_identity.rs"), "version_time"),
    (Path("crates/models-integration/src/applet/registration.rs"), "version_time"),
    (Path("crates/signatures/src/webvh/inception.rs"), "version_time"),
}


def main() -> int:
    errors: list[str] = []
    for path in sorted(CRATES.rglob("*.rs")):
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bexpires_at_unix(?:_ms)?\b", text):
            errors.append(f"{relative}: Arkret wire instant must not use expires_at_unix*")
        if (
            "to_rfc3339_opts" in text
            and relative not in EXTERNAL_FORMATTER_FILES
            and relative != Path("crates/canonical/src/canonical.rs")
        ):
            errors.append(f"{relative}: use the shared canonical timestamp formatter")
        if re.search(r"\.to_rfc3339\(\)", text):
            errors.append(f"{relative}: use the shared canonical timestamp formatter")
        if relative in {
            Path("crates/wire/src/cursor.rs"),
            Path("crates/server/src/cursor_authority.rs"),
        }:
            for pattern in (r"\bcursor\.t\b", r"\bcursor\.x\b", r"\bpub\s+[tx]\s*:"):
                if re.search(pattern, text):
                    errors.append(f"{relative}: retired cursor t/x representation remains")

    for path in sorted(CRATES.rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        depth = 0
        serde_struct_depth: int | None = None
        pending_serde = False
        derive_buffer: list[str] | None = None
        for index, line in enumerate(lines):
            if derive_buffer is None and "#[derive(" in line:
                derive_buffer = [line]
            elif derive_buffer is not None:
                derive_buffer.append(line)
            if derive_buffer is not None and ")]" in line:
                pending_serde = bool(
                    re.search(r"\b(?:Serialize|Deserialize)\b", "\n".join(derive_buffer))
                )
                derive_buffer = None
            if pending_serde and re.search(r"\b(?:struct|enum)\b", line) and "{" in line:
                serde_struct_depth = depth + line.count("{") - line.count("}")
                pending_serde = False
            field = re.search(
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*"
                r".*(?:chrono::)?DateTime<(?:chrono::)?Utc>",
                line,
            )
            if field and serde_struct_depth is not None and depth >= serde_struct_depth:
                relative = path.relative_to(ROOT)
                context = "\n".join(lines[max(0, index - 12) : index])
                if (
                    (relative, field.group(1)) not in EXTERNAL_DATETIME_FIELDS
                    and "canonical_timestamp" not in context
                ):
                    errors.append(
                        f"{relative}:{index + 1}: serde DateTime field lacks canonical timestamp adapter"
                    )
            depth += line.count("{") - line.count("}")
            if serde_struct_depth is not None and depth < serde_struct_depth:
                serde_struct_depth = None

    if errors:
        print("time representation lint failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("time representation lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
