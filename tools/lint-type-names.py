#!/usr/bin/env python3
"""Check public protocol type wrapper names against common-fields.md R4.

Rust error aliases and SDK implementation types are outside this check. Domain
subjects and external terms have exact owner/name exceptions, never suffix-wide
exemptions. Wire field names and schema fragments are independent of Rust names.
"""

from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
OWNERS = ("wire", "models-identity", "models-crypto", "models-collaboration",
          "models-discovery", "models-integration")
DECLARATION = re.compile(r"\bpub\s+(?:struct|enum)\s+(\w+)")
REJECTED = ("Result", "Candidate", "Item", "Response",
            "Row", "Wrapper", "Info", "Details", "ResBody", "ReqBody")
RETIRED = set(json.loads((ROOT / "tools/retired-public-type-names.json").read_text(encoding="utf-8"))["types"])
EXCEPTIONS = {
    ("wire/src/platform.rs", "WasmHttpResponse"):
        "Local browser transport carrier for an HTTP response, not an Arkret operation DTO.",
    ("models-collaboration/src/governance/realm_join_intake.rs", "RealmJoinCandidate"):
        "Domain subject: a candidate service for joining a Realm.",
    ("models-collaboration/src/call_signal.rs", "IceCandidate"):
        "External ICE candidate term.",
    ("models-collaboration/src/events_payloads/call.rs", "CallRecordingMetadata"):
        "Domain artifact: a produced call recording, not an endpoint result wrapper.",
    ("models-collaboration/src/events_payloads/call.rs", "CallTranscriptMetadata"):
        "Domain artifact: a produced call transcript, not an endpoint result wrapper.",
    ("models-collaboration/src/governance/generated/moderation_queue_contracts.rs", "ModerationQueueItem"):
        "First-class moderation queue object with its own registered identifier and schema.",
    ("models-collaboration/src/governance/realm_governance.rs", "RealmLinkTransitionCandidate"):
        "Non-wire borrowed input to the local transition evaluator.",
    ("models-collaboration/src/objects/productivity.rs", "RsvpResponse"):
        "Domain RSVP answer, not an endpoint response wrapper.",
}


def row_reexports(masked: str) -> list[str]:
    return [name for body in re.findall(r"\bpub\s+use\s+([^;]+);", masked)
            for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*Row\b", body)]


def retired_reexports(masked: str) -> list[str]:
    return [name for body in re.findall(r"\bpub\s+use\s+([^;]+);", masked)
            for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", body) if name in RETIRED]


def violations(path: str, source: str) -> list[str]:
    # Reuse the audit lexer so declarations in comments and strings do not count.
    from wire_value_audit import mask_non_code

    masked = mask_non_code(source)
    errors = [name for name in DECLARATION.findall(masked)
              if name in RETIRED or (name.endswith(REJECTED) and (path, name) not in EXCEPTIONS)]
    errors.extend(name for name in re.findall(r'\bpub\s+type\s+(\w+)', masked)
                  if name in RETIRED or name.endswith(('RequestBody', 'ResponseBody', 'Row')))
    errors.extend(row_reexports(masked))
    errors.extend(retired_reexports(masked))
    return errors


def main() -> int:
    errors = []
    declarations = set()
    for owner in OWNERS:
        for path in sorted((ROOT / "crates" / owner / "src").rglob("*.rs")):
            relative = path.relative_to(ROOT / "crates").as_posix()
            source = path.read_text(encoding="utf-8")
            declarations.update((relative, name) for name in DECLARATION.findall(source))
            errors.extend(f"{relative}: {name}: use an R4 wrapper or a domain noun"
                          for name in violations(relative, source))
    from wire_value_audit import mask_non_code
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if "src" not in path.relative_to(ROOT / "crates").parts:
            continue
        relative = path.relative_to(ROOT / "crates").as_posix()
        if relative.split("/", 1)[0] in OWNERS:
            continue
        masked = mask_non_code(path.read_text(encoding="utf-8"))
        errors.extend(f"{relative}: {name}: public Row reexports are forbidden" for name in row_reexports(masked))
        errors.extend(f"{relative}: {name}: retired duplicate reexport" for name in retired_reexports(masked))
        for name in re.findall(r"\bpub\s+(?:struct|enum|type)\s+(\w+)", masked):
            if name.endswith("Row") or name in RETIRED:
                errors.append(f"{relative}: {name}: public SDK models cannot use generic Row")
    errors.extend(f"stale type-name exception: {path}::{name}"
                  for path, name in EXCEPTIONS if (path, name) not in declarations)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Protocol type wrapper names passed ({len(declarations)} declarations; "
          f"{len(EXCEPTIONS)} exact domain/implementation exceptions).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
