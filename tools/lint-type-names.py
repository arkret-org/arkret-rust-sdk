#!/usr/bin/env python3
"""Check public protocol type wrapper names against common-fields.md R4.

Rust error aliases and SDK implementation types are outside this check. Domain
subjects and external terms have exact owner/name exceptions, never suffix-wide
exemptions. Wire field names and schema fragments are independent of Rust names.
"""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OWNERS = ("wire", "models-identity", "models-crypto", "models-collaboration",
          "models-discovery", "models-integration")
DECLARATION = re.compile(r"\bpub\s+(?:struct|enum)\s+(\w+)")
REJECTED = ("Result", "Candidate", "Item", "ResponseBody", "Response",
            "Wrapper", "Info", "Details", "ResBody", "ReqBody")
EXCEPTIONS = {
    ("wire/src/generated/event_kinds.rs", "ContainerMoveItem"):
        "Generated Event-kind marker for moving a domain item, not a wrapper.",
    ("wire/src/platform.rs", "WasmHttpResponseBody"):
        "Local browser transport carrier for an HTTP response, not an Arkret operation DTO.",
    ("models-collaboration/src/governance/realm_join_intake.rs", "RealmJoinCandidate"):
        "Domain subject: a candidate service for joining a Realm.",
    ("models-discovery/src/realm_join_preview.rs", "RealmJoinCandidate"):
        "Domain subject: a candidate service for joining a Realm.",
    ("models-collaboration/src/call_signal.rs", "IceCandidate"):
        "External ICE candidate term.",
    ("models-collaboration/src/events_payloads/call.rs", "CallStatePayloadRecordingResult"):
        "Domain artifact: a produced call recording, not an endpoint result wrapper.",
    ("models-collaboration/src/events_payloads/call.rs", "CallStatePayloadTranscriptResult"):
        "Domain artifact: a produced call transcript, not an endpoint result wrapper.",
    ("models-collaboration/src/events_payloads/poll.rs", "PollResponseBody"):
        "Domain response to a poll inside a content block, not an HTTP response.",
    ("models-collaboration/src/sync_frames/account_subscribe.rs", "AccountSubscribeSnapshotResult"):
        "Non-wire SDK orchestration result; no serialization or schema component.",
    ("models-collaboration/src/governance/moderation_queue.rs", "ModerationQueueItem"):
        "First-class moderation queue object with its own registered identifier and schema.",
    ("models-collaboration/src/governance/realm_governance.rs", "RealmLinkTransitionCandidate"):
        "Non-wire borrowed input to the local transition evaluator.",
    ("models-collaboration/src/objects/mimi.rs", "MimiGroupInfo"):
        "External MLS GroupInfo term in the MIMI binding.",
    ("models-collaboration/src/objects/interop.rs", "GroupInfo"):
        "External MLS GroupInfo term in the MIMI binding.",
    ("models-collaboration/src/objects/productivity.rs", "RsvpResponse"):
        "Domain RSVP answer, not an endpoint response wrapper.",
}


def violations(path: str, source: str) -> list[str]:
    # Reuse the audit lexer so declarations in comments and strings do not count.
    from wire_value_audit import mask_non_code

    return [name for name in DECLARATION.findall(mask_non_code(source))
            if name.endswith(REJECTED) and (path, name) not in EXCEPTIONS]


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
