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
            "Row", "Rows", "Results", "Wrapper", "Info", "Details", "ResBody", "ReqBody")
RETIRED = set(json.loads((ROOT / "tools/retired-public-type-names.json").read_text(encoding="utf-8"))["types"])
CANONICAL_TYPE_OWNERS = {
    "AgentLifecycleState": "models-identity/src/agent_signer_state.rs",
    "IssuerAuthorityRef": "models-collaboration/src/governance/grant_constraint.rs",
    "DidBindingPurpose": "identity/src/binding.rs",
    "AccountDidBindingPurpose": "models-identity/src/account.rs",
}


EXCEPTIONS = {
    ("wire/src/platform.rs", "WasmHttpResponse"):
        "Local browser transport carrier for an HTTP response, not an Arkret operation DTO.",
    ("models-collaboration/src/governance/realm_join_intake.rs", "RealmJoinCandidate"):
        "Domain subject: a candidate service for joining a Realm.",
    ("models-collaboration/src/call_signal.rs", "IceCandidate"):
        "External ICE candidate term.",
    ("models-collaboration/src/governance/generated/moderation_queue_contracts.rs", "ModerationQueueItem"):
        "First-class moderation queue object with its own registered identifier and schema.",
    ("models-collaboration/src/governance/realm_governance.rs", "RealmLinkTransitionCandidate"):
        "Non-wire borrowed input to the local transition evaluator.",
    ("models-collaboration/src/objects/productivity.rs", "RsvpResponse"):
        "Domain RSVP answer, not an endpoint response wrapper.",
}


def row_reexports(masked: str) -> list[str]:
    return [name for body in re.findall(r"\bpub\s+use\s+([^;]+);", masked)
            for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", body)
            if name.endswith(('Row', 'Rows'))]


def retired_reexports(masked: str) -> list[str]:
    return [name for body in re.findall(r"\bpub\s+use\s+([^;]+);", masked)
            for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", body) if name in RETIRED]


def public_aliases(masked: str):
    for match in re.finditer(r'\bpub\s+type\s+(\w+)', masked):
        stack = []
        for position in range(match.end(), len(masked)):
            token = masked[position]
            if token in '<([{':
                stack.append(token)
            elif token in '>)]}' and stack and stack[-1] == dict(zip('>)]}', '<([{'))[token]:
                stack.pop()
            elif token == '=' and not stack:
                yield match[1], masked[position + 1:masked.index(';', position)].strip()
                break
            elif token == ';' and not stack:
                break


def noncanonical_aliases(masked: str) -> list[str]:
    errors = [name for name, value in public_aliases(masked)
              if name.endswith('Result') and name not in RETIRED
              and not re.match(r'(?:(?:[A-Za-z_]\w*)::)*Result\s*<', value)]
    for body in re.findall(r'\bpub\s+use\s+([^;]+);', masked):
        for origin, name in re.findall(r'\b(\w+)\s+as\s+(\w+)', body):
            if name in RETIRED or name.endswith(('Row', 'Rows')):
                continue
            if (name.endswith(('RequestBody', 'ResponseBody', 'Results'))
                    or (name.endswith('Result') and not origin.endswith('Result'))):
                errors.append(name)
    return errors


def canonical_owner_errors(path: str, source: str) -> list[str]:
    from wire_value_audit import mask_non_code
    masked = mask_non_code(source)
    names = DECLARATION.findall(masked) + [name for name, _ in public_aliases(masked)]
    names += [name for body in re.findall(r"\bpub\s+use\s+([^;]+);", masked)
              for name in re.findall(r"\bas\s+(\w+)", body)]
    return [f"{path}: {name}: reuse canonical owner {CANONICAL_TYPE_OWNERS[name]}"
            for name in names if name in CANONICAL_TYPE_OWNERS and path != CANONICAL_TYPE_OWNERS[name]]


def violations(path: str, source: str) -> list[str]:
    # Reuse the audit lexer so declarations in comments and strings do not count.
    from wire_value_audit import mask_non_code

    masked = mask_non_code(source)
    errors = [name for name in DECLARATION.findall(masked)
              if name in RETIRED or (name.endswith(REJECTED) and (path, name) not in EXCEPTIONS)]
    errors.extend(name for name in re.findall(r'\bpub\s+type\s+(\w+)', masked)
                  if name in RETIRED or name.endswith(('RequestBody', 'ResponseBody', 'Row', 'Rows', 'Results')))
    errors.extend(row_reexports(masked))
    errors.extend(retired_reexports(masked))
    errors.extend(noncanonical_aliases(masked))
    return errors


def main() -> int:
    errors = []
    declarations = set()
    from wire_value_audit import mask_non_code
    for owner in OWNERS:
        for path in sorted((ROOT / "crates" / owner / "src").rglob("*.rs")):
            relative = path.relative_to(ROOT / "crates").as_posix()
            source = path.read_text(encoding="utf-8")
            declarations.update((relative, name) for name in DECLARATION.findall(mask_non_code(source)))
            errors.extend(canonical_owner_errors(relative, source))
            errors.extend(f"{relative}: {name}: use an R4 wrapper or a domain noun"
                          for name in violations(relative, source))
    from wire_value_audit import mask_non_code
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if "src" not in path.relative_to(ROOT / "crates").parts:
            continue
        relative = path.relative_to(ROOT / "crates").as_posix()
        if relative.split("/", 1)[0] in OWNERS:
            continue
        source = path.read_text(encoding="utf-8")
        masked = mask_non_code(source)
        errors.extend(canonical_owner_errors(relative, source))
        errors.extend(f"{relative}: {name}: public Row reexports are forbidden" for name in row_reexports(masked))
        errors.extend(f"{relative}: {name}: retired duplicate reexport" for name in retired_reexports(masked))
        for name in re.findall(r"\bpub\s+(?:struct|enum|type)\s+(\w+)", masked):
            if name.endswith(("Row", "Rows")) or name in RETIRED:
                errors.append(f"{relative}: {name}: public SDK models cannot use generic Row")
    errors.extend(f"stale type-name exception: {path}::{name}"
                  for path, name in EXCEPTIONS if (path, name) not in declarations)
    errors.extend(f"redundant type-name exception: {path}::{name}"
                  for path, name in EXCEPTIONS if not name.endswith(REJECTED))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Protocol type wrapper names passed ({len(declarations)} declarations; "
          f"{len(EXCEPTIONS)} exact domain/implementation exceptions).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
