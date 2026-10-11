#!/usr/bin/env python3
"""Enforce the frozen crate-layering rules for the Arkret SDK workspace.

Rules source: arkret-work/refactor/tasks/2026-09-06-0913-local-gates-and-dependency-evidence.md.
The phase-0 data/runtime separation remains frozen. Precise carrier ownership
amendments below do not permit arbitrary cross-domain or runtime dependencies.

Checks:
  1. Every direct arkret->arkret normal/optional edge must be declared in
     ALLOWED_EDGES.
  2. Data crates (wire/model layer) must not pull runtime, framework, or
     crypto-machine third-party packages in their no-default-features
     normal graph.
  3. No workspace crate may depend on the umbrella package `arkret`.
  4. Any workspace crate named `arkret-*` that is missing from ALLOWED_EDGES
     is a failure: new crates must be registered here consciously.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Crates whose no-default-features normal graph must stay free of
# FORBIDDEN_THIRD_PARTY packages.
DATA_CRATES = (
    "arkret-canonical",
    "arkret-identifiers",
    "arkret-wire",
    "arkret-models-identity",
    "arkret-models-crypto",
    "arkret-models-collaboration",
    "arkret-models-integration",
    "arkret-models-discovery",
    "arkret-models",
    "arkret-schema",
    "arkret-policy",
    "arkret-state",
)

FORBIDDEN_THIRD_PARTY = {
    "aws-lc-sys",
    "diesel",
    "openmls",
    "reqwest",
    "salvo",
    "salvo-oapi",
    "tokio",
    "zstd-sys",
}

_BASE = {"arkret-canonical", "arkret-identifiers"}
_WIRE = _BASE | {"arkret-wire"}

# Target allowed direct arkret->arkret edges (normal + optional deps).
# Keys cover every current and planned workspace crate; the umbrella
# `arkret` is exempt (it may depend on everything).
ALLOWED_EDGES: dict[str, set[str]] = {
    "arkret-canonical": set(),
    "arkret-identifiers": {"arkret-canonical"},
    "arkret-wire": _BASE,
    # arkret-locale owns the single UI-locale vocabulary and is a leaf (no
    # arkret deps), so the account-profile `preferred_locale` field can take it
    # directly without giving the model layer a runtime dependency.
    "arkret-locale": set(),
    # Account-device signer evidence contains the crypto model's typed device
    # projection. Crypto models are now a leaf data domain: the former reverse
    # identity edge is removed, so the declared graph stays acyclic.
    "arkret-models-identity": _WIRE | {"arkret-locale", "arkret-models-crypto"},
    "arkret-models-crypto": _WIRE,
    # Current-result DTOs validate the generated family schemas with the pure
    # schema registry. That registry depends only on the wire layer, so this
    # edge introduces neither a cycle nor transport/runtime machinery.
    "arkret-models-collaboration": _WIRE
    | {"arkret-models-identity", "arkret-models-crypto", "arkret-schema"},
    # ae2bd748f5973b57df8c09d888651080b716be4e removed the duplicate
    # AppletCommittedEvent DTO: integration reexports its sole collaboration
    # owner, including retained device evidence and exact authority cuts.
    "arkret-models-integration": _WIRE
    | {"arkret-models-identity", "arkret-models-collaboration"},
    "arkret-models-discovery": _WIRE | {"arkret-models-identity"},
    "arkret-models": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-integration",
        "arkret-models-discovery",
    },
    "arkret-schema": _WIRE,
    # R2 (frozen): no policy -> state edge.
    # Amendment 2026-07-19 (phase 1A): policy -> models-integration allowed —
    # the blind-payload sanitizer consumes the push wire vocabulary owned by
    # models-integration; behavior depending on data is the correct direction.
    "arkret-policy": _WIRE
    | {
        "arkret-event-draft",
        "arkret-schema",
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-integration",
    },
    # The reducer-profile registry is generated into arkret-wire
    # (`ReducerProfileId`), so the state resolver rejects an event with an
    # unregistered or non-upgradable reducer profile without needing a policy
    # edge at all.
    "arkret-state": _WIRE
    | {
        "arkret-event-draft",
        "arkret-models-crypto",
        "arkret-models-collaboration",
    },
    "arkret-lattice-registry": _WIRE
    | {"arkret-models-collaboration", "arkret-schema", "arkret-state"},
    "arkret-bootstrap": {
        "arkret-canonical",
        "arkret-event-draft",
        "arkret-lattice-registry",
        "arkret-models-collaboration",
        "arkret-models-identity",
        "arkret-state",
        "arkret-wire",
    },
    # Signatures behavior signs over data owned by four model
    # crates ("behavior depends on data"): models-identity (service-identity /
    # webvh inception contracts), models-collaboration (realm-organization
    # statement family + ephemeral proof envelope), models-discovery (DID
    # service-entry registry constants). The optional `collaboration` feature
    # also takes arkret-state, because portable Agent signer evidence is only
    # valid if the witnessed cell value recomputes to the committed state leaf
    # digest and its inclusion proof verifies; both are owned by arkret-state.
    # The same verifier projects lifecycle Event writes through arkret-schema's
    # generated registry, avoiding a duplicate hand-written cell projector.
    "arkret-signatures": _WIRE
    | {
        "arkret-event-draft",
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-discovery",
        "arkret-state",
        "arkret-schema",
    },
    # The issuing-service `Cursor` mint/validate surface is a wire sync token
    # owned by arkret-wire; arkret-hlc re-exports it, hence the wire edge.
    "arkret-hlc": _WIRE,
    # Dev-only spec drift/conformance tooling: it loads arkret-spec artifacts
    # and decodes them through the wire vocabulary. `publish = false`, and it is
    # excluded from `default-members`.
    "arkret-schema-conformance": {"arkret-schema", "arkret-wire"},
    # Dev-only shared protocol test material. It takes exactly the crates a
    # canonical signed Event needs and nothing else: no service, product or
    # model-composition crate, so it cannot become a second place where
    # protocol behavior is defined. `publish = false`, excluded from
    # `default-members`, and `tools/test_kit_production_gate.py` keeps it out of
    # every production dependency graph.
    "arkret-test-kit": _WIRE
    | {
        "arkret-event-draft",
        "arkret-signatures",
    },
    "arkret-event-draft": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-integration",
    },
    # arkret-egress-policy carries the outbound SSRF host/IP deny-list
    # classifier (STA-05-001) the did:web / did:webvh resolvers guard fetches
    # with; it is a leaf crate (no arkret deps), so the edge is cycle-free.
    # The service identity bundle backends
    # (FileIdentityBundleBackend + KeyStoreIdentityBundleBackend) are owned by
    # arkret-identity. The KeyStore-backed backend wraps a
    # `KeyStore` from arkret-keystore (a leaf crate, no arkret deps — the edge
    # is cycle-free), mirroring the batch 4b auth->keystore precedent.
    "arkret-identity": _WIRE
    | {
        "arkret-models-identity",
        # a9bb7df46fefb7f0103faca311ca23e8b17c24b7 introduced portable
        # authority verification. This behavior layer consumes the canonical
        # historical signer, handoff and invite-delivery data carriers.
        "arkret-models-collaboration",
        "arkret-signatures",
        "arkret-egress-policy",
        "arkret-keystore",
    },
    "arkret-auth": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-collaboration",
        "arkret-identity",
        "arkret-policy",
        "arkret-signatures",
        "arkret-crypto",
    },
    # R4 (frozen): no crypto -> state edge.
    # consumes the history response capability and envelope data owned by the
    # collaboration model crate. This remains a cycle-free behavior -> data
    # edge and does not give crypto access to collaboration behavior.
    "arkret-crypto": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-signatures",
    },
    "arkret-mls": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        # MLS verifies the typed Welcome trust-binding carrier owned alongside
        # the collaboration event payload. This is a cycle-free behavior ->
        # data edge; the model crate has no dependency on the MLS machine.
        "arkret-models-collaboration",
        "arkret-crypto",
        "arkret-policy",
        "arkret-signatures",
    },
    # R1 (frozen): keystore owns the trait and backends as a standalone crate
    # with no Arkret dependencies.
    "arkret-keystore": set(),
    "arkret-egress-policy": set(),
    # arkret-egress-reqwest is the composition layer over the deny-list
    # primitives: parse -> classify -> resolve DNS -> classify every answer ->
    # bind to a reqwest client. It exists because exporting only the primitives
    # left seven repositories each re-assembling that sequence by hand. Its one
    # arkret edge is to the primitives it composes, so it is cycle-free.
    "arkret-egress-reqwest": {"arkret-egress-policy"},
    "arkret-push-policy": {"arkret-models-integration"},
    "arkret-rate-limit": set(),
    # arkret-retry is pure schedule arithmetic for the normative backoff curve
    # (`api-conventions.md` §556) with no reqwest, runtime, clock or getrandom
    # dependency, so the wasm consumers can share the one implementation. Leaf
    # crate, no arkret deps.
    "arkret-retry": set(),
    # arkret-egress-policy: the did:web / did:webvh resolver in this crate is one
    # of the outbound fetchers the SSRF deny-list exists for.
    # arkret-schema: the events endpoint submits a `PreparedStandardEvent`, the
    # prepared-event contract owned by the schema crate.
    "arkret-http-client": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-discovery",
        "arkret-models-integration",
        "arkret-egress-policy",
        "arkret-egress-reqwest",
        "arkret-identity",
        "arkret-schema",
        "arkret-signatures",
        "arkret-state",
    },
    "arkret-server": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-integration",
        "arkret-models-discovery",
        # Phase 5-f: the federation transaction bodies bind
        # `arkret_event_draft::Operation`, so the server endpoint contracts
        # consume them from arkret-event-draft directly (behavior depends on
        # data). event-draft has no server dep, so the edge is cycle-free.
        "arkret-event-draft",
        "arkret-rate-limit",
        "arkret-signatures",
        "arkret-state",
    },
    "arkret-sdk-fuzz": {
        "arkret-canonical",
        "arkret-hlc",
        "arkret-identifiers",
        "arkret-models-crypto",
        "arkret-signatures",
        "arkret-wire",
    },
}

UMBRELLA = "arkret"


def cargo_metadata(root: Path) -> dict[str, object]:
    process = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(process.stdout)


def no_default_normal_tree(root: Path, package: str) -> set[str]:
    process = subprocess.run(
        [
            "cargo",
            "tree",
            "-p",
            package,
            "--no-default-features",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        line.split()[0]
        for line in process.stdout.splitlines()
        if line and not line.startswith("[")
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    metadata = cargo_metadata(root)
    packages = metadata["packages"]
    assert isinstance(packages, list)

    failures: list[str] = []

    workspace = {pkg["name"]: pkg for pkg in packages}

    for name, pkg in sorted(workspace.items()):
        if name == UMBRELLA:
            continue
        arkret_deps = {
            dep["name"]
            for dep in pkg["dependencies"]
            if dep["name"].startswith("arkret") and dep["kind"] is None
        }
        if arkret_deps and name not in ALLOWED_EDGES and not name.startswith("arkret"):
            continue
        if name not in ALLOWED_EDGES:
            failures.append(
                f"{name}: crate is not registered in ALLOWED_EDGES; "
                "register new crates consciously"
            )
            continue
        if UMBRELLA in arkret_deps:
            failures.append(f"{name}: depends on the umbrella `{UMBRELLA}`")
        allowed = ALLOWED_EDGES[name]
        for dep in sorted(arkret_deps - {UMBRELLA}):
            if dep in allowed:
                continue
            failures.append(f"{name}: forbidden edge -> {dep}")

    checked = 0
    for leaf in DATA_CRATES:
        if leaf not in workspace:
            continue
        checked += 1
        tree = no_default_normal_tree(root, leaf)
        tree.discard(leaf)
        forbidden = sorted(tree & FORBIDDEN_THIRD_PARTY)
        if forbidden:
            failures.append(f"{leaf}: forbidden third-party {', '.join(forbidden)}")

    if failures:
        print("layering violations:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"layering OK: {len(workspace) - 1} crates checked, "
        f"{checked} data crates scanned for forbidden third-party deps"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
