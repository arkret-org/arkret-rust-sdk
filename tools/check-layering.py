#!/usr/bin/env python3
"""Enforce the frozen crate-layering rules for the Arkret SDK workspace.

Rules source: cotask/work/active/2026-07-19-arkret-rust-sdk-crate-architecture-review.md
(phase-0 exit review, frozen 2026-07-19).

Checks:
  1. Every direct arkret->arkret normal/optional edge must be declared in
     ALLOWED_EDGES or LEGACY_EDGES (legacy edges are tracked with the phase
     that removes them and reported, not failed).
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
    "arkret-models-identity": _WIRE,
    "arkret-models-crypto": _WIRE | {"arkret-models-identity"},
    "arkret-models-collaboration": _WIRE
    | {"arkret-models-identity", "arkret-models-crypto"},
    "arkret-models-integration": _WIRE | {"arkret-models-identity"},
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
        "arkret-schema",
        "arkret-models-identity",
        "arkret-models-collaboration",
        "arkret-models-integration",
    },
    "arkret-state": _WIRE
    | {"arkret-models-crypto", "arkret-models-collaboration"},
    # Phase 2-b: signatures behavior signs over data owned by three model
    # crates ("behavior depends on data"): models-identity (service-identity /
    # webvh inception contracts), models-collaboration (realm-organization
    # statement family + ephemeral proof envelope), models-discovery (DID
    # service-entry registry constants).
    "arkret-signatures": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-collaboration",
        "arkret-models-discovery",
    },
    "arkret-hlc": _BASE,
    "arkret-event-draft": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
    },
    # arkret-egress-policy carries the outbound SSRF host/IP deny-list
    # classifier (STA-05-001) the did:web / did:webvh resolvers guard fetches
    # with; it is a leaf crate (no arkret deps), so the edge is cycle-free.
    "arkret-identity": _WIRE
    | {"arkret-models-identity", "arkret-signatures", "arkret-egress-policy"},
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
    "arkret-crypto": _WIRE | {"arkret-models-identity", "arkret-models-crypto", "arkret-signatures"},
    "arkret-mls": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-crypto",
        "arkret-signatures",
    },
    # R1 (frozen): keystore owns trait + backends, standalone. Phase 2-b
    # moved the KeyStore contract (trait + error + in-memory backend) here
    # from arkret-core; the crate now has no arkret dependencies at all.
    "arkret-keystore": set(),
    "arkret-egress-policy": set(),
    "arkret-http-client": _WIRE
    | {
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-collaboration",
        "arkret-models-discovery",
        "arkret-identity",
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
        "arkret-identity",
        "arkret-policy",
        "arkret-signatures",
        "arkret-state",
    },
    # Legacy crates: retired in phase 1A (wire-edge) / phase 5 (core, ffi).
    "arkret-core": {
        "arkret-canonical",
        "arkret-identifiers",
        "arkret-policy",
        "arkret-schema",
        "arkret-state",
        "arkret-wire",
        # Transitional shim targets while core re-exports migrate (phase 5 removes core).
        "arkret-hlc",
        "arkret-event-draft",
        "arkret-models-identity",
        "arkret-models-crypto",
        "arkret-models-integration",
        "arkret-models-discovery",
        "arkret-models-collaboration",
        # Phase 2-b transitional edges: the KeyStore contract moved into
        # arkret-keystore (core re-exports it), and signatures / crypto own
        # their boundary errors (core keeps the `From` bridges into its
        # facade `Error`). All three edges retire with core in phase 5.
        "arkret-keystore",
        "arkret-signatures",
        "arkret-crypto",
        # Phase 2-c1: optional (mls-feature-only) edge so the facade `Error`
        # can bridge `arkret_mls::MlsError`. openmls stays out of the default
        # core graph.
        "arkret-mls",
        # Phase 2-c2b: facade `Error` bridges `arkret_identity::IdentityError`
        # and `arkret_auth::AuthError` (same transitional pattern as
        # signatures/crypto/mls). Retire with core in phase 5.
        "arkret-identity",
        "arkret-auth",
    },
    "arkret-ffi": {"arkret-core"},
    "arkret-sdk-fuzz": {"arkret-core", "arkret-signatures"},
}

# Edges tolerated until the named phase removes them. Reported, not failed.
#
# Phase 2-b cleared signatures/crypto/keystore -> arkret-core (and the stale
# crypto -> arkret-schema entry: schema is dev-dependency-only there). The two
# remaining edges are endpoint-definition dependencies; their residual core
# symbol surface and destination plan:
#
# arkret-http-client -> arkret-core:
#   - `Error` / `Result` transport contract (`Error::Http` / `Error::Url` /
#     `Error::Api` client variants) — splits out with the facade in phase 5;
#   - `http::{paths, params, bodies}` endpoint DTO clusters consumed by every
#     `endpoints_*.rs` module — follow the http-face extraction (pre-phase-5);
#   - `models` aggregate re-exports (sync/event DTOs), `Cursor`,
#     `StreamTraceValidator`, `is_query_auth_parameter` — move with their
#     owning modules when core's leftover clusters are rehomed.
#
# arkret-server -> arkret-core:
#   - `http` bodies/outcome DTO clusters + `ServiceDescribe` and the applet
#     view aggregates re-exported by core (endpoint registry / dispatch);
#   - `Cursor` / `CursorPurpose` (cursor authority), `ErrorEnvelope`
#     constructors in `service`, `is_query_auth_parameter`;
#   - `schema::SpecArtifactBundle` (embedded artifacts, tests only).
#   Same destination: shrink alongside the http-face extraction, gone in
#   phase 5 with the facade.
LEGACY_EDGES: dict[tuple[str, str], str] = {
    ("arkret-http-client", "arkret-core"): "phase 5 (http face)",
    ("arkret-server", "arkret-core"): "phase 5 (http face)",
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
    legacy_seen: list[str] = []

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
            phase = LEGACY_EDGES.get((name, dep))
            if phase is not None:
                legacy_seen.append(f"{name} -> {dep} (remove in {phase})")
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

    if legacy_seen:
        print(f"legacy edges remaining ({len(legacy_seen)}):")
        for edge in legacy_seen:
            print(f"  {edge}")
    print(
        f"layering OK: {len(workspace) - 1} crates checked, "
        f"{checked} data crates scanned for forbidden third-party deps"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
