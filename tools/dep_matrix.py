#!/usr/bin/env python3
"""Build a cross-repository Cargo dependency matrix from manifests and lockfiles.

The generator is pure text analysis: it reads every `Cargo.toml` and `Cargo.lock`
in the workspace repositories and never invokes `cargo`. That keeps it usable
while another agent holds the shared `target/` build lock, and makes the result
reproducible from a checkout alone.

Two dependency layers are reported separately:

* direct       - declared in a `Cargo.toml` (`[dependencies]`,
                 `[dev-dependencies]`, `[build-dependencies]`,
                 `[target.<cfg>.*-dependencies]`, `[workspace.dependencies]`).
                 Carries the requirement string, feature set, `optional` flag,
                 `default-features` flag and the `cfg(...)` target predicate.
* resolved     - the concrete versions in `Cargo.lock`. This is the full
                 transitive closure; anything not also seen as a direct
                 declaration is transitive-only.

"Major" follows Cargo's compatibility rule, not raw semver: `1.2.3` and `1.9.0`
share major `1`, while `0.4.x` and `0.5.x` are *different* majors because a 0.x
minor bump is breaking.

The script lives in `arkret-rust-sdk/tools` so the multi-repository
compatibility manifest can declare it as a check; the default workspace root is
still two levels above the script, and the default report directory is still
`arkret-work/reports/dep-matrix`.

Usage:
    python dep_matrix.py                      # write JSON + CSV + text summary
    python dep_matrix.py --format text        # summary on stdout only
    python dep_matrix.py --focus-only         # restrict summary to focus crates
    python dep_matrix.py --fail-on-divergence # non-zero exit when majors split
    python dep_matrix.py --require-repository soland
                                              # exit 2 when a repository the
                                              # caller expects is absent
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import re
import tomllib
from collections import defaultdict
from datetime import date
from pathlib import Path

# Repository directories, relative to the workspace root, that carry Rust code.
# `savfox` lives outside the workspace root and is probed separately.
WORKSPACE_REPOS = [
    "arkret-rust-sdk",
    "garth",
    "inkson",
    "soland",
    "cotest",
    "coauth",
    "teabay",
    "floria",
    "chime",
    "sodmin",
    "bridges",
]

EXTERNAL_REPOS = [
    ("savfox", "../savfox-ai/savfox"),
]

# `savfox` consumes the SDK, garth and bridges through path deps, so it belongs
# in the matrix, but it also carries a large unrelated agent-tooling tree. The
# summary therefore reports whether a split exists inside the core protocol
# repositories alone, which is what the convergence task can actually act on.
CORE_REPOS = set(WORKSPACE_REPOS)

SKIP_DIRS = {".git", "target", "node_modules", ".venv", "dist", ".shared-target"}

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

# Crates the convergence task tracks explicitly. Everything else is still
# analysed; this list only drives the highlighted section of the summary.
FOCUS_CRATES = [
    "aes-gcm",
    "base64",
    "chacha20poly1305",
    "chrono",
    "digest",
    "dioxus",
    "ed25519-dalek",
    "getrandom",
    "gloo-console",
    "gloo-events",
    "gloo-file",
    "gloo-net",
    "gloo-storage",
    "gloo-timers",
    "gloo-utils",
    "hkdf",
    "josekit",
    "jsonwebtoken",
    "openmls",
    "rand",
    "rand_core",
    "reqwest",
    "salvo",
    "serde",
    "serde_json",
    "sha2",
    "sqlx",
    "time",
    "tokio",
    "uuid",
    "wasm-bindgen",
    "web-sys",
    "x25519-dalek",
]


def major_key(version: str) -> str:
    """Return Cargo's compatibility bucket for a version string.

    `1.4.2` -> `1`, `0.7.3` -> `0.7`, `0.0.5` -> `0.0.5`.
    """
    core = version.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    try:
        numbers = [int(part) for part in parts[:3]]
    except ValueError:
        return version
    while len(numbers) < 3:
        numbers.append(0)
    major, minor, patch = numbers
    if major > 0:
        return str(major)
    if minor > 0:
        return f"0.{minor}"
    return f"0.0.{patch}"


def version_sort_key(version: str) -> tuple:
    """Numeric ordering for concrete lock versions, with a lexical fallback."""
    core = version.split("+", 1)[0].split("-", 1)[0]
    try:
        return (0, tuple(int(part) for part in core.split(".")))
    except ValueError:
        return (1, (0,))


def requirement_major(req: str) -> str:
    """Compatibility bucket of a requirement string such as `=0.96.0` or `^1.2`."""
    numbers = re.findall(r"\d+", req.lstrip("=^~><, ").split(",")[0])
    if not numbers:
        return req
    return major_key(".".join(numbers[:3]))


def major_sort_key(major: str) -> tuple:
    """Order compatibility buckets numerically: 0.7 < 0.8 < 0.10 < 1 < 2."""
    parts = major.split(".")
    try:
        numbers = tuple(int(part) for part in parts)
    except ValueError:
        return (9999, major)
    return (0,) + numbers if numbers[0] == 0 else (1,) + numbers


def iter_manifests(repo_root: Path):
    """Yield every `Cargo.toml` under `repo_root`, skipping build output."""
    stack = [repo_root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                stack.append(entry)
            elif entry.name == "Cargo.toml":
                yield entry


def iter_locks(repo_root: Path):
    """Yield every `Cargo.lock` under `repo_root`, skipping build output."""
    stack = [repo_root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                stack.append(entry)
            elif entry.name == "Cargo.lock":
                yield entry


def load_toml(path: Path) -> dict:
    # Some manifests are stored UTF-8 with BOM; `tomllib` rejects the BOM.
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return tomllib.loads(raw.decode("utf-8"))


def normalise_spec(name: str, spec) -> dict:
    """Flatten a dependency value into a uniform record."""
    if isinstance(spec, str):
        return {
            "name": name,
            "package": name,
            "req": spec,
            "features": [],
            "optional": False,
            "default_features": True,
            "path": None,
            "git": None,
            "inherits_workspace": False,
        }
    if not isinstance(spec, dict):
        return {
            "name": name,
            "package": name,
            "req": None,
            "features": [],
            "optional": False,
            "default_features": True,
            "path": None,
            "git": None,
            "inherits_workspace": False,
        }
    return {
        "name": name,
        "package": spec.get("package", name),
        "req": spec.get("version"),
        "features": list(spec.get("features", [])),
        "optional": bool(spec.get("optional", False)),
        "default_features": bool(spec.get("default-features", True)),
        "path": spec.get("path"),
        "git": spec.get("git"),
        "inherits_workspace": bool(spec.get("workspace", False)),
    }


def merge_workspace_inheritance(record: dict, workspace_deps: dict) -> dict:
    """Resolve `foo = { workspace = true }` against `[workspace.dependencies]`."""
    if not record["inherits_workspace"]:
        return record
    base = workspace_deps.get(record["name"])
    if base is None:
        return record
    merged = dict(base)
    merged["name"] = record["name"]
    merged["inherits_workspace"] = True
    # A member may add features on top of the inherited set; `optional` and
    # `default-features` may also be overridden at the member.
    merged["features"] = sorted(set(base["features"]) | set(record["features"]))
    if record["optional"]:
        merged["optional"] = True
    if record["default_features"] is False:
        merged["default_features"] = False
    return merged


def collect_manifest_deps(manifest: dict) -> list[dict]:
    """Extract direct declarations from one parsed `Cargo.toml`."""
    found: list[dict] = []

    def take(table, kind: str, target: str | None) -> None:
        if not isinstance(table, dict):
            return
        for name, spec in table.items():
            record = normalise_spec(name, spec)
            record["kind"] = kind
            record["target"] = target
            found.append(record)

    for table_name in DEPENDENCY_TABLES:
        take(manifest.get(table_name), table_name, None)

    for target, tables in (manifest.get("target") or {}).items():
        if not isinstance(tables, dict):
            continue
        for table_name in DEPENDENCY_TABLES:
            take(tables.get(table_name), table_name, target)

    workspace = manifest.get("workspace") or {}
    take(workspace.get("dependencies"), "workspace-dependencies", None)

    return found


def workspace_dependency_table(manifest: dict) -> dict:
    table = (manifest.get("workspace") or {}).get("dependencies") or {}
    return {name: normalise_spec(name, spec) for name, spec in table.items()}


def package_name(manifest: dict, manifest_path: Path) -> str:
    package = manifest.get("package") or {}
    name = package.get("name")
    if isinstance(name, str):
        return name
    if isinstance(name, dict):  # `name = { workspace = true }` is not legal, but be safe.
        return manifest_path.parent.name
    return f"<virtual:{manifest_path.parent.name}>"


def analyse_repo(repo_name: str, repo_root: Path, workspace_root: Path) -> dict:
    root_manifest_path = repo_root / "Cargo.toml"
    root_manifest = load_toml(root_manifest_path) if root_manifest_path.exists() else {}
    workspace_deps = workspace_dependency_table(root_manifest)

    direct: list[dict] = []
    members: list[str] = []
    for manifest_path in sorted(iter_manifests(repo_root)):
        try:
            manifest = load_toml(manifest_path)
        except tomllib.TOMLDecodeError as error:
            print(f"warn: cannot parse {manifest_path}: {error}", file=sys.stderr)
            continue
        rel = manifest_path.relative_to(workspace_root).as_posix()
        member = package_name(manifest, manifest_path)
        members.append(member)
        for record in collect_manifest_deps(manifest):
            resolved = merge_workspace_inheritance(record, workspace_deps)
            resolved["repo"] = repo_name
            resolved["manifest"] = rel
            resolved["member"] = member
            resolved["kind"] = record["kind"]
            resolved["target"] = record["target"]
            direct.append(resolved)

    # A repository can hold more than one lockfile: nested `[workspace]` trees
    # such as `fuzz/` or `tools/spec-codegen/` resolve independently of the
    # root workspace, so each lock is recorded with its own scope.
    resolved_packages: list[dict] = []
    lock_paths = sorted(
        path
        for path in iter_locks(repo_root)
    )
    for lock_path in lock_paths:
        scope = lock_path.parent.relative_to(repo_root).as_posix() or "."
        lock = load_toml(lock_path)
        for entry in lock.get("package", []):
            name = entry.get("name")
            version = entry.get("version")
            if not name or not version:
                continue
            source = entry.get("source")
            resolved_packages.append(
                {
                    "repo": repo_name,
                    "lock_scope": scope,
                    "name": name,
                    "version": version,
                    "major": major_key(version),
                    "source": source,
                    "local": source is None,
                    "deps": list(entry.get("dependencies", [])),
                }
            )

    return {
        "repo": repo_name,
        "root": repo_root.as_posix(),
        "members": sorted(set(members)),
        "lock_scopes": [path.parent.relative_to(repo_root).as_posix() or "." for path in lock_paths],
        "has_lock": bool(lock_paths),
        "direct": direct,
        "resolved": resolved_packages,
    }


def build_matrix(repos: list[dict]) -> dict:
    direct_index: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    resolved_index: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    local_crates: set[str] = set()

    for repo in repos:
        for record in repo["direct"]:
            key = record["package"]
            if record.get("path") or record.get("git"):
                local_crates.add(key)
            direct_index[key][repo["repo"]].append(record)
        for record in repo["resolved"]:
            if record["local"]:
                local_crates.add(record["name"])
            resolved_index[record["name"]][repo["repo"]].append(record)

    crates: dict[str, dict] = {}
    for name in sorted(set(direct_index) | set(resolved_index)):
        per_repo: dict[str, dict] = {}
        for repo_name, records in sorted(resolved_index.get(name, {}).items()):
            versions = sorted(
                {record["version"] for record in records}, key=version_sort_key
            )
            majors = sorted({record["major"] for record in records}, key=major_sort_key)
            # The root lockfile is the graph that actually ships; `fuzz/` and
            # tool workspaces resolve separately and are reported apart so a
            # fuzz-only split is never mistaken for a shipping divergence.
            root_records = [record for record in records if record["lock_scope"] == "."]
            root_versions = sorted(
                {record["version"] for record in root_records}, key=version_sort_key
            )
            root_majors = sorted(
                {record["major"] for record in root_records}, key=major_sort_key
            )
            per_repo.setdefault(repo_name, {})["resolved_versions"] = versions
            per_repo[repo_name]["resolved_majors"] = majors
            per_repo[repo_name]["root_versions"] = root_versions
            per_repo[repo_name]["root_majors"] = root_majors
            per_repo[repo_name]["aux_lock_scopes"] = sorted(
                {record["lock_scope"] for record in records if record["lock_scope"] != "."}
            )
            per_repo[repo_name]["intra_lock_split"] = len(root_majors) > 1
        for repo_name, records in sorted(direct_index.get(name, {}).items()):
            slot = per_repo.setdefault(repo_name, {})
            slot["direct"] = [
                {
                    "member": record["member"],
                    "manifest": record["manifest"],
                    "table": record["kind"],
                    "req": record["req"],
                    "features": record["features"],
                    "optional": record["optional"],
                    "default_features": record["default_features"],
                    "target": record["target"],
                    "path": record["path"],
                    "git": record["git"],
                }
                for record in sorted(records, key=lambda item: (item["manifest"], item["kind"]))
            ]

        all_majors = sorted(
            {
                major
                for slot in per_repo.values()
                for major in slot.get("resolved_majors", [])
            },
            key=major_sort_key,
        )
        direct_repos = sorted(direct_index.get(name, {}))
        crates[name] = {
            "name": name,
            "local": name in local_crates,
            "repos": per_repo,
            "all_majors": all_majors,
            "cross_repo_split": len(all_majors) > 1,
            "intra_lock_split_repos": sorted(
                repo for repo, slot in per_repo.items() if slot.get("intra_lock_split")
            ),
            "direct_in": direct_repos,
            "transitive_only_in": sorted(
                repo
                for repo in per_repo
                if repo not in direct_index.get(name, {})
            ),
        }

    return crates


def divergences(crates: dict) -> list[dict]:
    out = []
    for name, crate in crates.items():
        if crate["local"]:
            continue
        if not (crate["cross_repo_split"] or crate["intra_lock_split_repos"]):
            continue
        core_majors = sorted(
            {
                major
                for repo, slot in crate["repos"].items()
                if repo in CORE_REPOS
                for major in slot.get("root_majors", [])
            },
            key=major_sort_key,
        )
        core_declared = [repo for repo in crate["direct_in"] if repo in CORE_REPOS]
        declared_core_majors = sorted(
            {
                requirement_major(entry["req"])
                for repo in core_declared
                for entry in crate["repos"][repo].get("direct") or []
                if entry["req"]
            },
            key=major_sort_key,
        )
        declared_split = len(declared_core_majors) > 1
        out.append(
            {
                "crate": name,
                "majors": crate["all_majors"],
                "core_majors": core_majors,
                "core_split": len(core_majors) > 1,
                # Gate-relevant = the core repositories declare more than one
                # major themselves (a first-party disagreement someone can fix
                # by editing a manifest), or the crate is one the convergence
                # task tracks by name. A crate every core repo declares
                # identically, whose older major exists only because some
                # upstream dependency drags it in, is reported but not gated:
                # there is no first-party decision to make.
                "actionable": declared_split or name in FOCUS_CRATES,
                "declared_split": declared_split,
                "declared_core_majors": declared_core_majors,
                "declared_in_core": core_declared,
                "cross_repo_split": crate["cross_repo_split"],
                "intra_lock_split_repos": crate["intra_lock_split_repos"],
                "per_repo": {
                    repo: slot.get("root_versions", [])
                    for repo, slot in sorted(crate["repos"].items())
                },
                "per_repo_all_scopes": {
                    repo: slot.get("resolved_versions", [])
                    for repo, slot in sorted(crate["repos"].items())
                },
                "direct_in": crate["direct_in"],
                "focus": name in FOCUS_CRATES,
            }
        )
    out.sort(
        key=lambda item: (
            not item["actionable"],
            not item["declared_split"],
            not item["focus"],
            item["crate"],
        )
    )
    return out


def explain(repos: list[dict], crate_name: str) -> str:
    """Report, per repository, which locked packages pull each version of a crate.

    Cargo writes a bare `"name"` in a package's `dependencies` list when the
    graph holds exactly one version, and `"name version"` when several coexist,
    so both shapes have to be matched.
    """
    lines = [f"# reverse dependents of `{crate_name}`", ""]
    for repo in repos:
        versions = sorted(
            {pkg["version"] for pkg in repo["resolved"] if pkg["name"] == crate_name},
            key=version_sort_key,
        )
        if not versions:
            continue
        lines.append(f"## {repo['repo']}  ({', '.join(versions)})")
        wanted = {version: [] for version in versions}
        unqualified = []
        for pkg in repo["resolved"]:
            for edge in pkg["deps"]:
                parts = edge.split()
                if parts[0] != crate_name:
                    continue
                scope = "" if pkg["lock_scope"] == "." else f" [{pkg['lock_scope']}]"
                who = f"{pkg['name']} {pkg['version']}{scope}"
                if len(parts) >= 2 and parts[1] in wanted:
                    wanted[parts[1]].append(who)
                else:
                    unqualified.append(who)
        for version in versions:
            dependents = sorted(set(wanted[version]))
            lines.append(f"  {crate_name} {version}  <- {len(dependents)} dependent(s)")
            for who in dependents:
                lines.append(f"      {who}")
        if unqualified:
            lines.append(f"  (unversioned edges, single version in graph): {len(set(unqualified))}")
            for who in sorted(set(unqualified)):
                lines.append(f"      {who}")
        lines.append("")
    return "\n".join(lines)


DEFAULT_EXEMPTIONS = Path(__file__).resolve().parent / "dep_matrix_exemptions.json"


def load_exemptions(path: Path) -> dict:
    if not path.exists():
        return {"exemptions": []}
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_exemptions(payload: dict, exemptions: dict, today: str) -> dict:
    """Match every actionable divergence against the exemption ledger.

    An exemption covers a divergence only when it names the same crate and its
    `majors` list is a superset of the majors actually observed inside the core
    repositories. Narrowing the observed set (an upstream release finally
    landing) therefore keeps passing, while a *new* major appearing re-opens
    the finding instead of hiding behind a stale entry.
    """
    index = {entry["crate"]: entry for entry in exemptions.get("exemptions", [])}
    uncovered: list[dict] = []
    covered: list[dict] = []
    expired: list[dict] = []
    stale: list[str] = []
    seen: set[str] = set()

    for item in payload["divergences"]:
        if not (item["core_split"] and item["actionable"]):
            continue
        entry = index.get(item["crate"])
        if entry is None:
            uncovered.append(item)
            continue
        seen.add(item["crate"])
        allowed = set(entry.get("majors", []))
        observed = set(item["core_majors"])
        if not observed <= allowed:
            uncovered.append(
                dict(item, unexpected_majors=sorted(observed - allowed, key=major_sort_key))
            )
            continue
        covered.append(item)
        review_after = entry.get("review_after")
        if review_after and review_after < today:
            expired.append({"crate": item["crate"], "review_after": review_after})

    for crate in sorted(set(index) - seen):
        stale.append(crate)

    return {
        "uncovered": uncovered,
        "covered": [item["crate"] for item in covered],
        "review_due": expired,
        "stale_exemptions": stale,
    }


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_csv(path: Path, crates: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "crate",
                "repo",
                "layer",
                "resolved_versions",
                "resolved_majors",
                "requirement",
                "features",
                "optional",
                "default_features",
                "target_cfg",
                "table",
                "manifest",
                "cross_repo_split",
                "intra_lock_split",
                "local_path_crate",
            ]
        )
        for name in sorted(crates):
            crate = crates[name]
            for repo in sorted(crate["repos"]):
                slot = crate["repos"][repo]
                versions = ";".join(slot.get("resolved_versions", []))
                majors = ";".join(slot.get("resolved_majors", []))
                entries = slot.get("direct")
                if not entries:
                    writer.writerow(
                        [
                            name,
                            repo,
                            "transitive",
                            versions,
                            majors,
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            crate["cross_repo_split"],
                            slot.get("intra_lock_split", False),
                            crate["local"],
                        ]
                    )
                    continue
                for entry in entries:
                    writer.writerow(
                        [
                            name,
                            repo,
                            "direct",
                            versions,
                            majors,
                            entry["req"] or "",
                            ";".join(entry["features"]),
                            entry["optional"],
                            entry["default_features"],
                            entry["target"] or "",
                            entry["table"],
                            entry["manifest"],
                            crate["cross_repo_split"],
                            slot.get("intra_lock_split", False),
                            crate["local"],
                        ]
                    )


def render_text(payload: dict, focus_only: bool) -> str:
    lines: list[str] = []
    lines.append("# Cross-repo Cargo dependency matrix")
    lines.append("")
    lines.append(f"repos analysed: {len(payload['repos'])}")
    for repo in payload["repos"]:
        lines.append(
            f"  - {repo['repo']}: {len(repo['members'])} member(s), "
            f"{repo['direct_declarations']} direct decl(s), "
            f"{repo['locked_packages']} locked package(s)"
        )
    lines.append("")

    diverging = payload["divergences"]
    focus = [item for item in diverging if item["focus"]]
    other = [item for item in diverging if not item["focus"]]
    core = [item for item in diverging if item["core_split"]]
    lines.append(f"major-version divergences: {len(diverging)} "
                 f"({len(focus)} focus crate(s), {len(other)} other; "
                 f"{len(core)} split inside the core protocol repos)")
    lines.append("")

    def emit(items: list[dict], title: str) -> None:
        lines.append(f"## {title}")
        if not items:
            lines.append("  (none)")
            lines.append("")
            return
        for item in items:
            scope = []
            if item["cross_repo_split"]:
                scope.append("cross-repo")
            if item["intra_lock_split_repos"]:
                scope.append("intra-lock:" + ",".join(item["intra_lock_split_repos"]))
            if not item["core_split"]:
                scope.append("savfox-only")
            lines.append(
                f"- {item['crate']}  majors={','.join(item['majors'])}"
                f"  core={','.join(item['core_majors'])}  [{' '.join(scope)}]"
            )
            for repo, versions in item["per_repo"].items():
                marker = "*" if repo in item["direct_in"] else " "
                lines.append(f"    {marker} {repo}: {', '.join(versions)}")
        lines.append("")

    emit(focus, "Focus crates")
    if not focus_only:
        emit(other, "Other crates")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        default=None,
        help="workspace root containing the repositories (default: two levels above this script)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="directory for dep-matrix.json / dep-matrix.csv / dep-matrix.txt",
    )
    parser.add_argument(
        "--format",
        choices=["all", "text", "json", "csv"],
        default="all",
        help="which artifacts to produce (text always goes to stdout)",
    )
    parser.add_argument("--focus-only", action="store_true", help="summary lists focus crates only")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="also write dep-matrix-raw.json with every declaration and lock entry",
    )
    parser.add_argument(
        "--why",
        metavar="CRATE",
        default=None,
        help="print the reverse dependents of CRATE per repository and exit",
    )
    parser.add_argument(
        "--exemptions",
        default=None,
        help=f"exemption ledger (default: {DEFAULT_EXEMPTIONS.name} next to this script)",
    )
    parser.add_argument(
        "--fail-on-divergence",
        action="store_true",
        help="exit 1 when an actionable core-repo major split has no exemption entry",
    )
    parser.add_argument(
        "--require-repository",
        action="append",
        default=[],
        metavar="REPO",
        help=(
            "fail when REPO carries no Cargo manifest under the workspace root; "
            "repeat once per repository the caller expects to be analysed"
        ),
    )
    parser.add_argument(
        "--today",
        default=None,
        help="ISO date used to test exemption review dates (default: system date)",
    )
    args = parser.parse_args(argv)

    script_dir = Path(__file__).resolve().parent
    workspace_root = (
        Path(args.workspace_root).resolve() if args.workspace_root else script_dir.parent.parent
    )
    out_dir = (
        Path(args.out_dir).resolve()
        if args.out_dir
        else workspace_root / "arkret-work" / "reports" / "dep-matrix"
    )

    repos: list[dict] = []
    missing: list[str] = []
    for name in WORKSPACE_REPOS:
        root = workspace_root / name
        if not (root / "Cargo.toml").exists():
            missing.append(name)
            continue
        repos.append(analyse_repo(name, root, workspace_root))
    for name, relative in EXTERNAL_REPOS:
        root = (workspace_root / relative).resolve()
        if not (root / "Cargo.toml").exists():
            missing.append(f"{name} ({relative})")
            continue
        # External repos sit outside the workspace root, so manifest paths are
        # recorded relative to their own root instead.
        repos.append(analyse_repo(name, root, root.parent))

    # A partial checkout silently narrows the matrix: fewer repositories mean
    # fewer cross-repo splits, so `--fail-on-divergence` would pass vacuously.
    # Callers that run this as a gate name the repositories the checkout is
    # supposed to provide, and a missing one is a gate failure, not a warning.
    if args.require_repository:
        known = set(WORKSPACE_REPOS) | {name for name, _ in EXTERNAL_REPOS}
        unknown = sorted(set(args.require_repository) - known)
        if unknown:
            print(
                f"error: --require-repository names unknown repositories: {', '.join(unknown)}",
                file=sys.stderr,
            )
            return 2
        analysed = {repo["repo"] for repo in repos}
        absent = sorted(set(args.require_repository) - analysed)
        if absent:
            print(
                f"error: required repositories carry no Cargo manifest: {', '.join(absent)}",
                file=sys.stderr,
            )
            return 2

    if args.why:
        print(explain(repos, args.why))
        return 0

    crates = build_matrix(repos)
    payload = {
        "workspace_root": workspace_root.as_posix(),
        "missing_repos": missing,
        "focus_crates": FOCUS_CRATES,
        # The committed summary keeps per-repository counts, not the raw
        # declaration and lock dumps: those run to eight figures of JSON and
        # are reproducible from a checkout in seconds. `--raw` writes them to
        # a separate file for one-off analysis.
        "repos": [
            {
                "repo": repo["repo"],
                "root": repo["root"],
                "members": repo["members"],
                "has_lock": repo["has_lock"],
                "lock_scopes": repo["lock_scopes"],
                "direct_declarations": len(repo["direct"]),
                "locked_packages": len(repo["resolved"]),
            }
            for repo in repos
        ],
        "divergences": divergences(crates),
    }
    # `crates` is the full per-crate matrix. It is an order of magnitude larger
    # than the analysis above and fully reproducible, so the default JSON keeps
    # only the decisions: the complete table goes to CSV, and `--raw` dumps the
    # matrix plus every declaration and lock entry.
    raw = {
        "crates": crates,
        "repos": {
            repo["repo"]: {"direct": repo["direct"], "resolved": repo["resolved"]}
            for repo in repos
        },
    }

    text = render_text(payload, args.focus_only)
    print(text)

    if args.format in ("all", "json"):
        write_json(out_dir / "dep-matrix.json", payload)
    if args.format in ("all", "csv"):
        write_csv(out_dir / "dep-matrix.csv", crates)
    if args.raw:
        write_json(out_dir / "dep-matrix-raw.json", raw)
    if args.format == "all":
        (out_dir / "dep-matrix.txt").write_text(
            text + "\n", encoding="utf-8", newline="\n"
        )
    if args.format != "text":
        print(f"\nwrote artifacts to {out_dir}", file=sys.stderr)

    if missing:
        print(f"warn: repositories not found: {', '.join(missing)}", file=sys.stderr)

    exemption_path = Path(args.exemptions).resolve() if args.exemptions else DEFAULT_EXEMPTIONS
    today = args.today or date.today().isoformat()
    verdict = evaluate_exemptions(payload, load_exemptions(exemption_path), today)
    payload["exemption_verdict"] = verdict
    if args.format in ("all", "json"):
        write_json(out_dir / "dep-matrix.json", payload)

    if verdict["uncovered"]:
        print("", file=sys.stderr)
        print("actionable divergences without an exemption entry:", file=sys.stderr)
        for item in verdict["uncovered"]:
            extra = item.get("unexpected_majors")
            note = f"  (new majors: {','.join(extra)})" if extra else ""
            print(
                f"  - {item['crate']}: {','.join(item['core_majors'])}"
                f" in {', '.join(item['declared_in_core']) or 'transitive only'}{note}",
                file=sys.stderr,
            )
    for entry in verdict["review_due"]:
        print(
            f"warn: exemption for {entry['crate']} is past its review date {entry['review_after']}",
            file=sys.stderr,
        )
    for crate in verdict["stale_exemptions"]:
        print(f"warn: exemption for {crate} no longer matches any divergence", file=sys.stderr)

    if args.fail_on_divergence and verdict["uncovered"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
