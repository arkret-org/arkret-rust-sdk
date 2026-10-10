#!/usr/bin/env python3
"""Prepare a reviewable lockfile candidate in a complete sibling workspace."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess

REPOSITORIES = (
    "arkret-spec", "arkret-rust-sdk", "floria", "soland", "coauth",
    "garth", "chime", "inkson", "cotest", "sodmin",
)


def run(*args: str, cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", choices=REPOSITORIES, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace_root.resolve()
    repo = root / args.repository
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if run("git", "status", "--porcelain", cwd=repo).strip():
        raise SystemExit("Candidate repository must be clean before dependency resolution")
    if not run("git", "ls-files", "--", "Cargo.lock", cwd=repo).strip():
        raise SystemExit("This lockfile maintenance entry point requires a tracked Cargo.lock")
    for name in REPOSITORIES:
        if run("git", "status", "--porcelain", cwd=root / name).strip():
            raise SystemExit(f"Sibling {name} must be clean before dependency resolution")
    refs = {name: run("git", "rev-parse", "HEAD", cwd=root / name).strip()
            for name in REPOSITORIES}
    evidence = {
        "repository": args.repository,
        "base_commit": refs[args.repository],
        "repositories": refs,
        "scope": "New dependency candidate; not an accepted compatibility train",
        "validation": "Resolution only; MSRV, security, tests and exact compatibility require CI",
    }
    (output / "sources.json").write_text(json.dumps(evidence, indent=2) + "\n", newline="\n")
    shutil.copyfile(repo / "Cargo.lock", output / "Cargo.lock.before")
    run("cargo", "update", cwd=repo)
    run("cargo", "metadata", "--format-version", "1", "--locked", cwd=repo)
    tree = run("cargo", "tree", "--workspace", "--all-features", "--locked", cwd=repo)
    (output / "dependencies.txt").write_text(tree, newline="\n")
    shutil.copyfile(repo / "Cargo.lock", output / "Cargo.lock")
    patch = run("git", "diff", "--binary", "HEAD", "--", "Cargo.lock", cwd=repo)
    (output / "Cargo.lock.patch").write_text(patch, newline="\n")
    (output / "README.md").write_text(
        f"# Cargo dependency candidate for {args.repository}\n\n"
        f"Base commit: `{refs[args.repository]}`. The exact sibling sources are in `sources.json`.\n\n"
        "This is resolution evidence only. It does not prove MSRV, security or compatibility.\n"
        "Review the patch in a clean checkout at that base, use `git apply --check Cargo.lock.patch` "
        "before applying, then submit a normal PR and run the ordinary and exact-manifest CI gates.\n"
        "No patch means all dependencies already resolve to the latest allowed versions.\n",
        newline="\n",
    )
    print(f"Candidate written to {output}; lockfile changed: {bool(patch)}")


if __name__ == "__main__":
    main()
