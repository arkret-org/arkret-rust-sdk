#!/usr/bin/env python3
"""Build the arkret-core file dependency graph and strongly connected components."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


CRATE_PATH = re.compile(r"\bcrate::([A-Za-z_][A-Za-z0-9_:]*)")
SUPER_PATH = re.compile(r"\bsuper::([A-Za-z_][A-Za-z0-9_:]*)")
MOD_DECL = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")


def module_name(src: Path, path: Path) -> str:
    relative = path.relative_to(src)
    parts = list(relative.parts)
    filename = parts.pop()
    stem = Path(filename).stem
    if stem == "lib":
        return "crate_root"
    if stem != "mod":
        parts.append(stem)
    return "::".join(parts)


def resolve_module(modules: set[str], candidate: str) -> str | None:
    current = candidate
    while current:
        if current in modules:
            return current
        current = current.rpartition("::")[0]
    return None


def graph(src: Path) -> tuple[dict[str, set[str]], dict[str, str]]:
    files = sorted(src.rglob("*.rs"))
    paths = {module_name(src, path): str(path.relative_to(src)).replace("\\", "/") for path in files}
    modules = set(paths)
    edges: dict[str, set[str]] = {module: set() for module in modules}

    for module, relative in paths.items():
        text = (src / relative).read_text(encoding="utf-8")
        parent = module.rpartition("::")[0]
        if module == "crate_root":
            parent = ""
        for match in CRATE_PATH.finditer(text):
            target = resolve_module(modules, match.group(1))
            if target and target != module:
                edges[module].add(target)
        for match in SUPER_PATH.finditer(text):
            target = resolve_module(modules, "::".join(filter(None, (parent, match.group(1)))))
            if target and target != module:
                edges[module].add(target)
        for child in MOD_DECL.findall(text):
            prefix = "" if module == "crate_root" else module
            target = resolve_module(modules, "::".join(filter(None, (prefix, child))))
            if target and target != module:
                edges[module].add(target)
    return edges, paths


def strongly_connected_components(edges: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in edges[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                current = stack.pop()
                on_stack.remove(current)
                component.append(current)
                if current == node:
                    break
            components.append(sorted(component))

    for node in sorted(edges):
        if node not in indices:
            visit(node)
    return sorted(components, key=lambda component: (-len(component), component))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("docs/core-split-graph.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    src = root / "crates" / "core" / "src"
    edges, paths = graph(src)
    components = strongly_connected_components(edges)
    incoming: dict[str, set[str]] = defaultdict(set)
    for source, targets in edges.items():
        for target in targets:
            incoming[target].add(source)
    result = {
        "source_root": str(src.relative_to(root)).replace("\\", "/"),
        "files": paths,
        "edges": {source: sorted(targets) for source, targets in sorted(edges.items())},
        "sccs": components,
        "nontrivial_sccs": [component for component in components if len(component) > 1],
        "incoming_counts": {node: len(incoming[node]) for node in sorted(edges)},
    }
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"wrote {len(paths)} modules, {sum(map(len, edges.values()))} edges, "
        f"{len(result['nontrivial_sccs'])} non-trivial SCCs to {output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
