#!/usr/bin/env python3
"""Focused tests for the cross-repository dependency matrix and its exemption gate."""

import tempfile
import contextlib
import io
import json
from pathlib import Path

import dep_matrix
from dep_matrix import (
    DEFAULT_EXEMPTIONS,
    build_matrix,
    divergences,
    evaluate_exemptions,
    load_exemptions,
    major_key,
    major_sort_key,
    requirement_major,
    version_sort_key,
)


def test_major_buckets_follow_cargo_compatibility() -> None:
    # A 0.x minor bump is breaking, so it is its own bucket; a 1.x minor bump is not.
    assert major_key("1.2.3") == "1"
    assert major_key("1.9.0") == "1"
    assert major_key("0.7.3") == "0.7"
    assert major_key("0.8.0") == "0.8"
    assert major_key("0.0.29") == "0.0.29"
    assert major_key("2.2.0-rc.1") == "2"


def test_numeric_ordering_not_lexical() -> None:
    assert sorted(["0.10", "0.7", "1", "0.9"], key=major_sort_key) == ["0.7", "0.9", "0.10", "1"]
    assert sorted(["0.10.2", "0.9.5"], key=version_sort_key) == ["0.9.5", "0.10.2"]


def test_requirement_major_handles_pins_and_ranges() -> None:
    assert requirement_major("=0.96.0") == "0.96"
    assert requirement_major("^1.2") == "1"
    assert requirement_major("0.23.1") == "0.23"
    assert requirement_major(">= 2, <= 4") == "2"


def _repo(name: str, direct: list[dict], resolved: list[dict]) -> dict:
    return {
        "repo": name,
        "root": f"/{name}",
        "members": [name],
        "lock_scopes": ["."],
        "has_lock": True,
        "direct": direct,
        "resolved": resolved,
    }


def _decl(repo: str, package: str, req: str) -> dict:
    return {
        "repo": repo,
        "name": package,
        "package": package,
        "req": req,
        "features": [],
        "optional": False,
        "default_features": True,
        "path": None,
        "git": None,
        "inherits_workspace": False,
        "kind": "dependencies",
        "target": None,
        "manifest": f"{repo}/Cargo.toml",
        "member": repo,
    }


def _lock(repo: str, name: str, version: str, scope: str = ".", deps=()) -> dict:
    return {
        "repo": repo,
        "lock_scope": scope,
        "name": name,
        "version": version,
        "major": major_key(version),
        "source": "registry+x",
        "local": False,
        "deps": list(deps),
    }


def test_declared_split_is_gated_but_upstream_only_split_is_not() -> None:
    repos = [
        # Both repositories declare sha2 0.11; only the resolved graph carries a
        # second 0.10 copy dragged in by an upstream crate.
        _repo(
            "arkret-rust-sdk",
            [_decl("arkret-rust-sdk", "sha2", "0.11.0")],
            [
                _lock("arkret-rust-sdk", "sha2", "0.11.0"),
                _lock("arkret-rust-sdk", "sha2", "0.10.9"),
            ],
        ),
        # A genuine first-party disagreement: two repositories declare different majors.
        _repo(
            "coauth",
            [_decl("coauth", "sha2", "0.11.0"), _decl("coauth", "widget", "0.5.0")],
            [_lock("coauth", "sha2", "0.11.0"), _lock("coauth", "widget", "0.5.0")],
        ),
        _repo(
            "soland",
            [_decl("soland", "widget", "0.6.0")],
            [_lock("soland", "widget", "0.6.0")],
        ),
    ]
    found = {item["crate"]: item for item in divergences(build_matrix(repos))}

    assert found["sha2"]["core_split"]
    assert not found["sha2"]["declared_split"]
    # sha2 is still gated, but only because it is on the focus list.
    assert found["sha2"]["actionable"]

    assert found["widget"]["declared_split"]
    assert found["widget"]["declared_core_majors"] == ["0.5", "0.6"]
    assert found["widget"]["actionable"]


def test_auxiliary_lockfiles_do_not_manufacture_a_shipping_split() -> None:
    repos = [
        _repo(
            "arkret-rust-sdk",
            [_decl("arkret-rust-sdk", "gadget", "1.0.0")],
            [
                _lock("arkret-rust-sdk", "gadget", "1.0.0"),
                # A fuzz workspace resolves independently and must not be read
                # as the shipping graph carrying two majors.
                _lock("arkret-rust-sdk", "gadget", "2.0.0", scope="fuzz"),
            ],
        )
    ]
    crates = build_matrix(repos)
    assert crates["gadget"]["repos"]["arkret-rust-sdk"]["root_majors"] == ["1"]
    assert crates["gadget"]["repos"]["arkret-rust-sdk"]["resolved_majors"] == ["1", "2"]
    assert not [item for item in divergences(crates) if item["core_split"]]


def test_nested_workspace_direct_declarations_are_not_shipping_disagreements() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary)
        repo = workspace / "arkret-rust-sdk"
        (repo / "fuzz" / "member").mkdir(parents=True)
        (repo / "Cargo.toml").write_text(
            '[workspace]\n[workspace.dependencies]\ngadget = "1"\n', encoding="utf-8")
        (repo / "Cargo.lock").write_text(
            '[[package]]\nname = "gadget"\nversion = "1.0.0"\nsource = "registry+x"\n', encoding="utf-8")
        (repo / "fuzz" / "Cargo.toml").write_text(
            '[workspace]\n[workspace.dependencies]\ngadget = "2"\n', encoding="utf-8")
        (repo / "fuzz" / "member" / "Cargo.toml").write_text(
            '[package]\nname = "fuzzer"\nversion = "0.1.0"\n[dependencies]\ngadget = { workspace = true }\n',
            encoding="utf-8")
        (repo / "fuzz" / "Cargo.lock").write_text(
            '[[package]]\nname = "gadget"\nversion = "2.0.0"\nsource = "registry+x"\n', encoding="utf-8")
        analysed = dep_matrix.analyse_repo("arkret-rust-sdk", repo, workspace)
        declarations = analysed["direct"]
        assert [entry["workspace_scope"] for entry in declarations] == [".", "fuzz", "fuzz"]
        assert declarations[-1]["req"] == "2"
        found = divergences(build_matrix([analysed]))
        assert not found[0]["core_split"]
        assert not found[0]["declared_split"]
        assert not found[0]["actionable"]
        assert not evaluate_exemptions({"divergences": found}, {"exemptions": []}, "2026-10-09")["uncovered"]


def test_exemption_must_cover_every_observed_major() -> None:
    payload = {
        "divergences": [
            {
                "crate": "widget",
                "core_majors": ["0.5", "0.6"],
                "core_split": True,
                "actionable": True,
                "declared_in_core": ["coauth", "soland"],
            }
        ]
    }
    # A narrower entry does not silently cover a newly appeared major.
    narrow = {"exemptions": [{"crate": "widget", "majors": ["0.5"]}]}
    verdict = evaluate_exemptions(payload, narrow, "2026-09-04")
    assert [item["crate"] for item in verdict["uncovered"]] == ["widget"]
    assert verdict["uncovered"][0]["unexpected_majors"] == ["0.6"]

    wide = {
        "exemptions": [
            {"crate": "widget", "majors": ["0.5", "0.6"], "review_after": "2026-01-01"}
        ]
    }
    verdict = evaluate_exemptions(payload, wide, "2026-09-04")
    assert not verdict["uncovered"]
    assert verdict["covered"] == ["widget"]
    # An entry past its review date is reported even though it still passes.
    assert verdict["review_due"] == [{"crate": "widget", "review_after": "2026-01-01"}]

    # An entry that matches nothing any more is reported as stale.
    verdict = evaluate_exemptions(
        {"divergences": []}, wide, "2026-09-04"
    )
    assert verdict["stale_exemptions"] == ["widget"]


def test_shipped_exemption_ledger_is_well_formed() -> None:
    ledger = load_exemptions(DEFAULT_EXEMPTIONS)
    assert ledger["exemptions"], "the ledger must not be empty while divergences exist"
    families = ledger["families"]
    for entry in ledger["exemptions"]:
        crate = entry["crate"]
        assert entry.get("majors"), f"{crate}: majors is required"
        assert entry.get("owner"), f"{crate}: an owner is required"
        # A permanent exemption is not allowed.
        assert entry.get("expires_when"), f"{crate}: an expiry condition is required"
        assert entry.get("review_after"), f"{crate}: a review date is required"
        for family in entry.get("families", []):
            assert family in families, f"{crate}: unknown family {family}"
    for name, family in families.items():
        assert family.get("owner"), f"{name}: an owner is required"
        assert family.get("expires_when"), f"{name}: an expiry condition is required"
        assert family.get("verify"), f"{name}: a verification command is required"


def test_partial_checkout_cannot_pass_the_gate_vacuously() -> None:
    # An empty workspace analyses nothing, so every divergence disappears and
    # `--fail-on-divergence` alone would report success. `--require-repository`
    # is what turns that silent narrowing into a failure.
    with tempfile.TemporaryDirectory() as temporary:
        empty = Path(temporary)
        argv = ["--workspace-root", str(empty), "--format", "text", "--fail-on-divergence"]
        assert dep_matrix.main(argv) == 0
        assert dep_matrix.main(argv + ["--require-repository", "soland"]) == 2
        # A name outside the analysed repository set is a caller error, not a
        # finding, and must not be reported as a passing gate either.
        assert dep_matrix.main(argv + ["--require-repository", "not-a-repository"]) == 2


def test_declared_split_without_lockfile_is_not_hidden() -> None:
    repos = [_repo(name, [_decl(name, "widget", req)], [])
             for name, req in [("coauth", "1"), ("soland", "2")]]
    found = divergences(build_matrix(repos))
    assert found[0]["declared_split"]
    assert not found[0]["core_split"]
    payload = {"divergences": found}
    verdict = evaluate_exemptions(payload, {"exemptions": []}, "2026-10-09")
    assert [item["crate"] for item in verdict["uncovered"]] == ["widget"]
    narrow = {"exemptions": [{"crate": "widget", "majors": ["1"]}]}
    assert evaluate_exemptions(payload, narrow, "2026-10-09")["uncovered"][0]["unexpected_majors"] == ["2"]


def test_bad_member_manifest_fails_instead_of_narrowing_report() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary)
        repo = workspace / "soland"
        (repo / "member").mkdir(parents=True)
        (repo / "Cargo.toml").write_text('[workspace]\nmembers = ["member"]\n', encoding="utf-8")
        (repo / "member" / "Cargo.toml").write_text("[package\n", encoding="utf-8")
        assert dep_matrix.main(["--workspace-root", str(workspace), "--format", "text",
                                "--require-repository", "soland"]) == 2


def test_nonmatching_exemptions_explain_all_filtering_cases() -> None:
    payload = {"divergences": [
        {"crate": "external", "core_split": False, "actionable": True},
        {"crate": "upstream", "core_split": True, "actionable": False},
    ]}
    ledger = {"exemptions": [{"crate": name} for name in ["gone", "external", "upstream"]]}
    reasons = evaluate_exemptions(payload, ledger, "2026-10-09")["stale_exemption_reasons"]
    assert reasons == {
        "gone": "no divergence in analysed input",
        "external": "divergence only outside core shipping dependencies",
        "upstream": "core divergence is not actionable",
    }


def test_text_and_json_reports_use_the_same_verdict() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary)
        for name, version in [("coauth", "1"), ("soland", "2")]:
            repo = workspace / name
            repo.mkdir()
            (repo / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\n[dependencies]\nwidget = "{version}"\n',
                encoding="utf-8")
        ledger = workspace / "exemptions.json"
        ledger.write_text('{"exemptions": []}', encoding="utf-8")
        output = workspace / "report"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = dep_matrix.main(["--workspace-root", str(workspace), "--out-dir", str(output),
                                    "--format", "all", "--fail-on-divergence", "--exemptions", str(ledger)])
        assert code == 1
        payload = json.loads((output / "dep-matrix.json").read_text(encoding="utf-8"))
        assert [item["crate"] for item in payload["exemption_verdict"]["uncovered"]] == ["widget"]
        assert "uncovered: widget" in stdout.getvalue()
        assert (output / "dep-matrix.txt").read_text(encoding="utf-8") == dep_matrix.render_text(payload, False) + "\n"


def main() -> None:
    tests = [value for key, value in sorted(globals().items()) if key.startswith("test_")]
    for test in tests:
        test()
    print(f"dep_matrix: {len(tests)} checks passed")


if __name__ == "__main__":
    main()
