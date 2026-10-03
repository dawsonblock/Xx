"""Regression checks for release authority identity generation."""

from __future__ import annotations

import json

from tools import generate_release_manifests as manifests


def test_release_authority_files_are_covered():
    groups = manifests._tcb_groups(manifests._source_paths())
    release = set(groups["release_tcb"])
    sandbox = set(groups["sandbox_tcb"])
    assert {
        ".github/workflows/python-publish.yml",
        ".github/workflows/package-smoke.yml",
        ".github/workflows/linux-bubblewrap.yml",
        "Dockerfile",
        "Makefile",
        "setup.py",
        "MANIFEST.in",
        "tools/verify_package.py",
        "tools/generate_release_manifests.py",
        "requirements-rsi-ci.in",
        "requirements-rsi-ci.lock",
        "VERSION",
    } <= release
    assert {"Dockerfile", ".github/workflows/linux-bubblewrap.yml"} <= sandbox


def test_identity_is_deterministic_and_separate_from_status():
    first = manifests.build_manifests()
    second = manifests.build_manifests()
    for name in manifests.OUTPUTS:
        assert json.dumps(first[name], sort_keys=True, indent=2) == json.dumps(
            second[name], sort_keys=True, indent=2
        )
    identity = first["IDENTITY_MANIFEST.json"]
    assert "release_status" not in identity
    assert "qualification" not in identity
    assert (
        identity["release_tcb_sha256"]
        == first["TCB_MANIFEST.json"]["group_digests"]["release_tcb"]
    )
    assert len(identity["docker_base_image_digest"]) == 64
    assert identity["docker_build_context_sha256"] == identity["source_snapshot_sha256"]


def test_release_workflow_change_invalidates_aggregate_identity(tmp_path, monkeypatch):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    workflow = tmp_path / ".github/workflows/python-publish.yml"
    workflow.write_text("name: first\n")
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    first = manifests._tcb_groups(manifests._source_paths())
    first_digest = manifests._canonical_sha256(
        manifests._file_hashes(sorted(set().union(*first.values())))
    )
    workflow.write_text("name: changed\n")
    second = manifests._tcb_groups(manifests._source_paths())
    second_digest = manifests._canonical_sha256(
        manifests._file_hashes(sorted(set().union(*second.values())))
    )
    assert first_digest != second_digest
