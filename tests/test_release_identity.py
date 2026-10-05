"""Regression checks for release authority identity generation."""

from __future__ import annotations

import json

import pytest

from tools import generate_release_manifests as manifests


def test_release_authority_files_are_covered():
    groups = manifests._tcb_groups(manifests._source_paths())
    release = set(groups["release_tcb"])
    runtime = set(groups["runtime_tcb"])
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
        "requirements-runtime.lock",
        "VERSION",
    } <= release
    assert {"requirements-runtime.lock", "requirements.txt"} <= runtime
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


def test_generated_evidence_does_not_change_source_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    source = tmp_path / "tools/verify_release.py"
    source.parent.mkdir()
    source.write_text("source policy\n")
    before = manifests._canonical_sha256(
        manifests._file_hashes(manifests._source_paths())
    )
    generated = {
        "RELEASE_QUALIFICATION_LEDGER.json",
        "RELEASE_QUALIFICATION_LEDGER.sig",
        "SOURCE_QUALIFICATION_LEDGER.json",
        "SOURCE_QUALIFICATION_LEDGER.sig",
        "BUILD_PROVENANCE.json",
        "ARTIFACT_ATTESTATION.json",
        "ARTIFACT_ATTESTATION.sig",
        "PUBLICATION_RECEIPT.json",
        "PACKAGE_HASHES.json",
        "qualification/evidence/pytest.json",
    }
    for name in generated:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("generated evidence\n")
    after = manifests._canonical_sha256(
        manifests._file_hashes(manifests._source_paths())
    )
    assert before == after


def test_public_key_and_gate_policy_remain_source_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    for name in (
        "release/qualification-ledger-public.pem",
        "tools/verify_release.py",
        "tools/gate_specs.py",
        "tools/evidence_schema.py",
        "tools/generate_release_manifests.py",
        "BENCHMARK_FAMILY_MANIFEST.json",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("source authority\n")
    source_paths = set(manifests._source_paths())
    assert {
        "release/qualification-ledger-public.pem",
        "tools/verify_release.py",
        "tools/gate_specs.py",
        "tools/evidence_schema.py",
        "tools/generate_release_manifests.py",
        "BENCHMARK_FAMILY_MANIFEST.json",
    } <= source_paths


@pytest.mark.parametrize(
    "name",
    [
        "RELEASE_QUALIFICATION_LEDGER.json",
        "RELEASE_QUALIFICATION_LEDGER.sig",
        "SOURCE_QUALIFICATION_LEDGER.json",
        "SOURCE_QUALIFICATION_LEDGER.sig",
        "BUILD_PROVENANCE.json",
        "ARTIFACT_ATTESTATION.json",
        "ARTIFACT_ATTESTATION.sig",
    ],
)
def test_generated_release_files_are_excluded_from_source_identity(
    tmp_path, monkeypatch, name
):
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    policy = tmp_path / "tools/gate_specs.py"
    policy.parent.mkdir()
    policy.write_text("policy\n")
    before = set(manifests._source_paths())
    output = tmp_path / name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("generated\n")
    assert set(manifests._source_paths()) == before
