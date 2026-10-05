"""JUnit only counts when its envelope matches every current identity."""

from __future__ import annotations

import hashlib

import pytest

from tools import generate_release_manifests as manifests
from tools.evidence_schema import canonical_bytes
from tools.gate_specs import gate_spec


@pytest.fixture
def bound_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    test_file = tmp_path / "tests/test_example.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_ok(): assert True\n")
    qualification = tmp_path / "qualification/repair-1.3.6"
    qualification.mkdir(parents=True)
    junit = qualification / "pytest-junit.xml"
    junit.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"/>')
    identity = {
        "source_snapshot_sha256": "a" * 64,
        "runtime_tcb_sha256": "1" * 64,
        "release_tcb_sha256": "2" * 64,
        "statistical_tcb_sha256": "3" * 64,
        "sandbox_tcb_sha256": "4" * 64,
        "aggregate_tcb_sha256": "b" * 64,
        "dependency_lock_sha256": "c" * 64,
        "runtime_dependency_lock_sha256": "5" * 64,
        "statistical_protocol_sha256": "d" * 64,
        "evaluator_sha256": "e" * 64,
        "benchmark_family_manifest_sha256": "f" * 64,
        "docker_base_image_digest": "6" * 64,
        "docker_build_context_sha256": "7" * 64,
    }
    spec = gate_spec("pytest")
    envelope = {
        "schema_version": 2,
        "gate_id": spec.gate_id,
        "runner_id": spec.runner_id,
        "verifier_id": spec.verifier_id,
        "phase": spec.phase,
        "identity": identity,
        "environment": {
            "python": "3.12.0",
            "platform": "test-platform",
            "architecture": "x86_64",
        },
        "parameters": {},
        "artifacts": [
            {
                "artifact_id": "junit",
                "sha256": hashlib.sha256(junit.read_bytes()).hexdigest(),
            }
        ],
        "result": {
            "status": "PASS",
            "exit_code": 0,
            "details": {
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "test_inventory_sha256": manifests._canonical_sha256(
                    manifests._file_hashes(["tests/test_example.py"])
                ),
            },
        },
    }
    evidence = tmp_path / spec.evidence_path
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(canonical_bytes(envelope))
    return identity, envelope, evidence, junit, test_file


def test_unchanged_identity_and_evidence_pass(bound_evidence):
    identity, *_ = bound_evidence
    assert manifests._pytest_validation(identity)["status"] == "PASS"


@pytest.mark.parametrize(
    "field",
    [
        "source_snapshot_sha256",
        "runtime_tcb_sha256",
        "release_tcb_sha256",
        "statistical_tcb_sha256",
        "sandbox_tcb_sha256",
        "aggregate_tcb_sha256",
        "dependency_lock_sha256",
        "runtime_dependency_lock_sha256",
        "statistical_protocol_sha256",
        "evaluator_sha256",
        "benchmark_family_manifest_sha256",
        "docker_base_image_digest",
        "docker_build_context_sha256",
    ],
)
def test_authority_change_makes_test_evidence_stale(bound_evidence, field):
    identity, *_ = bound_evidence
    identity[field] = "0" * 64
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"


def test_junit_binding_and_test_inventory_changes_are_stale(bound_evidence):
    identity, envelope, evidence, junit, test_file = bound_evidence
    junit.write_text(junit.read_text() + " ")
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
    junit.write_text(junit.read_text().rstrip())
    envelope["runner_id"] = "arbitrary-runner"
    evidence.write_bytes(canonical_bytes(envelope))
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
    envelope["runner_id"] = gate_spec("pytest").runner_id
    evidence.write_bytes(canonical_bytes(envelope))
    test_file.write_text("def test_ok(): assert 1 == 1\n")
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
