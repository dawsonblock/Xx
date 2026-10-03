"""JUnit only counts when its envelope matches every current identity."""

from __future__ import annotations

import hashlib
import json

import pytest

from tools import generate_release_manifests as manifests


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
        "aggregate_tcb_sha256": "b" * 64,
        "dependency_lock_sha256": "c" * 64,
        "statistical_protocol_sha256": "d" * 64,
        "evaluator_sha256": "e" * 64,
        "benchmark_family_manifest_sha256": "f" * 64,
    }
    envelope = {
        "schema_version": 1,
        **identity,
        "junit_sha256": hashlib.sha256(junit.read_bytes()).hexdigest(),
        "test_command": manifests.TEST_QUALIFICATION_COMMAND,
        "test_inventory_sha256": manifests._canonical_sha256(
            manifests._file_hashes(["tests/test_example.py"])
        ),
        "python_version": "3.12.0",
        "platform": "test-platform",
        "exit_code": 0,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
    }
    evidence = qualification / "pytest-evidence.json"
    evidence.write_text(json.dumps(envelope))
    return identity, envelope, evidence, junit, test_file


def test_unchanged_identity_and_evidence_pass(bound_evidence):
    identity, *_ = bound_evidence
    assert manifests._pytest_validation(identity)["status"] == "PASS"


@pytest.mark.parametrize(
    "field",
    [
        "source_snapshot_sha256",
        "aggregate_tcb_sha256",
        "dependency_lock_sha256",
        "statistical_protocol_sha256",
        "evaluator_sha256",
        "benchmark_family_manifest_sha256",
    ],
)
def test_authority_change_makes_test_evidence_stale(bound_evidence, field):
    identity, *_ = bound_evidence
    identity[field] = "0" * 64
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"


def test_junit_command_and_test_inventory_changes_are_stale(bound_evidence):
    identity, envelope, evidence, junit, test_file = bound_evidence
    junit.write_text(junit.read_text() + " ")
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
    junit.write_text(junit.read_text().rstrip())
    envelope["test_command"] = "python -m pytest tests/test_example.py"
    evidence.write_text(json.dumps(envelope))
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
    envelope["test_command"] = manifests.TEST_QUALIFICATION_COMMAND
    evidence.write_text(json.dumps(envelope))
    test_file.write_text("def test_ok(): assert 1 == 1\n")
    assert manifests._pytest_validation(identity)["status"] == "STALE_OR_UNBOUND"
