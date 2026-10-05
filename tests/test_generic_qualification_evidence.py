"""Qualification evidence uses one identity-bound envelope for every gate."""

from __future__ import annotations

import json

import pytest

from tools.evidence_schema import canonical_bytes
from tools.evidence_schema import validate_evidence
from tools.gate_specs import GATE_SPECS
from tools import qualification_evidence


@pytest.fixture
def bound_evidence(tmp_path):
    gate_id = "dependency_install"
    spec = GATE_SPECS[gate_id]
    identity = {
        "source_snapshot_sha256": "a" * 64,
        "runtime_tcb_sha256": "2" * 64,
        "release_tcb_sha256": "3" * 64,
        "statistical_tcb_sha256": "4" * 64,
        "sandbox_tcb_sha256": "5" * 64,
        "aggregate_tcb_sha256": "b" * 64,
        "dependency_lock_sha256": "c" * 64,
        "runtime_dependency_lock_sha256": "d" * 64,
        "statistical_protocol_sha256": "e" * 64,
        "evaluator_sha256": "f" * 64,
        "benchmark_family_manifest_sha256": "1" * 64,
        "docker_build_context_sha256": "6" * 64,
        "docker_base_image_digest": "7" * 64,
    }
    evidence = {
        "schema_version": 2,
        "gate_id": gate_id,
        "runner_id": spec.runner_id,
        "verifier_id": spec.verifier_id,
        "phase": "source",
        "identity": {key: identity[key] for key in spec.source_identity_requirements},
        "environment": {
            "python": "3.12.1",
            "platform": "test-linux",
            "architecture": "x86_64",
        },
        "parameters": {},
        "artifacts": [],
        "result": {"status": "PASS", "exit_code": 0, "details": {"installed": True}},
    }
    path = tmp_path / spec.evidence_path
    path.parent.mkdir(parents=True)
    path.write_bytes(canonical_bytes(evidence))
    return tmp_path, identity, path, evidence


def test_matching_evidence_and_identity_pass(bound_evidence):
    root, identity, *_ = bound_evidence
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "PASS"
    )


def test_missing_evidence_is_not_run(bound_evidence):
    root, identity, path, _ = bound_evidence
    path.unlink()
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "NOT_RUN"
    )


@pytest.mark.parametrize(
    "field",
    [
        "source_snapshot_sha256",
        "aggregate_tcb_sha256",
        "runtime_tcb_sha256",
        "release_tcb_sha256",
        "statistical_tcb_sha256",
        "sandbox_tcb_sha256",
        "dependency_lock_sha256",
        "runtime_dependency_lock_sha256",
        "statistical_protocol_sha256",
        "evaluator_sha256",
        "benchmark_family_manifest_sha256",
        "docker_build_context_sha256",
        "docker_base_image_digest",
    ],
)
def test_authority_change_stales_evidence(bound_evidence, field):
    root, identity, *_ = bound_evidence
    identity[field] = "0" * 64
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda evidence: evidence.__setitem__("runner_id", "fake"),
        lambda evidence: evidence.__setitem__("verifier_id", "fake"),
        lambda evidence: evidence.__setitem__("phase", "artifact"),
        lambda evidence: evidence.__setitem__("command", "arbitrary shell"),
        lambda evidence: evidence["result"].__setitem__("status", "FAIL"),
        lambda evidence: evidence["identity"].__setitem__(
            "source_snapshot_sha256", "0" * 64
        ),
    ],
)
def test_policy_or_identity_tampering_stales_evidence(bound_evidence, mutation):
    root, identity, path, evidence = bound_evidence
    changed = json.loads(json.dumps(evidence))
    mutation(changed)
    path.write_bytes(canonical_bytes(changed))
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


def test_unknown_fields_duplicate_keys_and_nonfinite_values_are_rejected(
    bound_evidence,
):
    root, identity, path, evidence = bound_evidence
    changed = dict(evidence, surprise=True)
    path.write_bytes(canonical_bytes(changed))
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )
    path.write_text('{"schema_version":2,"schema_version":2}')
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )
    path.write_text('{"value":NaN}')
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


def test_artifact_evidence_binds_runner_parameters_and_hashes(bound_evidence):
    _, identity, _, _ = bound_evidence
    spec = GATE_SPECS["wheel_integrity"]
    artifact_hash = "8" * 64
    evidence = {
        "schema_version": 2,
        "gate_id": spec.gate_id,
        "runner_id": spec.runner_id,
        "verifier_id": spec.verifier_id,
        "phase": spec.phase,
        "identity": {key: identity[key] for key in spec.source_identity_requirements},
        "environment": {
            "python": "3.12.3",
            "platform": "test-linux",
            "architecture": "x86_64",
        },
        "parameters": {"wheel_sha256": artifact_hash},
        "artifacts": [{"artifact_id": "wheel", "sha256": artifact_hash}],
        "result": {"status": "PASS", "exit_code": 0, "details": {}},
    }
    validate_evidence(evidence, spec=spec, identity=identity)
    evidence["artifacts"][0]["sha256"] = "9" * 64
    with pytest.raises(ValueError, match="hashes differ"):
        validate_evidence(evidence, spec=spec, identity=identity)
