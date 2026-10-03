"""Every qualification artifact needs matching bytes, identity, and command."""

from __future__ import annotations

import hashlib
import json

import pytest

from tools import qualification_evidence


@pytest.fixture
def bound_gate(tmp_path):
    gate_id = "dependency_install"
    artifact_name = qualification_evidence.GATE_ARTIFACTS[gate_id]
    artifact = tmp_path / artifact_name
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"installed": true}\n')
    identity = {
        "source_snapshot_sha256": "a" * 64,
        "aggregate_tcb_sha256": "b" * 64,
        "dependency_lock_sha256": "c" * 64,
        "statistical_protocol_sha256": "d" * 64,
        "evaluator_sha256": "e" * 64,
        "benchmark_family_manifest_sha256": "f" * 64,
        "docker_base_image_digest": "1" * 64,
    }
    envelope = {
        "schema_version": 1,
        "gate_id": gate_id,
        "artifact": artifact_name,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "command": qualification_evidence.GATE_COMMANDS[gate_id],
        "python_version": "3.12.12",
        "platform": "test-linux",
        "exit_code": 0,
        "status": "PASS",
        **identity,
    }
    envelope_path = tmp_path / f"qualification/repair-1.3.6/evidence-{gate_id}.json"
    envelope_path.write_text(json.dumps(envelope))
    return tmp_path, identity, artifact, envelope_path, envelope


def test_matching_artifact_and_identity_pass(bound_gate):
    root, identity, *_ = bound_gate
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "PASS"
    )


def test_historical_artifact_without_envelope_is_stale(bound_gate):
    root, identity, _, envelope_path, _ = bound_gate
    envelope_path.unlink()
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


@pytest.mark.parametrize(
    "field",
    [
        "source_snapshot_sha256",
        "aggregate_tcb_sha256",
        "dependency_lock_sha256",
        "statistical_protocol_sha256",
        "evaluator_sha256",
        "benchmark_family_manifest_sha256",
        "docker_base_image_digest",
    ],
)
def test_authority_change_stales_other_qualification_artifacts(bound_gate, field):
    root, identity, *_ = bound_gate
    identity[field] = "0" * 64
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


def test_artifact_or_command_mutation_stales_gate(bound_gate):
    root, identity, artifact, envelope_path, envelope = bound_gate
    artifact.write_text('{"installed": false}\n')
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )
    artifact.write_text('{"installed": true}\n')
    envelope["command"] = "python -m pip install requirements-rsi-ci.lock"
    envelope_path.write_text(json.dumps(envelope))
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )


def test_duplicate_json_keys_cannot_claim_pass(bound_gate):
    root, identity, _, envelope_path, envelope = bound_gate
    data = json.dumps(envelope)
    envelope_path.write_text(data[:-1] + ', "status": "PASS"}')
    assert (
        qualification_evidence.validation_status(root, "dependency_install", identity)[
            "status"
        ]
        == "STALE"
    )
