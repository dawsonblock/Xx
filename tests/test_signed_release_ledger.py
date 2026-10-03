"""A status string cannot replace a signature over source-bound evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

import pytest

from tools.verify_release import (
    LEDGER,
    LEDGER_PUBLIC_KEY,
    LEDGER_SIGNATURE,
    REQUIRED_GATES,
    verify_signed_ledger,
)

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="OpenSSL is required"
)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _run(*args):
    subprocess.run(args, check=True, capture_output=True)


@pytest.fixture
def signed_ledger(tmp_path):
    identity = {
        "source_snapshot_sha256": "a" * 64,
        "runtime_tcb_sha256": "b" * 64,
        "release_tcb_sha256": "c" * 64,
        "statistical_tcb_sha256": "d" * 64,
        "sandbox_tcb_sha256": "e" * 64,
        "aggregate_tcb_sha256": "f" * 64,
        "dependency_lock_sha256": "1" * 64,
        "runtime_dependency_lock_sha256": "2" * 64,
        "statistical_protocol_sha256": "3" * 64,
        "evaluator_sha256": "4" * 64,
        "benchmark_family_manifest_sha256": "5" * 64,
        "docker_build_context_sha256": "6" * 64,
        "docker_base_image_digest": "7" * 64,
    }
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / LEDGER_PUBLIC_KEY
    public_key.parent.mkdir(parents=True)
    _run("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key))
    _run(
        "openssl",
        "pkey",
        "-in",
        str(private_key),
        "-pubout",
        "-out",
        str(public_key),
    )
    gates = []
    for gate_id in sorted(REQUIRED_GATES):
        evidence_path = f"qualification/evidence/{gate_id}.json"
        envelope_path = f"qualification/evidence/{gate_id}-envelope.json"
        evidence = _canonical({"gate": gate_id, "result": "observed"})
        evidence_file = tmp_path / evidence_path
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        evidence_file.write_bytes(evidence)
        command = f"run qualified gate {gate_id}"
        envelope = {
            "schema_version": 1,
            "gate_id": gate_id,
            "artifact": evidence_path,
            "artifact_sha256": hashlib.sha256(evidence).hexdigest(),
            "command": command,
            "python_version": "3.12.12",
            "platform": "test-linux",
            "exit_code": 0,
            "status": "PASS",
            **identity,
        }
        envelope_bytes = _canonical(envelope)
        envelope_file = tmp_path / envelope_path
        envelope_file.write_bytes(envelope_bytes)
        gates.append(
            {
                "gate_id": gate_id,
                "mandatory": True,
                "status": "PASS",
                "command": command,
                "environment": {},
                "platform": "test-linux",
                "started_at": "2026-10-03T00:00:00Z",
                "ended_at": "2026-10-03T00:00:01Z",
                "exit_code": 0,
                "evidence_path": evidence_path,
                "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                "envelope_path": envelope_path,
                "envelope_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
                **identity,
            }
        )
    ledger = {
        "schema_version": 1,
        "release_status": "RELEASE_QUALIFIED",
        "source_commit": "a" * 40,
        "identity": identity,
        "gates": gates,
    }
    ledger_bytes = _canonical(ledger)
    (tmp_path / LEDGER).write_bytes(ledger_bytes)
    signature_path = tmp_path / LEDGER_SIGNATURE
    _run(
        "openssl",
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        str(private_key),
        "-in",
        str(tmp_path / LEDGER),
        "-out",
        str(signature_path),
    )
    return tmp_path, identity, ledger


def test_valid_signed_ledger_binds_every_gate_and_artifact(signed_ledger):
    root, identity, _ = signed_ledger
    verify_signed_ledger(root=root, identity=identity, source_commit="a" * 40)


def test_ledger_signature_and_gate_evidence_tampering_fail(signed_ledger):
    root, identity, _ = signed_ledger
    evidence = root / "qualification/evidence/pytest.json"
    evidence.write_text('{"forged": true}')
    with pytest.raises(ValueError, match="evidence bytes differ"):
        verify_signed_ledger(root=root, identity=identity, source_commit="a" * 40)


def test_ledger_identity_and_commit_must_match(signed_ledger):
    root, identity, _ = signed_ledger
    with pytest.raises(ValueError, match="source commit differs"):
        verify_signed_ledger(root=root, identity=identity, source_commit="b" * 40)
    changed = dict(identity, aggregate_tcb_sha256="8" * 64)
    with pytest.raises(ValueError, match="identity differs"):
        verify_signed_ledger(root=root, identity=changed, source_commit="a" * 40)
