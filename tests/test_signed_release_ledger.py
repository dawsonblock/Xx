"""A signer attests results but cannot redefine source qualification policy."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

import pytest

from tools.evidence_schema import canonical_bytes
from tools.gate_specs import ARTIFACT_GATES, GATE_SPECS, SOURCE_GATES
from tools.verify_release import (
    LEDGER,
    LEDGER_PUBLIC_KEY,
    LEDGER_SIGNATURE,
    verify_signed_ledger,
)

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="OpenSSL is required"
)

IDENTITY_KEYS = (
    "source_snapshot_sha256",
    "aggregate_tcb_sha256",
    "dependency_lock_sha256",
    "runtime_dependency_lock_sha256",
    "statistical_protocol_sha256",
    "evaluator_sha256",
    "benchmark_family_manifest_sha256",
)


def _run(*args):
    subprocess.run(args, check=True, capture_output=True)


def _sign(root, private_key, ledger):
    (root / LEDGER).write_bytes(canonical_bytes(ledger))
    _run(
        "openssl",
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        str(private_key),
        "-in",
        str(root / LEDGER),
        "-out",
        str(root / LEDGER_SIGNATURE),
    )


@pytest.fixture
def signed_ledger(tmp_path):
    identity = {
        **{key: f"{index:x}" * 64 for index, key in enumerate(IDENTITY_KEYS, 1)},
        "runtime_tcb_sha256": "8" * 64,
        "release_tcb_sha256": "9" * 64,
        "statistical_tcb_sha256": "a" * 64,
        "sandbox_tcb_sha256": "b" * 64,
        "docker_build_context_sha256": "c" * 64,
        "docker_base_image_digest": "d" * 64,
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
    for gate_id in sorted(SOURCE_GATES):
        spec = GATE_SPECS[gate_id]
        evidence_path = tmp_path / spec.evidence_path
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        result = {"status": "PASS", "exit_code": 0, "details": {"observed": True}}
        evidence = {
            "schema_version": 2,
            "gate_id": gate_id,
            "runner_id": spec.runner_id,
            "verifier_id": spec.verifier_id,
            "phase": "source",
            "identity": {key: identity[key] for key in spec.source_identity_requirements},
            "environment": {
                "python": "3.12.3",
                "platform": "test-linux",
                "architecture": "x86_64",
            },
            "parameters": {},
            "artifacts": [],
            "result": result,
        }
        evidence_bytes = canonical_bytes(evidence)
        evidence_path.write_bytes(evidence_bytes)
        gates.append(
            {
                "gate_id": gate_id,
                "phase": "source",
                "runner_id": spec.runner_id,
                "verifier_id": spec.verifier_id,
                "parameters": {},
                "evidence_path": spec.evidence_path,
                "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                "result": result,
            }
        )
    ledger = {
        "schema_version": 2,
        "qualification_status": "SOURCE_QUALIFIED",
        "qualification_phase": "source",
        "source_commit": "a" * 40,
        "identity": {
            key: value
            for key, value in identity.items()
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        },
        "gates": gates,
    }
    _sign(tmp_path, private_key, ledger)
    return tmp_path, identity, ledger, private_key


def _mutate_and_verify(signed_ledger, mutate):
    root, identity, ledger, private_key = signed_ledger
    changed = json.loads(json.dumps(ledger))
    mutate(changed)
    _sign(root, private_key, changed)
    verify_signed_ledger(
        root=root,
        identity=identity,
        source_commit="a" * 40,
    )


def _gate(ledger, gate_id="pytest"):
    return next(gate for gate in ledger["gates"] if gate["gate_id"] == gate_id)


def test_valid_signed_source_ledger_binds_every_gate(signed_ledger):
    root, identity, _, _ = signed_ledger
    verify_signed_ledger(root=root, identity=identity, source_commit="a" * 40)


def test_signed_ledger_identity_and_commit_must_match(signed_ledger):
    root, identity, _, _ = signed_ledger
    with pytest.raises(ValueError, match="source commit differs"):
        verify_signed_ledger(root=root, identity=identity, source_commit="b" * 40)
    changed = dict(identity, aggregate_tcb_sha256="e" * 64)
    with pytest.raises(ValueError, match="identity differs"):
        verify_signed_ledger(root=root, identity=changed, source_commit="a" * 40)


def test_valid_signer_cannot_change_pytest_runner(signed_ledger):
    with pytest.raises(ValueError, match="policy differs"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: _gate(ledger).__setitem__("runner_id", "fake-runner"),
        )


def test_valid_signer_cannot_change_pytest_verifier(signed_ledger):
    with pytest.raises(ValueError, match="policy differs"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: _gate(ledger).__setitem__("verifier_id", "pytest"),
        )


def test_valid_signer_cannot_redirect_evidence(signed_ledger):
    with pytest.raises(ValueError, match="evidence path differs"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: _gate(ledger).__setitem__(
                "evidence_path", "qualification/arbitrary.txt"
            ),
        )


def test_valid_signer_cannot_invent_gate(signed_ledger):
    with pytest.raises(ValueError, match="unknown qualification gate"):
        def mutate(ledger):
            ledger["gates"].pop()
            ledger["gates"].append({"gate_id": "invented"})

        _mutate_and_verify(signed_ledger, mutate)


def test_valid_signer_cannot_duplicate_gate(signed_ledger):
    with pytest.raises(ValueError, match="duplicate"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: ledger["gates"].append(
                json.loads(json.dumps(_gate(ledger)))
            ),
        )


def test_valid_signer_cannot_omit_mandatory_gate(signed_ledger):
    with pytest.raises(ValueError, match="exact mandatory"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: ledger["gates"].pop(),
        )


def test_pytest_evidence_cannot_bypass_common_schema(signed_ledger):
    root, identity, ledger, private_key = signed_ledger
    entry = _gate(ledger)
    evidence_path = root / entry["evidence_path"]
    evidence_path.write_bytes(canonical_bytes({"schema_version": 1, "status": "PASS"}))
    changed = json.loads(json.dumps(ledger))
    _gate(changed)["evidence_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    _sign(root, private_key, changed)
    with pytest.raises(ValueError, match="evidence has invalid fields"):
        verify_signed_ledger(root=root, identity=identity, source_commit="a" * 40)


def test_package_integrity_gates_are_artifact_only():
    assert not ({"package_integrity", "wheel_integrity"} & SOURCE_GATES)
    assert {"wheel_integrity", "sdist_integrity", "source_zip_integrity"} <= ARTIFACT_GATES


def test_source_ledger_rejects_artifact_phase(signed_ledger):
    with pytest.raises(ValueError, match="artifact gate appears"):
        _mutate_and_verify(
            signed_ledger,
            lambda ledger: _gate(ledger).__setitem__("gate_id", "wheel_integrity"),
        )
