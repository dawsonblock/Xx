"""Validate identity-bound qualification artifacts without trusting PASS strings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

GATE_ARTIFACTS = {
    "statistical_calibration": "qualification/repair-1.3.6/multitask-statistical-qualification.json",
    "dependency_install": "qualification/repair-1.3.6/dependency-lock-install.json",
    "runtime_dependency_install": "qualification/repair-program/RUNTIME_DEPENDENCY_PROBE.json",
    "runtime_container": "qualification/repair-1.3.6/runtime-container.json",
    "linux_sandbox": "qualification/repair-program/SANDBOX_QUALIFICATION.json",
    "linux_hosted": "qualification/repair-1.3.6/hosted-workflow-runs.json",
    "macos_hosted": "qualification/repair-1.3.6/macos-hosted-result.json",
    "windows_hosted": "qualification/repair-1.3.6/windows-hosted-result.json",
    "benchmark_families": "BENCHMARK_FAMILY_MANIFEST.json",
    "real_null_controls": "qualification/repair-1.3.6/real-null-controls.json",
    "degraded_controls": "qualification/repair-1.3.6/degraded-controls.json",
    "planted_improvements": "qualification/repair-1.3.6/planted-improvements.json",
    "crash_fault_injection": "qualification/repair-1.3.6/crash-fault-injection.json",
    "external_anchor": "qualification/repair-1.3.6/anchor-result.json",
    "destructive_rollback": "qualification/repair-1.3.6/rollback-result.json",
    "key_authority": "qualification/repair-1.3.6/key-authority.json",
    "evidence_tampering": "qualification/repair-1.3.6/evidence-tampering.json",
    "atomic_promotion": "qualification/repair-1.3.6/atomic-promotion.json",
    "package_integrity": "qualification/repair-1.3.6/package-integrity.json",
    "clean_room": "qualification/repair-1.3.6/clean-room.json",
}

# A changed command changes the trusted policy file and invalidates its envelope.
GATE_COMMANDS = {
    "statistical_calibration": "python tools/qualify_canary_statistics.py",
    "dependency_install": "python -m pip install --require-hashes -r requirements-rsi-ci.lock",
    "runtime_dependency_install": "python -m pip install --require-hashes -r requirements-runtime.lock",
    "runtime_container": "docker build --pull --tag aideml-rsi-qualified .",
    "linux_sandbox": "python -m pytest -q tests/test_rsi_bubblewrap_adversarial.py",
    "linux_hosted": "github-actions:.github/workflows/linux-bubblewrap.yml",
    "macos_hosted": "github-actions:.github/workflows/macos-seatbelt.yml",
    "windows_hosted": "github-actions:.github/workflows/windows-rsi-state-lock.yml",
    "benchmark_families": "python tools/verify_release.py --check-benchmark-manifest",
    "real_null_controls": "python tools/run_real_null_controls.py",
    "degraded_controls": "python tools/run_degraded_controls.py",
    "planted_improvements": "python tools/run_planted_improvements.py",
    "crash_fault_injection": "python tools/run_crash_campaign.py",
    "external_anchor": "python -m pytest -q tests/test_rsi_anchor_external.py",
    "destructive_rollback": "python -m pytest -q tests/test_rsi_destructive_rollback.py",
    "key_authority": "python tools/audit_key_authority.py",
    "evidence_tampering": "python -m pytest -q tests/test_evidence_tampering.py",
    "atomic_promotion": "python -m pytest -q tests/test_atomic_promotion.py",
    "package_integrity": "python tools/verify_package.py --integrity-only",
    "clean_room": "python tools/run_clean_room_qualification.py",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


def validation_status(
    root: Path, gate_id: str, identity: dict[str, Any]
) -> dict[str, Any]:
    """Return PASS only for a complete envelope bound to current artifact bytes."""
    if gate_id not in GATE_ARTIFACTS:
        raise ValueError(f"unknown qualification gate: {gate_id}")
    artifact_name = GATE_ARTIFACTS[gate_id]
    artifact = root / artifact_name
    envelope_name = f"qualification/repair-1.3.6/evidence-{gate_id}.json"
    envelope_path = root / envelope_name
    result: dict[str, Any] = {
        "gate_id": gate_id,
        "artifact": artifact_name,
        "envelope": envelope_name,
        "status": (
            "NOT_RUN"
            if not artifact.exists() and not envelope_path.exists()
            else "STALE"
        ),
        "artifact_sha256": None,
        "envelope_sha256": None,
    }
    if not artifact.is_file() or not envelope_path.is_file():
        return result
    if artifact.is_symlink() or envelope_path.is_symlink():
        return result
    artifact_bytes = artifact.read_bytes()
    result["artifact_sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
    result["envelope_sha256"] = hashlib.sha256(envelope_path.read_bytes()).hexdigest()
    try:
        envelope = _read_json(envelope_path)
    except (OSError, UnicodeError, ValueError):
        return result
    if not isinstance(envelope, dict):
        return result
    required = {
        "schema_version",
        "gate_id",
        "artifact",
        "artifact_sha256",
        "command",
        "python_version",
        "platform",
        "exit_code",
        "status",
        *(
            key
            for key in identity
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        ),
    }
    if not required <= set(envelope):
        return result
    valid = (
        envelope["schema_version"] == 1
        and envelope["gate_id"] == gate_id
        and envelope["artifact"] == artifact_name
        and envelope["artifact_sha256"] == result["artifact_sha256"]
        and envelope["command"] == GATE_COMMANDS[gate_id]
        and isinstance(envelope["python_version"], str)
        and envelope["python_version"].startswith("3.12.")
        and isinstance(envelope["platform"], str)
        and bool(envelope["platform"])
        and envelope["exit_code"] == 0
        and envelope["status"] == "PASS"
        and all(
            envelope.get(key) == value
            for key, value in identity.items()
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        )
    )
    if valid:
        result["status"] = "PASS"
    return result


def validation_matrix(
    root: Path, identity: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    return {
        gate_id: validation_status(root, gate_id, identity)
        for gate_id in sorted(GATE_ARTIFACTS)
    }
