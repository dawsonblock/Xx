"""Validate qualification evidence using the source-controlled gate policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.evidence_schema import canonical_bytes, parse_json, sha256, validate_evidence
from tools.gate_specs import GATE_SPECS, gate_spec

GATE_ARTIFACTS = {gate_id: spec.evidence_path for gate_id, spec in GATE_SPECS.items()}


def validation_status(
    root: Path, gate_id: str, identity: dict[str, Any]
) -> dict[str, Any]:
    """Return PASS only for a canonical v2 envelope bound to the current identity."""
    spec = gate_spec(gate_id)
    evidence_path = root / spec.evidence_path
    result: dict[str, Any] = {
        "gate_id": gate_id,
        "evidence": spec.evidence_path,
        "status": "NOT_RUN" if not evidence_path.exists() else "STALE",
        "evidence_sha256": None,
    }
    if not evidence_path.is_file() or evidence_path.is_symlink():
        return result
    evidence_bytes = evidence_path.read_bytes()
    result["evidence_sha256"] = sha256(evidence_bytes)
    try:
        envelope = parse_json(evidence_bytes)
        if evidence_bytes != canonical_bytes(envelope):
            return result
        validate_evidence(
            envelope,
            spec=spec,
            identity=identity,
            parameters=envelope.get("parameters") if isinstance(envelope, dict) else None,
        )
    except (OSError, UnicodeError, ValueError):
        return result
    result["status"] = "PASS"
    return result


def validation_matrix(
    root: Path, identity: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    return {
        gate_id: validation_status(root, gate_id, identity)
        for gate_id in sorted(GATE_SPECS)
    }
