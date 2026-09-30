"""Validation helpers for evaluator provenance attached to replay outcomes."""

import hashlib
import json
import math
import re
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_EVALUATION_HASHES = (
    "candidate_sha256",
    "evaluator_sha256",
    "dataset_sha256",
    "split_sha256",
    "result_sha256",
)


def evaluation_result_digest(provenance: dict[str, Any], score: float) -> str:
    """Bind the measured scalar and direction to source and evaluator identities."""
    payload = {
        key: provenance[key]
        for key in (
            "candidate_sha256",
            "evaluator_sha256",
            "dataset_sha256",
            "split_sha256",
        )
    }
    payload["metric_maximize"] = provenance["metric_maximize"]
    payload["metric_value"] = float(score)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def has_trusted_evaluation(node: Any) -> bool:
    """Require host-recorded authority and complete immutable evaluator bindings."""
    provenance = getattr(node, "provenance", {}) or {}
    if provenance.get("evaluation_authority") != "trusted_external":
        return False
    if not all(
        isinstance(provenance.get(key), str)
        and _SHA256_RE.fullmatch(provenance[key]) is not None
        for key in _REQUIRED_EVALUATION_HASHES
    ):
        return False
    if not isinstance(provenance.get("metric_maximize"), bool):
        return False
    try:
        score = float(node.score)
    except (TypeError, ValueError, AttributeError):
        return False
    return math.isfinite(score) and provenance[
        "result_sha256"
    ] == evaluation_result_digest(provenance, score)
