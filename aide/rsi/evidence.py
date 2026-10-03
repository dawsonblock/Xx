"""Validation helpers for evaluator provenance attached to replay outcomes."""

import hashlib
import hmac
import json
import math
import os
import re
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_EVALUATION_HASHES = (
    "candidate_sha256",
    "evaluator_sha256",
    "evaluator_config_sha256",
    "task_sha256",
    "dataset_sha256",
    "split_sha256",
    "predictions_sha256",
    "environment_sha256",
    "result_sha256",
    "evaluation_record_sha256",
)
_REQUIRED_EVALUATION_TEXT = ("metric_id",)
_ATTESTATION_KEY_ENV = "AIDE_RSI_EVALUATION_HMAC_KEY"


def evaluation_result_digest(provenance: dict[str, Any], score: float) -> str:
    """Bind the measured scalar and direction to source and evaluator identities."""
    payload = {
        key: provenance[key]
        for key in (
            "candidate_sha256",
            "evaluator_sha256",
            "evaluator_config_sha256",
            "task_sha256",
            "dataset_sha256",
            "split_sha256",
            "predictions_sha256",
            "environment_sha256",
            "metric_id",
        )
    }
    payload["metric_maximize"] = provenance["metric_maximize"]
    payload["metric_value"] = float(score)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def evaluation_record_bytes(provenance: dict[str, Any], score: float) -> bytes:
    """Canonical unsigned record body used as the evaluation CAS object."""
    payload = {
        key: value
        for key, value in provenance.items()
        if key not in {"evaluation_record_sha256", "attestation_hmac_sha256"}
    }
    payload["metric_value"] = float(score)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _evaluation_key(key: str | bytes | None = None) -> bytes | None:
    raw = key if key is not None else os.environ.get(_ATTESTATION_KEY_ENV)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, bytes) or len(raw) < 32:
        return None
    return raw


def _attestation_payload(provenance: dict[str, Any], score: float) -> bytes:
    payload = {
        "evaluation_authority": "trusted_external",
        "candidate_sha256": provenance["candidate_sha256"],
        "evaluator_sha256": provenance["evaluator_sha256"],
        "evaluator_config_sha256": provenance["evaluator_config_sha256"],
        "task_sha256": provenance["task_sha256"],
        "dataset_sha256": provenance["dataset_sha256"],
        "split_sha256": provenance["split_sha256"],
        "predictions_sha256": provenance["predictions_sha256"],
        "environment_sha256": provenance["environment_sha256"],
        "metric_id": provenance["metric_id"],
        "result_sha256": provenance["result_sha256"],
        "evaluation_record_sha256": provenance["evaluation_record_sha256"],
        "metric_maximize": provenance["metric_maximize"],
        "metric_value": float(score),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def attest_evaluation(
    provenance: dict[str, Any], score: float, *, key: str | bytes | None = None
) -> dict[str, Any]:
    """Create a host-only HMAC attestation after an external evaluator returns."""
    secret = _evaluation_key(key)
    if secret is None:
        raise ValueError(
            f"set {_ATTESTATION_KEY_ENV} to at least 32 bytes in the trusted evaluator environment"
        )
    signed = dict(provenance)
    signed["evaluation_authority"] = "trusted_external"
    signed["result_sha256"] = evaluation_result_digest(signed, score)
    signed["evaluation_record_sha256"] = hashlib.sha256(
        evaluation_record_bytes(signed, score)
    ).hexdigest()
    signed["attestation_hmac_sha256"] = hmac.new(
        secret, _attestation_payload(signed, score), hashlib.sha256
    ).hexdigest()
    return signed


def has_trusted_evaluation(
    node: Any,
    *,
    maximize: bool | None = None,
    artifact_root: str | os.PathLike[str] | None = None,
    require_artifacts: bool = False,
) -> bool:
    """Require an HMAC-backed evaluator record and complete immutable bindings."""
    secret = _evaluation_key()
    if secret is None:
        return False
    provenance = getattr(node, "provenance", None)
    if provenance is None:
        provenance = getattr(node, "rsi_provenance", {})
    provenance = provenance or {}
    if provenance.get("evaluation_authority") != "trusted_external":
        return False
    if not all(
        isinstance(provenance.get(key), str)
        and _SHA256_RE.fullmatch(provenance[key]) is not None
        for key in _REQUIRED_EVALUATION_HASHES
    ):
        return False
    if any(
        not isinstance(provenance.get(key), str) or not provenance[key].strip()
        for key in _REQUIRED_EVALUATION_TEXT
    ):
        return False
    if not isinstance(provenance.get("metric_maximize"), bool):
        return False
    if maximize is not None and provenance["metric_maximize"] is not maximize:
        return False
    try:
        value = getattr(node, "score", None)
        if value is None:
            metric = getattr(node, "metric", None)
            value = getattr(metric, "value", None)
        score = float(value)
    except (TypeError, ValueError, AttributeError):
        return False
    if not math.isfinite(score) or provenance[
        "result_sha256"
    ] != evaluation_result_digest(provenance, score):
        return False
    if (
        provenance["evaluation_record_sha256"]
        != hashlib.sha256(evaluation_record_bytes(provenance, score)).hexdigest()
    ):
        return False
    expected = hmac.new(
        secret, _attestation_payload(provenance, score), hashlib.sha256
    ).hexdigest()
    valid = hmac.compare_digest(
        str(provenance.get("attestation_hmac_sha256", "")), expected
    )
    if not valid or not require_artifacts:
        return valid
    if artifact_root is None:
        return False
    root = os.fspath(artifact_root)
    candidate = provenance["candidate_sha256"]
    predictions = provenance["predictions_sha256"]
    evaluation = provenance["evaluation_record_sha256"]
    paths = (
        (os.path.join(root, "sha256", candidate[:2], f"{candidate}.py"), candidate),
        (
            os.path.join(
                root, "predictions", "sha256", predictions[:2], f"{predictions}.jsonl"
            ),
            predictions,
        ),
        (
            os.path.join(
                root, "evaluations", "sha256", evaluation[:2], f"{evaluation}.json"
            ),
            evaluation,
        ),
    )
    try:
        for path, expected_digest in paths:
            if os.path.islink(path) or not os.path.isfile(path):
                return False
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != expected_digest:
                return False
    except OSError:
        return False
    return True


def has_trusted_world_evidence(
    world: Any,
    *,
    artifact_root: str | os.PathLike[str] | None = None,
    require_artifacts: bool = False,
) -> bool:
    """Require at least one score and attest every scored node in a world."""
    nodes = [node for node in world.nodes.values() if getattr(node, "valid", False)]
    return bool(nodes) and all(
        has_trusted_evaluation(
            node,
            maximize=world.maximize,
            artifact_root=artifact_root,
            require_artifacts=require_artifacts,
        )
        for node in nodes
    )


def sign_canary_decision(decision: dict[str, Any]) -> dict[str, Any]:
    """Bind a canary decision and its evidence references to the host HMAC key."""
    secret = _evaluation_key()
    if secret is None:
        raise ValueError(f"set {_ATTESTATION_KEY_ENV} to at least 32 bytes")
    signed = dict(decision)
    signed.pop("attestation_hmac_sha256", None)
    payload = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    signed["attestation_hmac_sha256"] = hmac.new(
        secret, b"aide-rsi-canary-decision/v1\0" + payload, hashlib.sha256
    ).hexdigest()
    return signed


def has_valid_canary_attestation(decision: dict[str, Any]) -> bool:
    """Verify the host signature over a persisted canary decision."""
    secret = _evaluation_key()
    signature = decision.get("attestation_hmac_sha256")
    if (
        secret is None
        or not isinstance(signature, str)
        or not _SHA256_RE.fullmatch(signature)
    ):
        return False
    payload = dict(decision)
    payload.pop("attestation_hmac_sha256", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(
        secret, b"aide-rsi-canary-decision/v1\0" + encoded, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def sign_canary_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    """Sign a canary reservation so consumed sample shards survive crashes."""
    secret = _evaluation_key()
    if secret is None:
        raise ValueError(f"set {_ATTESTATION_KEY_ENV} to at least 32 bytes")
    signed = dict(transaction)
    signed.pop("attestation_hmac_sha256", None)
    payload = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    signed["attestation_hmac_sha256"] = hmac.new(
        secret, b"aide-rsi-canary-transaction/v1\0" + payload, hashlib.sha256
    ).hexdigest()
    return signed


def has_valid_canary_transaction(transaction: dict[str, Any]) -> bool:
    secret = _evaluation_key()
    signature = transaction.get("attestation_hmac_sha256")
    if (
        secret is None
        or not isinstance(signature, str)
        or not _SHA256_RE.fullmatch(signature)
    ):
        return False
    payload = dict(transaction)
    payload.pop("attestation_hmac_sha256", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(
        secret, b"aide-rsi-canary-transaction/v1\0" + encoded, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def sign_rsi_state(state: dict[str, Any]) -> dict[str, Any]:
    """Authenticate durable RSI state when trusted evaluation is enabled."""
    secret = _evaluation_key()
    if secret is None:
        raise ValueError(f"set {_ATTESTATION_KEY_ENV} to at least 32 bytes")
    signed = dict(state)
    signed.pop("state_attestation_hmac_sha256", None)
    payload = json.dumps(
        signed, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    signed["state_attestation_hmac_sha256"] = hmac.new(
        secret, b"aide-rsi-state/v1\0" + payload, hashlib.sha256
    ).hexdigest()
    return signed


def has_valid_rsi_state(state: dict[str, Any]) -> bool:
    """Verify durable RSI state without accepting unsigned trusted-run state."""
    secret = _evaluation_key()
    signature = state.get("state_attestation_hmac_sha256")
    if (
        secret is None
        or not isinstance(signature, str)
        or not _SHA256_RE.fullmatch(signature)
    ):
        return False
    payload = dict(state)
    payload.pop("state_attestation_hmac_sha256", None)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    expected = hmac.new(
        secret, b"aide-rsi-state/v1\0" + encoded, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
