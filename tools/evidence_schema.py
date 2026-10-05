"""Canonical validation for qualification evidence envelopes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tools.gate_specs import GateSpec

_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_FIELDS = {
    "schema_version",
    "gate_id",
    "runner_id",
    "verifier_id",
    "phase",
    "identity",
    "environment",
    "parameters",
    "artifacts",
    "result",
}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def parse_json(data: bytes) -> Any:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def validate_evidence(
    evidence: Any,
    *,
    spec: GateSpec,
    identity: dict[str, Any],
    parameters: dict[str, Any] | None = None,
) -> None:
    if not isinstance(evidence, dict) or set(evidence) != _FIELDS:
        raise ValueError("qualification evidence has invalid fields")
    if evidence.get("schema_version") != 2:
        raise ValueError("qualification evidence schema mismatch")
    if (
        evidence.get("gate_id") != spec.gate_id
        or evidence.get("runner_id") != spec.runner_id
        or evidence.get("verifier_id") != spec.verifier_id
        or evidence.get("phase") != spec.phase
    ):
        raise ValueError("qualification evidence gate policy differs")
    expected_identity = {
        key: identity.get(key) for key in spec.source_identity_requirements
    }
    if (
        any(
            not isinstance(value, str) or not _DIGEST.fullmatch(value)
            for value in expected_identity.values()
        )
        or evidence.get("identity") != expected_identity
    ):
        raise ValueError("qualification evidence identity differs")
    environment = evidence.get("environment")
    if (
        not isinstance(environment, dict)
        or set(environment) != {"python", "platform", "architecture"}
        or not isinstance(environment.get("python"), str)
        or not environment["python"].startswith("3.12.")
        or not all(
            isinstance(environment.get(key), str) and environment[key]
            for key in ("platform", "architecture")
        )
    ):
        raise ValueError("qualification evidence environment is invalid")
    actual_parameters = evidence.get("parameters")
    if not isinstance(actual_parameters, dict):
        raise ValueError("qualification evidence parameters are invalid")
    if parameters is not None and actual_parameters != parameters:
        raise ValueError("qualification evidence parameters differ")
    if set(actual_parameters) - set(spec.parameter_schema):
        raise ValueError("qualification evidence has unknown parameters")
    if spec.phase == "artifact" and set(actual_parameters) != set(
        spec.parameter_schema
    ):
        raise ValueError("artifact gate evidence is missing parameters")
    if any(
        not isinstance(value, spec.parameter_schema[name])
        for name, value in actual_parameters.items()
    ):
        raise ValueError("qualification evidence parameter type differs")
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("qualification evidence artifacts are invalid")
    if spec.artifact_policy == "sha256-list" and not artifacts:
        raise ValueError("artifact gate evidence must bind artifacts")
    artifact_ids = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"artifact_id", "sha256"}
            or not isinstance(artifact.get("artifact_id"), str)
            or not artifact["artifact_id"]
            or not isinstance(artifact.get("sha256"), str)
            or not _DIGEST.fullmatch(artifact["sha256"])
            or artifact["artifact_id"] in artifact_ids
        ):
            raise ValueError("qualification evidence artifact is invalid")
        artifact_ids.add(artifact["artifact_id"])
    if spec.phase == "artifact":
        expected_artifacts = {
            (name.removesuffix("_sha256"), value)
            for name, value in actual_parameters.items()
        }
        if "container_digest" in actual_parameters:
            expected_artifacts.add(("container", actual_parameters["container_digest"]))
        if {
            (artifact["artifact_id"], artifact["sha256"]) for artifact in artifacts
        } != expected_artifacts:
            raise ValueError("artifact gate evidence hashes differ from parameters")
    result = evidence.get("result")
    if (
        not isinstance(result, dict)
        or set(result) != {"status", "exit_code", "details"}
        or result.get("status") != "PASS"
        or type(result.get("exit_code")) is not int
        or result["exit_code"] != 0
        or not isinstance(result.get("details"), dict)
    ):
        raise ValueError("qualification evidence result is not PASS")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
