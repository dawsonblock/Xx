"""Source-controlled qualification gate policy."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class GateSpec:
    gate_id: str
    phase: str
    required: bool
    runner_id: str
    verifier_id: str
    evidence_kind: str
    artifact_policy: str
    parameter_schema: Mapping[str, type]
    dependencies: tuple[str, ...]
    evidence_path: str
    source_identity_requirements: tuple[str, ...]


_SOURCE_IDENTITY = (
    "source_snapshot_sha256",
    "runtime_tcb_sha256",
    "release_tcb_sha256",
    "statistical_tcb_sha256",
    "sandbox_tcb_sha256",
    "aggregate_tcb_sha256",
    "dependency_lock_sha256",
    "runtime_dependency_lock_sha256",
    "statistical_protocol_sha256",
    "evaluator_sha256",
    "benchmark_family_manifest_sha256",
    "docker_build_context_sha256",
    "docker_base_image_digest",
)

_SOURCE_GATES = (
    "source_manifest",
    "tcb_manifest",
    "dependency_install",
    "runtime_dependency_install",
    "pytest",
    "statistical_calibration",
    "linux_sandbox",
    "linux_hosted",
    "macos_hosted",
    "windows_hosted",
    "benchmark_families",
    "real_null_controls",
    "degraded_controls",
    "planted_improvements",
    "crash_fault_injection",
    "external_anchor",
    "destructive_rollback",
    "key_authority",
    "evidence_tampering",
    "atomic_promotion",
    "runtime_container",
)

_ARTIFACT_GATES = (
    "wheel_integrity",
    "sdist_integrity",
    "source_zip_integrity",
    "container_integrity",
    "clean_room_rebuild",
)

_DEPENDENCIES = {
    "tcb_manifest": ("source_manifest",),
    "dependency_install": ("source_manifest", "tcb_manifest"),
    "runtime_dependency_install": ("source_manifest", "tcb_manifest"),
    "pytest": ("dependency_install",),
    "statistical_calibration": ("dependency_install",),
    "linux_sandbox": ("runtime_dependency_install",),
    "linux_hosted": ("linux_sandbox",),
    "macos_hosted": ("source_manifest",),
    "windows_hosted": ("source_manifest",),
    "benchmark_families": ("source_manifest",),
    "real_null_controls": ("statistical_calibration", "benchmark_families"),
    "degraded_controls": ("statistical_calibration", "benchmark_families"),
    "planted_improvements": ("statistical_calibration", "benchmark_families"),
    "crash_fault_injection": ("statistical_calibration",),
    "external_anchor": ("source_manifest",),
    "destructive_rollback": ("external_anchor",),
    "key_authority": ("source_manifest",),
    "evidence_tampering": ("source_manifest",),
    "atomic_promotion": ("external_anchor",),
    "runtime_container": ("runtime_dependency_install", "linux_sandbox"),
    "wheel_integrity": ("source_manifest",),
    "sdist_integrity": ("source_manifest",),
    "source_zip_integrity": ("source_manifest",),
    "container_integrity": ("runtime_container",),
    "clean_room_rebuild": ("wheel_integrity", "sdist_integrity", "source_zip_integrity"),
}

_ARTIFACT_PARAMETERS = {
    "wheel_integrity": MappingProxyType({"wheel_sha256": str}),
    "sdist_integrity": MappingProxyType({"sdist_sha256": str}),
    "source_zip_integrity": MappingProxyType({"source_zip_sha256": str}),
    "container_integrity": MappingProxyType({"container_digest": str}),
    "clean_room_rebuild": MappingProxyType(
        {
            "wheel_sha256": str,
            "sdist_sha256": str,
            "source_zip_sha256": str,
            "container_digest": str,
        }
    ),
}


def _specs() -> dict[str, GateSpec]:
    specs = {}
    for gate_id in (*_SOURCE_GATES, *_ARTIFACT_GATES):
        phase = "source" if gate_id in _SOURCE_GATES else "artifact"
        artifact_gate = phase == "artifact"
        specs[gate_id] = GateSpec(
            gate_id=gate_id,
            phase=phase,
            required=True,
            runner_id=f"{gate_id.replace('_', '-')}-v1",
            verifier_id=f"{gate_id.replace('_', '-')}-evidence-v1",
            evidence_kind=gate_id,
            artifact_policy="sha256-list" if artifact_gate else "none",
            parameter_schema=(
                _ARTIFACT_PARAMETERS.get(gate_id, MappingProxyType({}))
            ),
            dependencies=_DEPENDENCIES.get(gate_id, ()),
            evidence_path=f"qualification/evidence/{gate_id}.json",
            source_identity_requirements=_SOURCE_IDENTITY,
        )
    return specs


GATE_SPECS: Mapping[str, GateSpec] = MappingProxyType(_specs())
SOURCE_GATES = frozenset(gate_id for gate_id, spec in GATE_SPECS.items() if spec.phase == "source")
ARTIFACT_GATES = frozenset(gate_id for gate_id, spec in GATE_SPECS.items() if spec.phase == "artifact")


def gate_spec(gate_id: str) -> GateSpec:
    try:
        return GATE_SPECS[gate_id]
    except KeyError as error:
        raise ValueError(f"unknown qualification gate: {gate_id}") from error
