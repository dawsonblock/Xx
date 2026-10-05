"""Fail closed unless a committed source and signed qualification ledger agree."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import generate_release_manifests as manifests  # noqa: E402
from tools.evidence_schema import (  # noqa: E402
    canonical_bytes,
    parse_json,
    sha256,
    validate_evidence,
)
from tools.gate_specs import ARTIFACT_GATES, SOURCE_GATES, gate_spec  # noqa: E402
from tools.release_state import ReleaseState, transition  # noqa: E402

LEDGER = "SOURCE_QUALIFICATION_LEDGER.json"
LEDGER_SIGNATURE = "SOURCE_QUALIFICATION_LEDGER.sig"
LEDGER_PUBLIC_KEY = "release/qualification-ledger-public.pem"
REQUIRED_GATES = SOURCE_GATES


def _json_bytes(data: bytes) -> Any:
    return parse_json(data)


def _sha(data: bytes) -> str:
    return sha256(data)


def _qualification_path(name: Any) -> str:
    if (
        not isinstance(name, str)
        or not name.startswith("qualification/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("unsafe qualification evidence path")
    return name


def verify_signed_ledger(
    *,
    root: Path,
    identity: dict[str, Any],
    source_commit: str,
    read_bytes: Any = None,
    phase: str = "source",
) -> None:
    """Verify a signed source-only ledger against immutable source gate policy."""
    if phase != "source":
        raise ValueError("artifact qualification requires a separate attestation")
    if read_bytes is None:

        def read_bytes(name: str) -> bytes:
            path = root / name
            if path.is_symlink():
                raise ValueError(f"qualification symlink: {name}")
            return path.read_bytes()

    ledger_bytes = read_bytes(LEDGER)
    signature = read_bytes(LEDGER_SIGNATURE)
    public_key = read_bytes(LEDGER_PUBLIC_KEY)
    if not signature or not public_key:
        raise ValueError("qualification ledger signature or public key is missing")
    # OpenSSL verifies the exact ledger bytes. The public key itself is source/TCB-bound.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="aide-ledger-signature-") as temporary:
        directory = Path(temporary)
        (directory / "ledger.json").write_bytes(ledger_bytes)
        (directory / "ledger.sig").write_bytes(signature)
        (directory / "public.pem").write_bytes(public_key)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(directory / "public.pem"),
                "-sigfile",
                str(directory / "ledger.sig"),
                "-in",
                str(directory / "ledger.json"),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("qualification ledger signature is invalid")
    ledger = _json_bytes(ledger_bytes)
    if ledger_bytes != canonical_bytes(ledger):
        raise ValueError("qualification ledger is not canonical JSON")
    if (
        not isinstance(ledger, dict)
        or set(ledger)
        != {
            "schema_version",
            "qualification_status",
            "qualification_phase",
            "source_commit",
            "identity",
            "gates",
        }
        or ledger.get("schema_version") != 2
    ):
        raise ValueError("invalid qualification ledger schema")
    if ledger.get("qualification_phase") != "source":
        raise ValueError("qualification ledger is not source-only")
    if ledger.get("qualification_status") != "SOURCE_QUALIFIED":
        raise ValueError("qualification ledger does not qualify source")
    if ledger.get("source_commit") != source_commit:
        raise ValueError("qualification ledger source commit differs")
    expected_identity = {
        key: value
        for key, value in identity.items()
        if key.endswith("_sha256") or key == "docker_base_image_digest"
    }
    if ledger.get("identity") != expected_identity:
        raise ValueError("qualification ledger identity differs")
    gates = ledger.get("gates")
    if not isinstance(gates, list):
        raise TypeError("qualification ledger gates are missing")
    by_id: dict[str, dict[str, Any]] = {}
    for gate in gates:
        if not isinstance(gate, dict) or not isinstance(gate.get("gate_id"), str):
            raise TypeError("invalid qualification gate")
        gate_id = gate["gate_id"]
        spec = gate_spec(gate_id)
        if spec.phase != "source":
            raise ValueError(f"artifact gate appears in source ledger: {gate_id}")
        if gate_id in by_id:
            raise ValueError(f"duplicate qualification gate: {gate_id}")
        by_id[gate_id] = gate
        required_fields = {
            "gate_id",
            "phase",
            "runner_id",
            "verifier_id",
            "parameters",
            "evidence_path",
            "evidence_sha256",
            "result",
        }
        if set(gate) != required_fields:
            raise ValueError(f"qualification gate has invalid fields: {gate_id}")
        if (
            gate.get("phase") != spec.phase
            or gate.get("runner_id") != spec.runner_id
            or gate.get("verifier_id") != spec.verifier_id
        ):
            raise ValueError(f"qualification gate policy differs: {gate_id}")
        parameters = gate.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError(f"qualification gate parameters are invalid: {gate_id}")
        if set(parameters) - set(spec.parameter_schema) or any(
            not isinstance(value, spec.parameter_schema[name])
            for name, value in parameters.items()
        ):
            raise ValueError(f"qualification gate parameters differ: {gate_id}")
        evidence_path = _qualification_path(gate.get("evidence_path"))
        if evidence_path != spec.evidence_path:
            raise ValueError(f"qualification evidence path differs: {gate_id}")
        evidence_bytes = read_bytes(evidence_path)
        if gate.get("evidence_sha256") != _sha(evidence_bytes):
            raise ValueError(f"qualification evidence bytes differ: {gate_id}")
        envelope = _json_bytes(evidence_bytes)
        if evidence_bytes != canonical_bytes(envelope):
            raise ValueError(f"qualification evidence is not canonical: {gate_id}")
        validate_evidence(
            envelope,
            spec=spec,
            identity=identity,
            parameters=parameters,
        )
        if gate.get("result") != envelope["result"]:
            raise ValueError(f"qualification gate result differs: {gate_id}")
    if set(by_id) != REQUIRED_GATES:
        raise ValueError("qualification ledger lacks the exact mandatory gate set")
    for gate_id, gate in by_id.items():
        if any(
            dependency not in by_id
            or by_id[dependency].get("result", {}).get("status") != "PASS"
            for dependency in gate_spec(gate_id).dependencies
        ):
            raise ValueError(f"qualification gate dependency failed: {gate_id}")


def verify_source(expected_commit: str | None = None, *, root: Path = ROOT) -> None:
    """Verify frozen source qualification without requiring built artifacts."""
    if sys.version_info[:2] != (3, 12):
        raise ValueError("release verification requires Python 3.12")
    subprocess.run(
        [sys.executable, str(root / "tools/generate_release_manifests.py"), "--check"],
        cwd=root,
        check=True,
    )
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    if expected_commit is not None and head != expected_commit:
        raise ValueError("release checkout differs from expected commit")
    changes = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True
    )
    generated_release_files = {
        "BUILD_PROVENANCE.json",
        "SOURCE_QUALIFICATION_LEDGER.json",
        "SOURCE_QUALIFICATION_LEDGER.sig",
        "RELEASE_QUALIFICATION_LEDGER.json",
        "RELEASE_QUALIFICATION_LEDGER.sig",
        "ARTIFACT_ATTESTATION.json",
        "ARTIFACT_ATTESTATION.sig",
        "PUBLICATION_RECEIPT.json",
        "PACKAGE_HASHES.json",
        "ARTIFACT_HASHES.json",
        "PACKAGE_SHA256SUMS",
        "SHA256SUMS",
    }
    for line in changes.splitlines():
        path = line[3:]
        if path not in generated_release_files and not path.startswith(
            ("build/", "dist/", "aideml_rsi.egg-info/", "qualification/")
        ):
            raise ValueError(f"release checkout has an unexpected change: {path}")
    source = _json_bytes((root / "SOURCE_TREE_MANIFEST.json").read_bytes())
    tcb = _json_bytes((root / "TCB_MANIFEST.json").read_bytes())
    identity = _json_bytes((root / "IDENTITY_MANIFEST.json").read_bytes())
    freeze = _json_bytes((root / "RELEASE_FREEZE_MANIFEST.json").read_bytes())
    if freeze.get("source_snapshot_status") != "COMMITTED_SOURCE_SNAPSHOT":
        raise ValueError("release source is not a committed snapshot")
    source_hashes = source.get("files")
    if not isinstance(source_hashes, dict) or any(
        not (root / path).is_file() or _sha((root / path).read_bytes()) != digest
        for path, digest in source_hashes.items()
    ):
        raise ValueError("release source files differ from manifest")
    if source.get("source_snapshot_sha256") != manifests._canonical_sha256(
        source_hashes
    ):
        raise ValueError("release source manifest digest is invalid")
    if not {
        LEDGER_PUBLIC_KEY,
        "tools/verify_release.py",
        "tools/gate_specs.py",
        "tools/evidence_schema.py",
        "tools/generate_release_manifests.py",
    } <= set(source_hashes):
        raise ValueError("release verification policy is not source-bound")
    tcb_hashes = tcb.get("files")
    if not isinstance(tcb_hashes, dict) or any(
        source_hashes.get(path) != digest for path, digest in tcb_hashes.items()
    ):
        raise ValueError("release TCB differs from source manifest")
    if identity.get("aggregate_tcb_sha256") != manifests._canonical_sha256(tcb_hashes):
        raise ValueError("aggregate release TCB digest is invalid")
    if identity.get("source_snapshot_sha256") != source["source_snapshot_sha256"]:
        raise ValueError("release identity differs from source")
    import re

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    docker_bases = re.findall(
        r"^FROM\s+\S+@sha256:([0-9a-f]{64})(?:\s|$)",
        dockerfile,
        flags=re.MULTILINE,
    )
    if not docker_bases or len(set(docker_bases)) != 1:
        raise ValueError("Docker base image is not pinned to one digest")
    if identity.get("docker_base_image_digest") != docker_bases[0]:
        raise ValueError("Docker base image digest differs from release identity")
    for name, field in (
        ("requirements-rsi-ci.lock", "dependency_lock_sha256"),
        ("requirements-runtime.lock", "runtime_dependency_lock_sha256"),
    ):
        if not (root / name).is_file() or identity.get(field) != _sha(
            (root / name).read_bytes()
        ):
            raise ValueError(f"release dependency lock differs: {name}")
    from aide.rsi.benchmark import load_manifest, manifest_sha256, validate_manifest

    benchmark = load_manifest(root / "BENCHMARK_FAMILY_MANIFEST.json")
    validate_manifest(benchmark, require_approved=True)
    if manifest_sha256(benchmark) != identity.get("benchmark_family_manifest_sha256"):
        raise ValueError("release benchmark taxonomy differs")
    verify_signed_ledger(
        root=root,
        identity=identity,
        source_commit=source["qualified_code_commit"],
    )
    state = transition(ReleaseState.DEVELOPMENT, ReleaseState.SOURCE_FROZEN)
    state = transition(state, ReleaseState.SOURCE_QUALIFICATION_IN_PROGRESS)
    transition(state, ReleaseState.SOURCE_QUALIFIED)


def verify_prebuild(expected_commit: str | None = None, *, root: Path = ROOT) -> None:
    """Compatibility alias for callers that used the prebuild source gate."""
    verify_source(expected_commit, root=root)


def _verify_signed_bytes(
    *,
    payload: bytes,
    signature: bytes,
    public_key: bytes,
) -> None:
    if not signature or not public_key:
        raise ValueError("release attestation signature or public key is missing")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="aide-release-signature-") as temporary:
        directory = Path(temporary)
        (directory / "payload.json").write_bytes(payload)
        (directory / "payload.sig").write_bytes(signature)
        (directory / "public.pem").write_bytes(public_key)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(directory / "public.pem"),
                "-sigfile",
                str(directory / "payload.sig"),
                "-in",
                str(directory / "payload.json"),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise ValueError("release attestation signature is invalid")


def _source_zip_hashes(path: Path) -> dict[str, str]:
    import zipfile

    hashes: dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            name = member.filename
            if (
                member.is_dir()
                or name in hashes
                or name.startswith("/")
                or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
            ):
                raise ValueError(f"unsafe or duplicate source ZIP member: {name}")
            hashes[name] = _sha(archive.read(member))
    return hashes


def verify_artifacts(
    *,
    wheel: Path,
    sdist: Path,
    source_zip: Path,
    container_digest: str,
    attestation: Path,
    attestation_signature: Path,
    expected_commit: str | None = None,
    root: Path = ROOT,
) -> None:
    """Verify exact artifact bytes against separately signed artifact evidence."""
    verify_source(expected_commit, root=root)
    from tools.verify_package import verify_archive

    verify_archive(wheel, "wheel", root=root, expected_commit=expected_commit)
    verify_archive(sdist, "sdist", root=root, expected_commit=expected_commit)
    source = _json_bytes((root / "SOURCE_TREE_MANIFEST.json").read_bytes())
    source_hashes = source.get("files")
    if not isinstance(source_hashes, dict):
        raise ValueError("source ZIP cannot be verified without source inventory")
    expected_source_zip = {
        **source_hashes,
        **{
            name: _sha((root / name).read_bytes())
            for name in manifests.OUTPUTS
            if (root / name).is_file()
        },
    }
    if _source_zip_hashes(source_zip) != expected_source_zip:
        raise ValueError("source ZIP inventory or bytes differ")
    provenance_path = root / "BUILD_PROVENANCE.json"
    if not provenance_path.is_file():
        raise ValueError("build provenance is missing")
    provenance_bytes = provenance_path.read_bytes()
    provenance = _json_bytes(provenance_bytes)
    if provenance_bytes != canonical_bytes(provenance):
        raise ValueError("build provenance is not canonical JSON")
    identity = _json_bytes((root / "IDENTITY_MANIFEST.json").read_bytes())
    source = _json_bytes((root / "SOURCE_TREE_MANIFEST.json").read_bytes())
    ledger_bytes = (root / LEDGER).read_bytes()
    if (
        not isinstance(provenance, dict)
        or provenance.get("source_snapshot_sha256")
        != identity.get("source_snapshot_sha256")
        or provenance.get("source_qualification_ledger_sha256") != _sha(ledger_bytes)
        or provenance.get("source_commit") != source.get("qualified_code_commit")
        or (
            expected_commit is not None
            and provenance.get("build_commit") != expected_commit
        )
        or provenance.get("build_runner_id") != "python-build-sdist-wheel-v1"
        or not str(provenance.get("python_version", "")).startswith("3.12.")
        or any(
            provenance.get(key) != value
            for key, value in identity.items()
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        )
    ):
        raise ValueError("build provenance is stale")
    if not isinstance(container_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", container_digest
    ):
        raise ValueError("qualified container digest is required")
    attestation_bytes = attestation.read_bytes()
    attestation_data = _json_bytes(attestation_bytes)
    if attestation_bytes != canonical_bytes(attestation_data):
        raise ValueError("artifact attestation is not canonical JSON")
    _verify_signed_bytes(
        payload=attestation_bytes,
        signature=attestation_signature.read_bytes(),
        public_key=(root / LEDGER_PUBLIC_KEY).read_bytes(),
    )
    required_attestation_fields = {
        "schema_version",
        "qualification_status",
        "qualification_phase",
        "identity",
        "source_qualification_ledger_sha256",
        "build_provenance_sha256",
        "artifacts",
        "gates",
    }
    if (
        not isinstance(attestation_data, dict)
        or set(attestation_data) != required_attestation_fields
        or attestation_data.get("schema_version") != 1
        or attestation_data.get("qualification_status") != "RELEASE_QUALIFIED"
        or attestation_data.get("qualification_phase") != "artifact"
        or attestation_data.get("identity")
        != {
            key: value
            for key, value in identity.items()
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        }
        or attestation_data.get("source_qualification_ledger_sha256")
        != _sha(ledger_bytes)
        or attestation_data.get("build_provenance_sha256") != _sha(provenance_bytes)
    ):
        raise ValueError("artifact attestation identity differs")
    artifacts = attestation_data.get("artifacts")
    expected_artifacts = {
        "wheel_sha256": _sha(wheel.read_bytes()),
        "sdist_sha256": _sha(sdist.read_bytes()),
        "source_zip_sha256": _sha(source_zip.read_bytes()),
        "container_digest": container_digest,
    }
    if artifacts != expected_artifacts:
        raise ValueError("artifact attestation hashes differ")
    gates = attestation_data.get("gates")
    if not isinstance(gates, list):
        raise ValueError("artifact qualification gates are missing")
    by_id = {}
    for gate in gates:
        if not isinstance(gate, dict) or not isinstance(gate.get("gate_id"), str):
            raise ValueError("invalid artifact qualification gate")
        spec = gate_spec(gate["gate_id"])
        if spec.phase != "artifact" or gate["gate_id"] in by_id:
            raise ValueError("unknown or duplicate artifact qualification gate")
        if set(gate) != {"gate_id", "evidence_path", "evidence_sha256", "result"}:
            raise ValueError("invalid artifact qualification gate fields")
        if gate["evidence_path"] != spec.evidence_path:
            raise ValueError("artifact qualification evidence path differs")
        evidence_file = root / spec.evidence_path
        if evidence_file.is_symlink():
            raise ValueError("artifact qualification evidence cannot be a symlink")
        evidence_bytes = evidence_file.read_bytes()
        evidence = _json_bytes(evidence_bytes)
        if evidence_bytes != canonical_bytes(evidence):
            raise ValueError("artifact qualification evidence is not canonical")
        if gate["evidence_sha256"] != _sha(evidence_bytes):
            raise ValueError("artifact qualification evidence hash differs")
        validate_evidence(evidence, spec=spec, identity=identity)
        if gate["result"] != evidence["result"]:
            raise ValueError("artifact qualification result differs")
        expected_parameters = {
            "wheel_integrity": {"wheel_sha256": expected_artifacts["wheel_sha256"]},
            "sdist_integrity": {"sdist_sha256": expected_artifacts["sdist_sha256"]},
            "source_zip_integrity": {
                "source_zip_sha256": expected_artifacts["source_zip_sha256"]
            },
            "container_integrity": {
                "container_digest": expected_artifacts["container_digest"]
            },
            "clean_room_rebuild": expected_artifacts,
        }[spec.gate_id]
        if evidence["parameters"] != expected_parameters:
            raise ValueError("artifact gate is not bound to the verified artifacts")
        by_id[spec.gate_id] = gate
    if set(by_id) != ARTIFACT_GATES:
        raise ValueError("artifact attestation lacks the exact mandatory gate set")
    for gate_id in by_id:
        missing = set(gate_spec(gate_id).dependencies) & ARTIFACT_GATES - set(by_id)
        if missing:
            raise ValueError(f"artifact qualification dependency missing: {gate_id}")
    state = transition(ReleaseState.SOURCE_QUALIFIED, ReleaseState.BUILD_IN_PROGRESS)
    state = transition(state, ReleaseState.ARTIFACTS_BUILT)
    state = transition(state, ReleaseState.ARTIFACTS_QUALIFIED)
    transition(state, ReleaseState.RELEASE_QUALIFIED)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify-source", action="store_true")
    modes.add_argument("--verify-artifacts", action="store_true")
    modes.add_argument("--prebuild", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--check-benchmark-manifest", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--source-zip", type=Path)
    parser.add_argument("--container-digest")
    parser.add_argument("--artifact-attestation", type=Path)
    parser.add_argument("--artifact-attestation-signature", type=Path)
    args = parser.parse_args(argv)
    if args.check_benchmark_manifest:
        from aide.rsi.benchmark import load_manifest, manifest_sha256, validate_manifest

        identity = _json_bytes((ROOT / "IDENTITY_MANIFEST.json").read_bytes())
        benchmark = load_manifest(ROOT / "BENCHMARK_FAMILY_MANIFEST.json")
        validate_manifest(benchmark, require_approved=True)
        if manifest_sha256(benchmark) != identity.get(
            "benchmark_family_manifest_sha256"
        ):
            raise ValueError("benchmark manifest digest mismatch")
        print("benchmark manifest verified")
        return 0
    if args.verify_artifacts:
        required = (
            args.wheel,
            args.sdist,
            args.source_zip,
            args.container_digest,
            args.artifact_attestation,
            args.artifact_attestation_signature,
        )
        if any(value is None for value in required):
            parser.error(
                "--verify-artifacts requires all artifact and attestation inputs"
            )
        verify_artifacts(
            wheel=args.wheel,
            sdist=args.sdist,
            source_zip=args.source_zip,
            container_digest=args.container_digest,
            attestation=args.artifact_attestation,
            attestation_signature=args.artifact_attestation_signature,
            expected_commit=args.expected_commit,
        )
        print(ReleaseState.RELEASE_QUALIFIED)
        return 0
    if any(
        (
            args.wheel,
            args.sdist,
            args.source_zip,
            args.container_digest,
            args.artifact_attestation,
            args.artifact_attestation_signature,
        )
    ):
        parser.error("artifact inputs are accepted only with --verify-artifacts")
    verify_source(args.expected_commit)
    print(ReleaseState.SOURCE_QUALIFIED)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
