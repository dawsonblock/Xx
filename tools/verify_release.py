"""Fail closed unless a committed source and signed qualification ledger agree."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import generate_release_manifests as manifests
from tools.qualification_evidence import _reject_constant, _reject_duplicate_keys

LEDGER = "RELEASE_QUALIFICATION_LEDGER.json"
LEDGER_SIGNATURE = "RELEASE_QUALIFICATION_LEDGER.sig"
LEDGER_PUBLIC_KEY = "release/qualification-ledger-public.pem"
REQUIRED_GATES = frozenset(
    {
        "pytest",
        "dependency_install",
        "runtime_dependency_install",
        "runtime_container",
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
        "package_integrity",
        "clean_room",
    }
)


def _json_bytes(data: bytes) -> Any:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
) -> None:
    """Verify one externally signed ledger and all of its evidence bytes."""
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
    if not isinstance(ledger, dict) or ledger.get("schema_version") != 1:
        raise ValueError("invalid qualification ledger schema")
    if ledger.get("release_status") != "RELEASE_QUALIFIED":
        raise ValueError("qualification ledger does not authorize a release")
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
        if gate_id in by_id:
            raise ValueError(f"duplicate qualification gate: {gate_id}")
        by_id[gate_id] = gate
        if gate.get("mandatory") is not True or gate.get("status") != "PASS":
            raise ValueError(f"qualification gate is not PASS: {gate_id}")
        if gate.get("exit_code") != 0 or not gate.get("command"):
            raise ValueError(f"qualification gate has no successful command: {gate_id}")
        if not isinstance(gate.get("environment"), dict) or not gate.get("platform"):
            raise ValueError(f"qualification gate lacks environment: {gate_id}")
        if not gate.get("started_at") or not gate.get("ended_at"):
            raise ValueError(f"qualification gate lacks timing: {gate_id}")
        if any(gate.get(key) != value for key, value in expected_identity.items()):
            raise ValueError(f"stale qualification gate identity: {gate_id}")
        evidence_path = _qualification_path(gate.get("evidence_path"))
        evidence_bytes = read_bytes(evidence_path)
        if gate.get("evidence_sha256") != _sha(evidence_bytes):
            raise ValueError(f"qualification evidence bytes differ: {gate_id}")
        envelope_path = _qualification_path(gate.get("envelope_path"))
        envelope_bytes = read_bytes(envelope_path)
        if gate.get("envelope_sha256") != _sha(envelope_bytes):
            raise ValueError(f"qualification envelope bytes differ: {gate_id}")
        envelope = _json_bytes(envelope_bytes)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema_version") != 1
            or envelope.get("gate_id") != gate_id
            or envelope.get("artifact") != evidence_path
            or envelope.get("artifact_sha256") != gate["evidence_sha256"]
            or envelope.get("command") != gate["command"]
            or envelope.get("exit_code") != 0
            or envelope.get("status") != "PASS"
            or not str(envelope.get("python_version", "")).startswith("3.12.")
            or not isinstance(envelope.get("platform"), str)
            or not envelope.get("platform")
            or any(
                envelope.get(key) != value for key, value in expected_identity.items()
            )
        ):
            raise ValueError(f"qualification envelope is stale: {gate_id}")
    if set(by_id) != REQUIRED_GATES:
        raise ValueError("qualification ledger lacks the exact mandatory gate set")


def verify_prebuild(expected_commit: str | None = None, *, root: Path = ROOT) -> None:
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
    for line in changes.splitlines():
        path = line[3:]
        if path != "BUILD_PROVENANCE.json" and not path.startswith(
            ("build/", "dist/", "aideml_rsi.egg-info/")
        ):
            raise ValueError(f"release checkout has an unexpected change: {path}")
    source = _json_bytes((root / "SOURCE_TREE_MANIFEST.json").read_bytes())
    tcb = _json_bytes((root / "TCB_MANIFEST.json").read_bytes())
    identity = _json_bytes((root / "IDENTITY_MANIFEST.json").read_bytes())
    freeze = _json_bytes((root / "RELEASE_FREEZE_MANIFEST.json").read_bytes())
    if freeze.get("source_snapshot_status") != "COMMITTED_SOURCE_SNAPSHOT":
        raise ValueError("release source is not a committed snapshot")
    if freeze.get("release_status") != "RELEASE_QUALIFIED":
        raise ValueError("release status is not RELEASE_QUALIFIED")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prebuild", action="store_true")
    parser.add_argument("--check-benchmark-manifest", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
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
    verify_prebuild(args.expected_commit)
    if not args.prebuild:
        if args.wheel is None or args.sdist is None:
            parser.error("wheel and sdist are required after the prebuild gate")
        from tools.verify_package import verify_archive

        verify_archive(args.wheel, "wheel", expected_commit=args.expected_commit)
        verify_archive(args.sdist, "sdist", expected_commit=args.expected_commit)
    print(
        "RELEASE QUALIFIED" if not args.prebuild else "PREBUILD QUALIFICATION VERIFIED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
