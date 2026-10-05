"""Verify package bytes against the trusted checkout and release identities."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
EMBEDDED = {
    "BENCHMARK_FAMILY_MANIFEST.json",
    "BUILD_MANIFEST.json",
    "IDENTITY_MANIFEST.json",
    "RELEASE_FREEZE_MANIFEST.json",
    "SOURCE_TREE_MANIFEST.json",
    "TCB_MANIFEST.json",
    "VERSION",
    "requirements-rsi-ci.in",
    "requirements-rsi-ci.lock",
    "requirements-runtime.lock",
    "requirements.txt",
    "requirements-replay.txt",
}
PACKAGE_ROOT_FILES = {
    "rsi_anchor_service.py",
    "VERSION",
    "requirements-rsi-ci.in",
    "requirements-rsi-ci.lock",
    "requirements-runtime.lock",
    "requirements.txt",
    "requirements-replay.txt",
}
EXECUTABLE_SUFFIXES = {".py", ".pyc", ".pth", ".sh", ".so", ".pyd", ".dll", ".exe"}
GENERATED_METADATA = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "top_level.txt",
    "requires.txt",
    "entry_points.txt",
}
DIST_INFO_METADATA = {
    "METADATA",
    "WHEEL",
    "RECORD",
    "entry_points.txt",
    "top_level.txt",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha(value: object) -> str:
    return _sha(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    )


def _safe_name(name: str) -> str:
    if "\\" in name or "\x00" in name:
        raise ValueError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not name
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError(f"unsafe archive member: {name!r}")
    return name


def _extract(path: Path, destination: Path, kind: str) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    if kind == "wheel":
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                name = _safe_name(item.filename)
                mode = (item.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ValueError(f"symlink in wheel: {name}")
                if name in members:
                    raise ValueError(f"duplicate wheel member: {name}")
                members[name] = archive.read(item)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for item in archive.getmembers():
                if item.isdir():
                    continue
                name = _safe_name(item.name)
                if not item.isfile() or name in members:
                    raise ValueError(f"unsafe or duplicate sdist member: {name}")
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError(f"unreadable sdist member: {name}")
                members[name] = stream.read()
    for name, data in members.items():
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return members


def _relative_members(members: dict[str, bytes], kind: str) -> dict[str, bytes]:
    if kind == "wheel":
        return members
    roots = {name.split("/", 1)[0] for name in members}
    if len(roots) != 1:
        raise ValueError("sdist must have exactly one root directory")
    root = roots.pop()
    if not re.fullmatch(r"aideml[-_]rsi-\d+\.\d+\.\d+", root):
        raise ValueError("unexpected sdist root")
    return {name[len(root) + 1 :]: data for name, data in members.items()}


def _wheel_source_path(name: str) -> str | None:
    if ".dist-info/" in name:
        return None
    match = re.fullmatch(r"[^/]+\.data/data/share/aideml-rsi/(.+)", name)
    if match:
        return match.group(1)
    if ".data/" in name:
        return None
    return name


def _embedded_bytes(members: dict[str, bytes], name: str, kind: str) -> bytes:
    matches = [
        data
        for member, data in members.items()
        if (member == name if kind == "sdist" else _wheel_source_path(member) == name)
    ]
    if len(matches) != 1:
        raise ValueError(f"missing or duplicate embedded {name}")
    return matches[0]


def _verify_wheel_record(members: dict[str, bytes]) -> None:
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise ValueError("wheel requires exactly one RECORD")
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(members[record_names[0]].decode())):
        if len(row) != 3 or row[0] in seen or row[0] not in members:
            raise ValueError("invalid wheel RECORD")
        seen.add(row[0])
        if row[0] == record_names[0]:
            if row[1] or row[2]:
                raise ValueError("RECORD self hash must be empty")
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(members[row[0]]).digest())
            .rstrip(b"=")
            .decode()
        )
        if row[1] != f"sha256={digest}" or row[2] != str(len(members[row[0]])):
            raise ValueError(f"wheel RECORD mismatch: {row[0]}")
    if seen != set(members):
        raise ValueError("wheel RECORD omits archive members")


def _check_qualification(
    root: Path,
    identity: dict,
    freeze: dict,
    source: dict,
    members: dict[str, bytes],
    kind: str,
    expected_commit: str | None,
) -> None:
    from aide.rsi.benchmark import validate_manifest
    from tools.verify_release import (
        LEDGER,
        LEDGER_PUBLIC_KEY,
        LEDGER_SIGNATURE,
        verify_signed_ledger,
    )

    validate_manifest(
        json.loads(_embedded_bytes(members, "BENCHMARK_FAMILY_MANIFEST.json", kind)),
        require_approved=True,
    )
    if freeze.get("source_qualification_status") != "SOURCE_QUALIFIED":
        raise ValueError("source status is not SOURCE_QUALIFIED")
    runtime_lock_digest = identity.get("runtime_dependency_lock_sha256")
    if not isinstance(runtime_lock_digest, str) or len(runtime_lock_digest) != 64:
        raise ValueError("qualified release requires a hashed runtime dependency lock")
    if (
        _sha(_embedded_bytes(members, "requirements-runtime.lock", kind))
        != runtime_lock_digest
    ):
        raise ValueError("runtime dependency lock digest mismatch")
    if not source.get("qualified_code_commit") or source.get(
        "qualified_code_commit"
    ) != freeze.get("qualified_code_commit"):
        raise ValueError("source and release commit metadata disagree")
    ledger_bytes = _embedded_bytes(members, LEDGER, kind)
    ledger = json.loads(ledger_bytes)
    if not isinstance(ledger, dict) or not isinstance(ledger.get("gates"), list):
        raise TypeError("qualification ledger is invalid")
    evidence_paths = {
        gate.get("evidence_path")
        for gate in ledger["gates"]
        if isinstance(gate, dict) and isinstance(gate.get("evidence_path"), str)
    }
    for name in {
        LEDGER,
        LEDGER_SIGNATURE,
        LEDGER_PUBLIC_KEY,
        "BUILD_PROVENANCE.json",
    } | evidence_paths:
        data = _embedded_bytes(members, name, kind)
        if not (root / name).is_file() or data != (root / name).read_bytes():
            raise ValueError(f"missing or mismatched {name}")
    if LEDGER_PUBLIC_KEY not in source["files"]:
        raise ValueError("qualification public key is not source-bound")
    verify_signed_ledger(
        root=root,
        identity=identity,
        source_commit=source["qualified_code_commit"],
        read_bytes=lambda name: _embedded_bytes(members, name, kind),
    )
    provenance = json.loads(_embedded_bytes(members, "BUILD_PROVENANCE.json", kind))
    if provenance.get("schema_version") != 1 or not str(
        provenance.get("python_version", "")
    ).startswith("3.12."):
        raise ValueError("build provenance is invalid")
    if provenance.get("source_qualification_ledger_sha256") != _sha(ledger_bytes):
        raise ValueError("build provenance does not bind source ledger")
    for field, value in identity.items():
        if (
            field.endswith("_sha256") or field == "docker_base_image_digest"
        ) and provenance.get(field) != value:
            raise ValueError(f"stale build provenance: {field}")
    if expected_commit and provenance.get("source_commit") != expected_commit:
        raise ValueError("build provenance has a different source commit")


def verify_archive(
    path: Path,
    kind: str,
    *,
    root: Path = ROOT,
    integrity_only: bool = False,
    expected_commit: str | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="aide-package-verify-") as temporary:
        members = _relative_members(_extract(path, Path(temporary), kind), kind)
        source = json.loads(_embedded_bytes(members, "SOURCE_TREE_MANIFEST.json", kind))
        tcb = json.loads(_embedded_bytes(members, "TCB_MANIFEST.json", kind))
        identity = json.loads(_embedded_bytes(members, "IDENTITY_MANIFEST.json", kind))
        freeze = json.loads(
            _embedded_bytes(members, "RELEASE_FREEZE_MANIFEST.json", kind)
        )
        build = json.loads(_embedded_bytes(members, "BUILD_MANIFEST.json", kind))
        release_evidence_paths: set[str] = set()
        ledger_matches = [
            data
            for name, data in members.items()
            if (name if kind == "sdist" else _wheel_source_path(name))
            == "SOURCE_QUALIFICATION_LEDGER.json"
        ]
        if ledger_matches:
            if len(ledger_matches) != 1:
                raise ValueError("duplicate qualification ledger")
            ledger_candidate = json.loads(ledger_matches[0])
            if not isinstance(ledger_candidate, dict) or not isinstance(
                ledger_candidate.get("gates"), list
            ):
                raise ValueError("invalid qualification ledger")
            for gate in ledger_candidate["gates"]:
                if not isinstance(gate, dict):
                    raise TypeError("invalid qualification gate")
                path = gate.get("evidence_path")
                if (
                    not isinstance(path, str)
                    or not path.startswith("qualification/")
                    or PurePosixPath(path).suffix != ".json"
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                ):
                    raise ValueError("invalid qualification evidence path")
                release_evidence_paths.add(path)
        for name in EMBEDDED:
            if (
                not (root / name).is_file()
                or _embedded_bytes(members, name, kind) != (root / name).read_bytes()
            ):
                raise ValueError(
                    f"embedded identity differs from trusted checkout: {name}"
                )
        source_hashes = source.get("files")
        if not isinstance(source_hashes, dict) or source.get(
            "source_snapshot_sha256"
        ) != _canonical_sha(source_hashes):
            raise ValueError("invalid source manifest digest")
        if tcb.get("aggregate_tcb_sha256") != _canonical_sha(tcb.get("files")):
            raise ValueError("invalid TCB aggregate digest")
        if not set(tcb["files"]) <= set(source_hashes):
            raise ValueError("TCB has files outside source snapshot")
        if any(source_hashes[name] != digest for name, digest in tcb["files"].items()):
            raise ValueError("TCB file hash differs from source manifest")
        if (
            identity.get("source_snapshot_sha256") != source["source_snapshot_sha256"]
            or identity.get("aggregate_tcb_sha256") != tcb["aggregate_tcb_sha256"]
        ):
            raise ValueError("identity manifest disagrees with source or TCB")
        if identity.get("dependency_lock_sha256") != _sha(
            _embedded_bytes(members, "requirements-rsi-ci.lock", kind)
        ):
            raise ValueError("dependency lock digest mismatch")
        if identity.get("runtime_dependency_lock_sha256") != _sha(
            _embedded_bytes(members, "requirements-runtime.lock", kind)
        ):
            raise ValueError("runtime dependency lock digest mismatch")
        from aide.rsi.benchmark import manifest_sha256

        benchmark = json.loads(
            _embedded_bytes(members, "BENCHMARK_FAMILY_MANIFEST.json", kind)
        )
        if identity.get("benchmark_family_manifest_sha256") != manifest_sha256(
            benchmark
        ):
            raise ValueError("benchmark family manifest digest mismatch")
        if freeze.get("package_version") != _embedded_bytes(
            members, "VERSION", kind
        ).decode().strip() or build.get("distribution_version") != freeze.get(
            "package_version"
        ):
            raise ValueError("package VERSION mismatch")
        if (
            freeze.get("statistical_protocol_sha256")
            != identity.get("statistical_protocol_sha256")
            or freeze.get("evaluator_sha256") != identity.get("evaluator_sha256")
            or freeze.get("benchmark_family_manifest_sha256")
            != identity.get("benchmark_family_manifest_sha256")
        ):
            raise ValueError("protocol, evaluator, or benchmark identity mismatch")
        observed: set[str] = set()
        for name, data in members.items():
            relative = name if kind == "sdist" else _wheel_source_path(name)
            if relative in source_hashes:
                if _sha(data) != source_hashes[relative]:
                    raise ValueError(f"source content mismatch: {relative}")
                observed.add(relative)
            elif (
                relative in EMBEDDED
                or relative
                in {
                    "SOURCE_QUALIFICATION_LEDGER.json",
                    "SOURCE_QUALIFICATION_LEDGER.sig",
                    "BUILD_PROVENANCE.json",
                }
                | release_evidence_paths
            ):
                continue
            elif kind == "wheel" and ".dist-info/" in name:
                tail = name.split(".dist-info/", 1)[1]
                if tail not in DIST_INFO_METADATA and not tail.startswith("licenses/"):
                    raise ValueError(f"unexpected wheel metadata: {name}")
            elif kind == "sdist" and (
                relative in GENERATED_METADATA
                or relative.startswith("aideml_rsi.egg-info/")
            ):
                if (
                    relative.startswith("aideml_rsi.egg-info/")
                    and relative.split("/")[-1] not in GENERATED_METADATA
                ):
                    raise ValueError(f"unexpected generated metadata: {relative}")
            elif kind == "sdist" and relative == "setup.cfg":
                if data != b"[egg_info]\ntag_build = \ntag_date = 0\n\n":
                    raise ValueError("unexpected generated setup.cfg")
            elif PurePosixPath(relative or name).suffix.lower() in EXECUTABLE_SUFFIXES:
                raise ValueError(f"unexpected executable file: {name}")
            else:
                raise ValueError(f"unexpected archive member: {name}")
        required = (
            PACKAGE_ROOT_FILES
            | {path for path in source_hashes if path.startswith(("aide/", "vendor/"))}
            | {
                path
                for path in source_hashes
                if path.startswith("tools/") and path.endswith(".py")
            }
        )
        if kind == "sdist":
            required |= set(source_hashes)
        if not required <= observed | EMBEDDED:
            raise ValueError(
                "missing source files: "
                + ", ".join(sorted(required - observed - EMBEDDED))
            )
        if kind == "wheel":
            _verify_wheel_record(members)
            metadata = next(
                data
                for name, data in members.items()
                if name.endswith(".dist-info/METADATA")
            )
            if f"Version: {freeze['package_version']}\n".encode() not in metadata:
                raise ValueError("wheel metadata VERSION mismatch")
        if not integrity_only:
            _check_qualification(
                root, identity, freeze, source, members, kind, expected_commit
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument(
        "--integrity-only",
        action="store_true",
        help="verify bytes without claiming release qualification",
    )
    parser.add_argument(
        "--expected-commit",
        help="require strict release provenance for this Git commit",
    )
    args = parser.parse_args(argv)
    subprocess.run(
        [sys.executable, str(ROOT / "tools/generate_release_manifests.py"), "--check"],
        check=True,
    )
    verify_archive(
        args.wheel,
        "wheel",
        integrity_only=args.integrity_only,
        expected_commit=args.expected_commit,
    )
    verify_archive(
        args.sdist,
        "sdist",
        integrity_only=args.integrity_only,
        expected_commit=args.expected_commit,
    )
    print(
        "wheel and sdist integrity verified"
        + (
            "; qualification not asserted"
            if args.integrity_only
            else "; release qualification verified"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
