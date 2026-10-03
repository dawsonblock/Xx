"""Adversarial archive content tests with recomputed wheel RECORD entries."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from aide.rsi.benchmark import manifest_sha256
from tools import verify_package


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _wheel_bytes(files):
    files = dict(files)
    record = "aideml_rsi-1.3.5.dist-info/RECORD"
    rows = []
    for name, data in sorted(files.items()):
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        rows.append((name, f"sha256={digest}", str(len(data))))
    rows.append((record, "", ""))
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerows(rows)
    files[record] = stream.getvalue().encode()
    return files


@pytest.fixture
def package_fixture(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    source_files = {
        path: (f"authentic {path}\n").encode()
        for path in verify_package.RUNTIME_REQUIRED
    }
    source_files.update(
        {
            "requirements-rsi-ci.in": b"locked input\n",
            "requirements-rsi-ci.lock": b"locked artifact\n",
            "requirements-runtime.lock": b"locked runtime\n",
            "VERSION": b"1.3.5\n",
        }
    )
    benchmark = {
        "schema_version": 1,
        "manifest_type": "benchmark_families",
        "review_status": "APPROVED",
        "families": [
            {
                "family_id": f"family-{index:02d}",
                "task_ids": [f"task-{index:02d}"],
                "domain": "synthetic test fixture",
                "dataset_provenance": f"dataset-{index:02d}",
                "generator_provenance": "test fixture",
                "shared_data": [f"dataset-{index:02d}"],
                "shared_evaluator_components": [],
                "known_correlations": [],
                "independence_group_id": f"group-{index:02d}",
                "independence_rationale": "isolated synthetic fixture",
                "review_status": "APPROVED",
            }
            for index in range(40)
        ],
    }
    source_files["BENCHMARK_FAMILY_MANIFEST.json"] = _json(benchmark)
    hashes = {
        name: hashlib.sha256(data).hexdigest() for name, data in source_files.items()
    }
    source = {
        "files": hashes,
        "source_snapshot_sha256": verify_package._canonical_sha(hashes),
        "qualified_code_commit": "a" * 40,
    }
    tcb_files = {"aide/rsi/sandbox.py": hashes["aide/rsi/sandbox.py"]}
    tcb = {
        "files": tcb_files,
        "aggregate_tcb_sha256": verify_package._canonical_sha(tcb_files),
    }
    identity = {
        "source_snapshot_sha256": source["source_snapshot_sha256"],
        "aggregate_tcb_sha256": tcb["aggregate_tcb_sha256"],
        "dependency_lock_sha256": hashes["requirements-rsi-ci.lock"],
        "runtime_dependency_lock_sha256": hashes["requirements-runtime.lock"],
        "statistical_protocol_sha256": "b" * 64,
        "evaluator_sha256": "c" * 64,
        "benchmark_family_manifest_sha256": manifest_sha256(benchmark),
    }
    freeze = {
        "package_version": "1.3.5",
        "release_status": "UNRELEASED_QUALIFICATION_INCOMPLETE",
        "qualified_code_commit": "a" * 40,
        "statistical_protocol_sha256": identity["statistical_protocol_sha256"],
        "evaluator_sha256": identity["evaluator_sha256"],
        "benchmark_family_manifest_sha256": manifest_sha256(benchmark),
    }
    embedded = {
        "SOURCE_TREE_MANIFEST.json": _json(source),
        "TCB_MANIFEST.json": _json(tcb),
        "IDENTITY_MANIFEST.json": _json(identity),
        "RELEASE_FREEZE_MANIFEST.json": _json(freeze),
        "BUILD_MANIFEST.json": _json({"distribution_version": "1.3.5"}),
    }
    for name, data in {**source_files, **embedded}.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    wheel_files = dict(source_files)
    for name, data in embedded.items():
        wheel_files[f"aideml_rsi-1.3.5.data/data/share/aideml-rsi/{name}"] = data
    for name in (
        "VERSION",
        "BENCHMARK_FAMILY_MANIFEST.json",
        "requirements-rsi-ci.in",
        "requirements-rsi-ci.lock",
        "requirements-runtime.lock",
    ):
        wheel_files[f"aideml_rsi-1.3.5.data/data/share/aideml-rsi/{name}"] = (
            wheel_files.pop(name)
        )
    wheel_files["aideml_rsi-1.3.5.dist-info/METADATA"] = (
        b"Name: aideml-rsi\nVersion: 1.3.5\n"
    )
    wheel_files["aideml_rsi-1.3.5.dist-info/WHEEL"] = b"Wheel-Version: 1.0\n"
    return root, wheel_files


def _write_wheel(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in _wheel_bytes(files).items():
            archive.writestr(name, data)


def _write_sdist(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(f"aideml-rsi-1.3.5/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def test_valid_synthetic_wheel_and_sdist_pass_integrity_only(package_fixture, tmp_path):
    root, wheel_files = package_fixture
    wheel = tmp_path / "valid.whl"
    _write_wheel(wheel, wheel_files)
    verify_package.verify_archive(wheel, "wheel", root=root, integrity_only=True)
    source_files = {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    sdist = tmp_path / "valid.tar.gz"
    _write_sdist(sdist, source_files)
    verify_package.verify_archive(sdist, "sdist", root=root, integrity_only=True)


@pytest.mark.parametrize(
    "attack", ["fake", "source", "tcb", "lock", "extra", "missing", "version"]
)
def test_tampered_wheel_fails_even_with_recomputed_record(
    package_fixture, tmp_path, attack
):
    root, files = package_fixture
    files = dict(files)
    target = "aide/rsi/sandbox.py" if attack == "tcb" else "aide/rsi/statistics.py"
    if attack == "fake":
        for name in list(files):
            if name.endswith(".py"):
                files[name] = b"not authentic"
    elif attack in {"source", "tcb"}:
        files[target] = b"modified source"
    elif attack == "lock":
        files[
            "aideml_rsi-1.3.5.data/data/share/aideml-rsi/requirements-rsi-ci.lock"
        ] = b"modified lock"
    elif attack == "extra":
        files["sitecustomize.py"] = b"print('executed')\n"
    elif attack == "missing":
        files.pop(target)
    elif attack == "version":
        files["aideml_rsi-1.3.5.data/data/share/aideml-rsi/VERSION"] = b"9.9.9\n"
    path = tmp_path / "attack.whl"
    _write_wheel(path, files)
    with pytest.raises(ValueError):
        verify_package.verify_archive(path, "wheel", root=root, integrity_only=True)


def test_stale_qualification_cannot_be_accepted(package_fixture, tmp_path):
    root, files = package_fixture
    path = tmp_path / "unqualified.whl"
    _write_wheel(path, files)
    with pytest.raises(ValueError, match="release status"):
        verify_package.verify_archive(path, "wheel", root=root)


def test_wrong_commit_and_stale_ledger_fail(package_fixture, tmp_path):
    root, files = package_fixture
    files = dict(files)
    freeze_path = root / "RELEASE_FREEZE_MANIFEST.json"
    freeze = json.loads(freeze_path.read_text())
    freeze["release_status"] = "RELEASE_QUALIFIED"
    freeze_path.write_bytes(_json(freeze))
    embedded_prefix = "aideml_rsi-1.3.5.data/data/share/aideml-rsi/"
    files[embedded_prefix + "RELEASE_FREEZE_MANIFEST.json"] = freeze_path.read_bytes()
    identity = json.loads((root / "IDENTITY_MANIFEST.json").read_text())
    gate = {key: value for key, value in identity.items() if key.endswith("_sha256")}
    gate.update({"gate_id": "test", "mandatory": True, "status": "PASS"})
    ledger = _json({"gates": [gate]})
    provenance = _json(
        {
            "source_snapshot_sha256": identity["source_snapshot_sha256"],
            "aggregate_tcb_sha256": identity["aggregate_tcb_sha256"],
            "dependency_lock_sha256": identity["dependency_lock_sha256"],
            "source_commit": "d" * 40,
        }
    )
    for name, data in {
        "RELEASE_QUALIFICATION_LEDGER.json": ledger,
        "BUILD_PROVENANCE.json": provenance,
    }.items():
        (root / name).write_bytes(data)
        files[embedded_prefix + name] = data
    path = tmp_path / "qualified.whl"
    _write_wheel(path, files)
    verify_package.verify_archive(path, "wheel", root=root, expected_commit="d" * 40)
    with pytest.raises(ValueError, match="different source commit"):
        verify_package.verify_archive(
            path, "wheel", root=root, expected_commit="e" * 40
        )
    gate["source_snapshot_sha256"] = "f" * 64
    stale = _json({"gates": [gate]})
    (root / "RELEASE_QUALIFICATION_LEDGER.json").write_bytes(stale)
    files[embedded_prefix + "RELEASE_QUALIFICATION_LEDGER.json"] = stale
    _write_wheel(path, files)
    with pytest.raises(ValueError, match="stale gate identity"):
        verify_package.verify_archive(
            path, "wheel", root=root, expected_commit="d" * 40
        )
