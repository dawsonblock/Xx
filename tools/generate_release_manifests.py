"""Generate reproducible TCB and source-snapshot qualification manifests."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ("TCB_MANIFEST.json", "RELEASE_FREEZE_MANIFEST.json")
GENERATED_OR_VOLATILE = {
    *OUTPUTS,
    "BUILD_MANIFEST.json",
    "RELEASE_QUALIFICATION_MANIFEST.md",
    "RELEASE_SOURCE_SHA256SUMS",
    "SOURCE_TREE_MANIFEST.json",
    "VALIDATION_REPORT.md",
    "SECURITY_HARDENING_REPORT.md",
}
TCB_FIXED_PATHS = {
    ".github/workflows/linter.yml",
    ".github/workflows/linux-bubblewrap.yml",
    ".github/workflows/macos-nested-timeout.yml",
    ".github/workflows/macos-seatbelt.yml",
    ".github/workflows/package-smoke.yml",
    ".github/workflows/windows-rsi-state-lock.yml",
    "aide/utils/config.py",
    "aide/utils/config.yaml",
    "rsi_anchor_service.py",
    "requirements.txt",
    "requirements-replay.txt",
    "setup.py",
    "MANIFEST.in",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
    "tools/verify_package.py",
}
STATISTICAL_QUALIFICATION_PATHS = {
    "aide/rsi/canary.py",
    "aide/rsi/evidence.py",
    "aide/rsi/qualification.py",
    "aide/rsi/reference_evaluator.py",
    "aide/rsi/statistics.py",
    "aide/rsi/state.py",
    "aide/rsi/runner.py",
    "aide/rsi/trusted_evaluator.py",
    "aide/utils/config.py",
    "aide/utils/config.yaml",
    "rsi_anchor_service.py",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode:
        return None
    value = result.stdout.strip()
    return value or None


def _source_paths() -> list[str]:
    tracked = _git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if tracked is not None:
        paths = [path for path in tracked.split("\0") if path]
    else:
        paths = [
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.parts
        ]
    return sorted(
        path
        for path in paths
        if path not in GENERATED_OR_VOLATILE
        and not path.startswith(("build/", "dist/", ".pytest_cache/", "__pycache__/"))
        and not path.startswith("qualification/")
        and "/__pycache__/" not in path
    )


def _tcb_paths() -> list[str]:
    paths = set(TCB_FIXED_PATHS)
    paths.update(
        path.relative_to(ROOT).as_posix() for path in (ROOT / "aide/rsi").glob("*.py")
    )
    return sorted(path for path in paths if (ROOT / path).is_file())


def _file_hashes(paths: list[str]) -> dict[str, str]:
    return {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths
    }


def _current_statistical_protocol() -> tuple[str, str]:
    """Load the stdlib-only protocol module without importing aide.rsi.__init__."""
    name = "_aide_rsi_release_manifest_statistics"
    spec = importlib.util.spec_from_file_location(name, ROOT / "aide/rsi/statistics.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current RSI statistical protocol")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.MULTITASK_PROTOCOL_ID, module.MULTITASK_PROTOCOL_SHA256


def _pytest_validation() -> dict[str, Any]:
    path = ROOT / "qualification/pytest-junit.xml"
    if not path.is_file():
        return {"status": "NOT_RUN", "junit_xml_sha256": None}
    try:
        root = ET.parse(path).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        if not suites and "tests" in root.attrib:
            suites = [root]
        counts = {
            name: sum(int(suite.attrib.get(name, "0")) for suite in suites)
            for name in ("tests", "failures", "errors", "skipped")
        }
    except (OSError, ET.ParseError, ValueError):
        return {
            "status": "INVALID_REPORT",
            "junit_xml_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return {
        "status": (
            "PASS"
            if counts["tests"] > counts["skipped"]
            and counts["failures"] == 0
            and counts["errors"] == 0
            else "FAILED"
        ),
        "passed": max(
            0,
            counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"],
        ),
        **counts,
        "junit_xml_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def build_manifests(
    *,
    qualified_code_commit: str | None = None,
    qualified_code_tree: str | None = None,
) -> dict[str, dict[str, Any]]:
    source_hashes = _file_hashes(_source_paths())
    tcb_hashes = _file_hashes(_tcb_paths())
    current_protocol_id, current_protocol_sha256 = _current_statistical_protocol()
    tcb = {
        "schema_version": 2,
        "manifest_type": "trusted_computing_base",
        "files": tcb_hashes,
        "file_count": len(tcb_hashes),
        "canonical_files_sha256": _canonical_sha256(tcb_hashes),
    }
    old_freeze: dict[str, Any] = {}
    freeze_path = ROOT / "RELEASE_FREEZE_MANIFEST.json"
    if freeze_path.is_file():
        try:
            old_freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            old_freeze = {}
    prior_code_commit = old_freeze.get("qualified_code_commit")
    code_commit = (
        qualified_code_commit or prior_code_commit or _git("rev-parse", "HEAD")
    )
    if qualified_code_tree is not None:
        code_tree = qualified_code_tree
    elif qualified_code_commit is not None:
        code_tree = _git("rev-parse", f"{qualified_code_commit}^{{tree}}")
    elif prior_code_commit == code_commit:
        code_tree = old_freeze.get("qualified_code_git_tree")
    else:
        code_tree = (
            _git("rev-parse", f"{code_commit}^{{tree}}") if code_commit else None
        )
    dependency_files = {
        path: source_hashes[path]
        for path in ("requirements.txt", "requirements-replay.txt")
        if path in source_hashes
    }
    qualification_path = ROOT / "qualification/multitask-statistical-qualification.json"
    statistical_qualification: dict[str, Any] = {
        "artifact": "qualification/multitask-statistical-qualification.json",
        "artifact_sha256": None,
        "status": "NOT_RUN",
        "source_file_manifest_sha256": None,
        "null_familywise_rate": None,
        "null_familywise_wilson_95": None,
    }
    if qualification_path.is_file():
        try:
            artifact = json.loads(qualification_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            artifact = None
        if isinstance(artifact, dict):
            artifact_hashes = artifact.get("source_files_sha256")
            sources_match = (
                isinstance(artifact_hashes, dict)
                and set(artifact_hashes) == STATISTICAL_QUALIFICATION_PATHS
                and all(
                    source_hashes.get(path) == digest
                    for path, digest in artifact_hashes.items()
                )
                and artifact.get("source_file_manifest_sha256")
                == _canonical_sha256(artifact_hashes)
            )
            familywise = artifact.get("null_familywise_calibration", {})
            matrix = artifact.get(
                "family_cluster_null_type_i_by_seed_and_family_correlation", {}
            )
            power_by_family = artifact.get("power_by_independent_family_count", {})
            required_power_families = {"20", "30", "40"}
            calibration_passed = (
                artifact.get("protocol_id") == current_protocol_id
                and artifact.get("protocol_sha256") == current_protocol_sha256
                and artifact.get("family_alpha") == 0.05
                and isinstance(familywise, dict)
                and familywise.get("lineages", 0) >= 20_000
                and familywise.get("passed_family_alpha_bound") is True
                and isinstance(matrix, dict)
                and len(matrix) == 25
                and all(
                    isinstance(item, dict)
                    and item.get("passed_calibration_bound") is True
                    for item in matrix.values()
                )
                and artifact.get("attempts_per_familywise_lineage", 0) >= 100
                and isinstance(power_by_family, dict)
                and required_power_families <= set(power_by_family)
            )
            lineage = artifact.get("synthetic_lineage_stress", {})
            lineage_passed = (
                sources_match
                and calibration_passed
                and isinstance(lineage, dict)
                and isinstance(lineage.get("attempts"), int)
                and lineage.get("attempts", 0) >= 100
                and lineage.get("panel_count") == lineage.get("attempts")
                and lineage.get("alpha_remaining", 1.0)
                <= artifact.get("family_alpha", 0.05)
            )
            statistical_qualification = {
                "artifact": "qualification/multitask-statistical-qualification.json",
                "artifact_sha256": hashlib.sha256(
                    qualification_path.read_bytes()
                ).hexdigest(),
                "status": (
                    "SYNTHETIC_NULL_CALIBRATION_PASS"
                    if sources_match and calibration_passed
                    else "STALE_OR_FAILED"
                ),
                "protocol_id": artifact.get("protocol_id"),
                "protocol_sha256": artifact.get("protocol_sha256"),
                "source_file_manifest_sha256": artifact.get(
                    "source_file_manifest_sha256"
                ),
                "null_familywise_rate": (
                    familywise.get("false_promotion_rate")
                    if isinstance(familywise, dict)
                    else None
                ),
                "null_familywise_wilson_95": (
                    [
                        familywise.get("wilson_95_low"),
                        familywise.get("wilson_95_high"),
                    ]
                    if isinstance(familywise, dict)
                    else None
                ),
                "synthetic_lineage_attempts": artifact.get(
                    "attempts_per_familywise_lineage"
                ),
                "null_familywise_lineages": (
                    familywise.get("lineages") if isinstance(familywise, dict) else None
                ),
                "correlation_scenarios_passed": (
                    sum(
                        1
                        for item in matrix.values()
                        if isinstance(item, dict)
                        and item.get("passed_calibration_bound") is True
                    )
                    if isinstance(matrix, dict)
                    else 0
                ),
                "in_memory_lineage_stress_status": (
                    "PASS_NOT_STATESTORE_OR_ANCHOR_QUALIFICATION"
                    if lineage_passed
                    else "NOT_RUN_OR_FAILED"
                ),
                "in_memory_lineage_attempts": (
                    lineage.get("attempts") if isinstance(lineage, dict) else None
                ),
                "power_curve_reported": bool(
                    artifact.get("power_by_independent_family_count")
                ),
            }
    freeze = {
        "schema_version": 1,
        "release_status": "UNRELEASED_QUALIFICATION_INCOMPLETE",
        "package_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "qualified_code_commit": code_commit,
        "qualified_code_git_tree": code_tree,
        "qualified_code_source_manifest_sha256": _canonical_sha256(source_hashes),
        "release_head": None,
        "source_snapshot_sha256": _canonical_sha256(source_hashes),
        "source_file_count": len(source_hashes),
        "security_relevant_files_sha256": tcb_hashes,
        "security_relevant_digest_sha256": _canonical_sha256(tcb_hashes),
        "tcb_manifest_sha256": _canonical_sha256(tcb),
        "dependency_manifest_files_sha256": dependency_files,
        "dependency_manifest_sha256": _canonical_sha256(dependency_files),
        "dependency_lock_sha256": None,
        "statistical_qualification": statistical_qualification,
        "validation": {
            "local_statistical_calibration": statistical_qualification["status"],
            "local_full_pytest": _pytest_validation(),
            "hosted_platform_qualification": "NOT_CONFIRMED",
            "external_anchor_rollback_qualification": "NOT_RUN",
            "real_multitask_controls": "NOT_RUN",
            "in_memory_synthetic_lineage_stress": statistical_qualification.get(
                "in_memory_lineage_stress_status", "NOT_RUN"
            ),
        },
        "limitations": [
            "requirements files are not a qualified dependency lock",
            "external anchor service is not independently deployed or rollback-qualified",
            "synthetic results do not establish real-task independence or AIDE improvement",
        ],
    }
    return {"TCB_MANIFEST.json": tcb, "RELEASE_FREEZE_MANIFEST.json": freeze}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--qualified-code-commit")
    parser.add_argument("--qualified-code-tree")
    args = parser.parse_args(argv)
    outputs = build_manifests(
        qualified_code_commit=args.qualified_code_commit,
        qualified_code_tree=args.qualified_code_tree,
    )
    stale = []
    for relative, value in outputs.items():
        path = ROOT / relative
        rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
                stale.append(relative)
        else:
            path.write_text(rendered, encoding="utf-8")
    if stale:
        print("stale generated manifests: " + ", ".join(stale))
        return 1
    if args.check:
        print("release manifests match the current source snapshot")
    else:
        print("generated TCB_MANIFEST.json and RELEASE_FREEZE_MANIFEST.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
