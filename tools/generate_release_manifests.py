"""Generate reproducible TCB and source-snapshot qualification manifests."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = (
    "BUILD_MANIFEST.json",
    "IDENTITY_MANIFEST.json",
    "TCB_MANIFEST.json",
    "RELEASE_FREEZE_MANIFEST.json",
    "SOURCE_TREE_MANIFEST.json",
)
HOSTED_WORKFLOWS = {
    "linux_bubblewrap",
    "macos_seatbelt",
    "macos_nested_candidate_timeout",
    "windows_rsi_state_lock",
    "linter",
    "package_completeness",
}
GENERATED_OR_VOLATILE = {
    *OUTPUTS,
    "BUILD_MANIFEST.json",
    "RELEASE_QUALIFICATION_MANIFEST.md",
    "RELEASE_SOURCE_SHA256SUMS",
    "RELEASE_QUALIFICATION_LEDGER.json",
    "RELEASE_QUALIFICATION_LEDGER.sig",
    "SOURCE_QUALIFICATION_LEDGER.json",
    "SOURCE_QUALIFICATION_LEDGER.sig",
    "BUILD_PROVENANCE.json",
    "ARTIFACT_ATTESTATION.json",
    "ARTIFACT_ATTESTATION.sig",
    "PUBLICATION_RECEIPT.json",
    "PACKAGE_HASHES.json",
    "ARTIFACT_HASHES.json",
    "PACKAGE_SHA256SUMS",
    "SHA256SUMS",
    "SOURCE_TREE_MANIFEST.json",
    "VALIDATION_REPORT.md",
    "SECURITY_HARDENING_REPORT.md",
}
RELEASE_AUTHORITY_PATHS = {
    ".dockerignore",
    "Dockerfile",
    "Makefile",
    "MANIFEST.in",
    "VERSION",
    "setup.py",
    "requirements.txt",
    "requirements-replay.txt",
    "requirements-rsi-ci.in",
    "requirements-rsi-ci.lock",
    "release/qualification-ledger-public.pem",
}
SANDBOX_AUTHORITY_PATHS = {
    "Dockerfile",
    ".dockerignore",
    ".github/workflows/linux-bubblewrap.yml",
    "aide/rsi/sandbox.py",
    "aide/rsi/reference_evaluator.py",
    "aide/rsi/trusted_evaluator.py",
    "aide/utils/config.py",
    "aide/utils/config.yaml",
}
EVALUATOR_AUTHORITY_PATHS = {
    "aide/rsi/reference_evaluator.py",
    "aide/rsi/trusted_evaluator.py",
    "aide/rsi/evidence.py",
    "aide/rsi/qualification.py",
    "aide/rsi/runner.py",
    "aide/utils/config.py",
    "aide/utils/config.yaml",
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
    "requirements-rsi-ci.in",
    "requirements-rsi-ci.lock",
    "rsi_anchor_service.py",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
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


def _source_snapshot_status(commit: str | None, source_paths: list[str]) -> str:
    """State whether the hashed files equal the supplied Git commit."""
    if not commit:
        return "SOURCE_COMMIT_UNAVAILABLE"
    committed_paths = _git("ls-tree", "-r", "--name-only", commit)
    if committed_paths is None:
        return "SOURCE_COMMIT_UNAVAILABLE"
    if set(source_paths) - set(committed_paths.splitlines()):
        return "WORKTREE_HAS_UNCOMMITTED_SOURCE_FILES"
    try:
        comparison = subprocess.run(
            ["git", "diff", "--quiet", commit, "--", *source_paths],
            cwd=ROOT,
            check=False,
        )
    except OSError:
        return "SOURCE_COMMIT_COMPARISON_FAILED"
    if comparison.returncode == 0:
        return "COMMITTED_SOURCE_SNAPSHOT"
    return "WORKTREE_DIFFERS_FROM_COMMIT"


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
        if (ROOT / path).is_file()
        and path not in GENERATED_OR_VOLATILE
        and not path.startswith(("build/", "dist/", ".pytest_cache/", "__pycache__/"))
        and not path.startswith("qualification/")
        and not any(part.endswith(".egg-info") for part in Path(path).parts)
        and not any(
            part in {".venv", ".ruff_cache", ".mypy_cache", "logs", "workspaces"}
            for part in Path(path).parts
        )
        and "/__pycache__/" not in path
    )


def _tcb_groups(source_paths: list[str]) -> dict[str, list[str]]:
    """Enumerate effective authority from the canonical source inventory."""
    source = set(source_paths)
    runtime = {
        path for path in source if path.startswith("aide/") and path.endswith(".py")
    } | {"aide/utils/config.yaml", "rsi_anchor_service.py"}
    # A bundled executable component may influence JEV advice or runtime behavior.
    runtime.update(path for path in source if path.startswith("vendor/"))
    runtime.update(
        path
        for path in source
        if path in {"requirements.txt", "requirements-runtime.lock"}
    )
    release = (
        RELEASE_AUTHORITY_PATHS
        | {
            path
            for path in source
            if path.startswith("requirements-") and path.endswith(".lock")
        }
        | {path for path in source if path.startswith(".github/workflows/")}
        | {
            path
            for path in source
            if path.startswith(("tools/", "tests/")) and path.endswith(".py")
        }
    )
    statistical = STATISTICAL_QUALIFICATION_PATHS | {
        "aide/rsi/evolution.py",
        "aide/rsi/jev.py",
        "aide/rsi/split.py",
    }
    sandbox = SANDBOX_AUTHORITY_PATHS
    groups = {
        "runtime_tcb": runtime,
        "statistical_tcb": statistical,
        "release_tcb": release,
        "sandbox_tcb": sandbox,
    }
    return {name: sorted(paths & source) for name, paths in sorted(groups.items())}


def _tcb_paths() -> list[str]:
    groups = _tcb_groups(_source_paths())
    return sorted({path for paths in groups.values() for path in paths})


def _file_hashes(paths: list[str]) -> dict[str, str]:
    return {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths
    }


def _evidence_matches_identity(evidence: Any, identity: dict[str, Any]) -> bool:
    """Unbound historical evidence cannot become current by its PASS label."""
    return isinstance(evidence, dict) and all(
        evidence.get(key) == value
        for key, value in identity.items()
        if key.endswith("_sha256") or key == "docker_base_image_digest"
    )


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


def _pytest_validation(
    expected_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = ROOT / "qualification/repair-1.3.6/pytest-junit.xml"
    from tools.evidence_schema import parse_json, validate_evidence
    from tools.gate_specs import gate_spec

    envelope_path = ROOT / gate_spec("pytest").evidence_path
    if not path.is_file():
        return {
            "status": "NOT_RUN",
            "artifact": "qualification/repair-1.3.6/pytest-junit.xml",
            "junit_xml_sha256": None,
        }
    junit_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if not envelope_path.is_file() or expected_identity is None:
        return {
            "status": "STALE_OR_UNBOUND",
            "artifact": "qualification/repair-1.3.6/pytest-junit.xml",
            "junit_xml_sha256": junit_sha256,
        }
    try:
        root = ET.parse(path).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        if not suites and "tests" in root.attrib:
            suites = [root]
        counts = {
            name: sum(int(suite.attrib.get(name, "0")) for suite in suites)
            for name in ("tests", "failures", "errors", "skipped")
        }
        envelope = parse_json(envelope_path.read_bytes())
    except (OSError, ET.ParseError, ValueError, json.JSONDecodeError):
        return {
            "status": "INVALID_REPORT",
            "artifact": "qualification/repair-1.3.6/pytest-junit.xml",
            "junit_xml_sha256": junit_sha256,
        }
    test_hashes = _file_hashes(
        [
            path
            for path in _source_paths()
            if path.startswith("tests/") and path.endswith(".py")
        ]
    )
    valid = False
    try:
        validate_evidence(
            envelope,
            spec=gate_spec("pytest"),
            identity=expected_identity,
            parameters={},
        )
        details = envelope["result"]["details"]
        valid = (
            envelope["artifacts"]
            == [{"artifact_id": "junit", "sha256": junit_sha256}]
            and details.get("test_inventory_sha256")
            == _canonical_sha256(test_hashes)
            and details.get("passed")
            == counts["tests"]
            - counts["failures"]
            - counts["errors"]
            - counts["skipped"]
            and details.get("failed") == counts["failures"] + counts["errors"]
            and details.get("skipped") == counts["skipped"]
        )
    except (KeyError, TypeError, ValueError):
        valid = False
    return {
        "status": (
            "PASS"
            if valid
            and counts["tests"] > counts["skipped"]
            and counts["failures"] == 0
            and counts["errors"] == 0
            else "STALE_OR_UNBOUND"
        ),
        "artifact": "qualification/repair-1.3.6/pytest-junit.xml",
        "passed": max(
            0,
            counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"],
        ),
        **counts,
        "junit_xml_sha256": junit_sha256,
        "evidence_sha256": hashlib.sha256(envelope_path.read_bytes()).hexdigest(),
    }


def build_manifests(
    *,
    qualified_code_commit: str | None = None,
    qualified_code_tree: str | None = None,
) -> dict[str, dict[str, Any]]:
    source_paths = _source_paths()
    source_hashes = _file_hashes(source_paths)
    source_snapshot_sha256 = _canonical_sha256(source_hashes)
    tcb_groups = {
        name: _file_hashes(paths) for name, paths in _tcb_groups(source_paths).items()
    }
    tcb_hashes = {
        path: source_hashes[path]
        for path in sorted({path for files in tcb_groups.values() for path in files})
    }
    tcb_group_digests = {
        name: _canonical_sha256(files) for name, files in tcb_groups.items()
    }
    evaluator_hashes = {
        path: source_hashes[path]
        for path in sorted(EVALUATOR_AUTHORITY_PATHS & set(source_hashes))
    }
    benchmark_manifest_path = ROOT / "BENCHMARK_FAMILY_MANIFEST.json"
    benchmark_manifest_sha256 = None
    if benchmark_manifest_path.is_file():
        spec = importlib.util.spec_from_file_location(
            "_aide_rsi_release_manifest_benchmark", ROOT / "aide/rsi/benchmark.py"
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load benchmark manifest validator")
        benchmark_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(benchmark_module)
        benchmark_manifest_sha256 = benchmark_module.manifest_sha256(
            benchmark_module.load_manifest(benchmark_manifest_path)
        )
    dockerfile = (
        (ROOT / "Dockerfile").read_text(encoding="utf-8")
        if (ROOT / "Dockerfile").is_file()
        else ""
    )
    docker_bases = re.findall(
        r"^FROM\s+\S+@sha256:([0-9a-f]{64})(?:\s|$)", dockerfile, flags=re.MULTILINE
    )
    docker_base_image_digest = (
        docker_bases[0] if docker_bases and len(set(docker_bases)) == 1 else None
    )
    current_protocol_id, current_protocol_sha256 = _current_statistical_protocol()
    tcb = {
        "schema_version": 3,
        "manifest_type": "trusted_computing_base",
        "files": tcb_hashes,
        "file_count": len(tcb_hashes),
        "canonical_files_sha256": _canonical_sha256(tcb_hashes),
        "groups": tcb_groups,
        "group_digests": tcb_group_digests,
        "aggregate_tcb_sha256": _canonical_sha256(tcb_hashes),
        "inclusion_policy": "All aide Python modules and bundled vendor files; statistical, sandbox, build, dependency, packaging, tests, and every GitHub workflow authority file.",
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
        qualified_code_commit
        or (
            prior_code_commit
            if old_freeze.get("source_snapshot_sha256") == source_snapshot_sha256
            else None
        )
        or _git("rev-parse", "HEAD")
    )
    if qualified_code_tree is not None:
        code_tree = qualified_code_tree
    elif qualified_code_commit is not None:
        code_tree = _git("rev-parse", f"{qualified_code_commit}^{{tree}}")
    elif (
        prior_code_commit == code_commit
        and old_freeze.get("source_snapshot_sha256") == source_snapshot_sha256
    ):
        code_tree = old_freeze.get("qualified_code_git_tree")
    else:
        code_tree = (
            _git("rev-parse", f"{code_commit}^{{tree}}") if code_commit else None
        )
    source_status = _source_snapshot_status(code_commit, source_paths)
    dependency_files = {
        path: source_hashes[path]
        for path in (
            "requirements.txt",
            "requirements-replay.txt",
            "requirements-rsi-ci.in",
            "requirements-rsi-ci.lock",
            "requirements-runtime.lock",
        )
        if path in source_hashes
    }
    dependency_lock_path = ROOT / "requirements-rsi-ci.lock"
    dependency_lock_sha256 = (
        hashlib.sha256(dependency_lock_path.read_bytes()).hexdigest()
        if dependency_lock_path.is_file()
        else None
    )
    runtime_lock_path = ROOT / "requirements-runtime.lock"
    runtime_dependency_lock_sha256 = (
        hashlib.sha256(runtime_lock_path.read_bytes()).hexdigest()
        if runtime_lock_path.is_file()
        else None
    )
    evidence_identity = {
        "source_snapshot_sha256": source_snapshot_sha256,
        "runtime_tcb_sha256": tcb_group_digests["runtime_tcb"],
        "release_tcb_sha256": tcb_group_digests["release_tcb"],
        "statistical_tcb_sha256": tcb_group_digests["statistical_tcb"],
        "sandbox_tcb_sha256": tcb_group_digests["sandbox_tcb"],
        "aggregate_tcb_sha256": tcb["aggregate_tcb_sha256"],
        "dependency_lock_sha256": dependency_lock_sha256,
        "runtime_dependency_lock_sha256": runtime_dependency_lock_sha256,
        "statistical_protocol_sha256": current_protocol_sha256,
        "evaluator_sha256": _canonical_sha256(evaluator_hashes),
        "benchmark_family_manifest_sha256": benchmark_manifest_sha256,
        "docker_base_image_digest": docker_base_image_digest,
        "docker_build_context_sha256": source_snapshot_sha256,
    }
    evidence_spec = importlib.util.spec_from_file_location(
        "_aide_rsi_qualification_evidence",
        Path(__file__).resolve().with_name("qualification_evidence.py"),
    )
    if evidence_spec is None or evidence_spec.loader is None:
        raise RuntimeError("cannot load qualification evidence policy")
    evidence_module = importlib.util.module_from_spec(evidence_spec)
    evidence_spec.loader.exec_module(evidence_module)
    qualification_artifact_envelopes = evidence_module.validation_matrix(
        ROOT, evidence_identity
    )
    source_qualification_passed = False
    if source_status == "COMMITTED_SOURCE_SNAPSHOT":
        try:
            benchmark_module.validate_manifest(
                benchmark_module.load_manifest(benchmark_manifest_path),
                require_approved=True,
            )
            release_spec = importlib.util.spec_from_file_location(
                "_aide_rsi_release_verifier", ROOT / "tools/verify_release.py"
            )
            if release_spec is None or release_spec.loader is None:
                raise RuntimeError("cannot load release verifier")
            release_module = importlib.util.module_from_spec(release_spec)
            release_spec.loader.exec_module(release_module)
            release_module.verify_signed_ledger(
                root=ROOT,
                identity=evidence_identity,
                source_commit=code_commit,
            )
            source_qualification_passed = True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            source_qualification_passed = False
    dependency_install_path = (
        ROOT / "qualification/repair-1.3.6/dependency-lock-install.json"
    )
    dependency_install_status = "NOT_RUN"
    if dependency_install_path.is_file():
        try:
            candidate = json.loads(dependency_install_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            candidate = None
        if isinstance(candidate, dict):
            inventory_sha = candidate.get("installed_distribution_inventory_sha256")
            dependency_install_status = (
                "PASS_LOCAL"
                if candidate.get("schema_version") == 1
                and candidate.get("status") == "PASS_LOCAL"
                and _evidence_matches_identity(candidate, evidence_identity)
                and candidate.get("lock_sha256") == dependency_lock_sha256
                and str(candidate.get("python_version", "")).startswith("3.12.")
                and candidate.get("install_command")
                == "python -m pip install --require-hashes -r requirements-rsi-ci.lock"
                and isinstance(candidate.get("installed_distribution_count"), int)
                and candidate["installed_distribution_count"] > 0
                and isinstance(inventory_sha, str)
                and len(inventory_sha) == 64
                else "INVALID_OR_STALE"
            )
    hosted_evidence_path = ROOT / "qualification/repair-1.3.6/hosted-workflow-runs.json"
    hosted_workflow_evidence: dict[str, Any] | None = None
    hosted_platform_status = "NOT_CONFIRMED"
    if hosted_evidence_path.is_file():
        hosted_platform_status = "STALE_OR_INCOMPLETE"
        try:
            evidence = json.loads(hosted_evidence_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            evidence = None
        if isinstance(evidence, dict):
            runs = evidence.get("runs")
            workflow_head = evidence.get("workflow_head_sha")
            source_matches = (
                evidence.get("qualified_code_commit") == code_commit
                and evidence.get("qualified_source_snapshot_sha256")
                == source_snapshot_sha256
                and _evidence_matches_identity(evidence, evidence_identity)
            )
            runs_complete = (
                isinstance(workflow_head, str)
                and len(workflow_head) == 40
                and isinstance(runs, dict)
                and set(runs) == HOSTED_WORKFLOWS
                and all(
                    isinstance(run, dict)
                    and run.get("conclusion") == "success"
                    and isinstance(run.get("run_id"), int)
                    and isinstance(run.get("url"), str)
                    and run.get("url", "").startswith("https://github.com/")
                    and run.get("head_sha") == workflow_head
                    and run.get("source_snapshot_sha256") == source_snapshot_sha256
                    and _evidence_matches_identity(run, evidence_identity)
                    for run in runs.values()
                )
            )
            hosted_workflow_evidence = {
                **evidence,
                "artifact_sha256": hashlib.sha256(
                    hosted_evidence_path.read_bytes()
                ).hexdigest(),
            }
            hosted_platform_status = (
                "PASS" if source_matches and runs_complete else "STALE_OR_INCOMPLETE"
            )
    qualification_path = (
        ROOT / "qualification/repair-1.3.6/multitask-statistical-qualification.json"
    )
    statistical_qualification: dict[str, Any] = {
        "artifact": "qualification/repair-1.3.6/multitask-statistical-qualification.json",
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
                and _evidence_matches_identity(artifact, evidence_identity)
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
            required_power_families = {"20", "30", "40", "50", "60"}
            order_null = artifact.get("sequence_order_null_calibration", {})
            required_order_scenarios = {
                "first_run_advantage",
                "second_run_advantage",
                "linear_time_drift",
                "monotonic_load_drift",
                "cache_warmup",
                "provider_degradation",
                "family_order_sensitivity",
                "combined_adverse_sequence_effects",
            }
            required_power_curve_keys = {
                f"effect_{effect:.3f}_attempt_{attempt}"
                for effect in (-0.01, 0.0, 0.005, 0.01, 0.02, 0.03)
                for attempt in (1, 10, 500)
            }
            power_curves_complete = (
                isinstance(power_by_family, dict)
                and required_power_families <= set(power_by_family)
                and all(
                    isinstance(power_by_family.get(family), dict)
                    and required_power_curve_keys <= set(power_by_family[family])
                    and all(
                        isinstance(power_by_family[family][key], dict)
                        and power_by_family[family][key].get("trials", 0) >= 5_000
                        for key in required_power_curve_keys
                    )
                    for family in required_power_families
                )
            )
            calibration_passed = (
                artifact.get("schema_version") == 4
                and artifact.get("protocol_id") == current_protocol_id
                and artifact.get("protocol_sha256") == current_protocol_sha256
                and artifact.get("family_alpha") == 0.05
                and artifact.get("runs_per_task") == 4
                and artifact.get("tasks_per_panel") == 80
                and artifact.get("independent_task_families_per_panel") == 40
                and artifact.get("minimum_production_tasks") == 40
                and artifact.get("minimum_production_independent_families") == 40
                and artifact.get("power_curve_family_counts_production_eligible")
                == {
                    "20": False,
                    "30": False,
                    "40": True,
                    "50": True,
                    "60": True,
                }
                and artifact.get("power_replicates", 0) >= 5_000
                and {1, 10, 500} <= set(artifact.get("power_attempt_indices", []))
                and isinstance(familywise, dict)
                and familywise.get("lineages", 0) >= 20_000
                and familywise.get("passed_family_alpha_bound") is True
                and isinstance(matrix, dict)
                and len(matrix) == 25
                and all(
                    isinstance(item, dict)
                    and item.get("passed_calibration_bound") is True
                    and item.get("trials", 0) >= 20_000
                    for item in matrix.values()
                )
                and isinstance(order_null, dict)
                and set(order_null) == required_order_scenarios
                and all(
                    isinstance(item, dict)
                    and item.get("passed_calibration_bound") is True
                    and item.get("bias_grid") == [0.01, 0.05, 0.1, 0.25]
                    and len(item.get("bias_sweep", [])) == 4
                    and all(
                        isinstance(bias, dict)
                        and bias.get("passed_calibration_bound") is True
                        and bias.get("trials", 0) >= 20_000
                        for bias in item.get("bias_sweep", [])
                    )
                    for item in order_null.values()
                )
                and artifact.get("attempts_per_familywise_lineage", 0) >= 500
                and power_curves_complete
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
                "artifact": "qualification/repair-1.3.6/multitask-statistical-qualification.json",
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
        "source_qualification_status": (
            "SOURCE_QUALIFIED"
            if source_qualification_passed
            else "SOURCE_QUALIFICATION_INCOMPLETE"
        ),
        "release_status": "UNRELEASED_QUALIFICATION_INCOMPLETE",
        "package_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "qualified_code_commit": code_commit,
        "qualified_code_git_tree": code_tree,
        "qualified_code_source_manifest_sha256": source_snapshot_sha256,
        "release_head": None,
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_snapshot_status": source_status,
        "source_file_count": len(source_hashes),
        "security_relevant_files_sha256": tcb_hashes,
        "security_relevant_digest_sha256": _canonical_sha256(tcb_hashes),
        "tcb_manifest_sha256": _canonical_sha256(tcb),
        "runtime_tcb_sha256": tcb_group_digests["runtime_tcb"],
        "release_tcb_sha256": tcb_group_digests["release_tcb"],
        "statistical_tcb_sha256": tcb_group_digests["statistical_tcb"],
        "sandbox_tcb_sha256": tcb_group_digests["sandbox_tcb"],
        "aggregate_tcb_sha256": tcb["aggregate_tcb_sha256"],
        "statistical_protocol_sha256": current_protocol_sha256,
        "evaluator_sha256": _canonical_sha256(evaluator_hashes),
        "benchmark_family_manifest_sha256": benchmark_manifest_sha256,
        "docker_base_image_digest": docker_base_image_digest,
        "docker_build_context_sha256": source_snapshot_sha256,
        "dependency_manifest_files_sha256": dependency_files,
        "dependency_manifest_sha256": _canonical_sha256(dependency_files),
        "dependency_lock_sha256": dependency_lock_sha256,
        "runtime_dependency_lock_sha256": runtime_dependency_lock_sha256,
        "dependency_lock_local_install_artifact": (
            "qualification/repair-1.3.6/dependency-lock-install.json"
        ),
        "dependency_lock_local_install_artifact_sha256": (
            hashlib.sha256(dependency_install_path.read_bytes()).hexdigest()
            if dependency_install_path.is_file()
            else None
        ),
        "dependency_lock_scope": (
            "Python 3.12 security/statistical CI and package qualification tools; "
            "not the complete optional AIDE research stack"
        ),
        "statistical_qualification": statistical_qualification,
        "hosted_workflow_runs": hosted_workflow_evidence,
        "validation": {
            "qualification_artifact_envelopes": qualification_artifact_envelopes,
            "local_statistical_calibration": statistical_qualification["status"],
            "local_full_pytest": _pytest_validation(evidence_identity),
            "hosted_platform_qualification": hosted_platform_status,
            "dependency_lock_qualification": (
                "HOSTED_MATRIX_PASS"
                if hosted_platform_status == "PASS" and dependency_lock_sha256
                else (
                    "LOCAL_HASHED_INSTALL_PASS_HOSTED_NOT_CONFIRMED"
                    if dependency_lock_sha256
                    and dependency_install_status == "PASS_LOCAL"
                    else (
                        "LOCK_PRESENT_HOSTED_NOT_CONFIRMED"
                        if dependency_lock_sha256
                        else "NOT_RUN"
                    )
                )
            ),
            "dependency_lock_local_install": dependency_install_status,
            "external_anchor_rollback_qualification": "NOT_RUN",
            "real_multitask_controls": "NOT_RUN",
            "linux_reference_evaluator_e2e": (
                "PASS"
                if hosted_platform_status == "PASS"
                else (
                    "STALE_OR_INCOMPLETE"
                    if hosted_platform_status == "STALE_OR_INCOMPLETE"
                    else "NOT_RUN_HOSTED"
                )
            ),
            "execution_order_balance": (
                "PASS_HOSTED"
                if hosted_platform_status == "PASS"
                else (
                    "STALE_OR_INCOMPLETE"
                    if hosted_platform_status == "STALE_OR_INCOMPLETE"
                    else "LOCAL_TESTS_PASS_HOSTED_NOT_RUN"
                )
            ),
            "null_and_power_calibration": statistical_qualification["status"],
            "real_task_null_and_effect_controls": "NOT_RUN",
            "in_memory_synthetic_lineage_stress": statistical_qualification.get(
                "in_memory_lineage_stress_status", "NOT_RUN"
            ),
        },
        "limitations": [
            "the hashed requirements-rsi-ci lock covers Python 3.12 security/statistical CI only; optional full AIDE research dependencies are outside this lock",
            "external anchor service is not independently deployed or rollback-qualified",
            "synthetic results do not establish real-task independence or AIDE improvement",
        ],
    }
    source_manifest = {
        "schema_version": 1,
        "manifest_type": "source_snapshot",
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_file_count": len(source_hashes),
        "qualified_code_commit": code_commit,
        "qualified_code_git_tree": code_tree,
        "files": source_hashes,
    }
    identity = {
        "schema_version": 1,
        "manifest_type": "release_identity",
        "source_snapshot_sha256": source_snapshot_sha256,
        "runtime_tcb_sha256": tcb_group_digests["runtime_tcb"],
        "release_tcb_sha256": tcb_group_digests["release_tcb"],
        "statistical_tcb_sha256": tcb_group_digests["statistical_tcb"],
        "sandbox_tcb_sha256": tcb_group_digests["sandbox_tcb"],
        "aggregate_tcb_sha256": tcb["aggregate_tcb_sha256"],
        "dependency_lock_sha256": dependency_lock_sha256,
        "runtime_dependency_lock_sha256": runtime_dependency_lock_sha256,
        "statistical_protocol_sha256": current_protocol_sha256,
        "evaluator_sha256": _canonical_sha256(evaluator_hashes),
        "benchmark_family_manifest_sha256": benchmark_manifest_sha256,
        "docker_base_image_digest": docker_base_image_digest,
        "docker_build_context_sha256": source_snapshot_sha256,
    }
    build = {
        "build": f"AIDE-DREAM-RSI-v{freeze['package_version']}-UNRELEASED",
        "distribution_name": "aideml-rsi",
        "distribution_version": freeze["package_version"],
        "current_qualification_status": freeze["release_status"],
        "current_qualification_manifest": "RELEASE_FREEZE_MANIFEST.json",
        "current_source_manifest": "SOURCE_TREE_MANIFEST.json",
        "current_tcb_manifest": "TCB_MANIFEST.json",
        "source_snapshot_sha256": source_snapshot_sha256,
        "security_relevant_digest_sha256": freeze["security_relevant_digest_sha256"],
        "dependency_lock_sha256": dependency_lock_sha256,
        "runtime_tcb_sha256": tcb_group_digests["runtime_tcb"],
        "release_tcb_sha256": tcb_group_digests["release_tcb"],
        "aggregate_tcb_sha256": tcb["aggregate_tcb_sha256"],
        "evaluator_sha256": _canonical_sha256(evaluator_hashes),
        "benchmark_family_manifest_sha256": benchmark_manifest_sha256,
        "statistical_protocol": {
            "id": current_protocol_id,
            "sha256": current_protocol_sha256,
        },
        "qualification_note": (
            "This is an unreleased repair snapshot. See the release freeze for "
            "source identity and explicit NOT_RUN qualification gates."
        ),
    }
    return {
        "BUILD_MANIFEST.json": build,
        "IDENTITY_MANIFEST.json": identity,
        "TCB_MANIFEST.json": tcb,
        "RELEASE_FREEZE_MANIFEST.json": freeze,
        "SOURCE_TREE_MANIFEST.json": source_manifest,
    }


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
        print("generated current source, TCB, and release freeze manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
