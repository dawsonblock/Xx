from __future__ import annotations

import json
import hashlib
import shutil

import numpy as np
import pytest

from tools import generate_release_manifests, qualify_canary_statistics


def test_calibration_tool_supports_source_archives_without_git_metadata(
    tmp_path, monkeypatch
):
    source_root = qualify_canary_statistics._ROOT
    for relative in qualify_canary_statistics._SOURCE_FILES:
        source = source_root / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    source_hashes = {
        relative: hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()
        for relative in qualify_canary_statistics._SOURCE_FILES
    }
    source_snapshot = hashlib.sha256(
        json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    (tmp_path / "SOURCE_TREE_MANIFEST.json").write_text(
        json.dumps(
            {
                "source_snapshot_sha256": source_snapshot,
                "files": source_hashes,
            }
        )
    )
    freeze = {
        "qualified_code_commit": "a" * 40,
        "qualified_code_git_tree": "b" * 40,
        "source_snapshot_sha256": source_snapshot,
    }
    (tmp_path / "RELEASE_FREEZE_MANIFEST.json").write_text(json.dumps(freeze))
    monkeypatch.setattr(qualify_canary_statistics, "_ROOT", tmp_path)
    assert qualify_canary_statistics._git_value("rev-parse", "HEAD") is None
    assert (
        qualify_canary_statistics._release_freeze_value(
            "qualified_code_commit", expected_files=source_hashes
        )
        == "a" * 40
    )
    result = qualify_canary_statistics.run_campaign(
        campaigns=20,
        attempts=2,
        power_replicates=10,
        tasks=80,
        task_families=40,
        runs_per_task=4,
        lineage_attempts=3,
        seed=20261002,
    )
    assert result["source_commit"] == "a" * 40
    assert result["source_git_tree"] == "b" * 40
    assert result["source_git_identity_available"]


def test_calibration_harness_reports_family_correlations_and_lineage():
    result = qualify_canary_statistics.run_campaign(
        campaigns=50,
        attempts=3,
        power_replicates=10,
        tasks=80,
        task_families=40,
        runs_per_task=4,
        lineage_attempts=5,
        seed=20261001,
    )

    assert result["primary_independent_unit"] == "task_family_cluster"
    assert (
        len(result["family_cluster_null_type_i_by_seed_and_family_correlation"]) == 25
    )
    assert result["synthetic_lineage_stress"]["attempts"] == 5
    assert result["synthetic_lineage_stress"]["alpha_remaining"] < 0.05
    assert result["promotion_attempt_horizon"] == 500
    assert result["spending_rule"] == "alpha_i = family_alpha / 500"
    assert result["protocol_id"] == "MULTITASK_PROMOTION_PROTOCOL_V5"
    assert result["minimum_production_tasks"] == 40
    assert result["minimum_production_independent_families"] == 40
    assert result["power_curve_family_counts_production_eligible"] == {
        "20": False,
        "30": False,
        "40": True,
        "50": True,
        "60": True,
    }
    assert result["runs_per_task"] == 4
    assert len(result["sequence_order_null_calibration"]) == 8
    assert result["schema_version"] == 4
    assert all(
        scenario["bias_grid"] == [0.01, 0.05, 0.1, 0.25]
        and len(scenario["bias_sweep"]) == 4
        for scenario in result["sequence_order_null_calibration"].values()
    )
    assert set(result["power_by_independent_family_count"]) == {
        "20",
        "30",
        "40",
        "50",
        "60",
    }


def test_four_run_order_schedule_cancels_constant_sequence_effects():
    family_effects, worst_task = qualify_canary_statistics._panel_family_effects_batch(
        np.random.default_rng(774),
        replicates=8,
        tasks=40,
        task_families=20,
        runs_per_task=4,
        true_effect=0.0,
        task_sd=0.0,
        run_sd=0.0,
        seed_correlation=0.0,
        family_correlation=0.0,
        tie_probability=0.0,
        order_nuisance={
            "first_run_advantage": 0.10,
            "second_run_advantage": 0.08,
            "time_drift": 0.04,
            "monotonic_load_drift": 0.03,
            "cache_warmup": 0.07,
            "provider_degradation": 0.05,
            "family_order_sensitivity_sd": 0.10,
        },
    )

    assert np.allclose(family_effects, 0.0, atol=1e-12)
    assert np.allclose(worst_task, 0.0, atol=1e-12)


def test_calibration_harness_rejects_attempts_beyond_protocol_horizon():
    with pytest.raises(ValueError, match="cannot exceed the fixed 500-attempt"):
        qualify_canary_statistics.run_campaign(
            campaigns=1,
            attempts=501,
            power_replicates=1,
            tasks=80,
            task_families=40,
            runs_per_task=4,
            lineage_attempts=1,
        )


def test_vectorized_calibration_decisions_match_production_gate():
    family_effects = np.asarray(
        [
            [0.1] * 20,
            [0.1] * 14 + [-0.01] * 6,
            [0.1] * 15 + [-0.01] * 5,
        ]
    )
    worst_task_effects = np.asarray([0.1, -0.01, -0.01])
    actual = qualify_canary_statistics._batch_decisions(
        family_effects,
        worst_task_effects,
        alpha=0.025,
    )
    expected = [
        qualify_canary_statistics.task_effect_decision(
            effects.tolist(),
            allocated_alpha=0.025,
            minimum_practical_effect=0.0,
            maximum_task_regression=0.25,
        )["passed"]
        for effects in family_effects
    ]
    assert actual.tolist() == expected


def test_release_freeze_is_content_addressed_and_does_not_claim_qualification():
    assert set(qualify_canary_statistics._SOURCE_FILES) == (
        generate_release_manifests.STATISTICAL_QUALIFICATION_PATHS
    )
    manifests = generate_release_manifests.build_manifests(
        qualified_code_commit="a" * 40, qualified_code_tree="b" * 40
    )
    tcb = manifests["TCB_MANIFEST.json"]
    release = manifests["RELEASE_FREEZE_MANIFEST.json"]
    source_manifest = manifests["SOURCE_TREE_MANIFEST.json"]

    assert tcb["file_count"] == len(tcb["files"])
    assert release["qualified_code_commit"] == "a" * 40
    assert release["qualified_code_git_tree"] == "b" * 40
    assert release["package_version"] == "1.3.5"
    assert release["release_head"] is None
    assert len(release["dependency_lock_sha256"]) == 64
    assert release["validation"]["dependency_lock_qualification"] in {
        "LOCAL_HASHED_INSTALL_PASS_HOSTED_NOT_CONFIRMED",
        "LOCK_PRESENT_HOSTED_NOT_CONFIRMED",
    }
    assert release["validation"]["dependency_lock_qualification"] != "PASS"
    assert release["validation"]["dependency_lock_local_install"] in {
        "PASS_LOCAL",
        "NOT_RUN",
    }
    assert release["release_status"] == "UNRELEASED_QUALIFICATION_INCOMPLETE"
    assert (
        source_manifest["source_snapshot_sha256"] == release["source_snapshot_sha256"]
    )
    assert source_manifest["files"]


def test_release_freeze_reads_pytest_counts_from_junit_xml(tmp_path, monkeypatch):
    qualification = tmp_path / "qualification/repair-1.3.6"
    qualification.mkdir(parents=True)
    (qualification / "pytest-junit.xml").write_text(
        '<testsuites><testsuite tests="207" failures="0" errors="0" '
        'skipped="1" /></testsuites>'
    )
    monkeypatch.setattr(generate_release_manifests, "ROOT", tmp_path)

    result = generate_release_manifests._pytest_validation()

    assert result["status"] == "PASS"
    assert result["tests"] == 207
    assert result["passed"] == 206
    assert result["skipped"] == 1


def test_release_freeze_ignores_historical_junit_results(tmp_path, monkeypatch):
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    (qualification / "pytest-junit.xml").write_text(
        '<testsuites><testsuite tests="207" failures="0" errors="0" '
        'skipped="1" /></testsuites>'
    )
    monkeypatch.setattr(generate_release_manifests, "ROOT", tmp_path)

    result = generate_release_manifests._pytest_validation()

    assert result["status"] == "NOT_RUN"
    assert result["junit_xml_sha256"] is None


def test_release_freeze_records_only_complete_matching_hosted_workflow_evidence(
    tmp_path, monkeypatch
):
    commit = "a" * 40
    workflow_head = "c" * 40
    (tmp_path / "VERSION").write_text("1.3.5\n")
    monkeypatch.setattr(generate_release_manifests, "ROOT", tmp_path)
    monkeypatch.setattr(
        generate_release_manifests,
        "_current_statistical_protocol",
        lambda: ("MULTITASK_PROMOTION_PROTOCOL_V5", "b" * 64),
    )
    source_snapshot = generate_release_manifests._canonical_sha256(
        generate_release_manifests._file_hashes(
            generate_release_manifests._source_paths()
        )
    )
    qualification = tmp_path / "qualification"
    qualification.mkdir()
    runs = {
        name: {
            "run_id": index,
            "url": f"https://github.com/example/repo/actions/runs/{index}",
            "head_sha": workflow_head,
            "source_snapshot_sha256": source_snapshot,
            "conclusion": "success",
        }
        for index, name in enumerate(
            sorted(generate_release_manifests.HOSTED_WORKFLOWS), start=1
        )
    }
    evidence = {
        "schema_version": 1,
        "qualified_code_commit": commit,
        "qualified_source_snapshot_sha256": source_snapshot,
        "workflow_head_sha": workflow_head,
        "runs": runs,
    }
    evidence_path = qualification / "repair-1.3.6/hosted-workflow-runs.json"
    evidence_path.parent.mkdir()
    evidence_path.write_text(json.dumps(evidence))

    release = generate_release_manifests.build_manifests(
        qualified_code_commit=commit, qualified_code_tree="d" * 40
    )["RELEASE_FREEZE_MANIFEST.json"]

    assert release["validation"]["hosted_platform_qualification"] == "PASS"
    assert release["hosted_workflow_runs"]["workflow_head_sha"] == workflow_head
    assert release["hosted_workflow_runs"]["artifact_sha256"]

    evidence["qualified_source_snapshot_sha256"] = "e" * 64
    evidence_path.write_text(json.dumps(evidence))
    stale = generate_release_manifests.build_manifests(
        qualified_code_commit=commit, qualified_code_tree="d" * 40
    )["RELEASE_FREEZE_MANIFEST.json"]
    assert stale["validation"]["hosted_platform_qualification"] == "STALE_OR_INCOMPLETE"

    evidence["qualified_source_snapshot_sha256"] = source_snapshot
    evidence["runs"].pop("package_completeness")
    evidence_path.write_text(json.dumps(evidence))
    incomplete = generate_release_manifests.build_manifests(
        qualified_code_commit=commit, qualified_code_tree="d" * 40
    )["RELEASE_FREEZE_MANIFEST.json"]
    assert (
        incomplete["validation"]["hosted_platform_qualification"]
        == "STALE_OR_INCOMPLETE"
    )
