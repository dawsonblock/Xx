from __future__ import annotations

import json
import shutil

import numpy as np

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
    freeze = {
        "qualified_code_commit": "a" * 40,
        "qualified_code_git_tree": "b" * 40,
        "source_snapshot_sha256": "b" * 64,
    }
    (tmp_path / "RELEASE_FREEZE_MANIFEST.json").write_text(json.dumps(freeze))
    monkeypatch.setattr(qualify_canary_statistics, "_ROOT", tmp_path)
    assert qualify_canary_statistics._git_value("rev-parse", "HEAD") is None
    assert (
        qualify_canary_statistics._release_freeze_value("qualified_code_commit")
        == "a" * 40
    )
    result = qualify_canary_statistics.run_campaign(
        campaigns=20,
        attempts=2,
        power_replicates=10,
        tasks=40,
        task_families=20,
        runs_per_task=3,
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
        tasks=40,
        task_families=20,
        runs_per_task=3,
        lineage_attempts=5,
        seed=20261001,
    )

    assert result["primary_independent_unit"] == "task_family_cluster"
    assert (
        len(result["family_cluster_null_type_i_by_seed_and_family_correlation"]) == 25
    )
    assert result["synthetic_lineage_stress"]["attempts"] == 5
    assert result["synthetic_lineage_stress"]["alpha_remaining"] < 0.05


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

    assert tcb["file_count"] == len(tcb["files"])
    assert release["qualified_code_commit"] == "a" * 40
    assert release["qualified_code_git_tree"] == "b" * 40
    assert release["package_version"] == "1.3.5"
    assert release["release_head"] is None
    assert release["dependency_lock_sha256"] is None
    assert release["release_status"] == "UNRELEASED_QUALIFICATION_INCOMPLETE"


def test_release_freeze_reads_pytest_counts_from_junit_xml(tmp_path, monkeypatch):
    (tmp_path / "qualification").mkdir()
    (tmp_path / "qualification/pytest-junit.xml").write_text(
        '<testsuites><testsuite tests="207" failures="0" errors="0" '
        'skipped="1" /></testsuites>'
    )
    monkeypatch.setattr(generate_release_manifests, "ROOT", tmp_path)

    result = generate_release_manifests._pytest_validation()

    assert result["status"] == "PASS"
    assert result["tests"] == 207
    assert result["passed"] == 206
    assert result["skipped"] == 1
