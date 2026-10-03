"""A changed family taxonomy cannot reuse the frozen panel identity."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from aide.rsi.benchmark import (
    load_manifest,
    manifest_sha256,
    validate_manifest,
    validate_panel_assignments,
)
from aide.rsi.state import RSIStateStore


def _reviewed_families():
    return {
        "schema_version": 1,
        "manifest_type": "benchmark_families",
        "review_status": "APPROVED",
        "families": [
            {
                "family_id": f"family-{index:02d}",
                "task_ids": [f"task-{index:02d}"],
                "domain": "synthetic fixture",
                "dataset_provenance": f"dataset-{index:02d}",
                "generator_provenance": "synthetic fixture",
                "shared_data": [f"dataset-{index:02d}"],
                "shared_evaluator_components": [],
                "known_correlations": [],
                "independence_group_id": f"group-{index:02d}",
                "independence_rationale": "test fixture uses disjoint synthetic data",
                "review_status": "APPROVED",
            }
            for index in range(40)
        ],
    }


def test_unreviewed_repository_manifest_cannot_authorize_live_panel():
    manifest = load_manifest(
        Path(__file__).resolve().parents[1] / "BENCHMARK_FAMILY_MANIFEST.json"
    )
    assert manifest["families"] == []
    with pytest.raises(ValueError, match="40 approved"):
        validate_manifest(manifest, require_approved=True)


def test_correlated_split_and_reassignment_invalidate_authority():
    original = _reviewed_families()
    validate_manifest(original, require_approved=True)
    panel = SimpleNamespace(
        tasks=[
            SimpleNamespace(
                task_id=f"task-{index:02d}", task_family=f"family-{index:02d}"
            )
            for index in range(40)
        ]
    )
    validate_panel_assignments(original, panel)
    original_digest = manifest_sha256(original)

    correlated = copy.deepcopy(original)
    correlated["families"][1]["independence_group_id"] = "group-00"
    with pytest.raises(ValueError, match="correlated families"):
        validate_manifest(correlated, require_approved=True)

    shared_data = copy.deepcopy(original)
    shared_data["families"][1]["shared_data"] = ["dataset-00"]
    with pytest.raises(ValueError, match="shared data"):
        validate_manifest(shared_data, require_approved=True)

    reassigned = copy.deepcopy(original)
    reassigned["families"][1]["task_ids"] = ["task-01-renamed"]
    assert manifest_sha256(reassigned) != original_digest
    with pytest.raises(ValueError, match="assignments differ"):
        validate_panel_assignments(reassigned, panel)


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="duplicate"):
        load_manifest(path)


def test_benchmark_digest_is_frozen_in_panel_and_durable_state(tmp_path):
    first = "a" * 64
    second = "b" * 64
    store = RSIStateStore(tmp_path / "state.json")
    store.write(benchmark_family_manifest_sha256=first)
    with pytest.raises(ValueError, match="immutable"):
        store.write(benchmark_family_manifest_sha256=second)
