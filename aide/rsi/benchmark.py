"""Canonical, precommitted benchmark family provenance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

FAMILY_KEYS = {
    "family_id",
    "task_ids",
    "domain",
    "dataset_provenance",
    "generator_provenance",
    "shared_data",
    "shared_evaluator_components",
    "known_correlations",
    "independence_group_id",
    "independence_rationale",
    "review_status",
}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate benchmark manifest key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs
    )
    validate_manifest(value)
    return value


def manifest_sha256(value: dict[str, Any]) -> str:
    validate_manifest(value)
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_manifest(value: Any, *, require_approved: bool = False) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "manifest_type",
        "review_status",
        "families",
    }:
        raise ValueError("benchmark manifest fields are invalid")
    if value["schema_version"] != 1 or value["manifest_type"] != "benchmark_families":
        raise ValueError("unsupported benchmark manifest")
    families = value["families"]
    if not isinstance(families, list):
        raise TypeError("benchmark families must be a list")
    if value["review_status"] not in {"UNREVIEWED", "APPROVED"}:
        raise ValueError("invalid benchmark review status")
    family_ids: set[str] = set()
    task_ids: set[str] = set()
    data_ids: set[str] = set()
    group_ids: set[str] = set()
    for family in families:
        if not isinstance(family, dict) or set(family) != FAMILY_KEYS:
            raise ValueError("benchmark family fields are invalid")
        for name in (
            "family_id",
            "domain",
            "dataset_provenance",
            "generator_provenance",
            "independence_group_id",
            "independence_rationale",
        ):
            if not isinstance(family[name], str) or not family[name].strip():
                raise ValueError(f"benchmark family {name} is required")
        if family["review_status"] not in {"UNREVIEWED", "APPROVED"}:
            raise ValueError("invalid family review status")
        if family["family_id"] in family_ids:
            raise ValueError("duplicate benchmark family")
        family_ids.add(family["family_id"])
        if family["independence_group_id"] in group_ids:
            raise ValueError("correlated families cannot be counted as independent")
        group_ids.add(family["independence_group_id"])
        for key in (
            "task_ids",
            "shared_data",
            "shared_evaluator_components",
            "known_correlations",
        ):
            items = family[key]
            if (
                not isinstance(items, list)
                or any(not isinstance(item, str) or not item.strip() for item in items)
                or len(items) != len(set(items))
            ):
                raise ValueError(f"invalid benchmark {key}")
        if not family["task_ids"]:
            raise ValueError("benchmark family requires tasks")
        if task_ids.intersection(family["task_ids"]):
            raise ValueError("task assigned to multiple benchmark families")
        task_ids.update(family["task_ids"])
        if data_ids.intersection(family["shared_data"]):
            raise ValueError("shared data crosses declared independent families")
        data_ids.update(family["shared_data"])
        if require_approved and (
            family["review_status"] != "APPROVED" or family["known_correlations"]
        ):
            raise ValueError("benchmark family independence is not approved")
    if families != sorted(families, key=lambda family: family["family_id"]):
        raise ValueError("benchmark families must use canonical path order")
    if require_approved and (
        value["review_status"] != "APPROVED" or len(families) < 40
    ):
        raise ValueError("at least 40 approved independent families are required")


def validate_panel_assignments(value: dict[str, Any], panel: Any) -> None:
    validate_manifest(value, require_approved=True)
    expected = {
        task_id: family["family_id"]
        for family in value["families"]
        for task_id in family["task_ids"]
    }
    observed = {task.task_id: task.task_family for task in panel.tasks}
    if observed != expected:
        raise ValueError(
            "panel task/family assignments differ from frozen benchmark manifest"
        )
