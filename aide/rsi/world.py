from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable

from .types import ROOT_ID, ReplayNode, ReplayWorld


def _metric_value(node: Any) -> float | None:
    metric = getattr(node, "metric", None)
    if metric is None or getattr(metric, "is_worst", False):
        return None
    value = getattr(metric, "value", None)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _failure_class(node: Any) -> str:
    if not getattr(node, "is_buggy", False):
        return "ok"
    exc_type = getattr(node, "exc_type", None)
    if exc_type:
        text = str(exc_type).lower()
        if "timeout" in text:
            return "timeout"
        if "memory" in text or "oom" in text:
            return "resource"
        if "syntax" in text or "compile" in text:
            return "compile"
        return "runtime"
    analysis = str(getattr(node, "analysis", "") or "").lower()
    if "memory" in analysis or "oom" in analysis:
        return "resource"
    if "syntax" in analysis or "compile" in analysis:
        return "compile"
    return "evaluation"


def _node_depth(node: Any) -> int:
    depth = 1
    parent = getattr(node, "parent", None)
    seen: set[str] = set()
    while parent is not None:
        pid = str(getattr(parent, "id", id(parent)))
        if pid in seen:
            break
        seen.add(pid)
        depth += 1
        parent = getattr(parent, "parent", None)
    return depth


def _branch_id(node: Any) -> str:
    cur = node
    seen: set[str] = set()
    while getattr(cur, "parent", None) is not None:
        cid = str(getattr(cur, "id", id(cur)))
        if cid in seen:
            break
        seen.add(cid)
        cur = cur.parent
    return str(getattr(cur, "id", "unknown"))


def world_from_journal(
    journal: Any,
    *,
    world_id: str | None = None,
    max_parallelism: int = 1,
    metadata: dict[str, Any] | None = None,
) -> ReplayWorld:
    """Convert an AIDE Journal (or compatible object) into a grounded replay world."""

    nodes: dict[str, ReplayNode] = {}
    ordered = sorted(
        list(getattr(journal, "nodes", [])),
        key=lambda n: (getattr(n, "step", 0), str(getattr(n, "id", ""))),
    )
    for node in ordered:
        node_id = str(node.id)
        parent = getattr(node, "parent", None)
        parent_id = str(parent.id) if parent is not None else ROOT_ID
        score = _metric_value(node)
        is_buggy = bool(getattr(node, "is_buggy", score is None))
        nodes[node_id] = ReplayNode(
            id=node_id,
            parent_id=parent_id,
            step=int(getattr(node, "step", len(nodes)) or 0),
            depth=_node_depth(node),
            branch_id=_branch_id(node),
            score=score,
            valid=(score is not None and not is_buggy),
            is_buggy=is_buggy,
            fail_class=_failure_class(node),
            error=(
                str(getattr(node, "exc_info", None))
                if getattr(node, "exc_info", None)
                else None
            ),
            plan=getattr(node, "plan", None),
            analysis=getattr(node, "analysis", None),
            exec_time=getattr(node, "exec_time", None),
            provenance=dict(getattr(node, "rsi_provenance", {}) or {}),
            repairability=(
                dict(getattr(node, "rsi_jev_advisory", {}) or {}).get("repairability")
            ),
            advisory=dict(getattr(node, "rsi_jev_advisory", {}) or {}),
        )

    metric_maximize = getattr(journal, "metric_maximize", None)
    if metric_maximize is None:
        metric_maximize = True
        for node in ordered:
            metric = getattr(node, "metric", None)
            maximize = getattr(metric, "maximize", None) if metric is not None else None
            if maximize is not None:
                metric_maximize = bool(maximize)
                break

    # A replay policy must never receive a baseline inferred from an unrevealed
    # historical attempt. Only an explicitly supplied pre-search baseline is public.
    public_baseline = (metadata or {}).get("public_baseline_score")
    if world_id is None:
        fingerprint = "|".join(
            f"{n.id}:{n.parent_id}:{n.step}:{n.score}" for n in nodes.values()
        )
        world_id = "journal-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16]

    return ReplayWorld(
        world_id=world_id,
        nodes=nodes,
        maximize=bool(metric_maximize),
        max_parallelism=max(1, int(max_parallelism)),
        baseline_score=public_baseline,
        metadata=dict(metadata or {}),
    )


def world_from_journal_json(
    path: str | Path, *, world_id: str | None = None, max_parallelism: int = 1
) -> ReplayWorld:
    """Read an AIDE journal.json without importing dataclasses_json.

    The serialized journal stores parent links in ``node2parent``. This loader is
    intentionally dependency-light so replay tooling can run without the full AIDE
    runtime environment.
    """

    path = Path(path)
    raw = json.loads(path.read_text())
    node2parent = {str(k): str(v) for k, v in raw.get("node2parent", {}).items()}
    raw_nodes = raw.get("nodes", [])

    def depth(node_id: str) -> int:
        d = 1
        cur = node_id
        seen: set[str] = set()
        while cur in node2parent and cur not in seen:
            seen.add(cur)
            cur = node2parent[cur]
            d += 1
        return d

    def branch(node_id: str) -> str:
        cur = node_id
        seen: set[str] = set()
        while cur in node2parent and cur not in seen:
            seen.add(cur)
            cur = node2parent[cur]
        return cur

    replay_nodes: dict[str, ReplayNode] = {}
    maximize = raw.get("metric_maximize")
    for idx, item in enumerate(raw_nodes):
        nid = str(item.get("id"))
        metric = item.get("metric") or {}
        value = metric.get("value")
        is_worst = bool(metric.get("is_worst", False))
        try:
            score = None if is_worst or value is None else float(value)
            if score is not None and not math.isfinite(score):
                score = None
        except (TypeError, ValueError):
            score = None
        if maximize is None and metric.get("maximize") is not None:
            maximize = bool(metric.get("maximize"))
        buggy = bool(item.get("is_buggy", score is None))
        exc_type = item.get("exc_type")
        fail_class = (
            "ok" if not buggy else (str(exc_type).lower() if exc_type else "evaluation")
        )
        replay_nodes[nid] = ReplayNode(
            id=nid,
            parent_id=node2parent.get(nid, ROOT_ID),
            step=int(item.get("step", idx) or idx),
            depth=depth(nid),
            branch_id=branch(nid),
            score=score,
            valid=(score is not None and not buggy),
            is_buggy=buggy,
            fail_class=fail_class,
            error=(str(item.get("exc_info")) if item.get("exc_info") else None),
            plan=item.get("plan"),
            analysis=item.get("analysis"),
            exec_time=item.get("exec_time"),
            provenance=dict(item.get("rsi_provenance") or {}),
            repairability=(
                dict(item.get("rsi_jev_advisory") or {}).get("repairability")
            ),
            advisory=dict(item.get("rsi_jev_advisory") or {}),
        )

    # Standalone journal JSON does not contain a trustworthy pre-search baseline.
    # Keep it hidden rather than leaking the first historical result to the policy.
    baseline = None
    if world_id is None:
        fingerprint = "|".join(
            f"{n.id}:{n.parent_id}:{n.step}:{n.score}:{n.is_buggy}"
            for n in sorted(replay_nodes.values(), key=lambda n: (n.step, n.id))
        )
        world_id = "journal-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
    return ReplayWorld(
        world_id=world_id,
        nodes=replay_nodes,
        maximize=True if maximize is None else bool(maximize),
        max_parallelism=max(1, int(max_parallelism)),
        baseline_score=baseline,
        metadata={"source_journal": str(path)},
    )


def load_worlds(paths: Iterable[str | Path]) -> list[ReplayWorld]:
    worlds: list[ReplayWorld] = []
    for p in paths:
        p = Path(p)
        worlds.append(
            ReplayWorld.load(p)
            if p.name.endswith(".world.json")
            else world_from_journal_json(p)
        )
    return worlds
