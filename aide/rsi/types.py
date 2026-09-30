from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

ROOT_ID = "__ROOT__"


def _atomic_json_write(path: str | Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode()
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class ReplayNode:
    """One recorded generation/evaluation outcome in a replay world."""

    id: str
    parent_id: str
    step: int
    depth: int
    branch_id: str
    score: float | None
    valid: bool
    is_buggy: bool
    fail_class: str = "ok"
    error: str | None = None
    plan: str | None = None
    analysis: str | None = None
    exec_time: float | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    repairability: str | None = None
    advisory: dict[str, Any] = field(default_factory=dict)

    def direction_score(self, maximize: bool) -> float | None:
        if self.score is None or not math.isfinite(self.score):
            return None
        return self.score if maximize else -self.score


@dataclass
class ReplayWorld:
    """A grounded replay simulator source built only from recorded outcomes."""

    world_id: str
    nodes: dict[str, ReplayNode]
    maximize: bool = True
    max_parallelism: int = 1
    baseline_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self, *, require_chain_branches: bool = False) -> None:
        if not self.world_id:
            raise ValueError("replay world_id must be non-empty")
        if int(self.max_parallelism) < 1:
            raise ValueError("max_parallelism must be >= 1")
        children: dict[str, list[str]] = {ROOT_ID: []}
        for key, node in self.nodes.items():
            if key != node.id:
                raise ValueError(f"replay node key/id mismatch: {key} != {node.id}")
            if node.id == ROOT_ID:
                raise ValueError("ROOT_ID is reserved and cannot be a replay node id")
            if node.parent_id != ROOT_ID and node.parent_id not in self.nodes:
                raise ValueError(
                    f"missing parent {node.parent_id} for replay node {node.id}"
                )
            if node.depth < 1:
                raise ValueError(f"invalid depth for replay node {node.id}")
            children.setdefault(node.parent_id, []).append(node.id)
            children.setdefault(node.id, [])

        # Detect cycles and validate recorded depth/branch identity from ancestry.
        for node in self.nodes.values():
            seen: set[str] = set()
            cur = node
            depth = 1
            while cur.parent_id != ROOT_ID:
                if cur.id in seen:
                    raise ValueError(f"cycle detected in replay world at {cur.id}")
                seen.add(cur.id)
                parent = self.nodes[cur.parent_id]
                if parent.step > cur.step:
                    raise ValueError(
                        f"parent step follows child step: {parent.id} -> {cur.id}"
                    )
                cur = parent
                depth += 1
            if node.depth != depth:
                raise ValueError(
                    f"depth mismatch for {node.id}: stored={node.depth} actual={depth}"
                )
            if node.branch_id != cur.id:
                raise ValueError(
                    f"branch_id mismatch for {node.id}: {node.branch_id} != {cur.id}"
                )

        if require_chain_branches:
            ambiguous = {
                pid: ids
                for pid, ids in children.items()
                if pid != ROOT_ID and len(ids) > 1
            }
            if ambiguous:
                raise ValueError(
                    "replay/live parity requires at most one recorded continuation per non-root node; "
                    f"ambiguous parents: {sorted(ambiguous)}"
                )

    def children_map(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {ROOT_ID: []}
        for node in sorted(self.nodes.values(), key=lambda n: (n.step, n.id)):
            out.setdefault(node.parent_id, []).append(node.id)
            out.setdefault(node.id, [])
        return out

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    def best_recorded_score(self) -> float | None:
        values = [
            n.score
            for n in self.nodes.values()
            if n.valid and n.score is not None and math.isfinite(n.score)
        ]
        if not values:
            return None
        return (max if self.maximize else min)(values)

    def score_scale(self) -> float:
        values = [
            n.score
            for n in self.nodes.values()
            if n.valid and n.score is not None and math.isfinite(n.score)
        ]
        if len(values) < 2:
            return max(1.0, abs(values[0])) if values else 1.0
        return max(1e-12, max(values) - min(values))

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_id": self.world_id,
            "nodes": {k: asdict(v) for k, v in self.nodes.items()},
            "maximize": self.maximize,
            "max_parallelism": self.max_parallelism,
            "baseline_score": self.baseline_score,
            "metadata": self.metadata,
            "schema_version": 3,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ReplayWorld":
        version = int(raw.get("schema_version", 1))
        if version not in {1, 2, 3}:
            raise ValueError(f"unsupported ReplayWorld schema_version: {version}")
        return cls(
            world_id=str(raw["world_id"]),
            nodes={str(k): ReplayNode(**v) for k, v in raw.get("nodes", {}).items()},
            maximize=bool(raw.get("maximize", True)),
            max_parallelism=max(1, int(raw.get("max_parallelism", 1))),
            baseline_score=raw.get("baseline_score"),
            metadata=dict(raw.get("metadata", {})),
        )

    def save(self, path: str | Path) -> None:
        _atomic_json_write(path, self.to_dict())

    @classmethod
    def load(cls, path: str | Path) -> "ReplayWorld":
        return cls.from_dict(json.loads(Path(path).read_text()))


@dataclass(frozen=True)
class Observation:
    """Prefix-visible information exposed to the exploration policy."""

    id: str
    parent_id: str
    step: int
    depth: int
    branch_id: str
    score: float | None
    valid: bool
    is_buggy: bool
    fail_class: str
    error: str | None
    delta_vs_parent: float | None
    delta_vs_baseline: float | None
    exec_time: float | None
    repairability: str | None = None
    advisory_confidence: float | None = None


@dataclass(frozen=True)
class ReplayAction:
    """A legal prefix action. target_id is private to the simulator."""

    action_id: str
    parent_id: str
    kind: Literal["open_root", "refine"]
    target_id: str = field(repr=False, compare=True)


@dataclass(frozen=True)
class GridPlan:
    branch_count: int
    refine_count: int
    reason: str


@dataclass(frozen=True)
class PolicyGenome:
    """Narrow, declarative exploration program.

    The policy-development loop evolves this object instead of arbitrary Python,
    so the RSI boundary cannot rewrite evaluators, promotion gates, or sandboxes.
    """

    # Typed structural policy DSL. These categorical choices let offline
    # evolution change controller structure without executing arbitrary generated
    # Python. The verifier in ``bounded`` rejects unsupported operators.
    score_rule: str = "linear"  # linear | ucb | trend
    allocation_rule: str = "portfolio"  # portfolio | greedy | race
    stop_rule: str = "threshold"  # threshold | patience | conservative

    beta: float = 0.60
    ucb_weight: float = 0.35
    race_min_roots: int = 3
    exploit_weight: float = 1.00
    trend_weight: float = 0.75
    last_gain_weight: float = 0.45
    exploration_weight: float = 0.80
    underexplored_weight: float = 0.35
    recovery_weight: float = 0.55
    failure_penalty: float = 0.90
    depth_penalty: float = 0.10
    stagnation_penalty: float = 0.30
    stop_threshold: float = -0.15
    stagnation_patience: int = 3
    min_relative_gain: float = 0.005
    exploration_floor: float = 0.15
    recovery_floor: float = 0.05
    ood_explore_boost: float = 0.25

    def bounded(self) -> "PolicyGenome":
        score_rule = str(self.score_rule).lower()
        allocation_rule = str(self.allocation_rule).lower()
        stop_rule = str(self.stop_rule).lower()
        if score_rule not in {"linear", "ucb", "trend"}:
            raise ValueError(f"unsupported score_rule: {self.score_rule}")
        if allocation_rule not in {"portfolio", "greedy", "race"}:
            raise ValueError(f"unsupported allocation_rule: {self.allocation_rule}")
        if stop_rule not in {"threshold", "patience", "conservative"}:
            raise ValueError(f"unsupported stop_rule: {self.stop_rule}")
        return replace(
            self,
            score_rule=score_rule,
            allocation_rule=allocation_rule,
            stop_rule=stop_rule,
            beta=min(1.0, max(0.0, float(self.beta))),
            ucb_weight=min(4.0, max(0.0, float(self.ucb_weight))),
            race_min_roots=min(32, max(1, int(self.race_min_roots))),
            exploit_weight=min(4.0, max(0.0, float(self.exploit_weight))),
            trend_weight=min(4.0, max(0.0, float(self.trend_weight))),
            last_gain_weight=min(4.0, max(0.0, float(self.last_gain_weight))),
            exploration_weight=min(4.0, max(0.0, float(self.exploration_weight))),
            underexplored_weight=min(4.0, max(0.0, float(self.underexplored_weight))),
            recovery_weight=min(4.0, max(0.0, float(self.recovery_weight))),
            failure_penalty=min(4.0, max(0.0, float(self.failure_penalty))),
            depth_penalty=min(2.0, max(0.0, float(self.depth_penalty))),
            stagnation_penalty=min(2.0, max(0.0, float(self.stagnation_penalty))),
            stop_threshold=min(2.0, max(-2.0, float(self.stop_threshold))),
            stagnation_patience=min(20, max(1, int(self.stagnation_patience))),
            min_relative_gain=min(0.5, max(0.0, float(self.min_relative_gain))),
            exploration_floor=min(0.8, max(0.0, float(self.exploration_floor))),
            recovery_floor=min(0.5, max(0.0, float(self.recovery_floor))),
            ood_explore_boost=min(1.0, max(0.0, float(self.ood_explore_boost))),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyGenome":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in raw.items() if k in allowed}).bounded()

    def save(self, path: str | Path) -> None:
        _atomic_json_write(path, self.to_dict())

    @classmethod
    def load(cls, path: str | Path) -> "PolicyGenome":
        return cls.from_dict(json.loads(Path(path).read_text()))


@dataclass
class ReplayEpisodeResult:
    world_id: str
    reward: float
    attainment: float
    best_score: float | None
    probes: int
    rounds: int
    parallel_efficiency: float
    stopped: bool
    trace: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PolicyPoolScore:
    mean_reward: float
    mean_attainment: float
    mean_work_fraction: float
    mean_parallel_efficiency: float
    episodes: list[ReplayEpisodeResult] = field(default_factory=list)


@dataclass
class PromotionRecord:
    candidate: dict[str, Any]
    incumbent: dict[str, Any]
    dev_delta: float
    validation_delta: float
    qualification_delta: float
    promoted: bool
    reason: str
    world_ids: dict[str, list[str]] = field(default_factory=dict)
    worst_qualification_delta: float = 0.0

    def save(self, path: str | Path) -> None:
        _atomic_json_write(path, asdict(self))
