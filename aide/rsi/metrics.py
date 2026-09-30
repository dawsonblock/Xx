from __future__ import annotations

from statistics import mean

from .types import ReplayWorld


def live_cycle_summary(world: ReplayWorld) -> dict[str, float]:
    nodes = sorted(world.nodes.values(), key=lambda n: (n.step, n.id))
    if not nodes:
        return {
            "early_root_gain_rate": 0.0,
            "deep_gain_rate": 0.0,
            "plateau_rate": 1.0,
            "hard_failure_rate": 0.0,
            "direction_coverage": 0.0,
        }
    score_by_id = {n.id: n.score for n in nodes}
    early_root_gains, deep_gains = [], []
    hard_failures = 0
    valid_deltas = []
    branches = {n.branch_id for n in nodes}
    for n in nodes:
        if n.is_buggy and n.fail_class in {
            "dependency",
            "permission",
            "sandbox",
            "unsupported",
        }:
            hard_failures += 1
        if n.parent_id == "__ROOT__" or n.score is None:
            continue
        p = score_by_id.get(n.parent_id)
        if p is None:
            continue
        d = (n.score - p) if world.maximize else (p - n.score)
        valid_deltas.append(d)
        if n.depth <= 2:
            early_root_gains.append(max(0.0, d))
        elif n.depth >= 4:
            deep_gains.append(max(0.0, d))
    scale = max(1e-9, world.score_scale())
    plateau = sum(
        1 for x in valid_deltas[-max(3, len(valid_deltas) // 3) :] if x <= 0.005 * scale
    )
    denom = max(1, len(valid_deltas[-max(3, len(valid_deltas) // 3) :]))
    return {
        "early_root_gain_rate": (
            mean(early_root_gains) / scale if early_root_gains else 0.0
        ),
        "deep_gain_rate": mean(deep_gains) / scale if deep_gains else 0.0,
        "plateau_rate": plateau / denom,
        "hard_failure_rate": hard_failures / max(1, len(nodes)),
        "direction_coverage": min(
            1.0,
            len(branches)
            / max(1, int(world.metadata.get("planned_width", len(branches) or 1))),
        ),
    }
