from __future__ import annotations

from .types import ReplayWorld


def summarize_worlds(worlds: list[ReplayWorld], *, max_entries: int = 12) -> str:
    """Compact cross-round memory for the fixed coding agent.

    Replay remains the authority for policy improvement; this summary only keeps the
    next coding round aware of previously measured mechanisms and failures.
    """
    records = []
    for world in worlds:
        for n in world.nodes.values():
            if n.score is None:
                continue
            direction = n.score if world.maximize else -n.score
            records.append((direction, world.world_id, n))
    records.sort(key=lambda x: x[0], reverse=True)
    lines = [
        "Measured cross-round discovery history (measured results override proposal claims):"
    ]
    for _, wid, node in records[:max_entries]:
        lines.append(
            f"- world={wid} score={node.score} status={'bug' if node.is_buggy else 'valid'} "
            f"mechanism={node.plan or '(no plan)'} result={node.analysis or '(no analysis)'}"
        )
    failures = []
    for world in worlds[-5:]:
        for n in world.nodes.values():
            if n.is_buggy:
                failures.append(
                    f"- world={world.world_id} failure={n.fail_class}: {n.analysis or n.error or '(no detail)'}"
                )
    if failures:
        lines.append("Recent failures:")
        lines.extend(failures[-max_entries // 2 :])
    return "\n".join(lines)
