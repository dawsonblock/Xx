from __future__ import annotations

import math
from statistics import mean, pstdev
from typing import Iterable

from .types import Observation, ReplayNode, ReplayWorld


def _signature_from_records(records: Iterable[object]) -> tuple[float, ...]:
    nodes = list(records)
    if not nodes:
        return (0.0,) * 6
    roots = sum(1 for n in nodes if getattr(n, "depth", 1) == 1)
    depths = [max(1, int(getattr(n, "depth", 1))) for n in nodes]
    failures = sum(1 for n in nodes if bool(getattr(n, "is_buggy", False)))
    scores = [
        float(getattr(n, "score"))
        for n in nodes
        if bool(getattr(n, "valid", False))
        and getattr(n, "score", None) is not None
        and math.isfinite(float(getattr(n, "score")))
    ]
    score_spread = (max(scores) - min(scores)) if len(scores) >= 2 else 0.0
    return (
        math.log1p(len(nodes)),
        math.log1p(roots),
        mean(depths),
        max(depths),
        failures / len(nodes),
        math.log1p(abs(score_spread)),
    )


def world_signature(world: ReplayWorld) -> tuple[float, ...]:
    return _signature_from_records(world.nodes.values())


def observation_signature(observed: dict[str, Observation]) -> tuple[float, ...]:
    return _signature_from_records(observed.values())


class ReplaySupportIndex:
    """Coverage estimator only; it never predicts outcomes.

    v1.2 indexes historical *prefixes*, not just completed worlds. This makes the
    support score meaningful during a live episode and preserves replay/live
    parity: both environments can ask how similar the currently revealed prefix is
    to prefixes seen in prior worlds.
    """

    def __init__(self, worlds: list[ReplayWorld]):
        self.signatures: list[tuple[float, ...]] = []
        for world in worlds:
            ordered: list[ReplayNode] = sorted(
                world.nodes.values(), key=lambda n: (n.step, n.id)
            )
            prefix: list[ReplayNode] = []
            for node in ordered:
                prefix.append(node)
                self.signatures.append(_signature_from_records(prefix))
        if self.signatures:
            cols = list(zip(*self.signatures))
            self.means = tuple(mean(c) for c in cols)
            self.scales = tuple(max(0.25, pstdev(c)) for c in cols)
        else:
            self.means = (0.0,) * 6
            self.scales = (1.0,) * 6

    def support_signature(self, sig: tuple[float, ...]) -> float:
        if not self.signatures:
            return 0.0
        best = math.inf
        for ref in self.signatures:
            dist = math.sqrt(
                sum(((x - r) / s) ** 2 for x, r, s in zip(sig, ref, self.scales))
                / len(sig)
            )
            best = min(best, dist)
        return 1.0 / (1.0 + best)

    def support(self, world: ReplayWorld) -> float:
        return self.support_signature(world_signature(world))

    def support_observations(self, observed: dict[str, Observation]) -> float:
        return self.support_signature(observation_signature(observed))
