from __future__ import annotations

from .evaluator import ReplayEvaluator
from .policy import AdaptiveReplayPolicy
from .split import WorldSplit
from .types import PolicyGenome, PromotionRecord


class QualificationGate:
    """Prevents a replay winner from automatically gaining live authority.

    Qualification now checks both aggregate held-out replay fitness and the worst
    single-world regression. A candidate therefore cannot hide a catastrophic loss
    on one qualification world behind gains on another.
    """

    def __init__(
        self,
        evaluator: ReplayEvaluator,
        *,
        min_validation_margin: float = 0.0,
        max_qualification_regression: float = 0.01,
        max_single_world_regression: float = 0.05,
        min_qualification_worlds: int = 1,
        beta_grid=(0.2, 0.4, 0.6, 0.8, 1.0),
    ):
        self.evaluator = evaluator
        self.min_validation_margin = float(min_validation_margin)
        self.max_qualification_regression = float(max_qualification_regression)
        self.max_single_world_regression = float(max_single_world_regression)
        self.min_qualification_worlds = max(1, int(min_qualification_worlds))
        self.beta_grid = tuple(float(x) for x in beta_grid)

    def _score(self, genome: PolicyGenome, worlds) -> float:
        return self.evaluator.pareto_fitness(
            AdaptiveReplayPolicy(genome), worlds, self.beta_grid
        )

    def _world_delta(
        self, candidate: PolicyGenome, incumbent: PolicyGenome, world
    ) -> float:
        return self._score(candidate, [world]) - self._score(incumbent, [world])

    def compare(
        self, candidate: PolicyGenome, incumbent: PolicyGenome, split: WorldSplit
    ) -> PromotionRecord:
        dev_c, dev_i = self._score(candidate, split.development), self._score(
            incumbent, split.development
        )
        val_pool = split.validation or split.development
        val_c, val_i = self._score(candidate, val_pool), self._score(
            incumbent, val_pool
        )
        qual_c = (
            self._score(candidate, split.qualification) if split.qualification else 0.0
        )
        qual_i = (
            self._score(incumbent, split.qualification) if split.qualification else 0.0
        )
        per_world = [
            self._world_delta(candidate, incumbent, w) for w in split.qualification
        ]
        worst_qual = min(per_world) if per_world else 0.0

        if len(split.qualification) < self.min_qualification_worlds:
            promoted = False
            reason = "insufficient immutable held-out replay worlds; candidate remains shadow-only"
        elif val_c - val_i < self.min_validation_margin:
            promoted = False
            reason = "candidate failed validation replay margin"
        elif qual_c - qual_i < -self.max_qualification_regression:
            promoted = False
            reason = "candidate regressed on aggregate immutable qualification replay"
        elif worst_qual < -self.max_single_world_regression:
            promoted = False
            reason = "candidate exceeded worst-world qualification regression limit"
        else:
            promoted = True
            reason = "candidate passed immutable replay qualification; repeated paired online canary still required"

        return PromotionRecord(
            candidate=candidate.to_dict(),
            incumbent=incumbent.to_dict(),
            dev_delta=dev_c - dev_i,
            validation_delta=val_c - val_i,
            qualification_delta=qual_c - qual_i,
            promoted=promoted,
            reason=reason,
            world_ids={
                "development": [w.world_id for w in split.development],
                "validation": [w.world_id for w in split.validation],
                "qualification": [w.world_id for w in split.qualification],
            },
            worst_qualification_delta=worst_qual,
        )
