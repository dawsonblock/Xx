from __future__ import annotations

import random
from dataclasses import replace
from typing import Iterable

from .evaluator import ReplayEvaluator
from .policy import AdaptiveReplayPolicy
from .types import PolicyGenome, ReplayWorld

# beta is deliberately excluded: it is swept offline and selected between live
# cycles instead of being mutated inside the structural policy search.
_FLOAT_FIELDS = {
    "ucb_weight",
    "exploit_weight",
    "trend_weight",
    "last_gain_weight",
    "exploration_weight",
    "underexplored_weight",
    "recovery_weight",
    "failure_penalty",
    "depth_penalty",
    "stagnation_penalty",
    "stop_threshold",
    "min_relative_gain",
    "exploration_floor",
    "recovery_floor",
    "ood_explore_boost",
}
_INT_FIELDS = {"stagnation_patience", "race_min_roots"}
_CATEGORICAL_FIELDS = {
    "score_rule": ("linear", "ucb", "trend"),
    "allocation_rule": ("portfolio", "greedy", "race"),
    "stop_rule": ("threshold", "patience", "conservative"),
}


def mutate_genome(
    genome: PolicyGenome, rng: random.Random, *, scale: float = 0.18
) -> PolicyGenome:
    """Mutate both bounded numeric parameters and safe structural DSL operators."""
    raw = genome.to_dict()
    names = [n for n in raw if n != "beta"]
    mutation_count = rng.randint(1, min(6, len(names)))
    for name in rng.sample(names, mutation_count):
        value = raw[name]
        if name in _CATEGORICAL_FIELDS:
            choices = [x for x in _CATEGORICAL_FIELDS[name] if x != value]
            if choices:
                raw[name] = rng.choice(choices)
        elif name in _INT_FIELDS:
            raw[name] = int(value) + rng.choice([-2, -1, 1, 2])
        elif name in _FLOAT_FIELDS:
            magnitude = max(0.05, abs(float(value)))
            raw[name] = float(value) + rng.gauss(0.0, scale * magnitude)
    return PolicyGenome.from_dict(raw)


class PolicyEvolutionEngine:
    """Cheap offline policy search over grounded replay worlds with beta sweeps.

    Structural search remains inside the typed PolicyGenome DSL: evolution can
    switch scoring/allocation/stopping operators, but never generate executable
    controller code.
    """

    def __init__(
        self,
        evaluator: ReplayEvaluator,
        *,
        population: int = 48,
        generations: int = 5,
        elite_count: int = 8,
        seed: int = 0,
        beta_grid: Iterable[float] | None = None,
    ):
        self.evaluator = evaluator
        self.population = max(4, int(population))
        self.generations = max(1, int(generations))
        self.elite_count = max(1, min(int(elite_count), self.population))
        self.seed = int(seed)
        self.beta_grid = tuple(beta_grid or (0.2, 0.4, 0.6, 0.8, 1.0))

    def _fitness(self, genome: PolicyGenome, worlds: list[ReplayWorld]) -> float:
        return self.evaluator.pareto_fitness(
            AdaptiveReplayPolicy(genome), worlds, self.beta_grid
        )

    def evolve(
        self,
        incumbent: PolicyGenome,
        development_worlds: Iterable[ReplayWorld],
        validation_worlds: Iterable[ReplayWorld] = (),
        seed_candidates: Iterable[PolicyGenome] = (),
    ) -> tuple[PolicyGenome, list[dict[str, object]]]:
        dev, val = list(development_worlds), list(validation_worlds)
        if not dev:
            return incumbent, []
        rng = random.Random(self.seed + len(dev) * 1009)
        population = [incumbent]
        for candidate in seed_candidates:
            if len(population) >= self.population:
                break
            population.append(candidate.bounded())
        population.extend(
            mutate_genome(incumbent, rng, scale=0.30)
            for _ in range(self.population - len(population))
        )
        history: list[dict[str, object]] = []

        for generation in range(self.generations):
            scored = sorted(
                ((self._fitness(g, dev), g) for g in population),
                key=lambda x: x[0],
                reverse=True,
            )
            elites = [g for _, g in scored[: self.elite_count]]
            best_dev, best_genome = scored[0]
            best_val = self._fitness(best_genome, val) if val else best_dev
            history.append(
                {
                    "generation": generation,
                    "dev_pareto": best_dev,
                    "validation_pareto": best_val,
                    "score_rule": best_genome.score_rule,
                    "allocation_rule": best_genome.allocation_rule,
                    "stop_rule": best_genome.stop_rule,
                }
            )
            population = [incumbent, *elites[: self.elite_count]]
            while len(population) < self.population:
                parent = rng.choice(elites)
                population.append(
                    mutate_genome(
                        parent, rng, scale=max(0.06, 0.22 * (0.8**generation))
                    )
                )

        unique = {tuple(sorted(g.to_dict().items())): g for g in population}
        candidates = list(unique.values())
        selection = val or dev
        candidate = max(
            candidates,
            key=lambda g: (self._fitness(g, selection), self._fitness(g, dev)),
        )
        if self._fitness(candidate, selection) < self._fitness(incumbent, selection):
            candidate = incumbent

        # Choose one live beta only after structural policy selection.
        beta = self.evaluator.best_beta(
            AdaptiveReplayPolicy(candidate), selection, self.beta_grid
        )
        candidate = replace(candidate, beta=float(beta)).bounded()
        return candidate, history
