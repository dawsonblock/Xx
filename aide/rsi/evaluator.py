from __future__ import annotations

from statistics import mean
from typing import Iterable

from .policy import AdaptiveReplayPolicy
from .replay import ReplaySimulator
from .support import ReplaySupportIndex
from .types import PolicyPoolScore, ReplayEpisodeResult, ReplayWorld


class ReplayEvaluator:
    """Score exploration policies without executing the underlying coding agent."""

    def __init__(
        self,
        *,
        work_penalty: float = 0.10,
        parallel_bonus: float = 0.0,
        max_rounds: int | None = None,
    ):
        self.work_penalty = float(work_penalty)
        self.parallel_bonus = float(parallel_bonus)
        self.max_rounds = max_rounds

    @staticmethod
    def _attainment(world: ReplayWorld, best_seen: float | None) -> float:
        """Normalize discovery quality using evaluator-private recorded bounds.

        Policy code never receives these bounds. If an explicit pre-search baseline is
        available, use it; otherwise normalize against the worst *recorded* valid node.
        This fixes the old baseline leak while preserving a [0, 1] attainment scale.
        """
        if best_seen is None:
            return 0.0
        values = [
            n.score for n in world.nodes.values() if n.valid and n.score is not None
        ]
        if not values:
            return 0.0
        oracle = (max if world.maximize else min)(values)
        baseline = world.baseline_score
        if baseline is None:
            baseline = (min if world.maximize else max)(values)
        denom = (oracle - baseline) if world.maximize else (baseline - oracle)
        numer = (best_seen - baseline) if world.maximize else (baseline - best_seen)
        if abs(denom) <= 1e-12:
            return 1.0 if numer >= -1e-12 else 0.0
        return max(0.0, min(1.0, numer / denom))

    def evaluate_world(
        self,
        policy: AdaptiveReplayPolicy,
        world: ReplayWorld,
        *,
        support_index: ReplaySupportIndex | None = None,
    ) -> ReplayEpisodeResult:
        sim = ReplaySimulator(world, support_index=support_index)
        trace: list[dict[str, object]] = []
        round_limit = self.max_rounds or max(1, world.node_count * 2)
        stopped = False
        while not sim.done() and sim.rounds < round_limit:
            state = sim.snapshot()
            batch = policy.select_batch(state)
            trace.append(
                {
                    "round": sim.rounds,
                    "probes": sim.probes,
                    "batch": list(batch),
                    "best_score_before": sim.best_score(),
                }
            )
            if not batch:
                stopped = True
                break
            sim.probe_batch(batch)

        attainment = self._attainment(world, sim.best_score())
        work_fraction = sim.probes / max(1, world.node_count)
        if sim.probes == 0 or sim.rounds == 0:
            parallel_eff = 0.0
        else:
            parallel_eff = min(
                1.0, sim.probes / max(1.0, sim.rounds * world.max_parallelism)
            )
        reward = (
            attainment
            - self.work_penalty * work_fraction
            + self.parallel_bonus * parallel_eff
        )
        return ReplayEpisodeResult(
            world_id=world.world_id,
            reward=reward,
            attainment=attainment,
            best_score=sim.best_score(),
            probes=sim.probes,
            rounds=sim.rounds,
            parallel_efficiency=parallel_eff,
            stopped=stopped,
            trace=trace,
        )

    def evaluate_pool(
        self, policy: AdaptiveReplayPolicy, worlds: Iterable[ReplayWorld]
    ) -> PolicyPoolScore:
        worlds = list(worlds)
        if not worlds:
            return PolicyPoolScore(0.0, 0.0, 0.0, 0.0, [])
        episodes = []
        for i, world in enumerate(worlds):
            # Estimate coverage from other worlds only; allowing a world to index
            # itself would force support=1.0 and make the OOD control gene inert.
            reference = [w for j, w in enumerate(worlds) if j != i]
            support_index = ReplaySupportIndex(reference) if reference else None
            episodes.append(
                self.evaluate_world(policy, world, support_index=support_index)
            )
        work_fracs = [
            ep.probes / max(1, w.node_count) for ep, w in zip(episodes, worlds)
        ]
        return PolicyPoolScore(
            mean_reward=mean(ep.reward for ep in episodes),
            mean_attainment=mean(ep.attainment for ep in episodes),
            mean_work_fraction=mean(work_fracs),
            mean_parallel_efficiency=mean(ep.parallel_efficiency for ep in episodes),
            episodes=episodes,
        )

    def beta_sweep(
        self,
        policy: AdaptiveReplayPolicy,
        worlds: Iterable[ReplayWorld],
        beta_grid: Iterable[float],
    ) -> list[dict[str, float]]:
        worlds = list(worlds)
        out: list[dict[str, float]] = []
        for beta in beta_grid:
            score = self.evaluate_pool(policy.with_beta(beta), worlds)
            out.append(
                {
                    "beta": float(beta),
                    "reward": score.mean_reward,
                    "attainment": score.mean_attainment,
                    "work_fraction": score.mean_work_fraction,
                    "parallel_efficiency": score.mean_parallel_efficiency,
                }
            )
        return out

    def pareto_fitness(
        self,
        policy: AdaptiveReplayPolicy,
        worlds: Iterable[ReplayWorld],
        beta_grid: Iterable[float],
    ) -> float:
        """Area under attainment-vs-work curve with a small reward tie-breaker."""
        sweep = self.beta_sweep(policy, worlds, beta_grid)
        if not sweep:
            return 0.0
        # Build the monotone upper envelope in attainment-vs-work space rather
        # than integrating dominated sweep points. This makes beta sweeps a true
        # cost/attainment frontier instead of rewarding noisy non-monotone curves.
        by_work: dict[float, float] = {}
        for item in sweep:
            x = max(0.0, min(1.0, float(item["work_fraction"])))
            y = max(0.0, min(1.0, float(item["attainment"])))
            by_work[x] = max(y, by_work.get(x, 0.0))
        points: list[tuple[float, float]] = []
        running = 0.0
        for x, y in sorted(by_work.items()):
            running = max(running, y)
            points.append((x, running))

        # Add origin so policies that only attain quality after lots of work pay for it.
        auc = 0.0
        px, py = 0.0, 0.0
        for x, y in points:
            auc += (x - px) * (py + y) / 2.0
            px, py = x, y
        if px < 1.0:
            auc += (1.0 - px) * py
        best_reward = max(x["reward"] for x in sweep)
        return auc + 0.05 * best_reward

    def best_beta(
        self,
        policy: AdaptiveReplayPolicy,
        worlds: Iterable[ReplayWorld],
        beta_grid: Iterable[float],
    ) -> float:
        sweep = self.beta_sweep(policy, worlds, beta_grid)
        if not sweep:
            return policy.genome.beta
        # Reward already incorporates work (and, if enabled, real parallelism).
        return max(
            sweep, key=lambda x: (x["reward"], x["attainment"], -x["work_fraction"])
        )["beta"]
