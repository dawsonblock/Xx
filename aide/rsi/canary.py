from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from statistics import median
from typing import Any, Iterable


@dataclass(frozen=True)
class CanaryResult:
    passed: bool
    candidate_best: float | None
    incumbent_best: float | None
    normalized_delta: float
    reason: str


@dataclass(frozen=True)
class CanarySeriesResult:
    passed: bool
    pass_fraction: float
    median_normalized_delta: float
    candidate_median_best: float | None
    incumbent_median_best: float | None
    reason: str
    pairs: tuple[CanaryResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "pass_fraction": self.pass_fraction,
            "median_normalized_delta": self.median_normalized_delta,
            "candidate_median_best": self.candidate_median_best,
            "incumbent_median_best": self.incumbent_median_best,
            "reason": self.reason,
            "pairs": [asdict(x) for x in self.pairs],
        }


class RealCanaryGate:
    """Paired real-world incumbent/challenger qualification.

    Every pair starts from fresh equivalent task state with the same attempt budget.
    v1.2 can aggregate multiple order-balanced pairs so a single stochastic coding
    rollout cannot silently grant live authority.
    """

    def __init__(
        self,
        *,
        max_normalized_regression: float = 0.05,
        min_valid: int = 1,
        min_pass_fraction: float = 0.66,
        score_scale_floor: float = 1.0,
    ):
        self.max_normalized_regression = float(max_normalized_regression)
        self.min_valid = max(1, int(min_valid))
        self.min_pass_fraction = min(1.0, max(0.0, float(min_pass_fraction)))
        self.score_scale_floor = max(1e-9, float(score_scale_floor))

    @staticmethod
    def _journal_scores(journal: Any) -> tuple[list[float], bool]:
        maximize = (
            True
            if getattr(journal, "metric_maximize", None) is None
            else bool(journal.metric_maximize)
        )
        values: list[float] = []
        for node in getattr(journal, "nodes", []):
            metric = getattr(node, "metric", None)
            if (
                metric is None
                or getattr(metric, "is_worst", False)
                or getattr(node, "is_buggy", False)
            ):
                continue
            try:
                v = float(metric.value)
            except (TypeError, ValueError, AttributeError):
                continue
            if math.isfinite(v):
                values.append(v)
        return values, maximize

    def evaluate_pair(
        self, candidate_journal: Any, incumbent_journal: Any
    ) -> CanaryResult:
        cvals, cmax = self._journal_scores(candidate_journal)
        ivals, imax = self._journal_scores(incumbent_journal)
        if cmax != imax:
            return CanaryResult(
                False, None, None, -math.inf, "metric direction mismatch"
            )
        if len(cvals) < self.min_valid:
            return CanaryResult(
                False,
                None,
                None,
                -math.inf,
                "challenger produced too few valid outcomes",
            )
        if len(ivals) < self.min_valid:
            return CanaryResult(
                False,
                None,
                None,
                -math.inf,
                "incumbent canary produced too few valid outcomes",
            )
        cbest = (max if cmax else min)(cvals)
        ibest = (max if imax else min)(ivals)
        # The comparison's outcome must not set its own normalization scale.
        # Use a fixed task-configurable floor and incumbent-relative scale only.
        scale = max(self.score_scale_floor, abs(ibest) * 0.05)
        delta = ((cbest - ibest) if cmax else (ibest - cbest)) / scale
        passed = delta >= -self.max_normalized_regression
        return CanaryResult(
            passed,
            cbest,
            ibest,
            delta,
            (
                "paired canary within regression envelope"
                if passed
                else "challenger regressed against paired incumbent canary"
            ),
        )

    def evaluate_series(self, pairs: Iterable[tuple[Any, Any]]) -> CanarySeriesResult:
        results = tuple(self.evaluate_pair(c, i) for c, i in pairs)
        if not results:
            return CanarySeriesResult(
                False,
                0.0,
                -math.inf,
                None,
                None,
                "no paired canary repetitions",
                results,
            )
        pass_fraction = sum(1 for r in results if r.passed) / len(results)
        deltas = [r.normalized_delta for r in results]
        med_delta = median(deltas)
        cvals = [r.candidate_best for r in results if r.candidate_best is not None]
        ivals = [r.incumbent_best for r in results if r.incumbent_best is not None]
        cmed = median(cvals) if cvals else None
        imed = median(ivals) if ivals else None
        passed = (
            pass_fraction >= self.min_pass_fraction
            and med_delta >= -self.max_normalized_regression
        )
        if passed:
            reason = "repeated paired canary passed aggregate regression gate"
        elif pass_fraction < self.min_pass_fraction:
            reason = "too few paired canary repetitions passed"
        else:
            reason = "median paired canary regression exceeded limit"
        return CanarySeriesResult(
            passed, pass_fraction, med_delta, cmed, imed, reason, results
        )
