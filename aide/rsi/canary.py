from __future__ import annotations

import math
import random
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any

from .evidence import has_trusted_evaluation


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
    lower_confidence_bound: float | None
    reason: str
    pairs: tuple[CanaryResult, ...]
    sign_test_p_value: float | None = None
    sequential_alpha: float | None = None
    promotion_attempt_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "pass_fraction": self.pass_fraction,
            "median_normalized_delta": self.median_normalized_delta,
            "candidate_median_best": self.candidate_median_best,
            "incumbent_median_best": self.incumbent_median_best,
            "lower_confidence_bound": self.lower_confidence_bound,
            "sign_test_p_value": self.sign_test_p_value,
            "sequential_alpha": self.sequential_alpha,
            "promotion_attempt_index": self.promotion_attempt_index,
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
        min_pairs: int = 5,
        confidence_level: float = 0.95,
        bootstrap_samples: int = 10000,
        min_effect_size: float = 0.0,
        max_single_pair_regression: float = 0.25,
        score_scale_floor: float = 1.0,
        artifact_root: str | Path | None = None,
        require_artifacts: bool = False,
        expected_evaluation_identity: dict[str, Any] | None = None,
        promotion_block_reason: str | None = None,
        promotion_attempt_index: int | None = None,
        experiment_alpha: float | None = None,
    ):
        self.max_normalized_regression = float(max_normalized_regression)
        if (
            not math.isfinite(self.max_normalized_regression)
            or self.max_normalized_regression < 0
        ):
            raise ValueError("max_normalized_regression must be finite and nonnegative")
        self.min_valid = max(1, int(min_valid))
        self.min_pass_fraction = float(min_pass_fraction)
        if (
            not math.isfinite(self.min_pass_fraction)
            or not 0 <= self.min_pass_fraction <= 1
        ):
            raise ValueError("min_pass_fraction must be in [0, 1]")
        self.configured_min_pairs = max(1, int(min_pairs))
        self.min_pairs = self.configured_min_pairs
        self.confidence_level = float(confidence_level)
        if not 0.5 < self.confidence_level < 1.0:
            raise ValueError("confidence_level must be in (0.5, 1)")
        self.bootstrap_samples = int(bootstrap_samples)
        if not 100 <= self.bootstrap_samples <= 1_000_000:
            raise ValueError("bootstrap_samples must be in [100, 1000000]")
        self.min_effect_size = float(min_effect_size)
        self.max_single_pair_regression = float(max_single_pair_regression)
        if not math.isfinite(self.min_effect_size):
            raise ValueError("min_effect_size must be finite")
        if (
            not math.isfinite(self.max_single_pair_regression)
            or self.max_single_pair_regression < self.max_normalized_regression
        ):
            raise ValueError(
                "max_single_pair_regression must be finite and at least the series regression margin"
            )
        self.score_scale_floor = float(score_scale_floor)
        if not math.isfinite(self.score_scale_floor) or self.score_scale_floor <= 0:
            raise ValueError("score_scale_floor must be finite and positive")
        self.artifact_root = Path(artifact_root) if artifact_root is not None else None
        self.require_artifacts = bool(require_artifacts)
        self.expected_evaluation_identity = dict(expected_evaluation_identity or {})
        self.promotion_block_reason = promotion_block_reason
        if (promotion_attempt_index is None) != (experiment_alpha is None):
            raise ValueError(
                "promotion_attempt_index and experiment_alpha must be configured together"
            )
        self.promotion_attempt_index: int | None = None
        self.experiment_alpha: float | None = None
        self.sequential_alpha: float | None = None
        if promotion_attempt_index is not None:
            if (
                isinstance(promotion_attempt_index, bool)
                or not isinstance(promotion_attempt_index, int)
                or not 1 <= promotion_attempt_index <= 1_000_000_000
            ):
                raise ValueError("promotion_attempt_index must be a positive integer")
            experiment_alpha = float(experiment_alpha)
            if not math.isfinite(experiment_alpha) or not 0 < experiment_alpha < 1:
                raise ValueError("experiment_alpha must be finite and in (0, 1)")
            self.promotion_attempt_index = promotion_attempt_index
            self.experiment_alpha = experiment_alpha
            # This alpha-spending sequence sums to experiment_alpha over an
            # unbounded number of promotions: alpha_i = alpha / (i * (i + 1)).
            self.sequential_alpha = experiment_alpha / (
                promotion_attempt_index * (promotion_attempt_index + 1)
            )
            exact_sign_pairs = max(1, math.ceil(math.log2(1.0 / self.sequential_alpha)))
            while 2.0**-exact_sign_pairs > self.sequential_alpha:
                exact_sign_pairs += 1
            self.min_pairs = max(self.min_pairs, exact_sign_pairs)

    def authority_config(self) -> dict[str, Any]:
        """Return every setting that can affect a promotion decision."""
        config = {
            "max_normalized_regression": self.max_normalized_regression,
            "min_valid": self.min_valid,
            "min_pass_fraction": self.min_pass_fraction,
            "min_pairs": self.min_pairs,
            "confidence_level": self.confidence_level,
            "bootstrap_samples": self.bootstrap_samples,
            "min_effect_size": self.min_effect_size,
            "max_single_pair_regression": self.max_single_pair_regression,
            "score_scale_floor": self.score_scale_floor,
            "require_artifacts": self.require_artifacts,
            "expected_evaluation_identity": self.expected_evaluation_identity,
            "promotion_block_reason": self.promotion_block_reason,
        }
        if self.promotion_attempt_index is not None:
            config.update(
                promotion_attempt_index=self.promotion_attempt_index,
                experiment_alpha=self.experiment_alpha,
                sequential_alpha=self.sequential_alpha,
            )
        return config

    def policy_config(self) -> dict[str, Any]:
        """Static promotion rules pinned for the lifetime of an experiment."""
        config = {
            "max_normalized_regression": self.max_normalized_regression,
            "min_valid": self.min_valid,
            "min_pass_fraction": self.min_pass_fraction,
            "configured_min_pairs": self.configured_min_pairs,
            "confidence_level": self.confidence_level,
            "bootstrap_samples": self.bootstrap_samples,
            "min_effect_size": self.min_effect_size,
            "max_single_pair_regression": self.max_single_pair_regression,
            "score_scale_floor": self.score_scale_floor,
            "require_artifacts": self.require_artifacts,
        }
        if self.experiment_alpha is not None:
            config["experiment_alpha"] = self.experiment_alpha
        return config

    @staticmethod
    def _journal_scores(
        journal: Any,
        *,
        artifact_root: Path | None = None,
        require_artifacts: bool = False,
        expected_identity: dict[str, Any] | None = None,
    ) -> tuple[list[float], bool, bool]:
        maximize = (
            True
            if getattr(journal, "metric_maximize", None) is None
            else bool(journal.metric_maximize)
        )
        values: list[float] = []
        all_trusted = True
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
                all_trusted = all_trusted and has_trusted_evaluation(
                    node,
                    maximize=maximize,
                    artifact_root=artifact_root,
                    require_artifacts=require_artifacts,
                )
                if expected_identity:
                    outer_provenance = getattr(node, "rsi_provenance", {}) or {}
                    attested_provenance = getattr(node, "provenance", {}) or {}
                    all_trusted = all_trusted and all(
                        (
                            attested_provenance.get(key)
                            if key in attested_provenance
                            else outer_provenance.get(key)
                        )
                        == value
                        for key, value in expected_identity.items()
                    )
                values.append(v)
        return values, maximize, all_trusted

    def evaluate_pair(
        self, candidate_journal: Any, incumbent_journal: Any
    ) -> CanaryResult:
        if self.promotion_block_reason:
            return CanaryResult(
                False, None, None, -math.inf, self.promotion_block_reason
            )
        cvals, cmax, ctrusted = self._journal_scores(
            candidate_journal,
            artifact_root=self.artifact_root,
            require_artifacts=self.require_artifacts,
            expected_identity=self.expected_evaluation_identity,
        )
        ivals, imax, itrusted = self._journal_scores(
            incumbent_journal,
            artifact_root=self.artifact_root,
            require_artifacts=self.require_artifacts,
            expected_identity=self.expected_evaluation_identity,
        )
        if not ctrusted or not itrusted:
            return CanaryResult(
                False,
                None,
                None,
                -math.inf,
                "canary requires HMAC-attested trusted external evaluator records",
            )
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
                None,
                "no paired canary repetitions",
                results,
                None,
                self.sequential_alpha,
                self.promotion_attempt_index,
            )
        pass_fraction = sum(1 for r in results if r.passed) / len(results)
        deltas = [r.normalized_delta for r in results]
        med_delta = median(deltas)
        cvals = [r.candidate_best for r in results if r.candidate_best is not None]
        ivals = [r.incumbent_best for r in results if r.incumbent_best is not None]
        cmed = median(cvals) if cvals else None
        imed = median(ivals) if ivals else None
        finite_deltas = all(math.isfinite(delta) for delta in deltas)
        sign_test_p_value = None
        if finite_deltas:
            positive_pairs = sum(delta > 0.0 for delta in deltas)
            sign_test_p_value = sum(
                math.comb(len(deltas), k)
                for k in range(positive_pairs, len(deltas) + 1)
            ) / (2 ** len(deltas))
        lower_bound = None
        if finite_deltas and len(deltas) >= self.min_pairs:
            rng = random.Random(0)
            bootstrap_means = sorted(
                mean(rng.choices(deltas, k=len(deltas)))
                for _ in range(self.bootstrap_samples)
            )
            lower_index = int(
                (1.0 - self.confidence_level) * (self.bootstrap_samples - 1)
            )
            lower_bound = bootstrap_means[lower_index]
        enough_pairs = len(deltas) >= self.min_pairs
        worst_pair_ok = (
            finite_deltas and min(deltas) >= -self.max_single_pair_regression
        )
        pass_fraction_ok = pass_fraction >= self.min_pass_fraction
        effect_ok = med_delta >= self.min_effect_size
        confidence_ok = (
            lower_bound is not None and lower_bound >= -self.max_normalized_regression
        )
        sequential_alpha_ok = self.sequential_alpha is None or (
            sign_test_p_value is not None and sign_test_p_value <= self.sequential_alpha
        )
        passed = (
            enough_pairs
            and worst_pair_ok
            and pass_fraction_ok
            and effect_ok
            and confidence_ok
            and sequential_alpha_ok
        )
        if passed:
            reason = "paired canary passed bootstrap non-inferiority gate"
        elif not enough_pairs:
            reason = "too few paired canary repetitions for confidence gate"
        elif not finite_deltas:
            reason = "one or more canary pairs lack trusted valid outcomes"
        elif not worst_pair_ok:
            reason = "worst paired canary regression exceeded limit"
        elif not pass_fraction_ok:
            reason = "too few paired canary repetitions passed"
        elif not effect_ok:
            reason = "median paired canary effect did not meet minimum"
        elif not confidence_ok:
            reason = "bootstrap confidence bound did not meet regression margin"
        elif not sequential_alpha_ok:
            reason = "paired sign test exceeded the experiment alpha-spending budget"
        else:
            reason = "median paired canary regression exceeded limit"
        return CanarySeriesResult(
            passed,
            pass_fraction,
            med_delta,
            cmed,
            imed,
            lower_bound,
            reason,
            results,
            sign_test_p_value,
            self.sequential_alpha,
            self.promotion_attempt_index,
        )
