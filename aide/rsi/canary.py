from __future__ import annotations

import math
import random
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any

from .evidence import has_trusted_evaluation
from .statistics import (
    MAX_PROMOTION_ATTEMPTS,
    MULTITASK_MIN_RUNS_PER_TASK,
    MULTITASK_PROTOCOL_ID,
    SPENDING_RULE_ID,
    SPENDING_RULE_VERSION,
    CanaryPanel,
    effect_is_positive,
    exact_sign_min_pairs,
    multitask_protocol_config,
    multitask_protocol_sha256,
    sequential_alpha,
    task_effect_decision,
)


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
    sequential_alpha_rule_id: str | None = None
    sequential_alpha_rule_version: int | None = None

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
            "sequential_alpha_rule_id": self.sequential_alpha_rule_id,
            "sequential_alpha_rule_version": self.sequential_alpha_rule_version,
            "reason": self.reason,
            "pairs": [asdict(x) for x in self.pairs],
        }


@dataclass(frozen=True)
class TaskCanaryEffect:
    task_id: str
    task_family: str
    task_stratum: str
    runs: int
    median_normalized_effect: float
    positive: bool
    pair_results: tuple[CanaryResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_family": self.task_family,
            "task_stratum": self.task_stratum,
            "runs": self.runs,
            "median_normalized_effect": self.median_normalized_effect,
            "positive": self.positive,
            "pair_results": [asdict(result) for result in self.pair_results],
        }


@dataclass(frozen=True)
class TaskFamilyCanaryEffect:
    """One inference unit after aggregating all correlated tasks in a family."""

    task_family: str
    task_stratum: str
    task_count: int
    median_normalized_effect: float
    positive: bool
    task_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MultiTaskCanaryResult:
    passed: bool
    panel_sha256: str
    protocol_sha256: str
    promotion_attempt_index: int
    allocated_alpha: float
    p_value: float | None
    median_task_effect: float | None
    worst_task_effect: float | None
    positive_tasks: int
    total_tasks: int
    reason: str
    task_effects: tuple[TaskCanaryEffect, ...]
    critical_positive_families: int | None = None
    positive_families: int = 0
    total_families: int = 0
    median_family_effect: float | None = None
    family_effects: tuple[TaskFamilyCanaryEffect, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "panel_sha256": self.panel_sha256,
            "protocol_id": MULTITASK_PROTOCOL_ID,
            "protocol_sha256": self.protocol_sha256,
            "promotion_attempt_index": self.promotion_attempt_index,
            "allocated_alpha": self.allocated_alpha,
            "p_value": self.p_value,
            "median_task_effect": self.median_task_effect,
            "worst_task_effect": self.worst_task_effect,
            "positive_tasks": self.positive_tasks,
            "total_tasks": self.total_tasks,
            "critical_positive_families": self.critical_positive_families,
            "positive_families": self.positive_families,
            "total_families": self.total_families,
            "median_family_effect": self.median_family_effect,
            "reason": self.reason,
            "task_effects": [effect.to_dict() for effect in self.task_effects],
            "family_effects": [effect.to_dict() for effect in self.family_effects],
        }


class TaskClusteredCanaryGate:
    """Promotion gate whose independent evidence units are task families.

    Replicate results are reduced to one median effect per task before the
    family median; only independent family effects enter the exact sign test.
    Ties count as non-wins and every panel task must produce the predeclared
    number of trusted paired runs.
    """

    def __init__(
        self,
        *,
        panel: CanaryPanel,
        pair_gates: dict[str, RealCanaryGate],
        promotion_attempt_index: int,
        family_alpha: float,
        allocated_alpha: float,
        min_effect_size: float,
        max_task_regression: float,
    ):
        if set(pair_gates) != set(panel.task_ids):
            raise ValueError("pair evaluator gates must exactly match panel tasks")
        pair_policies = [gate.policy_config() for gate in pair_gates.values()]
        if any(policy != pair_policies[0] for policy in pair_policies[1:]):
            raise ValueError("all task pair gates must use the same fixed protocol")
        self.pair_gate_policy = pair_policies[0]
        if (
            isinstance(promotion_attempt_index, bool)
            or not isinstance(promotion_attempt_index, int)
            or promotion_attempt_index < 1
        ):
            raise ValueError("promotion attempt index must be positive")
        expected_protocol_sha256 = multitask_protocol_sha256(
            family_alpha,
            min_effect_size,
            max_task_regression,
            pair_gate_policy=self.pair_gate_policy,
        )
        expected_allocation = sequential_alpha(family_alpha, promotion_attempt_index)
        if (
            not math.isfinite(allocated_alpha)
            or not 0 < allocated_alpha < 1
            or not math.isclose(allocated_alpha, expected_allocation, rel_tol=1e-12)
            or not math.isfinite(min_effect_size)
            or not math.isfinite(max_task_regression)
            or max_task_regression < 0
        ):
            raise ValueError(
                "invalid multi-task promotion thresholds or allocated alpha"
            )
        if panel.protocol_sha256 != expected_protocol_sha256:
            raise ValueError("canary panel protocol does not match gate parameters")
        self.panel = panel
        self.pair_gates = dict(pair_gates)
        self.promotion_attempt_index = promotion_attempt_index
        self.family_alpha = float(family_alpha)
        self.allocated_alpha = float(allocated_alpha)
        self.min_effect_size = float(min_effect_size)
        self.max_task_regression = float(max_task_regression)

    def authority_config(self) -> dict[str, Any]:
        return {
            "protocol_id": MULTITASK_PROTOCOL_ID,
            "protocol": multitask_protocol_config(
                self.family_alpha,
                self.min_effect_size,
                self.max_task_regression,
                pair_gate_policy=self.pair_gate_policy,
            ),
            "protocol_sha256": self.panel.protocol_sha256,
            "panel": self.panel.to_dict(),
            "panel_sha256": self.panel.panel_sha256,
            "promotion_attempt_index": self.promotion_attempt_index,
            "allocated_alpha": self.allocated_alpha,
            "min_effect_size": self.min_effect_size,
            "max_task_regression": self.max_task_regression,
            "task_pair_gate_configs": {
                task_id: self.pair_gates[task_id].authority_config()
                for task_id in self.panel.task_ids
            },
        }

    def policy_config(self) -> dict[str, Any]:
        """Static rule and task authority pinned for the statistical epoch."""
        return {
            "protocol_id": MULTITASK_PROTOCOL_ID,
            "protocol": multitask_protocol_config(
                self.family_alpha,
                self.min_effect_size,
                self.max_task_regression,
                pair_gate_policy=self.pair_gate_policy,
            ),
            "protocol_sha256": self.panel.protocol_sha256,
            "pair_gate_policy": self.pair_gate_policy,
        }

    def evaluate_panel(
        self,
        task_pairs: dict[str, Iterable[tuple[Any, Any]]],
    ) -> MultiTaskCanaryResult:
        if set(task_pairs) != set(self.panel.task_ids):
            return MultiTaskCanaryResult(
                False,
                self.panel.panel_sha256,
                self.panel.protocol_sha256,
                self.promotion_attempt_index,
                self.allocated_alpha,
                None,
                None,
                None,
                0,
                len(task_pairs),
                "canary task result set does not match the reserved panel",
                (),
            )
        task_definitions = {task.task_id: task for task in self.panel.tasks}
        effects: list[TaskCanaryEffect] = []
        invalid = False
        for task_id in self.panel.task_ids:
            definition = task_definitions[task_id]
            results = tuple(
                self.pair_gates[task_id].evaluate_pair(candidate, incumbent)
                for candidate, incumbent in task_pairs[task_id]
            )
            if (
                len(results) != len(definition.replicate_ids)
                or len(results) < MULTITASK_MIN_RUNS_PER_TASK
            ):
                invalid = True
                continue
            deltas = [result.normalized_delta for result in results]
            if not all(math.isfinite(delta) for delta in deltas):
                invalid = True
                continue
            task_effect = float(median(deltas))
            effects.append(
                TaskCanaryEffect(
                    task_id,
                    definition.task_family,
                    definition.task_stratum,
                    len(results),
                    task_effect,
                    effect_is_positive(task_effect, self.min_effect_size),
                    results,
                )
            )
        if invalid or len(effects) != len(self.panel.tasks):
            return MultiTaskCanaryResult(
                False,
                self.panel.panel_sha256,
                self.panel.protocol_sha256,
                self.promotion_attempt_index,
                self.allocated_alpha,
                None,
                None,
                None,
                sum(effect.positive for effect in effects),
                len(effects),
                "every reserved task needs all trusted paired runs",
                tuple(effects),
            )
        family_tasks: dict[str, list[TaskCanaryEffect]] = {}
        for effect in effects:
            family_tasks.setdefault(effect.task_family, []).append(effect)
        family_effects = tuple(
            TaskFamilyCanaryEffect(
                task_family=family,
                task_stratum=members[0].task_stratum,
                task_count=len(members),
                median_normalized_effect=float(
                    median(member.median_normalized_effect for member in members)
                ),
                positive=effect_is_positive(
                    float(
                        median(member.median_normalized_effect for member in members)
                    ),
                    self.min_effect_size,
                ),
                task_ids=tuple(sorted(member.task_id for member in members)),
            )
            for family, members in sorted(family_tasks.items())
        )
        family_effect_values = [
            effect.median_normalized_effect for effect in family_effects
        ]
        decision = task_effect_decision(
            family_effect_values,
            allocated_alpha=self.allocated_alpha,
            minimum_practical_effect=self.min_effect_size,
            maximum_task_regression=self.max_task_regression,
        )
        worst_task_effect = min(effect.median_normalized_effect for effect in effects)
        task_regression_safe = worst_task_effect >= -self.max_task_regression
        passed = decision["passed"] and task_regression_safe
        reason = decision["reason"]
        if decision["passed"] and not task_regression_safe:
            reason = "worst-task regression exceeded the panel safety limit"
        return MultiTaskCanaryResult(
            passed,
            self.panel.panel_sha256,
            self.panel.protocol_sha256,
            self.promotion_attempt_index,
            self.allocated_alpha,
            decision["p_value"],
            float(median(effect.median_normalized_effect for effect in effects)),
            worst_task_effect,
            sum(effect.positive for effect in effects),
            len(effects),
            reason,
            tuple(effects),
            critical_positive_families=decision["critical_positive_independent_units"],
            positive_families=decision["positive_independent_units"],
            total_families=decision["total_independent_units"],
            median_family_effect=decision["median_independent_unit_effect"],
            family_effects=family_effects,
        )


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
                or not 1 <= promotion_attempt_index <= MAX_PROMOTION_ATTEMPTS
            ):
                raise ValueError(
                    "promotion_attempt_index is outside the fixed protocol horizon"
                )
            experiment_alpha = float(experiment_alpha)
            if not math.isfinite(experiment_alpha) or not 0 < experiment_alpha < 1:
                raise ValueError("experiment_alpha must be finite and in (0, 1)")
            self.promotion_attempt_index = promotion_attempt_index
            self.experiment_alpha = experiment_alpha
            self.sequential_alpha = sequential_alpha(
                experiment_alpha, promotion_attempt_index
            )
            required_pairs = exact_sign_min_pairs(self.sequential_alpha)
            self.min_pairs = max(self.min_pairs, required_pairs)

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
                sequential_alpha_rule_id=SPENDING_RULE_ID,
                sequential_alpha_rule_version=SPENDING_RULE_VERSION,
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
                SPENDING_RULE_ID if self.promotion_attempt_index is not None else None,
                (
                    SPENDING_RULE_VERSION
                    if self.promotion_attempt_index is not None
                    else None
                ),
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
            SPENDING_RULE_ID if self.promotion_attempt_index is not None else None,
            SPENDING_RULE_VERSION if self.promotion_attempt_index is not None else None,
        )
