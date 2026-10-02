"""Authenticated experiment-wide alpha-spending budget primitives."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from statistics import median
from typing import Any

SPENDING_RULE_ID = "finite-horizon-bonferroni"
SPENDING_RULE_VERSION = 1
MAX_PROMOTION_ATTEMPTS = 500
_MAX_ATTEMPTS = MAX_PROMOTION_ATTEMPTS
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

MULTITASK_PROTOCOL_ID = "MULTITASK_PROMOTION_PROTOCOL_V5"
MULTITASK_PROTOCOL_VERSION = 5
MULTITASK_MIN_TASKS = 40
MULTITASK_MIN_INDEPENDENT_FAMILIES = 40
MULTITASK_MIN_STRATA = 3
MULTITASK_MIN_FAMILIES_PER_STRATUM = 3
MULTITASK_MIN_RUNS_PER_TASK = 4
SIGN_TIE_ABS_TOLERANCE = 1e-12
MULTITASK_PROTOCOL = {
    "protocol_id": MULTITASK_PROTOCOL_ID,
    "version": MULTITASK_PROTOCOL_VERSION,
    "primary_unit": "independent_task_family_cluster",
    "within_task_estimator": "median_normalized_paired_effect",
    "within_family_estimator": "median_task_effect",
    "ties": "count_as_non_wins",
    "tie_absolute_tolerance": SIGN_TIE_ABS_TOLERANCE,
    "family_weighting": "equal",
    "minimum_tasks": MULTITASK_MIN_TASKS,
    "minimum_independent_task_families": MULTITASK_MIN_INDEPENDENT_FAMILIES,
    "minimum_task_strata": MULTITASK_MIN_STRATA,
    "minimum_families_per_stratum": MULTITASK_MIN_FAMILIES_PER_STRATUM,
    "maximum_family_stratum_share": 0.5,
    "minimum_runs_per_task": MULTITASK_MIN_RUNS_PER_TASK,
    "replicate_seed_schedule": "paired_within_task; disjoint_across_family_clusters; provider_rng_may_be_uncontrolled",
    "execution_order_schedule": "four_runs_per_task; canonical_task_order; replicate_ids_do_not_select_order; per_task_ABBA_or_BAAB_exact_balance; family_and_global_first_side_exact_balance",
    "test": "one_sided_exact_binomial_sign_test",
    "alpha_spending_rule_id": SPENDING_RULE_ID,
    "alpha_spending_rule_version": SPENDING_RULE_VERSION,
    "promotion_attempt_horizon": MAX_PROMOTION_ATTEMPTS,
    "alpha_allocation": "family_alpha / promotion_attempt_horizon",
    "family_alpha": 0.05,
    "minimum_practical_effect": 0.0,
    "maximum_task_regression": 0.25,
    "pair_effect_normalization": "incumbent_relative_with_fixed_score_floor",
    "invalid_pair": "fail_closed",
}


def multitask_protocol_config(
    family_alpha: float = 0.05,
    min_effect_size: float = 0.0,
    max_task_regression: float = 0.25,
    pair_gate_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    values = {
        **MULTITASK_PROTOCOL,
        "family_alpha": float(family_alpha),
        "minimum_practical_effect": float(min_effect_size),
        "maximum_task_regression": float(max_task_regression),
        "pair_gate_policy": dict(pair_gate_policy or {}),
    }
    if (
        not math.isfinite(values["family_alpha"])
        or not 0 < values["family_alpha"] < 1
        or not math.isfinite(values["minimum_practical_effect"])
        or not math.isfinite(values["maximum_task_regression"])
        or values["maximum_task_regression"] < 0
    ):
        raise ValueError("invalid multi-task protocol parameters")
    return values


def multitask_protocol_sha256(
    family_alpha: float = 0.05,
    min_effect_size: float = 0.0,
    max_task_regression: float = 0.25,
    pair_gate_policy: dict[str, Any] | None = None,
) -> str:
    payload = json.dumps(
        multitask_protocol_config(
            family_alpha, min_effect_size, max_task_regression, pair_gate_policy
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


MULTITASK_PROTOCOL_SHA256 = multitask_protocol_sha256()


def statistical_epoch_sha256(family_alpha: float, protocol_sha256: str) -> str:
    """Identify one immutable protocol, alpha, and spending-rule epoch."""
    alpha = float(family_alpha)
    _require_sha256(protocol_sha256, "statistical protocol digest")
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("family alpha must be finite and in (0, 1)")
    return _canonical_digest(
        {
            "domain": "aide-rsi-statistical-epoch/v2",
            "protocol_sha256": protocol_sha256,
            "family_alpha": alpha,
            "spending_rule_id": SPENDING_RULE_ID,
            "spending_rule_version": SPENDING_RULE_VERSION,
            "promotion_attempt_horizon": MAX_PROMOTION_ATTEMPTS,
        }
    )


def sequential_alpha(family_alpha: float, attempt_index: int) -> float:
    """Return the fixed Bonferroni allocation for a precommitted 500-attempt epoch."""
    alpha = float(family_alpha)
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("family alpha must be finite and in (0, 1)")
    if (
        isinstance(attempt_index, bool)
        or not isinstance(attempt_index, int)
        or not 1 <= attempt_index <= MAX_PROMOTION_ATTEMPTS
    ):
        raise ValueError(
            f"attempt index must be an integer in [1, {MAX_PROMOTION_ATTEMPTS}]"
        )
    return alpha / MAX_PROMOTION_ATTEMPTS


def exact_sign_min_pairs(alpha: float) -> int:
    """Smallest n for which the one-sided all-positive sign-test p-value fits alpha."""
    value = float(alpha)
    if not math.isfinite(value) or not 0 < value < 1:
        raise ValueError("attempt alpha must be finite and in (0, 1)")
    pairs = max(1, math.ceil(math.log2(1.0 / value)))
    while 2.0**-pairs > value:
        pairs += 1
    return pairs


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _require_sha256(value: Any, name: str, *, allow_none: bool = False) -> None:
    if allow_none and value is None:
        return
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class CanaryPanelTask:
    """Identity and fixed run schedule for one independent canary task."""

    task_id: str
    task_family: str
    task_stratum: str
    task_sha256: str
    evaluator_authority_sha256: str
    shard_sha256: str
    dataset_sha256: str
    split_sha256: str
    metric_id: str
    metric_maximize: bool
    sample_ids: tuple[str, ...]
    public_input_sha256: tuple[str, ...]
    sample_content_sha256: tuple[str, ...]
    replicate_ids: tuple[int, ...]
    replicate_seeds: tuple[int, ...]
    budget_per_run: int
    public_data_sha256: str

    def __post_init__(self) -> None:
        for name in ("task_id", "task_family", "task_stratum", "metric_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"canary panel {name} must be nonempty")
        for name in (
            "task_sha256",
            "evaluator_authority_sha256",
            "shard_sha256",
            "dataset_sha256",
            "split_sha256",
            "public_data_sha256",
        ):
            _require_sha256(getattr(self, name), f"canary panel {name}")
        if not isinstance(self.metric_maximize, bool):
            raise TypeError("canary panel metric direction must be boolean")
        if (
            not self.sample_ids
            or any(not isinstance(value, str) or not value for value in self.sample_ids)
            or len(set(self.sample_ids)) != len(self.sample_ids)
        ):
            raise ValueError("canary panel sample IDs must be nonempty and unique")
        if not self.replicate_ids or len(set(self.replicate_ids)) != len(
            self.replicate_ids
        ):
            raise ValueError("canary panel replicate IDs must be nonempty and unique")
        if len(self.replicate_ids) != MULTITASK_MIN_RUNS_PER_TASK:
            raise ValueError(
                f"each canary task needs exactly {MULTITASK_MIN_RUNS_PER_TASK} paired runs"
            )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in self.replicate_ids
        ):
            raise ValueError("canary panel replicate IDs must be nonnegative integers")
        if (
            tuple(sorted(self.replicate_ids)) != self.replicate_ids
            or len(self.replicate_seeds) != len(self.replicate_ids)
            or len(set(self.replicate_seeds)) != len(self.replicate_seeds)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in self.replicate_seeds
            )
        ):
            raise ValueError(
                "canary panel requires a sorted, unique fixed seed for each replicate"
            )
        if (
            isinstance(self.budget_per_run, bool)
            or not isinstance(self.budget_per_run, int)
            or self.budget_per_run < 1
        ):
            raise ValueError("canary panel run budget must be a positive integer")
        for name in ("public_input_sha256", "sample_content_sha256"):
            values = getattr(self, name)
            if not values or len(set(values)) != len(values):
                raise ValueError(f"canary panel {name} must be nonempty and unique")
            if len(values) != len(self.sample_ids):
                raise ValueError(f"canary panel {name} must cover every sample ID")
            for value in values:
                _require_sha256(value, f"canary panel {name} entry")

    def to_dict(self) -> dict[str, Any]:
        # Keep each row's ID and identities associated in the canonical panel.
        # Sorting the three arrays independently would make the digest invariant
        # to swapping content hashes between different sample IDs.
        sample_order = sorted(
            range(len(self.sample_ids)), key=lambda index: self.sample_ids[index]
        )
        return {
            **asdict(self),
            "sample_ids": [self.sample_ids[index] for index in sample_order],
            "public_input_sha256": [
                self.public_input_sha256[index] for index in sample_order
            ],
            "sample_content_sha256": [
                self.sample_content_sha256[index] for index in sample_order
            ],
            "replicate_ids": list(self.replicate_ids),
            "replicate_seeds": list(self.replicate_seeds),
        }

    def seed_for(self, replicate_id: int) -> int:
        try:
            index = self.replicate_ids.index(replicate_id)
        except ValueError as exc:
            raise KeyError(replicate_id) from exc
        return self.replicate_seeds[index]


@dataclass(frozen=True)
class CanaryPanel:
    """Immutable, content-addressed, pre-observation multi-task canary panel."""

    epoch: int
    tasks: tuple[CanaryPanelTask, ...]
    protocol_sha256: str = MULTITASK_PROTOCOL_SHA256

    def __post_init__(self) -> None:
        if (
            isinstance(self.epoch, bool)
            or not isinstance(self.epoch, int)
            or self.epoch < 0
        ):
            raise ValueError("canary panel epoch must be a nonnegative integer")
        _require_sha256(self.protocol_sha256, "statistical protocol digest")
        if len(self.tasks) < MULTITASK_MIN_TASKS:
            raise ValueError(
                f"canary panel requires at least {MULTITASK_MIN_TASKS} task records"
            )
        task_ids = [task.task_id for task in self.tasks]
        task_digests = [task.task_sha256 for task in self.tasks]
        if len(set(task_ids)) != len(task_ids) or len(set(task_digests)) != len(
            task_digests
        ):
            raise ValueError("canary panel task IDs and identities must be unique")
        family_strata: dict[str, str] = {}
        for task in self.tasks:
            previous_stratum = family_strata.setdefault(
                task.task_family, task.task_stratum
            )
            if previous_stratum != task.task_stratum:
                raise ValueError(
                    "tasks in one independent family must use the same stratum"
                )
        seed_families: dict[int, str] = {}
        for task in self.tasks:
            for seed in task.replicate_seeds:
                previous_family = seed_families.setdefault(seed, task.task_family)
                if previous_family != task.task_family:
                    raise ValueError(
                        "replicate seeds must not be shared across independent task families"
                    )
        stratum_counts: dict[str, int] = {}
        for task_stratum in family_strata.values():
            stratum_counts[task_stratum] = stratum_counts.get(task_stratum, 0) + 1
        if len(family_strata) < MULTITASK_MIN_INDEPENDENT_FAMILIES:
            raise ValueError(
                "canary panel requires at least "
                f"{MULTITASK_MIN_INDEPENDENT_FAMILIES} independent task-family clusters"
            )
        if len(stratum_counts) < MULTITASK_MIN_STRATA:
            raise ValueError(
                f"canary panel requires at least {MULTITASK_MIN_STRATA} task strata"
            )
        if min(stratum_counts.values()) < MULTITASK_MIN_FAMILIES_PER_STRATUM:
            raise ValueError(
                "canary panel requires at least "
                f"{MULTITASK_MIN_FAMILIES_PER_STRATUM} independent families "
                "in every represented stratum"
            )
        if max(stratum_counts.values()) > len(family_strata) / 2:
            raise ValueError("no task stratum may exceed half the family clusters")
        public_hashes: set[str] = set()
        full_hashes: set[str] = set()
        for task in self.tasks:
            task_public = set(task.public_input_sha256)
            task_full = set(task.sample_content_sha256)
            if public_hashes.intersection(task_public):
                raise ValueError(
                    "canary panel tasks duplicate candidate-visible sample content"
                )
            if full_hashes.intersection(task_full):
                raise ValueError("canary panel tasks duplicate full sample content")
            public_hashes.update(task_public)
            full_hashes.update(task_full)

    def body(self) -> dict[str, Any]:
        return {
            "protocol_id": MULTITASK_PROTOCOL_ID,
            "protocol_version": MULTITASK_PROTOCOL_VERSION,
            "protocol_sha256": self.protocol_sha256,
            "epoch": self.epoch,
            "tasks": [
                task.to_dict() for task in sorted(self.tasks, key=lambda t: t.task_id)
            ],
        }

    @property
    def panel_sha256(self) -> str:
        return _canonical_digest(self.body())

    @property
    def task_ids(self) -> tuple[str, ...]:
        return tuple(
            task.task_id for task in sorted(self.tasks, key=lambda t: t.task_id)
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "panel_sha256": self.panel_sha256}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CanaryPanel:
        if not isinstance(value, dict):
            raise TypeError("canary panel must be an object")
        if set(value) != {
            "protocol_id",
            "protocol_version",
            "protocol_sha256",
            "epoch",
            "tasks",
            "panel_sha256",
        }:
            raise ValueError("canary panel fields are invalid")
        if (
            value["protocol_id"] != MULTITASK_PROTOCOL_ID
            or value["protocol_version"] != MULTITASK_PROTOCOL_VERSION
        ):
            raise ValueError("canary panel statistical protocol is unsupported")
        if not isinstance(value["tasks"], list):
            raise TypeError("canary panel tasks must be a list")
        tasks = []
        for task in value["tasks"]:
            if not isinstance(task, dict):
                raise TypeError("canary panel task must be an object")
            task_value = dict(task)
            for name in (
                "sample_ids",
                "public_input_sha256",
                "sample_content_sha256",
                "replicate_ids",
                "replicate_seeds",
            ):
                if not isinstance(task_value.get(name), list):
                    raise TypeError(f"canary panel task {name} must be a list")
                task_value[name] = tuple(task_value[name])
            tasks.append(CanaryPanelTask(**task_value))
        result = cls(
            epoch=value["epoch"],
            tasks=tuple(tasks),
            protocol_sha256=value["protocol_sha256"],
        )
        if value["panel_sha256"] != result.panel_sha256:
            raise ValueError("canary panel digest mismatch")
        return result


def canary_execution_schedule(panel: CanaryPanel) -> tuple[dict[str, Any], ...]:
    """Build the canonical, globally and family-balanced paired run schedule.

    Replicate IDs label stored run records only. Execution order is determined
    by canonical task order and replicate ordinal. Four paired runs use an
    exact ABBA or BAAB first-side sequence, balancing each task and cancelling
    constant first/second-position effects in the median task effect.
    """
    task_records = sorted(
        panel.tasks, key=lambda task: (task.task_id, task.task_sha256)
    )
    family_indices = {
        family: index
        for index, family in enumerate(
            sorted({task.task_family for task in task_records})
        )
    }
    family_first_counts: dict[str, list[int]] = {}
    schedule: list[dict[str, Any]] = []
    for task_index, task in enumerate(task_records):
        counts = family_first_counts.setdefault(task.task_family, [0, 0])
        challenger_first_pattern = (
            "challenger",
            "incumbent",
            "incumbent",
            "challenger",
        )
        incumbent_first_pattern = ("incumbent", "challenger", "challenger", "incumbent")
        first_sides = (
            challenger_first_pattern
            if (family_indices[task.task_family] + task_index) % 2 == 0
            else incumbent_first_pattern
        )
        for ordinal, (replicate_id, seed, first_side) in enumerate(
            zip(task.replicate_ids, task.replicate_seeds, first_sides, strict=True)
        ):
            second_side = "incumbent" if first_side == "challenger" else "challenger"
            schedule.append(
                {
                    "task_id": task.task_id,
                    "task_sha256": task.task_sha256,
                    "task_family": task.task_family,
                    "replicate_ordinal": ordinal,
                    "replicate_id": replicate_id,
                    "seed": seed,
                    "order": [first_side, second_side],
                }
            )
            if first_side == "challenger":
                counts[0] += 1
            else:
                counts[1] += 1
    challenger_first_count = sum(counts[0] for counts in family_first_counts.values())
    incumbent_first_count = sum(counts[1] for counts in family_first_counts.values())
    if challenger_first_count != incumbent_first_count:
        raise AssertionError(
            "canonical canary execution schedule is not exactly balanced"
        )
    if any(counts[0] != counts[1] for counts in family_first_counts.values()):
        raise AssertionError("canonical canary family schedule is not exactly balanced")
    return tuple(schedule)


@dataclass(frozen=True)
class StatisticalBudget:
    """Monotonic alpha allocation state stored inside authenticated RSI state.

    Reservations spend alpha before the first authoritative canary evaluation.
    An aborted or interrupted attempt therefore cannot return its allocation.
    ``history_digest`` commits each reservation to the prior budget state.
    """

    family_alpha: float
    attempt_index: int
    spent_alpha: float
    remaining_alpha: float
    last_allocation: float
    spending_rule_id: str
    spending_rule_version: int
    history_digest: str
    panel_sha256: str | None = None
    protocol_sha256: str | None = None
    max_attempts: int = MAX_PROMOTION_ATTEMPTS

    @classmethod
    def initial(cls, family_alpha: float) -> StatisticalBudget:
        alpha = float(family_alpha)
        if not math.isfinite(alpha) or not 0 < alpha < 1:
            raise ValueError("family alpha must be finite and in (0, 1)")
        genesis = _canonical_digest(
            {
                "domain": "aide-rsi-statistical-budget/v2",
                "family_alpha": alpha,
                "spending_rule_id": SPENDING_RULE_ID,
                "spending_rule_version": SPENDING_RULE_VERSION,
                "max_attempts": MAX_PROMOTION_ATTEMPTS,
            }
        )
        return cls(
            family_alpha=alpha,
            attempt_index=0,
            spent_alpha=0.0,
            remaining_alpha=alpha,
            last_allocation=0.0,
            spending_rule_id=SPENDING_RULE_ID,
            spending_rule_version=SPENDING_RULE_VERSION,
            history_digest=genesis,
            panel_sha256=None,
            protocol_sha256=None,
            max_attempts=MAX_PROMOTION_ATTEMPTS,
        )

    @classmethod
    def migrate_legacy(
        cls, family_alpha: float, legacy_attempt_index: int
    ) -> StatisticalBudget:
        """Initialize only pristine legacy runs under the new statistical epoch.

        Existing attempts were tested under a different protocol. Carrying them
        into a new epoch would make the family-wise error claim ambiguous, so a
        nonzero legacy counter must be resolved by starting a fresh experiment.
        """
        if (
            isinstance(legacy_attempt_index, bool)
            or not isinstance(legacy_attempt_index, int)
            or not 0 <= legacy_attempt_index <= _MAX_ATTEMPTS
        ):
            raise ValueError("legacy attempt index is invalid")
        if legacy_attempt_index != 0:
            raise ValueError(
                "legacy statistical attempts require a fresh statistical epoch"
            )
        return cls.initial(family_alpha)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StatisticalBudget:
        if not isinstance(value, dict):
            raise TypeError("statistical budget must be an object")
        expected_keys = set(cls.__dataclass_fields__)
        if set(value) != expected_keys:
            raise ValueError("statistical budget fields are invalid")
        try:
            result = cls(**value)
        except TypeError as exc:
            raise ValueError("statistical budget fields are invalid") from exc
        result.validate()
        return result

    def validate(self) -> None:
        if (
            isinstance(self.family_alpha, bool)
            or not isinstance(self.family_alpha, (int, float))
            or not math.isfinite(self.family_alpha)
            or not 0 < self.family_alpha < 1
        ):
            raise ValueError("statistical budget family alpha is invalid")
        if (
            isinstance(self.attempt_index, bool)
            or not isinstance(self.attempt_index, int)
            or not 0 <= self.attempt_index <= _MAX_ATTEMPTS
        ):
            raise ValueError("statistical budget attempt index is invalid")
        if (
            self.spending_rule_id != SPENDING_RULE_ID
            or isinstance(self.spending_rule_version, bool)
            or not isinstance(self.spending_rule_version, int)
            or self.spending_rule_version != SPENDING_RULE_VERSION
        ):
            raise ValueError("statistical budget spending rule is unsupported")
        if (
            isinstance(self.max_attempts, bool)
            or not isinstance(self.max_attempts, int)
            or self.max_attempts != MAX_PROMOTION_ATTEMPTS
        ):
            raise ValueError("statistical budget attempt horizon is unsupported")
        if not isinstance(self.history_digest, str) or not _SHA256_RE.fullmatch(
            self.history_digest
        ):
            raise ValueError("statistical budget history digest is invalid")
        _require_sha256(
            self.panel_sha256, "statistical budget panel digest", allow_none=True
        )
        _require_sha256(
            self.protocol_sha256, "statistical budget protocol digest", allow_none=True
        )
        if (self.panel_sha256 is None) != (self.protocol_sha256 is None):
            raise ValueError("statistical budget panel and protocol must be paired")

        expected_spent = self.family_alpha * self.attempt_index / self.max_attempts
        expected_remaining = self.family_alpha - expected_spent
        expected_last = (
            0.0
            if self.attempt_index == 0
            else sequential_alpha(self.family_alpha, self.attempt_index)
        )
        for actual, expected in (
            (self.spent_alpha, expected_spent),
            (self.remaining_alpha, expected_remaining),
            (self.last_allocation, expected_last),
        ):
            if (
                isinstance(actual, bool)
                or not isinstance(actual, (int, float))
                or not math.isfinite(actual)
                or not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-15)
            ):
                raise ValueError("statistical budget alpha totals are inconsistent")
        if (
            self.remaining_alpha < -1e-15
            or self.spent_alpha - self.family_alpha > 1e-15
        ):
            raise ValueError("statistical budget exceeds its family alpha")

    def reserve(self, *, panel_sha256: str, protocol_sha256: str) -> StatisticalBudget:
        if self.attempt_index >= _MAX_ATTEMPTS:
            raise ValueError(
                f"statistical budget exhausted after {MAX_PROMOTION_ATTEMPTS} attempts"
            )
        _require_sha256(panel_sha256, "reserved canary panel digest")
        _require_sha256(protocol_sha256, "reserved statistical protocol digest")
        next_index = self.attempt_index + 1
        allocation = sequential_alpha(self.family_alpha, next_index)
        next_spent = self.family_alpha * next_index / self.max_attempts
        next_remaining = self.family_alpha - next_spent
        history = _canonical_digest(
            {
                "domain": "aide-rsi-statistical-budget-reservation/v2",
                "attempt_index": next_index,
                "allocated_alpha": allocation,
                "family_alpha": self.family_alpha,
                "max_attempts": self.max_attempts,
                "spending_rule_id": self.spending_rule_id,
                "spending_rule_version": self.spending_rule_version,
                "previous_history_digest": self.history_digest,
                "panel_sha256": panel_sha256,
                "protocol_sha256": protocol_sha256,
            }
        )
        result = StatisticalBudget(
            family_alpha=self.family_alpha,
            attempt_index=next_index,
            spent_alpha=next_spent,
            remaining_alpha=next_remaining,
            last_allocation=allocation,
            spending_rule_id=self.spending_rule_id,
            spending_rule_version=self.spending_rule_version,
            history_digest=history,
            panel_sha256=panel_sha256,
            protocol_sha256=protocol_sha256,
            max_attempts=self.max_attempts,
        )
        result.validate()
        return result

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return _canonical_digest(self.to_dict())


def task_sign_test(
    task_effects: Iterable[float], *, minimum_practical_effect: float = 0.0
) -> tuple[int, int, float]:
    """Exact one-sided sign test over task effects.

    Effects equal to the predeclared minimum practical effect are ties and count
    as non-wins. The promotion gate calls :func:`independent_unit_sign_test`
    after reducing runs to tasks and tasks to independent family clusters.
    """
    effects = tuple(float(effect) for effect in task_effects)
    threshold = float(minimum_practical_effect)
    if not effects or not math.isfinite(threshold):
        raise ValueError("task sign test requires finite effects and a threshold")
    if not all(math.isfinite(effect) for effect in effects):
        raise ValueError("task sign test effects must all be finite")
    wins = sum(effect - threshold > SIGN_TIE_ABS_TOLERANCE for effect in effects)
    p_value = sum(math.comb(len(effects), k) for k in range(wins, len(effects) + 1)) / (
        2 ** len(effects)
    )
    return wins, len(effects), p_value


def independent_unit_sign_test(
    unit_effects: Iterable[float], *, minimum_practical_effect: float = 0.0
) -> tuple[int, int, float]:
    """Exact one-sided sign test over predeclared independent units."""
    return task_sign_test(
        unit_effects, minimum_practical_effect=minimum_practical_effect
    )


def effect_is_positive(effect: float, threshold: float) -> bool:
    """Treat floating-point-near ties as non-wins under the fixed protocol."""
    value = float(effect)
    floor = float(threshold)
    if not math.isfinite(value) or not math.isfinite(floor):
        raise ValueError("effect and threshold must be finite")
    return value - floor > SIGN_TIE_ABS_TOLERANCE


def exact_sign_critical_wins(task_count: int, alpha: float) -> int | None:
    """Return the minimum positive task effects needed at one-sided alpha."""
    if (
        isinstance(task_count, bool)
        or not isinstance(task_count, int)
        or task_count < 1
    ):
        raise ValueError("task count must be a positive integer")
    value = float(alpha)
    if not math.isfinite(value) or not 0 < value < 1:
        raise ValueError("alpha must be finite and in (0, 1)")
    for wins in range(task_count + 1):
        tail = sum(
            math.comb(task_count, count) for count in range(wins, task_count + 1)
        ) / (2**task_count)
        if tail <= value:
            return wins
    return None


def task_effect_decision(
    unit_effects: Iterable[float],
    *,
    allocated_alpha: float,
    minimum_practical_effect: float,
    maximum_task_regression: float,
) -> dict[str, Any]:
    """Apply the production promotion rule to independent-unit effects."""
    alpha = float(allocated_alpha)
    practical_floor = float(minimum_practical_effect)
    regression_limit = float(maximum_task_regression)
    if (
        not math.isfinite(alpha)
        or not 0 < alpha < 1
        or not math.isfinite(practical_floor)
        or not math.isfinite(regression_limit)
        or regression_limit < 0
    ):
        raise ValueError("invalid task-effect decision thresholds")
    effects = tuple(float(effect) for effect in unit_effects)
    if not effects or not all(math.isfinite(effect) for effect in effects):
        raise ValueError("promotion decision requires finite unit effects")
    wins, total, p_value = independent_unit_sign_test(
        effects, minimum_practical_effect=practical_floor
    )
    median_effect = float(median(effects))
    worst_effect = min(effects)
    critical_wins = exact_sign_critical_wins(total, alpha)
    significant = critical_wins is not None and wins >= critical_wins
    practical = median_effect >= practical_floor
    localized = worst_effect >= -regression_limit
    passed = significant and practical and localized
    if passed:
        reason = "family-clustered canary passed the precommitted sign test"
    elif not significant:
        reason = "independent-unit sign test exceeded the allocated alpha"
    elif not practical:
        reason = "median task effect did not meet the practical improvement threshold"
    else:
        reason = "worst-task regression exceeded the panel safety limit"
    return {
        "passed": passed,
        "positive_independent_units": wins,
        "total_independent_units": total,
        "critical_positive_independent_units": critical_wins,
        "p_value": p_value,
        "median_independent_unit_effect": median_effect,
        "worst_independent_unit_effect": worst_effect,
        "significant": significant,
        "practical": practical,
        "localized_regression_safe": localized,
        "reason": reason,
    }
