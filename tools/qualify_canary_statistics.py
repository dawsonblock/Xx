"""Calibrate the family-clustered canary test under correlated runs and tasks.

This is synthetic statistical calibration. It does not establish independence
or generalization for any real task matrix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aide.rsi.statistics import (
    MULTITASK_MIN_INDEPENDENT_FAMILIES,
    MULTITASK_MIN_TASKS,
    MULTITASK_PROTOCOL_ID,
    MULTITASK_PROTOCOL_SHA256,
    SIGN_TIE_ABS_TOLERANCE,
    StatisticalBudget,
    exact_sign_critical_wins,
    sequential_alpha,
    task_effect_decision,
)

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_FILES = (
    "aide/rsi/canary.py",
    "aide/rsi/evidence.py",
    "aide/rsi/qualification.py",
    "aide/rsi/reference_evaluator.py",
    "aide/rsi/statistics.py",
    "aide/rsi/state.py",
    "aide/rsi/runner.py",
    "aide/rsi/trusted_evaluator.py",
    "aide/utils/config.py",
    "aide/utils/config.yaml",
    "rsi_anchor_service.py",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
)


def _wilson_interval(successes: int, trials: int) -> tuple[float, float]:
    if trials <= 0:
        return (0.0, 1.0)
    z = 1.959963984540054
    observed = successes / trials
    denominator = 1 + z * z / trials
    center = (observed + z * z / (2 * trials)) / denominator
    half = (
        z
        * math.sqrt(observed * (1 - observed) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return max(0.0, center - half), min(1.0, center + half)


def _git_value(*args: str) -> str | None:
    """Return Git metadata when run from a checkout; ZIP extractions are valid."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _release_freeze_value(key: str) -> Any:
    """Read snapshot identity from the generated freeze when Git is absent."""
    candidates = (
        _ROOT / "RELEASE_FREEZE_MANIFEST.json",
        Path(sysconfig.get_path("data"))
        / "share"
        / "aideml-rsi"
        / "RELEASE_FREEZE_MANIFEST.json",
    )
    for path in candidates:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            return value.get(key)
    return None


def _panel_family_effects_batch(
    rng,
    *,
    replicates: int,
    tasks: int,
    task_families: int,
    runs_per_task: int,
    true_effect: float,
    task_sd: float,
    run_sd: float,
    seed_correlation: float,
    family_correlation: float,
    tie_probability: float = 0.02,
):
    """Vectorized nested simulation; return family effects and worst task.

    A family shock induces dependence among its tasks. Task and seed effects
    are reduced before the independent family-cluster sign test. Incumbent and
    challenger share a simulated environment shift that cancels in each pair.
    """
    if tasks < task_families or tasks % task_families:
        raise ValueError("tasks must divide evenly among task families")
    if not 0 <= seed_correlation <= 1 or not 0 <= family_correlation <= 1:
        raise ValueError("correlations must be in [0, 1]")
    families = task_families
    tasks_per_family = tasks // families
    shape = (replicates, families, tasks_per_family, runs_per_task)
    heavy_tail_scale = math.sqrt(3.0)

    def student_t(size, scale=1.0):
        return rng.standard_t(df=3, size=size) * (scale / heavy_tail_scale)

    family_scale = rng.uniform(0.5, 2.0, size=(replicates, families, 1, 1))
    family_shock = (
        student_t(
            (replicates, families, 1, 1),
            task_sd * math.sqrt(family_correlation),
        )
        * family_scale
    )
    task_scale = rng.uniform(0.5, 1.5, size=(replicates, families, tasks_per_family, 1))
    task_noise = (
        student_t(
            (replicates, families, tasks_per_family, 1),
            task_sd * math.sqrt(1.0 - family_correlation),
        )
        * task_scale
    )
    shared_seed_noise = student_t(
        (replicates, families, tasks_per_family, 1),
        run_sd * math.sqrt(seed_correlation),
    )
    run_noise = student_t(
        shape,
        run_sd * math.sqrt(1.0 - seed_correlation),
    )
    shared_environment = rng.normal(0.0, run_sd, size=shape)
    incumbent_scores = shared_environment
    challenger_scores = (
        shared_environment
        + true_effect
        + family_shock
        + task_noise
        + shared_seed_noise
        + run_noise
    )
    deltas = challenger_scores - incumbent_scores
    ties = rng.random(size=shape) < tie_probability
    deltas[ties] = 0.0
    task_effects = np.median(deltas, axis=3)
    family_effects = np.median(task_effects, axis=2)
    worst_task = np.min(task_effects, axis=(1, 2))
    return family_effects, worst_task


def _batch_decisions(
    family_effects,
    worst_task_effects,
    *,
    alpha: float,
    minimum_effect: float = 0.0,
    regression_limit: float = 0.25,
):
    """Apply the exact production sign cutoff to a batch of simulated panels."""
    critical = exact_sign_critical_wins(family_effects.shape[1], alpha)
    if critical is None:
        return np.zeros(family_effects.shape[0], dtype=bool)

    wins = np.sum(family_effects - minimum_effect > SIGN_TIE_ABS_TOLERANCE, axis=1)
    median_family = np.median(family_effects, axis=1)
    return (
        (wins >= critical)
        & (median_family >= minimum_effect)
        & (worst_task_effects >= -regression_limit)
    )


def _single_attempt_null_calibration(
    *,
    rng,
    replicates: int,
    alpha: float,
    tasks: int,
    task_families: int,
    runs_per_task: int,
    task_sd: float,
    run_sd: float,
    correlations: tuple[float, ...],
) -> dict[str, Any]:
    result = {}
    for seed_correlation in correlations:
        for family_correlation in correlations:
            family_effects, worst_task = _panel_family_effects_batch(
                rng,
                replicates=replicates,
                tasks=tasks,
                task_families=task_families,
                runs_per_task=runs_per_task,
                true_effect=0.0,
                task_sd=task_sd,
                run_sd=run_sd,
                seed_correlation=seed_correlation,
                family_correlation=family_correlation,
            )
            rejected = int(
                _batch_decisions(
                    family_effects,
                    worst_task,
                    alpha=alpha,
                ).sum()
            )
            low, high = _wilson_interval(rejected, replicates)
            key = f"seed_rho={seed_correlation};family_rho={family_correlation}"
            result[key] = {
                "within_task_seed_correlation": seed_correlation,
                "within_family_task_correlation": family_correlation,
                "false_promotions": rejected,
                "trials": replicates,
                "rate": rejected / replicates,
                "wilson_95_low": low,
                "wilson_95_high": high,
                "allocated_alpha": alpha,
                "within_task_aggregation": "median paired effect",
                "within_family_aggregation": "median task effect",
                "independent_unit": "task_family_cluster",
                "noise_model": "student_t_3_with_heteroscedastic_task_and_family_scale",
                "tie_probability": 0.02,
                "paired_environment_noise": "shared_between_incumbent_and_challenger_then_cancelled",
                "passed_calibration_bound": high <= alpha + max(0.005, 4 / replicates),
            }
    return result


def _familywise_campaign(
    rng,
    *,
    replicates: int,
    alpha: float,
    attempts: int,
    tasks: int,
    task_families: int,
    runs_per_task: int,
    task_sd: float,
    run_sd: float,
    seed_correlation: float,
    family_correlation: float,
):
    first_promotion = np.zeros(replicates, dtype="int32")
    active = np.ones(replicates, dtype=bool)
    for attempt_index in range(1, attempts + 1):
        indices = np.flatnonzero(active)
        if not len(indices):
            break
        family_effects, worst_task = _panel_family_effects_batch(
            rng,
            replicates=len(indices),
            tasks=tasks,
            task_families=task_families,
            runs_per_task=runs_per_task,
            true_effect=0.0,
            task_sd=task_sd,
            run_sd=run_sd,
            seed_correlation=seed_correlation,
            family_correlation=family_correlation,
        )
        passed = _batch_decisions(
            family_effects,
            worst_task,
            alpha=sequential_alpha(alpha, attempt_index),
        )
        winners = indices[passed]
        first_promotion[winners] = attempt_index
        active[winners] = False
    return first_promotion


def _power_curve(
    *,
    rng,
    replicates: int,
    alpha: float,
    tasks: int,
    task_families: int,
    runs_per_task: int,
    task_sd: float,
    run_sd: float,
    seed_correlation: float,
    family_correlation: float,
    attempt_indices: tuple[int, ...],
) -> dict[str, Any]:
    output = {}
    for effect in (-0.01, 0.0, 0.005, 0.01, 0.02, 0.03):
        for attempt_index in attempt_indices:
            family_effects, worst_task = _panel_family_effects_batch(
                rng,
                replicates=replicates,
                tasks=tasks,
                task_families=task_families,
                runs_per_task=runs_per_task,
                true_effect=effect,
                task_sd=task_sd,
                run_sd=run_sd,
                seed_correlation=seed_correlation,
                family_correlation=family_correlation,
            )
            accepted = int(
                _batch_decisions(
                    family_effects,
                    worst_task,
                    alpha=sequential_alpha(alpha, attempt_index),
                ).sum()
            )
            low, high = _wilson_interval(accepted, replicates)
            output[f"effect_{effect:.3f}_attempt_{attempt_index}"] = {
                "true_family_level_effect": effect,
                "attempt_index": attempt_index,
                "allocated_alpha": sequential_alpha(alpha, attempt_index),
                "accepted": accepted,
                "trials": replicates,
                "rate": accepted / replicates,
                "wilson_95_low": low,
                "wilson_95_high": high,
            }
    return output


def _lineage_stress(*, attempts: int, alpha: float, seed: int) -> dict[str, Any]:
    """Exercise 100-500 actual budget reservations and family-cluster decisions."""
    rng = random.Random(seed)
    protocol = MULTITASK_PROTOCOL_SHA256
    budget = StatisticalBudget.initial(alpha)
    consumed_panels: set[str] = set()
    consumed_tasks: set[str] = set()
    revisions = 0
    policy_sha = hashlib.sha256(b"genesis-policy").hexdigest()
    lineage = []
    crashes_after_reservation = 0
    failed_panels = 0
    rejected = 0
    promoted = 0
    false_promotions = 0
    previous_remaining = budget.remaining_alpha

    for attempt in range(1, attempts + 1):
        # A pre-reservation crash observes no result and burns neither alpha nor
        # panel. The controller then tries this attempt with a fresh panel.
        if rng.random() < 0.05:
            revisions += 1
        panel_sha = hashlib.sha256(f"panel-{attempt}".encode()).hexdigest()
        task_shas = {
            hashlib.sha256(f"task-{attempt}-{index}".encode()).hexdigest()
            for index in range(20)
        }
        if panel_sha in consumed_panels or consumed_tasks.intersection(task_shas):
            raise AssertionError("synthetic lineage reused a reserved panel or task")
        consumed_panels.add(panel_sha)
        consumed_tasks.update(task_shas)
        budget = budget.reserve(panel_sha256=panel_sha, protocol_sha256=protocol)
        if budget.remaining_alpha > previous_remaining:
            raise AssertionError("alpha budget increased across a reservation")
        previous_remaining = budget.remaining_alpha
        revisions += 1

        # Crashes and failed evaluations happen after reservation and therefore
        # permanently burn this panel and its alpha allocation.
        if rng.random() < 0.10:
            crashes_after_reservation += 1
            continue
        if rng.random() < 0.05:
            failed_panels += 1
            continue

        true_effect = rng.choice((0.0, 0.0, -0.01, 0.01, 0.02, 0.03))
        family_effects = [true_effect + rng.gauss(0.0, 0.03) for _ in range(20)]
        decision = task_effect_decision(
            family_effects,
            allocated_alpha=budget.last_allocation,
            minimum_practical_effect=0.0,
            maximum_task_regression=0.25,
        )
        if not decision["passed"]:
            rejected += 1
            continue
        parent = policy_sha
        policy_sha = hashlib.sha256(f"policy-{attempt}-{parent}".encode()).hexdigest()
        lineage.append(
            {
                "attempt_index": attempt,
                "panel_sha256": panel_sha,
                "protocol_sha256": protocol,
                "parent_policy_sha256": parent,
                "policy_sha256": policy_sha,
                "family_effects": family_effects,
                "positive_families": decision["positive_independent_units"],
                "critical_positive_families": decision[
                    "critical_positive_independent_units"
                ],
                "allocated_alpha": budget.last_allocation,
                "cumulative_alpha_spent": budget.spent_alpha,
                "remaining_alpha": budget.remaining_alpha,
                "state_revision": revisions,
            }
        )
        false_promotions += int(true_effect <= 0.0)
        promoted += 1
        revisions += 1

    if budget.attempt_index != attempts:
        raise AssertionError("alpha attempt index regressed")
    if budget.remaining_alpha > alpha or len(consumed_panels) != attempts:
        raise AssertionError("alpha budget or panel retirement regressed")
    return {
        "attempts": attempts,
        "state_revision": revisions,
        "crashes_after_reservation": crashes_after_reservation,
        "failed_panels_after_reservation": failed_panels,
        "rejected_attempts": rejected,
        "synthetic_promotions": promoted,
        "synthetic_false_promotions": false_promotions,
        "alpha_spent": budget.spent_alpha,
        "alpha_remaining": budget.remaining_alpha,
        "panel_count": len(consumed_panels),
        "unique_task_identity_count": len(consumed_tasks),
        "promotion_lineage_entries": lineage,
        "scope": "in-memory budget and family-cluster lineage stress, not RSIStateStore or external-anchor crash qualification",
    }


def run_campaign(
    *,
    campaigns: int = 20_000,
    attempts: int = 100,
    power_replicates: int = 5_000,
    tasks: int = 40,
    task_families: int = MULTITASK_MIN_INDEPENDENT_FAMILIES,
    runs_per_task: int = 5,
    alpha: float = 0.05,
    seed: int = 20261001,
    lineage_attempts: int = 500,
    source_commit_override: str | None = None,
    source_tree_override: str | None = None,
) -> dict[str, Any]:
    if min(campaigns, attempts, power_replicates, tasks, runs_per_task) < 1:
        raise ValueError("simulation counts must be positive")
    if (
        tasks < MULTITASK_MIN_TASKS
        or task_families < MULTITASK_MIN_INDEPENDENT_FAMILIES
        or tasks < task_families
        or tasks % task_families != 0
        or runs_per_task < 3
    ):
        raise ValueError(
            "statistical calibration needs at least "
            f"{MULTITASK_MIN_TASKS} tasks and "
            f"{MULTITASK_MIN_INDEPENDENT_FAMILIES} independent task families, "
            "with 3 runs/task"
        )
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("alpha must be finite and in (0, 1)")

    rng = np.random.default_rng(seed)
    correlations = (0.0, 0.25, 0.5, 0.75, 0.95)
    task_sd = 0.03
    run_sd = 0.02
    single_attempt = _single_attempt_null_calibration(
        rng=rng,
        replicates=campaigns,
        alpha=sequential_alpha(alpha, 1),
        tasks=tasks,
        task_families=task_families,
        runs_per_task=runs_per_task,
        task_sd=task_sd,
        run_sd=run_sd,
        correlations=correlations,
    )
    first_promotions = _familywise_campaign(
        rng,
        replicates=campaigns,
        alpha=alpha,
        attempts=attempts,
        tasks=tasks,
        task_families=task_families,
        runs_per_task=runs_per_task,
        task_sd=task_sd,
        run_sd=run_sd,
        seed_correlation=0.75,
        family_correlation=0.75,
    )
    first_promotion_attempts = [
        int(attempt) for attempt in first_promotions if attempt > 0
    ]
    familywise_false = len(first_promotion_attempts)
    family_low, family_high = _wilson_interval(familywise_false, campaigns)
    power = _power_curve(
        rng=rng,
        replicates=power_replicates,
        alpha=alpha,
        tasks=tasks,
        task_families=task_families,
        runs_per_task=runs_per_task,
        task_sd=task_sd,
        run_sd=run_sd,
        seed_correlation=0.75,
        family_correlation=0.75,
        attempt_indices=(1, min(10, attempts), attempts),
    )
    family_panel_power = {}
    for family_count in (20, 30, 40):
        if family_count < MULTITASK_MIN_INDEPENDENT_FAMILIES:
            continue
        family_panel_power[str(family_count)] = _power_curve(
            rng=rng,
            replicates=power_replicates,
            alpha=alpha,
            tasks=family_count * 2,
            task_families=family_count,
            runs_per_task=runs_per_task,
            task_sd=task_sd,
            run_sd=run_sd,
            seed_correlation=0.75,
            family_correlation=0.75,
            attempt_indices=(1, min(10, attempts), attempts),
        )
    lineage = _lineage_stress(attempts=lineage_attempts, alpha=alpha, seed=seed + 1)
    source_hashes = {
        path: hashlib.sha256((_ROOT / path).read_bytes()).hexdigest()
        for path in _SOURCE_FILES
    }
    source_commit = (
        source_commit_override
        or _release_freeze_value("qualified_code_commit")
        or _git_value("rev-parse", "HEAD")
    )
    source_tree = (
        source_tree_override
        or _release_freeze_value("qualified_code_git_tree")
        or _git_value("rev-parse", "HEAD^{tree}")
    )
    source_manifest_sha256 = hashlib.sha256(
        json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    allocated = sum(sequential_alpha(alpha, index) for index in range(1, attempts + 1))
    return {
        "schema_version": 2,
        "qualification_type": "synthetic statistical calibration; not real-task qualification",
        "protocol_id": MULTITASK_PROTOCOL_ID,
        "protocol_sha256": MULTITASK_PROTOCOL_SHA256,
        "gate_implementation": "TaskClusteredCanaryGate task-to-family aggregation plus exact family-cluster sign test",
        "seed": seed,
        "source_commit": source_commit,
        "source_git_tree": source_tree,
        "source_git_identity_available": source_tree is not None,
        "release_freeze_manifest_available": (
            _release_freeze_value("source_snapshot_sha256") is not None
        ),
        "release_freeze_source_snapshot_sha256": _release_freeze_value(
            "source_snapshot_sha256"
        ),
        "release_freeze_tcb_manifest_sha256": _release_freeze_value(
            "tcb_manifest_sha256"
        ),
        "source_files_sha256": source_hashes,
        "source_file_manifest_sha256": source_manifest_sha256,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "tasks_per_panel": tasks,
        "independent_task_families_per_panel": task_families,
        "runs_per_task": runs_per_task,
        "primary_independent_unit": "task_family_cluster",
        "within_task_estimator": "median paired effect",
        "within_family_estimator": "median task effect",
        "within_task_seed_correlations": list(correlations),
        "within_family_task_correlations": list(correlations),
        "family_cluster_null_type_i_by_seed_and_family_correlation": single_attempt,
        "family_alpha": alpha,
        "spending_rule": "alpha_i = alpha / (i * (i + 1))",
        "attempts_per_familywise_lineage": attempts,
        "theoretical_alpha_allocated_through_last_attempt": allocated,
        "theoretical_remaining_alpha": alpha / (attempts + 1),
        "null_familywise_calibration": {
            "lineages": campaigns,
            "false_promotion_lineages": familywise_false,
            "false_promotion_rate": familywise_false / campaigns,
            "wilson_95_low": family_low,
            "wilson_95_high": family_high,
            "passed_family_alpha_bound": family_high
            <= alpha + max(0.005, 4 / campaigns),
            "first_promotion_attempts": first_promotion_attempts,
            "panel_task_effects_redrawn_per_attempt": True,
        },
        "single_attempt_power_curve": power,
        "power_by_independent_family_count": family_panel_power,
        "synthetic_lineage_stress": lineage,
        "interpretation": (
            "The simulation aggregates correlated tasks within each predeclared family and performs "
            "inference across independent family clusters. It covers within-task seed correlation, "
            "within-family task correlation, heteroscedasticity, heavy tails, ties, and paired shared "
            "environment noise. It does not prove real family independence, external-anchor rollback "
            "resistance, or AIDE improvement."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaigns", type=int, default=20_000)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--power-replicates", type=int, default=5_000)
    parser.add_argument("--tasks", type=int, default=40)
    parser.add_argument(
        "--task-families", type=int, default=MULTITASK_MIN_INDEPENDENT_FAMILIES
    )
    parser.add_argument("--runs-per-task", type=int, default=5)
    parser.add_argument("--lineage-attempts", type=int, default=500)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = run_campaign(
        campaigns=args.campaigns,
        attempts=args.attempts,
        power_replicates=args.power_replicates,
        tasks=args.tasks,
        task_families=args.task_families,
        runs_per_task=args.runs_per_task,
        lineage_attempts=args.lineage_attempts,
        alpha=args.alpha,
        seed=args.seed,
        source_commit_override=args.source_commit,
        source_tree_override=args.source_tree,
    )
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
