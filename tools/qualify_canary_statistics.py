"""Monte Carlo qualification probe for the production paired canary gate.

This is a synthetic calibration tool. It measures the current gate under
independent and clustered rollout assumptions; it does not qualify real task
or seed independence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aide.rsi.canary import RealCanaryGate
from aide.rsi.evidence import attest_evaluation
from aide.rsi.statistics import sequential_alpha

_SIMULATION_KEY = "synthetic-only-statistical-qualification-key-v1"
_IDENTITY = {
    "evaluator_sha256": "b" * 64,
    "evaluator_config_sha256": "c" * 64,
    "task_sha256": "d" * 64,
    "dataset_sha256": "e" * 64,
    "split_sha256": "f" * 64,
    "predictions_sha256": "1" * 64,
    "environment_sha256": "2" * 64,
    "metric_id": "synthetic.utility",
    "metric_maximize": True,
}
_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_FILES = (
    "aide/rsi/canary.py",
    "aide/rsi/evidence.py",
    "aide/rsi/statistics.py",
    "tools/qualify_canary_statistics.py",
)
_SOURCE_HASHES = {
    path: hashlib.sha256((_ROOT / path).read_bytes()).hexdigest()
    for path in _SOURCE_FILES
}


@dataclass
class _Metric:
    value: float
    is_worst: bool = False


class _Node:
    def __init__(self, score: float, role: str):
        candidate_hash = hashlib.sha256(role.encode()).hexdigest()
        provenance = attest_evaluation(
            {"candidate_sha256": candidate_hash, **_IDENTITY},
            score,
            key=_SIMULATION_KEY,
        )
        self.metric = _Metric(score)
        self.is_buggy = False
        self.rsi_provenance = provenance


class _Journal:
    metric_maximize = True

    def __init__(self, score: float, role: str):
        self.nodes = [_Node(score, role)]


def _gate(alpha: float, attempt: int, bootstrap_samples: int) -> RealCanaryGate:
    return RealCanaryGate(
        max_normalized_regression=0.05,
        min_valid=1,
        min_pass_fraction=0.66,
        min_pairs=5,
        confidence_level=0.95,
        bootstrap_samples=bootstrap_samples,
        min_effect_size=0.0,
        max_single_pair_regression=0.25,
        score_scale_floor=1.0,
        experiment_alpha=alpha,
        promotion_attempt_index=attempt,
    )


def _attempt(
    rng: random.Random,
    *,
    alpha: float,
    attempt_index: int,
    bootstrap_samples: int,
    effect_mean: float,
    effect_sd: float,
    common_task_effect: float = 0.0,
    within_task_sd: float | None = None,
) -> bool:
    gate = _gate(alpha, attempt_index, bootstrap_samples)
    sigma = effect_sd if within_task_sd is None else within_task_sd
    pairs = []
    for _ in range(gate.min_pairs):
        delta = common_task_effect + rng.gauss(effect_mean, sigma)
        pairs.append(
            (
                _Journal(1.0 + delta, "challenger"),
                _Journal(1.0, "incumbent"),
            )
        )
    return gate.evaluate_series(pairs).passed


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


def _familywise_campaign(
    rng: random.Random,
    *,
    alpha: float,
    attempts: int,
    bootstrap_samples: int,
    clustered: bool,
) -> tuple[bool, int | None]:
    # A shared task-level effect models repeated seeds from one task cluster.
    common = rng.gauss(0.0, 0.01) if clustered else 0.0
    for attempt_index in range(1, attempts + 1):
        if _attempt(
            rng,
            alpha=alpha,
            attempt_index=attempt_index,
            bootstrap_samples=bootstrap_samples,
            effect_mean=0.0,
            effect_sd=0.01,
            common_task_effect=common,
            within_task_sd=0.001 if clustered else None,
        ):
            return True, attempt_index
    return False, None


def run_campaign(
    *,
    campaigns: int = 200,
    attempts: int = 100,
    power_replicates: int = 500,
    bootstrap_samples: int = 100,
    alpha: float = 0.05,
    seed: int = 20261001,
) -> dict[str, Any]:
    if campaigns < 1 or attempts < 1 or power_replicates < 1:
        raise ValueError("campaign, attempt, and replicate counts must be positive")
    if not 100 <= bootstrap_samples <= 1_000_000:
        raise ValueError("bootstrap_samples must be in [100, 1000000]")
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("alpha must be finite and in (0, 1)")

    old_key = os.environ.get("AIDE_RSI_EVALUATION_HMAC_KEY")
    os.environ["AIDE_RSI_EVALUATION_HMAC_KEY"] = _SIMULATION_KEY
    try:
        rng = random.Random(seed)
        independent_promotions = 0
        clustered_promotions = 0
        independent_attempts: list[int] = []
        clustered_attempts: list[int] = []
        for _ in range(campaigns):
            promoted, at = _familywise_campaign(
                rng,
                alpha=alpha,
                attempts=attempts,
                bootstrap_samples=bootstrap_samples,
                clustered=False,
            )
            independent_promotions += int(promoted)
            if at is not None:
                independent_attempts.append(at)
            promoted, at = _familywise_campaign(
                rng,
                alpha=alpha,
                attempts=attempts,
                bootstrap_samples=bootstrap_samples,
                clustered=True,
            )
            clustered_promotions += int(promoted)
            if at is not None:
                clustered_attempts.append(at)

        power: dict[str, dict[str, float]] = {}
        for attempt_index in sorted({1, attempts}):
            for name, mean_effect in (
                ("positive", 0.015),
                ("negative", -0.015),
            ):
                accepted = sum(
                    _attempt(
                        rng,
                        alpha=alpha,
                        attempt_index=attempt_index,
                        bootstrap_samples=bootstrap_samples,
                        effect_mean=mean_effect,
                        effect_sd=0.01,
                    )
                    for _ in range(power_replicates)
                )
                lower, upper = _wilson_interval(accepted, power_replicates)
                power[f"{name}_effect_attempt_{attempt_index}"] = {
                    "accepted": accepted,
                    "trials": power_replicates,
                    "rate": accepted / power_replicates,
                    "wilson_95_low": lower,
                    "wilson_95_high": upper,
                }
    finally:
        if old_key is None:
            os.environ.pop("AIDE_RSI_EVALUATION_HMAC_KEY", None)
        else:
            os.environ["AIDE_RSI_EVALUATION_HMAC_KEY"] = old_key

    independent_low, independent_high = _wilson_interval(
        independent_promotions, campaigns
    )
    clustered_low, clustered_high = _wilson_interval(clustered_promotions, campaigns)
    allocated = sum(sequential_alpha(alpha, index) for index in range(1, attempts + 1))
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    source_tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "schema_version": 1,
        "qualification_type": "synthetic Monte Carlo; not real-task qualification",
        "gate_implementation": "aide.rsi.canary.RealCanaryGate",
        "seed": seed,
        "source_commit": source_commit,
        "source_git_tree": source_tree,
        "source_worktree_includes_uncommitted_changes": bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        ),
        "source_files_sha256": _SOURCE_HASHES,
        "python_version": platform.python_version(),
        "campaigns_per_null_model": campaigns,
        "attempts_per_campaign": attempts,
        "bootstrap_samples_per_gate": bootstrap_samples,
        "family_alpha": alpha,
        "spending_rule": "alpha_i = alpha / (i * (i + 1))",
        "theoretical_alpha_allocated_through_last_attempt": allocated,
        "theoretical_remaining_alpha": alpha / (attempts + 1),
        "independent_null": {
            "promoted_lineages": independent_promotions,
            "familywise_false_promotion_rate": independent_promotions / campaigns,
            "wilson_95_low": independent_low,
            "wilson_95_high": independent_high,
            "first_promotion_attempts": independent_attempts,
        },
        "same_task_clustered_null": {
            "promoted_lineages": clustered_promotions,
            "familywise_false_promotion_rate": clustered_promotions / campaigns,
            "wilson_95_low": clustered_low,
            "wilson_95_high": clustered_high,
            "first_promotion_attempts": clustered_attempts,
            "model": "one zero-mean task effect shared across seeds and all attempts, plus small within-task noise",
        },
        "single_attempt_power": power,
        "independence_assumption": "The exact sign-test alpha guarantee requires valid independent paired rollout signs within each attempt. This tool does not establish that real AIDE tasks or seeds satisfy it.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaigns", type=int, default=200)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--power-replicates", type=int, default=500)
    parser.add_argument("--bootstrap-samples", type=int, default=100)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = run_campaign(
        campaigns=args.campaigns,
        attempts=args.attempts,
        power_replicates=args.power_replicates,
        bootstrap_samples=args.bootstrap_samples,
        alpha=args.alpha,
        seed=args.seed,
    )
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
