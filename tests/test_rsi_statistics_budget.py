from __future__ import annotations

import hashlib
import math

import pytest

from aide.rsi.state import RSIStateStore
from aide.rsi.statistics import (
    MAX_PROMOTION_ATTEMPTS,
    MULTITASK_MIN_TASKS,
    SPENDING_RULE_ID,
    SPENDING_RULE_VERSION,
    StatisticalBudget,
    exact_sign_min_pairs,
    sequential_alpha,
    statistical_epoch_sha256,
    task_sign_test,
)

_PROTOCOL = "a" * 64


def _reserve(budget: StatisticalBudget, attempt: int) -> StatisticalBudget:
    panel_sha256 = hashlib.sha256(f"panel-{attempt}".encode()).hexdigest()
    return budget.reserve(panel_sha256=panel_sha256, protocol_sha256=_PROTOCOL)


def _task_hashes(attempt: int) -> list[str]:
    return [
        hashlib.sha256(f"task-{attempt}-{index}".encode()).hexdigest()
        for index in range(MULTITASK_MIN_TASKS)
    ]


def test_statistical_budget_spends_a_fixed_bonferroni_horizon():
    family_alpha = 0.05
    budget = StatisticalBudget.initial(family_alpha)
    previous_remaining = budget.remaining_alpha
    first_digest = budget.history_digest
    allocation_sum = 0.0

    for attempt in range(1, MAX_PROMOTION_ATTEMPTS + 1):
        allocation = sequential_alpha(family_alpha, attempt)
        allocation_sum += allocation
        assert exact_sign_min_pairs(allocation) >= 1
        budget = _reserve(budget, attempt)
        assert budget.attempt_index == attempt
        assert budget.last_allocation == pytest.approx(allocation)
        assert budget.remaining_alpha < previous_remaining
        assert budget.spent_alpha + budget.remaining_alpha == pytest.approx(
            family_alpha
        )
        assert budget.history_digest != first_digest
        first_digest = budget.history_digest
        previous_remaining = budget.remaining_alpha

    assert allocation_sum == pytest.approx(family_alpha)
    assert family_alpha - allocation_sum == pytest.approx(budget.remaining_alpha)
    assert budget.remaining_alpha == pytest.approx(0.0)
    with pytest.raises(ValueError, match="exhausted"):
        budget.reserve(
            panel_sha256=hashlib.sha256(b"panel-after-horizon").hexdigest(),
            protocol_sha256=_PROTOCOL,
        )
    with pytest.raises(ValueError, match="attempt index"):
        sequential_alpha(family_alpha, MAX_PROMOTION_ATTEMPTS + 1)


def test_statistical_budget_only_migrates_pristine_legacy_runs():
    migrated = StatisticalBudget.migrate_legacy(0.05, 0)
    assert migrated.attempt_index == 0
    assert migrated.remaining_alpha == pytest.approx(0.05)
    assert migrated.max_attempts == MAX_PROMOTION_ATTEMPTS
    assert migrated.spending_rule_id == SPENDING_RULE_ID
    assert migrated.spending_rule_version == SPENDING_RULE_VERSION
    with pytest.raises(ValueError, match="fresh statistical epoch"):
        StatisticalBudget.migrate_legacy(0.05, 20)


def test_budget_deserialization_rejects_policy_and_counter_tampering():
    budget = _reserve(StatisticalBudget.initial(0.05), 1)
    encoded = budget.to_dict()
    encoded["remaining_alpha"] *= 2
    with pytest.raises(ValueError, match="totals are inconsistent"):
        StatisticalBudget.from_dict(encoded)

    encoded = budget.to_dict()
    encoded["spending_rule_version"] = 2
    with pytest.raises(ValueError, match="unsupported"):
        StatisticalBudget.from_dict(encoded)

    encoded = budget.to_dict()
    encoded["max_attempts"] += 1
    with pytest.raises(ValueError, match="horizon is unsupported"):
        StatisticalBudget.from_dict(encoded)


def test_state_store_accepts_only_exact_next_budget_reservation(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AIDE_RSI_EVALUATION_HMAC_KEY", "test-only-statistical-budget-key-32-bytes"
    )
    store = RSIStateStore(tmp_path / "state.json", require_attestation=True)
    store.write(
        canary_attempt_count=0,
        canary_experiment_alpha=0.05,
        statistical_protocol_sha256=_PROTOCOL,
    )
    epoch = statistical_epoch_sha256(0.05, _PROTOCOL)
    store.write(statistical_epoch_sha256=epoch)
    with pytest.raises(ValueError, match="epoch is immutable"):
        store.write(statistical_epoch_sha256="b" * 64)
    with pytest.raises(ValueError, match="protocol is immutable"):
        store.write(statistical_protocol_sha256="c" * 64)
    initial = StatisticalBudget.initial(0.05)
    store.write(statistical_budget=initial.to_dict())

    first = _reserve(initial, 1)
    store.write(
        canary_attempt_count=1,
        statistical_budget=first.to_dict(),
        consumed_canary_panel_sha256=[first.panel_sha256],
        consumed_canary_task_sha256=_task_hashes(1),
    )
    assert store.load()["statistical_budget"] == first.to_dict()

    with pytest.raises(ValueError, match="advance only once"):
        second = _reserve(first, 2)
        third = _reserve(second, 3)
        store.write(
            canary_attempt_count=3,
            statistical_budget=third.to_dict(),
            consumed_canary_panel_sha256=[
                first.panel_sha256,
                second.panel_sha256,
                third.panel_sha256,
            ],
            consumed_canary_task_sha256=_task_hashes(1)
            + _task_hashes(2)
            + _task_hashes(3),
        )
    with pytest.raises(ValueError, match="exact next panel allocation"):
        invalid_next = _reserve(first, 2).to_dict()
        invalid_next["history_digest"] = "0" * 64
        store.write(
            canary_attempt_count=2,
            statistical_budget=invalid_next,
            consumed_canary_panel_sha256=[
                first.panel_sha256,
                invalid_next["panel_sha256"],
            ],
            consumed_canary_task_sha256=_task_hashes(1) + _task_hashes(2),
        )
    with pytest.raises(ValueError, match="cannot change without a reservation"):
        altered = first.to_dict()
        altered["history_digest"] = "0" * 64
        store.write(statistical_budget=altered)
    with pytest.raises(ValueError, match="attempt count cannot decrease"):
        store.write(canary_attempt_count=0, statistical_budget=initial.to_dict())
    with pytest.raises(ValueError, match="exact next panel allocation"):
        next_budget = _reserve(first, 2)
        store.write(
            canary_attempt_count=2,
            statistical_budget=next_budget.to_dict(),
            consumed_canary_panel_sha256=[first.panel_sha256],
            consumed_canary_task_sha256=_task_hashes(1) + _task_hashes(2),
        )

    final = store.load()
    assert final["statistical_budget"] == first.to_dict()
    assert math.isclose(
        final["statistical_budget"]["remaining_alpha"],
        0.05 - 0.05 / MAX_PROMOTION_ATTEMPTS,
    )


def test_task_sign_test_counts_tasks_and_treats_effect_threshold_as_a_tie():
    wins, tasks, p_value = task_sign_test(
        [0.2, 0.2, -0.1, 0.0], minimum_practical_effect=0.0
    )
    assert wins == 2
    assert tasks == 4
    assert p_value == pytest.approx(11 / 16)
