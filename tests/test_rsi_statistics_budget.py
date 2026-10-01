from __future__ import annotations

import math

import pytest

from aide.rsi.state import RSIStateStore
from aide.rsi.statistics import (
    SPENDING_RULE_ID,
    SPENDING_RULE_VERSION,
    StatisticalBudget,
    exact_sign_min_pairs,
    sequential_alpha,
)


def test_statistical_budget_spends_a_summable_monotonic_sequence():
    family_alpha = 0.05
    budget = StatisticalBudget.initial(family_alpha)
    previous_remaining = budget.remaining_alpha
    first_digest = budget.history_digest
    allocation_sum = 0.0

    for attempt in range(1, 1001):
        allocation = sequential_alpha(family_alpha, attempt)
        allocation_sum += allocation
        assert exact_sign_min_pairs(allocation) >= 1
        budget = budget.reserve()
        assert budget.attempt_index == attempt
        assert budget.last_allocation == pytest.approx(allocation)
        assert budget.remaining_alpha < previous_remaining
        assert budget.spent_alpha + budget.remaining_alpha == pytest.approx(
            family_alpha
        )
        assert budget.history_digest != first_digest
        first_digest = budget.history_digest
        previous_remaining = budget.remaining_alpha

    assert allocation_sum <= family_alpha
    assert family_alpha - allocation_sum == pytest.approx(budget.remaining_alpha)
    assert budget.remaining_alpha == pytest.approx(family_alpha / 1001)


def test_statistical_budget_migration_burns_legacy_attempts():
    migrated = StatisticalBudget.migrate_legacy(0.05, 20)
    assert migrated.attempt_index == 20
    assert migrated.spent_alpha == pytest.approx(0.05 * 20 / 21)
    assert migrated.remaining_alpha == pytest.approx(0.05 / 21)
    assert migrated.last_allocation == pytest.approx(sequential_alpha(0.05, 20))
    assert migrated.spending_rule_id == SPENDING_RULE_ID
    assert migrated.spending_rule_version == SPENDING_RULE_VERSION
    assert migrated.reserve().attempt_index == 21


def test_budget_deserialization_rejects_policy_and_counter_tampering():
    budget = StatisticalBudget.initial(0.05).reserve()
    encoded = budget.to_dict()
    encoded["remaining_alpha"] *= 2
    with pytest.raises(ValueError, match="totals are inconsistent"):
        StatisticalBudget.from_dict(encoded)

    encoded = budget.to_dict()
    encoded["spending_rule_version"] = 2
    with pytest.raises(ValueError, match="unsupported"):
        StatisticalBudget.from_dict(encoded)


def test_state_store_accepts_only_exact_next_budget_reservation(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AIDE_RSI_EVALUATION_HMAC_KEY", "test-only-statistical-budget-key-32-bytes"
    )
    store = RSIStateStore(tmp_path / "state.json", require_attestation=True)
    store.write(canary_attempt_count=0, canary_experiment_alpha=0.05)
    initial = StatisticalBudget.initial(0.05)
    store.write(statistical_budget=initial.to_dict())

    first = initial.reserve()
    store.write(canary_attempt_count=1, statistical_budget=first.to_dict())
    assert store.load()["statistical_budget"] == first.to_dict()

    with pytest.raises(ValueError, match="advance only once"):
        store.write(
            canary_attempt_count=3,
            statistical_budget=first.reserve().reserve().to_dict(),
        )
    with pytest.raises(ValueError, match="exact next allocation"):
        invalid_next = first.reserve().to_dict()
        invalid_next["history_digest"] = "0" * 64
        store.write(canary_attempt_count=2, statistical_budget=invalid_next)
    with pytest.raises(ValueError, match="cannot change without a reservation"):
        altered = first.to_dict()
        altered["history_digest"] = "0" * 64
        store.write(statistical_budget=altered)
    with pytest.raises(ValueError, match="attempt count cannot decrease"):
        store.write(canary_attempt_count=0, statistical_budget=initial.to_dict())

    final = store.load()
    assert final["statistical_budget"] == first.to_dict()
    assert math.isclose(final["statistical_budget"]["remaining_alpha"], 0.025)
