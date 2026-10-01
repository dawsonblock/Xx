"""Authenticated experiment-wide alpha-spending budget primitives."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any

SPENDING_RULE_ID = "telescoping-harmonic"
SPENDING_RULE_VERSION = 1
_MAX_ATTEMPTS = 1_000_000_000
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def sequential_alpha(family_alpha: float, attempt_index: int) -> float:
    """The precommitted summable schedule: alpha_i = alpha / (i * (i + 1))."""
    alpha = float(family_alpha)
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("family alpha must be finite and in (0, 1)")
    if (
        isinstance(attempt_index, bool)
        or not isinstance(attempt_index, int)
        or not 1 <= attempt_index <= _MAX_ATTEMPTS
    ):
        raise ValueError("attempt index must be a positive integer")
    return alpha / (attempt_index * (attempt_index + 1))


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

    @classmethod
    def initial(cls, family_alpha: float) -> StatisticalBudget:
        alpha = float(family_alpha)
        if not math.isfinite(alpha) or not 0 < alpha < 1:
            raise ValueError("family alpha must be finite and in (0, 1)")
        genesis = _canonical_digest(
            {
                "domain": "aide-rsi-statistical-budget/v1",
                "family_alpha": alpha,
                "spending_rule_id": SPENDING_RULE_ID,
                "spending_rule_version": SPENDING_RULE_VERSION,
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
        )

    @classmethod
    def migrate_legacy(
        cls, family_alpha: float, legacy_attempt_index: int
    ) -> StatisticalBudget:
        """Conservatively reserve all legacy attempts when adding the ledger."""
        if (
            isinstance(legacy_attempt_index, bool)
            or not isinstance(legacy_attempt_index, int)
            or not 0 <= legacy_attempt_index <= _MAX_ATTEMPTS
        ):
            raise ValueError("legacy attempt index is invalid")
        base = cls.initial(family_alpha)
        if legacy_attempt_index == 0:
            return base
        alpha = base.family_alpha
        spent = alpha * legacy_attempt_index / (legacy_attempt_index + 1)
        remaining = alpha / (legacy_attempt_index + 1)
        allocation = sequential_alpha(alpha, legacy_attempt_index)
        history = _canonical_digest(
            {
                "domain": "aide-rsi-statistical-budget-legacy-migration/v1",
                "legacy_attempt_index": legacy_attempt_index,
                "family_alpha": alpha,
                "spending_rule_id": SPENDING_RULE_ID,
                "spending_rule_version": SPENDING_RULE_VERSION,
                "previous_history_digest": base.history_digest,
            }
        )
        return cls(
            family_alpha=alpha,
            attempt_index=legacy_attempt_index,
            spent_alpha=spent,
            remaining_alpha=remaining,
            last_allocation=allocation,
            spending_rule_id=SPENDING_RULE_ID,
            spending_rule_version=SPENDING_RULE_VERSION,
            history_digest=history,
        )

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
        if not isinstance(self.history_digest, str) or not _SHA256_RE.fullmatch(
            self.history_digest
        ):
            raise ValueError("statistical budget history digest is invalid")

        expected_spent = (
            0.0
            if self.attempt_index == 0
            else self.family_alpha * self.attempt_index / (self.attempt_index + 1)
        )
        expected_remaining = self.family_alpha / (self.attempt_index + 1)
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
        if self.remaining_alpha < 0 or self.spent_alpha - self.family_alpha > 1e-15:
            raise ValueError("statistical budget exceeds its family alpha")

    def reserve(self) -> StatisticalBudget:
        if self.attempt_index >= _MAX_ATTEMPTS:
            raise ValueError("statistical budget attempt limit reached")
        next_index = self.attempt_index + 1
        allocation = sequential_alpha(self.family_alpha, next_index)
        next_spent = self.family_alpha * next_index / (next_index + 1)
        next_remaining = self.family_alpha / (next_index + 1)
        history = _canonical_digest(
            {
                "domain": "aide-rsi-statistical-budget-reservation/v1",
                "attempt_index": next_index,
                "allocated_alpha": allocation,
                "family_alpha": self.family_alpha,
                "spending_rule_id": self.spending_rule_id,
                "spending_rule_version": self.spending_rule_version,
                "previous_history_digest": self.history_digest,
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
        )
        result.validate()
        return result

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return _canonical_digest(self.to_dict())
