from __future__ import annotations

from dataclasses import dataclass

from .capabilities import CapabilityRegistry


@dataclass(frozen=True)
class EscalationPolicy:
    error_cost: float = 1.0
    cost_weight: float = 0.02
    latency_weight: float = 0.01
    min_expected_gain: float = 0.0

    def should_escalate(self, *, score: float, score_semantics: str, current_backend: str,
                        next_backend: str | None, question_type: str, capabilities: CapabilityRegistry) -> bool:
        if not next_backend:
            return False
        current=capabilities.get(current_backend); nxt=capabilities.get(next_backend)
        if current is None or nxt is None:
            return False
        next_acc=nxt.accuracy(question_type)
        if next_acc is None:
            return False
        if score_semantics == "calibrated":
            current_error=max(0.0,min(1.0,1.0-float(score)))
        else:
            acc=current.accuracy(question_type)
            if acc is None:
                return False
            current_error=1.0-acc
        next_error=1.0-next_acc
        expected_gain=(current_error-next_error)*self.error_cost
        incremental=max(0.0,nxt.cost_units-current.cost_units)*self.cost_weight
        incremental+=max(0.0,nxt.p95_ms-current.p95_ms)/1000.0*self.latency_weight
        return expected_gain > incremental + self.min_expected_gain
