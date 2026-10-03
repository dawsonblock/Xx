from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CapabilityProfile:
    backend: str
    question_types: tuple[str, ...] = ("noul", "choice", "score")
    expected_accuracy: Mapping[str, float] = field(default_factory=dict)
    p95_ms: float = 0.0
    cost_units: float = 0.0
    max_state_chars: int | None = None

    def __post_init__(self) -> None:
        if not self.backend:
            raise ValueError("capability backend is required")
        if any(q not in {"noul", "choice", "score"} for q in self.question_types):
            raise ValueError(f"backend {self.backend}: unsupported question type in capability manifest")
        if self.p95_ms < 0 or self.cost_units < 0:
            raise ValueError(f"backend {self.backend}: p95_ms/cost_units must be >= 0")
        if self.max_state_chars is not None and self.max_state_chars < 1:
            raise ValueError(f"backend {self.backend}: max_state_chars must be positive")
        for q, value in self.expected_accuracy.items():
            if q not in self.question_types or not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"backend {self.backend}: invalid expected_accuracy[{q!r}]")

    def supports(self, question_type: str, state_chars: int | None = None) -> bool:
        if question_type not in self.question_types:
            return False
        return self.max_state_chars is None or state_chars is None or state_chars <= self.max_state_chars

    def accuracy(self, question_type: str) -> float | None:
        value = self.expected_accuracy.get(question_type)
        return None if value is None else float(value)


class CapabilityRegistry:
    """Non-authoritative backend capability/performance hints.

    These hints can choose/sequence generalists but never grant direct authority. Missing or stale
    capability data therefore degrades to configured order rather than weakening policy controls.
    """
    def __init__(self, profiles: Mapping[str, CapabilityProfile] | None = None):
        self.profiles = dict(profiles or {})

    @classmethod
    def load(cls, path: str | None) -> "CapabilityRegistry":
        if not path:
            return cls()
        data = json.loads(Path(path).read_text())
        if int(data.get("version", 0)) != 1 or not isinstance(data.get("backends"), Mapping):
            raise ValueError("capability manifest must be version 1 with a backends object")
        profiles: dict[str, CapabilityProfile] = {}
        for name, raw in data["backends"].items():
            if not isinstance(raw, Mapping):
                raise ValueError(f"capability entry {name!r} must be an object")
            profiles[str(name)] = CapabilityProfile(
                backend=str(name),
                question_types=tuple(raw.get("question_types") or ("noul", "choice", "score")),
                expected_accuracy=dict(raw.get("expected_accuracy") or {}),
                p95_ms=float(raw.get("p95_ms", 0.0)),
                cost_units=float(raw.get("cost_units", 0.0)),
                max_state_chars=(None if raw.get("max_state_chars") is None else int(raw["max_state_chars"])),
            )
        return cls(profiles)

    def get(self, backend: str) -> CapabilityProfile | None:
        return self.profiles.get(backend)

    def rank_names(self, names: Iterable[str], question_type: str, *, state_chars: int | None = None,
                   error_cost: float = 1.0, cost_weight: float = 0.02, latency_weight: float = 0.01) -> tuple[str, ...]:
        indexed = list(enumerate(names))
        supported=[]; unknown=[]
        for index, name in indexed:
            p=self.profiles.get(name)
            if p is None:
                unknown.append((index,name)); continue
            if not p.supports(question_type,state_chars):
                continue
            accuracy=p.accuracy(question_type)
            # Missing benchmark accuracy is deliberately penalized, not invented as high confidence.
            err = 0.5 if accuracy is None else 1.0-accuracy
            objective = error_cost*err + cost_weight*p.cost_units + latency_weight*(p.p95_ms/1000.0)
            supported.append((objective,index,name))
        supported.sort(key=lambda x:(x[0],x[1]))
        # Unknown profiles retain operator-configured order after known supported profiles.
        return tuple([x[2] for x in supported] + [x[1] for x in unknown])

    def snapshot(self) -> dict[str, Any]:
        return {name:{
            "question_types": list(p.question_types), "expected_accuracy": dict(p.expected_accuracy),
            "p95_ms": p.p95_ms, "cost_units": p.cost_units, "max_state_chars": p.max_state_chars,
        } for name,p in sorted(self.profiles.items())}
