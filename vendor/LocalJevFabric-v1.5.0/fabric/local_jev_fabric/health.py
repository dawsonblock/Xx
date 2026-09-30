from __future__ import annotations

import time
from dataclasses import dataclass

from .config import BackendConfig


@dataclass
class CircuitState:
    failures: int = 0
    opened_until: float = 0.0
    last_error: str | None = None
    half_open_probe: bool = False


class CircuitBreaker:
    """Small per-backend breaker with a single half-open probe after cooldown."""

    def __init__(self, backends: tuple[BackendConfig, ...]):
        self._config = {b.name: b for b in backends}
        self._state = {b.name: CircuitState() for b in backends}

    def allow(self, name: str) -> bool:
        now = time.monotonic()
        cfg = self._config[name]
        state = self._state[name]
        if state.failures < cfg.failure_threshold:
            return True
        if now < state.opened_until:
            return False
        # Cooldown elapsed: allow exactly one probe. Other concurrent work continues to fallback.
        if state.half_open_probe:
            return False
        state.half_open_probe = True
        return True

    def success(self, name: str) -> None:
        self._state[name] = CircuitState()

    def failure(self, name: str, error: str) -> None:
        cfg = self._config[name]
        state = self._state[name]
        state.failures += 1
        state.last_error = error[:500]
        state.half_open_probe = False
        if state.failures >= cfg.failure_threshold:
            state.opened_until = time.monotonic() + cfg.cooldown_s

    def snapshot(self) -> dict[str, dict]:
        now = time.monotonic()
        out: dict[str, dict] = {}
        for name, state in self._state.items():
            cfg = self._config[name]
            remaining = max(0.0, state.opened_until - now)
            if state.failures < cfg.failure_threshold:
                status = "closed"
            elif remaining > 0:
                status = "open"
            else:
                status = "half_open_probe" if state.half_open_probe else "half_open"
            out[name] = {
                "status": status,
                "failures": state.failures,
                "retry_after_s": round(remaining, 3),
                "last_error": state.last_error,
            }
        return out
