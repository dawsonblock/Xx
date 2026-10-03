from local_jev_fabric.config import BackendConfig
from local_jev_fabric.health import CircuitBreaker


def test_half_open_allows_only_one_probe_after_cooldown():
    backend = BackendConfig("b", "http://b", "m", failure_threshold=1, cooldown_s=60)
    breaker = CircuitBreaker((backend,))
    breaker.failure("b", "boom")
    assert breaker.allow("b") is False
    breaker._state["b"].opened_until = 0.0
    assert breaker.allow("b") is True
    assert breaker.allow("b") is False
    assert breaker.snapshot()["b"]["status"] == "half_open_probe"
    breaker.success("b")
    assert breaker.allow("b") is True
    assert breaker.snapshot()["b"]["status"] == "closed"
