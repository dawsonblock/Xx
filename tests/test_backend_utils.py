import pytest

from aide.backend import utils


class RetryableError(Exception):
    pass


def _no_wait(**_kwargs):
    while True:
        yield 0


def test_backoff_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(utils, "BACKOFF_MAX_TRIES", 2)
    monkeypatch.setattr(utils.backoff, "expo", _no_wait)
    attempts = 0

    def create():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RetryableError
        return "ok"

    assert utils.backoff_create(create, [RetryableError]) == "ok"
    assert attempts == 2


def test_backoff_reraises_retryable_exception_after_limit(monkeypatch):
    monkeypatch.setattr(utils, "BACKOFF_MAX_TRIES", 2)
    monkeypatch.setattr(utils.backoff, "expo", _no_wait)
    attempts = 0

    def create():
        nonlocal attempts
        attempts += 1
        raise RetryableError("still unavailable")

    with pytest.raises(RetryableError, match="still unavailable"):
        utils.backoff_create(create, [RetryableError])

    assert attempts == 2


def test_backoff_does_not_retry_unlisted_exception(monkeypatch):
    monkeypatch.setattr(utils, "BACKOFF_MAX_TRIES", 2)
    attempts = 0

    def create():
        nonlocal attempts
        attempts += 1
        raise ValueError("invalid request")

    with pytest.raises(ValueError, match="invalid request"):
        utils.backoff_create(create, [RetryableError])

    assert attempts == 1
