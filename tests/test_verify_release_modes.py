"""Source verification is independent of artifact availability."""

import pytest

from tools import verify_release
from tools.release_state import ReleaseState


def test_verify_source_mode_does_not_require_artifacts(monkeypatch, capsys):
    observed = []
    monkeypatch.setattr(
        verify_release,
        "verify_source",
        lambda expected_commit: observed.append(expected_commit),
    )
    assert verify_release.main(["--verify-source", "--expected-commit", "abc"]) == 0
    assert observed == ["abc"]
    assert capsys.readouterr().out.strip() == ReleaseState.SOURCE_QUALIFIED


def test_verify_artifacts_mode_requires_distinct_final_inputs(monkeypatch):
    def unexpected(_):
        raise AssertionError("source verification should not start")

    monkeypatch.setattr(verify_release, "verify_source", unexpected)
    with pytest.raises(SystemExit, match="2"):
        verify_release.main(["--verify-artifacts"])
