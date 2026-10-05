"""Release qualification phases cannot be skipped."""

import pytest

from tools.release_state import ReleaseState, transition


def test_release_state_accepts_only_the_next_qualification_phase():
    current = ReleaseState.DEVELOPMENT
    for target in (
        ReleaseState.SOURCE_FROZEN,
        ReleaseState.SOURCE_QUALIFICATION_IN_PROGRESS,
        ReleaseState.SOURCE_QUALIFIED,
        ReleaseState.BUILD_IN_PROGRESS,
        ReleaseState.ARTIFACTS_BUILT,
        ReleaseState.ARTIFACTS_QUALIFIED,
        ReleaseState.RELEASE_QUALIFIED,
        ReleaseState.RELEASED,
    ):
        current = transition(current, target)
    assert current is ReleaseState.RELEASED


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ReleaseState.DEVELOPMENT, ReleaseState.RELEASE_QUALIFIED),
        (ReleaseState.SOURCE_FROZEN, ReleaseState.SOURCE_QUALIFIED),
        (ReleaseState.SOURCE_QUALIFIED, ReleaseState.ARTIFACTS_BUILT),
        (ReleaseState.RELEASED, ReleaseState.RELEASE_QUALIFIED),
    ],
)
def test_release_state_rejects_skipped_or_reverse_transitions(current, target):
    with pytest.raises(ValueError, match="illegal release transition"):
        transition(current, target)
